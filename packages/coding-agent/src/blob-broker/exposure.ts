/**
 * Exposure backends for the blob broker: make the loopback blob server
 * reachable by provider-side image fetchers.
 *
 * Every adapter resolves to a public base URL. Tunnel adapters own a child
 * process whose exit is observable via {@link ActiveExposure.exited} so the
 * broker can stop advertising URLs the moment the tunnel dies.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { $which, logger } from "@oh-my-pi/pi-utils";

/** User-selectable exposure strategy. */
export type ExposureKind = "cloudflared" | "ngrok" | "tailscale" | "ssh" | "direct";

export interface ExposureConfig {
	kind: ExposureKind;
	/**
	 * Externally reachable base URL. Required for `ssh` (the remote web server
	 * fronting the forwarded port); optional for `direct`, which otherwise
	 * advertises the bind address itself (LAN / same-host use).
	 */
	publicBaseUrl?: string;
	/** Blob server bind host. Loopback for tunnels; `0.0.0.0` for direct serving. */
	bindHost: string;
	/** `user@host[:port]` destination for the ssh reverse forward. */
	sshTarget?: string;
	/** Remote listen port of the ssh reverse forward. */
	sshRemotePort?: number;
}

/** Live exposure of one local port. */
export interface ActiveExposure {
	readonly kind: ExposureKind;
	/** Public origin (no trailing slash) that reaches the local blob server. */
	readonly baseUrl: string;
	/** Resolves when the tunnel child exits; `null` for processless kinds. */
	readonly exited: Promise<void> | null;
	stop(): void;
}

const READY_TIMEOUT_MS = 30_000;
/** ssh prints nothing on success; alive past this grace period means forwarded. */
const SSH_READY_GRACE_MS = 1_500;

/** First `https://<sub>.trycloudflare.com` origin in a cloudflared log line. */
export function parseCloudflaredUrl(line: string): string | null {
	return /https:\/\/[a-z0-9-]+\.trycloudflare\.com/.exec(line)?.[0] ?? null;
}

/** Public URL from an ngrok `--log-format json` line (`started tunnel`). */
export function parseNgrokUrl(line: string): string | null {
	if (!line.includes('"url"')) return null;
	try {
		const parsed = JSON.parse(line) as { msg?: string; url?: string };
		if (typeof parsed.url === "string" && parsed.url.startsWith("https://")) return parsed.url;
	} catch {
		// Interleaved non-JSON output; keep scanning.
	}
	return null;
}

/** Funnel URL from `tailscale funnel` foreground output. */
export function parseTailscaleUrl(line: string): string | null {
	const match = /https:\/\/[a-z0-9.-]+\.ts\.net[^\s|]*/.exec(line);
	return match ? match[0].replace(/\/+$/, "") : null;
}

function requireBinary(name: string): string {
	const path = $which(name);
	if (!path) {
		throw new Error(`imageUrls exposure "${name}" requires the ${name} binary on PATH`);
	}
	return path;
}

function normalizeBaseUrl(url: string): string {
	return url.replace(/\/+$/, "");
}

/**
 * SIGTERM, escalating to SIGKILL after a grace period. `tailscale funnel`
 * observably survives a bare SIGTERM mid-startup, and a leaked funnel child
 * blocks every later funnel invocation on the machine.
 */
function killTunnelProcess(proc: Bun.Subprocess): void {
	proc.kill();
	const timer = setTimeout(() => {
		if (proc.exitCode === null) proc.kill("SIGKILL");
	}, 2_000);
	timer.unref();
}

/**
 * Spawn a tunnel process with its output redirected to a temp log file and
 * poll the file until `extract` yields the public URL. Kills the child and
 * throws on exit or timeout.
 *
 * Deliberately avoids piped stdio: a piped subprocess with an active reader
 * spuriously settles `proc.exited` after `unref()` (observed on Bun 1.3.14,
 * exit code 143 with the process still alive), and an unconsumed pipe would
 * eventually block — or SIGPIPE-kill — the Go tunnel binaries. A file sink
 * has neither failure mode, so `exited` remains a trustworthy death signal.
 */
async function spawnUrlTunnel(
	argv: string[],
	extract: (line: string) => string | null,
	readyPattern?: RegExp,
): Promise<{ proc: Bun.Subprocess; baseUrl: string }> {
	const logPath = path.join(os.tmpdir(), `omp-blob-tunnel-${Date.now().toString(36)}-${process.pid}.log`);
	const fd = fs.openSync(logPath, "w");
	let proc: Bun.Subprocess;
	try {
		proc = Bun.spawn(argv, { stdin: "ignore", stdout: fd, stderr: fd });
	} finally {
		fs.closeSync(fd);
	}

	const deadline = Date.now() + READY_TIMEOUT_MS;
	let scanned = 0;
	let baseUrl: string | undefined;
	while (Date.now() < deadline) {
		let text = "";
		try {
			text = await Bun.file(logPath).text();
		} catch {
			// Log file not flushed yet; keep polling.
		}
		if (text.length > scanned) {
			if (baseUrl === undefined) {
				for (const line of text.slice(scanned).split("\n")) {
					const url = extract(line);
					if (url) {
						baseUrl = normalizeBaseUrl(url);
						break;
					}
				}
				scanned = text.lastIndexOf("\n") + 1;
			}
			// The URL banner can precede edge registration (cloudflared prints the
			// hostname before any connection is live); wait for the ready marker.
			if (baseUrl !== undefined && (!readyPattern || readyPattern.test(text))) {
				return { proc, baseUrl };
			}
		}
		if (proc.exitCode !== null) {
			throw new Error(`${argv[0]} exited with code ${proc.exitCode} before reporting a tunnel URL`);
		}
		await Bun.sleep(150);
	}
	killTunnelProcess(proc);
	throw new Error(`${argv[0]} did not report a tunnel URL within ${READY_TIMEOUT_MS / 1000}s`);
}

function processExposure(kind: ExposureKind, baseUrl: string, proc: Bun.Subprocess): ActiveExposure {
	proc.unref();
	return {
		kind,
		baseUrl,
		exited: proc.exited.then(() => undefined),
		stop: () => killTunnelProcess(proc),
	};
}

/**
 * Expose `port` per `config`. Throws when the backend is missing,
 * misconfigured, or fails to come up; the caller degrades to inline base64.
 */
export async function startExposure(config: ExposureConfig, port: number): Promise<ActiveExposure> {
	switch (config.kind) {
		case "direct": {
			const baseUrl = normalizeBaseUrl(config.publicBaseUrl ?? `http://${config.bindHost}:${port}`);
			return { kind: "direct", baseUrl, exited: null, stop: () => {} };
		}
		case "cloudflared": {
			const binary = requireBinary("cloudflared");
			const { proc, baseUrl } = await spawnUrlTunnel(
				[binary, "tunnel", "--no-autoupdate", "--url", `http://127.0.0.1:${port}`],
				parseCloudflaredUrl,
				/Registered tunnel connection/,
			);
			return processExposure("cloudflared", baseUrl, proc);
		}
		case "ngrok": {
			const binary = requireBinary("ngrok");
			const { proc, baseUrl } = await spawnUrlTunnel(
				[binary, "http", String(port), "--log", "stdout", "--log-format", "json"],
				parseNgrokUrl,
			);
			return processExposure("ngrok", baseUrl, proc);
		}
		case "tailscale": {
			const binary = requireBinary("tailscale");
			const { proc, baseUrl } = await spawnUrlTunnel([binary, "funnel", String(port)], parseTailscaleUrl);
			return processExposure("tailscale", baseUrl, proc);
		}
		case "ssh": {
			if (!config.publicBaseUrl) throw new Error('imageUrls exposure "ssh" requires imageUrls.publicBaseUrl');
			if (!config.sshTarget) throw new Error('imageUrls exposure "ssh" requires imageUrls.sshTarget');
			const binary = requireBinary("ssh");
			const remotePort = config.sshRemotePort ?? 8787;
			const proc = Bun.spawn(
				[
					binary,
					"-o",
					"BatchMode=yes",
					"-o",
					"ExitOnForwardFailure=yes",
					"-N",
					"-R",
					`${remotePort}:127.0.0.1:${port}`,
					config.sshTarget,
				],
				{ stdin: "ignore", stdout: "ignore", stderr: "ignore" },
			);
			const early = await Promise.race([
				proc.exited.then(code => code),
				Bun.sleep(SSH_READY_GRACE_MS).then(() => null),
			]);
			if (early !== null) {
				throw new Error(`ssh reverse forward to ${config.sshTarget} exited with code ${early}`);
			}
			logger.debug("blob-broker: ssh reverse forward established", {
				target: config.sshTarget,
				remotePort,
				localPort: port,
			});
			return processExposure("ssh", normalizeBaseUrl(config.publicBaseUrl), proc);
		}
	}
}
