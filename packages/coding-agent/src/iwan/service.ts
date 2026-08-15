/**
 * iWAN VPN tunnel service for `omp`.
 *
 * Owns the OAuth PKCE login flow, controller server discovery, server-password
 * recovery, and the long-lived native tunnel (`IwanTunnel` from
 * `@oh-my-pi/pi-natives`). On connect, it registers the tunnel's local SOCKS5
 * port with `@oh-my-pi/pi-ai/iwan/route` so the fetch path can route
 * `api.llm.ustc.edu.cn` through the tunnel.
 *
 * The crypto primitives and SOCKS5 bridge live in `packages/ai/src/iwan/`
 * (native-free); only this module touches the native binding, because
 * `pi-ai` has no `@oh-my-pi/pi-natives` dependency.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import {
	AUTH_URL,
	CLIENT_ID,
	CONTROLLER,
	CONTROLLER_APP_ID,
	controllerSignature,
	DOMAIN,
	decryptServerPassword,
	type IwanServer,
	REDIRECT_URI,
	randomHex,
	SCOPE,
	sha256,
	TOKEN_URL,
} from "@oh-my-pi/pi-ai/iwan/protocol";
import { setIwanRoutePort } from "@oh-my-pi/pi-ai/iwan/route";
import { IwanTunnel } from "@oh-my-pi/pi-natives";
import { getConfigRootDir } from "@oh-my-pi/pi-utils";

const CONFIG_PATH = path.join(getConfigRootDir(), "iwan.json");

interface StoredConfig {
	accessToken?: string;
	username?: string;
	servers?: IwanServer[];
	selected?: number;
	/** In-flight OAuth PKCE state, persisted so `login` and `connect` can span separate processes. */
	pending?: PendingLogin;
}

interface PendingLogin {
	state: string;
	verifier: string;
	url: string;
}

export type IwanState = "disconnected" | "login" | "servers" | "connecting" | "connected" | "error";

export interface IwanStatus {
	state: IwanState;
	username?: string;
	servers: Array<{ name: string; host: string; port: number }>;
	selected?: number;
	server?: { name: string; host: string; port: number };
	proxy?: { address: string; port: number; flows: number };
	loginURL?: string;
	error?: string;
}

async function readConfig(): Promise<StoredConfig | undefined> {
	try {
		const content = await fs.promises.readFile(CONFIG_PATH, "utf-8");
		const parsed = JSON.parse(content) as StoredConfig;
		return Array.isArray(parsed.servers) || parsed.pending ? parsed : undefined;
	} catch {
		return undefined;
	}
}

async function writeConfig(config: StoredConfig): Promise<void> {
	await fs.promises.mkdir(path.dirname(CONFIG_PATH), { recursive: true, mode: 0o700 });
	await fs.promises.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2), { encoding: "utf-8", mode: 0o600 });
}

class IwanManager {
	#config: StoredConfig | undefined;
	#pending: PendingLogin | undefined;
	#tunnel: IwanTunnel | undefined;
	#socksPort: number | undefined;
	#flows = 0;
	#state: IwanState = "disconnected";
	#errorMessage: string | undefined;
	#initPromise: Promise<void> | undefined;
	/** Set by the long-lived interactive process to auto-reconnect on tunnel death. */
	#autoReconnect = false;
	#reconnectTimer: ReturnType<typeof setTimeout> | undefined;

	async init(): Promise<void> {
		this.#initPromise ??= this.#loadConfig();
		await this.#initPromise;
	}

	/**
	 * Enable automatic reconnect in the long-lived interactive process: when the
	 * tunnel dies on its own, `#handleTunnelClosed` schedules a fresh connect.
	 * Short-lived `omp iwan …` per-command processes leave this off.
	 */
	enableAutoReconnect(): void {
		this.#autoReconnect = true;
	}

	status(): IwanStatus {
		const current = this.#tunnel;
		return {
			state: this.#state,
			username: this.#config?.username,
			servers: this.#config?.servers?.map(publicServer) ?? [],
			selected: this.#config?.selected,
			server:
				this.#config?.servers?.length && this.#config.selected !== undefined
					? publicServer(this.#config.servers[this.#config.selected])
					: undefined,
			proxy: current ? { address: "127.0.0.1", port: this.#socksPort ?? 0, flows: this.#flows } : undefined,
			loginURL: this.#pending?.url,
			error: this.#errorMessage,
		};
	}

	async beginLogin(): Promise<IwanStatus> {
		if (this.#config?.servers?.length) {
			if (!this.#tunnel) this.#state = "servers";
			this.#errorMessage = undefined;
			return this.status();
		}
		const verifier = randomBase64Url(64);
		const challenge = base64Url(sha256(verifier));
		const oauthState = randomAlphaNumeric(32);
		const params = new URLSearchParams({
			client_id: CLIENT_ID,
			redirect_uri: REDIRECT_URI,
			response_type: "code",
			scope: SCOPE,
			code_challenge: challenge,
			code_challenge_method: "S256",
			state: oauthState,
		});
		this.#pending = { state: oauthState, verifier, url: `${AUTH_URL}?${params}` };
		this.#state = "login";
		this.#errorMessage = undefined;
		await writeConfig({ ...this.#config, pending: this.#pending, servers: this.#config?.servers ?? [] });
		return this.status();
	}

	async completeLogin(redirect: string): Promise<IwanStatus> {
		const login = this.#pending;
		if (!login) throw new Error("iWAN login has not been started");
		try {
			const url = new URL(redirect.trim());
			const params = url.searchParams;
			const returnedState = params.get("state");
			if (returnedState !== login.state) throw new Error("iWAN OAuth state mismatch");
			const oauthError = params.get("error");
			if (oauthError) throw new Error(params.get("error_description") ?? oauthError);
			const code = params.get("code");
			if (!code) throw new Error("iWAN redirect URL does not contain an authorization code");

			const token = await exchangeToken(code, login.verifier);
			const username = token.username;
			const servers = await fetchServers(token.accessToken, username);
			if (servers.length === 0) throw new Error("iWAN controller returned no available servers");

			const result: StoredConfig = { accessToken: token.accessToken, username, servers, selected: 0 };
			this.#config = result;
			this.#pending = undefined;
			this.#state = "servers";
			this.#errorMessage = undefined;
			await writeConfig(result);
			return this.status();
		} catch (cause) {
			this.#state = "error";
			this.#errorMessage = cause instanceof Error ? cause.message : String(cause);
			throw cause;
		}
	}

	async connect(index: number): Promise<IwanStatus> {
		const current = this.#config;
		if (!current) throw new Error("iWAN login is required first");
		const server = current.servers?.[index];
		if (!server) throw new Error("iWAN server selection is invalid");

		this.#state = "connecting";
		this.#errorMessage = undefined;
		try {
			await this.#stopTunnel();
			const password = decryptServerPassword(server);
			const tunnel = new IwanTunnel(message => this.#handleTunnelClosed(message));
			const status = await tunnel.connect(server.host, server.port, server.username, password);
			this.#tunnel = tunnel;
			this.#socksPort = status.port;
			this.#flows = status.flows;
			setIwanRoutePort(status.port);
			this.#config = { ...current, selected: index };
			await writeConfig(this.#config);
			this.#state = "connected";
			return this.status();
		} catch (cause) {
			await this.#stopTunnel().catch(() => {});
			this.#state = "error";
			this.#errorMessage = cause instanceof Error ? cause.message : String(cause);
			throw cause;
		}
	}

	/**
	 * Respond to the native tunnel reporting it died on its own (UDP error or a
	 * server `Close`). Clear the dead route so future requests fail fast instead
	 * of hanging, then — in the long-lived interactive process — reconnect.
	 */
	#handleTunnelClosed(message: string): void {
		// Ignore a stale tunnel's death: only the current one matters.
		if (!this.#tunnel) return;
		this.#errorMessage = message;
		this.#state = "error";
		// The native tunnel already tore itself down; drop the dead handle and
		// route so no request keeps targeting a dead SOCKS port.
		this.#tunnel = undefined;
		this.#socksPort = undefined;
		this.#flows = 0;
		setIwanRoutePort(undefined);
		if (!this.#autoReconnect) return;
		this.#scheduleReconnect();
	}

	/** Backoff reconnect, best-effort, until a fresh tunnel is up or stopped. */
	#scheduleReconnect(delayMs = 1_000): void {
		if (this.#reconnectTimer) return;
		const selected = this.#config?.selected;
		this.#reconnectTimer = setTimeout(() => {
			this.#reconnectTimer = undefined;
			if (selected === undefined || this.#tunnel) return;
			this.connect(selected)
				.then(() => {
					// Success: reset backoff (next death starts at 1s again).
				})
				.catch(() => {
					this.#scheduleReconnect(Math.min(delayMs * 2, 30_000));
				});
		}, delayMs);
	}

	async stop(): Promise<IwanStatus> {
		this.#cancelReconnect();
		await this.#stopTunnel();
		this.#pending = undefined;
		this.#state = this.#config?.servers?.length ? "servers" : "disconnected";
		this.#errorMessage = undefined;
		await writeConfig({ ...this.#config, pending: undefined });
		return this.status();
	}

	async #loadConfig(): Promise<void> {
		this.#config = await readConfig();
		this.#pending = this.#config?.pending;
		if (this.#config?.servers?.length) this.#state = "servers";
		else if (this.#pending) this.#state = "login";
	}

	#cancelReconnect(): void {
		if (this.#reconnectTimer) {
			clearTimeout(this.#reconnectTimer);
			this.#reconnectTimer = undefined;
		}
	}

	async #stopTunnel(): Promise<void> {
		this.#cancelReconnect();
		if (this.#tunnel) {
			await this.#tunnel.stop();
			this.#tunnel = undefined;
			this.#socksPort = undefined;
			this.#flows = 0;
			setIwanRoutePort(undefined);
		}
	}
}

function publicServer(server: IwanServer): { name: string; host: string; port: number } {
	return { name: server.name, host: server.host, port: server.port };
}

function randomAlphaNumeric(length: number): string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	const bytes = new Uint8Array(length);
	crypto.getRandomValues(bytes);
	return Array.from(bytes, byte => alphabet[byte % alphabet.length]).join("");
}

function randomBase64Url(bytes: number): string {
	const data = new Uint8Array(bytes);
	crypto.getRandomValues(data);
	return Buffer.from(data).toString("base64url");
}

function base64Url(data: Uint8Array): string {
	return Buffer.from(data).toString("base64url");
}

async function exchangeToken(code: string, verifier: string): Promise<{ accessToken: string; username: string }> {
	const body = await postJson(TOKEN_URL, {
		client_id: CLIENT_ID,
		code,
		code_verifier: verifier,
		redirect_uri: REDIRECT_URI,
		grant_type: "authorization_code",
	});
	const accessToken = recordValue(body, "access_token");
	if (typeof accessToken !== "string" || !accessToken) throw new Error("iWAN token response has no access_token");
	const idToken = recordValue(body, "id_token");
	const username = typeof idToken === "string" ? jwtUsername(idToken) : undefined;
	return { accessToken, username: username ?? "unknown" };
}

async function fetchServers(accessToken: string, username: string): Promise<IwanServer[]> {
	const body = {
		domain: DOMAIN,
		type: "android",
		oem_name: "panabit",
		device_id: randomHex(8),
		userName: username,
		serverlist_version: "0",
		ipfilter_version: "0",
		branding_version: "0",
	};
	await controllerPost("/m/auth", body, accessToken);
	await controllerPost("/m/keepalive", { ...body, type: "keepalive" }, accessToken);
	const response = await controllerPost("/m/config", body, accessToken);
	const list = recordValue(recordValue(response, "serverlist"), "serverlist");
	if (!Array.isArray(list)) return [];
	return list.flatMap((item): IwanServer[] => {
		const value = record(item);
		if (!value) return [];
		const name = value.name;
		const host = value.serverName;
		const port = value.serverPort;
		const user = value.userName;
		const passWord = value.passWord;
		if (
			typeof name !== "string" ||
			typeof host !== "string" ||
			typeof user !== "string" ||
			typeof passWord !== "string"
		)
			return [];
		const serverPort =
			port === undefined || port === null
				? 6001
				: typeof port === "number" && Number.isInteger(port) && port >= 1 && port <= 65535
					? port
					: undefined;
		if (serverPort === undefined) return [];
		return [{ name, host, port: serverPort, username: user, passWord }];
	});
}

async function controllerPost(endpoint: string, body: Record<string, unknown>, accessToken: string): Promise<unknown> {
	const text = JSON.stringify(body);
	const timestamp = Math.floor(Date.now() / 1000).toString();
	const nonce = randomHex(16).toUpperCase();
	const signature = controllerSignature(endpoint, text, timestamp, nonce);
	return postJson(`${CONTROLLER}${endpoint}`, body, {
		Authorization: `Bearer ${accessToken}`,
		"X-Auth-AppId": CONTROLLER_APP_ID,
		"X-Auth-Timestamp": timestamp,
		"X-Auth-Nonce": nonce,
		"X-Auth-Sign": signature,
	});
}

async function postJson(
	url: string,
	body: Record<string, unknown>,
	extraHeaders?: Record<string, string>,
): Promise<unknown> {
	const response = await fetch(url, {
		method: "POST",
		headers: { "Content-Type": "application/json", ...extraHeaders },
		body: JSON.stringify(body),
	});
	const text = await response.text();
	const value = text ? (JSON.parse(text) as unknown) : undefined;
	if (!response.ok) {
		const detail = typeof value === "string" ? value : JSON.stringify(value);
		throw new Error(`iWAN request failed (${response.status}): ${detail}`);
	}
	return value;
}

function jwtUsername(idToken: string): string | undefined {
	const encoded = idToken.split(".")[1];
	if (!encoded) return undefined;
	try {
		const claims = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as Record<string, unknown>;
		return (claims.name ?? claims.preferred_username ?? claims.sub) as string | undefined;
	} catch {
		return undefined;
	}
}

function record(value: unknown): Record<string, unknown> | undefined {
	return typeof value === "object" && value !== null && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}

function recordValue(value: unknown, key: string): unknown {
	return record(value)?.[key];
}

export const iwanManager = new IwanManager();

/**
 * Best-effort startup recovery: if a previous session saved a server selection,
 * reconnect the tunnel in-process so `api.llm.ustc.edu.cn` requests (chat and
 * model discovery) route through it without a manual `/iwan connect`. Never
 * throws and never blocks startup — a down/unreachable iWAN endpoint simply
 * leaves the manager disconnected, and the user can `/iwan connect` later.
 */
export async function autoConnectIwanOnStartup(): Promise<void> {
	try {
		iwanManager.enableAutoReconnect();
		await iwanManager.init();
		const selected = iwanManager.status().selected;
		if (selected === undefined) return;
		await iwanManager.connect(selected);
	} catch {
		// Fire-and-forget: a failed reconnect must not fail interactive startup.
	}
}
