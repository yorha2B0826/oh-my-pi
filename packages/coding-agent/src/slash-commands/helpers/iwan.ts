import { openBrowser } from "../../iwan/browser";
import { type IwanStatus, iwanManager } from "../../iwan/service";
import type { ParsedSlashCommand, SlashCommandResult, SlashCommandRuntime } from "../types";
import { commandConsumed, errorMessage, parseSubcommand, usage } from "./parse";

const IWAN_HELP_TEXT = [
	"iWAN campus VPN tunnel (USTC)",
	"  /iwan login                                   Start OAuth login; opens the browser",
	'  /iwan connect [<index>] [--redirect "<url>"]   Complete login + connect a server',
	"  /iwan status                                  Show tunnel state",
	"  /iwan servers                                 List controller-advertised servers",
	"  /iwan stop                                    Tear down the tunnel",
	"  /iwan help                                    Show this help",
].join("\n");

async function handleLoginCommand(runtime: SlashCommandRuntime): Promise<SlashCommandResult> {
	try {
		const status = await iwanManager.beginLogin();
		if (status.state === "servers") {
			await runtime.output(formatStatus(await iwanManager.connect(status.selected ?? 0)));
			return commandConsumed();
		}
		if (status.state === "connected") {
			await runtime.output(formatStatus(status));
			return commandConsumed();
		}
		if (status.loginURL) {
			openBrowser(status.loginURL);
			await runtime.output(
				`Opening the browser to authorize…\n${status.loginURL}\n\nAfter authorizing you'll land on a com.panabit.mobile://oauth2redirect?... URL. Copy it and run:\n/iwan connect --redirect "<redirect-url>"`,
			);
			return commandConsumed();
		}
		return usage("iWAN login did not produce a URL.", runtime);
	} catch (err) {
		return usage(`iWAN login failed: ${errorMessage(err)}`, runtime);
	}
}

async function handleConnectCommand(rest: string, runtime: SlashCommandRuntime): Promise<SlashCommandResult> {
	try {
		// `--redirect "<url>"` completes the pending OAuth login first.
		const redirectMatch = rest.match(/--redirect\s+(?:"([^"]*)"|'([^']*)'|(\S+))/);
		if (redirectMatch) {
			const redirect = redirectMatch[1] ?? redirectMatch[2] ?? redirectMatch[3] ?? "";
			await iwanManager.completeLogin(redirect);
		}
		const remaining = rest.replace(/--redirect\s+(?:"[^"]*"|'[^']*'|\S+)/, "").trim();
		const index = remaining ? Number.parseInt(remaining, 10) : 0;
		if (Number.isNaN(index) || index < 0) return usage("Server index must be a non-negative integer.", runtime);
		const status = await iwanManager.connect(index);
		await runtime.output(formatStatus(status));
		return commandConsumed();
	} catch (err) {
		return usage(`iWAN connect failed: ${errorMessage(err)}`, runtime);
	}
}

async function handleStopCommand(runtime: SlashCommandRuntime): Promise<SlashCommandResult> {
	try {
		await iwanManager.stop();
		await runtime.output("iWAN tunnel stopped.");
		return commandConsumed();
	} catch (err) {
		return usage(`iWAN stop failed: ${errorMessage(err)}`, runtime);
	}
}

function formatStatus(status: IwanStatus): string {
	switch (status.state) {
		case "disconnected":
			return "iWAN: disconnected. Run /iwan login to start.";
		case "login":
			return `iWAN: awaiting login.\n${status.loginURL ?? ""}`;
		case "servers":
			return `iWAN: logged in as ${status.username ?? "unknown"} (${status.servers.length} servers); not connected.`;
		case "connecting":
			return "iWAN: connecting…";
		case "connected":
			return `iWAN: connected → ${status.server?.name} via SOCKS5 ${status.proxy?.address}:${status.proxy?.port} (${status.proxy?.flows ?? 0} flows).`;
		case "error":
			return `iWAN: error — ${status.error ?? "unknown"}`;
	}
}

/** ACP/text-mode `/iwan` handler. */
export async function handleIwanAcp(
	command: ParsedSlashCommand,
	runtime: SlashCommandRuntime,
): Promise<SlashCommandResult> {
	await iwanManager.init();
	const { verb, rest } = parseSubcommand(command.args);
	if (!verb || verb === "help") {
		await runtime.output(IWAN_HELP_TEXT);
		return commandConsumed();
	}
	switch (verb) {
		case "login":
			return await handleLoginCommand(runtime);
		case "connect":
			return await handleConnectCommand(rest, runtime);
		case "status":
			await runtime.output(formatStatus(iwanManager.status()));
			return commandConsumed();
		case "servers": {
			const status = iwanManager.status();
			await runtime.output(
				status.servers.length === 0
					? "No servers. Run /iwan login first."
					: status.servers
							.map((server, index) => `[${index}] ${server.name} (${server.host}:${server.port})`)
							.join("\n"),
			);
			return commandConsumed();
		}
		case "stop":
			return await handleStopCommand(runtime);
		default:
			return usage(`Unknown /iwan subcommand: ${verb}. Use /iwan help for available subcommands.`, runtime);
	}
}
