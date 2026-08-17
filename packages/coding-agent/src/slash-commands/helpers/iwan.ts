import { Spacer, Text, wrapTextWithAnsi } from "@oh-my-pi/pi-tui";
import { openBrowser } from "../../iwan/browser";
import { type IwanStatus, iwanManager } from "../../iwan/service";
import { TranscriptBlock } from "../../modes/components/transcript-container";
import { theme } from "../../modes/theme/theme";
import { urlHyperlinkAlways, WidthAwareText } from "../../tui";
import type { ParsedSlashCommand, SlashCommandResult, SlashCommandRuntime, TuiSlashCommandRuntime } from "../types";
import { commandConsumed, errorMessage, parseSubcommand, usage } from "./parse";

/** Claimed under this id on `ctx.oauthManualInput` while `/iwan login` waits for the redirect URL. */
export const IWAN_MANUAL_INPUT_PROVIDER_ID = "iwan";

const IWAN_HELP_TEXT = [
	"iWAN campus VPN tunnel (USTC)",
	"  /iwan login [<redirect-url>]   Open the browser and wait for the callback, or complete a login with a pasted redirect URL",
	"  /iwan connect [<index>]        Choose an advertised network and connect (picks from a list when no index is given)",
	"  /iwan status                   Show tunnel state",
	"  /iwan servers                  List controller-advertised networks",
	"  /iwan stop                     Tear down the tunnel",
	"  /iwan help                     Show this help",
].join("\n");

async function handleLoginCommand(rest: string, runtime: SlashCommandRuntime): Promise<SlashCommandResult> {
	try {
		// Text/ACP clients have no interactive wait: the pasted redirect URL
		// arrives as the subcommand argument on the next invocation.
		if (rest) {
			await iwanManager.completeLogin(rest);
			await runtime.output(formatStatus(iwanManager.status()));
			return commandConsumed();
		}
		const status = await iwanManager.beginLogin();
		if (status.state === "servers" || status.state === "connected") {
			await runtime.output(formatStatus(status));
			return commandConsumed();
		}
		if (status.loginURL) {
			openBrowser(status.loginURL);
			await runtime.output(
				`Opening the browser to authorize…\n${status.loginURL}\n\nAfter authorizing you'll land on a com.panabit.mobile://oauth2redirect?... URL. Paste it back with:\n/iwan login <redirect-url>`,
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
		const status = iwanManager.status();
		if (!rest) {
			if (status.servers.length === 0) return usage("No networks available. Run /iwan login first.", runtime);
			await runtime.output(
				`Available networks:\n${formatServerList(status)}\n\nChoose one with /iwan connect <index>.`,
			);
			return commandConsumed();
		}
		const index = Number.parseInt(rest, 10);
		if (Number.isNaN(index) || index < 0) return usage("Server index must be a non-negative integer.", runtime);
		const connected = await iwanManager.connect(index);
		await runtime.output(formatStatus(connected));
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
			return await handleLoginCommand(rest, runtime);
		case "connect":
			return await handleConnectCommand(rest, runtime);
		case "status":
			await runtime.output(formatStatus(iwanManager.status()));
			return commandConsumed();
		case "servers": {
			const status = iwanManager.status();
			await runtime.output(
				status.servers.length === 0 ? "No networks. Run /iwan login first." : formatServerList(status),
			);
			return commandConsumed();
		}
		case "stop":
			return await handleStopCommand(runtime);
		default:
			return usage(`Unknown /iwan subcommand: ${verb}. Use /iwan help for available subcommands.`, runtime);
	}
}

/** Interactive TUI `/iwan` handler: waits for the redirect URL on login and offers a network picker on connect. */
export async function handleIwanTui(command: ParsedSlashCommand, runtime: TuiSlashCommandRuntime): Promise<void> {
	await iwanManager.init();
	const ctx = runtime.ctx;
	ctx.editor.setText("");
	const { verb, rest } = parseSubcommand(command.args);
	if (!verb || verb === "help") {
		presentTextBlock(ctx, ...IWAN_HELP_TEXT.split("\n"));
		return;
	}
	switch (verb) {
		case "login":
			await handleTuiLogin(runtime, rest);
			break;
		case "connect":
			await handleTuiConnect(runtime, rest);
			break;
		case "status": {
			const status = iwanManager.status();
			ctx.showStatus(
				status.state === "login"
					? "iWAN: awaiting login — paste the redirect URL here (Esc cancels)."
					: formatStatus(status),
			);
			break;
		}
		case "servers": {
			const status = iwanManager.status();
			presentTextBlock(
				ctx,
				...(status.servers.length === 0
					? ["No networks. Run /iwan login first."]
					: formatServerList(status).split("\n")),
			);
			break;
		}
		case "stop":
			try {
				await iwanManager.stop();
				ctx.showStatus("iWAN tunnel stopped.");
			} catch (err) {
				ctx.showError(`iWAN stop failed: ${errorMessage(err)}`);
			}
			break;
		default:
			ctx.showWarning(`Unknown /iwan subcommand: ${verb}. Use /iwan help for available subcommands.`);
	}
}

async function handleTuiLogin(runtime: TuiSlashCommandRuntime, rest: string): Promise<void> {
	const ctx = runtime.ctx;
	const manualInput = ctx.oauthManualInput;

	if (rest) {
		// `/iwan login <redirect-url>` resolves the waiting claim.
		if (!manualInput.hasPending()) {
			ctx.showWarning("No iWAN login is waiting for a redirect URL. Run /iwan login first.");
			return;
		}
		if (manualInput.pendingProviderId !== IWAN_MANUAL_INPUT_PROVIDER_ID) {
			ctx.showWarning(
				`OAuth login for ${manualInput.pendingProviderId} is waiting for input; cancel it before completing iWAN login.`,
			);
			return;
		}
		manualInput.submit(rest);
		ctx.showStatus("iWAN redirect URL received; completing login…");
		return;
	}

	if (manualInput.hasPending()) {
		if (manualInput.pendingProviderId === IWAN_MANUAL_INPUT_PROVIDER_ID) {
			ctx.showWarning("iWAN login already in progress. Paste the redirect URL here (Esc cancels).");
		} else {
			ctx.showWarning(`OAuth login for ${manualInput.pendingProviderId} is already in progress.`);
		}
		return;
	}

	const login = await asyncBlock(iwanManager.beginLogin(), ctx, "iWAN login failed");
	if (!login) return;
	if (login.state === "servers") {
		ctx.showStatus(
			`iWAN: already logged in as ${login.username ?? "unknown"} — ${login.servers.length} networks available. Run /iwan connect to choose one.`,
		);
		return;
	}
	if (login.state === "connected") {
		ctx.showStatus(formatStatus(login));
		return;
	}
	if (!login.loginURL) {
		ctx.showError("iWAN login did not produce a URL.");
		return;
	}

	const claim = manualInput.tryClaimInput(IWAN_MANUAL_INPUT_PROVIDER_ID);
	if (!claim) {
		ctx.showWarning("Another OAuth login is waiting for input; complete or cancel it first.");
		return;
	}

	openBrowser(login.loginURL);
	presentIwanLoginBlock(ctx, login.loginURL, true);

	const previousOnEscape = ctx.editor.onEscape;
	ctx.editor.onEscape = () => claim.clear("iWAN login cancelled");
	// 等待用户直接粘贴 redirect URL(回车即提交,无需再输 /iwan login <url>)。
	// 超时保护:5 分钟内未收到链接则认证失败,不再无限等待。
	const AUTH_TIMEOUT_MS = 5 * 60 * 1000;
	let redirect: string;
	try {
		redirect = await Promise.race([
			claim.promise,
			new Promise<never>((_, reject) =>
				setTimeout(
					() => reject(new Error(`iWAN authentication timed out after ${AUTH_TIMEOUT_MS / 1000}s`)),
					AUTH_TIMEOUT_MS,
				),
			),
		]);
	} catch (err) {
		claim.clear("iWAN login ended");
		const reason = err instanceof Error ? err.message : String(err);
		if (reason === "iWAN login cancelled") {
			ctx.showStatus("iWAN login cancelled.", { dim: true });
		} else {
			ctx.showError(`iWAN login failed: ${reason}`);
		}
		return;
	} finally {
		ctx.editor.onEscape = previousOnEscape;
	}

	await asyncBlock(iwanManager.completeLogin(redirect), ctx, "iWAN login failed");
	const after = iwanManager.status();
	if (after.state === "servers") {
		ctx.showStatus(
			`iWAN: logged in as ${after.username ?? "unknown"} — ${after.servers.length} networks available. Run /iwan connect to choose one.`,
		);
	}
}

async function handleTuiConnect(runtime: TuiSlashCommandRuntime, rest: string): Promise<void> {
	const ctx = runtime.ctx;
	if (rest) {
		const index = Number.parseInt(rest, 10);
		if (Number.isNaN(index) || index < 0) {
			ctx.showWarning("Network index must be a non-negative integer.");
			return;
		}
		await connectTui(ctx, index);
		return;
	}
	const index = await ctx.showIwanServerSelector();
	if (index === undefined) {
		// `undefined` with servers present is a real cancel; the "no networks"
		// status stays untouched when the selector bailed for lack of servers.
		if (iwanManager.status().servers.length > 0) ctx.showStatus("iWAN connect cancelled.", { dim: true });
		return;
	}
	await connectTui(ctx, index);
}

async function connectTui(ctx: TuiSlashCommandRuntime["ctx"], index: number): Promise<void> {
	try {
		ctx.showStatus(formatStatus(await iwanManager.connect(index)));
	} catch (err) {
		ctx.showError(`iWAN connect failed: ${errorMessage(err)}`);
	}
}

/** Await a step, surfacing failures as an error banner; returns falsy on failure. */
async function asyncBlock<T>(
	promise: Promise<T>,
	ctx: TuiSlashCommandRuntime["ctx"],
	prefix: string,
): Promise<T | undefined> {
	try {
		return await promise;
	} catch (err) {
		ctx.showError(`${prefix}: ${errorMessage(err)}`);
		return undefined;
	}
}

function presentIwanLoginBlock(ctx: TuiSlashCommandRuntime["ctx"], url: string, waiting: boolean): void {
	const block = new TranscriptBlock();
	block.addChild(new Text(theme.bold("iWAN authorization"), 1, 0));
	block.addChild(new Spacer(1));
	block.addChild(
		new WidthAwareText(
			contentWidth =>
				wrapTextWithAnsi(url, contentWidth)
					.map(row => theme.fg("accent", urlHyperlinkAlways(url, row)))
					.join("\n"),
			1,
			0,
		),
	);
	block.addChild(new Spacer(1));
	block.addChild(
		new Text(
			theme.fg(
				"muted",
				waiting
					? "Complete authorization in the browser, then paste the redirect URL here (Esc cancels)."
					: "Complete authorization in the browser, then paste the redirect URL here.",
			),
			1,
			0,
		),
	);
	ctx.present(block);
}

function presentTextBlock(ctx: TuiSlashCommandRuntime["ctx"], ...lines: string[]): void {
	const block = new TranscriptBlock();
	for (const line of lines) block.addChild(new Text(line, 1, 0));
	ctx.present(block);
}

function formatServerList(status: IwanStatus): string {
	return status.servers.map((server, index) => `[${index}] ${server.name} (${server.host}:${server.port})`).join("\n");
}

function formatStatus(status: IwanStatus): string {
	switch (status.state) {
		case "disconnected":
			return "iWAN: disconnected. Run /iwan login to start.";
		case "login":
			return `iWAN: awaiting login.\n${status.loginURL ?? ""}`;
		case "servers":
			return `iWAN: logged in as ${status.username ?? "unknown"} (${status.servers.length} networks); use /iwan connect to choose one.`;
		case "connecting":
			return "iWAN: connecting…";
		case "connected":
			return `iWAN: connected → ${status.server?.name} via SOCKS5 ${status.proxy?.address}:${status.proxy?.port} (${status.proxy?.flows ?? 0} flows).`;
		case "error":
			return `iWAN: error — ${status.error ?? "unknown"}`;
	}
}
