/**
 * iWAN CLI command handlers.
 *
 * Handles `omp iwan <subcommand>`: PKCE login, tunnel connect/stop, and
 * status. The heavy lifting lives in `packages/ai/src/iwan/service.ts`
 * (`iwanManager`); this module is a thin stdin/stdout UI over it.
 */

import * as readline from "node:readline/promises";
import chalk from "@oh-my-pi/pi-utils/chalk";
import { openBrowser } from "../iwan/browser";
import { type IwanStatus, iwanManager } from "../iwan/service";

// =============================================================================
// Types
// =============================================================================

export type IwanAction = "login" | "connect" | "status" | "stop" | "servers";

export interface IwanCommandArgs {
	action: IwanAction;
	args: string[];
	flags: {
		json?: boolean;
		index?: number;
	};
}

// =============================================================================
// Main dispatcher
// =============================================================================

export async function runIwanCommand(cmd: IwanCommandArgs): Promise<void> {
	await iwanManager.init();
	switch (cmd.action) {
		case "login":
			await handleLogin(cmd);
			break;
		case "connect":
			await handleConnect(cmd);
			break;
		case "status":
			await handleStatus(cmd);
			break;
		case "stop":
			await handleStop(cmd);
			break;
		case "servers":
			await handleServers(cmd);
			break;
		default:
			process.stdout.write(chalk.red(`Unknown action: ${cmd.action}\n`));
			process.stdout.write(`Valid actions: login, connect, status, stop, servers\n`);
			process.exitCode = 1;
	}
}

// =============================================================================
// Handlers
// =============================================================================

async function handleLogin(cmd: IwanCommandArgs): Promise<void> {
	try {
		const status = await iwanManager.beginLogin();
		if (status.state === "servers") {
			// Already logged in — no browser round-trip; point at the network picker.
			if (cmd.flags.json) {
				printStatus(status, true);
				return;
			}
			process.stdout.write(
				chalk.dim(`iWAN: already logged in as ${status.username} — choose a network with \`omp iwan connect\`.\n`),
			);
			printServerList(status);
		} else if (status.state === "connected") {
			printStatus(status, cmd.flags.json);
		} else if (status.loginURL) {
			// JSON mode stays non-interactive for scripting.
			if (cmd.flags.json) {
				process.stdout.write(JSON.stringify({ loginURL: status.loginURL }, null, 2));
				process.stdout.write("\n");
				return;
			}

			process.stdout.write(chalk.bold("iWAN login:\n"));
			openBrowser(status.loginURL);
			process.stdout.write(`  Opening ${chalk.cyan(status.loginURL)}\n`);
			process.stdout.write(
				`  After authorizing you'll land on a ${chalk.dim("com.panabit.mobile://oauth2redirect?...")} URL.\n`,
			);
			process.stdout.write(`  Paste that redirect URL here:\n`);

			const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
			try {
				const redirect = (await rl.question("> ")).trim();
				if (!redirect) {
					process.stdout.write(chalk.yellow("No redirect URL pasted; login aborted. Re-run `omp iwan login`.\n"));
					return;
				}
				const loggedIn = await iwanManager.completeLogin(redirect);
				process.stdout.write(
					chalk.green(
						`iWAN: logged in as ${loggedIn.username ?? "unknown"} — ${loggedIn.servers.length} networks.\n`,
					),
				);
				process.stdout.write(`Run ${chalk.bold("omp iwan connect")} to choose a network.\n`);
				return;
			} finally {
				rl.close();
			}
		} else {
			process.stdout.write(chalk.red("Error: iWAN login did not produce a URL.\n"));
			process.exitCode = 1;
		}
	} catch (err) {
		process.stdout.write(chalk.red(`Error: ${errMsg(err)}\n`));
		process.exitCode = 1;
	}
}

async function handleConnect(cmd: IwanCommandArgs): Promise<void> {
	try {
		const status = iwanManager.status();
		if (status.servers.length === 0) {
			process.stdout.write(chalk.red("Error: no networks available. Run `omp iwan login` first.\n"));
			process.exitCode = 1;
			return;
		}

		const rawIndex: number | string | undefined =
			cmd.flags.index ?? (cmd.args[0] !== undefined ? cmd.args[0] : undefined);
		let index: number | undefined;
		if (typeof rawIndex === "number") {
			index = rawIndex;
		} else if (rawIndex !== undefined) {
			index = Number.parseInt(rawIndex, 10);
		} else if (cmd.flags.json) {
			// JSON mode stays non-interactive for scripting.
			process.stdout.write(chalk.red("Error: server index required in JSON mode (use --index <n>)\n"));
			process.exitCode = 1;
			return;
		} else {
			printServerList(status);
			const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
			try {
				const answer = (await rl.question("Choose a network [0-...] > ")).trim();
				index = Number.parseInt(answer, 10);
			} finally {
				rl.close();
			}
		}

		if (Number.isNaN(index) || index === undefined || index < 0 || index >= status.servers.length) {
			process.stdout.write(
				chalk.red(`Error: server index must be an integer between 0 and ${status.servers.length - 1}\n`),
			);
			process.exitCode = 1;
			return;
		}

		await connectAndPrint(cmd, index);
	} catch (err) {
		process.stdout.write(chalk.red(`Error: ${errMsg(err)}\n`));
		process.exitCode = 1;
	}
}

async function connectAndPrint(cmd: IwanCommandArgs, index: number): Promise<void> {
	const status = await iwanManager.connect(index);
	if (cmd.flags.json) {
		process.stdout.write(JSON.stringify(status, null, 2));
		process.stdout.write("\n");
		return;
	}
	process.stdout.write(
		chalk.green(
			`Connected to "${status.server?.name}" via SOCKS5 at ${status.proxy?.address}:${status.proxy?.port}\n`,
		),
	);
}

async function handleStatus(cmd: IwanCommandArgs): Promise<void> {
	printStatus(iwanManager.status(), cmd.flags.json);
}

async function handleStop(cmd: IwanCommandArgs): Promise<void> {
	try {
		await iwanManager.stop();
		if (cmd.flags.json) {
			process.stdout.write(JSON.stringify(iwanManager.status(), null, 2));
			process.stdout.write("\n");
			return;
		}
		process.stdout.write(chalk.dim("iWAN tunnel stopped.\n"));
	} catch (err) {
		process.stdout.write(chalk.red(`Error: ${errMsg(err)}\n`));
		process.exitCode = 1;
	}
}

async function handleServers(cmd: IwanCommandArgs): Promise<void> {
	const status = iwanManager.status();
	if (cmd.flags.json) {
		process.stdout.write(JSON.stringify(status.servers, null, 2));
		process.stdout.write("\n");
		return;
	}
	if (status.servers.length === 0) {
		process.stdout.write(chalk.dim("No networks. Run `omp iwan login` first.\n"));
		return;
	}
	printServerList(status);
}

// =============================================================================
// Helpers
// =============================================================================

function printServerList(status: IwanStatus): void {
	status.servers.forEach((server, index) => {
		const marker = index === status.selected ? chalk.green("▶") : " ";
		process.stdout.write(`  ${marker} [${index}] ${server.name} (${server.host}:${server.port})\n`);
	});
}

function printStatus(status: IwanStatus, json: boolean | undefined): void {
	if (json) {
		process.stdout.write(JSON.stringify(status, null, 2));
		process.stdout.write("\n");
		return;
	}
	switch (status.state) {
		case "disconnected":
			process.stdout.write(chalk.dim("iWAN: disconnected. Run `omp iwan login` to start.\n"));
			break;
		case "login":
			process.stdout.write(
				chalk.yellow(`iWAN: awaiting login — re-run \`omp iwan login\` to continue (${status.loginURL})\n`),
			);
			break;
		case "servers":
			process.stdout.write(
				chalk.dim(
					`iWAN: logged in as ${status.username} (${status.servers.length} networks); choose one with \`omp iwan connect\`.\n`,
				),
			);
			break;
		case "connecting":
			process.stdout.write(chalk.yellow("iWAN: connecting…\n"));
			break;
		case "connected":
			process.stdout.write(
				chalk.green(
					`iWAN: connected → ${status.server?.name} via SOCKS5 ${status.proxy?.address}:${status.proxy?.port} (${status.proxy?.flows ?? 0} flows).\n`,
				),
			);
			break;
		case "error":
			process.stdout.write(chalk.red(`iWAN: error — ${status.error ?? "unknown"}\n`));
			break;
	}
}

function errMsg(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
