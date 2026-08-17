/**
 * Manage the USTC iWAN campus VPN tunnel.
 */

import { Args, Command, Flags } from "@oh-my-pi/pi-utils/cli";
import { iwanHelp as commandHelp } from "../cli/command-help";
import { type IwanAction, type IwanCommandArgs, runIwanCommand } from "../cli/iwan-cli";

const ACTIONS: IwanAction[] = ["login", "connect", "status", "stop", "servers"];

export default class Iwan extends Command {
	static description = commandHelp.description;
	static args = {
		action: Args.string({
			description: "iWAN action",
			required: false,
			options: ACTIONS,
		}),
		server: Args.string({
			description: "Server index for `connect`",
			required: false,
		}),
	};

	static flags = {
		json: Flags.boolean({ description: "Output JSON" }),
		index: Flags.integer({ description: "Server index for `connect`" }),
	};

	async run(): Promise<void> {
		const { args, flags } = await this.parse(Iwan);
		const action = (args.action ?? "status") as IwanAction;

		const cmd: IwanCommandArgs = {
			action,
			args: args.server ? [args.server] : [],
			flags: {
				json: flags.json,
				index: flags.index,
			},
		};

		await runIwanCommand(cmd);
	}
}
