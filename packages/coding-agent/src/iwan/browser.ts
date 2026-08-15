import { spawn } from "node:child_process";

/** Open `url` in the user's default browser, best-effort on each platform. */
export function openBrowser(url: string): void {
	const command = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
	const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
	try {
		spawn(command, args, { stdio: "ignore", detached: true }).unref();
	} catch {
		// If spawning the browser fails, the caller has already printed the URL.
	}
}
