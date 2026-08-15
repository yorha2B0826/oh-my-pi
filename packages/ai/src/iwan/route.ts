/**
 * Process-global registry for the active iWAN tunnel's local SOCKS5 port.
 *
 * The tunnel itself (the native `IwanTunnel` napi class) belongs to the
 * `coding-agent` package, which owns the native dependency and the login flow.
 * This module lives in `pi-ai` — which has no native dependency — so that the
 * fetch path in `stream.ts` can route `api.llm.ustc.edu.cn` requests through the
 * tunnel without importing the native binding.
 *
 * `coding-agent` calls {@link setIwanRoutePort} when the tunnel connects/stops;
 * consumers call {@link routeFetch} (or {@link getIwanRoutePort}) to apply the
 * route. {@link routeFetch} returns its argument unchanged when no tunnel is up,
 * so it is a safe no-op on every other request path.
 */

import type { FetchImpl } from "../types";
import { routeUstcFetch } from "./fetch";

let activePort: number | undefined;

/** Register (or clear) the active SOCKS5 port the iWAN tunnel is draining on. */
export function setIwanRoutePort(port: number | undefined): void {
	activePort = port;
}

/** The active SOCKS5 port, or `undefined` when the tunnel is not connected. */
export function getIwanRoutePort(): number | undefined {
	return activePort;
}

/**
 * Return a `FetchImpl` that routes `api.llm.ustc.edu.cn` through the tunnel
 * whenever it is up. The port is read at call time (not at wrap time) so a
 * tunnel connected *after* the fetch was installed is still honoured — the
 * discovery path in `model-registry` installs this once at startup.
 */
export function routeFetch(fallback: FetchImpl): FetchImpl {
	return (input, init) => {
		const port = activePort;
		if (port === undefined) return fallback(input, init);
		return routeUstcFetch(fallback, port)(input, init);
	};
}
