/**
 * SOCKS5 `FetchImpl` bridge for the USTC gateway.
 *
 * Bun's native `fetch` honors HTTP(S) proxies via `RequestInit.proxy` but has
 * no reliable SOCKS support for this endpoint, and the repo carries no SOCKS
 * agent library. The iWAN
 * tunnel exposes a local SOCKS5 listener (`127.0.0.1:<port>`), so we hand-roll
 * the SOCKS5 `CONNECT` handshake over Bun's native socket API, upgrade to TLS
 * when the target is `https:`, and drive an HTTP request over the established
 * socket — the same idiom as `connectProxiedSocket` in
 * `packages/ai/src/utils/proxy.ts`, but with a SOCKS5 greeting in place of an
 * HTTP `CONNECT`.
 *
 * Only requests to `api.llm.ustc.edu.cn` are rerouted; everything else falls
 * through to the caller's `fetch`.
 */

import { Duplex } from "node:stream";
import { ProviderResponseError } from "../error/provider";
import type { FetchImpl } from "../types";

/** Host that the iWAN tunnel serves; everything else bypasses the tunnel. */
const USTC_API_HOST = "api.llm.ustc.edu.cn";

function isUstcApiUrl(input: string | URL | Request): boolean {
	const url = new URL(input instanceof Request ? input.url : input.toString());
	return url.hostname === USTC_API_HOST;
}

/** Build a `FetchImpl` that routes USTC requests through the local SOCKS5 port. */
export function routeUstcFetch(fetchImpl: FetchImpl, socksPort: number): FetchImpl {
	const wrapped = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
		if (!isUstcApiUrl(input)) return fetchImpl(input, init);
		return requestViaSocks(input, init, socksPort);
	};
	if (fetchImpl.preconnect) {
		wrapped.preconnect = fetchImpl.preconnect;
	}
	return wrapped;
}

async function requestViaSocks(
	input: string | URL | Request,
	init: RequestInit | undefined,
	socksPort: number,
): Promise<Response> {
	const source = input instanceof Request ? input : undefined;
	const url = new URL(input instanceof Request ? input.url : input.toString());
	const method = (init?.method ?? source?.method ?? "GET").toUpperCase();
	const headers = new Headers(source?.headers);
	for (const [key, value] of new Headers(init?.headers)) headers.set(key, value);
	const body =
		init?.body ?? (source && method !== "GET" && method !== "HEAD" ? await source.clone().arrayBuffer() : undefined);
	const bodyBytes = body === undefined || body === null ? undefined : await bodyBuffer(body);

	const requestHeaders: Record<string, string> = {};
	headers.forEach((value, key) => {
		requestHeaders[key] = value;
	});
	if (!headers.has("host")) requestHeaders.host = url.host;
	requestHeaders.connection = "close";
	requestHeaders["accept-encoding"] = "identity";
	if (bodyBytes && !headers.has("content-length")) requestHeaders["content-length"] = String(bodyBytes.length);

	const socket = await socks5Connect(url, socksPort, init?.signal ?? source?.signal);
	const requestHead = [
		`${method} ${url.pathname}${url.search} HTTP/1.1`,
		...Object.entries(requestHeaders).map(([key, value]) => `${key}: ${value}`),
		"",
		"",
	].join("\r\n");
	const requestBytes = bodyBytes ? Buffer.concat([Buffer.from(requestHead), bodyBytes]) : Buffer.from(requestHead);
	return readHttpResponse(socket, requestBytes, init?.signal ?? source?.signal);
}

function readHttpResponse(socket: Duplex, request: Buffer, signal?: AbortSignal): Promise<Response> {
	return new Promise<Response>((resolve, reject) => {
		let headerBuffer = Buffer.alloc(0);
		let responseStarted = false;
		let bodyController: ReadableStreamDefaultController<Uint8Array> | undefined;
		let decoder: ChunkedDecoder | undefined;
		let remainingBody: number | undefined;

		const cleanup = () => {
			signal?.removeEventListener("abort", onAbort);
			socket.off("data", onData);
			socket.off("end", onEnd);
			socket.off("error", onError);
		};
		const fail = (error: Error) => {
			cleanup();
			if (responseStarted) bodyController?.error(error);
			else reject(error);
		};
		const onAbort = () => {
			socket.destroy();
			fail(new Error("iWAN request aborted"));
		};
		const finish = () => {
			cleanup();
			bodyController?.close();
		};
		const emitBody = (data: Buffer) => {
			if (data.length === 0 || !bodyController) return;
			if (decoder) {
				try {
					for (const chunk of decoder.push(data)) bodyController.enqueue(chunk);
					if (decoder.done) finish();
				} catch (error) {
					fail(error instanceof Error ? error : new Error(String(error)));
				}
				return;
			}
			if (remainingBody !== undefined) {
				const length = Math.min(data.length, remainingBody);
				if (length > 0) bodyController.enqueue(data.subarray(0, length));
				remainingBody -= length;
				if (remainingBody === 0) finish();
				return;
			}
			bodyController.enqueue(data);
		};
		const onData = (data: Buffer) => {
			if (responseStarted) {
				emitBody(data);
				return;
			}
			headerBuffer = Buffer.concat([headerBuffer, data]);
			const boundary = headerBuffer.indexOf("\r\n\r\n");
			if (boundary < 0) return;
			let parsed: ParsedHttpResponseHead;
			try {
				parsed = parseHttpResponseHead(headerBuffer.subarray(0, boundary).toString("latin1"));
			} catch (error) {
				fail(error instanceof Error ? error : new Error(String(error)));
				return;
			}
			const initialBody = headerBuffer.subarray(boundary + 4);
			const transferEncoding = parsed.headers.get("transfer-encoding")?.toLowerCase();
			if (transferEncoding?.includes("chunked")) decoder = new ChunkedDecoder();
			else {
				const contentLength = parsed.headers.get("content-length");
				if (contentLength !== null) {
					remainingBody = Number.parseInt(contentLength, 10);
					if (!Number.isSafeInteger(remainingBody) || remainingBody < 0) {
						fail(new Error("iWAN gateway returned an invalid content length"));
						return;
					}
				}
			}
			const body = new ReadableStream<Uint8Array>({
				start(controller) {
					bodyController = controller;
				},
				cancel() {
					socket.destroy();
					cleanup();
				},
			});
			responseStarted = true;
			resolve(new Response(body, parsed));
			if (remainingBody === 0) finish();
			else emitBody(initialBody);
		};
		const onEnd = () => {
			if (!responseStarted) fail(iwanTransportError("iWAN gateway closed before sending an HTTP response"));
			else if (decoder && !decoder.done) fail(iwanTransportError("iWAN gateway closed during a chunked response"));
			else finish();
		};
		const onError = (error: Error) => fail(iwanTransportCause(error, "iWAN gateway connection failed"));

		if (signal?.aborted) return onAbort();
		signal?.addEventListener("abort", onAbort, { once: true });
		socket.on("data", onData);
		socket.once("end", onEnd);
		socket.once("error", onError);
		socket.write(request);
	});
}

interface ParsedHttpResponseHead extends ResponseInit {
	headers: Headers;
}

function parseHttpResponseHead(head: string): ParsedHttpResponseHead {
	const [statusLine, ...headerLines] = head.split("\r\n");
	const match = statusLine?.match(/^HTTP\/1\.[01] (\d{3})(?: (.*))?$/);
	if (!match) throw new Error("iWAN gateway returned an invalid HTTP status line");
	const headers = new Headers();
	for (const line of headerLines) {
		const separator = line.indexOf(":");
		if (separator <= 0) throw new Error("iWAN gateway returned an invalid HTTP header");
		headers.append(line.slice(0, separator).trim(), line.slice(separator + 1).trim());
	}
	return { status: Number.parseInt(match[1], 10), statusText: match[2] ?? "", headers };
}

class ChunkedDecoder {
	#buffer = Buffer.alloc(0);
	#remaining: number | undefined;
	done = false;

	push(data: Buffer): Buffer[] {
		if (this.done) return [];
		this.#buffer = Buffer.concat([this.#buffer, data]);
		const output: Buffer[] = [];
		while (true) {
			// A zero-sized chunk is followed by either a final CRLF or trailers.
			// Keep this as a distinct persistent state: the terminator may be split
			// across arbitrary socket data events.
			if (this.#remaining === 0) {
				if (this.#buffer.length < 2) break;
				if (this.#buffer.subarray(0, 2).toString("ascii") === "\r\n") {
					this.done = true;
					break;
				}
				const trailerEnd = this.#buffer.indexOf("\r\n\r\n");
				if (trailerEnd < 0) break;
				this.done = true;
				break;
			}
			if (this.#remaining === undefined) {
				const lineEnd = this.#buffer.indexOf("\r\n");
				if (lineEnd < 0) break;
				const sizeText = this.#buffer.subarray(0, lineEnd).toString("ascii").split(";", 1)[0]?.trim() ?? "";
				if (!/^[0-9a-f]+$/i.test(sizeText)) throw new Error("iWAN gateway returned an invalid chunk size");
				this.#remaining = Number.parseInt(sizeText, 16);
				this.#buffer = this.#buffer.subarray(lineEnd + 2);
				if (this.#remaining === 0) continue;
			}
			if (this.#remaining === undefined || this.#buffer.length < this.#remaining + 2) break;
			const chunk = this.#buffer.subarray(0, this.#remaining);
			if (this.#buffer.subarray(this.#remaining, this.#remaining + 2).toString("ascii") !== "\r\n") {
				throw new Error("iWAN gateway returned a malformed chunked response");
			}
			output.push(chunk);
			this.#buffer = this.#buffer.subarray(this.#remaining + 2);
			this.#remaining = undefined;
		}
		return output;
	}
}

/**
 * Establish a SOCKS5 `CONNECT` tunnel to `url` through `127.0.0.1:<socksPort>`
 * and return a Node-compatible duplex, upgraded with Bun's native TLS stack
 * when the target is `https:`.
 *
 * Bun 1.3's `node:tls.connect({ socket })` compatibility path emits a
 * different ClientHello from Bun's native socket stack. USTC's gateway resets
 * that compatibility-layer handshake before `secureConnect`, while
 * `Socket.upgradeTLS()` negotiates TLS 1.2/1.3 normally. The duplex adapter
 * feeds a streaming HTTP/1 parser that handles content-length, chunked, and
 * SSE bodies without sending the TLS handshake through `node:tls`.
 */
async function socks5Connect(url: URL, socksPort: number, signal?: AbortSignal): Promise<Duplex> {
	const targetHost = url.hostname;
	const targetPort = url.port ? Number.parseInt(url.port, 10) : url.protocol === "https:" ? 443 : 80;
	return openSocks5Tunnel(socksPort, targetHost, targetPort, url.protocol === "https:", signal);
}

function openSocks5Tunnel(
	socksPort: number,
	targetHost: string,
	targetPort: number,
	secure: boolean,
	signal?: AbortSignal,
): Promise<Duplex> {
	return new Promise<Duplex>((resolve, reject) => {
		let stage: "greet" | "connect" | "done" = "greet";
		let buffer = Buffer.alloc(0);
		let activeSocket: Bun.Socket<undefined> | undefined;
		let duplex: Duplex | undefined;
		let settled = false;
		let tlsUpgradeStarted = false;

		const cleanup = () => {
			signal?.removeEventListener("abort", onAbort);
		};
		const onAbort = () => {
			cleanup();
			activeSocket?.terminate();
			fail(new Error("iWAN request aborted"));
		};
		const fail = (error: Error) => {
			if (settled) {
				duplex?.destroy(error);
				return;
			}
			settled = true;
			cleanup();
			reject(error);
		};
		const succeed = (socket: Bun.Socket<undefined>, initialData?: Buffer) => {
			if (settled) return;
			activeSocket = socket;
			duplex = bunSocketDuplex(socket);
			if (initialData?.length) duplex.push(initialData);
			settled = true;
			cleanup();
			resolve(duplex);
		};

		const onData = (socket: Bun.Socket<undefined>, chunk: Buffer) => {
			if (stage === "done") {
				// upgradeTLS() retires the raw socket and installs a separate TLS
				// handler. Ignore any late ciphertext delivered to the old handler;
				// only the TLS handler may feed plaintext into the HTTP parser.
				if (!tlsUpgradeStarted) duplex?.push(chunk);
				return;
			}
			buffer = Buffer.concat([buffer, chunk]);
			if (stage === "greet") {
				// Reply: VER(0x05) METHOD. We offered no-auth (0x00) first.
				if (buffer.length < 2) return;
				if (buffer[0] !== 0x05 || buffer[1] !== 0x00) {
					fail(new Error("iWAN SOCKS5 negotiation failed"));
					socket.terminate();
					return;
				}
				buffer = Buffer.alloc(0);
				stage = "connect";
				writeConnectRequest(socket);
			} else if (stage === "connect") {
				if (buffer.length < 4) return;
				if (buffer[0] !== 0x05) {
					fail(iwanTransportError("iWAN SOCKS5 CONNECT failed"));
					socket.terminate();
					return;
				}
				if (buffer[1] !== 0x00) {
					fail(iwanTransportError(`iWAN SOCKS5 CONNECT failed (reply ${buffer[1]})`));
					socket.terminate();
					return;
				}
				const addressType = buffer[3];
				if (addressType !== 0x01 && addressType !== 0x03 && addressType !== 0x04) {
					fail(new Error("iWAN SOCKS5 CONNECT returned an invalid address type"));
					socket.terminate();
					return;
				}
				const addressLength = addressType === 0x01 ? 4 : addressType === 0x03 ? 1 + (buffer[4] ?? 0) : 16;
				const replyLength = 4 + addressLength + 2;
				if (buffer.length < replyLength) return;
				const extra = buffer.subarray(replyLength);
				stage = "done";
				if (!secure) {
					succeed(socket, extra);
					return;
				}
				tlsUpgradeStarted = true;
				const [, tlsSocket] = socket.upgradeTLS<undefined>({
					tls: { serverName: targetHost, rejectUnauthorized: true, ALPNProtocols: "http/1.1" },
					socket: {
						open: succeed,
						data(_tlsSocket, data) {
							duplex?.push(data);
						},
						drain() {
							duplex?.emit("bun-drain");
						},
						close() {
							duplex?.push(null);
						},
						error(_tlsSocket, error) {
							fail(iwanTransportCause(error, "iWAN TLS connection failed"));
						},
					},
				});
				activeSocket = tlsSocket;
			}
		};

		const writeConnectRequest = (socket: Bun.Socket<undefined>) => {
			const host = Buffer.from(targetHost, "utf8");
			if (host.length > 255) {
				fail(new Error("iWAN SOCKS5 target hostname is too long"));
				return;
			}
			const request = Buffer.alloc(7 + host.length);
			request[0] = 0x05; // VER
			request[1] = 0x01; // CMD = CONNECT
			request[2] = 0x00; // RSV
			request[3] = 0x03; // ATYP = DOMAINNAME
			request[4] = host.length;
			host.copy(request, 5);
			request.writeUInt16BE(targetPort, 5 + host.length);
			socket.write(request);
		};

		signal?.addEventListener("abort", onAbort, { once: true });
		if (signal?.aborted) return onAbort();
		void Bun.connect<undefined>({
			hostname: "127.0.0.1",
			port: socksPort,
			socket: {
				open(socket) {
					activeSocket = socket;
					// Greeting: VER(0x05) NMETHODS(1) NO-AUTH(0x00).
					socket.write(Buffer.from([0x05, 0x01, 0x00]));
				},
				data: onData,
				drain() {
					duplex?.emit("bun-drain");
				},
				close() {
					// Closing the raw socket is part of Bun's normal TLS handoff.
					if (tlsUpgradeStarted) return;
					if (!settled) fail(iwanTransportError("iWAN SOCKS5 connection closed"));
					else duplex?.push(null);
				},
				error(_socket, error) {
					if (tlsUpgradeStarted) return;
					fail(iwanTransportCause(error, "iWAN SOCKS5 connection failed"));
				},
				connectError(_socket, error) {
					fail(iwanTransportCause(error, "iWAN SOCKS5 connection failed"));
				},
			},
		}).catch(error => fail(iwanTransportCause(error, "iWAN SOCKS5 connection failed")));
	});
}

function iwanTransportError(message: string, cause?: unknown): ProviderResponseError {
	return new ProviderResponseError(message, { provider: "ustc", kind: "incomplete-stream", cause });
}

function iwanTransportCause(error: unknown, fallback: string): ProviderResponseError {
	if (error instanceof ProviderResponseError) return error;
	return iwanTransportError(error instanceof Error ? error.message : fallback, error);
}

function bunSocketDuplex(socket: Bun.Socket<undefined>): Duplex {
	const duplex = new Duplex({
		read() {},
		write(chunk: Buffer | string, encoding, callback) {
			const bytes = typeof chunk === "string" ? Buffer.from(chunk, encoding) : chunk;
			let offset = 0;
			const flush = () => {
				try {
					const written = socket.write(bytes, offset, bytes.length - offset);
					if (written < 0) throw new Error("iWAN socket closed while writing");
					offset += written;
					if (offset >= bytes.length) callback();
					else duplex.once("bun-drain", flush);
				} catch (error) {
					callback(error instanceof Error ? error : new Error(String(error)));
				}
			};
			flush();
		},
		final(callback) {
			socket.end();
			callback();
		},
		destroy(error, callback) {
			socket.terminate();
			callback(error);
		},
	});
	return duplex;
}

async function bodyBuffer(body: NonNullable<RequestInit["body"]> | ArrayBuffer): Promise<Buffer> {
	if (typeof body === "string") return Buffer.from(body);
	if (body instanceof URLSearchParams) return Buffer.from(body.toString());
	if (body instanceof ArrayBuffer) return Buffer.from(body);
	if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
	if (body instanceof Blob) return Buffer.from(await body.arrayBuffer());
	return Buffer.from(await new Response(body).arrayBuffer());
}
