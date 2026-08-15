import { afterEach, describe, expect, test } from "bun:test";
import * as net from "node:net";
import * as AIError from "@oh-my-pi/pi-ai/error";
import { routeUstcFetch } from "@oh-my-pi/pi-ai/iwan/fetch";
import { setIwanRoutePort } from "@oh-my-pi/pi-ai/iwan/route";
import { streamSimple } from "@oh-my-pi/pi-ai/stream";
import type { ModelSpec } from "@oh-my-pi/pi-ai/types";
import { buildModel } from "@oh-my-pi/pi-catalog/build";

const servers: net.Server[] = [];

afterEach(async () => {
	setIwanRoutePort(undefined);
	await Promise.all(
		servers.splice(0).map(
			server =>
				new Promise<void>(resolve => {
					server.close(() => resolve());
				}),
		),
	);
});

describe("iWAN SOCKS fetch bridge", () => {
	test("negotiates SOCKS5 and decodes a split chunked HTTP response", async () => {
		const port = await startFakeSocksServer();
		const response = await routeUstcFetch(fetch, port)("http://api.llm.ustc.edu.cn/v1/test");

		expect(response.status).toBe(200);
		expect(response.headers.get("content-type")).toBe("text/plain");
		expect(await response.text()).toBe("hello world");
	});

	test("accepts a terminal zero chunk split from its final CRLF", async () => {
		const port = await startFakeSocksServer([
			"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n",
			"\r\n",
		]);
		const response = await routeUstcFetch(fetch, port)("http://api.llm.ustc.edu.cn/v1/test");

		expect(response.status).toBe(200);
		expect(await response.text()).toBe("ok");
	});

	test("accepts fragmented trailers after a terminal zero chunk", async () => {
		const port = await startFakeSocksServer([
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Trace: complete\r\n",
			"\r\n",
		]);
		const response = await routeUstcFetch(fetch, port)("http://api.llm.ustc.edu.cn/v1/test");

		expect(await response.text()).toBe("ok");
	});

	test("classifies a genuinely truncated chunked response as retryable", async () => {
		const port = await startFakeSocksServer([
			"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\ncut",
		]);
		const response = await routeUstcFetch(fetch, port)("http://api.llm.ustc.edu.cn/v1/test");

		try {
			await response.text();
			expect.unreachable("truncated response should reject");
		} catch (error) {
			expect(error).toBeInstanceOf(Error);
			expect((error as Error).message).toBe("iWAN gateway closed during a chunked response");
			expect(AIError.retriable(AIError.classify(error, "openai-completions"))).toBe(true);
		}
	});

	test("classifies a SOCKS connection close before negotiation as retryable", async () => {
		const server = net.createServer(socket => socket.once("data", () => socket.end()));
		servers.push(server);
		const listening = Promise.withResolvers<void>();
		server.once("error", listening.reject);
		server.listen(0, "127.0.0.1", listening.resolve);
		await listening.promise;
		const address = server.address();
		if (!address || typeof address === "string") throw new Error("closing SOCKS server did not bind TCP");

		try {
			await routeUstcFetch(fetch, address.port)("http://api.llm.ustc.edu.cn/v1/test");
			expect.unreachable("closed SOCKS connection should reject");
		} catch (error) {
			expect(error).toBeInstanceOf(Error);
			expect((error as Error).message).toBe("iWAN SOCKS5 connection closed");
			expect(AIError.retriable(AIError.classify(error, "openai-completions"))).toBe(true);
		}
	});

	test("classifies a SOCKS CONNECT rejection as retryable", async () => {
		const port = await startSocksServerAfterConnect(socket => {
			socket.write(Buffer.from([5, 1, 0, 1, 127, 0, 0, 1, 0, 0]));
		});

		try {
			await routeUstcFetch(fetch, port)("http://api.llm.ustc.edu.cn/v1/test");
			expect.unreachable("rejected SOCKS CONNECT should reject");
		} catch (error) {
			expect(error).toBeInstanceOf(Error);
			expect((error as Error).message).toBe("iWAN SOCKS5 CONNECT failed (reply 1)");
			expect(AIError.retriable(AIError.classify(error, "openai-completions"))).toBe(true);
		}
	});

	test("classifies a TLS handshake disconnect as retryable", async () => {
		const port = await startSocksServerAfterConnect(socket => {
			socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
			setImmediate(() => socket.end());
		});

		try {
			await routeUstcFetch(fetch, port)("https://api.llm.ustc.edu.cn/v1/test");
			expect.unreachable("TLS handshake disconnect should reject");
		} catch (error) {
			expect(error).toBeInstanceOf(Error);
			expect(AIError.retriable(AIError.classify(error, "openai-completions"))).toBe(true);
		}
	});

	test("preserves retry metadata through a truncated provider stream", async () => {
		const payload = `data: ${JSON.stringify({ id: "c", choices: [{ index: 0, delta: { reasoning_content: "working" } }] })}\n\n`;
		const chunk = `${Buffer.byteLength(payload).toString(16)}\r\n${payload}\r\n`;
		const port = await startFakeSocksServer([
			`HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n${chunk}`,
		]);
		setIwanRoutePort(port);
		const spec: ModelSpec<"openai-completions"> = {
			id: "test",
			name: "Test",
			api: "openai-completions",
			provider: "ustc",
			baseUrl: "http://api.llm.ustc.edu.cn/v1",
			reasoning: true,
			input: ["text"],
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			contextWindow: 1000,
			maxTokens: 100,
		};

		const result = await streamSimple(
			buildModel(spec),
			{ systemPrompt: ["test"], messages: [{ role: "user", content: "ping", timestamp: Date.now() }] },
			{ apiKey: "test" },
		).result();

		expect(result.stopReason).toBe("error");
		expect(result.content).toContainEqual(expect.objectContaining({ type: "thinking", thinking: "working" }));
		expect(AIError.retriable(result.errorId)).toBe(true);
	});

	test("leaves non-USTC requests on the supplied fetch", async () => {
		let calls = 0;
		const fallback = Object.assign(
			async () => {
				calls += 1;
				return new Response("fallback");
			},
			{ preconnect() {} },
		);
		const routed = routeUstcFetch(fallback, 1);

		expect(await (await routed("https://example.com")).text()).toBe("fallback");
		expect(calls).toBe(1);
		expect(routed.preconnect).toBe(fallback.preconnect);
	});

	test("routes the streamSimple provider path and preserves SSE output", async () => {
		const payload = [
			`data: ${JSON.stringify({ id: "c", choices: [{ index: 0, delta: { content: "ok" } }] })}\n\n`,
			`data: ${JSON.stringify({ id: "c", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\n`,
			"data: [DONE]\n\n",
		].join("");
		const response = `HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: ${Buffer.byteLength(payload)}\r\n\r\n${payload}`;
		const port = await startFakeSocksServer([response.slice(0, 80), response.slice(80)]);
		setIwanRoutePort(port);
		const spec: ModelSpec<"openai-completions"> = {
			id: "test",
			name: "Test",
			api: "openai-completions",
			provider: "ustc",
			baseUrl: "http://api.llm.ustc.edu.cn/v1",
			reasoning: false,
			input: ["text"],
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			contextWindow: 1000,
			maxTokens: 100,
		};

		const result = await streamSimple(
			buildModel(spec),
			{ systemPrompt: ["test"], messages: [{ role: "user", content: "ping", timestamp: Date.now() }] },
			{ apiKey: "test" },
		).result();

		expect(result.stopReason).toBe("stop");
		expect(result.content).toEqual([{ type: "text", text: "ok" }]);
	});
});

async function startFakeSocksServer(
	responseParts: readonly string[] = [
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhe",
		"llo\r\n6\r\n world\r\n0\r\n\r\n",
	],
): Promise<number> {
	const server = net.createServer(socket => {
		let stage: "greet" | "connect" | "http" = "greet";
		let input = Buffer.alloc(0);
		socket.on("data", data => {
			input = Buffer.concat([input, typeof data === "string" ? Buffer.from(data) : data]);
			if (stage === "greet") {
				if (input.length < 3) return;
				input = input.subarray(3);
				stage = "connect";
				socket.write(Buffer.from([5, 0]));
			}
			if (stage === "connect") {
				if (input.length < 5) return;
				const requestLength = 7 + input[4];
				if (input.length < requestLength) return;
				input = input.subarray(requestLength);
				stage = "http";
				socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
			}
			if (stage === "http" && input.includes("\r\n\r\n")) {
				stage = "greet";
				socket.write(responseParts[0] ?? "");
				setImmediate(() => socket.end(responseParts.slice(1).join("")));
			}
		});
	});
	servers.push(server);
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => resolve());
	});
	const address = server.address();
	if (!address || typeof address === "string") throw new Error("fake SOCKS server did not bind TCP");
	return address.port;
}

async function startSocksServerAfterConnect(onConnect: (socket: net.Socket) => void): Promise<number> {
	const server = net.createServer(socket => {
		let stage: "greet" | "connect" | "done" = "greet";
		let input = Buffer.alloc(0);
		socket.on("data", data => {
			input = Buffer.concat([input, typeof data === "string" ? Buffer.from(data) : data]);
			if (stage === "greet") {
				if (input.length < 3) return;
				input = input.subarray(3);
				stage = "connect";
				socket.write(Buffer.from([5, 0]));
			}
			if (stage !== "connect" || input.length < 5) return;
			const requestLength = 7 + input[4];
			if (input.length < requestLength) return;
			stage = "done";
			onConnect(socket);
		});
	});
	servers.push(server);
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", resolve);
	});
	const address = server.address();
	if (!address || typeof address === "string") throw new Error("fake SOCKS server did not bind TCP");
	return address.port;
}
