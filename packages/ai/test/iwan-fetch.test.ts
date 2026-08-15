import { afterEach, describe, expect, test } from "bun:test";
import * as net from "node:net";
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
