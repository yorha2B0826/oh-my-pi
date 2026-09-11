import { describe, expect, test } from "bun:test";
import { buildModel } from "@oh-my-pi/pi-catalog/build";
import { Effort } from "@oh-my-pi/pi-catalog/effort";
import { ustcModelManagerOptions } from "@oh-my-pi/pi-catalog/provider-models/openai-compat";

function discovery(data: unknown[]) {
	return Object.assign(
		async () =>
			new Response(JSON.stringify({ data }), { status: 200, headers: { "content-type": "application/json" } }),
		{ preconnect: () => {} },
	);
}

async function discover(ids: unknown[]) {
	const specs = await ustcModelManagerOptions({ apiKey: "test-key", fetch: discovery(ids) }).fetchDynamicModels?.();
	return new Map((specs ?? []).map(buildModel).map(model => [model.id, model]));
}

describe("USTC provider discovery", () => {
	test("restores the effort selector for reasoning models omitted by the models endpoint", async () => {
		const byId = await discover([
			{ id: "deepseek-v4-pro" },
			{ id: "qwen3.8-reasoner" },
			{ id: "smart/reasoning" },
			{ id: "qwen3.8-chat" },
		]);

		expect(byId.get("deepseek-v4-pro")?.thinking?.efforts).toEqual([Effort.Low, Effort.High, Effort.Max]);
		expect(byId.get("qwen3.8-reasoner")?.thinking?.efforts).toEqual([
			Effort.Minimal,
			Effort.Low,
			Effort.Medium,
			Effort.High,
		]);
		expect(byId.get("smart/reasoning")?.reasoning).toBe(true);
		expect(byId.get("qwen3.8-chat")?.thinking).toBeUndefined();
	});

	test("mirrors the live gateway catalog: advertised limits, context windows, modality, reasoning", async () => {
		const byId = await discover([
			// The gateway advertises limits for these (2026-09-11 /v1/models).
			{ id: "claude-haiku-4-5", max_input_tokens: 200_000, max_output_tokens: 64_000 },
			{ id: "claude-sonnet-4-6", max_input_tokens: 1_000_000, max_output_tokens: 64_000 },
			{ id: "deepseek-v4-pro", max_input_tokens: 1_000_000, max_output_tokens: 8_192 },
			// Ids the gateway lists without limits — the fork table fills them in.
			{ id: "deepseek-flash" },
			{ id: "deepseek-v4-flash-ascend" },
			{ id: "qwen3.5" },
			{ id: "qwen3.5-non-thinking" },
			{ id: "qwen3.6-reasoner" },
			{ id: "qwen3.7-plus" },
			{ id: "smart/default" },
			{ id: "unlimited-ocr" },
			{ id: "glm-5.3-flash" },
			{ id: "unknown-vendor-9" },
		]);

		// Advertised max_input_tokens/max_output_tokens win over the hand table.
		expect(byId.get("claude-haiku-4-5")?.contextWindow).toBe(200_000);
		expect(byId.get("claude-haiku-4-5")?.maxTokens).toBe(64_000);
		expect(byId.get("deepseek-v4-pro")?.maxTokens).toBe(8_192);

		// Platform catalog / probe-derived context windows.
		expect(byId.get("deepseek-flash")?.contextWindow).toBe(1_000_000);
		expect(byId.get("deepseek-v4-flash-ascend")?.contextWindow).toBe(1_000_000);
		expect(byId.get("qwen3.5")?.contextWindow).toBe(262_144);
		expect(byId.get("qwen3.6-reasoner")?.contextWindow).toBe(262_144);
		expect(byId.get("qwen3.7-plus")?.contextWindow).toBe(262_000);
		expect(byId.get("smart/default")?.contextWindow).toBe(262_000);
		// Unknown ids keep the conservative default.
		expect(byId.get("unknown-vendor-9")?.contextWindow).toBe(32_000);

		// Modality: verified live with a two-colour image probe on 2026-09-11.
		expect(byId.get("deepseek-flash")?.input).toEqual(["text", "image"]);
		expect(byId.get("deepseek-v4-flash-ascend")?.input).toEqual(["text"]);
		expect(byId.get("qwen3.5")?.input).toEqual(["text", "image"]);
		expect(byId.get("claude-haiku-4-5")?.input).toEqual(["text", "image"]);
		expect(byId.get("qwen3.7-plus")?.input).toEqual(["text"]);
		expect(byId.get("glm-5.3-flash")?.input).toEqual(["text", "image"]);
		expect(byId.get("unlimited-ocr")?.input).toEqual(["text", "image"]);
		expect(byId.get("smart/default")?.input).toEqual(["text"]);

		// Reasoning: thinking ids, plus the two marker-less thinking lanes.
		expect(byId.get("qwen3.7-plus")?.reasoning).toBe(true);
		expect(byId.get("deepseek-flash")?.reasoning).toBe(true);
		expect(byId.get("qwen3.6-reasoner")?.reasoning).toBe(true);
		expect(byId.get("qwen3.5-non-thinking")?.reasoning).toBe(false);
	});
});
