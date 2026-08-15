import { describe, expect, test } from "bun:test";
import { buildModel } from "@oh-my-pi/pi-catalog/build";
import { Effort } from "@oh-my-pi/pi-catalog/effort";
import { ustcModelManagerOptions } from "@oh-my-pi/pi-catalog/provider-models/openai-compat";

describe("USTC provider discovery", () => {
	test("restores the effort selector for reasoning models omitted by the models endpoint", async () => {
		const fetchMock = Object.assign(
			async () =>
				new Response(
					JSON.stringify({
						data: [
							{ id: "deepseek-v4-pro" },
							{ id: "qwen3.8-reasoner" },
							{ id: "smart/reasoning" },
							{ id: "qwen3.8-chat" },
						],
					}),
					{ status: 200, headers: { "content-type": "application/json" } },
				),
			{ preconnect: () => {} },
		);
		const specs = await ustcModelManagerOptions({ apiKey: "test-key", fetch: fetchMock }).fetchDynamicModels?.();
		const models = specs?.map(buildModel) ?? [];
		const byId = new Map(models.map(model => [model.id, model]));

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
});
