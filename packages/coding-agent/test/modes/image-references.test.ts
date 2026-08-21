import { describe, expect, it } from "bun:test";
import {
	type PlaceholderKind,
	renderPlaceholders,
	shiftImageMarkers,
} from "@oh-my-pi/pi-coding-agent/modes/image-references";

function capture(text: string): {
	out: string;
	refs: Array<{ label: string; kind: PlaceholderKind; index: number }>;
} {
	const refs: Array<{ label: string; kind: PlaceholderKind; index: number }> = [];
	const out = renderPlaceholders(text, {
		renderText: t => t,
		renderReference: (label, kind, index) => {
			refs.push({ label, kind, index });
			return `<${kind}:${index}>`;
		},
	});
	return { out, refs };
}

describe("renderPlaceholders", () => {
	it("classifies image and paste markers with their index and full label", () => {
		const { out, refs } = capture("see [Image #1, 800x600] then [Paste #2, +30 lines] done");
		expect(refs).toEqual([
			{ label: "[Image #1, 800x600]", kind: "image", index: 1 },
			{ label: "[Paste #2, +30 lines]", kind: "paste", index: 2 },
		]);
		expect(out).toBe("see <image:1> then <paste:2> done");
	});

	it("matches the bare image form and the char-count paste form", () => {
		expect(capture("[Image #3]").refs[0]).toMatchObject({ kind: "image", index: 3 });
		expect(capture("[Paste #4, 1500 chars]").refs[0]).toMatchObject({ kind: "paste", index: 4 });
	});

	it("passes plain text straight through renderText with no references", () => {
		const { out, refs } = capture("no markers here");
		expect(refs).toHaveLength(0);
		expect(out).toBe("no markers here");
	});

	it("does not treat an unterminated marker as a reference", () => {
		// This is the half-eaten state atomic deletion prevents — it must render as plain text.
		const { refs } = capture("[Paste #1, +30 lines");
		expect(refs).toHaveLength(0);
	});

	it("preserves the adjacent attachment URI as plain text", () => {
		expect(capture("[Image #1, 800x600] attachment://1").out).toBe("<image:1> attachment://1");
	});
});

describe("shiftImageMarkers", () => {
	it("returns text unchanged when the offset is zero", () => {
		const text = "[Image #1] attachment://1 then [Image #2, 100x100] attachment://2";
		expect(shiftImageMarkers(text, 0)).toBe(text);
	});

	it("renumbers an image marker and its attachment URI by the offset", () => {
		expect(shiftImageMarkers("see [Image #1, 800x600] attachment://1", 3)).toBe(
			"see [Image #4, 800x600] attachment://4",
		);
	});

	it("does not shift unrelated attachment URI text", () => {
		expect(shiftImageMarkers("attachment://1 then [Image #1] attachment://9 and attachment://2", 3)).toBe(
			"attachment://1 then [Image #4] attachment://9 and attachment://2",
		);
	});

	it("shifts multiple image marker and URI pairs exactly once", () => {
		expect(shiftImageMarkers("[Image #1] attachment://1 then [Image #2, 100x100] attachment://2", 2)).toBe(
			"[Image #3] attachment://3 then [Image #4, 100x100] attachment://4",
		);
	});

	it("never touches Paste markers", () => {
		expect(shiftImageMarkers("[Image #1] [Paste #1, +5 lines]", 2)).toBe("[Image #3] [Paste #1, +5 lines]");
	});
});
