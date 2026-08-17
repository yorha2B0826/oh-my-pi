import { beforeAll, describe, expect, it } from "bun:test";
import { IwanServerSelectorComponent } from "@oh-my-pi/pi-coding-agent/modes/components/iwan-server-selector";
import { initTheme } from "@oh-my-pi/pi-coding-agent/modes/theme/theme";

beforeAll(async () => {
	await initTheme();
});

const servers = [
	{ name: "Campus", host: "campus.iwan.ustc", port: 443 },
	{ name: "Cernet", host: "cernet.iwan.ustc", port: 443 },
	{ name: "Mobile", host: "mobile.iwan.ustc", port: 443 },
	{ name: "Telecom", host: "telecom.iwan.ustc", port: 443 },
];

describe("IwanServerSelectorComponent", () => {
	it("starts on the current network and Enter resolves with its supplier index", () => {
		const selected: number[] = [];
		const component = new IwanServerSelectorComponent(
			servers,
			2,
			index => selected.push(index),
			() => {},
		);
		component.handleInput("\n");
		expect(selected).toEqual([2]);
	});

	it("arrow navigation moves the cursor and Enter resolves the newly-highlighted network", () => {
		const selected: number[] = [];
		const component = new IwanServerSelectorComponent(
			servers,
			3,
			index => selected.push(index),
			() => {},
		);
		component.handleInput("\x1b[A");
		component.handleInput("\n");
		expect(selected).toEqual([2]);
	});

	it("Escape and Ctrl+C both cancel without resolving", () => {
		let cancellations = 0;
		const resolve: number[] = [];

		const escapeComponent = new IwanServerSelectorComponent(
			servers,
			0,
			() => {},
			() => {
				cancellations += 1;
			},
		);
		escapeComponent.handleInput("\x1b");

		const ctrlCComponent = new IwanServerSelectorComponent(
			servers,
			0,
			() => {},
			() => {
				cancellations += 1;
			},
		);
		ctrlCComponent.handleInput("\x03");

		expect(cancellations).toBe(2);
		expect(resolve).toEqual([]);
	});
});
