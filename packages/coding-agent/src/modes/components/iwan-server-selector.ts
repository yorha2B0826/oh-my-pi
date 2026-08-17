import { Container, type SelectItem, SelectList, type SgrMouseEvent, Spacer, TruncatedText } from "@oh-my-pi/pi-tui";
import type { IwanStatus } from "../../iwan/service";
import { getSelectListTheme, theme } from "../../modes/theme/theme";
import { DynamicBorder } from "./dynamic-border";

const MAX_VISIBLE = 10;
const LIST_ROW_OFFSET = 4;

/** Network picker opened by `/iwan connect` for the controller-advertised servers. */
export class IwanServerSelectorComponent extends Container {
	#selectList: SelectList;

	constructor(
		servers: IwanStatus["servers"],
		selectedIndex: number | undefined,
		onSelect: (index: number) => void,
		onCancel: () => void,
	) {
		super();
		const items: SelectItem[] = servers.map((server, index) => ({
			value: String(index),
			label: server.name,
			description: `${server.host}:${server.port}`,
			hint: index === selectedIndex ? "current" : undefined,
		}));

		this.addChild(new DynamicBorder());
		this.addChild(new Spacer(1));
		this.addChild(new TruncatedText(theme.bold("Choose an iWAN network:")));
		this.addChild(new Spacer(1));

		this.#selectList = new SelectList(items, Math.min(Math.max(items.length, 1), MAX_VISIBLE), getSelectListTheme());
		const initial = selectedIndex ?? 0;
		if (initial >= 0 && initial < items.length) this.#selectList.setSelectedIndex(initial);
		this.#selectList.onSelect = item => onSelect(Number.parseInt(item.value, 10));
		this.#selectList.onCancel = onCancel;
		this.addChild(this.#selectList);
		this.addChild(new Spacer(1));
		this.addChild(new DynamicBorder());
	}

	/** Forward keyboard navigation and cancellation when the wrapper owns focus. */
	handleInput(keyData: string): void {
		this.#selectList.handleInput(keyData);
	}

	/** Route mouse selection through the title rows into the server list. */
	routeMouse(event: SgrMouseEvent, line: number, col: number): void {
		this.#selectList.routeMouse(event, line - LIST_ROW_OFFSET, col);
	}
}
