import { Database } from "bun:sqlite";
import { afterEach, describe, expect, test, vi } from "bun:test";
import { AuthStorage, SqliteAuthCredentialStore } from "@oh-my-pi/pi-ai/auth-storage";
import { getOAuthProviders } from "@oh-my-pi/pi-ai/registry/oauth";
import { setIwanRoutePort } from "@oh-my-pi/pi-ai/iwan/route";
import { PROVIDER_REGISTRY } from "@oh-my-pi/pi-ai/registry/registry";
import type { FetchImpl } from "@oh-my-pi/pi-ai/types";

const ORIGINAL_ENV = {
	USTC_API_KEY: Bun.env.USTC_API_KEY,
} as const;

afterEach(() => {
	for (const [name, value] of Object.entries(ORIGINAL_ENV)) {
		if (value === undefined) delete Bun.env[name];
		else Bun.env[name] = value;
	}
	vi.restoreAllMocks();
	setIwanRoutePort(undefined);
});

describe("USTC login wiring (fork: iWAN tunnel)", () => {
	test("registers USTC in the login provider selector", () => {
		const provider = getOAuthProviders().find(item => item.id === "ustc");
		expect(provider).toBeDefined();
		expect(provider?.name).toBe("USTC");
	});

	test("registry entry wraps USTC login with the iWAN routeFetch bridge", () => {
		const entry = PROVIDER_REGISTRY.find(item => item.id === "ustc");
		expect(entry).toBeDefined();
		expect(entry?.login).toBeDefined();
	});

	test("AuthStorage.login('ustc') validation goes through the tunneled fetch when route port is set", async () => {
		// Route port set → routeFetch proxies through the SOCKS bridge, which
		// (with no real server) fails with a connection error instead of
		// reaching the mock. That proves the tunnel was injected: plain fetch
		// would have hit the mock and returned 200.
		setIwanRoutePort(4242);
		const fetchMock: FetchImpl = vi.fn(async () => new Response("{}", { status: 200 }));

		const store = new SqliteAuthCredentialStore(new Database(":memory:"));
		const storage = new AuthStorage(store);
		await storage.reload();

		// Tunneled fetch to a dead SOCKS port → connection refused error,
		// NOT the mock's success. This distinguishes tunneled from direct.
		await expect(
			storage.login("ustc", {
				onAuth: () => {},
				onPrompt: async () => "sk-test-ustc-key",
				onProgress: () => {},
				fetch: fetchMock,
			}),
		).rejects.toThrow();

		// The mock must NOT have been called (request never went direct).
		expect(fetchMock).not.toHaveBeenCalled();
		store.close();
	});

	test("AuthStorage.login('ustc') validates directly when no tunnel is up", async () => {
		// No route port → routeFetch falls back to the caller's fetch.
		setIwanRoutePort(undefined);
		const fetchMock: FetchImpl = vi.fn(
			async () =>
				new Response(JSON.stringify({ data: [{ id: "glm-5.3-flash" }] }), {
					status: 200,
					headers: { "Content-Type": "application/json" },
				}),
		);

		const store = new SqliteAuthCredentialStore(new Database(":memory:"));
		const storage = new AuthStorage(store);
		await storage.reload();

		await storage.login("ustc", {
			onAuth: () => {},
			onPrompt: async () => "sk-valid-ustc",
			onProgress: () => {},
			fetch: fetchMock,
		});

		const credential = await storage.get("ustc");
		expect(credential).toEqual({ type: "api_key", key: "sk-valid-ustc", source: "login" });
		expect(fetchMock).toHaveBeenCalled();
		store.close();
	});
});
