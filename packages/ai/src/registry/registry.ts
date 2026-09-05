import type { KnownProvider } from "@oh-my-pi/pi-catalog";
import { authProviders } from "@oh-my-pi/pi-catalog/compat/auth";
import type { AuthProviderId, LoginProviderId } from "@oh-my-pi/pi-catalog/compat/auth-ids";
import { amazonBedrockTransport } from "./amazon-bedrock";
import { bedrockMantleTransport } from "./bedrock-mantle";
import { buildProviderDefinition, type ProviderTransport } from "./build";
import { cloudflareAiGatewayTransport } from "./cloudflare-ai-gateway";
import { museCodeTransport } from "./muse-code";
import type { ProviderDefinition } from "./types";
// ── Fork customization: USTC /login validation travels the iWAN tunnel ──
import { routeFetch as routeIwanFetch } from "../iwan/route";

/**
 * TypeScript-side request/model shaping for providers whose transport needs
 * code beside the KDL auth policy. Keyed by provider id; every other provider
 * is fully described by `rules/auth/<id>.kdl`.
 */
const TRANSPORTS: Record<string, ProviderTransport> = {
	"amazon-bedrock": amazonBedrockTransport,
	"bedrock-mantle": bedrockMantleTransport,
	"cloudflare-ai-gateway": cloudflareAiGatewayTransport,
	"muse-code": museCodeTransport,
};

/**
 * The single per-provider list, derived from the compiled auth stratum
 * (`@oh-my-pi/pi-catalog` `rules/auth/*.kdl`) in `/login` display order.
 * Adding a provider = one new `auth/<id>.kdl` (plus a `TRANSPORTS` entry when
 * it shapes requests in code). Every legacy structure (`OAuthProvider` union,
 * env map, login list, refresh/login dispatch, CLI callback maps) derives
 * from this registry.
 */

// ── Fork customization: USTC login validation through the iWAN tunnel ────────
// USTC's gateway (api.llm.ustc.edu.cn) is campus-only: the /login API-key
// validation request must go through the iWAN SOCKS5 tunnel. The declarative
// KDL api-key flow validates against the models endpoint using
// `callbacks.fetch`; we wrap USTC's login so the tunneled fetch (routeFetch)
// is injected. No tunnel up → routeFetch falls back to plain fetch (safe).
// Upstream merges may move this; keep the wrap for provider id "ustc".
function ustcTunneledLogin(login: NonNullable<ProviderDefinition["login"]>): NonNullable<ProviderDefinition["login"]> {
	return async callbacks => login({ ...callbacks, fetch: routeIwanFetch(callbacks.fetch ?? fetch) });
}

export const PROVIDER_REGISTRY: readonly ProviderDefinition[] = authProviders().map(policy => {
	const def = buildProviderDefinition(policy, TRANSPORTS[policy.id]);
	return policy.id === "ustc" && def.login ? { ...def, login: ustcTunneledLogin(def.login) } : def;
});

const BY_ID: Record<string, ProviderDefinition> = Object.fromEntries(PROVIDER_REGISTRY.map(p => [p.id, p]));

export function getProviderDefinition(id: string): ProviderDefinition | undefined {
	return BY_ID[id];
}

/** Compile-time completeness: every catalog chat-model provider must have an auth policy. */
type _MissingCatalogProviders = Exclude<KnownProvider, AuthProviderId>;
type _CheckRegistryComplete = _MissingCatalogProviders extends never
	? true
	: ["auth rules are missing catalog providers", _MissingCatalogProviders];
true satisfies _CheckRegistryComplete;

/** Loginable providers (those whose auth policy declares a `login` flow). */
export type OAuthProviderUnion = LoginProviderId;
