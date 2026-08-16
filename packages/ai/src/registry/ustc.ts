import { routeFetch } from "../iwan/route";
import { createApiKeyLogin } from "./api-key-login";
import type { OAuthLoginCallbacks } from "./oauth/types";
import type { ProviderDefinition } from "./types";

const baseLoginUstc = createApiKeyLogin({
	providerLabel: "USTC",
	instructions: "Create or copy your API key from the USTC LLM gateway console",
	promptMessage: "Paste your USTC API key",
	placeholder: "sk-...",
	validation: {
		kind: "models-endpoint",
		provider: "ustc",
		modelsUrl: "https://api.llm.ustc.edu.cn/v1/models",
	},
});

/**
 * USTC 网关 (api.llm.ustc.edu.cn) 是校内服务,/login 的 API key 验证请求
 * 必须走 iWAN 隧道才能到达——只有 USTC 供应商有此需求。
 *
 * 这里只给 USTC 的验证 fetch 包一层 routeFetch:
 *  - 隧道已连接 → 验证请求 (modelsUrl) 走 SOCKS5 隧道
 *  - 隧道未连接 → 回退到原 fetch(与其他供应商行为一致)
 *  - 非 USTC 域名 → 完全不受影响
 *
 * 其他供应商的验证路径不经过此包装,保持原样。
 */
export const loginUstc = async (options: OAuthLoginCallbacks): Promise<string> => {
	return baseLoginUstc({
		...options,
		fetch: routeFetch(options.fetch ?? fetch),
	});
};

export const ustcProvider = {
	id: "ustc",
	name: "USTC",
	login: (cb: OAuthLoginCallbacks) => loginUstc(cb),
} as const satisfies ProviderDefinition;
