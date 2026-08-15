import { createApiKeyLogin } from "./api-key-login";
import type { OAuthLoginCallbacks } from "./oauth/types";
import type { ProviderDefinition } from "./types";

export const loginUstc = createApiKeyLogin({
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

export const ustcProvider = {
	id: "ustc",
	name: "USTC",
	login: (cb: OAuthLoginCallbacks) => loginUstc(cb),
} as const satisfies ProviderDefinition;
