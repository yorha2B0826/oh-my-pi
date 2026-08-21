/**
 * Transparent inline-base64 retry for URL-decorated requests.
 *
 * A provider that fails to fetch a blob URL rejects the whole request (e.g.
 * Vertex 400s on a bad `fileUri`, Anthropic errors on an unfetchable source)
 * before emitting any content. When the first terminal event of a decorated
 * request is an error with zero content events forwarded, this wrapper
 * re-issues the identical request with URLs stripped back to inline base64
 * and pipes the retry through — the consumer sees one clean stream.
 *
 * The provider is quarantined from future decoration only when the inline
 * retry *succeeds*: that is proof the URLs were the problem, so unrelated
 * failures (auth, rate limits, outages) never misclassify.
 */

import type { StreamFn } from "@oh-my-pi/pi-agent-core";
import { AssistantMessageEventStream } from "@oh-my-pi/pi-ai/utils/event-stream";
import { logger } from "@oh-my-pi/pi-utils";
import { contextHasImageUrls } from "./context-images";
import type { ImageUrlService } from "./service";

/** Wrap `base` with the inline retry; identity when no broker is active. */
export function wrapStreamFnWithBlobUrlFallback(base: StreamFn, broker: ImageUrlService | undefined): StreamFn {
	if (!broker) return base;
	return (model, context, options) => {
		if (!contextHasImageUrls(context)) return base(model, context, options);

		const outer = new AssistantMessageEventStream();
		// `start` fires pre-flight, before the provider accepts the request, so
		// it neither counts as content nor repeats when the retry stream opens.
		let sawStart = false;
		let sawContent = false;

		const pipe = async (stream: AssistantMessageEventStream): Promise<boolean> => {
			let succeeded = false;
			for await (const event of stream) {
				if (event.type === "start") {
					if (sawStart) continue;
					sawStart = true;
				} else if (event.type === "done") {
					succeeded = true;
				}
				outer.push(event);
			}
			return succeeded;
		};

		const run = async (): Promise<void> => {
			const inner = await base(model, context, options);
			for await (const event of inner) {
				if (event.type === "start") {
					if (!sawStart) {
						sawStart = true;
						outer.push(event);
					}
					continue;
				}
				if (event.type === "error" && !sawContent && event.error.stopReason === "error") {
					logger.warn("blob-broker: provider rejected request with image URLs; retrying inline", {
						provider: model.provider,
						model: model.id,
						error: event.error.errorMessage?.slice(0, 200),
					});
					const retry = await base(model, await broker.inlineContext(context), options);
					if (await pipe(retry)) {
						broker.quarantine(model.provider, "request failed with image URLs but succeeded inline");
					}
					return;
				}
				sawContent = true;
				outer.push(event);
			}
		};

		void run().catch(error => {
			if (!outer.done) outer.fail(error);
		});
		return outer;
	};
}
