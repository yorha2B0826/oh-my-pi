/**
 * Blob URL backends: give outgoing images an externally fetchable URL.
 *
 * `LocalBlobBackend` runs everything in-process — either a loopback HTTP
 * server behind a tunnel/direct exposure (serve mode) or a push-once uploader
 * (upload mode). The daemon-shared variant in `daemon.ts` implements the same
 * {@link BlobBackend} contract over the project blob daemon so every omp
 * process reuses one exposure and one URL per blob.
 *
 * Design invariants:
 * - **Stable, multi-use URLs.** A blob's URL is keyed by content hash for the
 *   backend's lifetime. Anthropic silently forgets images unless a resent turn
 *   is byte-identical, OpenAI's fetcher issues two GETs per image, and any
 *   provider may refetch on a cache miss — single-use tokens would break all
 *   three.
 * - **Unguessable URL is the only authorization.** 128-bit random token per
 *   blob. `User-Agent` attribution (pi-catalog fetcher registry) is telemetry,
 *   never a gate.
 * - **Fail toward inline.** Missing binary, tunnel crash, failed upload, or a
 *   provider rejection all degrade to inline base64.
 */

import { logger } from "@oh-my-pi/pi-utils";
import type { BlobDestinationId } from "./destinations";
import { type ExposureConfig, type ExposureKind, startExposure } from "./exposure";
import type {
	BlobBrokerPurgeRequest,
	BlobBrokerPurgeResponse,
	BlobBrokerWorkerConfig,
	BlobStoreStatus,
} from "./protocol";
import type { BlobPublication, BlobUploadRequest } from "./publication";
import { BlobRegistry, type BlobRegistryEntry, EXT_BY_MIME, type LazyBlobFetcher } from "./store";
import { DestinationUnavailableError } from "./uploader-runtime";
import { createConfiguredUploader, memoizeUploader } from "./uploaders";

/** Turns blob bytes into externally fetchable publications. */
export interface BlobBackend {
	/** Whether render-on-fetch blobs are supported (serve mode only). */
	readonly supportsLazy: boolean;
	/**
	 * Stable publication for the content behind `key`, or `null` when the backend
	 * cannot provide one. `getBytes` is invoked only when the key is unknown —
	 * persisted or already-registered blobs never decode or transfer bytes.
	 */
	ensureBlob(key: string, mimeType: string, getBytes: () => Uint8Array): Promise<BlobPublication | null>;
	/** Stable publication served by invoking `fetcher` on demand; `null` when unsupported. */
	ensureLazy(key: string, mimeType: string, fetcher: LazyBlobFetcher): Promise<BlobPublication | null>;
	/** Release backend-owned stores, servers, and exposure processes. */
	stop(): void;
}

const SERVE_KINDS: Readonly<Partial<Record<BlobDestinationId, true>>> = {
	cloudflared: true,
	ngrok: true,
	tailscale: true,
	ssh: true,
	direct: true,
};

/** Whether a destination exposes the local blob server. */
export function isServeKind(kind: BlobDestinationId): kind is ExposureKind {
	return SERVE_KINDS[kind] === true;
}

/** Whether a configured destination bypasses the local serving path. */
export function isUploaderKind(kind: BlobDestinationId): boolean {
	return !isServeKind(kind);
}

/** In-process backend hosting the store, exposure, or uploader directly. */
export class LocalBlobBackend implements BlobBackend {
	#config: BlobBrokerWorkerConfig;
	#store: BlobRegistry;
	#server: Bun.Server<undefined> | undefined;
	#exposure: { baseUrl: string; stop(): void } | undefined;
	#startPromise: Promise<string | null> | undefined;
	#upload: ((hash: string, request: BlobUploadRequest) => Promise<BlobPublication | null>) | undefined;
	#dead = false;

	/** Create one local serving or configured upload backend. */
	constructor(config: BlobBrokerWorkerConfig) {
		this.#config = config;
		const servesBlobs = isServeKind(config.kind);
		const uploader = servesBlobs
			? null
			: createConfiguredUploader(config.kind, {
					options: config.options,
					credentials: config.credentials,
				});
		if (!servesBlobs && !uploader) {
			throw new DestinationUnavailableError(config.kind, "no built-in uploader or serving adapter is implemented");
		}
		this.#store = new BlobRegistry({ persist: config.persist });
		if (uploader) this.#upload = memoizeUploader(uploader);
	}

	/** Whether this backend can render blobs on fetch. */
	get supportsLazy(): boolean {
		return this.#upload === undefined;
	}

	/**
	 * Start the local server and exposure once (serve mode); resolves to the
	 * public base URL or `null` after a failure (sticky for this backend).
	 */
	ensureStarted(): Promise<string | null> {
		if (this.#upload) return Promise.resolve(null);
		this.#startPromise ??= this.#start();
		return this.#startPromise;
	}

	async #start(): Promise<string | null> {
		try {
			this.#server = Bun.serve({
				hostname: this.#config.bindHost,
				port: 0,
				fetch: request => this.#store.serve(request),
			});
			this.#server.unref();
			const port = this.#server.port;
			if (port === undefined) throw new Error("blob server bound without a TCP port");
			const kind = this.#config.kind;
			if (!isServeKind(kind)) {
				throw new DestinationUnavailableError(kind, "the destination does not expose the local blob server");
			}
			const exposureConfig: ExposureConfig = {
				kind,
				publicBaseUrl: this.#config.publicBaseUrl,
				bindHost: this.#config.bindHost,
				sshTarget: this.#config.sshTarget,
				sshRemotePort: this.#config.sshRemotePort,
			};
			const exposure = await startExposure(exposureConfig, port);
			this.#exposure = exposure;
			void exposure.exited?.then(() => {
				if (this.#dead) return;
				this.#dead = true;
				logger.warn("blob-broker: exposure process exited; image URLs disabled, falling back to inline base64", {
					kind: this.#config.kind,
				});
			});
			logger.info("blob-broker: serving image URLs", {
				kind: this.#config.kind,
				baseUrl: exposure.baseUrl,
				localPort: port,
			});
			return exposure.baseUrl;
		} catch (error) {
			this.#dead = true;
			this.#server?.stop(true);
			logger.warn("blob-broker: exposure failed to start; image URLs disabled, falling back to inline base64", {
				kind: this.#config.kind,
				error: error instanceof Error ? error.message : String(error),
			});
			return null;
		}
	}

	/** Ensure eager bytes have a stable publication. */
	async ensureBlob(key: string, mimeType: string, getBytes: () => Uint8Array): Promise<BlobPublication | null> {
		if (this.#dead) return null;
		if (this.#upload) {
			const existing = this.#store.lookup(key);
			if (
				existing?.publication &&
				(existing.publication.expiresAt === undefined || existing.publication.expiresAt > Date.now())
			) {
				return existing.publication;
			}
			const bytes = getBytes();
			if (bytes.byteLength === 0) return null;
			const publication = await this.#upload(key, {
				bytes,
				mimeType,
				extension: EXT_BY_MIME[mimeType] ?? "bin",
			});
			if (publication) this.#store.recordPublication(key, mimeType, publication);
			return publication;
		}
		const baseUrl = await this.ensureStarted();
		if (!baseUrl || this.#dead) return null;
		const existing = this.#store.lookup(key);
		if (existing) return this.#publish(key, baseUrl, existing);
		const bytes = getBytes();
		if (bytes.byteLength === 0) return null;
		return this.#publish(key, baseUrl, await this.#store.registerBytes(key, mimeType, bytes));
	}

	/** Probe for an existing (persisted or live) registration without bytes. */
	async lookupBlob(key: string): Promise<BlobPublication | null> {
		if (this.#dead) return null;
		if (this.#upload) {
			const publication = this.#store.lookup(key)?.publication;
			return publication && (publication.expiresAt === undefined || publication.expiresAt > Date.now())
				? publication
				: null;
		}
		const baseUrl = await this.ensureStarted();
		if (!baseUrl || this.#dead) return null;
		const existing = this.#store.lookup(key);
		return existing ? this.#publish(key, baseUrl, existing) : null;
	}

	/** Ensure a lazy producer has a stable publication. */
	async ensureLazy(key: string, mimeType: string, fetcher: LazyBlobFetcher): Promise<BlobPublication | null> {
		if (this.#dead || this.#upload) return null;
		const baseUrl = await this.ensureStarted();
		if (!baseUrl || this.#dead) return null;
		return this.#publish(key, baseUrl, this.#store.registerLazy(key, mimeType, fetcher));
	}

	#publish(key: string, baseUrl: string, entry: BlobRegistryEntry): BlobPublication {
		const ttlMs = this.#config.persist?.ttlMs ?? 0;
		const publication: BlobPublication = {
			...entry.publication,
			url: `${baseUrl}/${entry.path}`,
			destination: this.#config.kind,
			bytes: entry.bytes,
			...(ttlMs > 0 ? { expiresAt: Date.now() + ttlMs } : {}),
		};
		this.#store.setPublication(key, publication);
		return publication;
	}

	/** Return current serving-store counters and fetch attribution. */
	storeStatus(): BlobStoreStatus {
		return this.#store.status();
	}

	/** Remove registrations selected for local and remote cleanup. */
	purge(request: BlobBrokerPurgeRequest): BlobBrokerPurgeResponse {
		return this.#store.purge(request);
	}

	/** Local server origin for tests, diagnostics, and the daemon worker. */
	get localBaseUrl(): string | null {
		return this.#server ? `http://${this.#config.bindHost}:${this.#server.port}` : null;
	}

	/** Stop serving and flush persistent registry state. */
	stop(): void {
		this.#dead = true;
		this.#store.flush();
		this.#exposure?.stop();
		this.#server?.stop(true);
	}
}
