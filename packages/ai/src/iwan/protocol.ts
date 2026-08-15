/**
 * iWAN protocol primitives: constants, packet framing, and the crypto used to
 * talk to USTC's campus VPN controller and recover server credentials.
 *
 * This mirrors `ustcode/packages/ustcode/src/iwan/protocol.ts` but uses only
 * `node:crypto`, avoiding any new runtime dependency. The Rust side
 * (`crates/pi-iwan`) owns the tunnel/data-plane crypto; what stays here is the
 * TS-only login path: OAuth parameter assembly, controller request signing,
 * and server-password decryption.
 */

import { createDecipheriv, createHash, createHmac, randomBytes } from "node:crypto";

export const DOMAIN = "iwan.ustc";
export const APP_SECRET = "ca6a3532abd2986a03b86b3a";
export const CONTROLLER = "https://crtl.ivpn.ustc.edu.cn";
export const AUTH_URL = "https://auth.ivpn.ustc.edu.cn/login/oauth/authorize";
export const TOKEN_URL = "https://auth.ivpn.ustc.edu.cn/api/login/oauth/access_token";
export const CLIENT_ID = "afc6479ffb531d71daef";
export const REDIRECT_URI = "com.panabit.mobile://oauth2redirect";
export const SCOPE = "openid profile email offline_access";
export const CONTROLLER_APP_ID = "controller-ustc";

/** A controller-advertised VPN server plus its (encrypted) server password. */
export interface IwanServer {
	name: string;
	host: string;
	port: number;
	username: string;
	passWord: string;
}

export function md5(data: Uint8Array | string): Buffer {
	return createHash("md5").update(data).digest();
}

export function sha256(data: Uint8Array | string): Buffer {
	return createHash("sha256").update(data).digest();
}

export function hmacSha256(key: Uint8Array | string, data: Uint8Array | string): Buffer {
	return createHmac("sha256", key).update(data).digest();
}

export function hex(data: Uint8Array): string {
	return Buffer.from(data).toString("hex");
}

export function base64Url(data: Uint8Array): string {
	return Buffer.from(data).toString("base64url");
}

export function base64UrlDecode(value: string): Buffer {
	return Buffer.from(value, "base64url");
}

export function randomHex(bytes: number): string {
	return hex(randomBytes(bytes));
}

/** Decrypt a controller-provided server password (AES-256-GCM, key derived from APP_SECRET|domain|username). */
export function decryptServerPassword(server: IwanServer): string {
	const key = sha256(`${APP_SECRET}|${DOMAIN}|${server.username}`);
	const encoded = base64UrlDecode(server.passWord);
	if (encoded.length < 28) throw new Error("iWAN server password is too short");
	const plaintext = aesGcmDecrypt(
		key,
		encoded.subarray(0, 12),
		encoded.subarray(12),
		Buffer.from(`${DOMAIN}|${server.username}`),
	);
	return plaintext.toString("utf8");
}

function aesGcmDecrypt(key: Buffer, nonce: Uint8Array, ciphertextAndTag: Uint8Array, aad: Uint8Array): Buffer {
	if (ciphertextAndTag.byteLength < 16) throw new Error("AES-GCM ciphertext is missing its tag");
	const ciphertext = ciphertextAndTag.subarray(0, -16);
	const tag = ciphertextAndTag.subarray(-16);
	const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(nonce));
	decipher.setAAD(Buffer.from(aad));
	decipher.setAuthTag(Buffer.from(tag));
	return Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]);
}

/**
 * Build the controller POST signature: HMAC-SHA256 over the canonical request
 * line, with `APP_SECRET` as the key.
 */
export function controllerSignature(endpoint: string, text: string, timestamp: string, nonce: string): string {
	const canonical = ["POST", endpoint, "", hex(sha256(text)), timestamp, nonce].join("\n");
	return hex(hmacSha256(APP_SECRET, canonical));
}
