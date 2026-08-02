/**
 * Digest + randomness helpers for the asset surface.
 *
 * Clean-room port of the Rust helpers the asset service leaned on:
 *  - `ferrogate_storage::sha256_hex` (content hash, re-verified on every read),
 *  - `asset_presign::random_hex_128` (128 bits of OS randomness, hex),
 *  - `ferrogate_providers::sigv4::{hmac_bytes, hex_hmac}` (SigV4 signing key).
 *
 * Everything runs on WebCrypto, which is available in `workerd` — no Node
 * `crypto` module, no `nodejs_compat` dependency.
 */

const HEX = "0123456789abcdef";

/** Lowercase hex of an arbitrary byte string. */
export function toHex(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = "";
  for (const byte of view) {
    out += HEX[byte >> 4];
    out += HEX[byte & 0x0f];
  }
  return out;
}

/** SHA-256 of raw bytes, hex-encoded — Rust `sha256_hex`. */
export async function sha256Hex(bytes: ArrayBuffer | Uint8Array | string): Promise<string> {
  const data = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  // `crypto.subtle.digest` wants a BufferSource; a Uint8Array view qualifies.
  const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return toHex(digest);
}

/** Raw HMAC-SHA256 bytes — the SigV4 key-derivation primitive. */
export async function hmacSha256(
  key: ArrayBuffer | Uint8Array,
  message: string | Uint8Array,
): Promise<Uint8Array> {
  const keyData = key instanceof Uint8Array ? key : new Uint8Array(key);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const data = typeof message === "string" ? new TextEncoder().encode(message) : message;
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, data as BufferSource);
  return new Uint8Array(signature);
}

/**
 * 128 bits of CSPRNG output, hex-encoded (32 chars) — Rust `random_hex_128`.
 * Used for `upload_id` and for the unique per-attempt object name that makes
 * concurrent first-pushes of one version non-clobbering (Rust issue #369).
 */
export function randomHex128(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

/** True for a canonical 64-character hex SHA-256 — Rust `is_hex_sha256`. */
export function isHexSha256(value: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(value);
}

/** Constant-time-ish string compare for signature/digest comparisons. */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
