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

const STREAM_SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
  0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
  0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
  0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70,
  0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
  0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee,
  0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function streamRotateRight(value: number, amount: number): number {
  return (value >>> amount) | (value << (32 - amount));
}

function compressSha256Block(state: Uint32Array, block: Uint8Array): void {
  const view = new DataView(block.buffer, block.byteOffset, block.byteLength);
  const schedule = new Uint32Array(64);
  for (let i = 0; i < 16; i += 1) schedule[i] = view.getUint32(i * 4, false);
  for (let i = 16; i < 64; i += 1) {
    const prior15 = schedule[i - 15]!;
    const prior2 = schedule[i - 2]!;
    const s0 = streamRotateRight(prior15, 7) ^ streamRotateRight(prior15, 18) ^ (prior15 >>> 3);
    const s1 = streamRotateRight(prior2, 17) ^ streamRotateRight(prior2, 19) ^ (prior2 >>> 10);
    schedule[i] = (schedule[i - 16]! + s0 + schedule[i - 7]! + s1) >>> 0;
  }

  let [a, b, c, d, e, f, g, h] = [
    state[0]!,
    state[1]!,
    state[2]!,
    state[3]!,
    state[4]!,
    state[5]!,
    state[6]!,
    state[7]!,
  ];
  for (let i = 0; i < 64; i += 1) {
    const s1 = streamRotateRight(e, 6) ^ streamRotateRight(e, 11) ^ streamRotateRight(e, 25);
    const choose = (e & f) ^ (~e & g);
    const t1 = (h + s1 + choose + STREAM_SHA256_K[i]! + schedule[i]!) >>> 0;
    const s0 = streamRotateRight(a, 2) ^ streamRotateRight(a, 13) ^ streamRotateRight(a, 22);
    const majority = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (s0 + majority) >>> 0;
    h = g;
    g = f;
    f = e;
    e = (d + t1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (t1 + t2) >>> 0;
  }
  state[0] = (state[0]! + a) >>> 0;
  state[1] = (state[1]! + b) >>> 0;
  state[2] = (state[2]! + c) >>> 0;
  state[3] = (state[3]! + d) >>> 0;
  state[4] = (state[4]! + e) >>> 0;
  state[5] = (state[5]! + f) >>> 0;
  state[6] = (state[6]! + g) >>> 0;
  state[7] = (state[7]! + h) >>> 0;
}

/** Incremental SHA-256 for request bodies that must never be accumulated. */
export class StreamingSha256 {
  #state = new Uint32Array([
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
  ]);
  #pending = new Uint8Array(64);
  #pendingLength = 0;
  #byteLength = 0;

  update(bytes: Uint8Array): void {
    this.#byteLength += bytes.byteLength;
    let offset = 0;
    if (this.#pendingLength > 0) {
      const needed = 64 - this.#pendingLength;
      const copied = Math.min(needed, bytes.byteLength);
      this.#pending.set(bytes.subarray(0, copied), this.#pendingLength);
      this.#pendingLength += copied;
      offset += copied;
      if (this.#pendingLength === 64) {
        compressSha256Block(this.#state, this.#pending);
        this.#pendingLength = 0;
      }
    }
    while (offset + 64 <= bytes.byteLength) {
      compressSha256Block(this.#state, bytes.subarray(offset, offset + 64));
      offset += 64;
    }
    if (offset < bytes.byteLength) {
      this.#pending.set(bytes.subarray(offset), 0);
      this.#pendingLength = bytes.byteLength - offset;
    }
  }

  digest(): Uint8Array {
    const finalLength = this.#pendingLength < 56 ? 64 : 128;
    const finalBlock = new Uint8Array(finalLength);
    finalBlock.set(this.#pending.subarray(0, this.#pendingLength));
    finalBlock[this.#pendingLength] = 0x80;
    const bitLength = this.#byteLength * 8;
    const view = new DataView(finalBlock.buffer);
    view.setUint32(finalLength - 8, Math.floor(bitLength / 0x100000000), false);
    view.setUint32(finalLength - 4, bitLength >>> 0, false);

    const state = new Uint32Array(this.#state);
    for (let offset = 0; offset < finalLength; offset += 64) {
      compressSha256Block(state, finalBlock.subarray(offset, offset + 64));
    }
    const digest = new Uint8Array(32);
    const output = new DataView(digest.buffer);
    for (let i = 0; i < 8; i += 1) output.setUint32(i * 4, state[i]!, false);
    return digest;
  }
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
