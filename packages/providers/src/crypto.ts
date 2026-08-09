/**
 * Synchronous SHA-256 + HMAC-SHA256 primitives for SigV4 request signing.
 *
 * Port note (clean-room): the Rust crate signs with the `hmac`/`sha2` crates
 * inside a *synchronous* `ProviderAdapter::prepare_chat_completions`. The
 * inventory (§3.8) suggests Web Crypto (`crypto.subtle`), but `crypto.subtle`
 * is asynchronous — adopting it would force the entire adapter trait surface to
 * become `async`, a behavioral divergence from the Rust pure-synchronous
 * contract. To preserve that contract we re-implement SHA-256 and HMAC-SHA256
 * directly in synchronous TypeScript here (the same primitives the Rust crate
 * delegates to `sha2`/`hmac` for).
 *
 * `test/crypto-sigv4.test.ts` proves these agree with `crypto.subtle` byte for
 * byte, so the mechanism swap is invisible. See the mechanism note in
 * `sigv4.ts`.
 */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const rotr = (x: number, n: number): number => (x >>> n) | (x << (32 - n));

/** Raw SHA-256 of `bytes`, returning the 32-byte digest. */
export function sha256(bytes: Uint8Array): Uint8Array {
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);

  const bitLen = bytes.length * 8;
  const withOne = bytes.length + 1;
  const totalLen = withOne + ((56 - (withOne % 64) + 64) % 64) + 8;
  const padded = new Uint8Array(totalLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  // 64-bit big-endian length in the final 8 bytes (high word is 0 for our inputs).
  const dv = new DataView(padded.buffer);
  dv.setUint32(totalLen - 4, bitLen >>> 0, false);
  dv.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);

  const w = new Uint32Array(64);
  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(offset + i * 4, false);
    for (let i = 16; i < 64; i++) {
      // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
      const s0 = rotr(w[i - 15]!, 7) ^ rotr(w[i - 15]!, 18) ^ (w[i - 15]! >>> 3);
      // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
      const s1 = rotr(w[i - 2]!, 17) ^ rotr(w[i - 2]!, 19) ^ (w[i - 2]! >>> 10);
      // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0;
    }

    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    let [a, b, c, d, e, f, g, hh] = [h[0]!, h[1]!, h[2]!, h[3]!, h[4]!, h[5]!, h[6]!, h[7]!];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
      const t1 = (hh + S1 + ch + K[i]! + w[i]!) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[0] = (h[0]! + a) >>> 0;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[1] = (h[1]! + b) >>> 0;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[2] = (h[2]! + c) >>> 0;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[3] = (h[3]! + d) >>> 0;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[4] = (h[4]! + e) >>> 0;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[5] = (h[5]! + f) >>> 0;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[6] = (h[6]! + g) >>> 0;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[7] = (h[7]! + hh) >>> 0;
  }

  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, h[i]!, false);
  return out;
}

/** HMAC-SHA256 of `message` under `key`, returning the 32-byte MAC. */
export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  const blockSize = 64;
  let k = key;
  if (k.length > blockSize) k = sha256(k);
  const padded = new Uint8Array(blockSize);
  padded.set(k);

  const inner = new Uint8Array(blockSize);
  const outer = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    inner[i] = padded[i]! ^ 0x36;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    outer[i] = padded[i]! ^ 0x5c;
  }
  const innerMsg = new Uint8Array(blockSize + message.length);
  innerMsg.set(inner);
  innerMsg.set(message, blockSize);
  const innerHash = sha256(innerMsg);

  const outerMsg = new Uint8Array(blockSize + innerHash.length);
  outerMsg.set(outer);
  outerMsg.set(innerHash, blockSize);
  return sha256(outerMsg);
}

/** Lowercase hex encoding of a byte buffer. */
export function hexEncode(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

const encoder = new TextEncoder();
/** UTF-8 encode a string to bytes. */
export const utf8 = (value: string): Uint8Array => encoder.encode(value);

/** Lowercase hex SHA-256 of `bytes`. */
export const hexSha256 = (bytes: Uint8Array): string => hexEncode(sha256(bytes));

/** Lowercase hex HMAC-SHA256. */
export const hexHmac = (key: Uint8Array, message: Uint8Array): string =>
  hexEncode(hmacSha256(key, message));
