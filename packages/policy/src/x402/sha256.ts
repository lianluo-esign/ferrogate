/**
 * Minimal, dependency-free, synchronous SHA-256.
 *
 * The Rust `ferrogate-policy` x402 layer computes several deterministic
 * SHA-256 seals (`PaymentIntent::intent_hash_hex`, `RequestBodyHash::of`,
 * `PaymentAuthorization::decision_hash_hex`) synchronously via the `sha2`
 * crate. `crypto.subtle.digest` is async and `node:crypto` is not available in
 * the Workers runtime, so this pure-TS implementation keeps the seals sync and
 * runtime-portable while producing byte-for-byte identical digests.
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

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

/** SHA-256 of `data`, returned as 32 raw bytes. */
export function sha256(data: Uint8Array): Uint8Array {
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);

  // Pad: 0x80, zeros, then 64-bit big-endian bit length.
  const bitLen = data.length * 8;
  const withOne = data.length + 1;
  const total = withOne + ((56 - (withOne % 64) + 64) % 64) + 8;
  const msg = new Uint8Array(total);
  msg.set(data);
  msg[data.length] = 0x80;
  // 64-bit length; JS bit-ops are 32-bit, so split hi/lo.
  const hi = Math.floor(bitLen / 0x100000000);
  const lo = bitLen >>> 0;
  const dv = new DataView(msg.buffer);
  dv.setUint32(total - 8, hi);
  dv.setUint32(total - 4, lo);

  const w = new Uint32Array(64);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
      const w15 = w[i - 15]!;
      // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
      const w2 = w[i - 2]!;
      const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3);
      const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10);
      // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) | 0;
    }
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    let a = h[0]!;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    let b = h[1]!;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    let c = h[2]!;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    let d = h[3]!;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    let e = h[4]!;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    let f = h[5]!;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    let g = h[6]!;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    let hh = h[7]!;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
      const t1 = (hh + S1 + ch + K[i]! + w[i]!) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[0] = (h[0]! + a) | 0;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[1] = (h[1]! + b) | 0;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[2] = (h[2]! + c) | 0;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[3] = (h[3]! + d) | 0;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[4] = (h[4]! + e) | 0;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[5] = (h[5]! + f) | 0;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[6] = (h[6]! + g) | 0;
    // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
    h[7] = (h[7]! + hh) | 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  // biome-ignore lint/style/noNonNullAssertion: index is loop-bounded within a fixed-length buffer; the assertion is load-bearing under noUncheckedIndexedAccess and a runtime guard would burden a crypto hot path
  for (let i = 0; i < 8; i++) outView.setUint32(i * 4, h[i]!);
  return out;
}

/** Lowercase hex of a byte slice (mirrors the crate's `hex_lower`). */
export function hexLower(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

const encoder = new TextEncoder();

/**
 * Incremental byte accumulator mirroring the crate's `hasher.update(...)`
 * sequences. Supports appending UTF-8 strings and raw bytes, then finalizing to
 * a lowercase-hex SHA-256 digest.
 */
export class Sha256Builder {
  private chunks: Uint8Array[] = [];

  pushStr(value: string): this {
    this.chunks.push(encoder.encode(value));
    return this;
  }

  pushBytes(bytes: Uint8Array): this {
    this.chunks.push(bytes);
    return this;
  }

  pushByte(byte: number): this {
    this.chunks.push(Uint8Array.of(byte & 0xff));
    return this;
  }

  digestHex(): string {
    let len = 0;
    for (const c of this.chunks) len += c.length;
    const all = new Uint8Array(len);
    let off = 0;
    for (const c of this.chunks) {
      all.set(c, off);
      off += c.length;
    }
    return hexLower(sha256(all));
  }
}
