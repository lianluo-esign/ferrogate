/**
 * BLAKE2b-512, RFC 7693.
 *
 * ## Why this file exists at all
 *
 * `crates/ferrogate-auth-service/src/api_key.rs::verify_virtual_api_key_secret`
 * accepts TWO stored hash constructions:
 *
 * ```rust
 * if let Some(expected) = expected_hash.strip_prefix("sha256:")  { … Sha256 … }
 * if let Some(expected) = expected_hash.strip_prefix("blake2b:") { … Blake2b512 … }
 * ```
 *
 * Only `sha256:` is ever *written* (`hash_virtual_api_key_secret`), but
 * `blake2b:` is a live READ path: any row provisioned by an older FerroGate — or
 * imported from one — carries it. WebCrypto has SHA-256 and no BLAKE2b, so
 * dropping this would have silently turned every `blake2b:` row into a
 * permanently-401 key. That is exactly the "silently drop behavior" failure
 * HARD RULE 6 forbids, and it would be invisible until a customer's key stopped
 * working in production, so the digest is implemented here instead.
 *
 * Clean-room: written from the RFC 7693 specification (IV, SIGMA, the G
 * quarter-round, the 12-round compression F), not translated from the `blake2`
 * crate. `test/keys/hash.test.ts` pins it against the RFC's own published
 * vectors plus the abbreviated-output and long-input cases, so a transcription
 * error in SIGMA or a rotation constant cannot pass.
 *
 * Correctness over speed: 64-bit words are `BigInt`. This runs only for the
 * legacy `blake2b:` rows, never for the `sha256:` hot path, and a virtual-key
 * secret is ~51 bytes — one compression block.
 */

/** 2^64 - 1. Every add/rotate is masked back into 64 bits with this. */
const MASK64 = (1n << 64n) - 1n;

/**
 * RFC 7693 §2.6 IV — the first 64 bits of the fractional parts of the square
 * roots of the first 8 primes (identical to the SHA-512 IV).
 */
const IV: readonly bigint[] = [
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n,
];

/** RFC 7693 §2.7 SIGMA — the 10 message-word permutations, reused for 12 rounds. */
const SIGMA: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/** Bytes per compression block (BLAKE2b `bb`). */
const BLOCK_BYTES = 128;

/** Rotate a 64-bit word right by `bits` (RFC 7693 §2.3 `>>>`). */
function rotr64(word: bigint, bits: bigint): bigint {
  return ((word >> bits) | (word << (64n - bits))) & MASK64;
}

/** The G mixing function, RFC 7693 §3.1. Rotations are 32, 24, 16, 63. */
function mix(v: bigint[], a: number, b: number, c: number, d: number, x: bigint, y: bigint): void {
  v[a] = ((v[a] as bigint) + (v[b] as bigint) + x) & MASK64;
  v[d] = rotr64((v[d] as bigint) ^ (v[a] as bigint), 32n);
  v[c] = ((v[c] as bigint) + (v[d] as bigint)) & MASK64;
  v[b] = rotr64((v[b] as bigint) ^ (v[c] as bigint), 24n);
  v[a] = ((v[a] as bigint) + (v[b] as bigint) + y) & MASK64;
  v[d] = rotr64((v[d] as bigint) ^ (v[a] as bigint), 16n);
  v[c] = ((v[c] as bigint) + (v[d] as bigint)) & MASK64;
  v[b] = rotr64((v[b] as bigint) ^ (v[c] as bigint), 63n);
}

/**
 * Compression function F, RFC 7693 §3.2.
 *
 * @param h      chained state, mutated in place
 * @param block  128 message bytes (already zero-padded if final)
 * @param offset counter `t` — total bytes fed in *including* this block
 * @param last   the `f0` finalization flag
 */
function compress(h: bigint[], block: Uint8Array, offset: bigint, last: boolean): void {
  const m: bigint[] = new Array<bigint>(16);
  const view = new DataView(block.buffer, block.byteOffset, block.byteLength);
  for (let i = 0; i < 16; i += 1) {
    // Little-endian, per RFC 7693 §2.1 ("all multi-byte values are LE").
    m[i] = view.getBigUint64(i * 8, true);
  }

  const v: bigint[] = [...h, ...IV];
  v[12] = (v[12] as bigint) ^ (offset & MASK64);
  // t is 128-bit in the spec; a virtual-key secret never reaches 2^64 bytes, so
  // the high half is always zero and v[13] is left untouched — stated, not
  // assumed, because a wrong xor here would still pass short-input vectors.
  v[13] = (v[13] as bigint) ^ ((offset >> 64n) & MASK64);
  if (last) {
    v[14] = (v[14] as bigint) ^ MASK64;
  }

  for (let round = 0; round < 12; round += 1) {
    const s = SIGMA[round % 10] as readonly number[];
    mix(v, 0, 4, 8, 12, m[s[0] as number] as bigint, m[s[1] as number] as bigint);
    mix(v, 1, 5, 9, 13, m[s[2] as number] as bigint, m[s[3] as number] as bigint);
    mix(v, 2, 6, 10, 14, m[s[4] as number] as bigint, m[s[5] as number] as bigint);
    mix(v, 3, 7, 11, 15, m[s[6] as number] as bigint, m[s[7] as number] as bigint);
    mix(v, 0, 5, 10, 15, m[s[8] as number] as bigint, m[s[9] as number] as bigint);
    mix(v, 1, 6, 11, 12, m[s[10] as number] as bigint, m[s[11] as number] as bigint);
    mix(v, 2, 7, 8, 13, m[s[12] as number] as bigint, m[s[13] as number] as bigint);
    mix(v, 3, 4, 9, 14, m[s[14] as number] as bigint, m[s[15] as number] as bigint);
  }

  for (let i = 0; i < 8; i += 1) {
    h[i] = (h[i] as bigint) ^ (v[i] as bigint) ^ (v[i + 8] as bigint);
  }
}

/**
 * Unkeyed BLAKE2b digest of `input`.
 *
 * @param outputBytes digest length, 1..=64. The `blake2b:` rows this port has
 *   to read are all Blake2b**512** (`crates/…/api_key.rs` uses `Blake2b512`),
 *   which is the default here; the parameter exists because the RFC's own test
 *   vectors exercise shorter outputs and pinning those is what proves the
 *   parameter block is encoded correctly.
 */
export function blake2b(input: Uint8Array, outputBytes = 64): Uint8Array {
  if (!Number.isInteger(outputBytes) || outputBytes < 1 || outputBytes > 64) {
    throw new RangeError(`blake2b output length must be 1..=64, got ${outputBytes}`);
  }

  const h: bigint[] = [...IV];
  // Parameter block word 0: digest_length | (key_length << 8) | (fanout << 16)
  // | (depth << 24). Unkeyed sequential hashing ⇒ key_length 0, fanout 1,
  // depth 1 ⇒ 0x01010000 ^ outputBytes.
  h[0] = (h[0] as bigint) ^ BigInt(0x01010000 ^ outputBytes);

  let consumed = 0;
  // Every block EXCEPT the last is compressed with last=false. The loop stops
  // with at least one byte (or, for the empty input, zero bytes) left over, so
  // a message that is an exact multiple of 128 still gets its final block
  // finalized rather than compressed twice.
  while (input.length - consumed > BLOCK_BYTES) {
    compress(
      h,
      input.subarray(consumed, consumed + BLOCK_BYTES),
      BigInt(consumed + BLOCK_BYTES),
      false,
    );
    consumed += BLOCK_BYTES;
  }

  const finalBlock = new Uint8Array(BLOCK_BYTES);
  finalBlock.set(input.subarray(consumed));
  compress(h, finalBlock, BigInt(input.length), true);

  const digest = new Uint8Array(64);
  const out = new DataView(digest.buffer);
  for (let i = 0; i < 8; i += 1) {
    out.setBigUint64(i * 8, h[i] as bigint, true);
  }
  return digest.subarray(0, outputBytes);
}
