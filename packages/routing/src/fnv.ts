/**
 * FNV-1a 64-bit hashing and the deterministic rollout bucket.
 *
 * Clean-room port of the private `fnv1a64` + public `rollout_bucket` from the
 * Rust crate `ferrogate-routing` (`rollout.rs`). These MUST produce
 * byte-identical bucketing to the Rust implementation: they gate live traffic
 * and tests assert exact distributions, so the FNV constants and the
 * `salt\0sticky_key` input framing are preserved verbatim.
 */

/** FNV-1a 64-bit offset basis (`0xcbf29ce484222325`). */
const FNV_OFFSET_BASIS = 0xcbf2_9ce4_8422_2325n;
/** FNV-1a 64-bit prime (`0x100000001b3`). */
const FNV_PRIME = 0x0000_0100_0000_01b3n;
/** 64-bit wrap mask, emulating Rust's `wrapping_mul` on `u64`. */
const MASK_64 = 0xffff_ffff_ffff_ffffn;

const UTF8 = new TextEncoder();

/**
 * FNV-1a 64-bit hash of `bytes`, computed with wrapping (mod 2^64) arithmetic
 * so it matches Rust's `u64` `wrapping_mul`.
 */
export function fnv1a64(bytes: Uint8Array): bigint {
  let hash = FNV_OFFSET_BASIS;
  for (const byte of bytes) {
    hash ^= BigInt(byte);
    hash = (hash * FNV_PRIME) & MASK_64;
  }
  return hash;
}

/**
 * Deterministic `0..=99` bucket for `stickyKey` under a named split.
 *
 * The `salt` decorrelates independent splits: a caller can be inside the canary
 * bucket yet outside the shadow bucket (and vice versa) even at the same
 * percentage, so enabling one rollout never forces the other onto the same
 * subset of callers.
 *
 * Input framing is `salt` bytes, a single `0x00` separator, then `stickyKey`
 * bytes — all UTF-8, matching Rust's `str::as_bytes()`.
 */
export function rolloutBucket(salt: string, stickyKey: string): number {
  const saltBytes = UTF8.encode(salt);
  const keyBytes = UTF8.encode(stickyKey);
  const input = new Uint8Array(saltBytes.length + 1 + keyBytes.length);
  input.set(saltBytes, 0);
  input[saltBytes.length] = 0;
  input.set(keyBytes, saltBytes.length + 1);
  return Number(fnv1a64(input) % 100n);
}
