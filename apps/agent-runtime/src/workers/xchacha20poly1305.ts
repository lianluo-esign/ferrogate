/**
 * XChaCha20-Poly1305 — the AEAD the Rust self-hosted-worker binary seals with.
 *
 * ## Why this file exists
 *
 * `crates/ferrogate-runtime/src/self_hosted_worker.rs` seals every
 * `symmetric_aead` transport frame with **XChaCha20-Poly1305** (24-byte
 * extended nonce, `algorithm: "xchacha20poly1305"` on the wire). workerd's
 * `crypto.subtle` exposes no ChaCha20 family at all — AES-GCM/CBC/CTR/KW, HMAC,
 * RSA-*, ECDSA, ECDH, Ed25519, X25519, PBKDF2 and HKDF, and nothing else — so
 * the platform cannot produce or consume that wire format through WebCrypto.
 *
 * That is a limit on `crypto.subtle`, **not** on the platform: ChaCha20 and
 * Poly1305 are 32-bit integer arithmetic and modular arithmetic, both of which
 * a Worker runs perfectly well. So the honest port is to implement them, and
 * this module does, which is what makes a Rust-emitted frame open here
 * byte-for-byte rather than being refused as an alien format.
 *
 * ## Clean-room provenance
 *
 * Written from the PUBLIC specifications and nothing else:
 *
 *  - **RFC 8439** — ChaCha20 (§2.1–§2.4), Poly1305 (§2.5), the one-time-key
 *    generation (§2.6) and the AEAD_CHACHA20_POLY1305 construction (§2.8).
 *  - **draft-irtf-cfrg-xchacha-03** — HChaCha20 (§2.2) and the XChaCha20
 *    nonce-extension construction (§2.3).
 *
 * No line here is derived from `crates/**` or from any Rust artifact; the Rust
 * side is a `chacha20poly1305` crate call, and what is ported is the RFC the
 * crate implements. The tests pin the published RFC/draft test vectors, which
 * is the only meaningful proof of interoperability available offline: a
 * construction that reproduces the standard's vectors interoperates with every
 * conforming implementation, including the Rust one.
 *
 * ## What is NOT claimed
 *
 * This is a software implementation on a JIT runtime, so it is not
 * constant-time in the way a hardware AES path is. That matters for the TAG
 * COMPARISON (a variable-time compare is a forgery oracle) and that one step is
 * done in constant time by {@link constantTimeEqual}. The cipher core itself
 * has no secret-dependent branches or secret-dependent memory indices, which is
 * the property that rules out the classic table-lookup side channel.
 */

// ---------------------------------------------------------------------------
// ChaCha20 core (RFC 8439 §2.1–§2.3)
// ---------------------------------------------------------------------------

/** RFC 8439 §2.3: the constant `"expand 32-byte k"` as four little-endian words. */
const SIGMA: readonly number[] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/** RFC 8439 §2.1: the ChaCha20 block is 64 bytes. */
export const CHACHA20_BLOCK_BYTES = 64;

/** RFC 8439 §2.8: the AEAD key is 256 bits. */
export const CHACHA20_KEY_BYTES = 32;

/** RFC 8439 §2.8: the IETF ChaCha20-Poly1305 nonce is 96 bits. */
export const CHACHA20_NONCE_BYTES = 12;

/** draft-irtf-cfrg-xchacha §2.3: the extended nonce is 192 bits. */
export const XCHACHA20_NONCE_BYTES = 24;

/** RFC 8439 §2.5: the Poly1305 tag is 128 bits. */
export const POLY1305_TAG_BYTES = 16;

function rotateLeft32(value: number, bits: number): number {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

/** RFC 8439 §2.1 `QUARTERROUND(a, b, c, d)`, operating in place on the state. */
function quarterRound(x: Uint32Array, a: number, b: number, c: number, d: number): void {
  x[a] = (x[a]! + x[b]!) >>> 0;
  x[d] = rotateLeft32(x[d]! ^ x[a]!, 16);
  x[c] = (x[c]! + x[d]!) >>> 0;
  x[b] = rotateLeft32(x[b]! ^ x[c]!, 12);
  x[a] = (x[a]! + x[b]!) >>> 0;
  x[d] = rotateLeft32(x[d]! ^ x[a]!, 8);
  x[c] = (x[c]! + x[d]!) >>> 0;
  x[b] = rotateLeft32(x[b]! ^ x[c]!, 7);
}

/** The 20 rounds of RFC 8439 §2.3.1: ten column rounds each followed by a diagonal round. */
function twentyRounds(x: Uint32Array): void {
  for (let i = 0; i < 10; i += 1) {
    quarterRound(x, 0, 4, 8, 12);
    quarterRound(x, 1, 5, 9, 13);
    quarterRound(x, 2, 6, 10, 14);
    quarterRound(x, 3, 7, 11, 15);
    quarterRound(x, 0, 5, 10, 15);
    quarterRound(x, 1, 6, 11, 12);
    quarterRound(x, 2, 7, 8, 13);
    quarterRound(x, 3, 4, 9, 14);
  }
}

function readUint32LE(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset]! | (bytes[offset + 1]! << 8) | (bytes[offset + 2]! << 16)) >>> 0) +
    bytes[offset + 3]! * 0x1000000
  );
}

function writeUint32LE(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}

/** RFC 8439 §2.3: build the 16-word state from key, counter and 96-bit nonce. */
function chachaState(key: Uint8Array, counter: number, nonce: Uint8Array): Uint32Array {
  const state = new Uint32Array(16);
  state.set(SIGMA, 0);
  for (let i = 0; i < 8; i += 1) state[4 + i] = readUint32LE(key, i * 4);
  state[12] = counter >>> 0;
  for (let i = 0; i < 3; i += 1) state[13 + i] = readUint32LE(nonce, i * 4);
  return state;
}

/**
 * RFC 8439 §2.3 `chacha20_block`: 20 rounds, then add the ORIGINAL state back
 * (the feed-forward that makes the permutation one-way) and serialize.
 */
export function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  const initial = chachaState(key, counter, nonce);
  const working = Uint32Array.from(initial);
  twentyRounds(working);
  const out = new Uint8Array(CHACHA20_BLOCK_BYTES);
  for (let i = 0; i < 16; i += 1) {
    writeUint32LE(out, i * 4, (working[i]! + initial[i]!) >>> 0);
  }
  return out;
}

/**
 * RFC 8439 §2.4 `chacha20_encrypt`: XOR the message with the keystream.
 *
 * Encryption and decryption are the same operation, which is why the frame
 * codec calls this for both directions.
 */
export function chacha20Xor(
  key: Uint8Array,
  counter: number,
  nonce: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(data.length);
  for (let offset = 0; offset < data.length; offset += CHACHA20_BLOCK_BYTES) {
    const block = chacha20Block(key, counter + offset / CHACHA20_BLOCK_BYTES, nonce);
    const end = Math.min(offset + CHACHA20_BLOCK_BYTES, data.length);
    for (let i = offset; i < end; i += 1) out[i] = data[i]! ^ block[i - offset]!;
  }
  return out;
}

/**
 * draft-irtf-cfrg-xchacha §2.2 `HChaCha20`.
 *
 * The same permutation as ChaCha20 with the counter+nonce words replaced by a
 * 128-bit nonce and — the load-bearing difference — WITHOUT the feed-forward
 * addition. The output is state words 0..3 and 12..15, a 256-bit subkey.
 */
export function hchacha20(key: Uint8Array, nonce16: Uint8Array): Uint8Array {
  const state = new Uint32Array(16);
  state.set(SIGMA, 0);
  for (let i = 0; i < 8; i += 1) state[4 + i] = readUint32LE(key, i * 4);
  for (let i = 0; i < 4; i += 1) state[12 + i] = readUint32LE(nonce16, i * 4);
  twentyRounds(state);
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i += 1) writeUint32LE(out, i * 4, state[i]!);
  for (let i = 0; i < 4; i += 1) writeUint32LE(out, 16 + i * 4, state[12 + i]!);
  return out;
}

// ---------------------------------------------------------------------------
// Poly1305 (RFC 8439 §2.5)
// ---------------------------------------------------------------------------

/** RFC 8439 §2.5: the Poly1305 prime, 2^130 − 5. */
const POLY1305_PRIME = (1n << 130n) - 5n;

const MASK_128 = (1n << 128n) - 1n;

/**
 * RFC 8439 §2.5.1: `r` is clamped — the top four bits of bytes 3/7/11/15 and
 * the bottom two bits of bytes 4/8/12 are cleared — which is what bounds the
 * intermediate products and makes the 130-bit reduction exact.
 */
function clampR(keyBytes: Uint8Array): bigint {
  const r = keyBytes.slice(0, 16);
  r[3]! &= 15;
  r[7]! &= 15;
  r[11]! &= 15;
  r[15]! &= 15;
  r[4]! &= 252;
  r[8]! &= 252;
  r[12]! &= 252;
  return littleEndianToBigInt(r);
}

function littleEndianToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[i]!);
  return value;
}

/**
 * RFC 8439 §2.5.1, the Horner evaluation: for each 16-byte block, append a
 * single 1 bit above the block, add it to the accumulator, multiply by `r`, and
 * reduce mod 2^130−5. The final tag is `(accumulator + s) mod 2^128`.
 *
 * `s` (the second half of the one-time key) is added LAST and is what makes the
 * MAC one-time-secure: without it the polynomial evaluation would leak `r`.
 */
export function poly1305(message: Uint8Array, oneTimeKey: Uint8Array): Uint8Array {
  const r = clampR(oneTimeKey);
  const s = littleEndianToBigInt(oneTimeKey.subarray(16, 32));
  const view = new DataView(message.buffer, message.byteOffset, message.byteLength);

  let accumulator = 0n;
  let offset = 0;
  // Full 16-byte blocks: read as two 64-bit little-endian halves rather than
  // shifting byte by byte — same value, an order of magnitude less work.
  for (; offset + 16 <= message.length; offset += 16) {
    const low = view.getBigUint64(offset, true);
    const high = view.getBigUint64(offset + 8, true);
    accumulator = ((accumulator + (low | (high << 64n) | (1n << 128n))) * r) % POLY1305_PRIME;
  }
  if (offset < message.length) {
    const tail = message.subarray(offset);
    const block = littleEndianToBigInt(tail) | (1n << (8n * BigInt(tail.length)));
    accumulator = ((accumulator + block) * r) % POLY1305_PRIME;
  }

  const tagValue = (accumulator + s) & MASK_128;
  const tag = new Uint8Array(POLY1305_TAG_BYTES);
  let remaining = tagValue;
  for (let i = 0; i < POLY1305_TAG_BYTES; i += 1) {
    tag[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return tag;
}

/**
 * Length-independent constant-time comparison, used ONLY for the Poly1305 tag.
 *
 * A `===` on the tag would be a forgery oracle: an attacker who can time the
 * comparison can walk a forged tag out one byte at a time.
 */
export function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i += 1) difference |= left[i]! ^ right[i]!;
  return difference === 0;
}

// ---------------------------------------------------------------------------
// AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8)
// ---------------------------------------------------------------------------

/** RFC 8439 §2.8.1: each of AAD and ciphertext is zero-padded to a 16-byte boundary. */
function padding16(length: number): number {
  const remainder = length % 16;
  return remainder === 0 ? 0 : 16 - remainder;
}

function writeUint64LE(bytes: Uint8Array, offset: number, value: number): void {
  let remaining = BigInt(value);
  for (let i = 0; i < 8; i += 1) {
    bytes[offset + i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
}

/**
 * RFC 8439 §2.8.1: the MAC input is
 * `aad ‖ pad16(aad) ‖ ciphertext ‖ pad16(ciphertext) ‖ le64(|aad|) ‖ le64(|ciphertext|)`.
 *
 * The two trailing lengths are not decoration: without them an attacker could
 * shift bytes between the AAD and the ciphertext and keep the same MAC input.
 */
function macInput(aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const aadPad = padding16(aad.length);
  const ctPad = padding16(ciphertext.length);
  const out = new Uint8Array(aad.length + aadPad + ciphertext.length + ctPad + 16);
  out.set(aad, 0);
  out.set(ciphertext, aad.length + aadPad);
  const lengthsAt = aad.length + aadPad + ciphertext.length + ctPad;
  writeUint64LE(out, lengthsAt, aad.length);
  writeUint64LE(out, lengthsAt + 8, ciphertext.length);
  return out;
}

/**
 * RFC 8439 §2.6 `poly1305_key_gen`: the one-time Poly1305 key is the first 32
 * bytes of the ChaCha20 block at COUNTER 0, which is why the message keystream
 * starts at counter 1.
 */
function poly1305KeyGen(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  return chacha20Block(key, 0, nonce).subarray(0, 32);
}

function requireLength(name: string, bytes: Uint8Array, expected: number): void {
  if (bytes.length !== expected) {
    throw new Error(`${name} must be ${expected} bytes, got ${bytes.length}`);
  }
}

/** RFC 8439 §2.8 seal. Returns `ciphertext ‖ tag`, the layout the Rust crate emits. */
export function chacha20poly1305Seal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  requireLength("chacha20-poly1305 key", key, CHACHA20_KEY_BYTES);
  requireLength("chacha20-poly1305 nonce", nonce, CHACHA20_NONCE_BYTES);
  const ciphertext = chacha20Xor(key, 1, nonce, plaintext);
  const tag = poly1305(macInput(aad, ciphertext), poly1305KeyGen(key, nonce));
  const out = new Uint8Array(ciphertext.length + POLY1305_TAG_BYTES);
  out.set(ciphertext, 0);
  out.set(tag, ciphertext.length);
  return out;
}

/**
 * RFC 8439 §2.8 open. `undefined` — never a partial plaintext — when the tag
 * does not verify.
 *
 * The tag is checked BEFORE the ciphertext is decrypted, so a forged frame
 * never produces plaintext bytes that a caller could accidentally act on.
 */
export function chacha20poly1305Open(
  key: Uint8Array,
  nonce: Uint8Array,
  sealed: Uint8Array,
  aad: Uint8Array,
): Uint8Array | undefined {
  requireLength("chacha20-poly1305 key", key, CHACHA20_KEY_BYTES);
  requireLength("chacha20-poly1305 nonce", nonce, CHACHA20_NONCE_BYTES);
  if (sealed.length < POLY1305_TAG_BYTES) return undefined;
  const ciphertext = sealed.subarray(0, sealed.length - POLY1305_TAG_BYTES);
  const tag = sealed.subarray(sealed.length - POLY1305_TAG_BYTES);
  const expected = poly1305(macInput(aad, ciphertext), poly1305KeyGen(key, nonce));
  if (!constantTimeEqual(tag, expected)) return undefined;
  return chacha20Xor(key, 1, nonce, ciphertext);
}

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha §2.3)
// ---------------------------------------------------------------------------

/**
 * draft-irtf-cfrg-xchacha §2.3: derive a subkey with HChaCha20 over the first
 * 16 nonce bytes, then run IETF ChaCha20-Poly1305 under that subkey with the
 * 96-bit nonce `0x00000000 ‖ nonce[16..24]`.
 *
 * The four leading zero bytes are part of the construction, not padding this
 * port invented — omitting them yields a different keystream and every Rust
 * frame would fail to open.
 */
function xchachaSubkeyAndNonce(
  key: Uint8Array,
  nonce24: Uint8Array,
): { readonly subkey: Uint8Array; readonly nonce12: Uint8Array } {
  requireLength("xchacha20-poly1305 key", key, CHACHA20_KEY_BYTES);
  requireLength("xchacha20-poly1305 nonce", nonce24, XCHACHA20_NONCE_BYTES);
  const subkey = hchacha20(key, nonce24.subarray(0, 16));
  const nonce12 = new Uint8Array(CHACHA20_NONCE_BYTES);
  nonce12.set(nonce24.subarray(16, 24), 4);
  return { subkey, nonce12 };
}

/** Seal under XChaCha20-Poly1305. Returns `ciphertext ‖ tag`. */
export function xchacha20poly1305Seal(
  key: Uint8Array,
  nonce24: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  const { subkey, nonce12 } = xchachaSubkeyAndNonce(key, nonce24);
  return chacha20poly1305Seal(subkey, nonce12, plaintext, aad);
}

/** Open an XChaCha20-Poly1305 frame, or `undefined` when the tag does not verify. */
export function xchacha20poly1305Open(
  key: Uint8Array,
  nonce24: Uint8Array,
  sealed: Uint8Array,
  aad: Uint8Array,
): Uint8Array | undefined {
  const { subkey, nonce12 } = xchachaSubkeyAndNonce(key, nonce24);
  return chacha20poly1305Open(subkey, nonce12, sealed, aad);
}
