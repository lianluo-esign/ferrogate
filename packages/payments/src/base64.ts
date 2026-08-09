/**
 * Strict standard-alphabet base64 (padded) — the encoding the x402 wire uses
 * for every header value.
 *
 * The Rust crate uses `base64::engine::general_purpose::STANDARD`. This is a
 * deterministic, dependency-free re-implementation that rejects any input the
 * strict engine would (invalid characters, non-canonical padding, bad length)
 * so that a malformed header decodes to `null` rather than throwing or
 * silently coercing — the crate maps that `null` to `MalformedHeader`.
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const DECODE: Int16Array = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) table[ALPHABET.charCodeAt(i)] = i;
  return table;
})();

/** Look up one alphabet character for the low 6 bits of `n`. */
function C(n: number): string {
  return ALPHABET.charAt(n & 63);
}

/** Encode bytes as standard, padded base64. */
export function encodeBase64Std(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n =
      ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8) | (bytes[i + 2] as number);
    out += C(n >>> 18) + C(n >>> 12) + C(n >>> 6) + C(n);
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = (bytes[i] as number) << 16;
    out += `${C(n >>> 18) + C(n >>> 12)}==`;
  } else if (rem === 2) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8);
    out += `${C(n >>> 18) + C(n >>> 12) + C(n >>> 6)}=`;
  }
  return out;
}

/**
 * Decode standard, padded base64. Returns `null` on any invalid input:
 * non-alphabet characters, a length that is not a multiple of four, padding in
 * the wrong place, or non-zero bits behind the padding.
 */
export function decodeBase64Std(input: string): Uint8Array | null {
  const len = input.length;
  if (len === 0 || len % 4 !== 0) return null;

  const groups = len / 4;
  let padCount = 0;
  if (input.charCodeAt(len - 1) === 61) padCount++; // '='
  if (input.charCodeAt(len - 2) === 61) padCount++;
  const outLen = groups * 3 - padCount;
  const out = new Uint8Array(outLen);

  let oi = 0;
  for (let g = 0; g < groups; g++) {
    const base = g * 4;
    const isLast = g === groups - 1;
    const c0 = input.charCodeAt(base);
    const c1 = input.charCodeAt(base + 1);
    const c2 = input.charCodeAt(base + 2);
    const c3 = input.charCodeAt(base + 3);

    const s0 = c0 < 128 ? DECODE[c0] : -1;
    const s1 = c1 < 128 ? DECODE[c1] : -1;
    if (s0 === undefined || s0 < 0 || s1 === undefined || s1 < 0) return null;

    // Padding is only ever allowed in the final group's last two positions.
    const pad2 = c2 === 61;
    const pad3 = c3 === 61;
    if ((pad2 || pad3) && !isLast) return null;
    if (pad2 && !pad3) return null; // "=X" is illegal

    const s2 = pad2 ? 0 : c2 < 128 ? DECODE[c2] : -1;
    const s3 = pad3 ? 0 : c3 < 128 ? DECODE[c3] : -1;
    if (s2 === undefined || s2 < 0 || s3 === undefined || s3 < 0) return null;

    const n = (s0 << 18) | (s1 << 12) | (s2 << 6) | s3;
    out[oi++] = (n >>> 16) & 0xff;
    if (!pad2) out[oi++] = (n >>> 8) & 0xff;
    if (!pad3) out[oi++] = n & 0xff;

    // Canonical padding: bits behind the pad must be zero.
    if (pad2 && (n & 0xffff) !== 0) return null;
    if (pad3 && !pad2 && (n & 0xff) !== 0) return null;
  }
  return out;
}
