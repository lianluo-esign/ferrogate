/**
 * UTF-8 byte-offset primitives.
 *
 * The Rust crate indexes every finding, patch, and segment length in **UTF-8
 * byte offsets** (`str::len`, `str::is_char_boundary`, byte-slicing
 * `&segment.text[start..end]`). JavaScript strings are UTF-16, so a faithful
 * port must compute offsets in the same UTF-8 byte space, or the wire contract
 * (`Finding.byte_start`/`byte_end`, `ContentPatch` ranges) drifts from any Rust
 * peer and the patch-application char-boundary guard becomes wrong.
 *
 * These helpers keep all offset math in UTF-8 bytes while still using JS strings
 * for regex/keyword scanning; a code-unit→byte map bridges the two. For ASCII
 * (the overwhelming common case, and every deterministic secret pattern) a byte
 * offset equals the code-unit offset, so this is exact and cheap.
 */

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

/** UTF-8 byte length of `s` — the twin of Rust `str::len()`. */
export function byteLen(s: string): number {
  let n = 0;
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    n += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
  }
  return n;
}

/** Encode `s` to its UTF-8 bytes. */
export function encodeUtf8(s: string): Uint8Array {
  return ENCODER.encode(s);
}

/** Decode UTF-8 `bytes` to a string (lossy, mirroring `String::from_utf8_lossy`). */
export function decodeUtf8(bytes: Uint8Array): string {
  return DECODER.decode(bytes);
}

/**
 * Map from a UTF-16 code-unit index (0..=length) to the UTF-8 byte offset of
 * that position. Interior positions of a surrogate pair map to the pair's start
 * byte; regex/keyword matches never land there for our patterns.
 */
export function byteOffsetMap(s: string): number[] {
  const map = new Array<number>(s.length + 1);
  let byte = 0;
  let unit = 0;
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    const width = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    map[unit] = byte;
    if (ch.length === 2) {
      map[unit + 1] = byte;
    }
    byte += width;
    unit += ch.length;
  }
  map[s.length] = byte;
  return map;
}

/** Byte slice `s[startByte..endByte)` — the twin of Rust `&s[start..end]`. */
export function byteSlice(s: string, startByte: number, endByte: number): string {
  return DECODER.decode(ENCODER.encode(s).subarray(startByte, endByte));
}

/**
 * Whether `byteIndex` falls on a UTF-8 character boundary of `s` — the twin of
 * Rust `str::is_char_boundary`. `0` and `len` are boundaries; otherwise the byte
 * must not be a `10xxxxxx` continuation byte.
 */
export function isCharBoundary(s: string, byteIndex: number): boolean {
  const bytes = ENCODER.encode(s);
  return isCharBoundaryBytes(bytes, byteIndex);
}

/** `isCharBoundary` over pre-encoded bytes (avoids re-encoding in hot loops). */
export function isCharBoundaryBytes(bytes: Uint8Array, byteIndex: number): boolean {
  if (byteIndex === 0 || byteIndex === bytes.length) {
    return true;
  }
  if (byteIndex < 0 || byteIndex > bytes.length) {
    return false;
  }
  return ((bytes[byteIndex] as number) & 0xc0) !== 0x80;
}

/**
 * Non-overlapping byte offsets of every occurrence of `needle` in `haystack`,
 * mirroring Rust `str::match_indices` (which yields UTF-8 byte offsets). Empty
 * needle yields nothing.
 */
export function byteMatchIndices(haystack: string, needle: string): number[] {
  const out: number[] = [];
  if (needle.length === 0) {
    return out;
  }
  const map = byteOffsetMap(haystack);
  let from = 0;
  for (;;) {
    const unit = haystack.indexOf(needle, from);
    if (unit < 0) {
      break;
    }
    out.push(map[unit] as number);
    from = unit + needle.length;
  }
  return out;
}
