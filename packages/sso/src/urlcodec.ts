/**
 * Percent-encoding, ported 1:1 from `sso.rs::urlencode` and
 * `http.rs::urldecode`.
 *
 * `encodeURIComponent`/`decodeURIComponent` are NOT substitutes:
 *
 *  * `encodeURIComponent` leaves `!'()*` unescaped, so it produces different
 *    octets from the Rust encoder for the same input — and the redirect-binding
 *    signature is over exactly those octets;
 *  * `decodeURIComponent` THROWS on a malformed `%` sequence and does not map
 *    `+` to a space. The Rust decoder passes malformed sequences through
 *    unchanged and does map `+`, because the IdP's redirect is a query string
 *    whose shape we do not control. Throwing there would turn a cosmetic
 *    encoding quirk into an unhandled 500 instead of a clean refusal.
 */

const UNRESERVED = /[A-Za-z0-9\-_.~]/;

/** `sso.rs::urlencode` — RFC 3986 unreserved set, uppercase hex, byte-wise. */
export function urlencode(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let encoded = "";
  for (const byte of bytes) {
    const ch = String.fromCharCode(byte);
    encoded += UNRESERVED.test(ch) ? ch : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return encoded;
}

const HEX = /^[0-9A-Fa-f]{2}$/;

/** `http.rs::urldecode` — best-effort, never throws, `+` becomes a space. */
export function urldecode(value: string): string {
  const bytes = new TextEncoder().encode(value);
  const decoded: number[] = [];
  let index = 0;
  while (index < bytes.length) {
    const byte = bytes[index] as number;
    if (byte === 0x25 /* % */ && index + 2 < bytes.length) {
      const hex = String.fromCharCode(bytes[index + 1] as number, bytes[index + 2] as number);
      if (HEX.test(hex)) {
        decoded.push(Number.parseInt(hex, 16));
        index += 3;
        continue;
      }
      decoded.push(byte);
      index += 1;
      continue;
    }
    if (byte === 0x2b /* + */) {
      decoded.push(0x20);
      index += 1;
      continue;
    }
    decoded.push(byte);
    index += 1;
  }
  // `String::from_utf8_lossy` — invalid sequences become U+FFFD rather than
  // erroring, matching the Rust decoder exactly.
  return new TextDecoder("utf-8").decode(new Uint8Array(decoded));
}
