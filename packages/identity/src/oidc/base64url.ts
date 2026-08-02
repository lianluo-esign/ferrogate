/**
 * base64url (RFC 4648 §5) helpers, on the two primitives that exist in both
 * workerd and Node: `atob`/`btoa`.
 */

/** Decodes base64url to bytes, or `null` for anything that is not base64url. */
export function base64UrlToBytes(value: string): Uint8Array | null {
  // Reject before decoding: `atob` silently tolerates several near-misses, and
  // a JWS segment that is not strictly base64url is a malformed token, not a
  // token to guess at.
  if (!/^[A-Za-z0-9_-]*$/.test(value)) return null;
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  try {
    const binary = atob(padded + padding);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

/** Encodes bytes as base64url with no padding. */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decodes a base64url JSON segment to a plain object, or `null` if it is not
 * base64url, not JSON, or not a JSON OBJECT.
 *
 * The last check matters: `JSON.parse("[]")` and `JSON.parse("null")` succeed,
 * and a caller reading `payload.aud` off either gets `undefined` rather than a
 * parse failure — which a lenient claim check would then treat as "absent".
 */
export function decodeBase64UrlJson(segment: string): Record<string, unknown> | null {
  const bytes = base64UrlToBytes(segment);
  if (!bytes) return null;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}
