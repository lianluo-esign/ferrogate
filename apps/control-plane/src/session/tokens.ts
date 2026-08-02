/**
 * The admin-console session JWT — HS256, signed and verified with WebCrypto.
 *
 * Port of `admin_console.rs`'s `AdminSessionClaims` / `issue_access_token` /
 * `decode_access_token`, which use the `jsonwebtoken` crate's
 * `Header::default()` (HS256) and `Validation::default()`.
 *
 * ## What `Validation::default()` actually enforces, and is enforced here
 *
 * The Rust default is not "parse the token": it validates the **signature**
 * against the configured key, requires the `exp` claim and rejects an expired
 * one, and — critically — pins the algorithm to the one the key was built for.
 * All three are reproduced in {@link verifyAdminAccessToken}, and the third is
 * the one a hand-rolled verifier gets wrong:
 *
 *  - the header's `alg` must be exactly `HS256`. A token whose header says
 *    `{"alg":"none"}` with an empty signature is the textbook JWT forgery, and
 *    a verifier that reads `alg` out of the token and dispatches on it accepts
 *    it. Here the algorithm is a CONSTANT and the header is CHECKED against it,
 *    so an attacker-chosen `alg` can only ever cause a rejection.
 *  - the signature is verified over the exact `header.payload` bytes AS
 *    RECEIVED, never over a re-serialization of the decoded claims — otherwise
 *    a payload that round-trips differently (duplicate keys, unicode escapes)
 *    verifies against bytes nobody sent.
 *
 * Every failure is one `null`. The caller answers a single
 * `401 invalid or expired access token` for all of them (Rust does the same),
 * so the token's state is not disclosed.
 */

const UTF8 = new TextEncoder();

/** The ONLY algorithm this surface signs or accepts. */
const ALGORITHM = "HS256" as const;

/**
 * Admin console session access-token lifetime (Rust
 * `ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS`, issue #157). Short-lived by design:
 * the refresh token — durable, revocable, server-side — is what actually gates
 * a browser session's lifetime.
 */
export const ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS = 60 * 60;

/** Admin console refresh-token lifetime (Rust `ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS`). */
export const ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS = 60 * 60 * 24 * 30;

/** Rust `AdminSessionClaims`, field for field. */
export interface AdminSessionClaims {
  readonly sub: string;
  readonly email: string;
  readonly tenant_id: string;
  readonly role: string;
  readonly iat: number;
  readonly exp: number;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(value: string): Uint8Array | null {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  try {
    const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes;
  } catch {
    return null;
  }
}

async function hmacKey(secret: string, usage: "sign" | "verify"): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    UTF8.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    [usage],
  );
}

/** Rust `issue_access_token` — `encode(&Header::default(), &claims, key)`. */
export async function signAdminAccessToken(
  secret: string,
  claims: AdminSessionClaims,
): Promise<string> {
  const header = base64UrlEncode(UTF8.encode(JSON.stringify({ alg: ALGORITHM, typ: "JWT" })));
  const payload = base64UrlEncode(UTF8.encode(JSON.stringify(claims)));
  const signingInput = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(secret, "sign"),
    UTF8.encode(signingInput),
  );
  return `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`;
}

function claimsOf(value: unknown): AdminSessionClaims | null {
  if (typeof value !== "object" || value === null) return null;
  const raw = value as Record<string, unknown>;
  const strings = ["sub", "email", "tenant_id", "role"] as const;
  for (const field of strings) if (typeof raw[field] !== "string") return null;
  if (typeof raw.iat !== "number" || typeof raw.exp !== "number") return null;
  return {
    sub: raw.sub as string,
    email: raw.email as string,
    tenant_id: raw.tenant_id as string,
    role: raw.role as string,
    iat: raw.iat,
    exp: raw.exp,
  };
}

/**
 * Rust `decode_access_token` + `Validation::default()`.
 *
 * `null` for: a malformed token, a header whose `alg` is not {@link ALGORITHM},
 * a signature that does not verify, claims of the wrong shape, and an `exp`
 * that has passed. The caller must not distinguish them on the wire.
 *
 * `nowUnix` is a parameter so expiry is testable without waiting an hour and
 * without a clock stub that could silently disable the check.
 */
export async function verifyAdminAccessToken(
  secret: string,
  token: string,
  nowUnix: number = Math.floor(Date.now() / 1000),
): Promise<AdminSessionClaims | null> {
  const segments = token.split(".");
  if (segments.length !== 3) return null;
  const [headerSegment, payloadSegment, signatureSegment] = segments as [string, string, string];

  const headerBytes = base64UrlDecode(headerSegment);
  if (headerBytes === null) return null;
  let header: unknown;
  try {
    header = JSON.parse(new TextDecoder().decode(headerBytes));
  } catch {
    return null;
  }
  // The algorithm is OURS, not the token's. `{"alg":"none"}` lands here.
  if (typeof header !== "object" || header === null) return null;
  if ((header as Record<string, unknown>).alg !== ALGORITHM) return null;

  const signature = base64UrlDecode(signatureSegment);
  if (signature === null) return null;
  const verified = await crypto.subtle.verify(
    "HMAC",
    await hmacKey(secret, "verify"),
    signature as BufferSource,
    // The bytes AS RECEIVED — never a re-serialization of the parsed claims.
    UTF8.encode(`${headerSegment}.${payloadSegment}`),
  );
  if (!verified) return null;

  const payloadBytes = base64UrlDecode(payloadSegment);
  if (payloadBytes === null) return null;
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    return null;
  }
  const claims = claimsOf(payload);
  if (claims === null) return null;
  // `Validation::default()` requires `exp` and rejects an expired token.
  if (claims.exp <= nowUnix) return null;
  return claims;
}
