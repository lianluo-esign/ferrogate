/**
 * Compact JWS verification on WebCrypto — the primitive the whole OIDC leg
 * rests on.
 *
 * Design rules, each of which is a documented bypass class if dropped:
 *
 *  1. **The algorithm is chosen from an ALLOW-LIST, never from the token.**
 *     `alg: "none"` and `alg: "HS256"` are not entries in the table, so a
 *     token asserting either is refused before a key is even imported. (An
 *     implementation that maps the header's `alg` onto an HMAC verify with the
 *     RSA public key as the secret is the classic algorithm-confusion forgery.)
 *  2. **Every failure returns a refusal value.** Nothing here throws, so a
 *     caller cannot accidentally treat an exception path as "verified".
 *
 * ## An honest note on the `kty` / `crv` / `jwk.alg` guards below
 *
 * They are **redundant defence in depth, not a tested control**, and this
 * comment says so rather than implying otherwise. Removing all three and
 * re-running the suite leaves it GREEN (mutation `M2-jws-kty-family-guard`
 * SURVIVED), because `crypto.subtle.importKey` rejects exactly the same
 * inputs one line later. Probed directly on this runtime (Node 22):
 *
 * ```
 *   EC   jwk.alg=ES384 imported under P-256 → DataError
 *   RSA  jwk.alg=RS512 imported under SHA-256 → DataError
 *   RSA  jwk imported under ECDSA/P-256 → DataError (no crv)
 * ```
 *
 * So the ENFORCING layer for key/algorithm agreement is WebCrypto, and that
 * layer IS mutation-proven — `M1` (delete the `verify` result check) and `M3`
 * (fall back to RS256 for an unknown `alg`) both go RED. The guards stay
 * because they are three cheap comparisons that keep the refusal explicit if a
 * future runtime is more permissive; they are deliberately NOT claimed as the
 * thing that stops algorithm confusion. `M1` and `M3` are.
 */
import { base64UrlToBytes, decodeBase64UrlJson } from "./base64url.js";

export type JwsFailureReason =
  | "malformed"
  | "unsupported_alg"
  | "key_unusable"
  | "signature_invalid";

export type JwsVerification =
  | { ok: true; header: Record<string, unknown>; payload: Record<string, unknown> }
  | { ok: false; reason: JwsFailureReason };

/**
 * Sourced from `SubtleCrypto` itself rather than from the DOM lib: this
 * package compiles under `@cloudflare/workers-types` with no DOM, where
 * `RsaHashedImportParams` and friends are not ambient names.
 */
type ImportAlgorithm = Parameters<SubtleCrypto["importKey"]>[2];
type VerifyAlgorithm = Parameters<SubtleCrypto["verify"]>[0];

interface AlgorithmEntry {
  readonly kty: "RSA" | "EC";
  readonly crv?: string;
  readonly importParams: ImportAlgorithm;
  readonly verifyParams: VerifyAlgorithm;
}

/**
 * The allow-list. `none`, `HS*` (symmetric) and anything else are absent on
 * purpose: an ID token is signed by an IdP with a key we only ever hold the
 * PUBLIC half of, so a symmetric algorithm can only ever be a downgrade.
 */
const ALGORITHMS: Record<string, AlgorithmEntry> = {
  RS256: {
    kty: "RSA",
    importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    verifyParams: { name: "RSASSA-PKCS1-v1_5" },
  },
  RS384: {
    kty: "RSA",
    importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
    verifyParams: { name: "RSASSA-PKCS1-v1_5" },
  },
  RS512: {
    kty: "RSA",
    importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
    verifyParams: { name: "RSASSA-PKCS1-v1_5" },
  },
  PS256: {
    kty: "RSA",
    importParams: { name: "RSA-PSS", hash: "SHA-256" },
    verifyParams: { name: "RSA-PSS", saltLength: 32 },
  },
  PS384: {
    kty: "RSA",
    importParams: { name: "RSA-PSS", hash: "SHA-384" },
    verifyParams: { name: "RSA-PSS", saltLength: 48 },
  },
  PS512: {
    kty: "RSA",
    importParams: { name: "RSA-PSS", hash: "SHA-512" },
    verifyParams: { name: "RSA-PSS", saltLength: 64 },
  },
  ES256: {
    kty: "EC",
    crv: "P-256",
    importParams: { name: "ECDSA", namedCurve: "P-256" },
    verifyParams: { name: "ECDSA", hash: "SHA-256" },
  },
  ES384: {
    kty: "EC",
    crv: "P-384",
    importParams: { name: "ECDSA", namedCurve: "P-384" },
    verifyParams: { name: "ECDSA", hash: "SHA-384" },
  },
  ES512: {
    kty: "EC",
    crv: "P-521",
    importParams: { name: "ECDSA", namedCurve: "P-521" },
    verifyParams: { name: "ECDSA", hash: "SHA-512" },
  },
};

/** The algorithms this verifier will ever accept. */
export const SUPPORTED_JWS_ALGORITHMS: readonly string[] = Object.keys(ALGORITHMS);

/**
 * Reads `alg` and `kid` out of the protected header WITHOUT trusting either.
 *
 * The `kid` is a JWKS lookup hint and the `alg` is checked against the
 * allow-list; neither is evidence of anything on its own. Returns `null` for a
 * header that is not base64url JSON, and a `null` `kid` when the IdP omitted
 * it (which `verifyIdToken` then treats as fatal — an ID token with no `kid`
 * cannot be pinned to a published key).
 */
export function decodeJwsHeader(token: string): { alg: string; kid: string | null } | null {
  const segments = token.split(".");
  if (segments.length !== 3) return null;
  const header = decodeBase64UrlJson(segments[0] ?? "");
  if (!header) return null;
  const alg = header.alg;
  if (typeof alg !== "string" || alg.length === 0) return null;
  const kid = typeof header.kid === "string" && header.kid.length > 0 ? header.kid : null;
  return { alg, kid };
}

/**
 * Verifies a compact JWS against ONE JWK under ONE named algorithm.
 *
 * `alg` is supplied by the caller (from the protected header, after the caller
 * has decided the header is worth believing to that extent) and is validated
 * against the allow-list here, so this function can never be talked into a
 * symmetric or unsigned verification.
 */
export async function verifyCompactJws(
  token: string,
  jwk: JsonWebKey,
  alg: string,
): Promise<JwsVerification> {
  const entry = ALGORITHMS[alg];
  if (!entry) return { ok: false, reason: "unsupported_alg" };

  const segments = token.split(".");
  if (segments.length !== 3) return { ok: false, reason: "malformed" };
  const [headerSegment, payloadSegment, signatureSegment] = segments as [string, string, string];
  if (headerSegment.length === 0 || payloadSegment.length === 0 || signatureSegment.length === 0) {
    return { ok: false, reason: "malformed" };
  }

  const header = decodeBase64UrlJson(headerSegment);
  if (!header) return { ok: false, reason: "malformed" };
  // The header's own `alg` must be the one we were asked to verify under: a
  // token that says RS256 must not be verified with the caller's ES256 choice
  // or vice versa.
  if (header.alg !== alg) return { ok: false, reason: "unsupported_alg" };

  const payload = decodeBase64UrlJson(payloadSegment);
  if (!payload) return { ok: false, reason: "malformed" };

  const signature = base64UrlToBytes(signatureSegment);
  if (!signature || signature.length === 0) return { ok: false, reason: "malformed" };

  // Rule 2: the key type must match the algorithm family, whatever the runtime
  // would otherwise tolerate.
  if (jwk.kty !== entry.kty) return { ok: false, reason: "key_unusable" };
  if (entry.crv && jwk.crv !== entry.crv) return { ok: false, reason: "key_unusable" };
  // A JWKS entry may pin its own algorithm; honour it when present.
  if (typeof jwk.alg === "string" && jwk.alg !== alg) return { ok: false, reason: "key_unusable" };

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "jwk",
      // `key_ops`/`ext` from a third-party document can make `importKey`
      // reject a perfectly good verification key; the usage we request below
      // is the authority here.
      { ...jwk, key_ops: undefined, ext: true } as JsonWebKey,
      entry.importParams,
      false,
      ["verify"],
    );
  } catch {
    return { ok: false, reason: "key_unusable" };
  }

  try {
    const verified = await crypto.subtle.verify(
      entry.verifyParams,
      key,
      signature as unknown as BufferSource,
      new TextEncoder().encode(`${headerSegment}.${payloadSegment}`) as unknown as BufferSource,
    );
    if (!verified) return { ok: false, reason: "signature_invalid" };
  } catch {
    // A wrong-length ECDSA signature, for instance. Refuse, never propagate.
    return { ok: false, reason: "signature_invalid" };
  }

  return { ok: true, header, payload };
}
