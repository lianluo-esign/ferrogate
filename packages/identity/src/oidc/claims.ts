/**
 * ID-token CLAIM validation (OpenID Connect Core §3.1.3.7).
 *
 * A verified signature only proves the IdP minted the token. These checks
 * prove it was minted FOR THIS relying party, FOR THIS login attempt, and is
 * currently valid. Dropping any one of them is its own bypass:
 *
 *  - no `aud`   → any token the IdP issued to ANY of its other client
 *                 applications signs a user into FerroGate;
 *  - no `iss`   → a token from an unrelated IdP that happens to share a JWKS
 *                 host is accepted;
 *  - no `exp`   → a token captured once replays forever;
 *  - no `nonce` → an attacker's own valid ID token can be injected into a
 *                 victim's callback (OIDC's answer to code injection);
 *  - no `azp` on a multi-audience token → a co-audience application's token is
 *                 accepted as one of ours.
 */

/**
 * Permitted clock skew in either direction on `exp` / `iat` / `nbf`.
 *
 * 60 s, deliberately an order of magnitude tighter than the 300 s SAML
 * assertion window: an OIDC ID token is delivered over a back-channel token
 * exchange this service performs itself, seconds after the authorize leg, so
 * the only clock difference in play is IdP-vs-Worker — not a browser's.
 */
export const ID_TOKEN_CLOCK_SKEW_SECONDS = 60;

export interface IdTokenExpectations {
  /** The configured issuer, without a trailing slash. */
  issuer: string;
  /** This relying party's `client_id`. */
  audience: string;
  /** The nonce THIS flow issued. Required — see the module note. */
  nonce: string;
  nowUnix: number;
}

export type ClaimFailureReason =
  | "iss_mismatch"
  | "aud_mismatch"
  | "azp_mismatch"
  | "exp_missing"
  | "expired"
  | "iat_in_future"
  | "not_yet_valid"
  | "nonce_mismatch"
  | "sub_missing";

export type ClaimValidation = { ok: true } | { ok: false; reason: ClaimFailureReason };

function trimTrailingSlash(value: string): string {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

function numericClaim(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/**
 * Validates the registered claims of an ALREADY-SIGNATURE-VERIFIED ID token.
 *
 * Order matters only for the reported reason, not for the verdict: every check
 * must pass. The function is total — it returns a refusal for every input it
 * does not accept, and never throws.
 */
export function validateIdTokenClaims(
  claims: Record<string, unknown>,
  expectations: IdTokenExpectations,
): ClaimValidation {
  // --- iss ---------------------------------------------------------------
  // Exact match after normalising exactly one trailing slash. NOT a prefix
  // match: `https://idp.test.evil.example` starts with the configured issuer
  // under a naive `startsWith`.
  const issuer = claims.iss;
  if (typeof issuer !== "string") return { ok: false, reason: "iss_mismatch" };
  if (trimTrailingSlash(issuer) !== trimTrailingSlash(expectations.issuer)) {
    return { ok: false, reason: "iss_mismatch" };
  }

  // --- aud / azp ---------------------------------------------------------
  const audience = claims.aud;
  const audiences: string[] =
    typeof audience === "string"
      ? [audience]
      : Array.isArray(audience)
        ? audience.filter((value): value is string => typeof value === "string")
        : [];
  if (!audiences.includes(expectations.audience)) return { ok: false, reason: "aud_mismatch" };
  if (audiences.length > 1) {
    // Multi-audience: `azp` MUST be present and MUST be this client.
    const azp = claims.azp;
    if (typeof azp !== "string" || azp !== expectations.audience) {
      return { ok: false, reason: "azp_mismatch" };
    }
  }

  // --- exp / iat / nbf ---------------------------------------------------
  const exp = numericClaim(claims.exp);
  if (exp === null) return { ok: false, reason: "exp_missing" };
  if (exp + ID_TOKEN_CLOCK_SKEW_SECONDS < expectations.nowUnix) {
    return { ok: false, reason: "expired" };
  }
  const iat = numericClaim(claims.iat);
  if (iat !== null && iat - ID_TOKEN_CLOCK_SKEW_SECONDS > expectations.nowUnix) {
    return { ok: false, reason: "iat_in_future" };
  }
  const nbf = numericClaim(claims.nbf);
  if (nbf !== null && nbf - ID_TOKEN_CLOCK_SKEW_SECONDS > expectations.nowUnix) {
    return { ok: false, reason: "not_yet_valid" };
  }

  // --- nonce -------------------------------------------------------------
  // Strictly a string, strictly equal. A non-string that stringifies to the
  // expected value (`["nonce-123"]`) is a forgery, not a match.
  if (typeof claims.nonce !== "string" || claims.nonce !== expectations.nonce) {
    return { ok: false, reason: "nonce_mismatch" };
  }

  // --- sub ---------------------------------------------------------------
  if (typeof claims.sub !== "string" || claims.sub.length === 0) {
    return { ok: false, reason: "sub_missing" };
  }

  return { ok: true };
}
