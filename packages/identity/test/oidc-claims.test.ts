/**
 * ID-token CLAIM validation: `iss` / `aud` / `exp` / `iat` / `nbf` / `nonce`.
 *
 * A correct signature only proves the IdP minted the token. It does not prove
 * the token was minted for THIS relying party, for THIS login attempt, or that
 * it is still valid — those are the claims below, and each omission is its own
 * bypass (token replay across audiences, replay of an expired token, and
 * authorization-code/ID-token injection respectively).
 */
import { describe, expect, test } from "vitest";
import { ID_TOKEN_CLOCK_SKEW_SECONDS, validateIdTokenClaims } from "../src/oidc/claims.js";

const EXPECTATIONS = {
  issuer: "https://idp.test",
  audience: "client-abc",
  nonce: "nonce-123",
  nowUnix: 1_000_000,
} as const;

function claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: "https://idp.test",
    aud: "client-abc",
    exp: 1_000_060,
    iat: 999_990,
    nonce: "nonce-123",
    sub: "idp-user-1",
    email: "person@example.com",
    ...overrides,
  };
}

describe("validateIdTokenClaims", () => {
  test("accepts a well-formed token", () => {
    expect(validateIdTokenClaims(claims(), EXPECTATIONS)).toEqual({ ok: true });
  });

  test("REFUSES a token minted for a different audience", () => {
    expect(validateIdTokenClaims(claims({ aud: "someone-elses-client" }), EXPECTATIONS)).toEqual({
      ok: false,
      reason: "aud_mismatch",
    });
  });

  test("REFUSES an aud ARRAY that does not contain this client", () => {
    expect(
      validateIdTokenClaims(claims({ aud: ["other-a", "other-b"] }), EXPECTATIONS),
    ).toMatchObject({ ok: false, reason: "aud_mismatch" });
  });

  test("accepts a single-element aud array containing this client", () => {
    expect(validateIdTokenClaims(claims({ aud: ["client-abc"] }), EXPECTATIONS)).toEqual({
      ok: true,
    });
  });

  test("accepts a MULTI-audience token only when azp names this client", () => {
    expect(
      validateIdTokenClaims(
        claims({ aud: ["other", "client-abc"], azp: "client-abc" }),
        EXPECTATIONS,
      ),
    ).toEqual({ ok: true });
  });

  test("REFUSES a multi-audience token whose azp is another party", () => {
    // OIDC Core §3.1.3.7(4): when `azp` is present it must be this client.
    // Without the check, any co-audience app's token is accepted as one of
    // ours — the co-tenancy escape an IdP shared across products creates.
    expect(
      validateIdTokenClaims(claims({ aud: ["client-abc", "other"], azp: "other" }), EXPECTATIONS),
    ).toMatchObject({ ok: false, reason: "azp_mismatch" });
  });

  test("REFUSES a multi-audience token with NO azp at all", () => {
    // §3.1.3.7(3) says the client SHOULD verify `azp` is present for a
    // multi-audience token. This port makes it a MUST: a token minted for
    // several parties carries no evidence of which one it was meant for, and
    // "several parties" is exactly the case where that matters.
    expect(
      validateIdTokenClaims(claims({ aud: ["client-abc", "other"] }), EXPECTATIONS),
    ).toMatchObject({ ok: false, reason: "azp_mismatch" });
  });

  test("REFUSES a token from a different issuer", () => {
    expect(validateIdTokenClaims(claims({ iss: "https://evil.test" }), EXPECTATIONS)).toMatchObject(
      {
        ok: false,
        reason: "iss_mismatch",
      },
    );
  });

  test("REFUSES an issuer that only PREFIXES the configured one", () => {
    expect(
      validateIdTokenClaims(claims({ iss: "https://idp.test.evil.example" }), EXPECTATIONS),
    ).toMatchObject({ ok: false, reason: "iss_mismatch" });
  });

  test("normalises exactly one trailing slash on the issuer, nothing else", () => {
    expect(validateIdTokenClaims(claims({ iss: "https://idp.test/" }), EXPECTATIONS)).toEqual({
      ok: true,
    });
    expect(
      validateIdTokenClaims(claims({ iss: "https://idp.test/x" }), EXPECTATIONS),
    ).toMatchObject({ ok: false });
  });

  test("REFUSES a long-expired token", () => {
    expect(
      validateIdTokenClaims(claims({ exp: EXPECTATIONS.nowUnix - 3_600 }), EXPECTATIONS),
    ).toMatchObject({ ok: false, reason: "expired" });
  });

  test("pins the expiry tolerance EXACTLY at the documented skew", () => {
    // The boundary is the assertion, not a round number near it: a test that
    // only checks "an hour ago is refused" passes just as well against a
    // verifier with a one-hour leeway.
    const atTheEdge = EXPECTATIONS.nowUnix - ID_TOKEN_CLOCK_SKEW_SECONDS;
    expect(validateIdTokenClaims(claims({ exp: atTheEdge }), EXPECTATIONS)).toEqual({ ok: true });
    expect(validateIdTokenClaims(claims({ exp: atTheEdge - 1 }), EXPECTATIONS)).toEqual({
      ok: false,
      reason: "expired",
    });
  });

  test("the skew is small — it is IdP-vs-Worker clock drift, not a grace period", () => {
    expect(ID_TOKEN_CLOCK_SKEW_SECONDS).toBeLessThanOrEqual(60);
  });

  test("REFUSES a token with no exp at all", () => {
    const withoutExp = claims();
    // biome-ignore lint/performance/noDelete: modelling an IdP that omits exp.
    delete withoutExp.exp;
    expect(validateIdTokenClaims(withoutExp, EXPECTATIONS)).toMatchObject({
      ok: false,
      reason: "exp_missing",
    });
  });

  test("REFUSES a token issued in the future beyond the skew", () => {
    const iat = EXPECTATIONS.nowUnix + ID_TOKEN_CLOCK_SKEW_SECONDS + 60;
    expect(validateIdTokenClaims(claims({ iat, exp: iat + 60 }), EXPECTATIONS)).toMatchObject({
      ok: false,
      reason: "iat_in_future",
    });
  });

  test("REFUSES a token that is not yet valid (nbf)", () => {
    const nbf = EXPECTATIONS.nowUnix + ID_TOKEN_CLOCK_SKEW_SECONDS + 60;
    expect(validateIdTokenClaims(claims({ nbf }), EXPECTATIONS)).toMatchObject({
      ok: false,
      reason: "not_yet_valid",
    });
  });

  test("REFUSES a token whose nonce is not the one this flow issued", () => {
    expect(validateIdTokenClaims(claims({ nonce: "someone-elses-nonce" }), EXPECTATIONS)).toEqual({
      ok: false,
      reason: "nonce_mismatch",
    });
  });

  test("REFUSES a token with NO nonce when the flow issued one", () => {
    const withoutNonce = claims();
    // biome-ignore lint/performance/noDelete: modelling an IdP that drops nonce.
    delete withoutNonce.nonce;
    expect(validateIdTokenClaims(withoutNonce, EXPECTATIONS)).toEqual({
      ok: false,
      reason: "nonce_mismatch",
    });
  });

  test("REFUSES a non-string nonce that stringifies to the expected value", () => {
    // `String(x) === expected` would accept an object with a crafted toString.
    expect(validateIdTokenClaims(claims({ nonce: ["nonce-123"] }), EXPECTATIONS)).toEqual({
      ok: false,
      reason: "nonce_mismatch",
    });
  });

  test("REFUSES a missing sub", () => {
    const withoutSub = claims();
    // biome-ignore lint/performance/noDelete: modelling an IdP that omits sub.
    delete withoutSub.sub;
    expect(validateIdTokenClaims(withoutSub, EXPECTATIONS)).toMatchObject({
      ok: false,
      reason: "sub_missing",
    });
  });
});
