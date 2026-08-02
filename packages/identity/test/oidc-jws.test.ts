/**
 * ID-token SIGNATURE verification (WebCrypto JWS).
 *
 * Every case here is a known bypass class: a verifier that decodes the payload
 * without checking the signature accepts all of them.
 */
import { describe, expect, test } from "vitest";
import { decodeJwsHeader, verifyCompactJws } from "../src/oidc/jws.js";
import { generateEs256Key, generateRs256Key, signJwt, unsignedJwt } from "./jwt-fixtures.js";

describe("verifyCompactJws", () => {
  test("accepts an RS256 token signed by the matching key", async () => {
    const key = await generateRs256Key("k1");
    const token = await signJwt(key, { sub: "u1" });
    const result = await verifyCompactJws(token, key.jwk, "RS256");
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    expect(result.payload.sub).toBe("u1");
  });

  test("accepts an ES256 token signed by the matching key", async () => {
    const key = await generateEs256Key("e1");
    const token = await signJwt(key, { sub: "u2" });
    const result = await verifyCompactJws(token, key.jwk, "ES256");
    expect(result.ok).toBe(true);
  });

  test("REFUSES a token signed by a key that is not the one presented", async () => {
    const signer = await generateRs256Key("attacker");
    const advertised = await generateRs256Key("k1");
    const token = await signJwt(signer, { sub: "u1" }, { kid: "k1" });
    const result = await verifyCompactJws(token, advertised.jwk, "RS256");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason).toBe("signature_invalid");
  });

  test("REFUSES a tampered payload under a real signature", async () => {
    const key = await generateRs256Key("k1");
    const token = await signJwt(key, { sub: "u1", email: "victim@example.com" });
    const [header, , signature] = token.split(".");
    const forgedPayload = btoa(JSON.stringify({ sub: "u1", email: "attacker@example.com" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const result = await verifyCompactJws(
      `${header}.${forgedPayload}.${signature}`,
      key.jwk,
      "RS256",
    );
    expect(result.ok).toBe(false);
  });

  test('REFUSES alg:"none" (unsigned) even when the payload is well formed', async () => {
    const key = await generateRs256Key("k1");
    const token = unsignedJwt({ sub: "u1" });
    const result = await verifyCompactJws(token, key.jwk, "none");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason).toBe("unsupported_alg");
  });

  test("REFUSES an HS256 header — a symmetric-key confusion downgrade", async () => {
    const key = await generateRs256Key("k1");
    const result = await verifyCompactJws("a.b.c", key.jwk, "HS256");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason).toBe("unsupported_alg");
  });

  test("REFUSES a header alg that disagrees with the JWK alg", async () => {
    const rsa = await generateRs256Key("k1");
    const ec = await generateEs256Key("k1");
    const token = await signJwt(ec, { sub: "u1" });
    // The JWKS entry is RSA; the token claims ES256. Importing the RSA JWK
    // under ECDSA parameters must fail closed rather than throw out of the
    // verifier.
    const result = await verifyCompactJws(token, rsa.jwk, "ES256");
    expect(result.ok).toBe(false);
  });

  test("REFUSES a malformed compact serialization", async () => {
    const key = await generateRs256Key("k1");
    for (const bad of ["", "a", "a.b", "a.b.c.d", "....", "not-a-token"]) {
      const result = await verifyCompactJws(bad, key.jwk, "RS256");
      expect(result.ok, `expected ${JSON.stringify(bad)} to be refused`).toBe(false);
    }
  });

  test("REFUSES a token whose payload is not a JSON object", async () => {
    const key = await generateRs256Key("k1");
    const token = await signJwt(key, [] as unknown as Record<string, unknown>);
    const result = await verifyCompactJws(token, key.jwk, "RS256");
    expect(result.ok).toBe(false);
  });
});

describe("decodeJwsHeader", () => {
  test("reads alg + kid without trusting them", async () => {
    const key = await generateRs256Key("rotate-me");
    const token = await signJwt(key, { sub: "u1" });
    expect(decodeJwsHeader(token)).toEqual({ alg: "RS256", kid: "rotate-me" });
  });

  test("returns null for a header that is not JSON", () => {
    expect(decodeJwsHeader("%%%.payload.sig")).toBeNull();
  });

  test("returns a null kid rather than throwing when the IdP omits it", async () => {
    const key = await generateRs256Key("k1");
    const token = await signJwt(key, { sub: "u1" }, { kid: undefined });
    expect(decodeJwsHeader(token)).toEqual({ alg: "RS256", kid: null });
  });
});
