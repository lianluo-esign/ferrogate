import { describe, expect, test } from "vitest";
import { SamlError, parseRedirectBindingParams, verifyRedirectSignature } from "../src/index.js";
import {
  IDP_CERT_PEM,
  IDP_KEY_PKCS8_PEM,
  OTHER_CERT_PEM,
  OTHER_KEY_PKCS8_PEM,
} from "./fixtures.js";
import {
  SIG_ALG_SHA1,
  SIG_ALG_SHA256,
  encodedResponse,
  idpPercentEncode,
  signOctets,
  signedQuery,
} from "./support.js";

async function expectRefusal(
  work: Promise<unknown>,
  code: string,
  message?: string | RegExp,
): Promise<SamlError> {
  const error = await work.then(
    () => null,
    (caught: unknown) => caught,
  );
  expect(error, "the call must REFUSE, not resolve").toBeInstanceOf(SamlError);
  const samlError = error as SamlError;
  expect(samlError.code).toBe(code);
  if (typeof message === "string") expect(samlError.message).toBe(message);
  else if (message) expect(samlError.message).toMatch(message);
  return samlError;
}

describe("HTTP-Redirect binding signature (SAML 2.0 Bindings §3.4.4.1)", () => {
  test("a correctly signed redirect verifies against the IdP certificate", async () => {
    const response = await encodedResponse();
    const query = await signedQuery(IDP_KEY_PKCS8_PEM, response, "opaque-state-token");

    await expect(
      verifyRedirectSignature(parseRedirectBindingParams(query), IDP_CERT_PEM),
    ).resolves.toBeUndefined();
  });

  test("RSA-SHA1 (legacy) verifies too", async () => {
    const response = await encodedResponse();
    const query = await signedQuery(IDP_KEY_PKCS8_PEM, response, "opaque-state-token", {
      sigAlg: SIG_ALG_SHA1,
      hash: "SHA-1",
    });

    await expect(
      verifyRedirectSignature(parseRedirectBindingParams(query), IDP_CERT_PEM),
    ).resolves.toBeUndefined();
  });

  test("a tampered RelayState is refused", async () => {
    const response = await encodedResponse();
    const query = await signedQuery(IDP_KEY_PKCS8_PEM, response, "opaque-state-token");
    const tampered = query.replace("RelayState=opaque-state-token", "RelayState=attacker-state");
    expect(tampered).not.toBe(query);

    await expectRefusal(
      verifyRedirectSignature(parseRedirectBindingParams(tampered), IDP_CERT_PEM),
      "signature_verification_failed",
      "signature does not verify against the IdP certificate",
    );
  });

  test("a tampered SAMLResponse payload is refused", async () => {
    const response = await encodedResponse();
    const other = await encodedResponse({ audience: "attacker-sp" });
    const query = await signedQuery(IDP_KEY_PKCS8_PEM, response, "opaque-state-token");
    const tampered = query.replace(idpPercentEncode(response), idpPercentEncode(other));
    expect(tampered).not.toBe(query);

    await expectRefusal(
      verifyRedirectSignature(parseRedirectBindingParams(tampered), IDP_CERT_PEM),
      "signature_verification_failed",
    );
  });

  /**
   * THE signature-bypass regression. A verifier that URL-decodes the query and
   * re-serialises it (with `URLSearchParams`, `encodeURIComponent`, or any
   * other encoder) before hashing is verifying a string the IdP never signed —
   * and, symmetrically, will accept a signature computed over that re-
   * serialised string by anyone who can guess the canonicalisation. The only
   * safe input is the octets as received.
   *
   * `~` and `*` are the wedge: the IdP percent-encodes both (RFC 3986
   * unreserved set is `A-Za-z0-9-._~`... and `encodeURIComponent` leaves BOTH
   * `~` and `*` bare), so the raw octets and any re-serialisation differ.
   */
  test("a signature valid over a RE-SERIALISED form but not the raw octets is refused", async () => {
    const response = await encodedResponse();
    const relayState = "state~token*value";

    const rawResponseEnc = idpPercentEncode(response);
    const rawRelayEnc = idpPercentEncode(relayState);
    const rawSigAlgEnc = idpPercentEncode(SIG_ALG_SHA256);

    // What a re-serialising verifier would reconstruct: decode, then re-encode
    // with `encodeURIComponent` (which leaves `~` and `*` bare).
    const reserialised =
      `SAMLResponse=${encodeURIComponent(response)}` +
      `&RelayState=${encodeURIComponent(relayState)}` +
      `&SigAlg=${encodeURIComponent(SIG_ALG_SHA256)}`;
    const rawOctets = `SAMLResponse=${rawResponseEnc}&RelayState=${rawRelayEnc}&SigAlg=${rawSigAlgEnc}`;
    expect(reserialised, "the fixture is only meaningful if the two encodings differ").not.toBe(
      rawOctets,
    );

    const signature = await signOctets(IDP_KEY_PKCS8_PEM, reserialised);
    const query = `${rawOctets}&Signature=${idpPercentEncode(signature)}`;

    await expectRefusal(
      verifyRedirectSignature(parseRedirectBindingParams(query), IDP_CERT_PEM),
      "signature_verification_failed",
      "signature does not verify against the IdP certificate",
    );

    // Mirror: over the SAME query, a signature over the RAW octets IS accepted.
    // Without this half the test above would also pass against a verifier that
    // simply rejects everything.
    const rawSignature = await signOctets(IDP_KEY_PKCS8_PEM, rawOctets);
    await expect(
      verifyRedirectSignature(
        parseRedirectBindingParams(`${rawOctets}&Signature=${idpPercentEncode(rawSignature)}`),
        IDP_CERT_PEM,
      ),
    ).resolves.toBeUndefined();
  });

  test("a signature valid over the URL-DECODED form is refused", async () => {
    const response = await encodedResponse();
    const relayState = "opaque-state-token";
    const decodedForm = `SAMLResponse=${response}&RelayState=${relayState}&SigAlg=${SIG_ALG_SHA256}`;
    const signature = await signOctets(IDP_KEY_PKCS8_PEM, decodedForm);
    const query =
      `SAMLResponse=${idpPercentEncode(response)}` +
      `&RelayState=${idpPercentEncode(relayState)}` +
      `&SigAlg=${idpPercentEncode(SIG_ALG_SHA256)}` +
      `&Signature=${idpPercentEncode(signature)}`;

    await expectRefusal(
      verifyRedirectSignature(parseRedirectBindingParams(query), IDP_CERT_PEM),
      "signature_verification_failed",
    );
  });

  test("the signed octet string is rebuilt in the binding's fixed order, not the received order", async () => {
    const response = await encodedResponse();
    const query = await signedQuery(IDP_KEY_PKCS8_PEM, response, "opaque-state-token");
    const parts = new Map(query.split("&").map((pair) => pair.split("=") as [string, string]));
    const shuffled = ["SigAlg", "RelayState", "Signature", "SAMLResponse"]
      .map((key) => `${key}=${parts.get(key)}`)
      .join("&");
    expect(shuffled).not.toBe(query);

    await expect(
      verifyRedirectSignature(parseRedirectBindingParams(shuffled), IDP_CERT_PEM),
    ).resolves.toBeUndefined();
  });

  test("a signature from a DIFFERENT key is refused", async () => {
    const response = await encodedResponse();
    const query = await signedQuery(OTHER_KEY_PKCS8_PEM, response, "opaque-state-token");

    await expectRefusal(
      verifyRedirectSignature(parseRedirectBindingParams(query), IDP_CERT_PEM),
      "signature_verification_failed",
    );
    // ...and the same bytes DO verify against that key's own certificate, so
    // the refusal above is about the key, not about a broken fixture.
    await expect(
      verifyRedirectSignature(parseRedirectBindingParams(query), OTHER_CERT_PEM),
    ).resolves.toBeUndefined();
  });

  test("an UNSIGNED response is refused (no fall-through to trusted)", async () => {
    const response = await encodedResponse();
    const query =
      `SAMLResponse=${idpPercentEncode(response)}` +
      `&RelayState=x&SigAlg=${idpPercentEncode(SIG_ALG_SHA256)}`;

    await expectRefusal(
      verifyRedirectSignature(parseRedirectBindingParams(query), IDP_CERT_PEM),
      "response_not_signed",
      "response is not signed (no Signature parameter)",
    );
  });

  test("a missing SigAlg is refused", async () => {
    const response = await encodedResponse();
    const query = `SAMLResponse=${idpPercentEncode(response)}&RelayState=x&Signature=AAAA`;

    await expectRefusal(
      verifyRedirectSignature(parseRedirectBindingParams(query), IDP_CERT_PEM),
      "missing_sig_alg",
      "missing SigAlg",
    );
  });

  test("an unsupported SigAlg is refused rather than defaulted", async () => {
    const response = await encodedResponse();
    const evil = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
    const octets = `SAMLResponse=${idpPercentEncode(response)}&RelayState=x&SigAlg=${idpPercentEncode(evil)}`;
    const signature = await signOctets(IDP_KEY_PKCS8_PEM, octets);
    const query = `${octets}&Signature=${idpPercentEncode(signature)}`;

    await expectRefusal(
      verifyRedirectSignature(parseRedirectBindingParams(query), IDP_CERT_PEM),
      "unsupported_sig_alg",
      `unsupported SigAlg "${evil}"`,
    );
  });

  test("a missing SAMLResponse is refused when reconstructing the octet string", async () => {
    const query = `RelayState=x&SigAlg=${idpPercentEncode(SIG_ALG_SHA256)}&Signature=AAAA`;

    await expectRefusal(
      verifyRedirectSignature(parseRedirectBindingParams(query), IDP_CERT_PEM),
      "missing_saml_response",
      "missing SAMLResponse",
    );
  });

  test("a non-base64 Signature is refused, not silently treated as empty", async () => {
    const response = await encodedResponse();
    const query =
      `SAMLResponse=${idpPercentEncode(response)}&RelayState=x` +
      `&SigAlg=${idpPercentEncode(SIG_ALG_SHA256)}&Signature=%40%40not-base64%40%40`;

    await expectRefusal(
      verifyRedirectSignature(parseRedirectBindingParams(query), IDP_CERT_PEM),
      "signature_not_base64",
      /^signature is not valid base64: /,
    );
  });

  test("HTTP parameter pollution cannot split the signed octets from the parsed payload", async () => {
    const signedResponse = await encodedResponse();
    const evilResponse = await encodedResponse({ audience: "attacker-sp" });
    const query = await signedQuery(IDP_KEY_PKCS8_PEM, signedResponse, "opaque-state-token");
    // Append a SECOND SAMLResponse. Whichever occurrence wins, the octet string
    // and the decoded payload must come from the SAME one, so the signature
    // cannot cover one payload while the parser reads another.
    const polluted = `${query}&SAMLResponse=${idpPercentEncode(evilResponse)}`;
    const params = parseRedirectBindingParams(polluted);

    await expectRefusal(
      verifyRedirectSignature(params, IDP_CERT_PEM),
      "signature_verification_failed",
    );
    expect(params.samlResponse).toBe(evilResponse);
  });

  test("RelayState is optional in the signed octet string (SAML 2.0 allows its absence)", async () => {
    const response = await encodedResponse();
    const octets = `SAMLResponse=${idpPercentEncode(response)}&SigAlg=${idpPercentEncode(SIG_ALG_SHA256)}`;
    const signature = await signOctets(IDP_KEY_PKCS8_PEM, octets);

    await expect(
      verifyRedirectSignature(
        parseRedirectBindingParams(`${octets}&Signature=${idpPercentEncode(signature)}`),
        IDP_CERT_PEM,
      ),
    ).resolves.toBeUndefined();
  });

  test("params expose the URL-DECODED values for lookup while signing over the raw ones", () => {
    const params = parseRedirectBindingParams(
      "SAMLResponse=a%2Bb%2F&RelayState=state%7Etoken&SigAlg=x&Signature=y",
    );
    expect(params.samlResponse).toBe("a+b/");
    expect(params.relayState).toBe("state~token");
  });
});
