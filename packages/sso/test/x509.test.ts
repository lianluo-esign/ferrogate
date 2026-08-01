import { describe, expect, test } from "vitest";
import { SamlError, parseIdpPublicKey } from "../src/index.js";
import { EC_CERT_PEM, IDP_CERT_PEM, OTHER_CERT_PEM } from "./fixtures.js";
import { pemToDer, toBase64 } from "./support.js";

function refusal(work: () => unknown, code: string, message?: string | RegExp): SamlError {
  let caught: unknown = null;
  try {
    work();
  } catch (error) {
    caught = error;
  }
  expect(caught, "the parse must REFUSE, not return a key").toBeInstanceOf(SamlError);
  const samlError = caught as SamlError;
  expect(samlError.code).toBe(code);
  if (typeof message === "string") expect(samlError.message).toBe(message);
  else if (message) expect(samlError.message).toMatch(message);
  return samlError;
}

describe("X.509 IdP signing certificate", () => {
  test("PEM armor is stripped and the SubjectPublicKeyInfo is extracted", () => {
    const key = parseIdpPublicKey(IDP_CERT_PEM);
    // The SPKI is a DER SEQUENCE, and for a 2048-bit RSA key it is 294 bytes.
    expect(key.spki[0]).toBe(0x30);
    expect(key.spki.length).toBe(294);
    // The PKCS#1 `RSAPublicKey` is the BIT STRING payload — a SEQUENCE too,
    // 270 bytes for RSA-2048, and it is what the Rust port handed to `ring`.
    expect(key.pkcs1[0]).toBe(0x30);
    expect(key.pkcs1.length).toBe(270);
  });

  test("the extracted SPKI is sliced VERBATIM out of the certificate DER", () => {
    const der = pemToDer(IDP_CERT_PEM);
    const key = parseIdpPublicKey(IDP_CERT_PEM);
    let found = -1;
    for (let start = 0; start + key.spki.length <= der.length; start += 1) {
      let matches = true;
      for (let index = 0; index < key.spki.length; index += 1) {
        if (der[start + index] !== key.spki[index]) {
          matches = false;
          break;
        }
      }
      if (matches) {
        found = start;
        break;
      }
    }
    expect(found, "the SPKI must be a byte-identical slice, never re-encoded").toBeGreaterThan(0);
  });

  test("the extracted SPKI is importable by WebCrypto", async () => {
    const key = parseIdpPublicKey(IDP_CERT_PEM);
    const imported = await crypto.subtle.importKey(
      "spki",
      key.spki as unknown as ArrayBuffer,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    expect(imported.type).toBe("public");
    expect((imported.algorithm as { modulusLength: number }).modulusLength).toBe(2048);
  });

  test("bare base64 DER (no PEM armor) is accepted, exactly as PEM", () => {
    const bare = IDP_CERT_PEM.split("\n")
      .filter((line) => !line.startsWith("-----"))
      .join("");
    expect(toBase64(parseIdpPublicKey(bare).spki)).toBe(
      toBase64(parseIdpPublicKey(IDP_CERT_PEM).spki),
    );
  });

  test("a NON-RSA (EC) certificate is refused rather than mis-imported", () => {
    refusal(() => parseIdpPublicKey(EC_CERT_PEM), "invalid_x509_certificate", /RSA/);
  });

  test("a certificate that is not valid base64 is refused", () => {
    refusal(
      () => parseIdpPublicKey("-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----"),
      "certificate_not_base64",
      /^certificate is not valid base64: /,
    );
  });

  test("a TRUNCATED certificate DER is refused, not partially parsed", () => {
    const der = pemToDer(IDP_CERT_PEM);
    refusal(
      () => parseIdpPublicKey(toBase64(der.slice(0, 120))),
      "invalid_x509_certificate",
      /^invalid X\.509 certificate: /,
    );
  });

  test("an empty certificate body is refused", () => {
    refusal(() => parseIdpPublicKey(""), "invalid_x509_certificate");
  });

  test("a DER blob that is not a certificate at all is refused", () => {
    // A bare INTEGER, well-formed DER but nothing like a Certificate.
    refusal(
      () => parseIdpPublicKey(toBase64(new Uint8Array([0x02, 0x01, 0x2a]))),
      "invalid_x509_certificate",
    );
  });

  test("an indefinite-length (BER, not DER) encoding is refused", () => {
    // SEQUENCE with indefinite length — legal BER, illegal DER, and a classic
    // parser-differential wedge.
    refusal(
      () => parseIdpPublicKey(toBase64(new Uint8Array([0x30, 0x80, 0x02, 0x01, 0x2a, 0x00, 0x00]))),
      "invalid_x509_certificate",
      /indefinite/,
    );
  });

  test("a certificate whose public-key BIT STRING is empty is refused", () => {
    // Take the real certificate and blank out the subjectPublicKey payload by
    // replacing the whole SPKI with a syntactically valid but empty one.
    const emptySpki = new Uint8Array([
      0x30,
      0x0f, // SEQUENCE (SubjectPublicKeyInfo), 15 content octets
      0x30,
      0x0b, // SEQUENCE (AlgorithmIdentifier), 11 content octets
      0x06,
      0x09,
      0x2a,
      0x86,
      0x48,
      0x86,
      0xf7,
      0x0d,
      0x01,
      0x01,
      0x01, // OID rsaEncryption
      0x03,
      0x00, // BIT STRING, zero-length content
    ]);
    const der = buildMinimalCertificate(emptySpki);
    refusal(() => parseIdpPublicKey(toBase64(der)), "certificate_empty_public_key");
  });
});

/**
 * Wraps an arbitrary SubjectPublicKeyInfo in the smallest structurally valid
 * `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }`.
 * Used only to build the degenerate shapes openssl will not produce.
 */
function buildMinimalCertificate(spki: Uint8Array): Uint8Array {
  const der = (tag: number, content: number[]): number[] => {
    if (content.length < 0x80) return [tag, content.length, ...content];
    const lengthBytes: number[] = [];
    let remaining = content.length;
    while (remaining > 0) {
      lengthBytes.unshift(remaining & 0xff);
      remaining >>= 8;
    }
    return [tag, 0x80 | lengthBytes.length, ...lengthBytes, ...content];
  };
  const emptySeq = [0x30, 0x00];
  const tbs = der(0x30, [
    ...der(0xa0, [0x02, 0x01, 0x02]), // [0] version v3
    0x02,
    0x01,
    0x01, // serialNumber
    ...emptySeq, // signature AlgorithmIdentifier
    ...emptySeq, // issuer
    ...emptySeq, // validity
    ...emptySeq, // subject
    ...spki, // subjectPublicKeyInfo
  ]);
  return new Uint8Array(der(0x30, [...tbs, ...emptySeq, 0x03, 0x01, 0x00]));
}

describe("X.509 fixture sanity", () => {
  test("the two RSA fixtures really are different keys", () => {
    // Guards every "wrong signing key" assertion in the suite: if openssl had
    // been re-run in a way that produced the same key twice, those tests would
    // pass for the wrong reason.
    expect(toBase64(parseIdpPublicKey(IDP_CERT_PEM).spki)).not.toBe(
      toBase64(parseIdpPublicKey(OTHER_CERT_PEM).spki),
    );
  });
});
