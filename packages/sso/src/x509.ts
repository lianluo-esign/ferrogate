import { Base64Error, decodeBase64Strict } from "./base64.js";
import {
  DerError,
  TAG_BIT_STRING,
  TAG_OID,
  TAG_SEQUENCE,
  decodeOid,
  expectTag,
  readChildren,
  readTlv,
} from "./der.js";
import { type SamlError, samlError } from "./errors.js";

/** `rsaEncryption`, RFC 8017 A.1. Anything else is refused. */
const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

/**
 * The IdP's verification key, in the two shapes the two ports need.
 *
 * The Rust port returned only `pkcs1`, because `ring`'s
 * `RSA_PKCS1_*` verifiers consume a bare `RSAPublicKey ::= SEQUENCE
 * { modulus, publicExponent }`. WebCrypto's `importKey` consumes the enclosing
 * `SubjectPublicKeyInfo` instead, so this port carries both: `spki` is what is
 * actually used to verify, `pkcs1` is kept because it is the Rust port's
 * observable output and pinning it keeps the two ports diffable.
 */
export interface IdpPublicKey {
  /** The `SubjectPublicKeyInfo` TLV, sliced verbatim from the certificate. */
  readonly spki: Uint8Array;
  /** The PKCS#1 `RSAPublicKey` DER — the BIT STRING payload. */
  readonly pkcs1: Uint8Array;
}

/**
 * `saml.rs::certificate_der` — strips optional PEM armor and whitespace,
 * returning raw DER. Accepts PEM or bare base64, exactly as the Rust port did
 * (real-world IdP metadata carries `<ds:X509Certificate>` bodies with no armor).
 */
function certificateDer(certificate: string): Uint8Array {
  const trimmed = certificate.trim();
  const base64Body = trimmed.includes("BEGIN CERTIFICATE")
    ? trimmed
        .split("\n")
        .filter((line) => !line.startsWith("-----"))
        .join("")
        .replace(/\s+/g, "")
    : trimmed.split(/\s+/).join("");
  try {
    return decodeBase64Strict(base64Body);
  } catch (error) {
    const detail = error instanceof Base64Error ? error.message : String(error);
    throw samlError("certificate_not_base64", `certificate is not valid base64: ${detail}`);
  }
}

/**
 * `saml.rs::parse_idp_public_key` — parses the IdP signing certificate and
 * returns its RSA public key. Fails closed for a non-RSA or unparseable
 * certificate.
 *
 * The walk:
 *
 * ```text
 * Certificate     ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
 * TBSCertificate  ::= SEQUENCE { [0] version DEFAULT v1, serialNumber, signature,
 *                                issuer, validity, subject, subjectPublicKeyInfo, ... }
 * ```
 *
 * `[0] version` is OPTIONAL, so the SPKI is the 6th child for a v1 certificate
 * and the 7th for v2/v3 — detected from the context tag rather than assumed.
 */
export function parseIdpPublicKey(certificate: string): IdpPublicKey {
  const der = certificateDer(certificate);
  try {
    return extractPublicKey(der);
  } catch (error) {
    if (isSamlError(error)) throw error;
    const detail = error instanceof Error ? error.message : String(error);
    throw samlError("invalid_x509_certificate", `invalid X.509 certificate: ${detail}`);
  }
}

function isSamlError(error: unknown): error is SamlError {
  return error instanceof Error && error.name === "SamlError";
}

function extractPublicKey(der: Uint8Array): IdpPublicKey {
  const certificate = expectTag(readTlv(der, 0), TAG_SEQUENCE, "Certificate");
  if (certificate.end !== der.length) {
    throw new DerError("trailing octets after the Certificate SEQUENCE");
  }
  const certificateChildren = readChildren(certificate, der);
  const tbs = expectTag(
    certificateChildren[0] ?? missing("tbsCertificate"),
    TAG_SEQUENCE,
    "tbsCertificate",
  );
  const fields = readChildren(tbs, der);
  // `[0] EXPLICIT version` is context-specific constructed tag 0xA0.
  const versionPresent = (fields[0]?.tag ?? 0) === 0xa0;
  const spkiIndex = versionPresent ? 6 : 5;
  const spkiNode = expectTag(
    fields[spkiIndex] ?? missing("subjectPublicKeyInfo"),
    TAG_SEQUENCE,
    "subjectPublicKeyInfo",
  );

  const spkiChildren = readChildren(spkiNode, der);
  const algorithm = expectTag(
    spkiChildren[0] ?? missing("AlgorithmIdentifier"),
    TAG_SEQUENCE,
    "AlgorithmIdentifier",
  );
  const algorithmOid = expectTag(
    readChildren(algorithm, der)[0] ?? missing("algorithm OID"),
    TAG_OID,
    "algorithm OID",
  );
  const oid = decodeOid(algorithmOid.content);
  if (oid !== OID_RSA_ENCRYPTION) {
    // The Rust port leaned on `ring` rejecting a non-RSA key at verify time.
    // Refusing here instead means a tenant that pastes an EC certificate is
    // told so at CONFIG time rather than at every user's first login.
    throw new DerError(
      `public key algorithm ${oid} is not RSA (${OID_RSA_ENCRYPTION}); only RSA signing keys are supported`,
    );
  }

  const bitString = expectTag(
    spkiChildren[1] ?? missing("subjectPublicKey"),
    TAG_BIT_STRING,
    "subjectPublicKey",
  );
  if (bitString.content.length === 0) {
    throw samlError("certificate_empty_public_key", "certificate has an empty public key");
  }
  const unusedBits = bitString.content[0] as number;
  if (unusedBits !== 0) {
    throw new DerError(`subjectPublicKey has ${unusedBits} unused bits; expected 0`);
  }
  // For an RSA key the BIT STRING content IS the DER of
  // `RSAPublicKey ::= SEQUENCE { modulus, exponent }` — the same observation
  // the Rust port's comment makes.
  const pkcs1 = bitString.content.subarray(1);
  if (pkcs1.length === 0) {
    throw samlError("certificate_empty_public_key", "certificate has an empty public key");
  }
  return { spki: spkiNode.raw, pkcs1 };
}

function missing(what: string): never {
  throw new DerError(`certificate is missing ${what}`);
}

/**
 * Imports the certificate's key for RSASSA-PKCS1-v1_5 verification under the
 * given digest.
 *
 * ## Workers have no trust store — what that means here
 *
 * There is no `NODE_EXTRA_CA_CERTS`, no system root store, and no
 * certificate-chain API in workerd. This port therefore does NOT, and CANNOT,
 * validate a chain, check a CA signature, honour `notBefore`/`notAfter` on the
 * certificate, or consult a CRL/OCSP responder.
 *
 * That is not a regression: the Rust port did not do any of those either, and
 * for this protocol it is not the relevant control. SAML IdP signing
 * certificates are conventionally SELF-SIGNED and are pinned out of band — the
 * tenant owner pastes the exact certificate from their IdP's metadata into
 * `POST /v1/admin/team/sso-config`, and `parseIdpPublicKey` refuses at that
 * moment if it is not usable. **The configured certificate IS the trust
 * anchor.** Issuer validation is therefore not "does a CA vouch for this
 * certificate" but "was this assertion signed by the exact key this tenant
 * pinned", plus the `Issuer`-element equality check against the configured
 * `saml_idp_entity_id`.
 *
 * What the tenant loses relative to a CA-validated model is revocation and
 * expiry: a compromised or rotated IdP key stays trusted until the tenant
 * updates the config. That is inherent to key pinning, it is what the Rust
 * service did, and the mitigation is the same — rotate the config. It is called
 * out here so nobody later reads "no chain validation" as an oversight.
 */
export async function importIdpVerificationKey(
  certificate: string,
  hash: "SHA-256" | "SHA-1",
): Promise<CryptoKey> {
  const key = parseIdpPublicKey(certificate);
  try {
    return await crypto.subtle.importKey(
      "spki",
      key.spki as unknown as ArrayBuffer,
      { name: "RSASSA-PKCS1-v1_5", hash },
      false,
      ["verify"],
    );
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw samlError(
      "invalid_x509_certificate",
      `invalid X.509 certificate: public key could not be imported: ${detail}`,
    );
  }
}
