import { Base64Error, decodeBase64Strict } from "./base64.js";
import { rustDebugStr, samlError } from "./errors.js";
import { urldecode } from "./urlcodec.js";
import { importIdpVerificationKey } from "./x509.js";

export const SIG_ALG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
export const SIG_ALG_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

/**
 * Parsed HTTP-Redirect binding query parameters.
 *
 * The `*Raw` fields preserve the EXACT percent-encoded octets as received.
 * That is the whole point of this class: the redirect-binding signature is
 * computed over the query octet string, and any re-serialisation — decode then
 * re-encode, `URLSearchParams`, sorting, normalising `%7e` to `~` — produces a
 * different string. Verifying over a re-serialised form is a textbook
 * signature bypass: it lets a signature made over the canonical form be
 * replayed against a semantically different raw form, and vice versa.
 * `test/redirect-binding.test.ts` holds this from both directions.
 */
export class RedirectBindingParams {
  /** URL-decoded base64 `SAMLResponse` (still DEFLATE-compressed). */
  readonly samlResponse: string | null;
  /** URL-decoded `RelayState` — our opaque flow `state` token. */
  readonly relayState: string | null;

  private readonly samlResponseRaw: string | null;
  private readonly relayStateRaw: string | null;
  private readonly sigAlgRaw: string | null;
  private readonly signatureRaw: string | null;

  private constructor(
    samlResponseRaw: string | null,
    relayStateRaw: string | null,
    sigAlgRaw: string | null,
    signatureRaw: string | null,
  ) {
    this.samlResponseRaw = samlResponseRaw;
    this.relayStateRaw = relayStateRaw;
    this.sigAlgRaw = sigAlgRaw;
    this.signatureRaw = signatureRaw;
    this.samlResponse = samlResponseRaw === null ? null : urldecode(samlResponseRaw);
    this.relayState = relayStateRaw === null ? null : urldecode(relayStateRaw);
  }

  /**
   * `saml.rs::RedirectBindingParams::parse` — splits the raw query, preserving
   * each value's original percent-encoding (no decode) so the signed octet
   * string can be reconstructed byte-for-byte.
   *
   * A repeated parameter takes the LAST occurrence, matching the Rust loop.
   * What matters is not which one wins but that the SAME occurrence feeds both
   * the signed octet string and the decoded payload — otherwise an attacker
   * could append a second `SAMLResponse`, have the signature checked against
   * one and the assertion parsed from the other.
   */
  static parse(rawQuery: string): RedirectBindingParams {
    let samlResponseRaw: string | null = null;
    let relayStateRaw: string | null = null;
    let sigAlgRaw: string | null = null;
    let signatureRaw: string | null = null;
    for (const pair of rawQuery.split("&")) {
      const separator = pair.indexOf("=");
      if (separator < 0) continue;
      const key = pair.slice(0, separator);
      const value = pair.slice(separator + 1);
      switch (key) {
        case "SAMLResponse":
          samlResponseRaw = value;
          break;
        case "RelayState":
          relayStateRaw = value;
          break;
        case "SigAlg":
          sigAlgRaw = value;
          break;
        case "Signature":
          signatureRaw = value;
          break;
        default:
          break;
      }
    }
    return new RedirectBindingParams(samlResponseRaw, relayStateRaw, sigAlgRaw, signatureRaw);
  }

  /**
   * The exact octet string the IdP signed, reconstructed from the RECEIVED RAW
   * values in the binding's fixed order (`SAMLResponse`, then `RelayState` if
   * present, then `SigAlg`) — SAML 2.0 Bindings §3.4.4.1.
   *
   * The order is fixed by the spec, not by the order the parameters arrived
   * in, so a redirect whose parameters were reordered in transit still
   * verifies.
   */
  signedOctetString(): string {
    if (this.samlResponseRaw === null) {
      throw samlError("missing_saml_response", "missing SAMLResponse");
    }
    if (this.sigAlgRaw === null) {
      throw samlError("missing_sig_alg", "missing SigAlg");
    }
    let signed = `SAMLResponse=${this.samlResponseRaw}`;
    if (this.relayStateRaw !== null) {
      signed += `&RelayState=${this.relayStateRaw}`;
    }
    signed += `&SigAlg=${this.sigAlgRaw}`;
    return signed;
  }

  get signaturePresent(): boolean {
    return this.signatureRaw !== null;
  }

  /** @internal — read by `verifyRedirectSignature`. */
  get rawSignature(): string | null {
    return this.signatureRaw;
  }

  /** @internal — read by `verifyRedirectSignature`. */
  get rawSigAlg(): string | null {
    return this.sigAlgRaw;
  }
}

export function parseRedirectBindingParams(rawQuery: string): RedirectBindingParams {
  return RedirectBindingParams.parse(rawQuery);
}

/**
 * `saml.rs::verify_redirect_signature` — verifies the detached HTTP-Redirect
 * binding signature against the IdP certificate.
 *
 * Fails closed on a missing signature, an unsupported `SigAlg`, a
 * non-base64 signature, an unusable certificate, or a verification failure.
 * There is no branch that returns normally without `crypto.subtle.verify`
 * having returned `true`.
 */
export async function verifyRedirectSignature(
  params: RedirectBindingParams,
  certificate: string,
): Promise<void> {
  const signatureRaw = params.rawSignature;
  if (signatureRaw === null) {
    throw samlError("response_not_signed", "response is not signed (no Signature parameter)");
  }
  if (params.rawSigAlg === null) {
    throw samlError("missing_sig_alg", "missing SigAlg");
  }
  const sigAlg = urldecode(params.rawSigAlg);
  let hash: "SHA-256" | "SHA-1";
  switch (sigAlg) {
    case SIG_ALG_RSA_SHA256:
      hash = "SHA-256";
      break;
    case SIG_ALG_RSA_SHA1:
      // Legacy, still emitted by long-lived IdP deployments; the Rust port
      // accepted it via ring's `..._SHA1_FOR_LEGACY_USE_ONLY` verifier.
      hash = "SHA-1";
      break;
    default:
      throw samlError("unsupported_sig_alg", `unsupported SigAlg ${rustDebugStr(sigAlg)}`);
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = decodeBase64Strict(urldecode(signatureRaw));
  } catch (error) {
    const detail = error instanceof Base64Error ? error.message : String(error);
    throw samlError("signature_not_base64", `signature is not valid base64: ${detail}`);
  }

  const signed = params.signedOctetString();
  const key = await importIdpVerificationKey(certificate, hash);

  const verified = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    signatureBytes as unknown as ArrayBuffer,
    new TextEncoder().encode(signed) as unknown as ArrayBuffer,
  );
  if (!verified) {
    throw samlError(
      "signature_verification_failed",
      "signature does not verify against the IdP certificate",
    );
  }
}
