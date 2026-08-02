import { encodeBase64 } from "./base64.js";
import { deflateRaw } from "./deflate.js";
import { formatSamlInstant } from "./instant.js";
import { urlencode } from "./urlcodec.js";

const HTTP_REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

/** `saml.rs::xml_escape` — minimal escaping for the values we emit. */
function xmlEscape(value: string): string {
  let escaped = "";
  for (const ch of value) {
    switch (ch) {
      case "&":
        escaped += "&amp;";
        break;
      case "<":
        escaped += "&lt;";
        break;
      case ">":
        escaped += "&gt;";
        break;
      case '"':
        escaped += "&quot;";
        break;
      case "'":
        escaped += "&apos;";
        break;
      default:
        escaped += ch;
    }
  }
  return escaped;
}

export interface AuthnRequestOptions {
  readonly idpSsoUrl: string;
  readonly acsUrl: string;
  readonly spEntityId: string;
  readonly requestId: string;
  readonly relayState: string;
  /**
   * The `IssueInstant`. Passed in rather than read from the clock so the
   * caller's single `now()` port drives every timestamp in a flow — a handler
   * that reads the clock itself cannot be tested for skew behaviour.
   */
  readonly nowUnix: number;
}

/**
 * `saml.rs::build_authn_request_redirect` — builds the SP-initiated
 * `AuthnRequest`, DEFLATE-compresses + base64-encodes it per the
 * HTTP-Redirect binding, and returns the full IdP redirect URL.
 *
 * We do not sign our own request; IdPs that require signed requests were out
 * of scope for the Rust slice and remain so here.
 */
export async function buildAuthnRequestRedirect(options: AuthnRequestOptions): Promise<string> {
  const issueInstant = formatSamlInstant(options.nowUnix);
  const xml = [
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" `,
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${xmlEscape(options.requestId)}" `,
    `Version="2.0" IssueInstant="${issueInstant}" `,
    `Destination="${xmlEscape(options.idpSsoUrl)}" ProtocolBinding="${HTTP_REDIRECT_BINDING}" `,
    `AssertionConsumerServiceURL="${xmlEscape(options.acsUrl)}">`,
    `<saml:Issuer>${xmlEscape(options.spEntityId)}</saml:Issuer>`,
    "</samlp:AuthnRequest>",
  ].join("");

  const compressed = await deflateRaw(new TextEncoder().encode(xml));
  const encoded = encodeBase64(compressed);
  const separator = options.idpSsoUrl.includes("?") ? "&" : "?";
  return `${options.idpSsoUrl}${separator}SAMLRequest=${urlencode(encoded)}&RelayState=${urlencode(
    options.relayState,
  )}`;
}
