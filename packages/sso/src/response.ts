import { Base64Error, decodeBase64Strict } from "./base64.js";
import {
  MAX_INFLATED_SAML_RESPONSE_BYTES,
  MAX_SAML_RESPONSE_B64_CHARS,
  inflateFailure,
  inflateRawBounded,
} from "./deflate.js";
import { type SamlError, rustDebug, samlError } from "./errors.js";
import { parseSamlInstant } from "./instant.js";
import { type XmlAttribute, XmlError, scanXml } from "./xml.js";

export { MAX_INFLATED_SAML_RESPONSE_BYTES, MAX_SAML_RESPONSE_B64_CHARS };

const STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

/** `saml.rs::AssertionExpectations` — what a valid assertion must satisfy. */
export interface AssertionExpectations {
  readonly spEntityId: string;
  /** `null` disables the issuer check, matching the Rust `Option`. */
  readonly idpEntityId?: string | null;
  /** `null` disables the `InResponseTo` check (an IdP-initiated flow). */
  readonly inResponseTo?: string | null;
  readonly emailAttribute?: string | null;
  readonly nameAttribute?: string | null;
  readonly groupsAttribute?: string | null;
  readonly nowUnix: number;
  readonly clockSkewSecs: number;
}

/** `saml.rs::ValidatedAssertion` — the identity extracted from a verified assertion. */
export interface ValidatedAssertion {
  readonly email: string;
  readonly displayName: string;
  readonly groups: string[];
}

interface ParsedResponse {
  statusCode: string | null;
  responseInResponseTo: string | null;
  issuer: string | null;
  notBefore: string | null;
  notOnOrAfter: string | null;
  audiences: string[];
  nameId: string | null;
  attributes: Map<string, string[]>;
}

function attributeValue(attributes: XmlAttribute[], wanted: string): string | null {
  for (const attribute of attributes) {
    if (attribute.name === wanted) return attribute.value;
  }
  return null;
}

/** `saml.rs::capture_element` — pulls the fields we care about off an element. */
function captureElement(
  parsed: ParsedResponse,
  state: { currentAttribute: string | null },
  name: string,
  attributes: XmlAttribute[],
): void {
  switch (name) {
    case "Response":
      parsed.responseInResponseTo = attributeValue(attributes, "InResponseTo");
      break;
    case "StatusCode":
      if (parsed.statusCode === null) {
        parsed.statusCode = attributeValue(attributes, "Value");
      }
      break;
    case "Conditions":
      parsed.notBefore = attributeValue(attributes, "NotBefore");
      parsed.notOnOrAfter = attributeValue(attributes, "NotOnOrAfter");
      break;
    case "Attribute":
      state.currentAttribute =
        attributeValue(attributes, "Name") ?? attributeValue(attributes, "FriendlyName");
      break;
    default:
      break;
  }
}

/**
 * `saml.rs::parse_response_xml` — decodes base64, inflates raw DEFLATE, and
 * scans the XML for the handful of fields the validator needs.
 *
 * Note the ordering contract this function relies on: by the time it runs, the
 * bytes have ALREADY been authenticated by the redirect-binding signature
 * (`flow.ts` verifies before it inflates, exactly as `sso.rs::handle_saml_acs`
 * did). It is still written defensively — the size caps and the strict XML
 * scanner apply regardless — because "the caller checks first" is precisely the
 * assumption that rots.
 */
async function parseResponseXml(samlResponseB64: string): Promise<ParsedResponse> {
  if (samlResponseB64.length > MAX_SAML_RESPONSE_B64_CHARS) {
    throw samlError(
      "saml_response_too_large",
      `encoded SAMLResponse exceeds ${MAX_SAML_RESPONSE_B64_CHARS} characters`,
    );
  }
  let compressed: Uint8Array;
  try {
    compressed = decodeBase64Strict(samlResponseB64);
  } catch (error) {
    const detail = error instanceof Base64Error ? error.message : String(error);
    throw samlError("saml_response_not_base64", `SAMLResponse is not valid base64: ${detail}`);
  }

  let xmlBytes: Uint8Array;
  try {
    xmlBytes = await inflateRawBounded(compressed);
  } catch (error) {
    inflateFailure(error);
  }

  const parsed: ParsedResponse = {
    statusCode: null,
    responseInResponseTo: null,
    issuer: null,
    notBefore: null,
    notOnOrAfter: null,
    audiences: [],
    nameId: null,
    attributes: new Map(),
  };
  const state = { currentAttribute: null as string | null };
  const stack: string[] = [];

  try {
    // `fatal: true` — a malformed UTF-8 sequence is a refusal, not a run of
    // U+FFFD that could make two readers disagree about a value.
    const xml = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(xmlBytes);
    scanXml(xml, (event) => {
      switch (event.kind) {
        case "start":
          captureElement(parsed, state, event.name, event.attributes);
          stack.push(event.name);
          break;
        case "empty":
          // Self-closing elements never emit a matching end, so they are not
          // pushed — same as the Rust port's `Event::Empty` arm.
          captureElement(parsed, state, event.name, event.attributes);
          break;
        case "end":
          if (event.name === "Attribute") state.currentAttribute = null;
          stack.pop();
          break;
        case "text": {
          const parent = stack[stack.length - 1];
          if (parent === "Issuer") {
            if (parsed.issuer === null) parsed.issuer = event.value;
          } else if (parent === "Audience") {
            parsed.audiences.push(event.value);
          } else if (parent === "NameID") {
            parsed.nameId = event.value;
          } else if (parent === "AttributeValue" && state.currentAttribute !== null) {
            const values = parsed.attributes.get(state.currentAttribute);
            if (values) values.push(event.value);
            else parsed.attributes.set(state.currentAttribute, [event.value]);
          }
          break;
        }
      }
    });
  } catch (error) {
    const detail =
      error instanceof XmlError || error instanceof Error ? error.message : String(error);
    throw samlError("malformed_saml_xml", `malformed SAML XML: ${detail}`);
  }

  return parsed;
}

/**
 * `str::to_ascii_lowercase` — ASCII-only, as in the Rust port.
 * `String.prototype.toLowerCase` is Unicode-aware and would fold characters
 * Rust leaves alone (Turkish `İ`, Kelvin sign `K`, …), so two identity
 * providers' users could collapse onto one account here but not there.
 */
function asciiLowercase(value: string): string {
  let out = "";
  for (const ch of value) {
    const code = ch.charCodeAt(0);
    out += code >= 0x41 && code <= 0x5a ? String.fromCharCode(code + 0x20) : ch;
  }
  return out;
}

/** `util.rs::is_valid_email` — the same deliberately-loose shape check. */
function isValidEmail(email: string): boolean {
  const at = email.indexOf("@");
  if (at < 0) return false;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  return (
    local.length > 0 && domain.includes(".") && !domain.startsWith(".") && !domain.endsWith(".")
  );
}

/**
 * `saml.rs::parse_and_validate_response` — validates a parsed response against
 * the expectations and extracts the caller identity.
 *
 * EVERY failure below is a hard rejection. There is no path that returns a
 * `ValidatedAssertion` built from unchecked input, and no "warn and continue".
 * The checks run in the Rust port's order, which matters for the error a
 * caller sees but not for safety — all of them must pass.
 */
export async function parseAndValidateResponse(
  samlResponseB64: string,
  expectations: AssertionExpectations,
): Promise<ValidatedAssertion> {
  const parsed = await parseResponseXml(samlResponseB64);

  if (parsed.statusCode !== STATUS_SUCCESS) {
    throw samlError(
      "status_not_success",
      `status is not Success (got ${rustDebug(parsed.statusCode)})`,
    );
  }
  const expectedInResponseTo = expectations.inResponseTo ?? null;
  if (expectedInResponseTo !== null && parsed.responseInResponseTo !== expectedInResponseTo) {
    throw samlError(
      "in_response_to_mismatch",
      "InResponseTo does not match the pending AuthnRequest",
    );
  }
  const expectedIssuer = expectations.idpEntityId ?? null;
  if (expectedIssuer !== null && parsed.issuer !== expectedIssuer) {
    throw samlError(
      "issuer_mismatch",
      "assertion Issuer does not match the configured IdP entity id",
    );
  }
  if (!parsed.audiences.includes(expectations.spEntityId)) {
    throw samlError("audience_mismatch", "assertion audience does not include this SP");
  }
  if (parsed.notBefore !== null) {
    const notBefore = parseSamlInstant(parsed.notBefore);
    if (expectations.nowUnix + expectations.clockSkewSecs < notBefore) {
      throw samlError("assertion_not_yet_valid", "assertion is not yet valid (NotBefore)");
    }
  }
  if (parsed.notOnOrAfter !== null) {
    const notOnOrAfter = parseSamlInstant(parsed.notOnOrAfter);
    if (expectations.nowUnix - expectations.clockSkewSecs >= notOnOrAfter) {
      throw samlError("assertion_expired", "assertion has expired (NotOnOrAfter)");
    }
  }

  const firstAttribute = (name: string | null | undefined): string | null => {
    if (!name) return null;
    return parsed.attributes.get(name)?.[0] ?? null;
  };

  // Email: prefer the configured attribute, then the common conventions, then
  // the Subject NameID (frequently the email itself). Fail closed if none is a
  // usable address.
  const emailCandidate =
    firstAttribute(expectations.emailAttribute) ??
    firstAttribute("email") ??
    firstAttribute("mail") ??
    firstAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress") ??
    parsed.nameId;
  const email = emailCandidate === null ? null : asciiLowercase(emailCandidate.trim());
  if (email === null || !isValidEmail(email)) {
    throw samlError("no_usable_email", "assertion did not include a usable email");
  }

  const displayName =
    firstAttribute(expectations.nameAttribute) ??
    firstAttribute("displayName") ??
    firstAttribute("name") ??
    email;

  const groupsAttribute = expectations.groupsAttribute ?? "groups";
  const groups = [...(parsed.attributes.get(groupsAttribute) ?? [])];

  return { email, displayName, groups };
}

export type { SamlError };
