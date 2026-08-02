/**
 * Test-only helpers that stand in for the IdP.
 *
 * Everything here is written INDEPENDENTLY of `src/` on purpose. In
 * particular the percent-encoder below is a second implementation, not an
 * import of `src/urlcodec.ts`: if the test built the signed octet string with
 * the same encoder the verifier uses, then an encoder bug would cancel itself
 * out and the "signature is over the RAW query octets" claim would be proven
 * only against itself.
 */

/** A one-chunk source stream; see the note in `src/deflate.ts` on why it is Blob-backed. */
export function singleChunkStream(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new Blob([bytes]).stream() as ReadableStream<Uint8Array>;
}

/** Strict RFC 3986 unreserved-set percent-encoder — the IdP's encoder. */
export function idpPercentEncode(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let out = "";
  for (const byte of bytes) {
    const ch = String.fromCharCode(byte);
    if (/[A-Za-z0-9\-_.~]/.test(ch)) {
      out += ch;
    } else {
      out += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    }
  }
  return out;
}

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) out[index] = binary.charCodeAt(index);
  return out;
}

export function pemToDer(pem: string): Uint8Array {
  const body = pem
    .split("\n")
    .filter((line) => !line.startsWith("-----"))
    .join("");
  return fromBase64(body);
}

export async function deflateRaw(input: string | Uint8Array): Promise<Uint8Array> {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const stream = singleChunkStream(bytes).pipeThrough(new CompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Imports a PKCS#8 PEM private key for RSASSA-PKCS1-v1_5 signing. */
export async function importSigningKey(
  pkcs8Pem: string,
  hash: "SHA-256" | "SHA-1",
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "pkcs8",
    pemToDer(pkcs8Pem) as unknown as ArrayBuffer,
    { name: "RSASSA-PKCS1-v1_5", hash },
    false,
    ["sign"],
  );
}

/** Produces a REAL detached RSA signature over the exact bytes given. */
export async function signOctets(
  pkcs8Pem: string,
  octets: string,
  hash: "SHA-256" | "SHA-1" = "SHA-256",
): Promise<string> {
  const key = await importSigningKey(pkcs8Pem, hash);
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(octets) as unknown as ArrayBuffer,
  );
  return toBase64(new Uint8Array(signature));
}

export const SIG_ALG_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
export const SIG_ALG_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
export const STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

export interface SampleResponseOptions {
  notBefore?: string;
  notOnOrAfter?: string;
  inResponseTo?: string;
  issuer?: string;
  audience?: string;
  status?: string;
  email?: string | null;
  nameId?: string | null;
}

/** The sample `samlp:Response`, mirroring the Rust suite's fixture. */
export function sampleResponseXml(options: SampleResponseOptions = {}): string {
  const {
    notBefore = "2020-01-01T00:00:00Z",
    notOnOrAfter = "2999-01-01T00:00:00Z",
    inResponseTo = "_req-123",
    issuer = "https://idp.example/entity",
    audience = "sp-entity-id",
    status = STATUS_SUCCESS,
    email = "User@Example.com",
    nameId = "subject@example.com",
  } = options;
  const emailAttribute =
    email === null
      ? ""
      : `<saml:Attribute Name="email"><saml:AttributeValue>${email}</saml:AttributeValue></saml:Attribute>`;
  const subject =
    nameId === null ? "" : `<saml:Subject><saml:NameID>${nameId}</saml:NameID></saml:Subject>`;
  return [
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" `,
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" InResponseTo="${inResponseTo}">`,
    `<saml:Issuer>${issuer}</saml:Issuer>`,
    `<samlp:Status><samlp:StatusCode Value="${status}"/></samlp:Status>`,
    `<saml:Assertion><saml:Issuer>${issuer}</saml:Issuer>`,
    subject,
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">`,
    `<saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience>`,
    "</saml:AudienceRestriction></saml:Conditions>",
    "<saml:AttributeStatement>",
    emailAttribute,
    '<saml:Attribute Name="displayName"><saml:AttributeValue>Ada Lovelace</saml:AttributeValue></saml:Attribute>',
    '<saml:Attribute Name="groups">',
    "<saml:AttributeValue>Engineering</saml:AttributeValue>",
    "<saml:AttributeValue>Admins</saml:AttributeValue></saml:Attribute>",
    "</saml:AttributeStatement></saml:Assertion></samlp:Response>",
  ].join("");
}

export async function encodedResponse(options: SampleResponseOptions = {}): Promise<string> {
  return toBase64(await deflateRaw(sampleResponseXml(options)));
}

/**
 * Builds the query string an IdP would actually redirect the browser to: each
 * value percent-encoded, and the signature computed over the binding's fixed
 * `SAMLResponse=..&RelayState=..&SigAlg=..` octet string built from those
 * ENCODED values (SAML 2.0 Bindings §3.4.4.1).
 */
export async function signedQuery(
  pkcs8Pem: string,
  samlResponseB64: string,
  relayState: string,
  options: { sigAlg?: string; hash?: "SHA-256" | "SHA-1" } = {},
): Promise<string> {
  const { sigAlg = SIG_ALG_SHA256, hash = "SHA-256" } = options;
  const responseEnc = idpPercentEncode(samlResponseB64);
  const relayEnc = idpPercentEncode(relayState);
  const sigAlgEnc = idpPercentEncode(sigAlg);
  const octets = `SAMLResponse=${responseEnc}&RelayState=${relayEnc}&SigAlg=${sigAlgEnc}`;
  const signature = await signOctets(pkcs8Pem, octets, hash);
  return `${octets}&Signature=${idpPercentEncode(signature)}`;
}
