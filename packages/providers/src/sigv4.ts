/**
 * AWS Signature Version 4 request signing — port of `sigv4.rs` (issue #172).
 *
 * Byte-exact reimplementation of AWS's published SigV4 algorithm using the
 * synchronous {@link ./crypto} SHA-256 / HMAC-SHA256 primitives.
 *
 * MECHANISM NOTE (inventory §3.8) — the port is COMPLETE; only the primitive
 * differs, and the difference is PROVEN to be invisible.
 *
 * The inventory suggests `crypto.subtle` HMAC-SHA256. `crypto.subtle` is ASYNC,
 * and the Rust `sign` is synchronous — it is called inline from
 * `BedrockAdapter.prepareChatCompletions`, so adopting it would force the whole
 * `ProviderAdapter` surface to become `async`: a behavioral divergence from the
 * crate, in a request path where an extra microtask boundary changes ordering.
 * So signing uses a synchronous in-package SHA-256/HMAC-SHA256 (`./crypto.ts`).
 *
 * This is NOT a deferral, so it is not a PORT-TODO. `test/crypto-sigv4.test.ts`
 * asserts the sync primitives agree with `crypto.subtle` BYTE FOR BYTE across
 * block boundaries, over-long keys and multi-byte input, in addition to the
 * NIST/RFC 4231 vectors — so a drift fails the suite rather than producing a
 * silently-invalid Authorization header.
 */
import { hexHmac, hexSha256, hmacSha256, utf8 } from "./crypto.js";

/** AWS credentials for SigV4 signing. */
export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

/** Everything needed to sign one request (deterministic in `timestampUnix`). */
export interface SigningRequest {
  method: string;
  /** Absolute path only (no scheme/host/query), e.g. `/model/foo/converse`. */
  path: string;
  host: string;
  region: string;
  service: string;
  body: Uint8Array;
  /** Unix seconds. */
  timestampUnix: number;
}

/** The header values a signed request must send verbatim. */
export interface SignedHeaders {
  xAmzDate: string;
  authorization: string;
  /** Present only for temporary credentials. */
  xAmzSecurityToken?: string;
  /** Present only when signed via {@link signWithContentHashHeader}. */
  xAmzContentSha256?: string;
}

/** A request whose body is streamed; the payload is named by its hex SHA-256. */
export interface StreamedSigningRequest {
  method: string;
  path: string;
  host: string;
  region: string;
  service: string;
  /** Lowercase hex SHA-256 of the payload the caller will stream. */
  payloadSha256Hex: string;
  timestampUnix: number;
}

/** Inputs for a SigV4 query-string presigned URL (body is `UNSIGNED-PAYLOAD`). */
export interface PresignRequest {
  method: string;
  path: string;
  host: string;
  region: string;
  service: string;
  /** URL validity window (seconds); caller clamps to the S3 max of 604800. */
  expiresSecs: number;
  timestampUnix: number;
}

/** The payload constraints a bound presigned upload commits to (issue #368). */
export interface PresignBoundPayload {
  contentLength: number;
  /** Lowercase 64-char hex SHA-256 of the exact payload bytes. */
  contentSha256Hex: string;
}

/** A bound presigned upload: signed query string + verbatim required headers. */
export interface BoundPresignedUpload {
  query: string;
  requiredHeaders: [string, string][];
}

// ---------------------------------------------------------------------------
// Header-auth signing
// ---------------------------------------------------------------------------

/** Sign `request`, returning the minimal signed-header set (`host;x-amz-date`). */
export function sign(request: SigningRequest, credentials: AwsCredentials): SignedHeaders {
  return signInternal(request, credentials, false, "");
}

/** Like {@link sign}, but also signs+returns a literal `x-amz-content-sha256`. */
export function signWithContentHashHeader(
  request: SigningRequest,
  credentials: AwsCredentials,
): SignedHeaders {
  return signInternal(request, credentials, true, "");
}

/** Like {@link signWithContentHashHeader}, taking the payload hash directly. */
export function signStreamedWithContentHashHeader(
  request: StreamedSigningRequest,
  credentials: AwsCredentials,
): SignedHeaders {
  return signCanonical(
    request.method,
    request.path,
    request.host,
    request.region,
    request.service,
    request.timestampUnix,
    credentials,
    true,
    "",
    request.payloadSha256Hex,
  );
}

/** Like {@link signWithContentHashHeader}, folding a canonical query string in. */
export function signWithContentHashHeaderAndQuery(
  request: SigningRequest,
  credentials: AwsCredentials,
  canonicalQuery: string,
): SignedHeaders {
  return signInternal(request, credentials, true, canonicalQuery);
}

/** Build an S3 SigV4 canonical query string from raw `(key, value)` pairs. */
export function canonicalQueryString(params: readonly [string, string][]): string {
  const encoded = params.map(
    ([name, value]) => [percentEncodeQuery(name), percentEncodeQuery(value)] as const,
  );
  encoded.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  return encoded.map(([name, value]) => `${name}=${value}`).join("&");
}

function signInternal(
  request: SigningRequest,
  credentials: AwsCredentials,
  includeContentHashHeader: boolean,
  canonicalQuery: string,
): SignedHeaders {
  return signCanonical(
    request.method,
    request.path,
    request.host,
    request.region,
    request.service,
    request.timestampUnix,
    credentials,
    includeContentHashHeader,
    canonicalQuery,
    hexSha256(request.body),
  );
}

function signCanonical(
  method: string,
  path: string,
  host: string,
  region: string,
  service: string,
  timestampUnix: number,
  credentials: AwsCredentials,
  includeContentHashHeader: boolean,
  canonicalQuery: string,
  hashedPayload: string,
): SignedHeaders {
  const [amzDate, dateStamp] = formatTimestamps(timestampUnix);
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;

  const [signedHeaderNames, canonicalHeaders] = includeContentHashHeader
    ? [
        "host;x-amz-content-sha256;x-amz-date",
        `host:${host}\nx-amz-content-sha256:${hashedPayload}\nx-amz-date:${amzDate}\n`,
      ]
    : ["host;x-amz-date", `host:${host}\nx-amz-date:${amzDate}\n`];

  const canonicalRequest = `${method}\n${canonicalUri(path)}\n${canonicalQuery}\n${canonicalHeaders}\n${signedHeaderNames}\n${hashedPayload}`;

  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${hexSha256(utf8(canonicalRequest))}`;

  const signingKey = deriveSigningKey(credentials.secretAccessKey, dateStamp, region, service);
  const signature = hexHmac(signingKey, utf8(stringToSign));

  const authorization = `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaderNames}, Signature=${signature}`;

  return {
    xAmzDate: amzDate,
    authorization,
    xAmzSecurityToken: credentials.sessionToken,
    xAmzContentSha256: includeContentHashHeader ? hashedPayload : undefined,
  };
}

// ---------------------------------------------------------------------------
// Query-string presigning
// ---------------------------------------------------------------------------

/** Signed query string (no leading `?`) for a SigV4 query-string presigned URL. */
export function presignQuery(request: PresignRequest, credentials: AwsCredentials): string {
  return presignQueryInternal(request, credentials, [["host", request.host]], "UNSIGNED-PAYLOAD");
}

/** {@link presignQuery} bound to a declared size + checksum (issue #368). */
export function presignQueryBound(
  request: PresignRequest,
  credentials: AwsCredentials,
  payload: PresignBoundPayload,
): BoundPresignedUpload {
  const contentLength = String(payload.contentLength);
  const contentSha256 = payload.contentSha256Hex.toLowerCase();
  const signedHeaders: [string, string][] = [
    ["content-length", contentLength],
    ["host", request.host],
    ["x-amz-content-sha256", contentSha256],
  ];
  const query = presignQueryInternal(request, credentials, signedHeaders, "UNSIGNED-PAYLOAD");
  return {
    query,
    requiredHeaders: [
      ["content-length", contentLength],
      ["x-amz-content-sha256", contentSha256],
    ],
  };
}

function presignQueryInternal(
  request: PresignRequest,
  credentials: AwsCredentials,
  signedHeaders: readonly [string, string][],
  payloadHash: string,
): string {
  const [amzDate, dateStamp] = formatTimestamps(request.timestampUnix);
  const credentialScope = `${dateStamp}/${request.region}/${request.service}/aws4_request`;
  const credential = `${credentials.accessKeyId}/${credentialScope}`;
  const signedHeaderNames = signedHeaders.map(([name]) => name).join(";");
  const canonicalHeaders = signedHeaders.map(([name, value]) => `${name}:${value}\n`).join("");

  const params: [string, string][] = [
    ["X-Amz-Algorithm", "AWS4-HMAC-SHA256"],
    ["X-Amz-Credential", credential],
    ["X-Amz-Date", amzDate],
    ["X-Amz-Expires", String(request.expiresSecs)],
  ];
  if (credentials.sessionToken !== undefined) {
    params.push(["X-Amz-Security-Token", credentials.sessionToken]);
  }
  params.push(["X-Amz-SignedHeaders", signedHeaderNames]);

  const canonicalQuery = params
    .map(([name, value]) => `${percentEncodeQuery(name)}=${percentEncodeQuery(value)}`)
    .join("&");

  const canonicalRequest = `${request.method}\n${canonicalUri(request.path)}\n${canonicalQuery}\n${canonicalHeaders}\n${signedHeaderNames}\n${payloadHash}`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${hexSha256(utf8(canonicalRequest))}`;
  const signingKey = deriveSigningKey(
    credentials.secretAccessKey,
    dateStamp,
    request.region,
    request.service,
  );
  const signature = hexHmac(signingKey, utf8(stringToSign));

  return `${canonicalQuery}&X-Amz-Signature=${signature}`;
}

// ---------------------------------------------------------------------------
// Encoding + key derivation helpers
// ---------------------------------------------------------------------------

const isUnreserved = (byte: number): boolean =>
  (byte >= 0x41 && byte <= 0x5a) || // A-Z
  (byte >= 0x61 && byte <= 0x7a) || // a-z
  (byte >= 0x30 && byte <= 0x39) || // 0-9
  byte === 0x2d || // -
  byte === 0x5f || // _
  byte === 0x2e || // .
  byte === 0x7e; // ~

const hexByte = (byte: number): string => `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;

/** RFC 3986 encoding for a canonical query-string key or value (encodes `/`). */
function percentEncodeQuery(value: string): string {
  let out = "";
  for (const byte of utf8(value)) out += isUnreserved(byte) ? String.fromCharCode(byte) : hexByte(byte);
  return out;
}

function deriveSigningKey(
  secretAccessKey: string,
  dateStamp: string,
  region: string,
  service: string,
): Uint8Array {
  const kDate = hmacSha256(utf8(`AWS4${secretAccessKey}`), utf8(dateStamp));
  const kRegion = hmacSha256(kDate, utf8(region));
  const kService = hmacSha256(kRegion, utf8(service));
  return hmacSha256(kService, utf8("aws4_request"));
}

/** `YYYYMMDDTHHMMSSZ` and `YYYYMMDD` from a Unix timestamp (dependency-free). */
export function formatTimestamps(unixSeconds: number): [string, string] {
  const days = Math.floor(unixSeconds / 86_400);
  const secondsOfDay = unixSeconds % 86_400;
  const [year, month, day] = civilFromDays(days);
  const hour = Math.floor(secondsOfDay / 3600);
  const minute = Math.floor((secondsOfDay % 3600) / 60);
  const second = secondsOfDay % 60;
  const p = (value: number, width: number): string => String(value).padStart(width, "0");
  const amzDate = `${p(year, 4)}${p(month, 2)}${p(day, 2)}T${p(hour, 2)}${p(minute, 2)}${p(second, 2)}Z`;
  const dateStamp = `${p(year, 4)}${p(month, 2)}${p(day, 2)}`;
  return [amzDate, dateStamp];
}

/** Howard Hinnant's `civil_from_days`: days-since-epoch → (year, month, day). */
function civilFromDays(zInput: number): [number, number, number] {
  const z = zInput + 719_468;
  const era = Math.floor((z >= 0 ? z : z - 146_096) / 146_097);
  const doe = z - era * 146_097;
  const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146_096)) / 365);
  const y = yoe + era * 400;
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const m = mp < 10 ? mp + 3 : mp - 9;
  return [m <= 2 ? y + 1 : y, m, d];
}

/** AWS path canonicalization: per-segment encoding, preserving `/`. */
export function canonicalUri(path: string): string {
  if (path.length === 0) return "/";
  return path.split("/").map(percentEncodeSegment).join("/");
}

/** Encode one path segment, passing an already-well-formed `%XY` escape through. */
function percentEncodeSegment(segment: string): string {
  const bytes = utf8(segment);
  let out = "";
  let index = 0;
  while (index < bytes.length) {
    const byte = bytes[index]!;
    if (
      byte === 0x25 && // '%'
      index + 2 < bytes.length &&
      isHexDigit(bytes[index + 1]!) &&
      isHexDigit(bytes[index + 2]!)
    ) {
      out += "%" + String.fromCharCode(bytes[index + 1]!) + String.fromCharCode(bytes[index + 2]!);
      index += 3;
      continue;
    }
    out += isUnreserved(byte) ? String.fromCharCode(byte) : hexByte(byte);
    index += 1;
  }
  return out;
}

const isHexDigit = (byte: number): boolean =>
  (byte >= 0x30 && byte <= 0x39) ||
  (byte >= 0x41 && byte <= 0x46) ||
  (byte >= 0x61 && byte <= 0x66);
