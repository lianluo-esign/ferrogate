/**
 * AWS SigV4 **query-string** presigning against R2's S3-compatible endpoint.
 *
 * Clean-room port of `crates/ferrogate-providers/src/sigv4.rs`
 * (`presign_query`, `presign_query_bound`) and its two call sites in
 * `crates/ferrogate-gateway/src/server/asset_bucket.rs`
 * (`presign_put` / `presign_get`).
 *
 * Why this exists at all: the Workers `R2Bucket` binding has **no presign
 * method** — R2 presigned URLs are an S3-API feature over
 * `https://<account>.r2.cloudflarestorage.com`. Presigning is the whole point
 * of the endpoint family (the client's bytes must travel directly between the
 * client and the bucket and never traverse the gateway), so it is signed here
 * with WebCrypto rather than dropped.
 *
 * The upload signature is **bound** (Rust issue #368): `content-length` and
 * `x-amz-content-sha256` are signed headers, so a PUT that changes either — or
 * uploads bytes whose size/checksum differ from the declared intent — is
 * rejected at the bucket boundary, not merely at the gateway's commit check.
 */
import { hmacSha256, sha256Hex, toHex } from "./hash.js";
import type { AssetPresigner, PresignedUpload } from "./ports.js";

/** S3-endpoint coordinates for the R2 bucket holding asset objects. */
export interface R2S3Endpoint {
  /** e.g. `https://<account_id>.r2.cloudflarestorage.com` */
  readonly endpoint: string;
  readonly bucket: string;
  /** R2 is always `auto`; kept configurable for S3-compatible deployments. */
  readonly region: string;
  readonly accessKeyId: string;
  readonly secretAccessKey: string;
  readonly sessionToken?: string | undefined;
}

const ALGORITHM = "AWS4-HMAC-SHA256";
const SERVICE = "s3";

/** RFC-3986 encoding for a canonical query key/value: `/` becomes `%2F`. */
function percentEncodeQuery(value: string): string {
  let out = "";
  for (const byte of new TextEncoder().encode(value)) {
    const ch = String.fromCharCode(byte);
    if (/[A-Za-z0-9\-_.~]/.test(ch)) {
      out += ch;
    } else {
      out += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    }
  }
  return out;
}

/**
 * Encode one path segment, passing an already-well-formed `%XY` escape through
 * verbatim rather than re-encoding its `%` — Rust `percent_encode_segment`.
 * Double-encoding here would produce a signature no S3-compatible server can
 * independently re-derive from the (singly-encoded) wire request.
 */
function percentEncodeSegment(segment: string): string {
  const bytes = new TextEncoder().encode(segment);
  let out = "";
  let index = 0;
  const isHex = (byte: number | undefined): boolean =>
    byte !== undefined && /[0-9A-Fa-f]/.test(String.fromCharCode(byte));
  while (index < bytes.length) {
    const byte = bytes[index];
    if (byte === undefined) break;
    if (byte === 0x25 && isHex(bytes[index + 1]) && isHex(bytes[index + 2])) {
      out += `%${String.fromCharCode(bytes[index + 1] as number)}${String.fromCharCode(bytes[index + 2] as number)}`;
      index += 3;
      continue;
    }
    const ch = String.fromCharCode(byte);
    if (/[A-Za-z0-9\-_.~]/.test(ch)) {
      out += ch;
    } else {
      out += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    }
    index += 1;
  }
  return out;
}

/** Per-segment canonicalization that preserves `/` — Rust `canonical_uri`. */
function canonicalUri(path: string): string {
  if (path === "") return "/";
  return path.split("/").map(percentEncodeSegment).join("/");
}

/** `(amzDate, dateStamp)` — Rust `format_timestamps`. */
export function formatTimestamps(unixSeconds: number): [string, string] {
  const date = new Date(unixSeconds * 1000);
  const pad = (value: number, width = 2): string => String(value).padStart(width, "0");
  const dateStamp = `${pad(date.getUTCFullYear(), 4)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}`;
  const amzDate = `${dateStamp}T${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  return [amzDate, dateStamp];
}

async function deriveSigningKey(
  secretAccessKey: string,
  dateStamp: string,
  region: string,
  service: string,
): Promise<Uint8Array> {
  const kDate = await hmacSha256(new TextEncoder().encode(`AWS4${secretAccessKey}`), dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);
  return hmacSha256(kService, "aws4_request");
}

interface PresignInput {
  readonly method: "GET" | "PUT";
  /** Absolute request path, e.g. `/bucket/key`. */
  readonly path: string;
  readonly host: string;
  readonly region: string;
  readonly expiresSeconds: number;
  readonly timestampUnix: number;
}

/**
 * The shared presign core — Rust `presign_query_internal`. `signedHeaders` must
 * be lowercase, sorted by name, and include `host`.
 */
async function presignQuery(
  request: PresignInput,
  credentials: Pick<R2S3Endpoint, "accessKeyId" | "secretAccessKey" | "sessionToken">,
  signedHeaders: readonly (readonly [string, string])[],
  payloadHash: string,
): Promise<string> {
  const [amzDate, dateStamp] = formatTimestamps(request.timestampUnix);
  const credentialScope = `${dateStamp}/${request.region}/${SERVICE}/aws4_request`;
  const credential = `${credentials.accessKeyId}/${credentialScope}`;
  const signedHeaderNames = signedHeaders.map(([name]) => name).join(";");
  const canonicalHeaders = signedHeaders.map(([name, value]) => `${name}:${value}\n`).join("");

  // Canonical query params are sorted by encoded key; the `X-Amz-*` names below
  // are already alphabetical, and the optional security token slots between
  // `X-Amz-Expires` and `X-Amz-SignedHeaders`, which keeps them so.
  const params: [string, string][] = [
    ["X-Amz-Algorithm", ALGORITHM],
    ["X-Amz-Credential", credential],
    ["X-Amz-Date", amzDate],
    ["X-Amz-Expires", String(request.expiresSeconds)],
  ];
  if (credentials.sessionToken) {
    params.push(["X-Amz-Security-Token", credentials.sessionToken]);
  }
  params.push(["X-Amz-SignedHeaders", signedHeaderNames]);
  const canonicalQuery = params
    .map(([name, value]) => `${percentEncodeQuery(name)}=${percentEncodeQuery(value)}`)
    .join("&");

  const canonicalRequest = `${request.method}\n${canonicalUri(request.path)}\n${canonicalQuery}\n${canonicalHeaders}\n${signedHeaderNames}\n${payloadHash}`;
  const stringToSign = `${ALGORITHM}\n${amzDate}\n${credentialScope}\n${await sha256Hex(canonicalRequest)}`;
  const signingKey = await deriveSigningKey(
    credentials.secretAccessKey,
    dateStamp,
    request.region,
    SERVICE,
  );
  const signature = toHex(await hmacSha256(signingKey, stringToSign));
  return `${canonicalQuery}&X-Amz-Signature=${signature}`;
}

/**
 * SigV4 presigner over R2's S3 API — the production {@link AssetPresigner}.
 *
 * WIRED. `sigV4PresignerFromEnv` (`./handlers.ts`) builds this from the five
 * `ASSET_S3_*` bindings and `src/index.ts` passes it through
 * `assetDepsFromEnv`; with a partial credential set no presigner is built at
 * all and the presign family keeps answering `503 asset_bucket_unavailable`.
 *
 * PORT-TODO(P: inventory-request-path.md §1.6 "Object storage"): the two secret
 * halves (`ASSET_S3_ACCESS_KEY_ID` / `ASSET_S3_SECRET_ACCESS_KEY`) are Worker
 * SECRETS today (`wrangler secret put`) and belong in **Cloudflare Secrets
 * Store** once `@ferrogate/secrets` lands. Same platform constraint as the
 * worker transport secret in `src/adapters.ts`: a Secrets Store binding is
 * materialized at DEPLOY time against a store that must already exist in the
 * account, so it cannot be exercised under `wrangler dev --local` or
 * `vitest-pool-workers` the way D1/R2/Queues can. The difference is rotation
 * and blast radius, not the signing — this class takes the credentials as DATA
 * precisely so the swap touches no call site and no signature changes.
 */
export class SigV4Presigner implements AssetPresigner {
  private readonly config: R2S3Endpoint;

  constructor(config: R2S3Endpoint) {
    this.config = config;
  }

  private parts(key: string): { host: string; path: string; origin: string } {
    const url = new URL(this.config.endpoint);
    const basePath = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");
    return {
      host: url.host,
      path: `${basePath}/${this.config.bucket}/${key}`,
      origin: `${url.protocol}//${url.host}`,
    };
  }

  async presignPut(
    key: string,
    expiresSeconds: number,
    nowUnix: number,
    sizeBytes: number,
    contentSha256Hex: string,
  ): Promise<PresignedUpload> {
    const { host, path, origin } = this.parts(key);
    const contentLength = String(sizeBytes);
    const contentSha256 = contentSha256Hex.toLowerCase();
    // Lowercase, alphabetically sorted, `host` included — the bucket recomputes
    // the signature over exactly these, so changing any of them invalidates the
    // upload at the bucket boundary.
    const signedHeaders: readonly (readonly [string, string])[] = [
      ["content-length", contentLength],
      ["host", host],
      ["x-amz-content-sha256", contentSha256],
    ];
    const query = await presignQuery(
      {
        method: "PUT",
        path,
        host,
        region: this.config.region,
        expiresSeconds,
        timestampUnix: nowUnix,
      },
      this.config,
      signedHeaders,
      "UNSIGNED-PAYLOAD",
    );
    return {
      url: `${origin}${path}?${query}`,
      requiredHeaders: {
        "content-length": contentLength,
        "x-amz-content-sha256": contentSha256,
      },
    };
  }

  async presignGet(key: string, expiresSeconds: number, nowUnix: number): Promise<string> {
    const { host, path, origin } = this.parts(key);
    const query = await presignQuery(
      {
        method: "GET",
        path,
        host,
        region: this.config.region,
        expiresSeconds,
        timestampUnix: nowUnix,
      },
      this.config,
      [["host", host]],
      "UNSIGNED-PAYLOAD",
    );
    return `${origin}${path}?${query}`;
  }
}
