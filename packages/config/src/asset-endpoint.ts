/**
 * Port of `ferrogate-config`'s `config/asset_endpoint.rs` (inventory §5.4,
 * "Asset endpoint") — the single source of truth for `asset_bucket.endpoint`
 * decomposition, shared by the load-time R2 guards and the runtime SigV4
 * signer (issue #485/#410/#573).
 */

/**
 * The DNS suffix every Cloudflare R2 S3-API host ends with (issue #410).
 * The per-account host is `<account_id>.r2.cloudflarestorage.com`; the
 * jurisdiction hosts insert a `.eu.` / `.fedramp.` label before it.
 */
export const R2_ENDPOINT_SUFFIX = "r2.cloudflarestorage.com";

/**
 * The region FerroGate requires for an R2 endpoint. R2 ignores geographic
 * regions; its canonical credential scope is `.../auto/s3/aws4_request`.
 * FerroGate pins the canonical `auto` rather than accepting the `us-east-1` /
 * blank aliases so the signed scope is unambiguous.
 */
export const R2_REGION = "auto";

/** The optional data-residency jurisdiction of an R2 endpoint. */
export type R2Jurisdiction = "eu" | "fedramp";

/**
 * A parsed Cloudflare R2 S3 endpoint (issue #410): the account id and the
 * optional data-residency jurisdiction.
 */
export interface R2Endpoint {
  accountId: string;
  /** `null` for the default global host; `"eu"` / `"fedramp"` for the jurisdiction hosts. */
  jurisdiction: R2Jurisdiction | null;
}

/**
 * `asset_bucket.endpoint` decomposed into the exact pieces the runtime SigV4
 * path uses (issue #485). Both the load-time guards and the runtime signer go
 * through {@link parseEndpoint} so they cannot disagree about what an endpoint
 * *means*.
 */
export class EndpointParts {
  /** `http` only for an explicit `http://` endpoint; `https` otherwise. */
  readonly scheme: "http" | "https";
  /** `[userinfo@]host[:port]`, ASCII-lowercased. Userinfo retained for validation. */
  readonly authority: string;
  /** Any path/query/fragment suffix (`/storage/v1/s3`) or `""`; trailing `/` trimmed. */
  readonly pathPrefix: string;

  constructor(scheme: "http" | "https", authority: string, pathPrefix: string) {
    this.scheme = scheme;
    this.authority = authority;
    this.pathPrefix = pathPrefix;
  }

  /**
   * The literal `host[:port]` the runtime puts in the signed `host` header,
   * with endpoint userinfo and any base-path prefix excluded.
   */
  signingHost(): string {
    const at = this.authority.lastIndexOf("@");
    return at === -1 ? this.authority : this.authority.slice(at + 1);
  }

  /** The bare DNS host: {@link authority} with any `:port` removed. */
  hostName(): string {
    const at = this.authority.lastIndexOf("@");
    const authority = at === -1 ? this.authority : this.authority.slice(at + 1);
    if (authority.startsWith("[")) {
      // IPv6 literal: `[::1]:8080` -> `[::1]`.
      const end = authority.indexOf("]");
      return end === -1 ? authority : authority.slice(0, end + 1);
    }
    const colon = authority.indexOf(":");
    return colon === -1 ? authority : authority.slice(0, colon);
  }
}

/**
 * Decomposes `asset_bucket.endpoint` the way the runtime signer does. THE
 * single source of truth for "what host and base path will we sign?".
 * Throws on an endpoint with no host (mirrors Rust `anyhow::bail!`).
 */
export function parseEndpoint(endpoint: string): EndpointParts {
  const raw = endpoint.trim();
  let scheme: "http" | "https";
  let rest: string;
  if (raw.slice(0, "http://".length).toLowerCase() === "http://") {
    scheme = "http";
    rest = raw.slice("http://".length);
  } else if (raw.slice(0, "https://".length).toLowerCase() === "https://") {
    scheme = "https";
    rest = raw.slice("https://".length);
  } else {
    scheme = "https";
    rest = raw;
  }
  rest = rest.replace(/\/+$/, "");
  // `?` and `#` terminate the authority just as `/` does.
  const index = firstIndexOfAny(rest, ["/", "?", "#"]);
  const authority = index === -1 ? rest : rest.slice(0, index);
  const pathPrefix = index === -1 ? "" : rest.slice(index);
  if (authority.length === 0) {
    throw new Error(`asset_bucket.endpoint ${endpoint} has no host`);
  }
  return new EndpointParts(scheme, authority.toLowerCase(), pathPrefix);
}

function firstIndexOfAny(haystack: string, needles: string[]): number {
  let best = -1;
  for (const needle of needles) {
    const i = haystack.indexOf(needle);
    if (i !== -1 && (best === -1 || i < best)) best = i;
  }
  return best;
}

/**
 * True when `endpoint`'s host is under the R2 S3 domain (any account /
 * jurisdiction). Permissive on purpose so {@link parseR2Endpoint}'s callers can
 * reject malformed R2-shaped endpoints with a clear error.
 */
export function endpointTargetsR2(endpoint: string): boolean {
  let host: string;
  try {
    host = parseEndpoint(endpoint).hostName();
  } catch {
    return false;
  }
  return host === R2_ENDPOINT_SUFFIX || host.endsWith(`.${R2_ENDPOINT_SUFFIX}`);
}

/**
 * Strictly parses an R2 S3 endpoint of the form
 * `https://<account_id>.r2.cloudflarestorage.com` (optionally with an
 * `.eu.` / `.fedramp.` jurisdiction label). Returns `null` when the host is
 * not R2 *or* when the signer would not sign a bare R2 host for it (plaintext
 * scheme, malformed account id, userinfo, `:port`, or a URL suffix).
 */
export function parseR2Endpoint(endpoint: string): R2Endpoint | null {
  let parts: EndpointParts;
  try {
    parts = parseEndpoint(endpoint);
  } catch {
    return null;
  }
  if (parts.scheme !== "https") return null;
  if (parts.pathPrefix.length !== 0) return null;
  const host = parts.hostName();
  if (host.length !== parts.authority.length) return null; // userinfo or explicit :port
  if (!host.endsWith(R2_ENDPOINT_SUFFIX)) return null;
  let prefix = host.slice(0, host.length - R2_ENDPOINT_SUFFIX.length);
  if (!prefix.endsWith(".")) return null; // reject the bare suffix domain (empty account)
  prefix = prefix.slice(0, -1);

  let accountId: string;
  let jurisdiction: R2Jurisdiction | null;
  if (prefix.endsWith(".eu")) {
    accountId = prefix.slice(0, -".eu".length);
    jurisdiction = "eu";
  } else if (prefix.endsWith(".fedramp")) {
    accountId = prefix.slice(0, -".fedramp".length);
    jurisdiction = "fedramp";
  } else {
    accountId = prefix;
    jurisdiction = null;
  }
  // A valid account id is a single, non-empty DNS label.
  if (accountId.length === 0 || accountId.includes(".")) return null;
  return { accountId, jurisdiction };
}
