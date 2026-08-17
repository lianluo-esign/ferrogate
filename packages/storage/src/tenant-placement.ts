/**
 * The immutable address parts of a tenant Durable Object.
 *
 * `locationHint` is a best-effort placement preference. `jurisdiction` is a
 * hard namespace boundary: selecting it changes the Durable Object id for the
 * same tenant name and therefore cannot be changed after creation without a
 * data migration.
 */

export const TENANT_LOCATION_HINTS = [
  "wnam",
  "enam",
  "sam",
  "weur",
  "eeur",
  "apac",
  "apac-ne",
  "apac-se",
  "oc",
  "afr",
  "me",
] as const;

export type TenantLocationHint = (typeof TENANT_LOCATION_HINTS)[number];

export const TENANT_JURISDICTIONS = ["eu", "us", "fedramp"] as const;

export type TenantJurisdiction = (typeof TENANT_JURISDICTIONS)[number];

export interface TenantObjectAddress {
  readonly locationHint?: TenantLocationHint;
  readonly jurisdiction?: TenantJurisdiction;
}

export interface TenantPlacementSignal {
  readonly continent?: unknown;
  readonly colo?: unknown;
}

/**
 * Headers a trusted edge (a BFF at its own ingress) forwards so the control plane can recover the
 * end user's placement signal. A Worker→Worker service-binding hop does NOT carry the caller's
 * `request.cf`, so a BFF that relays registration reads `cf.continent`/`cf.colo` at its own ingress
 * and re-emits them here; the control plane reads them as a fallback when `request.cf` is absent.
 */
export const CF_CONTINENT_HEADER = "x-ferrogate-cf-continent";
export const CF_COLO_HEADER = "x-ferrogate-cf-colo";

export type TenantPlacementSignalOrigin = "cf" | "edge-header" | "none";

/**
 * Minimal request shape needed to derive a placement signal (native `cf` or forwarded headers).
 * `cf` is `unknown` so any runtime `Request` structurally matches regardless of how its `cf`
 * generic is parameterised (the Workers `Request<…, CfProperties>` init shape omits continent/colo);
 * the continent/colo are narrowed at read time.
 */
export interface PlacementRequestLike {
  readonly cf?: unknown;
  readonly headers?: { get(name: string): string | null };
}

function nonEmptySignalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

/**
 * Resolve the placement signal for a request, preferring the native Cloudflare `cf` object and
 * falling back to the forwarded `x-ferrogate-cf-*` headers (see {@link CF_CONTINENT_HEADER}). The
 * returned `origin` records provenance so callers can distinguish an edge-header placement from a
 * native `cf` one; `none` means neither was present (caller falls back to the placement default).
 */
export function placementSignalFromRequest(request?: PlacementRequestLike): {
  readonly signal: TenantPlacementSignal;
  readonly origin: TenantPlacementSignalOrigin;
} {
  const cf = request?.cf as { continent?: unknown; colo?: unknown } | undefined;
  const cfContinent = nonEmptySignalString(cf?.continent);
  const cfColo = nonEmptySignalString(cf?.colo);
  if (cfContinent !== undefined || cfColo !== undefined) {
    return { signal: { continent: cfContinent, colo: cfColo }, origin: "cf" };
  }
  const headers = request?.headers;
  if (headers) {
    const headerContinent = nonEmptySignalString(headers.get(CF_CONTINENT_HEADER));
    const headerColo = nonEmptySignalString(headers.get(CF_COLO_HEADER));
    if (headerContinent !== undefined || headerColo !== undefined) {
      return {
        signal: { continent: headerContinent, colo: headerColo },
        origin: "edge-header",
      };
    }
  }
  return { signal: {}, origin: "none" };
}

export interface TenantPlacementDecision {
  readonly locationHint: TenantLocationHint;
  readonly source: string;
}

/** The options accepted by a Durable Object namespace's first `get()`. */
export interface TenantObjectGetOptions {
  readonly locationHint?: TenantLocationHint;
}

/**
 * Narrow namespace shape shared by gateway, storage, and agent-runtime.
 * `TId` defaults to `string` for node-side tests; Worker bindings use their
 * opaque Durable Object id type through the second generic parameter.
 */
export interface TenantObjectNamespaceLike<TStub, TId = string> {
  idFromName(name: string): TId;
  get(id: TId, options?: TenantObjectGetOptions): TStub;
}

const EASTERN_NORTH_AMERICA_COLOS = new Set([
  "ATL",
  "BOS",
  "EWR",
  "IAD",
  "JFK",
  "MIA",
  "ORD",
  "PHL",
  "YYZ",
]);

const EASTERN_EUROPE_COLOS = new Set([
  "ATH",
  "BUD",
  "HEL",
  "IST",
  "KIV",
  "OTP",
  "PRG",
  "RIX",
  "SOF",
  "TLL",
  "VIE",
  "WAW",
]);

const NORTHEAST_ASIA_COLOS = new Set(["ICN", "KIX", "NRT", "PEK", "PVG", "TPE"]);
const SOUTHEAST_ASIA_COLOS = new Set(["BKK", "CGK", "HKG", "KUL", "MNL", "SIN"]);
const MIDDLE_EAST_COLOS = new Set(["AMM", "BAH", "DOH", "DXB", "JED", "KWI", "MCT", "RUH", "TLV"]);

function normalizedSignalPart(value: unknown): string {
  return typeof value === "string" ? value.trim().toUpperCase() : "";
}

/**
 * Map Cloudflare's request placement signal to a legal Durable Object hint.
 * The mapping is intentionally small and deterministic; it is not a
 * residency decision. In particular, `sam`, `afr`, and `me` currently have no
 * Durable Object capacity and remain best-effort hints rather than guarantees.
 */
export function locationHintFromCloudflareSignal(
  signal: TenantPlacementSignal,
): TenantPlacementDecision {
  const continent = normalizedSignalPart(signal.continent);
  const colo = normalizedSignalPart(signal.colo);
  const sourceParts = [
    ...(continent === "" ? [] : [`cf.continent=${continent}`]),
    ...(colo === "" ? [] : [`cf.colo=${colo}`]),
  ];
  const source = sourceParts.length === 0 ? "cf.unavailable" : sourceParts.join(";");

  let locationHint: TenantLocationHint;
  if (MIDDLE_EAST_COLOS.has(colo)) {
    locationHint = "me";
  } else if (NORTHEAST_ASIA_COLOS.has(colo)) {
    locationHint = "apac-ne";
  } else if (SOUTHEAST_ASIA_COLOS.has(colo)) {
    locationHint = "apac-se";
  } else if (continent === "EU") {
    locationHint = EASTERN_EUROPE_COLOS.has(colo) ? "eeur" : "weur";
  } else if (continent === "NA") {
    locationHint = EASTERN_NORTH_AMERICA_COLOS.has(colo) ? "enam" : "wnam";
  } else if (continent === "SA") {
    locationHint = "sam";
  } else if (continent === "AF") {
    locationHint = "afr";
  } else if (continent === "ME") {
    locationHint = "me";
  } else if (continent === "OC") {
    locationHint = "oc";
  } else if (continent === "AS") {
    locationHint = "apac";
  } else {
    locationHint = "wnam";
  }

  return { locationHint, source };
}

/**
 * Derive the hard namespace jurisdiction from the existing residency region
 * vocabulary. An EU region always wins because storing a governed tenant
 * outside the EU would violate the stricter policy. A policy with no region
 * constraint leaves the object unrestricted.
 */
export function tenantJurisdictionForResidencyRegions(
  regions: readonly string[],
): TenantJurisdiction | undefined {
  const normalized = regions.map((region) => region.trim().toLowerCase());
  if (normalized.some((region) => /^(?:eu|europe)(?:[-_]|$)/.test(region))) return "eu";
  if (normalized.some((region) => /^fedramp(?:[-_]|$)/.test(region))) return "fedramp";
  if (normalized.some((region) => /^us(?:[-_]|$)/.test(region))) return "us";
  return undefined;
}

/** Select the namespace address before deriving its tenant id. */
export function tenantObjectNamespaceFor<TStub, TId = string>(
  namespace: TenantObjectNamespaceLike<TStub, TId>,
  address?: TenantObjectAddress,
): TenantObjectNamespaceLike<TStub, TId> {
  const jurisdiction = address?.jurisdiction;
  if (jurisdiction === undefined) return namespace;
  const candidate = namespace as TenantObjectNamespaceLike<TStub, TId> & {
    jurisdiction?: (jurisdiction: TenantJurisdiction) => TenantObjectNamespaceLike<TStub, TId>;
  };
  if (candidate.jurisdiction === undefined) {
    throw new Error(
      `tenant object namespace does not support jurisdiction(${JSON.stringify(jurisdiction)})`,
    );
  }
  return candidate.jurisdiction(jurisdiction);
}

/** Address one tenant object, passing a hint only when the caller supplied one. */
export function tenantObjectStubFor<TStub, TId = string>(
  namespace: TenantObjectNamespaceLike<TStub, TId>,
  tenantId: string,
  address?: TenantObjectAddress,
): TStub {
  const selected = tenantObjectNamespaceFor(namespace, address);
  const id = selected.idFromName(tenantId);
  const locationHint = address?.locationHint;
  return locationHint === undefined ? selected.get(id) : selected.get(id, { locationHint });
}
