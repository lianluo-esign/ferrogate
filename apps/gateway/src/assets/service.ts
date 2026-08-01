/**
 * The asset service: every rule of `/v1/assets/**`, expressed over the narrow
 * ports in `./ports.ts` and free of Hono.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/server/assets.rs` and
 * `server/asset_presign.rs` (issues #176/#177/#179/#258/#259/#260/#261/#262/
 * #366/#367/#368/#369/#371/#378/#379/#398/#528).
 *
 * ## Why the logic lives here and not in `handlers.ts`
 *
 * Every invariant this surface exists to hold — version immutability, channel
 * resolution, yank, per-tenant key isolation, the presign commit/abort
 * lifecycle — is decided against *storage*, not against HTTP. Keeping them in a
 * class that takes an `R2Bucket`-shaped port means each one is asserted
 * directly, with no request/response ceremony in the way, and means the
 * production wiring (`new AssetService({ objects: env.ASSETS, … })`) and the
 * offline wiring differ only in which object store is passed.
 *
 * ## The results contract
 *
 * Methods never throw for an expected refusal; they return an {@link AssetResult}
 * carrying the exact `(status, code, message)` triple the Rust handler wrote.
 * `handlers.ts` renders it into the gateway error envelope. That is what keeps
 * the status/code taxonomy assertable without a Worker.
 */
import {
  ASSET_REJECTED_CODE,
  ASSET_REJECTED_STATUS,
  assetContentRejection,
} from "./content-gate.js";
import {
  type AssetEgressCounters,
  type AssetEgressMeter,
  InMemoryAssetEgressCounters,
  NO_ASSET_EGRESS_METER,
  assetEgressQuotaDenial,
  assetPullAuditMessage,
  recordAssetEgress,
} from "./egress.js";
import { sha256Hex } from "./hash.js";
import {
  type AssetObjectRef,
  CrossTenantKeyError,
  assertKeyBelongsToTenant,
  assetChannelId,
  commitObjectKeyPrefix,
  newAssetObjectKey,
  newCommitObjectKey,
  newUploadId,
  stagingObjectKey,
  storedAssetId,
  storedAssetVariantId,
} from "./keys.js";
import {
  type AssetAuditSink,
  type AssetCaller,
  type AssetMetadataStore,
  type AssetObjectStore,
  type AssetPresigner,
  type AssetScreener,
  type AssetScreeningRequest,
  type AssetVisibility,
  PresignUnavailableError,
  type PresignedUpload,
  type StoredAsset,
  type StoredAssetChannel,
  isDownloadable,
  isScreeningRejection,
} from "./ports.js";
import {
  compareVersionsNewestFirst,
  resolutionHeaderValue,
  resolveVersion,
  selectVariant,
} from "./registry.js";
import type {
  AssetManifest,
  AssetStorageSummary,
  AssetSummary,
  AssetVisibilityPromotionRequest,
  PresignAbortRequest,
  PresignCommitRequest,
  PresignUploadIntentRequest,
  WithheldAssetSummary,
} from "./schemas.js";

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/** A 2xx terminal: the status and the body, derived together (Rust #528). */
export interface AssetOk<T> {
  readonly ok: true;
  readonly status: number;
  readonly body: T;
  readonly headers?: Readonly<Record<string, string>>;
}

/** A refusal, already shaped as the gateway error envelope's inputs. */
export interface AssetFailure {
  readonly ok: false;
  readonly status: number;
  readonly code: string;
  readonly message: string;
  readonly headers?: Readonly<Record<string, string>>;
}

export type AssetResult<T> = AssetOk<T> | AssetFailure;

/** The byte-serving terminal of `GET /v1/assets/{type}/{name}/{version}`. */
export interface AssetBytesOk {
  readonly ok: true;
  readonly status: number;
  /** `null` for `304`/`416`, which carry validators but no body. */
  readonly bytes: Uint8Array | null;
  readonly headers: Readonly<Record<string, string>>;
}

export type AssetPullResult = AssetBytesOk | AssetFailure;

function fail(status: number, code: string, message: string): AssetFailure {
  return { ok: false, status, code, message };
}

/** Rust `AdminList<T>` / `AdminPage<T>`. */
export interface AdminList<T> {
  readonly object: "list";
  readonly data: readonly T[];
  readonly total?: number;
  readonly offset?: number;
  readonly limit?: number;
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/**
 * Rust `assets::INLINE_ASSET_MAX_BYTES` — the largest object the *inline*
 * (through-the-Worker) push will hold. Larger objects must use the presigned
 * direct path, whose bytes never traverse the gateway.
 */
export const INLINE_ASSET_MAX_BYTES = 10 * 1024 * 1024;

/** Rust `assets::DEFAULT_ASSET_CACHE_CONTROL`. */
export const DEFAULT_ASSET_CACHE_CONTROL = "private, max-age=0, must-revalidate";

/** Operator-level knobs (Rust `[asset_bucket]` config + gateway limits). */
export interface AssetLimits {
  /** Inline push/pull buffering ceiling. */
  readonly inlineMaxBytes: number;
  /** Global presigned per-object ceiling, before tenant tightening. */
  readonly presignMaxObjectBytes: number;
  /** Presigned URL TTL, seconds. */
  readonly presignTtlSeconds: number;
  /**
   * Whether an object bucket is configured at all. `false` reproduces the Rust
   * `asset_bucket_unavailable` 503 on the whole presign family rather than
   * silently routing bytes through the gateway.
   */
  readonly presignEnabled: boolean;
  /**
   * Whether the object store this service holds is a REAL bucket.
   *
   * `false` refuses the two operations that move object BYTES — the inline push
   * and the inline pull — with the same `503 asset_bucket_unavailable` the
   * presign family already answers. It exists because the failure it prevents
   * is silent and permanent: with no `[[r2_buckets]] ASSETS` binding the
   * service falls back to {@link InMemoryAssetObjectStore}, whose contents die
   * with the isolate, while the METADATA row is written to D1 and survives. A
   * push then reports 201 and every later pull answers "the stored asset object
   * is missing from the object bucket" — a durable row pointing at bytes that
   * no longer exist anywhere.
   *
   * `true` by default, because a service built with explicit `deps` (every unit
   * suite, and `wrangler dev --local`, where miniflare really does emulate R2)
   * has a store that works. Only `assetDepsFromEnv` — the composition root's
   * half, the one that can observe an ABSENT binding — turns it off.
   *
   * The presign family is NOT gated on this separately: `presignEnabled`
   * already requires the bucket binding AND the five `ASSET_S3_*` values, so it
   * is false whenever this one is.
   */
  readonly objectStoreEnabled: boolean;
}

export const DEFAULT_ASSET_LIMITS: AssetLimits = {
  inlineMaxBytes: INLINE_ASSET_MAX_BYTES,
  presignMaxObjectBytes: 5 * 1024 * 1024 * 1024,
  presignTtlSeconds: 900,
  presignEnabled: false,
  objectStoreEnabled: true,
};

/**
 * Rust `asset_presign::effective_max_object_bytes`: the operator's global
 * ceiling tightened to BOTH the tenant's dedicated per-object cap and its
 * cumulative storage quota — a single object can never exceed the whole quota,
 * and the dedicated cap binds independently of it.
 */
export function effectiveMaxObjectBytes(
  global: number,
  perObject: number | undefined,
  quota: number | undefined,
): number {
  return Math.min(global, perObject ?? Number.POSITIVE_INFINITY, quota ?? Number.POSITIVE_INFINITY);
}

/** Rust `assets::inline_push_byte_limit`. */
export function inlinePushByteLimit(
  inlineMaxBytes: number,
  perObject: number | undefined,
  quota: number | undefined,
): number {
  return effectiveMaxObjectBytes(inlineMaxBytes, perObject, quota);
}

// ---------------------------------------------------------------------------
// Conditional / range requests (Rust `responses::evaluate_conditional_request`)
// ---------------------------------------------------------------------------

export type ConditionalOutcome =
  | { readonly kind: "full" }
  | { readonly kind: "not_modified" }
  | { readonly kind: "range"; readonly start: number; readonly end: number }
  | { readonly kind: "range_not_satisfiable" };

/** Rust `if_none_match_matches` — weak comparison, `*` matches anything. */
function ifNoneMatchMatches(ifNoneMatch: string, etag: string): boolean {
  const normalized = etag.replace(/^W\//, "");
  return ifNoneMatch
    .split(",")
    .map((candidate) => candidate.trim())
    .some((candidate) => candidate === "*" || candidate.replace(/^W\//, "") === normalized);
}

/** IMF-fixdate → unix seconds. `null` when unparseable. */
function parseHttpDate(value: string): number | null {
  const parsed = Date.parse(value.trim());
  return Number.isNaN(parsed) ? null : Math.floor(parsed / 1000);
}

/** Unix seconds → IMF-fixdate (`Last-Modified`). */
export function formatHttpDate(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toUTCString();
}

/** Rust `parse_single_byte_range`. Multi-range degrades to a full response. */
function parseSingleByteRange(value: string, totalLength: number): ConditionalOutcome {
  const trimmed = value.trim();
  if (!trimmed.startsWith("bytes=")) return { kind: "full" };
  const spec = trimmed.slice("bytes=".length);
  if (spec.includes(",")) return { kind: "full" };
  const dash = spec.indexOf("-");
  if (dash < 0) return { kind: "full" };
  const startSpec = spec.slice(0, dash).trim();
  const endSpec = spec.slice(dash + 1).trim();
  if (totalLength === 0) return { kind: "range_not_satisfiable" };
  const last = totalLength - 1;
  let start: number;
  let end: number;
  if (startSpec === "") {
    if (!/^\d+$/.test(endSpec)) return { kind: "full" };
    const suffix = Number(endSpec);
    if (suffix === 0) return { kind: "range_not_satisfiable" };
    start = totalLength - Math.min(suffix, totalLength);
    end = last;
  } else {
    if (!/^\d+$/.test(startSpec)) return { kind: "full" };
    start = Number(startSpec);
    if (endSpec === "") {
      end = last;
    } else {
      if (!/^\d+$/.test(endSpec)) return { kind: "full" };
      end = Math.min(Number(endSpec), last);
    }
  }
  if (start > last || start > end) return { kind: "range_not_satisfiable" };
  return { kind: "range", start, end };
}

/** Rust `evaluate_conditional_request`. */
export function evaluateConditionalRequest(
  headers: Headers,
  etag: string,
  lastModifiedUnix: number,
  totalLength: number,
): ConditionalOutcome {
  const ifNoneMatch = headers.get("if-none-match");
  if (ifNoneMatch !== null) {
    if (ifNoneMatchMatches(ifNoneMatch, etag)) return { kind: "not_modified" };
  } else {
    const ifModifiedSince = headers.get("if-modified-since");
    if (ifModifiedSince !== null) {
      const since = parseHttpDate(ifModifiedSince);
      if (since !== null && lastModifiedUnix > 0 && lastModifiedUnix <= since) {
        return { kind: "not_modified" };
      }
    }
  }
  const range = headers.get("range");
  if (range !== null) return parseSingleByteRange(range, totalLength);
  return { kind: "full" };
}

// ---------------------------------------------------------------------------
// Service inputs
// ---------------------------------------------------------------------------

/** Per-request correlation, threaded onto every audit row (Rust #522). */
export interface AssetRequestContext {
  readonly requestId: string;
  readonly agentRunId?: string | undefined;
}

/** `{asset_type}/{name}` — the logical asset. */
export interface AssetName {
  readonly assetType: string;
  readonly name: string;
}

/** `{asset_type}/{name}/{version}` plus the optional platform variant. */
export interface AssetVersionRef extends AssetName {
  readonly version: string;
  readonly variant?: string | undefined;
}

export interface AssetPushInput {
  readonly contentType?: string | undefined;
  readonly content: Uint8Array;
  /** `?channel=` — an optional channel move folded into the same request. */
  readonly channel?: string | undefined;
  /**
   * The `x-asset-signature*` detached publisher signature, when one was
   * presented. Passed straight through to the screener, which owns the
   * decision — the service never interprets it.
   */
  readonly signature?: AssetScreeningRequest["signature"];
}

export interface AssetPullInput {
  /** `?platform=` / `x-ferrogate-platform`. */
  readonly platform?: string | undefined;
  /** Client conditional/`Range` headers. */
  readonly headers: Headers;
  /** `HEAD` suppresses the body but keeps every header. */
  readonly method?: string | undefined;
}

export interface WithheldListInput {
  readonly assetType?: string | undefined;
  readonly search?: string | undefined;
  readonly offset?: number | undefined;
  readonly limit?: number | undefined;
}

/**
 * The download-side governance seam (issue #262, certification finding D4).
 *
 * Absent ⇒ the {@link DEFAULT_ASSET_EGRESS} posture: per-isolate counters and a
 * meter that drops charges. That is a deliberate DEGRADATION, not a bypass —
 * the deny gate still runs against whatever budget the caller's quota carries,
 * so a configured budget is enforced with or without a billing sink.
 */
export interface AssetEgressDeps {
  readonly counters: AssetEgressCounters;
  readonly meter: AssetEgressMeter;
  /** `asset_egress_price_per_gb`. Absent ⇒ metered but not priced. */
  readonly pricePerGb?: number | undefined;
}

export interface AssetServiceDeps {
  readonly objects: AssetObjectStore;
  readonly metadata: AssetMetadataStore;
  readonly presigner: AssetPresigner;
  readonly screener: AssetScreener;
  readonly audit: AssetAuditSink;
  readonly limits?: Partial<AssetLimits> | undefined;
  /** Injected clock, in unix seconds. */
  readonly now?: (() => number) | undefined;
  /** Egress quota + metering (issue #262). See {@link AssetEgressDeps}. */
  readonly egress?: AssetEgressDeps | undefined;
}

// ---------------------------------------------------------------------------
// Projections
// ---------------------------------------------------------------------------

/** Rust `AssetSummary::from_stored` (#528 flattens `visibility` onto it). */
export function assetSummary(asset: StoredAsset): AssetSummary {
  return {
    id: asset.id,
    asset_type: asset.asset_type,
    name: asset.name,
    version: asset.version,
    content_type: asset.content_type,
    content_hash: asset.content_hash,
    size_bytes: asset.size_bytes,
    storage_backed: asset.storage_uri !== "",
    visibility: asset.visibility,
    created_at_unix: asset.created_at_unix,
    updated_at_unix: asset.updated_at_unix,
  };
}

function channelSummary(channel: StoredAssetChannel) {
  return {
    channel: channel.channel,
    version: channel.version,
    updated_at_unix: channel.updated_at_unix,
  };
}

/**
 * Rust `asset_mutation_status` (#528): `200` when the stored row is `visible`
 * (stored AND serving), `202` when it is stored but WITHHELD. A flat 200 for
 * both was the defect — it told the caller "published" for an object no read
 * surface would return.
 */
export function assetMutationStatus(visibility: AssetVisibility): number {
  return isDownloadable(visibility) ? 200 : 202;
}

/** Rust `variant_suffix`. */
function variantSuffix(variant: string): string {
  return variant === "" ? "" : ` (${variant})`;
}

/** Rust `admin_list_query::matches_search`. */
function matchesSearch(search: string | undefined, haystack: readonly string[]): boolean {
  if (search === undefined || search.trim() === "") return true;
  const needle = search.trim().toLowerCase();
  return haystack.some((value) => value.toLowerCase().includes(needle));
}

/** Rust `build_manifest`. */
export function buildManifest(
  assetType: string,
  name: string,
  assets: readonly StoredAsset[],
  channels: readonly StoredAssetChannel[],
): AssetManifest {
  const versions: {
    version: string;
    yanked: boolean;
    variants: {
      variant: string;
      content_type: string;
      content_hash: string;
      size_bytes: number;
      storage_backed: boolean;
    }[];
  }[] = [];
  for (const asset of assets) {
    const variant = {
      variant: asset.variant,
      content_type: asset.content_type,
      content_hash: asset.content_hash,
      size_bytes: asset.size_bytes,
      storage_backed: asset.storage_uri !== "",
    };
    const entry = versions.find((candidate) => candidate.version === asset.version);
    if (entry) {
      entry.yanked = entry.yanked || asset.yanked;
      entry.variants.push(variant);
    } else {
      versions.push({ version: asset.version, yanked: asset.yanked, variants: [variant] });
    }
  }
  versions.sort((a, b) => compareVersionsNewestFirst(a.version, b.version));
  for (const entry of versions) {
    entry.variants.sort((a, b) => (a.variant < b.variant ? -1 : a.variant > b.variant ? 1 : 0));
  }
  const channelRows = channels
    .map(channelSummary)
    .sort((a, b) => (a.channel < b.channel ? -1 : a.channel > b.channel ? 1 : 0));
  return {
    object: "asset_manifest",
    asset_type: assetType,
    name,
    channels: channelRows,
    versions,
  };
}

// ---------------------------------------------------------------------------
// The service
// ---------------------------------------------------------------------------

/** Rust `AbortReason::parse` — an unrecognized reason degrades DOWN. */
type AbortReason = "abandoned" | "bucket_rejected";
function parseAbortReason(value: string | undefined): AbortReason {
  return value === "bucket_rejected" ? "bucket_rejected" : "abandoned";
}

type StagingReclamation = "not_staged" | "removed" | "removal_failed";

/**
 * Rust `classify_abort`. The one place a client *claim* becomes gateway
 * *evidence*: a `bucket_rejected` report survives only when the gateway's own
 * staging lookup agrees with it (nothing staged). A claim contradicted by a
 * staged object is downgraded to a plain abort, and there is deliberately no
 * path that upgrades an unknown reason INTO a bucket rejection.
 */
export function classifyAbort(
  reason: AbortReason,
  reclamation: StagingReclamation,
): "aborted" | "aborted_reclaim_failed" | "rejected_bucket" {
  if (reason === "bucket_rejected" && reclamation === "not_staged") {
    return "rejected_bucket";
  }
  if (reclamation === "removal_failed") return "aborted_reclaim_failed";
  return "aborted";
}

export class AssetService {
  readonly #objects: AssetObjectStore;
  readonly #metadata: AssetMetadataStore;
  readonly #presigner: AssetPresigner;
  readonly #screener: AssetScreener;
  readonly #audit: AssetAuditSink;
  readonly #limits: AssetLimits;
  readonly #now: () => number;
  readonly #egress: AssetEgressDeps;

  constructor(deps: AssetServiceDeps) {
    this.#objects = deps.objects;
    this.#metadata = deps.metadata;
    this.#presigner = deps.presigner;
    this.#screener = deps.screener;
    this.#audit = deps.audit;
    this.#limits = { ...DEFAULT_ASSET_LIMITS, ...(deps.limits ?? {}) };
    this.#now = deps.now ?? (() => Math.floor(Date.now() / 1000));
    this.#egress = deps.egress ?? {
      counters: new InMemoryAssetEgressCounters(this.#now),
      meter: NO_ASSET_EGRESS_METER,
    };
  }

  get limits(): AssetLimits {
    return this.#limits;
  }

  // -------------------------------------------------------------------------
  // Guards
  // -------------------------------------------------------------------------

  /** Rust `tenant_required` — assets require a tenant-attributed credential. */
  #requireTenant(caller: AssetCaller): AssetFailure | null {
    return caller.tenantId === ""
      ? fail(403, "tenant_required", "assets require a tenant-attributed API key")
      : null;
  }

  /**
   * Rust `tenant_can_host`: the tenant's plan enables asset hosting OR a bound
   * role grants `assets.host`. Applied to every WRITE surface, and deliberately
   * NOT to the read surfaces (list/manifest/pull) or to the presigned download,
   * matching `authorize_asset(require_hosting: false)`.
   */
  #requireHosting(caller: AssetCaller): AssetFailure | null {
    const tenant = this.#requireTenant(caller);
    if (tenant) return tenant;
    return caller.assetHostingEnabled
      ? null
      : fail(
          403,
          "asset_hosting_disabled",
          "the tenant's plan does not enable asset hosting and no bound role grants the assets.host permission",
        );
  }

  #ref(caller: AssetCaller, ref: AssetVersionRef): AssetObjectRef {
    return {
      tenantId: caller.tenantId,
      assetType: ref.assetType,
      name: ref.name,
      version: ref.version,
      variant: ref.variant ?? "",
    };
  }

  #record(
    context: AssetRequestContext,
    caller: AssetCaller,
    action: string,
    target: string,
    outcome: string,
    message: string,
  ): void {
    this.#audit.record({
      action,
      target,
      outcome,
      message,
      tenantId: caller.tenantId,
      requestId: context.requestId,
      agentRunId: context.agentRunId,
      occurredAtUnix: this.#now(),
    });
  }

  /**
   * Commit the audit rows this request buffered.
   *
   * The route module calls it once per request, in a `finally`. It is exposed
   * on the service rather than on the sink because the sink is private and the
   * service is what the router holds — and it deliberately does NOT swallow:
   * an audit sink that fails silently is indistinguishable from one that is not
   * wired at all, which is precisely the defect this codebase keeps shipping.
   * `assetRouteModule` decides the request-facing consequence.
   */
  async flushAudit(): Promise<void> {
    await this.#audit.flush?.();
  }

  /**
   * The one cross-tenant object guard. Every bucket call in this file goes
   * through here, so a `storage_uri` naming another tenant's prefix — a
   * corrupted row, a hand-crafted id — is refused BEFORE the bucket sees it.
   * Fail-closed: the caller is told the asset does not exist, never that it
   * exists but belongs to someone else.
   */
  #guardKey(key: string, tenantId: string): AssetFailure | null {
    try {
      assertKeyBelongsToTenant(key, tenantId);
      return null;
    } catch (error) {
      if (error instanceof CrossTenantKeyError) {
        return fail(404, "asset_not_found", "no such asset");
      }
      throw error;
    }
  }

  /**
   * Gate 1 of the Rust publish screening (`asset_security.rs`, finding D5) —
   * the per-`asset_type` content-type allowlist and the `mcp_manifest` stdio
   * refusal.
   *
   * Called DIRECTLY here, ahead of `#screener.screen`, on both write paths.
   * Routing it through the screener seam instead would make a control against
   * publishing remote-code-execution manifests disableable by configuration
   * (`assetScreenerFromEnv`) or by an injected test double — see
   * `content-gate.ts` for why that is not acceptable for this particular gate.
   */
  #contentGate(assetType: string, contentType: string, content: Uint8Array): AssetFailure | null {
    const rejection = assetContentRejection(assetType, contentType, content);
    return rejection === undefined
      ? null
      : fail(ASSET_REJECTED_STATUS, ASSET_REJECTED_CODE, rejection);
  }

  /**
   * The fail-closed egress admission gate (Rust `asset_egress_quota_denial`,
   * finding D4). `sizeBytes` is the RESOLVED OBJECT SIZE, never a served slice.
   */
  async #egressDenial(caller: AssetCaller, sizeBytes: number): Promise<AssetFailure | null> {
    const denial = await assetEgressQuotaDenial({
      quota: caller.effectiveQuota ?? {},
      apiKeyId: caller.apiKeyId ?? "",
      tenantId: caller.tenantId,
      bytes: sizeBytes,
      counters: this.#egress.counters,
    });
    return denial === null ? null : fail(denial.status, denial.code, denial.message);
  }

  /**
   * The egress meter + monthly counter + PULL-side audit event (Rust
   * `record_asset_egress`).
   *
   * `servedBytes` is what this response actually put on the wire, so a `206`
   * bills its slice and a `304`/`416`/`HEAD` bills nothing. It runs BEFORE the
   * body is handed back to the router, which is what makes a client that
   * disconnects mid-download still billed for what was served.
   */
  async #recordEgress(
    caller: AssetCaller,
    context: AssetRequestContext,
    asset: { assetType: string; name: string; version: string },
    servedBytes: number,
  ): Promise<void> {
    const charge = await recordAssetEgress({
      quota: caller.effectiveQuota ?? {},
      apiKeyId: caller.apiKeyId ?? "",
      tenantId: caller.tenantId,
      projectId: caller.projectId,
      requestId: context.requestId,
      agentRunId: context.agentRunId,
      assetType: asset.assetType,
      name: asset.name,
      version: asset.version,
      bytes: servedBytes,
      pricePerGb: this.#egress.pricePerGb,
      counters: this.#egress.counters,
      meter: this.#egress.meter,
      nowUnix: this.#now(),
    });
    if (charge === null) return;
    const id = storedAssetId(caller.tenantId, asset.assetType, asset.name, asset.version);
    this.#record(
      context,
      caller,
      "asset.pull",
      id,
      "served",
      assetPullAuditMessage(id, servedBytes),
    );
  }

  /** All variant rows across every version of one `{asset_type}/{name}`. */
  async #assetVersions(tenantId: string, ref: AssetName): Promise<StoredAsset[]> {
    const assets = await this.#metadata.listAssets(tenantId, ref.assetType);
    return assets.filter((asset) => asset.name === ref.name);
  }

  // -------------------------------------------------------------------------
  // listAssets · listAssetsByType
  // -------------------------------------------------------------------------

  async listAssets(
    caller: AssetCaller,
    assetType?: string,
  ): Promise<AssetResult<AdminList<AssetSummary>>> {
    const denied = this.#requireTenant(caller);
    if (denied) return denied;
    const assets = await this.#metadata.listAssets(caller.tenantId, assetType);
    // #366: the ordinary listing withholds pending/quarantined rows. They are
    // surfaced only through the dedicated `withheld` view below.
    const data = assets.filter((asset) => isDownloadable(asset.visibility)).map(assetSummary);
    return { ok: true, status: 200, body: { object: "list", data } };
  }

  // -------------------------------------------------------------------------
  // listWithheldAssets (#379)
  // -------------------------------------------------------------------------

  async listWithheldAssets(
    caller: AssetCaller,
    input: WithheldListInput = {},
  ): Promise<AssetResult<AdminList<WithheldAssetSummary>>> {
    const denied = this.#requireTenant(caller);
    if (denied) return denied;
    const withheld = await this.#metadata.listWithheldAssets(caller.tenantId, input.assetType);
    // Best-effort correlation with the screening evidence recorded at push time
    // (#366). `undefined` when that audit row is no longer retained — never a
    // fabricated verdict; the authoritative reason is the row's own visibility.
    const evidence = await this.#audit.screeningEvidence(caller.tenantId);
    const rows: WithheldAssetSummary[] = withheld
      .filter((asset) =>
        matchesSearch(input.search, [
          asset.id,
          asset.name,
          asset.version,
          asset.asset_type,
          asset.visibility,
        ]),
      )
      .map((asset) => {
        const detail = evidence.get(asset.id);
        return detail === undefined
          ? assetSummary(asset)
          : { ...assetSummary(asset), screening_evidence: detail };
      });
    if (input.offset === undefined && input.limit === undefined) {
      return { ok: true, status: 200, body: { object: "list", data: rows } };
    }
    const offset = input.offset ?? 0;
    const limit = input.limit ?? rows.length;
    return {
      ok: true,
      status: 200,
      body: {
        object: "list",
        data: rows.slice(offset, offset + limit),
        total: rows.length,
        offset,
        limit,
      },
    };
  }

  // -------------------------------------------------------------------------
  // getAssetStorageSummary
  // -------------------------------------------------------------------------

  async storageSummary(caller: AssetCaller): Promise<AssetResult<AssetStorageSummary>> {
    const denied = this.#requireTenant(caller);
    if (denied) return denied;
    const used = await this.#metadata.tenantAssetStorageBytesUsed(caller.tenantId);
    const quota = caller.assetStorageQuotaBytes;
    // The advertised presigned ceiling is the PLAN-EFFECTIVE one, not the raw
    // operator constant — otherwise the client is told it may upload an object
    // the intent path would reject.
    const effective = effectiveMaxObjectBytes(
      this.#limits.presignMaxObjectBytes,
      caller.assetMaxObjectBytes,
      quota,
    );
    const body: AssetStorageSummary = {
      object: "asset_storage_summary",
      used_bytes: used,
      ...(quota === undefined
        ? {}
        : { quota_bytes: quota, remaining_bytes: Math.max(0, quota - used) }),
      inline_upload_max_bytes: inlinePushByteLimit(
        this.#limits.inlineMaxBytes,
        caller.assetMaxObjectBytes,
        quota,
      ),
      presigned_upload: this.#limits.presignEnabled
        ? {
            enabled: true,
            max_object_bytes: effective,
            url_ttl_seconds: this.#limits.presignTtlSeconds,
          }
        : { enabled: false },
    };
    return { ok: true, status: 200, body };
  }

  // -------------------------------------------------------------------------
  // putAsset — the inline push
  // -------------------------------------------------------------------------

  async putAsset(
    caller: AssetCaller,
    ref: AssetVersionRef,
    input: AssetPushInput,
    context: AssetRequestContext,
  ): Promise<AssetResult<{ object: "asset"; asset: AssetSummary }>> {
    const denied = this.#requireHosting(caller);
    if (denied) return denied;

    const variant = ref.variant ?? "";
    const contentType = input.contentType ?? "application/octet-stream";

    // The per-request byte ceiling: the inline cap tightened to BOTH the
    // tenant's dedicated per-object cap and its cumulative quota.
    const limit = inlinePushByteLimit(
      this.#limits.inlineMaxBytes,
      caller.assetMaxObjectBytes,
      caller.assetStorageQuotaBytes,
    );
    if (input.content.byteLength > limit) {
      return fail(
        413,
        "payload_too_large",
        `asset content exceeds the maximum size of ${limit} bytes`,
      );
    }

    const id = storedAssetVariantId(caller.tenantId, ref.assetType, ref.name, ref.version, variant);

    // Gate (1) of the Rust screening order (`asset_security.rs`, finding D5):
    // the content-type allowlist and the `mcp_manifest` stdio refusal, ahead of
    // the signature and scan gates and ahead of every durable effect.
    const contentRejected = this.#contentGate(ref.assetType, contentType, input.content);
    if (contentRejected) {
      this.#record(
        context,
        caller,
        "asset.push",
        id,
        "rejected_commit",
        `asset ${id} rejected by trust screening (${contentRejected.code}): ${contentRejected.message}`,
      );
      return contentRejected;
    }

    const contentHash = await sha256Hex(input.content);
    const now = this.#now();

    // Supply-chain trust (#179/#261/#366) runs BEFORE anything is durably
    // written — FerroGate vouches for what it stores, it does not merely proxy.
    const screening = await this.#screener.screen({
      assetId: storedAssetId(caller.tenantId, ref.assetType, ref.name, ref.version),
      tenantId: caller.tenantId,
      assetType: ref.assetType,
      contentType,
      content: input.content,
      contentSha256: contentHash,
      nowUnix: now,
      ...(input.signature !== undefined ? { signature: input.signature } : {}),
    });
    if (isScreeningRejection(screening)) {
      this.#record(
        context,
        caller,
        "asset.push",
        id,
        "rejected_commit",
        `asset ${id} rejected by trust screening (${screening.code}): ${screening.message}`,
      );
      return fail(screening.status, screening.code, screening.message);
    }

    // Immutability (#260): a published `{name}/{version}` per variant is frozen.
    // The definitive arbiter is the atomic create below; this pre-check only
    // saves a needless object write on the common case.
    const existing = await this.#metadata.getAsset(id);
    if (existing !== null) {
      return fail(
        409,
        "asset_version_immutable",
        `${ref.assetType}/${ref.name}/${ref.version}${variantSuffix(variant)} already exists and is immutable; delete it before republishing`,
      );
    }

    // #369: the bytes go to a UNIQUE per-attempt key, so two concurrent first
    // pushes of the same version can never overwrite each other's object — the
    // winner's row references only the bytes IT wrote, and a loser can only
    // ever reclaim its own candidate.
    const objectRef = this.#ref(caller, { ...ref, variant });
    const candidateKey = newAssetObjectKey(objectRef);
    const guard = this.#guardKey(candidateKey, caller.tenantId);
    if (guard) return guard;

    // No bucket ⇒ refuse HERE: after content screening (a security gate a
    // config error must never be able to skip) and immutability, but before the
    // FIRST durable effect. The `put` below and the `createAssetWithinQuota`
    // after it land in two different stores, and with no bucket only one of
    // them survives the isolate — see `AssetLimits.objectStoreEnabled` for why
    // a 201 there is worse than a 503 here.
    if (!this.#limits.objectStoreEnabled) return objectStoreUnavailable();

    await this.#objects.put(candidateKey, bufferOf(input.content), {
      httpMetadata: { contentType },
    });

    const asset: StoredAsset = {
      id,
      tenant_id: caller.tenantId,
      project_id: caller.projectId,
      asset_type: ref.assetType,
      name: ref.name,
      version: ref.version,
      content_type: contentType,
      content_hash: contentHash,
      size_bytes: input.content.byteLength,
      storage_uri: candidateKey,
      variant,
      yanked: false,
      // #366: persist the verdict, so a pending/quarantined push is durably
      // withheld from every read path rather than merely labeled on the wire.
      visibility: screening.visibility,
      created_at_unix: now,
      updated_at_unix: now,
    };

    // #371: quota admission is folded INTO the create, not a read-then-write
    // pair — the pair let two concurrent pushes of two different ids both
    // observe the same remaining capacity and jointly overshoot.
    const admission = await this.#metadata.createAssetWithinQuota(
      asset,
      caller.assetStorageQuotaBytes,
    );
    if (admission.kind === "over_quota") {
      // Definitively not published, so this attempt's candidate is provably
      // unreferenced and is reclaimed here.
      await this.#bestEffortDelete(candidateKey);
      this.#record(
        context,
        caller,
        "asset.push",
        id,
        "rejected_commit",
        `asset ${id} inline push rejected: reserving ${admission.attempted_bytes} bytes on top of ${admission.used_bytes} used would exceed the tenant's ${admission.quota_bytes}-byte asset storage quota`,
      );
      return fail(
        403,
        "asset_storage_quota_exceeded",
        `pushing this asset would exceed the tenant's ${admission.quota_bytes}-byte asset storage quota`,
      );
    }
    if (admission.kind === "already_exists") {
      await this.#bestEffortDelete(candidateKey);
      return fail(
        409,
        "asset_version_immutable",
        `${ref.assetType}/${ref.name}/${ref.version}${variantSuffix(variant)} already exists and is immutable; delete it before republishing`,
      );
    }

    this.#record(
      context,
      caller,
      "asset.push",
      id,
      "committed",
      `asset ${id} pushed (${asset.size_bytes} bytes); ${screening.auditDetail}; manifest=${JSON.stringify(screening.manifest)}`,
    );

    // Optional same-request channel move (#260): `?channel=stable`.
    if (input.channel !== undefined) {
      const moved = await this.#moveChannel(
        caller,
        { assetType: ref.assetType, name: ref.name },
        input.channel,
        ref.version,
        context,
      );
      if (!moved.ok) return moved;
    }

    return {
      ok: true,
      status: assetMutationStatus(asset.visibility),
      body: { object: "asset", asset: assetSummary(asset) },
    };
  }

  // -------------------------------------------------------------------------
  // getAsset — the pull
  // -------------------------------------------------------------------------

  async pullAsset(
    caller: AssetCaller,
    ref: AssetName & { readonly reference: string },
    input: AssetPullInput,
    context: AssetRequestContext = { requestId: "" },
  ): Promise<AssetPullResult> {
    const denied = this.#requireTenant(caller);
    if (denied) return denied;

    const all = await this.#assetVersions(caller.tenantId, ref);
    // #366: withhold pending/quarantined rows from RESOLUTION entirely, so an
    // unproven asset is absent from exact/channel/range resolution and can
    // never be selected for download (write-path == read-path).
    const assets = all.filter((asset) => isDownloadable(asset.visibility));
    const channels = await this.#metadata.listAssetChannels(
      caller.tenantId,
      ref.assetType,
      ref.name,
    );

    const resolved = resolveVersion(assets, channels, ref.reference);
    if (resolved === null) {
      return fail(
        404,
        "asset_not_found",
        `no asset resolves for ${ref.assetType}/${ref.name}/${ref.reference}`,
      );
    }

    const requestedPlatform =
      input.platform ?? input.headers.get("x-ferrogate-platform") ?? undefined;
    const versionRows = assets.filter((asset) => asset.version === resolved.version);
    const choice = selectVariant(versionRows, requestedPlatform);
    if (choice.kind === "not_found") {
      return fail(
        404,
        "asset_variant_not_found",
        `${ref.assetType}/${ref.name}/${resolved.version} has no${requestedPlatform === undefined ? "" : ` ${requestedPlatform}`} variant`,
      );
    }
    if (choice.kind === "ambiguous") {
      return fail(
        400,
        "asset_variant_required",
        `${ref.assetType}/${ref.name}/${resolved.version} carries multiple platform variants; specify one with ?platform=`,
      );
    }
    const selected = choice.asset;

    const extra: Record<string, string> = {
      "x-ferrogate-asset-resolved": resolutionHeaderValue(resolved.how, resolved.version),
      "x-ferrogate-asset-version": resolved.version,
    };
    if (selected.variant !== "") {
      extra["x-ferrogate-asset-variant"] = selected.variant;
    }
    if (resolved.yanked) {
      // An EXACT pull of a yanked version still succeeds — existing pins keep
      // working — but it says so, loudly and machine-readably.
      extra["warning"] =
        `299 ferrogate "asset ${ref.assetType}/${ref.name}/${resolved.version} is yanked"`;
      extra["x-ferrogate-asset-yanked"] = "true";
    }

    // #262 egress quota (finding D4): the fail-closed deny gate, BEFORE a byte
    // is read or served, charged the RESOLVED OBJECT SIZE exactly as Rust does
    // (`assets.rs:1114` passes `selected.size_bytes`, never a range slice, so a
    // caller cannot drain an exhausted budget one `Range` header at a time).
    const egressDenied = await this.#egressDenial(caller, selected.size_bytes);
    if (egressDenied) return egressDenied;

    const loaded = await this.#loadAssetContent(selected, caller.tenantId);
    if (!loaded.ok) return loaded;
    const content = loaded.body;

    // Re-verify integrity on EVERY read (#176/#179): a mismatch is storage
    // corruption or tampering, not a client error.
    if ((await sha256Hex(content)) !== selected.content_hash) {
      return fail(
        500,
        "asset_integrity_check_failed",
        "stored asset content hash does not match recorded hash",
      );
    }

    const etag = `"${selected.content_hash}"`;
    const validators: Record<string, string> = {
      ...extra,
      etag,
      "last-modified": formatHttpDate(selected.updated_at_unix),
      "cache-control": DEFAULT_ASSET_CACHE_CONTROL,
    };
    const isHead = (input.method ?? "GET").toUpperCase() === "HEAD";
    const outcome = evaluateConditionalRequest(
      input.headers,
      etag,
      selected.updated_at_unix,
      content.byteLength,
    );
    switch (outcome.kind) {
      case "not_modified":
        return { ok: true, status: 304, bytes: null, headers: validators };
      case "range_not_satisfiable":
        return {
          ok: true,
          status: 416,
          bytes: null,
          headers: {
            ...validators,
            "content-type": selected.content_type,
            "content-range": `bytes */${content.byteLength}`,
          },
        };
      case "range": {
        const slice = content.slice(outcome.start, outcome.end + 1);
        const body = isHead ? null : slice;
        // #262 egress metering: the SLICE, not the object. Two ranges that
        // together cover an object bill it exactly once, so a RESUMED download
        // is never double-billed. Recorded before the body is handed back, so
        // a client that disconnects mid-download is still billed for what was
        // actually served.
        await this.#recordEgress(
          caller,
          context,
          { assetType: ref.assetType, name: ref.name, version: resolved.version },
          body === null ? 0 : body.byteLength,
        );
        return {
          ok: true,
          status: 206,
          bytes: body,
          headers: {
            ...validators,
            "content-type": selected.content_type,
            "content-length": String(slice.byteLength),
            "content-range": `bytes ${outcome.start}-${outcome.end}/${content.byteLength}`,
          },
        };
      }
      case "full": {
        const body = isHead ? null : content;
        await this.#recordEgress(
          caller,
          context,
          { assetType: ref.assetType, name: ref.name, version: resolved.version },
          body === null ? 0 : body.byteLength,
        );
        return {
          ok: true,
          status: 200,
          bytes: body,
          headers: {
            ...validators,
            "content-type": selected.content_type,
            "content-length": String(content.byteLength),
          },
        };
      }
    }
  }

  // -------------------------------------------------------------------------
  // deleteAsset
  // -------------------------------------------------------------------------

  async deleteAsset(
    caller: AssetCaller,
    ref: AssetVersionRef,
    context: AssetRequestContext,
  ): Promise<AssetResult<{ object: string; id: string; deleted: boolean }>> {
    const denied = this.#requireHosting(caller);
    if (denied) return denied;
    const variant = ref.variant ?? "";
    const id = storedAssetVariantId(caller.tenantId, ref.assetType, ref.name, ref.version, variant);
    const existing = await this.#metadata.getAsset(id);
    // The ROW goes first and the object only after a committed row delete: an
    // orphaned object is reclaimable by GC, a row that outlives its bytes is not.
    const outcome = await this.#metadata.deleteAssetVariantIfUnreferenced(
      id,
      caller.tenantId,
      ref.assetType,
      ref.name,
      ref.version,
    );
    if (outcome.kind === "not_found") {
      return fail(
        404,
        "asset_not_found",
        `no asset at ${ref.assetType}/${ref.name}/${ref.version}${variantSuffix(variant)}`,
      );
    }
    if (outcome.kind === "blocked_by_channel") {
      this.#record(
        context,
        caller,
        "asset.delete",
        id,
        "rejected",
        `asset ${id} delete rejected: last resolvable variant of a channel-referenced version`,
      );
      return fail(
        409,
        "asset_version_referenced",
        `${ref.assetType}/${ref.name}/${ref.version} is the last resolvable variant of a channel-referenced version; move or delete the channel first`,
      );
    }
    if (existing !== null && existing.storage_uri !== "") {
      await this.#bestEffortDelete(existing.storage_uri, caller.tenantId);
    }
    this.#record(context, caller, "asset.delete", id, "committed", `asset ${id} deleted`);
    return { ok: true, status: 200, body: { object: "asset", id, deleted: true } };
  }

  // -------------------------------------------------------------------------
  // yank / unyank
  // -------------------------------------------------------------------------

  async setVersionYank(
    caller: AssetCaller,
    ref: AssetVersionRef,
    yanked: boolean,
    context: AssetRequestContext,
  ): Promise<AssetResult<AdminList<AssetSummary>>> {
    const denied = this.#requireHosting(caller);
    if (denied) return denied;
    const action = yanked ? "asset.yank" : "asset.unyank";
    const target = `${caller.tenantId}:${ref.assetType}:${ref.name}:${ref.version}`;
    const outcome = await this.#metadata.setAssetVersionYank(
      caller.tenantId,
      ref.assetType,
      ref.name,
      ref.version,
      yanked,
      this.#now(),
    );
    if (outcome.kind === "not_found") {
      return fail(
        404,
        "asset_not_found",
        `no asset at ${ref.assetType}/${ref.name}/${ref.version}`,
      );
    }
    if (outcome.kind === "referenced_by_channel") {
      // Fail-closed: a yank may not strand a live channel pointer. The single
      // serialization point in the store is what makes this hold against a
      // concurrent move rather than being a read-then-write race (#367).
      this.#record(
        context,
        caller,
        action,
        target,
        "rejected",
        `asset ${ref.assetType}/${ref.name}/${ref.version} yank rejected: still referenced by a channel; move the channel off this version first`,
      );
      return fail(
        409,
        "asset_version_referenced",
        `${ref.assetType}/${ref.name}/${ref.version} is still referenced by a channel; move the channel off this version before yanking`,
      );
    }
    this.#record(
      context,
      caller,
      action,
      target,
      "committed",
      `asset ${ref.assetType}/${ref.name}/${ref.version} ${yanked ? "yanked" : "unyanked"}`,
    );
    // Re-read for the RESPONSE only — the mutation already committed durably.
    const rows = await this.#assetVersions(caller.tenantId, ref);
    const data = rows.filter((asset) => asset.version === ref.version).map(assetSummary);
    return { ok: true, status: 200, body: { object: "list", data } };
  }

  // -------------------------------------------------------------------------
  // visibility promotion (#378)
  // -------------------------------------------------------------------------

  async promoteVisibility(
    caller: AssetCaller,
    ref: AssetVersionRef,
    request: AssetVisibilityPromotionRequest,
    context: AssetRequestContext,
  ): Promise<AssetResult<unknown>> {
    const denied = this.#requireHosting(caller);
    if (denied) return denied;

    // An unknown verdict is rejected fail-closed: a promotion NEVER defaults to
    // `visible`, so a malformed scan report can never publish unscanned bytes.
    let target: "visible" | "quarantined";
    switch (request.scan_outcome) {
      case "clean":
      case "visible":
        target = "visible";
        break;
      case "quarantined":
      case "quarantine":
      case "infected":
        target = "quarantined";
        break;
      default:
        return fail(
          400,
          "invalid_scan_outcome",
          `scan_outcome must be one of clean|quarantined (got ${JSON.stringify(request.scan_outcome)}); an unknown verdict is rejected fail-closed and never promotes`,
        );
    }
    const evidence = request.evidence.trim();
    if (evidence === "") {
      return fail(
        400,
        "missing_scan_evidence",
        "evidence is required: supply the completed-scan justification (scanner id, verdict detail, or ticket) to promote an asset",
      );
    }

    const variant = ref.variant ?? "";
    const id = storedAssetVariantId(caller.tenantId, ref.assetType, ref.name, ref.version, variant);
    const scanner = request.scanner ?? "out-of-band";
    const detail = `scan_outcome=${target} target_visibility=${target} scanner=${scanner} evidence=${evidence}`;
    const outcome = await this.#metadata.promotePendingAssetVisibility(id, target, this.#now());
    if (outcome.kind === "not_found") {
      // A scan verdict arriving for an absent asset is security-relevant.
      this.#record(
        context,
        caller,
        "asset.visibility.promote",
        id,
        "rejected",
        `asset ${id} promotion rejected: no such asset (${detail})`,
      );
      return fail(
        404,
        "asset_not_found",
        `no asset at ${ref.assetType}/${ref.name}/${ref.version}${variantSuffix(variant)}`,
      );
    }
    if (outcome.kind === "not_pending") {
      this.#record(
        context,
        caller,
        "asset.visibility.promote",
        id,
        "rejected",
        `asset ${id} promotion rejected: not pending_scan (current=${outcome.current}); ${detail}`,
      );
      return fail(
        409,
        "asset_not_pending_scan",
        `${ref.assetType}/${ref.name}/${ref.version}${variantSuffix(variant)} is ${outcome.current}, not pending_scan; only a pending_scan asset can be promoted`,
      );
    }
    this.#record(
      context,
      caller,
      "asset.visibility.promote",
      id,
      "committed",
      `asset ${id} promoted pending_scan -> ${outcome.to} (${detail})`,
    );
    const asset = await this.#metadata.getAsset(id);
    if (asset === null) {
      return fail(
        404,
        "asset_not_found",
        `no asset at ${ref.assetType}/${ref.name}/${ref.version}`,
      );
    }
    return {
      ok: true,
      status: 200,
      body: {
        object: "asset.visibility_promotion",
        id,
        visibility: outcome.to,
        scan_outcome: target,
        asset: assetSummary(asset),
      },
    };
  }

  // -------------------------------------------------------------------------
  // channels
  // -------------------------------------------------------------------------

  async listChannels(
    caller: AssetCaller,
    ref: AssetName,
  ): Promise<AssetResult<AdminList<ReturnType<typeof channelSummary>>>> {
    const denied = this.#requireTenant(caller);
    if (denied) return denied;
    const channels = await this.#metadata.listAssetChannels(
      caller.tenantId,
      ref.assetType,
      ref.name,
    );
    return {
      ok: true,
      status: 200,
      body: { object: "list", data: channels.map(channelSummary) },
    };
  }

  /** Shared by `putAssetChannel` and the push's `?channel=` fold. */
  async #moveChannel(
    caller: AssetCaller,
    ref: AssetName,
    channel: string,
    version: string,
    context: AssetRequestContext,
  ): Promise<AssetResult<StoredAssetChannel>> {
    const channelId = assetChannelId(caller.tenantId, ref.assetType, ref.name, channel);
    const now = this.#now();
    const outcome = await this.#metadata.moveAssetChannel(
      caller.tenantId,
      ref.assetType,
      ref.name,
      channel,
      version,
      now,
    );
    if (outcome.kind === "target_not_resolvable") {
      this.#record(
        context,
        caller,
        "asset.channel.move",
        channelId,
        "rejected",
        `channel ${ref.assetType}/${ref.name}/${channel} -> ${version} rejected: target version is absent or yanked`,
      );
      return fail(
        404,
        "channel_target_not_found",
        `no resolvable version ${ref.assetType}/${ref.name}/${version} for this channel`,
      );
    }
    this.#record(
      context,
      caller,
      "asset.channel.move",
      channelId,
      "committed",
      `channel ${ref.assetType}/${ref.name}/${channel} ${outcome.prior_version ?? "none"} -> ${version}`,
    );
    return {
      ok: true,
      status: 200,
      body: {
        id: channelId,
        tenant_id: caller.tenantId,
        asset_type: ref.assetType,
        name: ref.name,
        channel,
        version,
        updated_at_unix: now,
      },
    };
  }

  async putChannel(
    caller: AssetCaller,
    ref: AssetName,
    channel: string,
    version: string | undefined,
    context: AssetRequestContext,
  ): Promise<AssetResult<unknown>> {
    const denied = this.#requireHosting(caller);
    if (denied) return denied;
    if (version === undefined || version === "") {
      return fail(400, "channel_target_required", "a channel move requires ?version={version}");
    }
    const moved = await this.#moveChannel(caller, ref, channel, version, context);
    if (!moved.ok) return moved;
    return {
      ok: true,
      status: 200,
      body: {
        object: "asset_channel",
        asset_type: ref.assetType,
        name: ref.name,
        channel: channelSummary(moved.body),
      },
    };
  }

  async deleteChannel(
    caller: AssetCaller,
    ref: AssetName,
    channel: string,
    context: AssetRequestContext,
  ): Promise<AssetResult<{ object: string; id: string; deleted: boolean }>> {
    const denied = this.#requireHosting(caller);
    if (denied) return denied;
    const id = assetChannelId(caller.tenantId, ref.assetType, ref.name, channel);
    const deleted = await this.#metadata.deleteAssetChannel(id);
    if (!deleted) {
      return fail(404, "channel_not_found", `no channel ${ref.assetType}/${ref.name}/${channel}`);
    }
    this.#record(
      context,
      caller,
      "asset.channel.delete",
      id,
      "committed",
      `asset channel ${ref.assetType}/${ref.name}/${channel} deleted`,
    );
    return { ok: true, status: 200, body: { object: "asset_channel", id, deleted: true } };
  }

  // -------------------------------------------------------------------------
  // manifest
  // -------------------------------------------------------------------------

  async manifest(caller: AssetCaller, ref: AssetName): Promise<AssetResult<AssetManifest>> {
    const denied = this.#requireTenant(caller);
    if (denied) return denied;
    const all = await this.#assetVersions(caller.tenantId, ref);
    // #366: the self-serve manifest advertises RESOLVABLE versions, so a
    // withheld row must be absent from it exactly as it is from resolution.
    const assets = all.filter((asset) => isDownloadable(asset.visibility));
    if (assets.length === 0) {
      return fail(404, "asset_not_found", `no asset ${ref.assetType}/${ref.name}`);
    }
    const channels = await this.#metadata.listAssetChannels(
      caller.tenantId,
      ref.assetType,
      ref.name,
    );
    return {
      ok: true,
      status: 200,
      body: buildManifest(ref.assetType, ref.name, assets, channels),
    };
  }

  // -------------------------------------------------------------------------
  // presign: upload intent
  // -------------------------------------------------------------------------

  async createUploadIntent(
    caller: AssetCaller,
    ref: AssetVersionRef,
    request: PresignUploadIntentRequest,
    context: AssetRequestContext,
  ): Promise<AssetResult<unknown>> {
    const denied = this.#requireHosting(caller);
    if (denied) return denied;

    const id = storedAssetId(caller.tenantId, ref.assetType, ref.name, ref.version);
    const existing = await this.#metadata.getAsset(id);
    if (existing !== null) {
      return this.#versionImmutable(ref);
    }
    if (!this.#limits.presignEnabled) return bucketUnavailable();

    const maxObjectBytes = effectiveMaxObjectBytes(
      this.#limits.presignMaxObjectBytes,
      caller.assetMaxObjectBytes,
      caller.assetStorageQuotaBytes,
    );
    if (request.size_bytes > maxObjectBytes) {
      // `rejected_intent` distinguishes this PREFLIGHT rejection from a
      // bucket-boundary (`rejected_bucket`) and a commit-time
      // (`rejected_commit`) one — three different pieces of evidence.
      this.#record(
        context,
        caller,
        "asset.presign_upload_intent",
        id,
        "rejected_intent",
        `rejected upload intent for asset ${id}: ${request.size_bytes} bytes exceeds the ${maxObjectBytes}-byte per-object ceiling`,
      );
      return fail(
        413,
        "payload_too_large",
        `object size ${request.size_bytes} exceeds the per-object ceiling of ${maxObjectBytes} bytes`,
      );
    }

    // Quota PREFLIGHT so an obviously over-quota upload is refused before a URL
    // is handed out. The authoritative accounting still happens atomically at
    // commit, when the real bytes exist (#371).
    const quota = caller.assetStorageQuotaBytes;
    if (quota !== undefined) {
      const used = await this.#metadata.tenantAssetStorageBytesUsed(caller.tenantId);
      if (used + request.size_bytes > quota) {
        this.#record(
          context,
          caller,
          "asset.presign_upload_intent",
          id,
          "rejected_intent",
          `rejected upload intent for asset ${id}: ${request.size_bytes} bytes would exceed the tenant's ${quota}-byte asset storage quota`,
        );
        return fail(
          403,
          "asset_storage_quota_exceeded",
          `uploading this asset would exceed the tenant's ${quota}-byte asset storage quota`,
        );
      }
    }

    const uploadId = newUploadId();
    const sha256 = request.sha256.toLowerCase();
    const objectRef = this.#ref(caller, { ...ref, variant: "" });
    const stagingKey = stagingObjectKey(objectRef, uploadId, request.size_bytes, sha256);
    const guard = this.#guardKey(stagingKey, caller.tenantId);
    if (guard) return guard;

    let upload: PresignedUpload;
    try {
      // #368: the URL is BOUND to the declared size + checksum — those are
      // SigV4-signed headers, so a PUT that changes either is refused at the
      // bucket boundary, not merely at the gateway's commit check.
      upload = await this.#presigner.presignPut(
        stagingKey,
        this.#limits.presignTtlSeconds,
        this.#now(),
        request.size_bytes,
        sha256,
      );
    } catch (error) {
      if (error instanceof PresignUnavailableError) return bucketUnavailable();
      throw error;
    }

    this.#record(
      context,
      caller,
      "asset.presign_upload_intent",
      id,
      "issued",
      `issued upload ${uploadId} with a ${this.#limits.presignTtlSeconds}s presigned staging URL for asset ${id} (${request.size_bytes} bytes)`,
    );

    return {
      ok: true,
      status: 200,
      body: {
        object: "asset_upload_intent",
        key: id,
        upload_id: uploadId,
        upload_url: upload.url,
        method: "PUT",
        expires_in_seconds: this.#limits.presignTtlSeconds,
        size_bytes: request.size_bytes,
        sha256,
        required_headers: upload.requiredHeaders,
        max_object_bytes: maxObjectBytes,
        upload_protocol: "single_put",
      },
    };
  }

  // -------------------------------------------------------------------------
  // presign: commit
  // -------------------------------------------------------------------------

  async commitUpload(
    caller: AssetCaller,
    ref: AssetVersionRef,
    request: PresignCommitRequest,
    context: AssetRequestContext,
  ): Promise<AssetResult<unknown>> {
    const denied = this.#requireHosting(caller);
    if (denied) return denied;

    const sha256 = request.sha256.toLowerCase();
    const contentType = request.content_type ?? "application/octet-stream";
    const id = storedAssetId(caller.tenantId, ref.assetType, ref.name, ref.version);
    const objectRef = this.#ref(caller, { ...ref, variant: "" });
    const stagingKey = stagingObjectKey(objectRef, request.upload_id, request.size_bytes, sha256);
    const guard = this.#guardKey(stagingKey, caller.tenantId);
    if (guard) return guard;

    const existing = await this.#metadata.getAsset(id);
    if (existing !== null) {
      if (
        this.#existingMatchesCommit(
          existing,
          objectRef,
          request.upload_id,
          request.size_bytes,
          sha256,
          contentType,
        )
      ) {
        // An idempotent re-commit reports the durable row's CURRENT screening
        // state (#528): the retry's caller is exactly the client that needs to
        // learn the version it published is still withheld.
        return {
          ok: true,
          status: assetMutationStatus(existing.visibility),
          body: { object: "asset", asset: assetSummary(existing) },
        };
      }
      if (!this.#existingUsesUpload(existing, objectRef, request.upload_id)) {
        await this.#bestEffortDelete(stagingKey, caller.tenantId);
      }
      return this.#versionImmutable(ref);
    }

    if (!this.#limits.presignEnabled) return bucketUnavailable();

    // 1. HEAD gates the object's SIZE before a single byte is transferred.
    const head = await this.#objects.head(stagingKey);
    if (head === null) {
      // `staging_missing`, NOT `rejected_bucket`: absence proves only that no
      // bytes are staged. It cannot distinguish never-attempted from
      // expired-URL from bucket-refused, and the gateway never observes the
      // direct PUT — calling it a bucket rejection would be inference dressed
      // as evidence. The abort surface is where a corroborated rejection lives.
      this.#record(
        context,
        caller,
        "asset.push",
        id,
        "staging_missing",
        `asset ${id} upload ${request.upload_id} has no staged object at commit; the direct PUT was never attempted, its URL expired, or the bucket refused it (indistinguishable from here -- see POST /v1/assets/presign/abort)`,
      );
      return fail(
        404,
        "asset_not_uploaded",
        "no object was uploaded to the presigned URL for this asset",
      );
    }

    const maxObjectBytes = effectiveMaxObjectBytes(
      this.#limits.presignMaxObjectBytes,
      caller.assetMaxObjectBytes,
      caller.assetStorageQuotaBytes,
    );
    if (head.size !== request.size_bytes || head.size > maxObjectBytes) {
      await this.#bestEffortDelete(stagingKey, caller.tenantId);
      return this.#rejectedCommit(
        context,
        caller,
        id,
        request.upload_id,
        "asset_commit_size_mismatch",
        `committed object size ${head.size} does not match the registered ${request.size_bytes} bytes`,
      );
    }

    // 2. Fetch to verify the SHA-256 over the real bytes.
    const staged = await this.#objects.get(stagingKey);
    if (staged === null) {
      this.#record(
        context,
        caller,
        "asset.push",
        id,
        "staging_missing",
        `asset ${id} upload ${request.upload_id} disappeared between HEAD and GET at commit`,
      );
      return fail(
        404,
        "asset_not_uploaded",
        "no object was uploaded to the presigned URL for this asset",
      );
    }
    const bytes = new Uint8Array(await staged.arrayBuffer());
    const actualSha256 = await sha256Hex(bytes);
    if (actualSha256 !== sha256 || bytes.byteLength !== request.size_bytes) {
      await this.#bestEffortDelete(stagingKey, caller.tenantId);
      return this.#rejectedCommit(
        context,
        caller,
        id,
        request.upload_id,
        "asset_commit_hash_mismatch",
        "committed object sha256/size does not match the registered intent",
      );
    }

    const now = this.#now();
    // 3a. Gate (1) of the Rust screening order over the FINAL verified bytes
    // (finding D5). A presigned upload is exactly how a tenant would smuggle a
    // stdio `mcp_manifest` past an inline-only gate, so it runs here too.
    const contentRejected = this.#contentGate(ref.assetType, contentType, bytes);
    if (contentRejected) {
      await this.#bestEffortDelete(stagingKey, caller.tenantId);
      this.#record(
        context,
        caller,
        "asset.push",
        id,
        "rejected_commit",
        `asset ${id} upload ${request.upload_id} failed trust screening (${contentRejected.code}): ${contentRejected.message}`,
      );
      return contentRejected;
    }

    // 3b. The SAME trust screening the inline path runs, over the FINAL verified
    // bytes (#366). Before that issue a presigned upload silently bypassed the
    // signature requirement, the approval gate, and the malware scanner.
    const screening = await this.#screener.screen({
      assetId: id,
      tenantId: caller.tenantId,
      assetType: ref.assetType,
      contentType,
      content: bytes,
      contentSha256: actualSha256,
      nowUnix: now,
    });
    if (isScreeningRejection(screening)) {
      await this.#bestEffortDelete(stagingKey, caller.tenantId);
      this.#record(
        context,
        caller,
        "asset.push",
        id,
        "rejected_commit",
        `asset ${id} upload ${request.upload_id} failed trust screening (${screening.code}): ${screening.message}`,
      );
      return fail(screening.status, screening.code, screening.message);
    }

    // 4. Copy the VERIFIED bytes to a private immutable key nothing can
    // reference yet, so a replay of the client-facing staging URL cannot race a
    // different payload into the published object.
    const finalKey = newCommitObjectKey(objectRef, request.upload_id);
    const finalGuard = this.#guardKey(finalKey, caller.tenantId);
    if (finalGuard) return finalGuard;
    await this.#objects.put(finalKey, bufferOf(bytes), {
      httpMetadata: { contentType },
    });

    const asset: StoredAsset = {
      id,
      tenant_id: caller.tenantId,
      project_id: caller.projectId,
      asset_type: ref.assetType,
      name: ref.name,
      version: ref.version,
      content_type: contentType,
      content_hash: actualSha256,
      size_bytes: bytes.byteLength,
      storage_uri: finalKey,
      variant: "",
      yanked: false,
      visibility: screening.visibility,
      created_at_unix: now,
      updated_at_unix: now,
    };
    const admission = await this.#metadata.createAssetWithinQuota(
      asset,
      caller.assetStorageQuotaBytes,
    );
    if (admission.kind === "over_quota") {
      // Nothing was reserved or published, so the final candidate is provably
      // unreferenced. Staging is reclaimed too and the caller gets the 422 the
      // rest of commit verification uses.
      await this.#bestEffortDelete(finalKey, caller.tenantId);
      await this.#bestEffortDelete(stagingKey, caller.tenantId);
      this.#record(
        context,
        caller,
        "asset.push",
        id,
        "rejected_commit",
        `asset ${id} upload ${request.upload_id} rejected at commit: ${asset.size_bytes} bytes would exceed the tenant's ${admission.quota_bytes}-byte asset storage quota`,
      );
      return fail(
        422,
        "asset_storage_quota_exceeded",
        `committing this asset would exceed the tenant's ${admission.quota_bytes}-byte asset storage quota`,
      );
    }
    if (admission.kind === "already_exists") {
      await this.#bestEffortDelete(stagingKey, caller.tenantId);
      const winner = await this.#metadata.getAsset(id);
      if (winner === null) {
        await this.#bestEffortDelete(finalKey, caller.tenantId);
        return fail(
          503,
          "storage_unavailable",
          "the conflicting asset disappeared before it could be reconciled",
        );
      }
      if (winner.storage_uri !== finalKey) {
        await this.#bestEffortDelete(finalKey, caller.tenantId);
      }
      if (
        this.#existingMatchesCommit(
          winner,
          objectRef,
          request.upload_id,
          request.size_bytes,
          sha256,
          contentType,
        )
      ) {
        return {
          ok: true,
          status: assetMutationStatus(winner.visibility),
          body: { object: "asset", asset: assetSummary(winner) },
        };
      }
      return this.#versionImmutable(ref);
    }

    this.#record(
      context,
      caller,
      "asset.push",
      id,
      "committed",
      `asset ${id} committed via presigned upload ${request.upload_id} (${asset.size_bytes} bytes); ${screening.auditDetail}; manifest=${JSON.stringify(screening.manifest)}`,
    );
    await this.#bestEffortDelete(stagingKey, caller.tenantId);
    return {
      ok: true,
      status: assetMutationStatus(asset.visibility),
      body: { object: "asset", asset: assetSummary(asset) },
    };
  }

  // -------------------------------------------------------------------------
  // presign: abort
  // -------------------------------------------------------------------------

  async abortUpload(
    caller: AssetCaller,
    ref: AssetVersionRef,
    request: PresignAbortRequest,
    context: AssetRequestContext,
  ): Promise<AssetResult<unknown>> {
    const denied = this.#requireHosting(caller);
    if (denied) return denied;

    const reason = parseAbortReason(request.reason);
    const sha256 = request.sha256.toLowerCase();
    const id = storedAssetId(caller.tenantId, ref.assetType, ref.name, ref.version);
    const objectRef = this.#ref(caller, { ...ref, variant: "" });
    const stagingKey = stagingObjectKey(objectRef, request.upload_id, request.size_bytes, sha256);
    const guard = this.#guardKey(stagingKey, caller.tenantId);
    if (guard) return guard;

    // A published version is immutable: aborting its upload must not become a
    // back door to deleting what the commit already promoted.
    const existing = await this.#metadata.getAsset(id);
    if (existing !== null && this.#existingUsesUpload(existing, objectRef, request.upload_id)) {
      return fail(
        409,
        "asset_upload_already_committed",
        `upload ${request.upload_id} for ${ref.assetType}/${ref.name}/${ref.version} is already committed and cannot be aborted`,
      );
    }

    if (!this.#limits.presignEnabled) return bucketUnavailable();

    // The corroboration step. A HEAD transport failure is NOT laundered into
    // "nothing staged" — an unknown bucket state must never become evidence of
    // a bucket rejection, so it fails the request instead.
    let staged: boolean;
    try {
      staged = (await this.#objects.head(stagingKey)) !== null;
    } catch {
      return bucketUnavailable();
    }

    // The reclamation is reported from the DELETE's own result, never from the
    // HEAD that preceded it: telling a tenant its quota was freed while the
    // bytes sit in the bucket is exactly the dishonesty this endpoint removes.
    let reclamation: StagingReclamation;
    if (!staged) {
      reclamation = "not_staged";
    } else {
      reclamation = (await this.#bestEffortDelete(stagingKey, caller.tenantId))
        ? "removed"
        : "removal_failed";
    }

    const outcome = classifyAbort(reason, reclamation);
    const stagingState =
      reclamation === "not_staged"
        ? "no staging object existed"
        : reclamation === "removed"
          ? "its staging object was reclaimed"
          : "its staging object could NOT be deleted and still occupies bucket capacity until the lifecycle GC collects it";
    const claim =
      reason === "bucket_rejected"
        ? reclamation === "not_staged"
          ? "was reported rejected by the bucket; the report is consistent with the gateway finding nothing under its staging key"
          : "claimed a bucket rejection but its staging object existed, so the claim is contradicted and recorded as an abort instead"
        : "was abandoned by the client";
    this.#record(
      context,
      caller,
      "asset.presign_upload_abort",
      id,
      outcome,
      `asset ${id} upload ${request.upload_id} ${claim}; ${stagingState}`,
    );

    return {
      ok: true,
      status: 200,
      body: {
        object: "asset_upload_abort",
        upload_id: request.upload_id,
        staging_object_removed: reclamation === "removed",
        staging_reclamation: reclamation,
        outcome,
      },
    };
  }

  // -------------------------------------------------------------------------
  // presign: download
  // -------------------------------------------------------------------------

  async downloadUrl(
    caller: AssetCaller,
    ref: AssetVersionRef,
    context: AssetRequestContext,
  ): Promise<AssetResult<unknown>> {
    // `authorize_asset(require_hosting: false)`: a tenant whose hosting
    // entitlement lapsed must still be able to READ what it already published.
    const denied = this.#requireTenant(caller);
    if (denied) return denied;

    const id = storedAssetId(caller.tenantId, ref.assetType, ref.name, ref.version);
    const asset = await this.#metadata.getAsset(id);
    const notFound = fail(
      404,
      "asset_not_found",
      `no asset at ${ref.assetType}/${ref.name}/${ref.version}`,
    );
    if (asset === null) return notFound;
    // #366: a withheld asset is invisible here exactly as it is on the inline
    // pull — the SAME 404, so unproven is indistinguishable from absent.
    if (!isDownloadable(asset.visibility)) return notFound;
    // Cross-tenant: a row whose id somehow addresses another tenant's prefix is
    // refused before it can be signed.
    if (asset.tenant_id !== caller.tenantId) return notFound;
    if (asset.storage_uri === "") {
      return fail(
        409,
        "asset_not_bucket_backed",
        "this asset is stored inline; fetch it via GET /v1/assets/{asset_type}/{name}/{version}",
      );
    }
    const guard = this.#guardKey(asset.storage_uri, caller.tenantId);
    if (guard) return guard;
    if (!this.#limits.presignEnabled) {
      return fail(
        503,
        "asset_bucket_unavailable",
        "this asset is bucket-backed but no asset_bucket is configured",
      );
    }

    // #262 egress quota (finding D4): gate the presigned path too. The bytes
    // leave the bucket DIRECTLY and the gateway never observes them, so URL
    // issuance is the only moment at which this download can be refused —
    // leaving it ungated would make the presign endpoint a complete bypass of
    // the byte budget the inline pull enforces.
    const egressDenied = await this.#egressDenial(caller, asset.size_bytes);
    if (egressDenied) return egressDenied;

    let url: string;
    try {
      url = await this.#presigner.presignGet(
        asset.storage_uri,
        this.#limits.presignTtlSeconds,
        this.#now(),
      );
    } catch (error) {
      if (error instanceof PresignUnavailableError) return bucketUnavailable();
      throw error;
    }

    this.#record(
      context,
      caller,
      "asset.presign_download",
      id,
      "issued",
      `issued a ${this.#limits.presignTtlSeconds}s presigned download URL for asset ${id}`,
    );

    // Rust `asset_presign.rs:1629`: the presigned direct path bills at ISSUANCE
    // using the object size, since the bytes never traverse the gateway hot
    // path and there is no later moment at which they could be counted.
    await this.#recordEgress(
      caller,
      context,
      { assetType: ref.assetType, name: ref.name, version: ref.version },
      asset.size_bytes,
    );

    return {
      ok: true,
      status: 200,
      body: {
        object: "asset_download_url",
        download_url: url,
        method: "GET",
        expires_in_seconds: this.#limits.presignTtlSeconds,
        // The hash travels with the URL so the agent can verify bytes it fetched
        // directly from the bucket, which the gateway never sees.
        sha256: asset.content_hash,
        size_bytes: asset.size_bytes,
        content_type: asset.content_type,
      },
    };
  }

  // -------------------------------------------------------------------------
  // internals
  // -------------------------------------------------------------------------

  #versionImmutable(ref: AssetVersionRef): AssetFailure {
    return fail(
      409,
      "asset_version_immutable",
      `${ref.assetType}/${ref.name}/${ref.version} already exists and is immutable; delete it before republishing`,
    );
  }

  #rejectedCommit(
    context: AssetRequestContext,
    caller: AssetCaller,
    id: string,
    uploadId: string,
    code: string,
    message: string,
  ): AssetFailure {
    this.#record(
      context,
      caller,
      "asset.push",
      id,
      "rejected_commit",
      `asset ${id} upload ${uploadId} failed commit verification (${code}): ${message}`,
    );
    return fail(422, code, message);
  }

  /** Rust `existing_asset_uses_upload`. */
  #existingUsesUpload(asset: StoredAsset, ref: AssetObjectRef, uploadId: string): boolean {
    return asset.storage_uri.startsWith(commitObjectKeyPrefix(ref, uploadId));
  }

  /** Rust `existing_asset_matches_commit`. */
  #existingMatchesCommit(
    asset: StoredAsset,
    ref: AssetObjectRef,
    uploadId: string,
    sizeBytes: number,
    sha256: string,
    contentType: string,
  ): boolean {
    return (
      this.#existingUsesUpload(asset, ref, uploadId) &&
      asset.size_bytes === sizeBytes &&
      asset.content_hash.toLowerCase() === sha256 &&
      asset.content_type === contentType
    );
  }

  /**
   * Read an asset's real bytes. Bounded by the inline ceiling: the pull serves
   * from a full in-memory copy (it re-verifies the hash and answers
   * conditional/Range requests), so it MUST NOT be reachable for an object the
   * gateway refuses to hold — above the bound it names the presigned download
   * instead of materializing the object.
   */
  async #loadAssetContent(asset: StoredAsset, tenantId: string): Promise<AssetResult<Uint8Array>> {
    if (asset.size_bytes > this.#limits.inlineMaxBytes) {
      return fail(
        413,
        "asset_too_large_for_inline_pull",
        `asset ${asset.id} is ${asset.size_bytes} bytes, above the gateway's ${this.#limits.inlineMaxBytes}-byte inline read budget; fetch it via GET /v1/assets/presign/download/{asset_type}/{name}/{version}`,
      );
    }
    const guard = this.#guardKey(asset.storage_uri, tenantId);
    if (guard) return guard;
    // With no bucket bound, `get` would consult an isolate-local Map and report
    // the row's bytes "missing from the object bucket" — true, but it names the
    // wrong cause and invites an operator to hunt for a deleted object. The
    // bucket is not missing an object; there is no bucket.
    if (!this.#limits.objectStoreEnabled) return objectStoreUnavailable();
    const object = await this.#objects.get(asset.storage_uri);
    if (object === null) {
      return fail(
        503,
        "storage_unavailable",
        "the stored asset object is missing from the object bucket",
      );
    }
    return { ok: true, status: 200, body: new Uint8Array(await object.arrayBuffer()) };
  }

  /**
   * Delete an object, reporting whether the bucket confirmed it. Returns
   * `false` on refusal rather than throwing, because every call site's job is
   * cleanup — but no call site is allowed to *claim* a reclamation the bucket
   * refused, which is why the boolean exists at all.
   */
  async #bestEffortDelete(key: string, tenantId?: string): Promise<boolean> {
    if (tenantId !== undefined && this.#guardKey(key, tenantId) !== null) return false;
    try {
      await this.#objects.delete(key);
      return true;
    } catch {
      return false;
    }
  }
}

/** Rust `asset_bucket_unavailable`. */
function bucketUnavailable(): AssetFailure {
  return fail(
    503,
    "asset_bucket_unavailable",
    "the presigned large-file path requires an asset bucket to be configured",
  );
}

/**
 * The same Rust code for the INLINE family, with the cause named.
 *
 * Deliberately the same `asset_bucket_unavailable` code as the presign refusal:
 * from the client's side it is one condition — this deployment has no object
 * bucket — and splitting it would make a client handle two codes for one cause.
 * The MESSAGE differs because the remedy is read by an operator, not a client.
 */
function objectStoreUnavailable(): AssetFailure {
  return fail(
    503,
    "asset_bucket_unavailable",
    "no asset object bucket is configured on this deployment; declare the ASSETS R2 binding " +
      "before pushing or pulling asset bytes",
  );
}

/** A standalone `ArrayBuffer` copy of a view — R2 `put` wants a BufferSource. */
function bufferOf(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
