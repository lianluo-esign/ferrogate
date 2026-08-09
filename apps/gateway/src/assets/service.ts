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
  type AssetEgressCounters,
  type AssetEgressMeter,
  InMemoryAssetEgressCounters,
  NO_ASSET_EGRESS_METER,
  assetEgressQuotaDenial,
  assetEgressTargetId,
  assetPullAuditMessage,
  recordAssetEgress,
} from "@ferrogate/billing";
import {
  bundlePathRejection,
  detectArchiveFormat,
  expandBundle,
  isBundleArchiveContentType,
  isBundlePush,
  normalizeBundlePath,
  textBundleFileContentType,
} from "./bundle.js";
import {
  ASSET_REJECTED_CODE,
  ASSET_REJECTED_STATUS,
  EICAR_SIGNATURE,
  assetContentRejection,
  streamedAssetContentRejection,
} from "./content-gate.js";
import { StreamingSha256, randomHex128, sha256Hex, toHex } from "./hash.js";
import {
  type AssetObjectRef,
  CrossTenantKeyError,
  assertKeyBelongsToTenant,
  assetChannelId,
  bundleFileObjectKey,
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
  type AssetBundleIndexStore,
  type AssetBundleScreeningVerdict,
  type AssetCaller,
  type AssetMetadataStore,
  type AssetObjectBody,
  type AssetObjectStore,
  type AssetPresigner,
  type AssetScreener,
  type AssetScreeningRequest,
  type AssetScreeningVerdict,
  type AssetStreamScreeningRequest,
  type AssetVisibility,
  InMemoryAssetBundleIndexStore,
  PresignUnavailableError,
  type PresignedUpload,
  type StoredAsset,
  type StoredAssetChannel,
  type StoredAssetMetadata,
  type StoredBundleFile,
  isDownloadable,
  isScreeningRejection,
  strictestVisibility,
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
  FileListQuery,
  FileListResponse,
  FileObject,
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

function assetEgressAuditTarget(asset: StoredAsset, tenantId: string): string | AssetFailure {
  try {
    return assetEgressTargetId(
      {
        id: asset.id,
        assetType: asset.asset_type,
        name: asset.name,
        version: asset.version,
        sizeBytes: asset.size_bytes,
      },
      tenantId,
    );
  } catch {
    return fail(500, "asset_identity_invalid", "stored asset has no valid durable ID");
  }
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

/** Reserved asset coordinates backing the OpenAI-compatible Files API. */
export const OPENAI_FILE_ASSET_TYPE = "openai_file";
export const OPENAI_FILE_VERSION = "1";

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
  /** Metadata projection used by the OpenAI Files adapter. */
  readonly metadata?: StoredAssetMetadata | undefined;
}

/** Replayable multipart file input; the stream factory is used twice on the large path. */
export interface FileUploadInput {
  readonly size_bytes: number;
  readonly stream: () => ReadableStream<Uint8Array>;
  readonly contentType: string;
  readonly metadata: { readonly filename: string; readonly purpose: string };
}

export interface AssetPullInput {
  /** `?platform=` / `x-ferrogate-platform`. */
  readonly platform?: string | undefined;
  /**
   * `?path=` — one file inside a `static_site` BUNDLE version (#736).
   *
   * Deliberately NOT a second resolution path. The reference still resolves to
   * a version through {@link resolveVersion} and to an artifact through
   * {@link selectVariant}, with channels, semver ranges, yank and variants all
   * behaving exactly as they do for a single-object asset; only the last step —
   * which bytes of the already-resolved artifact to serve — consults the bundle
   * index. A yanked bundle therefore drops out of channel resolution before
   * this field is ever read.
   */
  readonly bundlePath?: string | undefined;
  /** Client conditional/`Range` headers. */
  readonly headers: Headers;
  /** `HEAD` suppresses the body but keeps every header. */
  readonly method?: string | undefined;
  /**
   * `cache-control` for THIS response (issue #737).
   *
   * Absent ⇒ {@link DEFAULT_ASSET_CACHE_CONTROL}, which is what
   * `GET /v1/assets/**` has always sent and still sends. The site serve mode
   * supplies its own, because cacheability there is a property of the file and
   * of how the reader was authenticated, not of the surface: see
   * `src/sites/policy.ts`.
   */
  readonly cacheControl?: string | undefined;
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
  /**
   * The `static_site` bundle file index (#736). Absent ⇒ an in-memory index,
   * which is right for unit suites and for `wrangler dev --local`; the
   * composition root supplies the D1-backed one.
   */
  readonly bundles?: AssetBundleIndexStore | undefined;
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

/** Project one reserved asset row into the OpenAI Files object. */
export function fileObject(asset: StoredAsset): FileObject {
  const status =
    asset.visibility === "visible"
      ? "processed"
      : asset.visibility === "pending_scan"
        ? "uploaded"
        : "error";
  return {
    id: asset.name,
    object: "file",
    bytes: asset.size_bytes,
    created_at: asset.created_at_unix,
    filename: asset.metadata?.filename ?? asset.name,
    purpose: asset.metadata?.purpose ?? "assistants",
    status,
    status_details: asset.visibility === "quarantined" ? "asset screening withheld the file" : null,
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
  readonly #bundles: AssetBundleIndexStore;
  readonly #presigner: AssetPresigner;
  readonly #screener: AssetScreener;
  readonly #audit: AssetAuditSink;
  readonly #limits: AssetLimits;
  readonly #now: () => number;
  readonly #egress: AssetEgressDeps;

  constructor(deps: AssetServiceDeps) {
    this.#objects = deps.objects;
    this.#metadata = deps.metadata;
    this.#bundles = deps.bundles ?? new InMemoryAssetBundleIndexStore();
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

  /** Screen text members of a `skill_bundle` archive without publishing rows. */
  async #screenSkillBundleFiles(
    caller: AssetCaller,
    assetType: string,
    assetId: string,
    archive: Uint8Array,
    contentType: string,
    context: AssetRequestContext,
  ): Promise<AssetResult<AssetBundleScreeningVerdict | undefined>> {
    if (assetType !== "skill_bundle" || this.#screener.screenBundleFiles === undefined) {
      return { ok: true, status: 200, body: undefined };
    }

    // A skill publisher may use the permissive octet-stream entry from the
    // content gate. Magic-byte detection keeps that declaration from becoming
    // an archive-screening bypass while still admitting ordinary binaries.
    if (!isBundleArchiveContentType(contentType) && detectArchiveFormat(archive) === undefined) {
      return { ok: true, status: 200, body: undefined };
    }
    const expansion = await expandBundle(archive, undefined, {
      fileContentType: textBundleFileContentType,
      skipUnknownFileTypes: true,
    });
    if (!expansion.ok) {
      return fail(
        ASSET_REJECTED_STATUS,
        ASSET_REJECTED_CODE,
        `${expansion.message} (pushed as ${contentType})`,
      );
    }
    return {
      ok: true,
      status: 200,
      body: await this.#screener.screenBundleFiles({
        assetId,
        tenantId: caller.tenantId,
        assetType,
        nowUnix: this.#now(),
        requestId: context.requestId,
        files: expansion.files,
      }),
    };
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
    asset: { id: string; assetType: string; name: string; version: string },
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
    const id = asset.id;
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
  // OpenAI Files projection (#742)
  // -------------------------------------------------------------------------

  async createFile(
    caller: AssetCaller,
    input: FileUploadInput,
    context: AssetRequestContext,
  ): Promise<AssetResult<FileObject>> {
    const fileId = `file-${randomHex128()}`;
    const ref: AssetVersionRef = {
      assetType: OPENAI_FILE_ASSET_TYPE,
      name: fileId,
      version: OPENAI_FILE_VERSION,
    };
    const inlineLimit = inlinePushByteLimit(
      this.#limits.inlineMaxBytes,
      caller.assetMaxObjectBytes,
      caller.assetStorageQuotaBytes,
    );

    let status: number;
    if (input.size_bytes <= inlineLimit) {
      let content: Uint8Array;
      try {
        content = await readUploadBytes(input.stream(), inlineLimit);
      } catch (error) {
        return fileUploadReadFailure(error, inlineLimit);
      }
      const pushed = await this.putAsset(
        caller,
        ref,
        {
          content,
          contentType: input.contentType,
          metadata: input.metadata,
        },
        context,
      );
      if (!pushed.ok) return pushed;
      status = pushed.status;
    } else {
      // A multipart File is replayable, so the first pass only measures and
      // hashes chunks. The second pass is handed directly to R2 under the
      // intent-derived staging key; no large Uint8Array is created in Worker.
      const maxObjectBytes = effectiveMaxObjectBytes(
        this.#limits.presignMaxObjectBytes,
        caller.assetMaxObjectBytes,
        caller.assetStorageQuotaBytes,
      );
      let measured: { size_bytes: number; sha256: string };
      try {
        measured = await measureUpload(input.stream(), maxObjectBytes);
      } catch (error) {
        return fileUploadReadFailure(error, maxObjectBytes);
      }
      const intent = await this.createUploadIntent(
        caller,
        ref,
        { size_bytes: measured.size_bytes, sha256: measured.sha256 },
        context,
      );
      if (!intent.ok) return intent;
      const uploadId = (intent.body as { upload_id?: unknown }).upload_id;
      if (typeof uploadId !== "string") {
        return fail(503, "storage_unavailable", "the upload intent did not return an upload id");
      }
      const stagingKey = stagingObjectKey(
        this.#ref(caller, { ...ref, variant: "" }),
        uploadId,
        measured.size_bytes,
        measured.sha256,
      );
      const guard = this.#guardKey(stagingKey, caller.tenantId);
      if (guard) return guard;
      try {
        await this.#objects.put(stagingKey, input.stream(), {
          httpMetadata: { contentType: input.contentType },
        });
      } catch (error) {
        await this.#bestEffortDelete(stagingKey, caller.tenantId);
        return fail(
          503,
          "storage_unavailable",
          `the file could not be staged in the object bucket: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      const committed = await this.commitUpload(
        caller,
        ref,
        {
          upload_id: uploadId,
          size_bytes: measured.size_bytes,
          sha256: measured.sha256,
          content_type: input.contentType,
          metadata: input.metadata,
        },
        context,
      );
      if (!committed.ok) return committed;
      status = committed.status;
    }

    const asset = await this.#metadata.getAsset(
      storedAssetVariantId(
        caller.tenantId,
        OPENAI_FILE_ASSET_TYPE,
        fileId,
        OPENAI_FILE_VERSION,
        "",
      ),
    );
    if (asset === null) {
      return fail(
        503,
        "storage_unavailable",
        "the file metadata row was not available after upload",
      );
    }
    return { ok: true, status, body: fileObject(asset) };
  }

  async listFiles(
    caller: AssetCaller,
    input: FileListQuery = {},
  ): Promise<AssetResult<FileListResponse>> {
    const denied = this.#requireTenant(caller);
    if (denied) return denied;
    let files = (await this.#metadata.listAssets(caller.tenantId, OPENAI_FILE_ASSET_TYPE))
      .filter((asset) => asset.asset_type === OPENAI_FILE_ASSET_TYPE && asset.variant === "")
      .filter((asset) => input.purpose === undefined || asset.metadata?.purpose === input.purpose)
      .sort((left, right) => {
        const byCreated = right.created_at_unix - left.created_at_unix;
        return byCreated !== 0 ? byCreated : right.name.localeCompare(left.name);
      });
    const afterIndex =
      input.after === undefined ? -1 : files.findIndex((file) => file.name === input.after);
    if (afterIndex >= 0) files = files.slice(afterIndex + 1);
    const limit = input.limit ?? 10_000;
    const data = files.slice(0, limit).map(fileObject);
    return {
      ok: true,
      status: 200,
      body: { object: "list", data, has_more: files.length > data.length },
    };
  }

  async getFile(caller: AssetCaller, fileId: string): Promise<AssetResult<FileObject>> {
    const denied = this.#requireTenant(caller);
    if (denied) return denied;
    const asset = await this.#metadata.getAsset(
      storedAssetVariantId(
        caller.tenantId,
        OPENAI_FILE_ASSET_TYPE,
        fileId,
        OPENAI_FILE_VERSION,
        "",
      ),
    );
    if (asset === null || asset.asset_type !== OPENAI_FILE_ASSET_TYPE || asset.variant !== "") {
      return fail(404, "asset_not_found", "no such file");
    }
    return { ok: true, status: 200, body: fileObject(asset) };
  }

  async fileContent(
    caller: AssetCaller,
    fileId: string,
    input: AssetPullInput,
    context: AssetRequestContext,
  ): Promise<AssetPullResult> {
    return this.pullAsset(
      caller,
      {
        assetType: OPENAI_FILE_ASSET_TYPE,
        name: fileId,
        reference: OPENAI_FILE_VERSION,
      },
      input,
      context,
    );
  }

  async deleteFile(
    caller: AssetCaller,
    fileId: string,
    context: AssetRequestContext,
  ): Promise<AssetResult<{ id: string; object: "file"; deleted: true }>> {
    const deleted = await this.deleteAsset(
      caller,
      {
        assetType: OPENAI_FILE_ASSET_TYPE,
        name: fileId,
        version: OPENAI_FILE_VERSION,
      },
      context,
    );
    if (!deleted.ok) return deleted;
    return {
      ok: true,
      status: deleted.status,
      body: { id: fileId, object: "file", deleted: true },
    };
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
    // #736: a `static_site` pushed as an archive is a multi-file BUNDLE, not an
    // opaque blob. The decision is made from the asset type plus the container
    // content type — both of which the content gate below has already vetted —
    // so it adds no new client-controlled switch.
    const bundle = isBundlePush(ref.assetType, contentType);

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
      // #740: the join key for the guardrail evidence rows this screening may
      // write, so `GET /admin/v1/investigations?request_id=…` finds the asset
      // evaluation exactly as it finds an inference one.
      requestId: context.requestId,
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

    // #740: a skill archive has no readable surface until it is expanded. The
    // archive is screened before its object is stored, just like the inline
    // text arm, but its opaque members are not published as bundle rows.
    const skillBundleScreening = await this.#screenSkillBundleFiles(
      caller,
      ref.assetType,
      id,
      input.content,
      contentType,
      context,
    );
    if (!skillBundleScreening.ok) {
      this.#record(
        context,
        caller,
        "asset.push",
        id,
        "rejected_commit",
        `asset ${id} rejected by skill bundle guardrail screening (${skillBundleScreening.code}): ${skillBundleScreening.message}`,
      );
      return skillBundleScreening;
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
      ...(input.metadata === undefined ? {} : { metadata: input.metadata }),
      size_bytes: input.content.byteLength,
      storage_uri: candidateKey,
      variant,
      yanked: false,
      // #366: persist the verdict, so a pending/quarantined push is durably
      // withheld from every read path rather than merely labeled on the wire.
      //
      // #736: a BUNDLE is admitted as `pending_scan` no matter what the
      // screener said, because the version is not yet what it claims to be —
      // its files have not been expanded. `pending_scan` is exactly the right
      // state for that: the row reserves `{name}/{version}` against a
      // concurrent push and against the quota, while `isDownloadable` keeps it
      // out of every read path. The screener's verdict is applied afterwards
      // through the existing CAS promotion, so a partial expansion cannot
      // reach `visible` — the promotion is the last step and never runs.
      visibility: bundle
        ? "pending_scan"
        : strictestVisibility(
            screening.visibility,
            skillBundleScreening.body?.visibility ?? "visible",
          ),
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

    // #736: the version is reserved and invisible; NOW expand it. A refusal
    // here — a traversing path, a symlink, a disallowed file type, a bomb —
    // unwinds the whole publish, so the reservation cannot become a permanent
    // tombstone that blocks the corrected republish.
    if (bundle) {
      const expanded = await this.#expandBundleIntoStore(
        caller,
        objectRef,
        id,
        input.content,
        contentType,
        context,
      );
      if (!expanded.ok) {
        await this.#unwindBundlePublish(caller, ref, id, candidateKey);
        this.#record(
          context,
          caller,
          "asset.push",
          id,
          "rejected_commit",
          `asset ${id} static_site bundle rejected (${expanded.code}): ${expanded.message}`,
        );
        return expanded;
      }
      // #740: the archive verdict and the PER-FILE verdict are folded through
      // `strictestVisibility`, so neither can lift the other. One bad file
      // withholds the whole VERSION — see `AssetBundleScreeningVerdict` for
      // why refusing a single file is not a representable product here.
      asset.visibility = await this.#promoteExpandedBundle(
        id,
        strictestVisibility(screening.visibility, expanded.body.screening.visibility),
      );
      this.#record(
        context,
        caller,
        "asset.push",
        id,
        "committed",
        `asset ${id} pushed as a static_site bundle of ${expanded.body.files.length} files (${asset.size_bytes} archive bytes); ${screening.auditDetail}; ${expanded.body.screening.auditDetail}`,
      );
    } else {
      this.#record(
        context,
        caller,
        "asset.push",
        id,
        "committed",
        `asset ${id} pushed (${asset.size_bytes} bytes); ${screening.auditDetail}${skillBundleScreening.body === undefined ? "" : `; ${skillBundleScreening.body.auditDetail}`}; manifest=${JSON.stringify(screening.manifest)}`,
      );
    }

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

  /**
   * Resolve `{asset_type}/{name}/{reference}` (+ platform) to ONE stored row —
   * the step every read surface shares.
   *
   * Extracted verbatim from {@link pullAsset} for issue #737, and extracted
   * rather than copied for the reason #736 wrote into the bundle index's own
   * schema note: a second resolution path is how a yanked site stays servable.
   * `/sites/*` must probe a bundle's index (does this directory have an
   * `index.html`?) before it knows which file to serve, and the only way that
   * probe can be guaranteed to see the same version a pull would is for both to
   * enter through here. Everything a resolution decides — the withholding of
   * `pending_scan`/`quarantined` rows, channel and semver-range precedence, the
   * yank rules, variant selection, the response headers that describe them —
   * happens once, in one place.
   */
  async #resolveArtifact(
    caller: AssetCaller,
    ref: AssetName & { readonly reference: string },
    requestedPlatform: string | undefined,
  ): Promise<
    AssetResult<{ selected: StoredAsset; version: string; headers: Record<string, string> }>
  > {
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

    const headers: Record<string, string> = {
      "x-ferrogate-asset-resolved": resolutionHeaderValue(resolved.how, resolved.version),
      "x-ferrogate-asset-version": resolved.version,
    };
    if (selected.variant !== "") {
      headers["x-ferrogate-asset-variant"] = selected.variant;
    }
    if (resolved.yanked) {
      // An EXACT pull of a yanked version still succeeds — existing pins keep
      // working — but it says so, loudly and machine-readably.
      headers.warning = `299 ferrogate "asset ${ref.assetType}/${ref.name}/${resolved.version} is yanked"`;
      headers["x-ferrogate-asset-yanked"] = "true";
    }
    return { ok: true, status: 200, body: { selected, version: resolved.version, headers } };
  }

  /**
   * Which of `candidates` exists inside the bundle version `ref` resolves to —
   * the FIRST one, or `null` when none does (issue #737).
   *
   * This is what makes `/sites/*` able to decide between serving a file,
   * redirecting to a directory's canonical URL, falling back to a site's own
   * `404.html` and refusing, WITHOUT reading or billing a single byte:
   * {@link pullAsset} charges the resolved object's whole size to the egress
   * budget before it reads anything, so probing with it would bill a tenant for
   * bytes nobody was ever sent.
   *
   * It is not a second resolution path. It calls {@link #resolveArtifact} — the
   * same code `pullAsset` enters through — and then does one index lookup per
   * candidate, which is exactly the last step `#projectBundleFile` performs.
   * A withheld, quarantined or yanked-out-of-channel version is therefore
   * unresolvable here for the same reason and at the same line as it is there.
   */
  async siteFileProbe(
    caller: AssetCaller,
    ref: AssetName & { readonly reference: string },
    candidates: readonly string[],
  ): Promise<AssetResult<{ readonly version: string; readonly path: string | null }>> {
    const denied = this.#requireTenant(caller);
    if (denied) return denied;
    const resolved = await this.#resolveArtifact(caller, ref, undefined);
    if (!resolved.ok) return resolved;
    const { selected } = resolved.body;
    for (const candidate of candidates) {
      if (bundlePathRejection(candidate) !== undefined) continue;
      const file = await this.#bundles.getBundleFile(selected.id, normalizeBundlePath(candidate));
      if (file !== null) {
        return { ok: true, status: 200, body: { version: selected.version, path: candidate } };
      }
    }
    return { ok: true, status: 200, body: { version: selected.version, path: null } };
  }

  async pullAsset(
    caller: AssetCaller,
    ref: AssetName & { readonly reference: string },
    input: AssetPullInput,
    context: AssetRequestContext = { requestId: "" },
  ): Promise<AssetPullResult> {
    const denied = this.#requireTenant(caller);
    if (denied) return denied;

    const requestedPlatform =
      input.platform ?? input.headers.get("x-ferrogate-platform") ?? undefined;
    const resolution = await this.#resolveArtifact(caller, ref, requestedPlatform);
    if (!resolution.ok) return resolution;
    const { selected, version } = resolution.body;

    const extra: Record<string, string> = { ...resolution.body.headers };

    // #736: `?path=` narrows the already-resolved artifact to ONE file of an
    // expanded bundle. `served` is that file projected onto the version row, so
    // every rule below — egress charging, the integrity re-check, the ETag, the
    // conditional/Range evaluation — runs over it verbatim rather than being
    // reimplemented for bundles.
    const projected = await this.#projectBundleFile(selected, input.bundlePath);
    if (!projected.ok) return projected;
    const served = projected.body;
    const egressTarget = assetEgressAuditTarget(served, caller.tenantId);
    if (typeof egressTarget !== "string") return egressTarget;

    // #262 egress quota (finding D4): the fail-closed deny gate, BEFORE a byte
    // is read or served, charged the RESOLVED OBJECT SIZE exactly as Rust does
    // (`assets.rs:1114` passes `selected.size_bytes`, never a range slice, so a
    // caller cannot drain an exhausted budget one `Range` header at a time).
    const egressDenied = await this.#egressDenial(caller, served.size_bytes);
    if (egressDenied) return egressDenied;

    const loaded = await this.#loadAssetContent(served, caller.tenantId);
    if (!loaded.ok) return loaded;
    const content = loaded.body;

    // Re-verify integrity on EVERY read (#176/#179): a mismatch is storage
    // corruption or tampering, not a client error.
    if ((await sha256Hex(content)) !== served.content_hash) {
      return fail(
        500,
        "asset_integrity_check_failed",
        "stored asset content hash does not match recorded hash",
      );
    }

    const etag = `"${served.content_hash}"`;
    const validators: Record<string, string> = {
      ...extra,
      etag,
      "last-modified": formatHttpDate(selected.updated_at_unix),
      // PER-RESPONSE since #737. It was one hard-coded constant for every byte
      // this method has ever served, which is right for an artifact pulled by
      // identity by a credential and wrong for a static site: a fingerprinted
      // `app.4f3a9c21.js` is immutable for a year, an HTML document behind a
      // mutable channel pointer must revalidate every time, and the two cannot
      // share one value. The caller supplies the policy because the caller is
      // the one that knows which URL shape produced the request; the DEFAULT is
      // unchanged, so every existing pull answers exactly what it did before.
      "cache-control": input.cacheControl ?? DEFAULT_ASSET_CACHE_CONTROL,
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
            "content-type": served.content_type,
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
          { id: egressTarget, assetType: ref.assetType, name: ref.name, version },
          body === null ? 0 : body.byteLength,
        );
        return {
          ok: true,
          status: 206,
          bytes: body,
          headers: {
            ...validators,
            "content-type": served.content_type,
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
          { id: egressTarget, assetType: ref.assetType, name: ref.name, version },
          body === null ? 0 : body.byteLength,
        );
        return {
          ok: true,
          status: 200,
          bytes: body,
          headers: {
            ...validators,
            "content-type": served.content_type,
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
    // #736: a bundle version owns per-file objects too. They are reclaimed
    // after the row delete committed, for the same reason the archive is: an
    // orphaned object is GC-able, bytes deleted under a live row are not.
    await this.#reclaimBundleObjects(caller.tenantId, id);
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
    const bundle = isBundlePush(ref.assetType, contentType);
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
    if (head.size > this.#limits.inlineMaxBytes) {
      return this.#commitStreamedUpload(caller, ref, request, context, {
        id,
        objectRef,
        stagingKey,
        staged,
        sha256,
        contentType,
        bundle,
      });
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
      requestId: context.requestId,
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

    // #740: keep the presigned commit path in parity with the inline path for
    // skill archives. The bytes are verified already, so the same expanded
    // text members can be screened before the final object is copied.
    const skillBundleScreening = await this.#screenSkillBundleFiles(
      caller,
      ref.assetType,
      id,
      bytes,
      contentType,
      context,
    );
    if (!skillBundleScreening.ok) {
      await this.#bestEffortDelete(stagingKey, caller.tenantId);
      return this.#rejectedCommit(
        context,
        caller,
        id,
        request.upload_id,
        skillBundleScreening.code,
        skillBundleScreening.message,
      );
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
      ...(request.metadata === undefined ? {} : { metadata: request.metadata }),
      size_bytes: bytes.byteLength,
      storage_uri: finalKey,
      variant: "",
      yanked: false,
      // #736: identical to the inline path — a bundle is admitted invisible and
      // only promoted once every file is expanded. The presigned path is
      // exactly how a tenant would smuggle an unexpanded archive past an
      // inline-only bundle gate, so it runs the same lifecycle.
      visibility: bundle
        ? "pending_scan"
        : strictestVisibility(
            screening.visibility,
            skillBundleScreening.body?.visibility ?? "visible",
          ),
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

    // #736: expand AFTER the reservation row exists and BEFORE anything can
    // resolve it — the same order as the inline path, through the same helpers.
    let bundleScreening = "";
    if (bundle) {
      const expanded = await this.#expandBundleIntoStore(
        caller,
        objectRef,
        id,
        bytes,
        contentType,
        context,
      );
      if (!expanded.ok) {
        await this.#unwindBundlePublish(caller, ref, id, finalKey);
        await this.#bestEffortDelete(stagingKey, caller.tenantId);
        this.#record(
          context,
          caller,
          "asset.push",
          id,
          "rejected_commit",
          `asset ${id} upload ${request.upload_id} static_site bundle rejected (${expanded.code}): ${expanded.message}`,
        );
        return expanded;
      }
      // #740, exactly as the inline path: the strictest of the two verdicts,
      // applied through the ONE CAS that may move a bundle to `visible`.
      asset.visibility = await this.#promoteExpandedBundle(
        id,
        strictestVisibility(screening.visibility, expanded.body.screening.visibility),
      );
      bundleScreening = `; ${expanded.body.screening.auditDetail}`;
    }

    this.#record(
      context,
      caller,
      "asset.push",
      id,
      "committed",
      `asset ${id} committed via presigned upload ${request.upload_id} (${asset.size_bytes} bytes); ${screening.auditDetail}${skillBundleScreening.body === undefined ? "" : `; ${skillBundleScreening.body.auditDetail}`}${bundleScreening}; manifest=${JSON.stringify(screening.manifest)}`,
    );
    await this.#bestEffortDelete(stagingKey, caller.tenantId);
    return {
      ok: true,
      status: assetMutationStatus(asset.visibility),
      body: { object: "asset", asset: assetSummary(asset) },
    };
  }

  /**
   * Commit an object above the inline budget without materializing it.
   *
   * The transform is deliberately the source for both verification and the
   * final PUT: a staged body is one-shot in R2, so a second read would either
   * buffer the object or silently verify different bytes than were copied.
   */
  async #commitStreamedUpload(
    caller: AssetCaller,
    ref: AssetVersionRef,
    request: PresignCommitRequest,
    context: AssetRequestContext,
    input: {
      readonly id: string;
      readonly objectRef: AssetObjectRef;
      readonly stagingKey: string;
      readonly staged: AssetObjectBody;
      readonly sha256: string;
      readonly contentType: string;
      readonly bundle: boolean;
    },
  ): Promise<AssetResult<unknown>> {
    const finalKey = newCommitObjectKey(input.objectRef, request.upload_id);
    const finalGuard = this.#guardKey(finalKey, caller.tenantId);
    if (finalGuard) {
      await this.#bestEffortDelete(input.stagingKey, caller.tenantId);
      return finalGuard;
    }

    const observed = trackedAssetBody(input.staged.body);
    try {
      // The transform hashes and scans the exact bytes this PUT consumes. The
      // object store therefore never receives an unverified buffered copy.
      await this.#objects.put(finalKey, observed.stream, {
        httpMetadata: { contentType: input.contentType },
      });
    } catch (error) {
      await this.#bestEffortDelete(finalKey, caller.tenantId);
      await this.#bestEffortDelete(input.stagingKey, caller.tenantId);
      return fail(
        503,
        "storage_unavailable",
        `the streamed asset commit could not copy the staged object: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    const result = observed.result();
    if (
      result.sizeBytes !== input.staged.size ||
      result.sizeBytes !== request.size_bytes ||
      result.sha256 !== input.sha256
    ) {
      await this.#bestEffortDelete(finalKey, caller.tenantId);
      await this.#bestEffortDelete(input.stagingKey, caller.tenantId);
      return this.#rejectedCommit(
        context,
        caller,
        input.id,
        request.upload_id,
        "asset_commit_hash_mismatch",
        "committed object sha256/size does not match the registered intent",
      );
    }

    const contentRejected = streamedAssetContentRejection(
      ref.assetType,
      input.contentType,
      result.eicarFound,
    );
    if (contentRejected !== undefined) {
      await this.#bestEffortDelete(finalKey, caller.tenantId);
      await this.#bestEffortDelete(input.stagingKey, caller.tenantId);
      return this.#rejectedCommit(
        context,
        caller,
        input.id,
        request.upload_id,
        ASSET_REJECTED_CODE,
        contentRejected,
      );
    }

    // Bundle expansion needs the complete archive. Keeping this refusal here
    // makes the large presigned path fail closed instead of publishing an
    // archive whose projected files were never screened or indexed.
    if (input.bundle || ref.assetType === "skill_bundle") {
      const message =
        "bundle assets above the gateway's streaming commit budget must use a buffered commit";
      await this.#bestEffortDelete(finalKey, caller.tenantId);
      await this.#bestEffortDelete(input.stagingKey, caller.tenantId);
      return this.#rejectedCommit(
        context,
        caller,
        input.id,
        request.upload_id,
        ASSET_REJECTED_CODE,
        message,
      );
    }

    const now = this.#now();
    const screeningRequest: AssetStreamScreeningRequest = {
      assetId: input.id,
      tenantId: caller.tenantId,
      assetType: ref.assetType,
      contentType: input.contentType,
      contentSha256: result.sha256,
      sizeBytes: result.sizeBytes,
      nowUnix: now,
      requestId: context.requestId,
      signaturePresented:
        request.signature !== undefined ||
        request.signature_format !== undefined ||
        request.signature_key_id !== undefined,
    };
    const screening =
      this.#screener.streamedScreen === undefined
        ? streamedPendingScreening(screeningRequest)
        : await this.#screener.streamedScreen(screeningRequest);
    if (isScreeningRejection(screening)) {
      await this.#bestEffortDelete(finalKey, caller.tenantId);
      await this.#bestEffortDelete(input.stagingKey, caller.tenantId);
      return this.#rejectedCommit(
        context,
        caller,
        input.id,
        request.upload_id,
        screening.code,
        screening.message,
      );
    }

    const asset: StoredAsset = {
      id: input.id,
      tenant_id: caller.tenantId,
      project_id: caller.projectId,
      asset_type: ref.assetType,
      name: ref.name,
      version: ref.version,
      content_type: input.contentType,
      content_hash: result.sha256,
      ...(request.metadata === undefined ? {} : { metadata: request.metadata }),
      size_bytes: result.sizeBytes,
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
      await this.#bestEffortDelete(finalKey, caller.tenantId);
      await this.#bestEffortDelete(input.stagingKey, caller.tenantId);
      this.#record(
        context,
        caller,
        "asset.push",
        input.id,
        "rejected_commit",
        `asset ${input.id} upload ${request.upload_id} rejected at commit: ${asset.size_bytes} bytes would exceed the tenant's ${admission.quota_bytes}-byte asset storage quota`,
      );
      return fail(
        422,
        "asset_storage_quota_exceeded",
        `committing this asset would exceed the tenant's ${admission.quota_bytes}-byte asset storage quota`,
      );
    }
    if (admission.kind === "already_exists") {
      await this.#bestEffortDelete(input.stagingKey, caller.tenantId);
      const winner = await this.#metadata.getAsset(input.id);
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
          input.objectRef,
          request.upload_id,
          request.size_bytes,
          input.sha256,
          input.contentType,
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
      input.id,
      "committed",
      `asset ${input.id} committed via streamed presigned upload ${request.upload_id} (${asset.size_bytes} bytes); ${screening.auditDetail}; manifest=${JSON.stringify(screening.manifest)}`,
    );
    await this.#bestEffortDelete(input.stagingKey, caller.tenantId);
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
    const egressTarget = assetEgressAuditTarget(asset, caller.tenantId);
    if (typeof egressTarget !== "string") return egressTarget;

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
      {
        id: egressTarget,
        assetType: ref.assetType,
        name: ref.name,
        version: ref.version,
      },
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

  // -------------------------------------------------------------------------
  // static_site bundles (#736)
  // -------------------------------------------------------------------------

  /**
   * Expand an archive into per-file R2 objects plus the D1 file index.
   *
   * Runs only while the version row is `pending_scan`, i.e. while nothing can
   * resolve it. Every file lands under the version's OWN key prefix, so the
   * one cross-tenant guard the rest of the service uses covers these keys
   * unchanged, and it is re-asserted per file rather than once for the batch.
   *
   * The decompressed ceiling is tightened to the tenant's storage quota when it
   * has one: expansion multiplies bytes, and a tenant should not be able to
   * turn a 10 MiB inline push into more storage than its whole quota. The
   * fixed {@link BUNDLE_MAX_TOTAL_BYTES} still binds independently — this only
   * ever lowers it.
   *
   * #740: the expanded FILES are also where guardrail screening happens, and
   * this is the only place they exist as text — the archive is a gzip stream
   * and the rows below carry only hashes. Screening the container instead
   * would repeat the mistake #736 already corrected for content types:
   * screening the archive is not screening its contents. The verdict is
   * returned rather than applied, because the ONE place a bundle may become
   * `visible` is {@link #promoteExpandedBundle}'s CAS.
   */
  async #expandBundleIntoStore(
    caller: AssetCaller,
    objectRef: AssetObjectRef,
    assetId: string,
    archive: Uint8Array,
    archiveContentType: string,
    context: AssetRequestContext,
  ): Promise<
    AssetResult<{
      readonly files: readonly StoredBundleFile[];
      readonly screening: AssetBundleScreeningVerdict;
    }>
  > {
    const expansion = await expandBundle(archive, {
      maxTotalBytes: caller.assetStorageQuotaBytes,
    });
    if (!expansion.ok) {
      // The SAME `422 asset_rejected` taxonomy the content gate uses. A file
      // the allowlist refuses is not a different kind of refusal just because
      // it arrived inside an archive — the archive's own content type
      // (`${archiveContentType}`) was allowed and proves nothing about it.
      return fail(
        ASSET_REJECTED_STATUS,
        ASSET_REJECTED_CODE,
        `${expansion.message} (pushed as ${archiveContentType})`,
      );
    }

    // #740: over the expanded files, BEFORE anything is written — a screener
    // that refuses must not have cost the bucket 2 000 puts first. A screener
    // with no `screenBundleFiles` has no opinion about files, which is the
    // honest answer for the archive-shaped screeners that predate bundles, so
    // the absence is recorded rather than defaulted to a pass.
    const screening: AssetBundleScreeningVerdict = (await this.#screener.screenBundleFiles?.({
      assetId,
      tenantId: caller.tenantId,
      assetType: objectRef.assetType,
      nowUnix: this.#now(),
      requestId: context.requestId,
      files: expansion.files,
    })) ?? { visibility: "visible", auditDetail: "guardrail=not_screened(no_file_screener)" };

    const now = this.#now();
    const written: string[] = [];
    const rows: StoredBundleFile[] = [];
    try {
      for (const file of expansion.files) {
        const key = bundleFileObjectKey(objectRef, file.path);
        // Fail-closed, per file: a path that somehow produced a key outside the
        // tenant prefix throws here rather than being written.
        assertKeyBelongsToTenant(key, caller.tenantId);
        await this.#objects.put(key, bufferOf(file.content), {
          httpMetadata: { contentType: file.contentType },
        });
        written.push(key);
        rows.push({
          asset_id: assetId,
          tenant_id: caller.tenantId,
          path: file.path,
          storage_uri: key,
          content_type: file.contentType,
          content_hash: file.sha256,
          size_bytes: file.content.byteLength,
          created_at_unix: now,
        });
      }
      // The index is written as ONE call after every object has landed, so a
      // reader can never see an index row whose bytes are not there yet.
      await this.#bundles.putBundleFiles(rows);
    } catch (error) {
      // A mid-expansion bucket failure. Reclaim what THIS attempt wrote — it is
      // provably unreferenced, because the version is still `pending_scan` and
      // the index write either never ran or is being undone right here.
      for (const key of written) await this.#bestEffortDelete(key, caller.tenantId);
      await this.#bundles.deleteBundleFiles(assetId);
      return fail(
        503,
        "storage_unavailable",
        `the static_site bundle could not be expanded into the object bucket: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    return { ok: true, status: 200, body: { files: rows, screening } };
  }

  /**
   * Project one bundle file onto the version row that resolution already
   * chose, or return the row unchanged when no `?path=` was asked for.
   *
   * The returned value is a {@link StoredAsset} on purpose: everything
   * downstream in `pullAsset` — egress charging, the object load, the integrity
   * re-check, the ETag, `evaluateConditionalRequest` — then operates on one
   * shape, and a bundle file cannot accidentally skip a rule that a
   * single-object asset gets. `updated_at_unix` and `variant` stay the
   * VERSION's, because a bundle's files are published atomically and share the
   * version's mutation time.
   */
  async #projectBundleFile(
    selected: StoredAsset,
    bundlePath: string | undefined,
  ): Promise<AssetResult<StoredAsset>> {
    if (bundlePath === undefined) return { ok: true, status: 200, body: selected };
    // The same grammar the expander enforced on write. A `..` on the READ side
    // can never reach a key (the index is a lookup, not path arithmetic), but
    // answering 400 rather than 404 keeps the two sides telling one story.
    const rejection = bundlePathRejection(bundlePath);
    if (rejection !== undefined) {
      return fail(400, "asset_bundle_path_invalid", `?path= is not a bundle path: ${rejection}`);
    }
    const file = await this.#bundles.getBundleFile(selected.id, normalizeBundlePath(bundlePath));
    if (file === null) {
      return fail(
        404,
        "asset_bundle_file_not_found",
        `${selected.asset_type}/${selected.name}/${selected.version} has no bundle file at ${normalizeBundlePath(bundlePath)}`,
      );
    }
    return {
      ok: true,
      status: 200,
      body: {
        ...selected,
        storage_uri: file.storage_uri,
        size_bytes: file.size_bytes,
        content_type: file.content_type,
        content_hash: file.content_hash,
      },
    };
  }

  /**
   * Apply the screener's verdict to a fully-expanded bundle through the
   * EXISTING `pending_scan` CAS (#378) — the same one the async-scan promotion
   * endpoint drives. Nothing else may move a bundle to `visible`.
   */
  async #promoteExpandedBundle(assetId: string, target: AssetVisibility): Promise<AssetVisibility> {
    // A screener that deferred wants the row withheld; leaving it `pending_scan`
    // is the verdict, not a missing step.
    if (target === "pending_scan") return "pending_scan";
    const outcome = await this.#metadata.promotePendingAssetVisibility(
      assetId,
      target,
      this.#now(),
    );
    if (outcome.kind === "promoted") return outcome.to;
    // Someone else moved the row between the create and here (a concurrent
    // promote/quarantine). Report what the store says, never what we wanted.
    if (outcome.kind === "not_pending") return outcome.current;
    return "pending_scan";
  }

  /**
   * Undo a bundle publish that failed after its row was created: drop the index
   * and its objects, the archive object, and the reservation row itself.
   *
   * The row goes LAST, mirroring `deleteAsset`'s ordering rationale in reverse:
   * here the row is invisible for its whole life, so the only durable harm a
   * crash mid-unwind can do is an orphaned object, which GC can reclaim.
   */
  async #unwindBundlePublish(
    caller: AssetCaller,
    ref: AssetVersionRef,
    assetId: string,
    archiveKey: string,
  ): Promise<void> {
    await this.#reclaimBundleObjects(caller.tenantId, assetId);
    await this.#bestEffortDelete(archiveKey, caller.tenantId);
    await this.#metadata.deleteAssetVariantIfUnreferenced(
      assetId,
      caller.tenantId,
      ref.assetType,
      ref.name,
      ref.version,
    );
  }

  /** Drop a bundle's index rows and the objects they point at. */
  async #reclaimBundleObjects(tenantId: string, assetId: string): Promise<void> {
    const removed = await this.#bundles.deleteBundleFiles(assetId);
    for (const file of removed) {
      await this.#bestEffortDelete(file.storage_uri, tenantId);
    }
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

class FileUploadTooLargeError extends Error {
  constructor() {
    super("file upload exceeds the configured inline or object-size limit");
    this.name = "FileUploadTooLargeError";
  }
}

class FileUploadReadError extends Error {
  constructor() {
    super("the uploaded file stream could not be read");
    this.name = "FileUploadReadError";
  }
}

interface StreamedAssetObservation {
  readonly sizeBytes: number;
  readonly sha256: string;
  readonly eicarFound: boolean;
}

const STREAMED_EICAR_BYTES = new TextEncoder().encode(EICAR_SIGNATURE);

function trackedAssetBody(body: ReadableStream<Uint8Array>): {
  readonly stream: ReadableStream<Uint8Array>;
  readonly result: () => StreamedAssetObservation;
} {
  const digest = new StreamingSha256();
  let sizeBytes = 0;
  let eicarFound = false;
  let carry = new Uint8Array(0);
  const stream = body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        sizeBytes += chunk.byteLength;
        digest.update(chunk);
        if (!eicarFound) {
          const searchable = new Uint8Array(carry.byteLength + chunk.byteLength);
          searchable.set(carry);
          searchable.set(chunk, carry.byteLength);
          eicarFound = containsBytes(searchable, STREAMED_EICAR_BYTES);
          if (!eicarFound) {
            const carryLength = Math.min(
              STREAMED_EICAR_BYTES.byteLength - 1,
              searchable.byteLength,
            );
            carry = searchable.slice(searchable.byteLength - carryLength);
          }
        }
        controller.enqueue(chunk);
      },
    }),
  );
  return {
    stream,
    result: () => ({
      sizeBytes,
      sha256: toHex(digest.digest()),
      eicarFound,
    }),
  };
}

function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.byteLength === 0) return true;
  if (haystack.byteLength < needle.byteLength) return false;
  for (let offset = 0; offset <= haystack.byteLength - needle.byteLength; offset += 1) {
    let matches = true;
    for (let index = 0; index < needle.byteLength; index += 1) {
      if (haystack[offset + index] !== needle[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}

function streamedPendingScreening(request: AssetStreamScreeningRequest): AssetScreeningVerdict {
  return {
    visibility: "pending_scan",
    auditDetail:
      "scan=pending_scan backend=buffer-required reason=screening_requires_buffering signature=absent approval=not_required",
    manifest: {
      scanner: "buffer-required",
      outcome: "pending_scan",
      reason: "screening_requires_buffering",
      sha256: request.contentSha256,
      size_bytes: request.sizeBytes,
      screened_at_unix: request.nowUnix,
    },
  };
}

function uploadChunk(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new FileUploadReadError();
}

async function readUploadBytes(
  stream: ReadableStream<Uint8Array>,
  maxBytes: number,
): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      const chunk = uploadChunk(next.value);
      total += chunk.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new FileUploadTooLargeError();
      }
      chunks.push(chunk);
    }
  } catch (error) {
    if (error instanceof FileUploadTooLargeError || error instanceof FileUploadReadError) {
      throw error;
    }
    throw new FileUploadReadError();
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function measureUpload(
  stream: ReadableStream<Uint8Array>,
  maxBytes: number,
): Promise<{ size_bytes: number; sha256: string }> {
  const reader = stream.getReader();
  const digest = new StreamingSha256();
  let total = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      const chunk = uploadChunk(next.value);
      total += chunk.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new FileUploadTooLargeError();
      }
      digest.update(chunk);
    }
  } catch (error) {
    if (error instanceof FileUploadTooLargeError || error instanceof FileUploadReadError) {
      throw error;
    }
    throw new FileUploadReadError();
  } finally {
    reader.releaseLock();
  }
  return { size_bytes: total, sha256: toHex(digest.digest()) };
}

function fileUploadReadFailure(error: unknown, maxBytes: number): AssetFailure {
  if (error instanceof FileUploadTooLargeError) {
    return fail(
      413,
      "payload_too_large",
      `file size exceeds the configured ${maxBytes}-byte upload ceiling`,
    );
  }
  return fail(400, "invalid_request", "could not read the uploaded file");
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
