/**
 * Narrow local interfaces (dependency inversion) for the asset surface, plus
 * in-memory defaults.
 *
 * The wave-2 library packages (`@ferrogate/storage`, `@ferrogate/policy`,
 * `@ferrogate/guardrails`, `@ferrogate/billing`, `@ferrogate/observability`)
 * are still stubs being written concurrently, so this app declares exactly the
 * slice of behavior it needs and codes against that. When those packages land,
 * an adapter satisfies these interfaces — no call site in `service.ts` moves.
 *
 * The object-store port is deliberately **R2-shaped**: a real `R2Bucket`
 * binding satisfies {@link AssetObjectStore} structurally, so
 * `new AssetService({ objects: env.ASSETS, ... })` is the production wiring and
 * {@link InMemoryAssetObjectStore} is the offline one.
 */
import type { AssetObjectRef } from "./keys.js";
import { storedAssetVariantId } from "./keys.js";

// ---------------------------------------------------------------------------
// Object storage (R2)
// ---------------------------------------------------------------------------

/** The subset of `R2Object` metadata the asset service reads. */
export interface AssetObjectMetadata {
  readonly key: string;
  readonly size: number;
  readonly httpMetadata?: { contentType?: string } | undefined;
}

/** The subset of `R2ObjectBody` the asset service reads. */
export interface AssetObjectBody extends AssetObjectMetadata {
  arrayBuffer(): Promise<ArrayBuffer>;
}

/** Options accepted on write; a strict subset of `R2PutOptions`. */
export interface AssetObjectPutOptions {
  httpMetadata?: { contentType?: string };
  customMetadata?: Record<string, string>;
}

/**
 * R2-shaped object store. A live `R2Bucket` is assignable to this type.
 *
 * PORT-TODO(inventory-request-path.md §1.6 "Object storage"): NOT a platform
 * limit and NOT unfinished work — a deliberate product decision, recorded here
 * so it is not "fixed" by someone reading the Rust. `asset_bucket.rs` also
 * exposed multipart create/upload-part/complete, and R2's Workers API does have
 * `createMultipartUpload`. The presigned surface FerroGate publishes is
 * single-PUT on purpose (`upload_protocol: "single_put"`): S3 signs each part
 * separately, so one presigned authorization cannot bind the WHOLE object's
 * size and checksum, and that binding is the entire invariant the presign
 * endpoint exists to enforce (issue #368). Multipart stays out of this port
 * until the contract grows an additive `upload_protocol` value that says which
 * guarantee the client is getting.
 */
export interface AssetObjectStore {
  put(
    key: string,
    value: ArrayBuffer | ArrayBufferView | string | null,
    options?: AssetObjectPutOptions,
  ): Promise<AssetObjectMetadata | null>;
  get(key: string): Promise<AssetObjectBody | null>;
  head(key: string): Promise<AssetObjectMetadata | null>;
  delete(key: string | string[]): Promise<void>;
}

/** Offline {@link AssetObjectStore} used by tests and local dev. */
export class InMemoryAssetObjectStore implements AssetObjectStore {
  readonly objects = new Map<string, { bytes: Uint8Array; contentType: string | undefined }>();

  async put(
    key: string,
    value: ArrayBuffer | ArrayBufferView | string | null,
    options?: AssetObjectPutOptions,
  ): Promise<AssetObjectMetadata | null> {
    if (value === null) {
      this.objects.delete(key);
      return null;
    }
    let bytes: Uint8Array;
    if (typeof value === "string") {
      bytes = new TextEncoder().encode(value);
    } else if (value instanceof ArrayBuffer) {
      bytes = new Uint8Array(value.slice(0));
    } else {
      bytes = new Uint8Array(
        value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength),
      );
    }
    this.objects.set(key, {
      bytes,
      contentType: options?.httpMetadata?.contentType,
    });
    return { key, size: bytes.byteLength };
  }

  async get(key: string): Promise<AssetObjectBody | null> {
    const object = this.objects.get(key);
    if (!object) return null;
    const bytes = object.bytes;
    return {
      key,
      size: bytes.byteLength,
      httpMetadata: { contentType: object.contentType },
      arrayBuffer: async () =>
        bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
    };
  }

  async head(key: string): Promise<AssetObjectMetadata | null> {
    const object = this.objects.get(key);
    if (!object) return null;
    return {
      key,
      size: object.bytes.byteLength,
      httpMetadata: { contentType: object.contentType },
    };
  }

  async delete(key: string | string[]): Promise<void> {
    for (const one of Array.isArray(key) ? key : [key]) {
      this.objects.delete(one);
    }
  }
}

// ---------------------------------------------------------------------------
// Asset metadata (control-plane rows)
// ---------------------------------------------------------------------------

/** Trust-screening state — Rust `AssetVisibility` (issue #366). */
export type AssetVisibility = "visible" | "pending_scan" | "quarantined";

/** Only a `visible` row is resolvable and downloadable. */
export function isDownloadable(visibility: AssetVisibility): boolean {
  return visibility === "visible";
}

/** One durable asset row — Rust `StoredAsset`. */
export interface StoredAsset {
  id: string;
  tenant_id: string;
  project_id?: string | undefined;
  asset_type: string;
  name: string;
  version: string;
  content_type: string;
  content_hash: string;
  size_bytes: number;
  /** Object-store key holding the bytes. Always tenant-prefixed. */
  storage_uri: string;
  /** Platform/arch variant; `""` is the default artifact. */
  variant: string;
  yanked: boolean;
  visibility: AssetVisibility;
  created_at_unix: number;
  updated_at_unix: number;
}

/** One mutable channel pointer — Rust `StoredAssetChannel`. */
export interface StoredAssetChannel {
  id: string;
  tenant_id: string;
  asset_type: string;
  name: string;
  channel: string;
  version: string;
  updated_at_unix: number;
}

/** Rust `AssetQuotaAdmission` — the definitive outcome of an atomic create. */
export type AssetQuotaAdmission =
  | { kind: "admitted" }
  | { kind: "already_exists" }
  | {
      kind: "over_quota";
      used_bytes: number;
      attempted_bytes: number;
      quota_bytes: number;
    };

/** Rust `ChannelMoveOutcome`. */
export type ChannelMoveOutcome =
  | { kind: "moved"; prior_version: string | undefined }
  | { kind: "target_not_resolvable" };

/** Rust `VersionYankOutcome`. */
export type VersionYankOutcome =
  | { kind: "applied"; variants: number }
  | { kind: "not_found" }
  | { kind: "referenced_by_channel" };

/** Rust `VariantDeleteOutcome`. */
export type VariantDeleteOutcome =
  | { kind: "deleted" }
  | { kind: "not_found" }
  | { kind: "blocked_by_channel" };

/** Rust `AssetVisibilityPromotionOutcome`. */
export type AssetVisibilityPromotionOutcome =
  | { kind: "promoted"; to: AssetVisibility }
  | { kind: "not_found" }
  | { kind: "not_pending"; current: AssetVisibility };

/**
 * The control-plane slice the asset service needs.
 *
 * Every mutation that carries a lifecycle invariant is ONE method, because the
 * invariant must hold under a single serialization point (Rust issue #367):
 * a channel may never point at a yanked/absent version, a yank may not strand a
 * channel, and a quota admission may not be a read-then-write pair. Splitting
 * any of these into a read + a write on this interface would reintroduce the
 * exact race the Rust tree closed.
 */
export interface AssetMetadataStore {
  getAsset(id: string): Promise<StoredAsset | null>;
  listAssets(tenantId: string, assetType?: string): Promise<StoredAsset[]>;
  /** Non-`visible` rows only — Rust `list_withheld_assets` (issue #379). */
  listWithheldAssets(tenantId: string, assetType?: string): Promise<StoredAsset[]>;
  tenantAssetStorageBytesUsed(tenantId: string): Promise<number>;
  /** Atomic create-if-absent folded with the tenant quota guard (issue #371). */
  createAssetWithinQuota(
    asset: StoredAsset,
    quotaBytes: number | undefined,
  ): Promise<AssetQuotaAdmission>;
  /** Delete one variant row unless it would strand a live channel (#367). */
  deleteAssetVariantIfUnreferenced(
    id: string,
    tenantId: string,
    assetType: string,
    name: string,
    version: string,
  ): Promise<VariantDeleteOutcome>;
  /** Yank/unyank every variant row of one logical version (#367). */
  setAssetVersionYank(
    tenantId: string,
    assetType: string,
    name: string,
    version: string,
    yanked: boolean,
    nowUnix: number,
  ): Promise<VersionYankOutcome>;
  /** Fail-closed `pending_scan -> visible|quarantined` CAS (#378). */
  promotePendingAssetVisibility(
    id: string,
    to: Exclude<AssetVisibility, "pending_scan">,
    nowUnix: number,
  ): Promise<AssetVisibilityPromotionOutcome>;
  listAssetChannels(
    tenantId: string,
    assetType: string,
    name: string,
  ): Promise<StoredAssetChannel[]>;
  /** Atomic move: durable only if the target resolves at write time (#367). */
  moveAssetChannel(
    tenantId: string,
    assetType: string,
    name: string,
    channel: string,
    version: string,
    nowUnix: number,
  ): Promise<ChannelMoveOutcome>;
  deleteAssetChannel(id: string): Promise<boolean>;
}

/**
 * In-memory {@link AssetMetadataStore}. JS is single-threaded per isolate, so
 * each method below runs to completion without interleaving — which is exactly
 * the "single serialization point" the Rust backends bought with `FOR UPDATE`
 * / a control-plane lock.
 */
export class InMemoryAssetMetadataStore implements AssetMetadataStore {
  readonly assets = new Map<string, StoredAsset>();
  readonly channels = new Map<string, StoredAssetChannel>();

  async getAsset(id: string): Promise<StoredAsset | null> {
    const asset = this.assets.get(id);
    return asset ? { ...asset } : null;
  }

  async listAssets(tenantId: string, assetType?: string): Promise<StoredAsset[]> {
    return [...this.assets.values()]
      .filter(
        (asset) =>
          asset.tenant_id === tenantId &&
          (assetType === undefined || asset.asset_type === assetType),
      )
      .map((asset) => ({ ...asset }));
  }

  async listWithheldAssets(tenantId: string, assetType?: string): Promise<StoredAsset[]> {
    const assets = await this.listAssets(tenantId, assetType);
    return assets.filter((asset) => !isDownloadable(asset.visibility));
  }

  /**
   * Synchronous byte count. Kept separate from the `async` accessor because
   * {@link createAssetWithinQuota} MUST NOT `await` between its read and its
   * write — see the note there.
   */
  #bytesUsed(tenantId: string): number {
    let used = 0;
    for (const asset of this.assets.values()) {
      if (asset.tenant_id === tenantId) used += asset.size_bytes;
    }
    return used;
  }

  async tenantAssetStorageBytesUsed(tenantId: string): Promise<number> {
    return this.#bytesUsed(tenantId);
  }

  /**
   * Create-if-absent folded with the quota guard.
   *
   * Every statement below runs in ONE synchronous turn: there is deliberately
   * no `await` between the `has` check, the quota arithmetic, and the `set`.
   * An `await` there — even on a method of this same class — yields the isolate
   * and lets a concurrent push observe the same absent id and the same
   * remaining capacity, so both would be admitted and jointly overshoot. That
   * is precisely the read-then-write gap Rust issues #369/#371 closed with a
   * single conditional statement, and the reason this method exists at all
   * rather than being a `getAsset` + `put` pair on the caller's side.
   */
  async createAssetWithinQuota(
    asset: StoredAsset,
    quotaBytes: number | undefined,
  ): Promise<AssetQuotaAdmission> {
    if (this.assets.has(asset.id)) return { kind: "already_exists" };
    const used = this.#bytesUsed(asset.tenant_id);
    if (quotaBytes !== undefined && used + asset.size_bytes > quotaBytes) {
      return {
        kind: "over_quota",
        used_bytes: used,
        attempted_bytes: asset.size_bytes,
        quota_bytes: quotaBytes,
      };
    }
    this.assets.set(asset.id, { ...asset });
    return { kind: "admitted" };
  }

  /** Variant rows of one logical version. */
  private versionRows(
    tenantId: string,
    assetType: string,
    name: string,
    version: string,
  ): StoredAsset[] {
    return [...this.assets.values()].filter(
      (asset) =>
        asset.tenant_id === tenantId &&
        asset.asset_type === assetType &&
        asset.name === name &&
        asset.version === version,
    );
  }

  private channelReferences(
    tenantId: string,
    assetType: string,
    name: string,
    version: string,
  ): boolean {
    return [...this.channels.values()].some(
      (channel) =>
        channel.tenant_id === tenantId &&
        channel.asset_type === assetType &&
        channel.name === name &&
        channel.version === version,
    );
  }

  async deleteAssetVariantIfUnreferenced(
    id: string,
    tenantId: string,
    assetType: string,
    name: string,
    version: string,
  ): Promise<VariantDeleteOutcome> {
    if (!this.assets.has(id)) return { kind: "not_found" };
    const rows = this.versionRows(tenantId, assetType, name, version);
    const remaining = rows.filter((row) => row.id !== id && !row.yanked);
    if (remaining.length === 0 && this.channelReferences(tenantId, assetType, name, version)) {
      return { kind: "blocked_by_channel" };
    }
    this.assets.delete(id);
    return { kind: "deleted" };
  }

  async setAssetVersionYank(
    tenantId: string,
    assetType: string,
    name: string,
    version: string,
    yanked: boolean,
    nowUnix: number,
  ): Promise<VersionYankOutcome> {
    const rows = this.versionRows(tenantId, assetType, name, version);
    if (rows.length === 0) return { kind: "not_found" };
    // Yank is fail-closed while a channel still points here; unyank only ever
    // restores resolvability, so it can never strand a channel.
    if (yanked && this.channelReferences(tenantId, assetType, name, version)) {
      return { kind: "referenced_by_channel" };
    }
    for (const row of rows) {
      this.assets.set(row.id, {
        ...row,
        yanked,
        updated_at_unix: nowUnix,
      });
    }
    return { kind: "applied", variants: rows.length };
  }

  async promotePendingAssetVisibility(
    id: string,
    to: Exclude<AssetVisibility, "pending_scan">,
    nowUnix: number,
  ): Promise<AssetVisibilityPromotionOutcome> {
    const asset = this.assets.get(id);
    if (!asset) return { kind: "not_found" };
    if (asset.visibility !== "pending_scan") {
      return { kind: "not_pending", current: asset.visibility };
    }
    this.assets.set(id, {
      ...asset,
      visibility: to,
      updated_at_unix: nowUnix,
    });
    return { kind: "promoted", to };
  }

  async listAssetChannels(
    tenantId: string,
    assetType: string,
    name: string,
  ): Promise<StoredAssetChannel[]> {
    return [...this.channels.values()]
      .filter(
        (channel) =>
          channel.tenant_id === tenantId &&
          channel.asset_type === assetType &&
          channel.name === name,
      )
      .map((channel) => ({ ...channel }));
  }

  async moveAssetChannel(
    tenantId: string,
    assetType: string,
    name: string,
    channel: string,
    version: string,
    nowUnix: number,
  ): Promise<ChannelMoveOutcome> {
    const rows = this.versionRows(tenantId, assetType, name, version);
    // Resolvable = at least one variant row, none yanked, and downloadable.
    // The Rust oracle (`channel_target_is_resolvable`) checked presence + not
    // yanked; the downloadable clause is a deliberate fail-closed tightening so
    // a channel can never be moved onto a `pending_scan`/`quarantined` version
    // that every read surface withholds (issue #366) — that would publish a
    // pointer to something nothing will serve.
    const resolvable =
      rows.length > 0 &&
      rows.every((row) => !row.yanked) &&
      rows.some((row) => isDownloadable(row.visibility));
    if (!resolvable) return { kind: "target_not_resolvable" };
    const id = `${tenantId}:${assetType}:${name}:${channel}`;
    const prior = this.channels.get(id);
    this.channels.set(id, {
      id,
      tenant_id: tenantId,
      asset_type: assetType,
      name,
      channel,
      version,
      updated_at_unix: nowUnix,
    });
    return { kind: "moved", prior_version: prior?.version };
  }

  async deleteAssetChannel(id: string): Promise<boolean> {
    return this.channels.delete(id);
  }
}

// ---------------------------------------------------------------------------
// Presigning
// ---------------------------------------------------------------------------

/** A bound presigned upload — Rust `PresignedUpload` (issue #368). */
export interface PresignedUpload {
  readonly url: string;
  /** Headers the client MUST send verbatim; they are signed. */
  readonly requiredHeaders: Record<string, string>;
}

/**
 * Issues short-TTL presigned URLs for the direct client↔bucket transfer.
 *
 * PORT-TODO(inventory-request-path.md §1.6): PLATFORM LIMIT, and the reason
 * this port exists separately from {@link AssetObjectStore} at all. The Workers
 * `R2Bucket` binding has NO presign method and no way to derive one: R2
 * presigned URLs are an **S3-API** feature, signed with SigV4 over
 * `https://<account_id>.r2.cloudflarestorage.com`, and that needs an S3 access
 * key pair the bucket binding does not carry. So one bucket needs TWO
 * credentials on this platform where the Rust needed one.
 *
 * What is implemented: `sigv4.ts` signs against R2's S3 endpoint, matching the
 * Rust `asset_bucket.rs` byte-for-byte in signing shape (same signed-header
 * set, same `content-length` + `x-amz-content-sha256` binding of size and
 * digest into the signature), and `sigV4PresignerFromEnv` (`./handlers.ts`)
 * builds it from the `ASSET_S3_*` bindings. `test/assets/r2.test.ts` pins the
 * degradation: any partial credential set yields NO presigner, and the
 * shipped-empty deployment answers the Rust `503 asset_bucket_unavailable` via
 * {@link UnavailablePresigner} rather than routing object bytes through the
 * Worker.
 */
export interface AssetPresigner {
  presignPut(
    key: string,
    expiresSeconds: number,
    nowUnix: number,
    sizeBytes: number,
    contentSha256Hex: string,
  ): Promise<PresignedUpload>;
  presignGet(key: string, expiresSeconds: number, nowUnix: number): Promise<string>;
}

/** Signals "no bucket configured" — the service maps it to a 503. */
export class PresignUnavailableError extends Error {
  override readonly name = "PresignUnavailableError";
}

/** Default presigner when no S3 credentials are bound. */
export class UnavailablePresigner implements AssetPresigner {
  async presignPut(): Promise<PresignedUpload> {
    throw new PresignUnavailableError(
      "the presigned large-file path requires an asset bucket to be configured",
    );
  }
  async presignGet(): Promise<string> {
    throw new PresignUnavailableError(
      "the presigned large-file path requires an asset bucket to be configured",
    );
  }
}

// ---------------------------------------------------------------------------
// Content screening (supply-chain trust)
// ---------------------------------------------------------------------------

/** What a screening pass decided about a set of bytes. */
export interface AssetScreeningVerdict {
  readonly visibility: AssetVisibility;
  /** Human-readable evidence recorded on the push/commit audit event. */
  readonly auditDetail: string;
  readonly manifest: Record<string, unknown>;
}

/** A screening refusal — the push is rejected outright, nothing is stored. */
export interface AssetScreeningRejection {
  readonly status: number;
  readonly code: string;
  readonly message: string;
}

export interface AssetScreeningRequest {
  readonly assetId: string;
  readonly tenantId: string;
  readonly assetType: string;
  readonly contentType: string;
  readonly content: Uint8Array;
  readonly contentSha256: string;
  readonly nowUnix: number;
}

/**
 * Supply-chain screening gate — Rust `asset_security::screen_asset_push`
 * (issues #179/#261/#366).
 *
 * The HTTP half of this seam is now PORTED and WIRED: `./scan.ts` carries
 * `ScanVerdict` / `resolve_scan_outcome` / the hosted-scanner backend / the
 * async-scan threshold, and `assetDepsFromEnv` builds it from the
 * `ASSET_SCANNER*` vars. With those vars unset the deployment keeps
 * {@link BuiltinEicarScreener} below, which is the Rust unconfigured posture.
 *
 * PORT-TODO(inventory-request-path.md §1.6 "Clamd/HTTP malware scanner"): the
 * full Rust gate ALSO ran detached minisign/Ed25519 signature verification, a
 * cross-tenant publish-approval check, and an out-of-process ClamAV scanner.
 * Those three are still unported. This port keeps the *decision shape* (and the
 * fail-closed default) so the read-path withholding of #366 is real today —
 * `test/assets/r2.test.ts` pins it against the live R2 bucket: an EICAR push is
 * STORED (202) and the pull still answers 404, so "unproven" is
 * indistinguishable from "absent" — and the richer detectors drop in behind
 * this same interface.
 *
 * Only ONE of the three is platform-constrained, and it is not the one it looks
 * like:
 *  - Ed25519 verification is `crypto.subtle.verify("Ed25519", …)`, supported in
 *    workerd. The minisign CONTAINER format (its own base64 envelope + trusted
 *    comment + global-key store) is what is unwritten, not the primitive.
 *  - the cross-tenant publish approval needs an approval-record store; no D1
 *    migration in this tree declares one (`sql/d1-ts/**` is not this app's).
 *  - the `clamd` DAEMON is the constrained one: a Worker cannot fork or exec, so
 *    the in-process/sidecar `clamscan` the Rust could use has no analogue. The
 *    closest reachable form is an INSTREAM client over `connect()` from
 *    `cloudflare:sockets` against a clamd the operator hosts — which is a
 *    different deployment contract (an exposed clamd, not a local socket) and
 *    must be its own slice, not a silent substitution here.
 */
export interface AssetScreener {
  screen(request: AssetScreeningRequest): Promise<AssetScreeningVerdict | AssetScreeningRejection>;
}

export function isScreeningRejection(
  value: AssetScreeningVerdict | AssetScreeningRejection,
): value is AssetScreeningRejection {
  return "code" in value && "status" in value;
}

/** The EICAR anti-malware test string the Rust offline scanner matched on. */
const EICAR_SIGNATURE = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/**
 * The offline default scanner, faithful to the Rust default posture: no
 * external scanner configured means the built-in EICAR detector runs, and a hit
 * is `quarantined` (withheld from every read surface), never a clean publish.
 *
 * The quarantine (rather than the Rust's outright `422` refusal) is this
 * screener's own long-standing decision — `test/assets/r2.test.ts` pins the
 * 202-then-404 it produces against the live bucket. A CONFIGURED backend does
 * refuse: see `resolveScanOutcome` in `./scan.ts`, which ports the Rust
 * `resolve_scan_outcome` unchanged.
 */
export class BuiltinEicarScreener implements AssetScreener {
  async screen(request: AssetScreeningRequest): Promise<AssetScreeningVerdict> {
    // `fatal: false` so arbitrary binary decodes lossily into replacement
    // characters instead of throwing — the EICAR signature is ASCII, so a
    // lossy decode still finds it wherever it appears in a mixed-content file.
    const text = new TextDecoder("utf-8", {
      fatal: false,
      ignoreBOM: false,
    }).decode(request.content);
    const infected = text.includes(EICAR_SIGNATURE);
    return {
      visibility: infected ? "quarantined" : "visible",
      auditDetail: infected
        ? "scan=infected(eicar) signature=absent approval=not_required"
        : "scan=clean signature=absent approval=not_required",
      manifest: {
        scanner: "builtin-eicar",
        outcome: infected ? "infected" : "clean",
        sha256: request.contentSha256,
        size_bytes: request.content.byteLength,
        screened_at_unix: request.nowUnix,
      },
    };
  }
}

// ---------------------------------------------------------------------------
// Caller identity / entitlements
// ---------------------------------------------------------------------------

/**
 * The resolved caller, narrowed to what the asset surface reads out of the
 * Rust `AuthContext` + `EffectiveQuota`. The auth middleware itself is owned by
 * another agent; this app only declares what it consumes.
 */
export interface AssetCaller {
  readonly tenantId: string;
  readonly projectId?: string | undefined;
  readonly scopes: ReadonlySet<string> | readonly string[];
  /** Cumulative tenant asset-storage budget. `undefined` = unbounded. */
  readonly assetStorageQuotaBytes?: number | undefined;
  /** Dedicated per-object ceiling. `undefined` = unbounded. */
  readonly assetMaxObjectBytes?: number | undefined;
  /** Plan/role entitlement to host assets at all (Rust `tenant_can_host`). */
  readonly assetHostingEnabled: boolean;
}

/** An auth refusal, already shaped as the wire error the handler writes. */
export interface AssetAuthFailure {
  readonly status: number;
  readonly code: string;
  readonly message: string;
}

/**
 * Resolves the caller for one request and enforces the contract's declared
 * scope (`assets.read` / `assets.write`).
 */
export interface AssetAuthenticator {
  authenticate(
    request: Request,
    requiredScope: "assets.read" | "assets.write",
  ): Promise<AssetCaller | AssetAuthFailure>;
}

export function isAuthFailure(value: AssetCaller | AssetAuthFailure): value is AssetAuthFailure {
  return "status" in value && "code" in value;
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/** One durable audit row — Rust `AdminAuditEventDraft`. */
export interface AssetAuditEvent {
  readonly action: string;
  readonly target: string;
  readonly outcome: string;
  readonly message: string;
  readonly tenantId: string;
  readonly requestId: string;
  /** Rust issue #522 correlation id (`x-ferrogate-agent-run-id`). */
  readonly agentRunId?: string | undefined;
  readonly occurredAtUnix: number;
}

export interface AssetAuditSink {
  /**
   * SYNCHRONOUS by design — 24 call sites in `./service.ts` record on both the
   * success and the refusal path, several inside `return fail(...)`
   * expressions, and an `await` at each would let a durable-store hiccup change
   * the ANSWER the caller gets. A durable sink therefore buffers here and
   * commits in {@link flush}.
   */
  record(event: AssetAuditEvent): void;
  /**
   * Screening evidence recorded at push/commit time, keyed by asset id — the
   * best-effort correlation the withheld listing surfaces (Rust issue #379).
   *
   * May be a promise: a durable sink has to read it back, and `#379`'s whole
   * point is that the evidence outlives the isolate that produced it.
   */
  screeningEvidence(tenantId: string): Map<string, string> | Promise<Map<string, string>>;
  /**
   * Commit whatever {@link record} buffered. Called ONCE per request by the
   * route module's `on()` wrapper — in a `finally`, so a refused request's
   * audit row is written too, which is the row an operator most wants.
   *
   * Optional: the in-memory sink has nothing to commit.
   */
  flush?(): Promise<void>;
}

/**
 * Bounded in-memory audit sink — the LOCAL-DEV default only.
 *
 * The production sink is {@link D1AssetAuditSink} (`./d1.ts`), which
 * `assetDepsFromEnv` supplies whenever `CONTROL_DB` is bound. Keep this one for
 * `wrangler dev` with no bindings and for tests that assert on `events`
 * directly; it is a RING BUFFER whose contents die with the isolate, so
 * `screeningEvidence` here answers for a push only when the very same isolate
 * served it.
 *
 * PORT-TODO(inventory-data-billing §1.4.6, issues #263/#284 — RETENTION, and a
 * CROSS-APP boundary, not a platform limit): `audit_events` is append-only and
 * NOTHING prunes it. `packages/storage/src/retention.ts` ports
 * `planLogRetention` — pure, tested, and with no executor and no
 * `retention_policies` reader. The executor belongs on a Cron trigger, and the
 * only `scheduled` handler in this Worker is `gatewayScheduled` in
 * `src/index.ts`, which this directory may not edit: the integrate step owns
 * every composition root. The exact line it needs, next to the existing
 * `await usage.sweep({ env, ctx })`:
 *
 * ```ts
 * await sweepRetention({ env, ctx });   // when a retention slice lands
 * ```
 *
 * Until then the mitigation is real but partial, and named so it is not
 * mistaken for the fix: {@link D1AssetAuditSink.screeningEvidence} reads a
 * `LIMIT`-bounded newest-first window (`AUDIT_EVIDENCE_SCAN_LIMIT`), so the
 * withheld listing does not degrade as the table grows — but the TABLE still
 * grows without bound.
 */
export class InMemoryAssetAuditSink implements AssetAuditSink {
  readonly events: AssetAuditEvent[] = [];
  private readonly limit: number;

  constructor(limit = 1000) {
    this.limit = limit;
  }

  record(event: AssetAuditEvent): void {
    this.events.push(event);
    if (this.events.length > this.limit) {
      this.events.splice(0, this.events.length - this.limit);
    }
  }

  screeningEvidence(tenantId: string): Map<string, string> {
    const latest = new Map<string, { at: number; message: string }>();
    for (const event of this.events) {
      if (event.action !== "asset.push" || event.outcome !== "committed") {
        continue;
      }
      if (event.tenantId !== tenantId) continue;
      const seen = latest.get(event.target);
      if (seen && seen.at >= event.occurredAtUnix) continue;
      latest.set(event.target, {
        at: event.occurredAtUnix,
        message: event.message,
      });
    }
    return new Map([...latest.entries()].map(([target, entry]) => [target, entry.message]));
  }
}

/** Convenience: the durable id of the row a `{ref}` addresses. */
export function assetRowId(ref: AssetObjectRef): string {
  return storedAssetVariantId(ref.tenantId, ref.assetType, ref.name, ref.version, ref.variant);
}
