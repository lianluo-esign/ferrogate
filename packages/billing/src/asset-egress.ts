/**
 * Asset egress governance — the download-side quota gate and the byte meter.
 *
 * Port of `crates/ferrogate-gateway/src/server/asset_egress.rs` (issue #262),
 * closing data-plane certification finding **D4**: `monthly_egress_bytes_budget`
 * and `download_rpm_limit` were parsed (`src/ratelimit/quota.ts`), persisted and
 * served by the admin API, and read by NOTHING; `asset_egress_price_per_gb` had
 * no consumer at all. An operator could configure an egress budget, see it
 * echoed back, and have it enforce nothing — unlimited bandwidth served, none of
 * it billed.
 *
 * ## The two halves, in Rust's order
 *
 * 1. {@link assetEgressQuotaDenial} — fail-closed, BEFORE a byte is served:
 *    - the monthly egress BYTE budget, checked READ-ONLY (`asset_egress.rs:63`)
 *      so a budget-exhausted download never burns a download-RPM token, then
 *    - the download RPM cap (`asset_egress.rs:77`), a per-minute request counter
 *      on the winning scope — the download-side analogue of inference RPM.
 *
 *    Both denials carry a distinct code so a client can tell "out of bandwidth
 *    budget" from "downloading too fast", and both are separate from the
 *    token-side `rate_limit_exceeded`.
 *
 * 2. {@link recordAssetEgress} — meter the bytes, accumulate the monthly counter
 *    that backs gate 1, and emit the PULL-side audit event. Best-effort: a
 *    metering failure is swallowed, never propagated, because serving a
 *    download the client already received must not become an error
 *    (`asset_egress.rs:106-110`).
 *
 * ## The counter keys
 *
 * Verbatim from Rust, and security-critical:
 *
 * ```
 * egress:{scope.counter_key(api_key_id)}              // byte budget
 * asset_egress_rpm:{scope.counter_key(api_key_id)}    // download RPM
 * ```
 *
 * The inner half comes from `@ferrogate/policy`'s `QuotaScopeSelector.counterKey`
 * — the ONE derivation site — so a `key` winner is `key:{api_key_id}` and never
 * the raw, tenant-controllable id. A tenant that mints the key id
 * `"tenant:victim"` gets `asset_egress_rpm:key:tenant:victim`, which cannot
 * collide with the victim tenant's aggregate window. The two outer prefixes then
 * keep egress accounting from colliding with ANY inference counter.
 *
 * They are derived identically on the deny side and the record side, so a served
 * download is counted against exactly the budget it was checked against.
 *
 * ## What is durable and what is not, stated so it is not mistaken for parity
 *
 * {@link InMemoryAssetEgressCounters} is per-ISOLATE. That is the same posture
 * Rust has — `AppState::record_asset_egress_bytes` /
 * `try_consume_api_key_request` are process-local maps on one gateway node, so a
 * multi-node Rust deployment already enforced this per node — but on Workers
 * "per isolate" is a much smaller unit than "per node". A deployment that needs
 * one aggregate window across isolates supplies a durable
 * {@link AssetEgressCounters}; the port exists precisely so that is a wiring
 * change and not a rewrite. The BILLING half has no such caveat: it goes
 * through {@link AssetEgressMeter}, whose production implementation writes the
 * same durable `billing_ledger` row every inference charge writes.
 */
import {
  type BillingEvent,
} from "./event.js";
import { charge as chargeEvent, ledgerEntryId } from "./ledger.js";
import { PriceBook, egressCostUsd } from "./pricing.js";
import { providerAttemptForRequest } from "./usage.js";
import { usdToCredits } from "./metering/credits.js";
import { D1LedgerStore } from "./metering/d1.js";
import type { LedgerStore, MeteredCharge } from "./metering/ports.js";
import { meteringDatabaseFrom } from "./metering/runtime.js";

// ---------------------------------------------------------------------------
// The quota slice this module reads
// ---------------------------------------------------------------------------

/**
 * The egress half of a resolved `EffectiveQuota`.
 *
 * Declared structurally rather than importing `EffectiveQuota` wholesale so a
 * caller can hand over exactly these four fields; `@ferrogate/policy`'s
 * `EffectiveQuota` is assignable to it unchanged.
 */
export interface AssetEgressQuota {
  /** `#262` monthly egress byte budget — the tightest across the scope chain. */
  readonly monthlyEgressBytesBudget?: number | undefined;
  /** The scope whose budget won the `min`; decides the counter key. */
  readonly monthlyEgressBytesScope?: AssetEgressScope | undefined;
  /** `#262` per-minute asset-download request cap. */
  readonly downloadRpmLimit?: number | undefined;
  /** The scope whose cap won the `min`; decides the RPM window key. */
  readonly downloadRpmLimitScope?: AssetEgressScope | undefined;
}

/** The only quota-scope behavior egress needs from the policy package. */
export interface AssetEgressScope {
  counterKey(apiKeyId: string): string;
}

/** Rust `egress_byte_counter_key` prefix. */
export const ASSET_EGRESS_BYTE_COUNTER_PREFIX = "egress:";
/** Rust `asset_egress_quota_denial`'s RPM window prefix. */
export const ASSET_EGRESS_RPM_COUNTER_PREFIX = "asset_egress_rpm:";

/**
 * Rust `egress_byte_counter_key`: the monthly-egress counter key for the scope
 * that owns the byte budget, falling back to the tenant scope when the budget
 * carries no recorded winning scope (a legacy/plan-less path).
 */
export function assetEgressByteCounterKey(
  quota: AssetEgressQuota,
  apiKeyId: string,
  tenantId: string,
): string {
  const scopeKey = quota.monthlyEgressBytesScope?.counterKey(apiKeyId) ?? `tenant:${tenantId}`;
  return `${ASSET_EGRESS_BYTE_COUNTER_PREFIX}${scopeKey}`;
}

/**
 * Rust `asset_egress_quota_denial`'s RPM window key. Falls back to the per-key
 * window (`key:{api_key_id}`) when the cap carries no winning scope.
 */
export function assetEgressRpmCounterKey(quota: AssetEgressQuota, apiKeyId: string): string {
  const scopeKey = quota.downloadRpmLimitScope?.counterKey(apiKeyId) ?? `key:${apiKeyId}`;
  return `${ASSET_EGRESS_RPM_COUNTER_PREFIX}${scopeKey}`;
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/** What the download-RPM window answered. Rust `Result<bool>`, flattened. */
export type DownloadAdmission = "allowed" | "denied" | "unavailable";

/**
 * The two counters egress governance needs — Rust's two `AppState` maps.
 *
 * `unavailable` is a first-class answer, never an exception, because Rust
 * distinguishes it: `try_consume_api_key_request` returns `Result<bool>` and an
 * `Err` becomes a distinct refusal. A counter backend that is DOWN must never be
 * indistinguishable from one that said "allowed".
 */
export interface AssetEgressCounters {
  /** Month-to-date bytes served against `counterKey`. READ-ONLY. */
  bytesUsed(counterKey: string): number | Promise<number>;
  /** Accumulate served bytes. Called only after a download was admitted. */
  addBytes(counterKey: string, bytes: number): void | Promise<void>;
  /** Consume one token from the per-minute download window. */
  tryConsumeDownload(
    counterKey: string,
    limit: number,
  ): DownloadAdmission | Promise<DownloadAdmission>;
}

/** The RPM window length, in seconds — the same minute the inference RPM uses. */
export const ASSET_EGRESS_RPM_WINDOW_SECONDS = 60;

/**
 * Per-isolate counters — the faithful analogue of Rust's process-local
 * `AppState` maps. See the module docstring for what that does and does not
 * guarantee on Workers.
 */
export class InMemoryAssetEgressCounters implements AssetEgressCounters {
  readonly #bytes = new Map<string, number>();
  readonly #windows = new Map<string, { startedAt: number; count: number }>();
  readonly #now: () => number;

  constructor(now: () => number = () => Math.floor(Date.now() / 1000)) {
    this.#now = now;
  }

  bytesUsed(counterKey: string): number {
    return this.#bytes.get(counterKey) ?? 0;
  }

  addBytes(counterKey: string, bytes: number): void {
    if (bytes <= 0) return;
    this.#bytes.set(counterKey, this.bytesUsed(counterKey) + bytes);
  }

  /** Test/diagnostic read of the current minute's download count. */
  downloadsConsumed(counterKey: string): number {
    const window = this.#windows.get(counterKey);
    if (window === undefined) return 0;
    return this.#now() - window.startedAt >= ASSET_EGRESS_RPM_WINDOW_SECONDS ? 0 : window.count;
  }

  tryConsumeDownload(counterKey: string, limit: number): DownloadAdmission {
    const now = this.#now();
    const window = this.#windows.get(counterKey);
    if (window === undefined || now - window.startedAt >= ASSET_EGRESS_RPM_WINDOW_SECONDS) {
      this.#windows.set(counterKey, { startedAt: now, count: 1 });
      return limit >= 1 ? "allowed" : "denied";
    }
    if (window.count >= limit) return "denied";
    window.count += 1;
    return "allowed";
  }
}

// ---------------------------------------------------------------------------
// The deny gate
// ---------------------------------------------------------------------------

/**
 * The three refusals, with the EXACT Rust code, status and message.
 *
 * **All three are 429.** `server/assets.rs:1114-1124` writes every one of them
 * with `StatusCode::TOO_MANY_REQUESTS` — including
 * `governance_counter_unavailable`, which the inference paths write as a 503.
 * `docs/rewrite/cutover-parity-dataplane.md` §D4 says "503
 * `governance_counter_unavailable`"; the Rust CODE says 429 at this call site,
 * and the code is what is ported here.
 */
export const ASSET_EGRESS_REFUSALS = {
  asset_egress_quota_exceeded: {
    status: 429,
    code: "asset_egress_quota_exceeded",
    message: (budget: number, used: number, requested: number) =>
      `monthly asset egress budget of ${budget} bytes is exhausted for this scope ` +
      `(${used} used, ${requested} requested)`,
  },
  asset_download_rate_limit_exceeded: {
    status: 429,
    code: "asset_download_rate_limit_exceeded",
    message: (limit: number) =>
      `asset download rate limit of ${limit}/min is exhausted for this scope`,
  },
  governance_counter_unavailable: {
    status: 429,
    code: "governance_counter_unavailable",
    message: () => "gateway counter backend is unavailable for asset download rate limiting",
  },
} as const;

/** A refusal, already shaped as the wire error the asset service returns. */
export interface AssetEgressDenial {
  readonly status: number;
  readonly code: string;
  readonly message: string;
}

export interface AssetEgressGateInput {
  readonly quota: AssetEgressQuota;
  readonly apiKeyId: string;
  readonly tenantId: string;
  /**
   * The RESOLVED OBJECT SIZE, never a slice.
   *
   * `assets.rs:1114` passes `selected.size_bytes`, so a range request is gated
   * on the whole object. That is fail-closed on purpose: gating on the slice
   * would let a caller drain an exhausted budget one `Range` header at a time.
   */
  readonly bytes: number;
  readonly counters: AssetEgressCounters;
}

/**
 * Rust `asset_egress_quota_denial`. `null` ⇒ the download may proceed.
 *
 * The byte budget is checked FIRST and READ-ONLY, which is the whole reason the
 * two checks cannot be folded together: a caller already over its bandwidth
 * budget must not also burn the download-RPM token it would have needed once
 * the month rolls.
 */
export async function assetEgressQuotaDenial(
  input: AssetEgressGateInput,
): Promise<AssetEgressDenial | null> {
  const { quota, apiKeyId, tenantId, bytes, counters } = input;

  const budget = quota.monthlyEgressBytesBudget;
  if (budget !== undefined) {
    const counterKey = assetEgressByteCounterKey(quota, apiKeyId, tenantId);
    const used = await counters.bytesUsed(counterKey);
    if (used + bytes > budget) {
      const refusal = ASSET_EGRESS_REFUSALS.asset_egress_quota_exceeded;
      return {
        status: refusal.status,
        code: refusal.code,
        message: refusal.message(budget, used, bytes),
      };
    }
  }

  const limit = quota.downloadRpmLimit;
  if (limit !== undefined) {
    const counterKey = assetEgressRpmCounterKey(quota, apiKeyId);
    const admission = await counters.tryConsumeDownload(counterKey, limit);
    if (admission === "denied") {
      const refusal = ASSET_EGRESS_REFUSALS.asset_download_rate_limit_exceeded;
      return { status: refusal.status, code: refusal.code, message: refusal.message(limit) };
    }
    if (admission === "unavailable") {
      const refusal = ASSET_EGRESS_REFUSALS.governance_counter_unavailable;
      return { status: refusal.status, code: refusal.code, message: refusal.message() };
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Metering
// ---------------------------------------------------------------------------

/** Rust `BillingEvent.provider` for an egress charge. */
export const ASSET_EGRESS_PROVIDER = "asset_egress";
/** Rust `logical_model` = `asset_egress:{asset_type}/{name}`. */
export const ASSET_EGRESS_LOGICAL_MODEL_PREFIX = "asset_egress:";
/** Rust `metadata["asset_egress_bytes"]`. */
export const ASSET_EGRESS_BYTES_METADATA_KEY = "asset_egress_bytes";
/**
 * `bytes × price_per_gb / 1e9`, or `undefined` when the deployment sets no
 * `asset_egress_price_per_gb`.
 *
 * The arithmetic is NOT restated here: it delegates to `@ferrogate/billing`'s
 * `egressCostUsd`, which already owns the decimal-GB divisor
 * (`BYTES_PER_BILLED_GB`) precisely "so the rate card and per-download metering
 * can never drift on the GB divisor". A second copy of `/ 1e9` in this file is
 * exactly that drift waiting to happen.
 *
 * An unpriced deployment stays METERED and auditable but carries no cost — no
 * fabricated figure, exactly how an unpriced model is metered but not charged
 * (`asset_egress_test.rs::unpriced_egress_is_metered_but_carries_no_cost`).
 */
export function assetEgressBytePrice(
  bytes: number,
  pricePerGb: number | undefined,
): number | undefined {
  if (pricePerGb === undefined || !Number.isFinite(pricePerGb)) return undefined;
  return egressCostUsd(pricePerGb, bytes);
}

/** One metered download. Rust `record_asset_egress_event`'s arguments. */
export interface AssetEgressCharge {
  readonly requestId: string;
  readonly agentRunId?: string | undefined;
  readonly tenantId: string;
  /** The authenticated credential that caused this transfer, when present. */
  readonly apiKeyId?: string | undefined;
  readonly projectId?: string | undefined;
  readonly assetType: string;
  readonly name: string;
  readonly version: string;
  /** The bytes THIS response put on the wire. See {@link recordAssetEgress}. */
  readonly bytes: number;
  readonly provider: string;
  readonly logicalModel: string;
  /** `undefined` on an unpriced deployment. */
  readonly costUsd?: number | undefined;
  readonly occurredAtUnix: number;
}

/**
 * Where a metered download is settled.
 *
 * `record` may return a promise, and callers MUST NOT let a rejection escape —
 * {@link recordAssetEgress} swallows it, because the bytes have already been
 * served and a metering failure must never become the caller's error.
 */
export interface AssetEgressMeter {
  record(charge: AssetEgressCharge): void | Promise<void>;
}

/** Asset metadata required by the shared read-side egress path. */
export interface AssetEgressReadableAsset {
  readonly id?: string | undefined;
  readonly assetType: string;
  readonly name: string;
  readonly version: string;
  readonly sizeBytes: number;
}

export type AssetEgressRead<TAsset extends AssetEgressReadableAsset, TFailure> =
  | { readonly ok: true; readonly asset: TAsset; readonly content: Uint8Array }
  | { readonly ok: false; readonly error: TFailure };

export interface ReadAssetWithEgressInput<
  TAsset extends AssetEgressReadableAsset,
  TFailure,
> {
  readonly quota: AssetEgressQuota;
  readonly apiKeyId: string;
  readonly tenantId: string;
  readonly projectId?: string | undefined;
  readonly requestId: string;
  readonly agentRunId?: string | undefined;
  /** Metadata from the resolved asset row, used for the pre-read gate. */
  readonly asset: TAsset;
  readonly read: () => Promise<AssetEgressRead<TAsset, TFailure>>;
  readonly pricePerGb?: number | undefined;
  readonly counters: AssetEgressCounters;
  readonly meter: AssetEgressMeter;
  readonly nowUnix: number;
}

export type ReadAssetWithEgressResult<
  TAsset extends AssetEgressReadableAsset,
  TFailure,
> =
  | {
      readonly ok: true;
      readonly asset: TAsset;
      readonly content: Uint8Array;
      readonly charge: AssetEgressCharge | null;
    }
  | { readonly ok: false; readonly kind: "quota"; readonly error: AssetEgressDenial }
  | { readonly ok: false; readonly kind: "read"; readonly error: TFailure };

/** Offline meter: the charges, in order. */
export class InMemoryAssetEgressMeter implements AssetEgressMeter {
  readonly charges: AssetEgressCharge[] = [];

  record(charge: AssetEgressCharge): void {
    this.charges.push(charge);
  }
}

/** A meter that drops everything — the posture when no billing sink is bound. */
export const NO_ASSET_EGRESS_METER: AssetEgressMeter = { record: () => undefined };

/**
 * The `BillingEvent` an egress charge settles as — Rust
 * `record_asset_egress_event`, field for field:
 *
 * | Rust | here |
 * |---|---|
 * | `provider = "asset_egress"` | {@link ASSET_EGRESS_PROVIDER} |
 * | `logical_model = "asset_egress:{type}/{name}"` | {@link AssetEgressCharge.logicalModel} |
 * | `provider_model = version` | `charge.version` |
 * | `usage.total_tokens = 0` | egress carries no token usage |
 * | `metadata["asset_egress_bytes"]` | {@link ASSET_EGRESS_BYTES_METADATA_KEY} |
 * | `cost_usd = bytes × price/GB` | `charge.costUsd`, gateway-SETTLED |
 *
 * `cost_usd` is the authoritative settled figure: `charge()` records it verbatim
 * rather than pricing tokens (there are none), which is the only reason this can
 * go through the ordinary ledger at all.
 */
export function assetEgressBillingEvent(charge: AssetEgressCharge): BillingEvent {
  return {
    request_id: charge.requestId,
    trace_id: charge.requestId,
    provider_attempt: providerAttemptForRequest(charge.requestId, 0),
    ...(charge.agentRunId !== undefined ? { agent_run_id: charge.agentRunId } : {}),
    tenant: {
      ...(charge.tenantId !== "" ? { organization_id: charge.tenantId } : {}),
      ...(charge.projectId !== undefined ? { project_id: charge.projectId } : {}),
      ...(charge.apiKeyId !== undefined && charge.apiKeyId !== ""
        ? { api_key_id: charge.apiKeyId }
        : {}),
    },
    logical_model: charge.logicalModel,
    provider: charge.provider,
    provider_model: charge.version,
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
    usage_source: "provider_usage",
    status_code: 200,
    occurred_at_unix: charge.occurredAtUnix,
    ...(charge.costUsd !== undefined ? { cost_usd: charge.costUsd } : {}),
    metadata: { [ASSET_EGRESS_BYTES_METADATA_KEY]: String(charge.bytes) },
  };
}

/**
 * The DURABLE meter: settle each egress charge into the same `billing_ledger` /
 * `billing_events` / `billing_report_outbox` rows every inference charge writes.
 *
 * Nothing here re-implements pricing or idempotency — `@ferrogate/billing`'s
 * `charge()` and `ledgerEntryId()` and the app's `LedgerStore` own both, and the
 * `record` contract is already idempotent on the entry id, so a retried pull of
 * the same request id cannot double-charge.
 *
 * An UNPRICED charge is skipped rather than written at zero: `charge()` would
 * throw `price_not_found` for provider `asset_egress` (no rate-card entry), and
 * billing a real transfer at $0 is the one outcome the metering layer refuses
 * everywhere else. It stays visible through the monthly counter and the pull
 * audit event.
 */
export class LedgerAssetEgressMeter implements AssetEgressMeter {
  readonly #ledger: LedgerStore;
  readonly #creditsPerUsd: number;

  constructor(ledger: LedgerStore, priceBook: PriceBook = PriceBook.withDefaultRateCard()) {
    this.#ledger = ledger;
    this.#creditsPerUsd = priceBook.credits_per_usd;
  }

  async record(charge: AssetEgressCharge): Promise<void> {
    if (charge.costUsd === undefined) return;
    const event = assetEgressBillingEvent(charge);
    const entry = chargeEvent(PriceBook.default(), event);
    const metered: MeteredCharge = {
      id: ledgerEntryId(event),
      requestId: event.request_id,
      event,
      entry,
      credits: usdToCredits(entry.cost.total_cost, this.#creditsPerUsd),
      occurredAtUnix: charge.occurredAtUnix,
    };
    await this.#ledger.record(metered);
  }
}

export interface RecordAssetEgressInput {
  readonly quota: AssetEgressQuota;
  readonly apiKeyId: string;
  readonly tenantId: string;
  readonly projectId?: string | undefined;
  readonly requestId: string;
  readonly agentRunId?: string | undefined;
  readonly assetType: string;
  readonly name: string;
  readonly version: string;
  /**
   * The bytes ACTUALLY SERVED by this response.
   *
   * Rust meters `selected.size_bytes` at the gate, which over-bills a `206` and
   * bills a `304` that put nothing on the wire. This port bills what left the
   * gateway instead — which is strictly narrower than Rust, never wider, and is
   * what makes a RESUMED download add up to the object's size once rather than
   * twice. The GATE keeps Rust's full-object figure, so the budget is still
   * fail-closed (see {@link AssetEgressGateInput.bytes}).
   */
  readonly bytes: number;
  readonly pricePerGb?: number | undefined;
  readonly counters: AssetEgressCounters;
  readonly meter: AssetEgressMeter;
  readonly nowUnix: number;
}

/**
 * Rust `record_asset_egress`: meter the transferred bytes, accumulate the
 * monthly counter that backs the byte-budget gate, and hand back the audit
 * message the caller records.
 *
 * A zero-byte response (a `304`, a `416`, a `HEAD`) is NOT metered at all: no
 * bytes left the gateway, so there is nothing to bill, nothing to accumulate,
 * and no pull to audit.
 *
 * Returns the {@link AssetEgressCharge} that was settled, or `null` when
 * nothing was.
 */
export async function recordAssetEgress(
  input: RecordAssetEgressInput,
): Promise<AssetEgressCharge | null> {
  if (input.bytes <= 0) return null;

  const charge: AssetEgressCharge = {
    requestId: input.requestId,
    agentRunId: input.agentRunId,
    tenantId: input.tenantId,
    ...(input.apiKeyId !== "" ? { apiKeyId: input.apiKeyId } : {}),
    projectId: input.projectId,
    assetType: input.assetType,
    name: input.name,
    version: input.version,
    bytes: input.bytes,
    provider: ASSET_EGRESS_PROVIDER,
    logicalModel: `${ASSET_EGRESS_LOGICAL_MODEL_PREFIX}${input.assetType}/${input.name}`,
    costUsd: assetEgressBytePrice(input.bytes, input.pricePerGb),
    occurredAtUnix: input.nowUnix,
  };

  // Best-effort, exactly as Rust logs-and-continues: the client already has the
  // bytes, so a metering failure must not turn a served download into an error.
  try {
    await input.meter.record(charge);
  } catch {
    // Deliberately swallowed. See `asset_egress.rs:126-133`.
  }

  // The counter is accumulated even when the meter threw: it is what the
  // fail-closed budget gate reads, and losing it would let a broken billing
  // sink silently uncap a tenant's bandwidth.
  await input.counters.addBytes(
    assetEgressByteCounterKey(input.quota, input.apiKeyId, input.tenantId),
    input.bytes,
  );

  return charge;
}

/**
 * One read-side path for every asset consumer: gate the resolved object before
 * reading it, then meter the bytes returned by storage.
 */
export async function readAssetWithEgress<
  TAsset extends AssetEgressReadableAsset,
  TFailure,
>(
  input: ReadAssetWithEgressInput<TAsset, TFailure>,
): Promise<ReadAssetWithEgressResult<TAsset, TFailure>> {
  const denial = await assetEgressQuotaDenial({
    quota: input.quota,
    apiKeyId: input.apiKeyId,
    tenantId: input.tenantId,
    bytes: input.asset.sizeBytes,
    counters: input.counters,
  });
  if (denial !== null) return { ok: false, kind: "quota", error: denial };

  const read = await input.read();
  if (!read.ok) return { ok: false, kind: "read", error: read.error };

  const charge = await recordAssetEgress({
    quota: input.quota,
    apiKeyId: input.apiKeyId,
    tenantId: input.tenantId,
    projectId: input.projectId,
    requestId: input.requestId,
    agentRunId: input.agentRunId,
    assetType: read.asset.assetType,
    name: read.asset.name,
    version: read.asset.version,
    bytes: read.content.byteLength,
    pricePerGb: input.pricePerGb,
    counters: input.counters,
    meter: input.meter,
    nowUnix: input.nowUnix,
  });
  return { ok: true, asset: read.asset, content: read.content, charge };
}

/** Rust: `asset {id} downloaded ({bytes} bytes)` — the pull audit message. */
export function assetPullAuditMessage(assetId: string, bytes: number): string {
  return `asset ${assetId} downloaded (${bytes} bytes)`;
}

/** The canonical `stored_assets.id` used by gateway and MCP audit rows. */
export function assetEgressTargetId(
  asset: AssetEgressReadableAsset,
  tenantId: string,
): string {
  void tenantId;
  if (asset.id === undefined || asset.id === "") {
    throw new Error("stored_assets.id is required for asset egress audit");
  }
  return asset.id;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * The deployment's asset-egress rate, in USD per decimal GB.
 *
 * Sourced from the SAME `PriceBook` the metering sink prices inference with —
 * `PriceBook.withDefaultRateCard()` already seeds
 * `DEFAULT_EGRESS_PRICE_PER_GB` (issue #262) and already exposes
 * `egress_price_per_gb`, so egress and inference cannot end up billing off two
 * different rate cards. `undefined` on a card with no egress rate leaves egress
 * metered and audited but uncharged.
 *
 * NOT read from a Worker var. `asset_egress_price_per_gb` is a
 * `packages/config` field and adding a `GATEWAY_ASSET_EGRESS_PRICE_PER_GB` var
 * would require declaring it in `apps/gateway/wrangler.toml`, a composition-root
 * file this slice may not edit (and `test/env-var-drift.test.ts` correctly
 * refuses an undeclared read). An operator who needs a different rate overrides
 * the rate card, which is the one place a price already lives.
 */
export function assetEgressPricePerGb(
  priceBook: PriceBook = PriceBook.withDefaultRateCard(),
): number | undefined {
  return priceBook.egress_price_per_gb;
}

/**
 * The durable egress meter for one `env`, or `null` when no billing database is
 * bound (`BILLING_DB` / `CONTROL_DB` — the same resolver the metering sink uses,
 * so egress and inference can never end up settling into different databases).
 */
export function assetEgressMeterFromEnv(env: unknown): AssetEgressMeter | null {
  const db = meteringDatabaseFrom(env);
  return db === undefined ? null : new LedgerAssetEgressMeter(new D1LedgerStore(db));
}

/**
 * The per-isolate counters for one `env` object, memoized ON that object.
 *
 * A `WeakMap` keyed by `env` rather than a module-scoped slot, for the reason
 * the metering sink states: two in-flight requests each resolve through their
 * OWN bindings, while the counters survive across requests within an isolate —
 * which is the whole point of a monthly accumulator. A per-request instance
 * would reset the budget on every single download.
 */
const COUNTERS_BY_ENV = new WeakMap<object, AssetEgressCounters>();

export function assetEgressCountersFromEnv(env: unknown): AssetEgressCounters {
  const key = (typeof env === "object" && env !== null ? env : COUNTERS_BY_ENV) as object;
  const cached = COUNTERS_BY_ENV.get(key);
  if (cached !== undefined) return cached;
  const counters = new InMemoryAssetEgressCounters();
  COUNTERS_BY_ENV.set(key, counters);
  return counters;
}
