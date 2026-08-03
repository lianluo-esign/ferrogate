/**
 * Asset egress governance for the MCP asset read path — the download-side quota
 * gate, byte meter, and audit event.
 *
 * ## Why this file exists
 *
 * `apps/gateway/src/assets/egress.ts` owns the same functions for the REST
 * `/v1/assets/` surface. The MCP `resources/read` and `builtin.fetch_asset`
 * paths must charge egress quota, emit the metering record and write the audit
 * event identically — an MCP read must not be a metering or quota bypass.
 *
 * This file reuses the SAME helpers from `@ferrogate/billing` and
 * `@ferrogate/policy` that the gateway's egress module uses, and implements the
 * same governance functions. The gateway-specific `LedgerAssetEgressMeter` is
 * not duplicated here; the MCP uses `NO_ASSET_EGRESS_METER` (no billing
 * database is bound to this Worker) and relies on the per-isolate counters for
 * the fail-closed byte-budget gate.
 *
 * ## The two gates, in order
 *
 * 1. {@link assetEgressQuotaDenial} — fail-closed, BEFORE a byte is served:
 *    - the monthly egress BYTE budget, checked READ-ONLY so a budget-exhausted
 *      download never burns a download-RPM token, then
 *    - the download RPM cap, a per-minute request counter on the winning scope.
 *
 * 2. {@link recordAssetEgress} — meter the bytes, accumulate the monthly
 *    counter that backs gate 1, and return the charge for audit. Best-effort:
 *    a metering failure is swallowed, never propagated.
 *
 * ## The counter keys
 *
 * Verbatim from the gateway:
 * ```
 * egress:{scope.counter_key(api_key_id)}              // byte budget
 * asset_egress_rpm:{scope.counter_key(api_key_id)}    // download RPM
 * ```
 */
import {
  type BillingEvent,
  PriceBook,
  egressCostUsd,
  providerAttemptForRequest,
} from "@ferrogate/billing";
import type { QuotaScopeSelector } from "@ferrogate/policy";

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
  readonly monthlyEgressBytesScope?: QuotaScopeSelector | undefined;
  /** `#262` per-minute asset-download request cap. */
  readonly downloadRpmLimit?: number | undefined;
  /** The scope whose cap won the `min`; decides the RPM window key. */
  readonly downloadRpmLimitScope?: QuotaScopeSelector | undefined;
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
 * `AppState` maps. See the gateway's egress.ts module docstring for what that
 * does and does not guarantee on Workers.
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
 * The three refusals, with the EXACT status and message from the gateway.
 *
 * **All three are 429.** The gateway's `assets.rs:1114-1124` writes every one
 * of them with `StatusCode::TOO_MANY_REQUESTS`.
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
   * The gateway's `assets.rs:1114` passes `selected.size_bytes`, so a range
   * request is gated on the whole object. That is fail-closed on purpose: gating
   * on the slice would let a caller drain an exhausted budget one `Range` header
   * at a time.
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
  readonly projectId?: string | undefined;
  readonly assetType: string;
  readonly name: string;
  readonly version: string;
  /** The bytes THIS response put on the wire. */
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
 * `record_asset_egress_event`, field for field.
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
   */
  readonly bytes: number;
  readonly pricePerGb?: number | undefined;
  readonly counters: AssetEgressCounters;
  readonly meter: AssetEgressMeter;
  readonly nowUnix: number;
}

/**
 * Rust `record_asset_egress`: meter the transferred bytes, accumulate the
 * monthly counter that backs the byte-budget gate, and return the charge for
 * audit.
 *
 * A zero-byte response is NOT metered at all: no bytes left the gateway, so
 * there is nothing to bill, nothing to accumulate, and no pull to audit.
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

  // Best-effort, exactly as the gateway logs-and-continues: the client already
  // has the bytes, so a metering failure must not turn a served download into
  // an error.
  try {
    await input.meter.record(charge);
  } catch {
    // Deliberately swallowed.
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

/** Rust: `asset {id} downloaded ({bytes} bytes)` — the pull audit message. */
export function assetPullAuditMessage(assetId: string, bytes: number): string {
  return `asset ${assetId} downloaded (${bytes} bytes)`;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * The deployment's asset-egress rate, in USD per decimal GB.
 *
 * Sourced from the SAME `PriceBook` the gateway uses.
 */
export function assetEgressPricePerGb(
  priceBook: PriceBook = PriceBook.withDefaultRateCard(),
): number | undefined {
  return priceBook.egress_price_per_gb;
}

/**
 * The per-isolate counters for one `env` object, memoized ON that object.
 *
 * A `WeakMap` keyed by `env` rather than a module-scoped slot, so two in-flight
 * requests each resolve through their OWN bindings, while the counters survive
 * across requests within an isolate.
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
