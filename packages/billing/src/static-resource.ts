/**
 * Static-resource per-request billing — the $0.001-per-pull meter for the
 * `static_resource` asset type (STATIC_RESOURCES_DESIGN.md §5.3).
 *
 * ## Why this is NOT `asset-egress.ts`
 *
 * `asset_egress` bills BYTES against a per-GB rate and enforces a monthly byte
 * budget + download-RPM gate. A `static_resource` pull is billed the OTHER way:
 * a flat per-REQUEST price, independent of object size (design Q-E — the
 * per-GB egress path is deliberately OFF for this type so the price a tenant
 * sees is "$0.001 every time an end user pulls a file", full stop). So this
 * module owns only the metering half: it has no quota gate, no byte counter,
 * and no size input. The wire-side anti-abuse limit, when one is wanted, reuses
 * the existing asset download-RPM window rather than growing a second one here.
 *
 * ## How it settles without a rate-card entry
 *
 * Like {@link ../asset-egress.ts}, the charge carries an authoritative
 * `cost_usd` (`requests × price_per_request`) and `charge()` records that figure
 * verbatim — a finite `cost_usd` is used as-is, so provider `static_resource`
 * needs no `PriceBook` rate-card row. An UNPRICED deployment (config field null)
 * yields `cost_usd === undefined`; the durable meter then SKIPS the write rather
 * than billing a real pull at $0, exactly as egress does. The pull stays
 * auditable through the request log regardless.
 *
 * The price is a `@ferrogate/config` field (`static_resource_price_per_request`,
 * default `0.001`), NOT a `PriceBook` member: the design puts operator-facing
 * pricing in config so Polaris can surface and edit it, and so the pinned
 * `PriceBook` JSON shape (`{ entries, credits_per_usd, egress_price_per_gb? }`)
 * is left untouched.
 */
import type { BillingEvent } from "./event.js";
import { charge as chargeEvent, ledgerEntryId } from "./ledger.js";
import { usdToCredits } from "./metering/credits.js";
import { D1LedgerStore } from "./metering/d1.js";
import type { LedgerStore, MeteredCharge } from "./metering/ports.js";
import { meteringDatabaseFrom } from "./metering/runtime.js";
import { PriceBook } from "./pricing.js";
import { providerAttemptForRequest } from "./usage.js";

// ---------------------------------------------------------------------------
// Price
// ---------------------------------------------------------------------------

/** The product default: $0.001 for every end-user pull of a static resource. */
export const DEFAULT_STATIC_RESOURCE_PRICE_PER_REQUEST = 0.001;

/** `BillingEvent.provider` for a static-resource pull charge. */
export const STATIC_RESOURCE_PROVIDER = "static_resource";

/** `logical_model = static_resource:{name}` — the pulled resource path. */
export const STATIC_RESOURCE_LOGICAL_MODEL_PREFIX = "static_resource:";

/** `metadata["static_resource_requests"]` — how many pulls this charge settles. */
export const STATIC_RESOURCE_REQUESTS_METADATA_KEY = "static_resource_requests";

export const STATIC_RESOURCE_IDENTITY_ERROR =
  "stored_assets.id is required for static-resource pull audit";

/**
 * `requests × price_per_request`, or `undefined` when the deployment sets no
 * `static_resource_price_per_request` (null/undefined) or when nothing was
 * pulled. A non-finite or negative price is treated as unpriced rather than
 * fabricating a cost — the same posture `assetEgressBytePrice` takes.
 */
export function staticResourceRequestCost(
  requests: number,
  pricePerRequest: number | null | undefined,
): number | undefined {
  if (pricePerRequest === undefined || pricePerRequest === null) return undefined;
  if (!Number.isFinite(pricePerRequest) || pricePerRequest < 0) return undefined;
  if (!Number.isFinite(requests) || requests <= 0) return undefined;
  return requests * pricePerRequest;
}

// ---------------------------------------------------------------------------
// Charge
// ---------------------------------------------------------------------------

/** One metered static-resource pull. Mirrors `AssetEgressCharge`, size-free. */
export interface StaticResourceCharge {
  readonly requestId: string;
  readonly agentRunId?: string | undefined;
  readonly tenantId: string;
  /** The authenticated credential that caused this pull, when present. */
  readonly apiKeyId?: string | undefined;
  readonly projectId?: string | undefined;
  /** Always `static_resource`, carried for symmetry with the egress path. */
  readonly assetType: string;
  readonly name: string;
  readonly version: string;
  /** How many pulls this charge settles — normally `1` per served GET. */
  readonly requests: number;
  readonly provider: string;
  readonly logicalModel: string;
  /** `undefined` on an unpriced deployment. */
  readonly costUsd?: number | undefined;
  readonly occurredAtUnix: number;
}

/**
 * The `BillingEvent` a static-resource pull settles as — the egress event's
 * shape with token usage zeroed and the per-request metadata substituted:
 *
 * | field | value |
 * |---|---|
 * | `provider` | `static_resource` |
 * | `logical_model` | `static_resource:{name}` |
 * | `provider_model` | `version` |
 * | `usage.*` | `0` — a pull carries no token usage |
 * | `metadata["static_resource_requests"]` | pull count |
 * | `cost_usd` | `requests × price`, gateway-SETTLED (omitted when unpriced) |
 */
export function staticResourceBillingEvent(charge: StaticResourceCharge): BillingEvent {
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
    metadata: { [STATIC_RESOURCE_REQUESTS_METADATA_KEY]: String(charge.requests) },
  };
}

// ---------------------------------------------------------------------------
// Meter
// ---------------------------------------------------------------------------

/** Where a metered pull is settled. Rejections MUST NOT escape the caller. */
export interface StaticResourceMeter {
  record(charge: StaticResourceCharge): void | Promise<void>;
}

/** Resolve a tenant-authoritative ledger for one settled pull. */
export type StaticResourceLedgerResolver = (tenantId: string) => LedgerStore | undefined;

/** Offline meter: the charges, in order. */
export class InMemoryStaticResourceMeter implements StaticResourceMeter {
  readonly charges: StaticResourceCharge[] = [];

  record(charge: StaticResourceCharge): void {
    this.charges.push(charge);
  }
}

/** A meter that drops everything — the posture when no billing sink is bound. */
export const NO_STATIC_RESOURCE_METER: StaticResourceMeter = { record: () => undefined };

/**
 * The DURABLE meter: settle each pull into the same `billing_ledger` /
 * `billing_events` / `billing_report_outbox` rows every inference charge writes.
 * Idempotent on {@link ledgerEntryId}, so a retried pull of the same request id
 * cannot double-charge. An UNPRICED charge is skipped rather than written at $0.
 */
export class LedgerStaticResourceMeter implements StaticResourceMeter {
  readonly #ledger: LedgerStore | StaticResourceLedgerResolver;
  readonly #creditsPerUsd: number;

  constructor(
    ledger: LedgerStore | StaticResourceLedgerResolver,
    priceBook: PriceBook = PriceBook.withDefaultRateCard(),
  ) {
    this.#ledger = ledger;
    this.#creditsPerUsd = priceBook.credits_per_usd;
  }

  async record(charge: StaticResourceCharge): Promise<void> {
    if (charge.costUsd === undefined) return;
    const ledger =
      typeof this.#ledger === "function" ? this.#ledger(charge.tenantId) : this.#ledger;
    if (ledger === undefined) return;
    const event = staticResourceBillingEvent(charge);
    const entry = chargeEvent(PriceBook.default(), event);
    const metered: MeteredCharge = {
      id: ledgerEntryId(event),
      requestId: event.request_id,
      event,
      entry,
      credits: usdToCredits(entry.cost.total_cost, this.#creditsPerUsd),
      occurredAtUnix: charge.occurredAtUnix,
    };
    await ledger.record(metered);
  }
}

// ---------------------------------------------------------------------------
// Record
// ---------------------------------------------------------------------------

export interface RecordStaticResourceInput {
  readonly tenantId: string;
  readonly apiKeyId?: string | undefined;
  readonly projectId?: string | undefined;
  readonly requestId: string;
  readonly agentRunId?: string | undefined;
  /** The pulled resource path (`name`, e.g. `docs/guide.md`). */
  readonly name: string;
  readonly version: string;
  /** How many pulls to settle — defaults to `1` per served GET (design Q-A). */
  readonly requests?: number | undefined;
  /** `static_resource_price_per_request` from config; `null` ⇒ unpriced. */
  readonly pricePerRequest?: number | null | undefined;
  readonly meter: StaticResourceMeter;
  readonly nowUnix: number;
}

/**
 * Meter one (or more) static-resource pulls: best-effort settle the charge and
 * hand it back. A metering failure is swallowed — the bytes have already been
 * served, so it must never become the caller's error. Returns the settled
 * {@link StaticResourceCharge}, or `null` when nothing was billable
 * (`requests <= 0`).
 *
 * The caller decides WHEN to invoke: per design Q-A, only a successful `200`
 * (whole or first slice of a resumed transfer) counts once; `HEAD`/`304` never
 * reach here.
 */
export async function recordStaticResourceRequest(
  input: RecordStaticResourceInput,
): Promise<StaticResourceCharge | null> {
  const requests = input.requests ?? 1;
  if (!Number.isFinite(requests) || requests <= 0) return null;

  const charge: StaticResourceCharge = {
    requestId: input.requestId,
    agentRunId: input.agentRunId,
    tenantId: input.tenantId,
    ...(input.apiKeyId !== undefined && input.apiKeyId !== "" ? { apiKeyId: input.apiKeyId } : {}),
    projectId: input.projectId,
    assetType: STATIC_RESOURCE_PROVIDER,
    name: input.name,
    version: input.version,
    requests,
    provider: STATIC_RESOURCE_PROVIDER,
    logicalModel: `${STATIC_RESOURCE_LOGICAL_MODEL_PREFIX}${input.name}`,
    costUsd: staticResourceRequestCost(requests, input.pricePerRequest),
    occurredAtUnix: input.nowUnix,
  };

  try {
    await input.meter.record(charge);
  } catch {
    // Deliberately swallowed, mirroring `recordAssetEgress`: a served pull must
    // not turn into an error because the billing sink was momentarily down.
  }

  return charge;
}

/** Rust-parity pull audit message, size-free variant. */
export function staticResourcePullAuditMessage(assetId: string, requests: number): string {
  return `static resource ${assetId} pulled (${requests} request${requests === 1 ? "" : "s"})`;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * The durable pull meter for one `env`, or `null` when no billing database is
 * bound. Tenant-aware callers supply a resolver so each charge settles against
 * its own tenant authority; without one this uses the shared `BILLING_DB` path.
 */
export function staticResourceMeterFromEnv(
  env: unknown,
  tenantLedger?: StaticResourceLedgerResolver,
): StaticResourceMeter | null {
  if (tenantLedger !== undefined) return new LedgerStaticResourceMeter(tenantLedger);
  const db = meteringDatabaseFrom(env);
  return db === undefined ? null : new LedgerStaticResourceMeter(new D1LedgerStore(db));
}
