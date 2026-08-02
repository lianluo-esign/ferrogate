/**
 * The billing wire event and its retention sink — clean-room port of the
 * `BillingEvent`, `BillingError`, metadata-bounds, and `BillingEventSink`
 * surface in `ferrogate-billing`'s `lib.rs`.
 *
 * Wire fidelity: `provider_attempt` is serialized FLAT (`#[serde(flatten)]`),
 * so {@link billingEventWireSchema} reads/writes `provider_attempt_id` /
 * `provider_attempt_index` at the top level and nests them on the in-memory
 * struct, exactly as serde does. The wallet integer domain
 * (`wallet_delta_credits`, `wallet_balance_after_credits`, Rust `i64`) is kept
 * as `bigint` per the inventory's no-drift directive (§2.5); it round-trips to
 * a JSON number on the wire (matching Rust `i64` serialization).
 */
import { z } from "zod";
import { tenantContextSchema, type TenantContext } from "@ferrogate/core";
import {
  billingUsageSourceSchema,
  tokenUsageSchema,
  u16,
  u32,
  u64,
  type BillingUsageSource,
  type ProviderAttempt,
  type TokenUsage,
} from "./usage.js";

// ---------------------------------------------------------------------------
// BillingError — the crate's typed billing-domain failure {code, message}.
// ---------------------------------------------------------------------------

/**
 * Port of Rust `struct BillingError { code, message }`. Thrown across the
 * charge / sink seam so the HTTP boundary can classify it
 * ({@link ../service.ts billingErrorHttpStatus}).
 */
export class BillingError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "BillingError";
    this.code = code;
  }
  /** Mirrors `BillingError::new`. */
  static new(code: string, message: string): BillingError {
    return new BillingError(code, message);
  }
}

// ---------------------------------------------------------------------------
// Request-metadata bounds (issue #171).
// ---------------------------------------------------------------------------

/** Max metadata key/value pairs a request may attach (issue #171). */
export const MAX_METADATA_ENTRIES = 8;
/** Max UTF-8 byte length of a single metadata key (issue #171). */
export const MAX_METADATA_KEY_LEN = 64;
/** Max UTF-8 byte length of a single metadata value (issue #171). */
export const MAX_METADATA_VALUE_LEN = 256;

const UTF8 = new TextEncoder();
function byteLen(value: string): number {
  return UTF8.encode(value).length;
}

/**
 * Validate a caller-supplied request metadata map against the entry-count /
 * key-length / value-length bounds (issue #171). Returns `null` when valid,
 * otherwise a human-readable reason for the first violation (mirrors Rust
 * `Result<(), String>`).
 */
export function validateRequestMetadata(
  metadata: Record<string, string>,
): string | null {
  const keys = Object.keys(metadata);
  if (keys.length > MAX_METADATA_ENTRIES) {
    return `metadata supports at most ${MAX_METADATA_ENTRIES} entries, got ${keys.length}`;
  }
  for (const key of keys) {
    const value = metadata[key] ?? "";
    if (key.length === 0) {
      return "metadata keys must not be empty";
    }
    if (byteLen(key) > MAX_METADATA_KEY_LEN) {
      return `metadata key ${JSON.stringify(key)} exceeds the ${MAX_METADATA_KEY_LEN}-byte limit`;
    }
    if (byteLen(value) > MAX_METADATA_VALUE_LEN) {
      return `metadata value for key ${JSON.stringify(key)} exceeds the ${MAX_METADATA_VALUE_LEN}-byte limit`;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// BillingEvent — the wire event forwarded by the gateway.
// ---------------------------------------------------------------------------

export interface BillingEvent {
  request_id: string;
  trace_id?: string;
  provider_attempt: ProviderAttempt;
  agent_run_id?: string;
  workflow_id?: string;
  workflow_version?: number;
  workflow_node_id?: string;
  cluster_id?: string;
  node_id?: string;
  tenant: TenantContext;
  logical_model: string;
  provider: string;
  provider_model: string;
  usage: TokenUsage;
  usage_source: BillingUsageSource;
  status_code: number;
  occurred_at_unix?: number;
  cost_usd?: number;
  latency_ms?: number;
  metadata: Record<string, string>;
  /** Prepaid-wallet debit for this request (issue #169); always negative. */
  wallet_delta_credits?: bigint;
  /** Wallet balance immediately after the debit (issue #169). */
  wallet_balance_after_credits?: bigint;
}

const optStr = z.string().nullish().transform((v) => v ?? undefined);
/** `Option<i64>` on the wire is a JSON number; keep it as `bigint` internally. */
const optI64 = z
  .union([z.bigint(), z.number().int()])
  .nullish()
  .transform((v) => (v == null ? undefined : BigInt(v)));

/**
 * Parses the flat serde wire form of a {@link BillingEvent} (flattened
 * provider-attempt keys, snake_case) and nests `provider_attempt`. Unknown
 * keys are ignored (Rust has no `deny_unknown_fields`).
 */
export const billingEventWireSchema = z
  .object({
    request_id: z.string(),
    trace_id: optStr,
    provider_attempt_id: z.string().default(""),
    provider_attempt_index: u32.default(0),
    agent_run_id: optStr,
    workflow_id: optStr,
    workflow_version: u32.nullish().transform((v) => v ?? undefined),
    workflow_node_id: optStr,
    cluster_id: optStr,
    node_id: optStr,
    tenant: tenantContextSchema,
    logical_model: z.string(),
    provider: z.string(),
    provider_model: z.string(),
    usage: tokenUsageSchema,
    usage_source: billingUsageSourceSchema.default("provider_usage"),
    status_code: u16,
    occurred_at_unix: u64.nullish().transform((v) => v ?? undefined),
    cost_usd: z.number().nullish().transform((v) => v ?? undefined),
    latency_ms: u64.nullish().transform((v) => v ?? undefined),
    metadata: z.record(z.string()).default({}),
    wallet_delta_credits: optI64,
    wallet_balance_after_credits: optI64,
  })
  .transform((w): BillingEvent => ({
    request_id: w.request_id,
    trace_id: w.trace_id,
    provider_attempt: {
      provider_attempt_id: w.provider_attempt_id,
      provider_attempt_index: w.provider_attempt_index,
    },
    agent_run_id: w.agent_run_id,
    workflow_id: w.workflow_id,
    workflow_version: w.workflow_version,
    workflow_node_id: w.workflow_node_id,
    cluster_id: w.cluster_id,
    node_id: w.node_id,
    tenant: w.tenant,
    logical_model: w.logical_model,
    provider: w.provider,
    provider_model: w.provider_model,
    usage: w.usage,
    usage_source: w.usage_source,
    status_code: w.status_code,
    occurred_at_unix: w.occurred_at_unix,
    cost_usd: w.cost_usd,
    latency_ms: w.latency_ms,
    metadata: w.metadata,
    wallet_delta_credits: w.wallet_delta_credits,
    wallet_balance_after_credits: w.wallet_balance_after_credits,
  }));

/** Parse an untrusted JSON value into a {@link BillingEvent} (throws on invalid). */
export function parseBillingEvent(value: unknown): BillingEvent {
  return billingEventWireSchema.parse(value);
}

// ---------------------------------------------------------------------------
// BillingEventSink + bounded in-memory implementation.
// ---------------------------------------------------------------------------

/** Port of `trait BillingEventSink { record, list }`. */
export interface BillingEventSink {
  record(event: BillingEvent): void;
  list(): BillingEvent[];
}

/**
 * Bounded, FIFO in-memory retention buffer (port of `InMemoryBillingEventSink`).
 * A `retention_limit` evicts the oldest events once exceeded. No lock-poisoning
 * path exists in single-threaded JS, so those Rust error branches collapse.
 */
export class InMemoryBillingEventSink implements BillingEventSink {
  private events: BillingEvent[] = [];
  private retentionLimit: number | undefined;
  private recordedTotalCount = 0;

  constructor(retentionLimit?: number) {
    this.retentionLimit = retentionLimit;
  }

  /** Mirrors `InMemoryBillingEventSink::with_retention_limit`. */
  static withRetentionLimit(retentionLimit: number): InMemoryBillingEventSink {
    return new InMemoryBillingEventSink(retentionLimit);
  }

  setRetentionLimit(retentionLimit: number): void {
    this.retentionLimit = retentionLimit;
    this.enforceRetention();
  }

  record(event: BillingEvent): void {
    this.events.push(event);
    this.recordedTotalCount += 1;
    this.enforceRetention();
  }

  list(): BillingEvent[] {
    return this.events.map((e) => ({ ...e }));
  }

  listPaginated(offset: number, limit: number): BillingEvent[] {
    return this.events.slice(offset, offset + limit).map((e) => ({ ...e }));
  }

  get length(): number {
    return this.events.length;
  }

  isEmpty(): boolean {
    return this.events.length === 0;
  }

  recordedTotal(): number {
    return this.recordedTotalCount;
  }

  private enforceRetention(): void {
    if (this.retentionLimit !== undefined) {
      while (this.events.length > this.retentionLimit) {
        this.events.shift();
      }
    }
  }
}
