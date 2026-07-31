/**
 * JSON encoding for the two storage documents the metering tables carry —
 * `event_json` and `entry_json`.
 *
 * Fidelity rule, taken from the Rust `serialize_storage_document`: the document
 * is serde's, so `Option<i64>` renders as a JSON NUMBER and an absent field is
 * omitted rather than written as `null`. `@ferrogate/billing` already ships
 * `ledgerEntryToWire` for the entry half (it flattens `provider_attempt` and
 * renders the wallet `i64`s as numbers, exactly as serde does); the event half
 * has a parser (`billingEventWireSchema`) but no writer, so {@link
 * billingEventToWire} supplies the mirror image.
 *
 * The `bigint`→`number` narrowing in these documents is DELIBERATE and is not
 * where precision is kept: the authoritative integer-credit figure travels in
 * its own lossless decimal-string column / field (`credits`), never inside the
 * JSON blob. See `credits.ts` and the `MeteringQueueMessage` doc.
 */
import {
  billingEventWireSchema,
  ledgerEntryToWire,
  ledgerEntryWireSchema,
  type BillingEvent,
  type LedgerEntry,
} from "@ferrogate/billing";

/** serde's `skip_serializing_if = "Option::is_none"`: absent, not `null`. */
function put(target: Record<string, unknown>, key: string, value: unknown): void {
  if (value !== undefined) {
    target[key] = value;
  }
}

/** `BillingEvent` → the flat serde JSON object (`event_json`). */
export function billingEventToWire(event: BillingEvent): Record<string, unknown> {
  const wire: Record<string, unknown> = {
    request_id: event.request_id,
    provider_attempt_id: event.provider_attempt.provider_attempt_id,
    provider_attempt_index: event.provider_attempt.provider_attempt_index,
    tenant: event.tenant,
    logical_model: event.logical_model,
    provider: event.provider,
    provider_model: event.provider_model,
    usage: event.usage,
    usage_source: event.usage_source,
    status_code: event.status_code,
    metadata: event.metadata,
  };
  put(wire, "trace_id", event.trace_id);
  put(wire, "agent_run_id", event.agent_run_id);
  put(wire, "workflow_id", event.workflow_id);
  put(wire, "workflow_version", event.workflow_version);
  put(wire, "workflow_node_id", event.workflow_node_id);
  put(wire, "cluster_id", event.cluster_id);
  put(wire, "node_id", event.node_id);
  put(wire, "occurred_at_unix", event.occurred_at_unix);
  put(wire, "cost_usd", event.cost_usd);
  put(wire, "latency_ms", event.latency_ms);
  put(
    wire,
    "wallet_delta_credits",
    event.wallet_delta_credits === undefined ? undefined : Number(event.wallet_delta_credits),
  );
  put(
    wire,
    "wallet_balance_after_credits",
    event.wallet_balance_after_credits === undefined
      ? undefined
      : Number(event.wallet_balance_after_credits),
  );
  return wire;
}

/** `LedgerEntry` → the flat serde JSON object (`entry_json`). */
export function ledgerEntryToWireDocument(entry: LedgerEntry): Record<string, unknown> {
  return ledgerEntryToWire(entry);
}

/** Inverse of {@link billingEventToWire}; throws on a malformed document. */
export function billingEventFromWire(value: unknown): BillingEvent {
  return billingEventWireSchema.parse(value);
}

/** Inverse of {@link ledgerEntryToWireDocument}; throws on a malformed document. */
export function ledgerEntryFromWire(value: unknown): LedgerEntry {
  return ledgerEntryWireSchema.parse(value);
}

/**
 * Lossless `bigint` transport.
 *
 * A decimal string is the only representation that survives JSON, D1's TEXT
 * columns and a Queue body without a 2^53 truncation, which is the entire point
 * of holding credits as `bigint` in the first place.
 */
export function creditsToWire(credits: bigint): string {
  return credits.toString(10);
}

/** Inverse of {@link creditsToWire}; throws rather than yielding a wrong charge. */
export function creditsFromWire(value: unknown): bigint {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "string" && /^[+-]?\d+$/.test(value)) {
    return BigInt(value);
  }
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return BigInt(value);
  }
  throw new TypeError(`credits value ${String(value)} is not a lossless integer`);
}
