/**
 * The CONSUMER half of the request-log queue — `export default { queue }` on
 * `src/worker.ts`.
 *
 * ## Why the gateway consumes its own queue
 *
 * `[[queues.producers]] BILLING` is producer-only on this Worker, and its
 * stanza says why: the consumer belongs to whoever settles wallets downstream.
 * Request logs are the opposite case. A message is written to the tenant's
 * authoritative object (attributed rows) or the PLATFORM_DATA singleton
 * (un-attributed rows); this Worker already binds both. Routing the message to a
 * second Worker would add a deploy unit, a second `wrangler.toml` and a second
 * set of credentials to be able to do exactly the same writes.
 *
 * A Worker consuming a queue it produces is a supported Cloudflare topology; it
 * is a separate invocation with its own `env`, not a re-entrant call.
 *
 * Track A: there is no shared-CONTROL projection any more. Attributed rows live
 * only in their tenant object, un-attributed rows only in PLATFORM_DATA.
 *
 * ## The batch contract, and why a bad message does not poison a good one
 *
 * Queues are AT LEAST ONCE. Every object write is keyed on `request_id` (an
 * upsert), so a redelivered message re-applies the same row instead of failing
 * on the primary key, which is what makes `retryAll()` on a partial failure safe
 * rather than a loop.
 *
 * A message whose body does not decode is `ack()`ed and counted, NOT retried:
 * it cannot become valid on redelivery, and retrying it would keep a
 * permanently-bad message in front of good evidence until it dead-lettered.
 * `requestLogFromWire` is total and returns `undefined` for exactly that case.
 *
 * Each tenant group is written in ONE object batch and the un-attributed rows in
 * ONE PLATFORM_DATA batch. On failure the delivery is retried whole — with the
 * upsert, rows that had already landed are simply re-applied.
 */
import {
  type GuardrailEvidenceDatabase,
  platformGuardrailEvidenceStatements,
  tenantGuardrailEvidenceStatements,
} from "../guardrails/evidence-d1.js";
import { guardrailEvidencePlatformDatabaseFrom } from "../guardrails/evidence-sink.js";
import {
  GUARDRAIL_EVALUATION_OBJECT,
  type GuardrailEvidenceEnvelope,
  guardrailEvidenceFromWire,
} from "../guardrails/evidence-wire.js";
import {
  type RequestLogDatabase,
  TENANT_REQUEST_LOG_UPSERT_SQL,
  platformRequestLogStatements,
  tenantRequestLogBindings,
} from "./d1.js";
import { requestLogFromWire } from "./record.js";
import { requestLogTenantDatabaseFromEnv } from "./sink.js";

/** The `MessageBatch` slice this consumer uses, structurally. */
export interface RequestLogMessageBatch {
  readonly queue?: string;
  readonly messages: readonly { readonly body: unknown; ack?(): void }[];
  retryAll?(options?: unknown): void;
}

/** What one delivery did, for the caller's diagnostics. */
export interface RequestLogConsumeResult {
  /** Messages decoded into a record and handed to D1. */
  readonly written: number;
  /** Messages whose body could not be decoded; acked, never retried. */
  readonly malformed: number;
  /** True when the batch was handed back for redelivery. */
  readonly retried: boolean;
}

function isGuardrailEvidenceBody(body: unknown): boolean {
  return (
    typeof body === "object" &&
    body !== null &&
    (body as { object?: unknown }).object === GUARDRAIL_EVALUATION_OBJECT
  );
}

/**
 * Apply one queue delivery to its authoritative homes: attributed rows to each
 * tenant's own object, un-attributed rows to the PLATFORM_DATA singleton.
 *
 * NEVER throws: a consumer that throws gets its batch redelivered by the
 * platform anyway, so throwing would only lose the ability to say what
 * happened. Failure is reported by arming `retryAll()` and returning
 * `retried: true`.
 */
export async function consumeRequestLogBatch(
  batch: RequestLogMessageBatch,
  env: unknown,
  tenantDatabaseOf: (
    env: unknown,
    tenantId: string,
  ) => RequestLogDatabase | undefined = requestLogTenantDatabaseFromEnv,
  // Track A: resolver for the PLATFORM_DATA singleton — the sole authoritative
  // home of un-attributed request logs and guardrail evidence. Default reads
  // `env.PLATFORM_DATA`.
  platformDatabaseOf: (
    env: unknown,
  ) => GuardrailEvidenceDatabase | undefined = guardrailEvidencePlatformDatabaseFrom,
): Promise<RequestLogConsumeResult> {
  const records = [];
  const evidence: GuardrailEvidenceEnvelope[] = [];
  let malformed = 0;
  for (const message of batch.messages) {
    // GUARDRAIL EVIDENCE IS TRIED FIRST, and the order is load-bearing (#665).
    // `requestLogFromWire` is permissive — it fills defaults for every field it
    // cannot find — so handing it a guardrail message would not fail, it would
    // succeed and write a plausible, wrong `request_logs` row. Discriminating
    // on `object` BEFORE decoding is what stops that.
    const envelope = guardrailEvidenceFromWire(message.body);
    if (envelope !== undefined) {
      evidence.push(envelope);
      continue;
    }
    if (isGuardrailEvidenceBody(message.body)) {
      malformed += 1;
      // A guardrail discriminator with an invalid payload must not fall
      // through to the permissive request-log decoder.
      message.ack?.();
      continue;
    }
    const record = requestLogFromWire(message.body);
    if (record === undefined) {
      malformed += 1;
      // Ack the undecodable message explicitly so `retryAll()` below (if the
      // rest of the batch fails) does not drag it along forever.
      message.ack?.();
      continue;
    }
    records.push(record);
  }

  if (records.length === 0 && evidence.length === 0) {
    return { written: 0, malformed, retried: false };
  }

  try {
    // One object batch per tenant preserves append throughput and the
    // transaction boundary without pretending that two objects share a
    // transaction. Retries are safe because every row is an upsert.
    const byTenant = new Map<
      string,
      { records: typeof records; evidence: GuardrailEvidenceEnvelope[] }
    >();
    // Unscoped/platform request logs (empty tenant) have no tenant object; their
    // sole authoritative home is the PLATFORM_DATA singleton, written below.
    const unscopedRecords: typeof records = [];
    for (const record of records) {
      if (record.tenantId === undefined || record.tenantId === "") {
        unscopedRecords.push(record);
        continue;
      }
      const group = byTenant.get(record.tenantId) ?? { records: [], evidence: [] };
      group.records.push(record);
      byTenant.set(record.tenantId, group);
    }
    // Unscoped/platform evidence (empty tenant) has no tenant object; its sole
    // authoritative home is the PLATFORM_DATA singleton, written below.
    const unscoped: GuardrailEvidenceEnvelope[] = [];
    for (const envelope of evidence) {
      const tenantId = envelope.evaluation.tenant.organizationId;
      if (typeof tenantId !== "string" || tenantId.trim() === "") {
        unscoped.push(envelope);
        continue;
      }
      const group = byTenant.get(tenantId) ?? { records: [], evidence: [] };
      group.evidence.push(envelope);
      byTenant.set(tenantId, group);
    }
    for (const [tenantId, group] of byTenant) {
      const tenantDb = tenantDatabaseOf(env, tenantId);
      if (tenantDb === undefined) {
        throw new Error(`authoritative TenantDataObject is unavailable for tenant ${tenantId}`);
      }
      const statements: unknown[] = [];
      if (group.records.length > 0) {
        const statement = tenantDb.prepare(TENANT_REQUEST_LOG_UPSERT_SQL);
        statements.push(
          ...group.records.map((record) => statement.bind(...tenantRequestLogBindings(record))),
        );
      }
      statements.push(...tenantGuardrailEvidenceStatements(tenantDb, group.evidence));
      await tenantDb.batch(statements);
    }

    // Un-attributed (platform-operator) request logs and guardrail evidence have
    // no tenant object; the PLATFORM_DATA singleton is their SOLE authoritative
    // home. Track A removed the shared-CONTROL projection, so these are the only
    // writes for unscoped rows — and therefore INSIDE the retry contract: a
    // platform-object failure must re-drive the batch, exactly like a tenant
    // write, because every row is an idempotent upsert and losing it would lose
    // evidence. A missing PLATFORM_DATA binding with unscoped rows to write is a
    // misconfiguration; throwing arms `retryAll()` rather than dropping evidence.
    if (unscopedRecords.length > 0 || unscoped.length > 0) {
      const platformDb = platformDatabaseOf(env);
      if (platformDb === undefined) {
        throw new Error("authoritative PlatformDataObject is unavailable for un-attributed rows");
      }
      if (unscopedRecords.length > 0) {
        await platformDb.batch(platformRequestLogStatements(platformDb, unscopedRecords));
      }
      if (unscoped.length > 0) {
        await platformDb.batch(platformGuardrailEvidenceStatements(platformDb, unscoped));
      }
    }

    return { written: records.length + evidence.length, malformed, retried: false };
  } catch (error) {
    // Log BEFORE the retry. A bare `catch {}` here left a failing consumer with
    // no signal at all: `retryAll()` re-queues the batch, it fails again, and
    // after the max attempts every message dead-letters — with nothing in the
    // logs to say why. `console.warn` reaches the Worker's log stream (same
    // channel `src/index.ts` uses), so an operator watching a filling DLQ can
    // see the cause (a missing tenant object, a schema gap, a D1 outage) instead
    // of guessing. The message is still retried; this only makes the failure
    // observable.
    console.warn(
      `[ferrogate] request-log consumer batch failed, retrying ${batch.messages.length} message(s): ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    batch.retryAll?.();
    return { written: 0, malformed, retried: true };
  }
}
