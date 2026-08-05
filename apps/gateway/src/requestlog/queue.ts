/**
 * The CONSUMER half of the request-log queue — `export default { queue }` on
 * `src/worker.ts`.
 *
 * ## Why the gateway consumes its own queue
 *
 * `[[queues.producers]] BILLING` is producer-only on this Worker, and its
 * stanza says why: the consumer belongs to whoever settles wallets downstream.
 * Request logs are the opposite case. A message is written to the tenant's
 * authoritative object and then to the CONTROL database compatibility
 * projection; this Worker already binds both because the guardrail policy
 * source reads from the control database. Routing the message to a second
 * Worker would add a deploy unit, a second `wrangler.toml` and a second set of
 * credentials to be able to do exactly the same writes.
 *
 * A Worker consuming a queue it produces is a supported Cloudflare topology; it
 * is a separate invocation with its own `env`, not a re-entrant call.
 *
 * ## The batch contract, and why a bad message does not poison a good one
 *
 * Queues are AT LEAST ONCE. The tenant-object write is keyed on `request_id`,
 * while the control projection is keyed on its tenant-qualified
 * `projection_key` (`d1.ts`). A redelivered message therefore re-applies the
 * same row instead of failing on the primary key, which is what makes
 * `retryAll()` on a partial failure safe rather than a loop.
 *
 * A message whose body does not decode is `ack()`ed and counted, NOT retried:
 * it cannot become valid on redelivery, and retrying it would keep a
 * permanently-bad message in front of good evidence until it dead-lettered.
 * `requestLogFromWire` is total and returns `undefined` for exactly that case.
 *
 * Each tenant group is written in ONE object batch, and the compatibility rows
 * plus the derived guardrail projection are written in ONE CONTROL batch.
 * On failure the delivery is retried whole — with the upsert, rows that had
 * already landed are simply re-applied.
 */
import {
  guardrailEvidenceStatements,
  tenantGuardrailEvidenceStatements,
} from "../guardrails/evidence-d1.js";
import {
  type GuardrailEvidenceEnvelope,
  guardrailEvidenceFromWire,
} from "../guardrails/evidence-wire.js";
import {
  REQUEST_LOG_UPSERT_SQL,
  type RequestLogDatabase,
  TENANT_REQUEST_LOG_UPSERT_SQL,
  requestLogBindings,
  tenantRequestLogBindings,
} from "./d1.js";
import { requestLogFromWire } from "./record.js";
import { requestLogDatabaseFrom, requestLogTenantDatabaseFromEnv } from "./sink.js";

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

/**
 * Apply one queue delivery to tenant-authoritative `request_logs` and its
 * derived control projection.
 *
 * NEVER throws: a consumer that throws gets its batch redelivered by the
 * platform anyway, so throwing would only lose the ability to say what
 * happened. Failure is reported by arming `retryAll()` and returning
 * `retried: true`.
 */
export async function consumeRequestLogBatch(
  batch: RequestLogMessageBatch,
  env: unknown,
  databaseOf: (env: unknown) => RequestLogDatabase | undefined = requestLogDatabaseFrom,
  tenantDatabaseOf: (
    env: unknown,
    tenantId: string,
  ) => RequestLogDatabase | undefined = requestLogTenantDatabaseFromEnv,
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
    for (const record of records) {
      if (record.tenantId === undefined || record.tenantId === "") continue;
      const group = byTenant.get(record.tenantId) ?? { records: [], evidence: [] };
      group.records.push(record);
      byTenant.set(record.tenantId, group);
    }
    for (const envelope of evidence) {
      const tenantId = envelope.evaluation.tenant.organizationId;
      if (typeof tenantId !== "string" || tenantId.trim() === "") continue;
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

    const projection = databaseOf(env);
    if (projection === undefined) throw new Error("derived request-log projection is unavailable");

    // The control batch is only the request-log compatibility projection plus
    // the derived guardrail projection. It is not the source of truth for the
    // tenant rows above.
    const requestLogStatement = projection.prepare(REQUEST_LOG_UPSERT_SQL);
    const statements = [
      ...records.map((record) => requestLogStatement.bind(...requestLogBindings(record))),
      ...guardrailEvidenceStatements(projection, evidence),
    ];
    await projection.batch(statements);
    return { written: records.length + evidence.length, malformed, retried: false };
  } catch {
    batch.retryAll?.();
    return { written: 0, malformed, retried: true };
  }
}
