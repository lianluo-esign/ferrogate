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
  type GuardrailEvidenceDatabase,
  guardrailEvidenceStatements,
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
  REQUEST_LOG_UPSERT_SQL,
  type RequestLogDatabase,
  TENANT_REQUEST_LOG_UPSERT_SQL,
  platformRequestLogStatements,
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

function isGuardrailEvidenceBody(body: unknown): boolean {
  return (
    typeof body === "object" &&
    body !== null &&
    (body as { object?: unknown }).object === GUARDRAIL_EVALUATION_OBJECT
  );
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
  // Zero-D1 Plan B: resolver for the PLATFORM_DATA singleton. Default reads
  // `env.PLATFORM_DATA`; a unit env or a not-yet-migrated Worker returns
  // undefined and the platform dual-write leg is skipped.
  platformDatabaseOf: (
    env: unknown,
  ) => GuardrailEvidenceDatabase | undefined = guardrailEvidencePlatformDatabaseFrom,
  // Track A / G2: each control-projection leg is independently gated so it can be
  // retired the moment its last reader moves off the control mirror. Both default
  // to true so the dual-write tests are unchanged; production wires them false.
  //
  //  - `projectGuardrailToControl` false drops the derived guardrail projection
  //    (tenant object + PLATFORM_DATA are its sole homes).
  //  - `projectRequestLogToControl` false drops the request_logs compatibility
  //    projection. Safe since #825 moved the SIEM pump onto the tenant object and
  //    the finops JOIN readers (request_logs⋈billing_events) fan out over the
  //    tenant/platform objects — the control projection now has ZERO runtime
  //    readers. Un-attributed rows keep their PLATFORM_DATA home (the dual-write
  //    leg below), so nothing is dropped; only the shared-DO mirror stops growing.
  //
  // Both are reversible — flipping back re-arms the dual write.
  options: { projectGuardrailToControl?: boolean; projectRequestLogToControl?: boolean } = {},
): Promise<RequestLogConsumeResult> {
  const projectGuardrailToControl = options.projectGuardrailToControl ?? true;
  const projectRequestLogToControl = options.projectRequestLogToControl ?? true;
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
    // Unscoped/platform request logs (empty tenant) have no tenant object; they
    // land in the control projection below and — Zero-D1 Plan B — also in
    // PLATFORM_DATA, the authoritative home the operator list is READ from once
    // the control projection is retired.
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
    // Unscoped/platform evidence (empty tenant) has no tenant object; it goes to
    // the control projection below and — Zero-D1 Plan B — also to PLATFORM_DATA.
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

    const projection = databaseOf(env);
    if (projection === undefined) throw new Error("derived request-log projection is unavailable");

    // The control batch is the request-log compatibility projection and the
    // derived guardrail projection, each UNLESS gated off by its G2 flag. It is
    // not the source of truth for the tenant rows above. With both flags false
    // the batch is empty and skipped entirely; with either preserved only that
    // leg is written.
    const statements: unknown[] = [];
    if (projectRequestLogToControl && records.length > 0) {
      const requestLogStatement = projection.prepare(REQUEST_LOG_UPSERT_SQL);
      statements.push(
        ...records.map((record) => requestLogStatement.bind(...requestLogBindings(record))),
      );
    }
    if (projectGuardrailToControl) {
      statements.push(...guardrailEvidenceStatements(projection, evidence));
    }
    if (statements.length > 0) {
      await projection.batch(statements);
    }

    // Zero-D1 Plan B (G1 dual-write): unscoped/platform request logs ALSO land in
    // the PLATFORM_DATA singleton — the authoritative home the operator list is
    // READ from once the control projection is retired. Same contract as the
    // guardrail platform leg below: OUTSIDE `retryAll()`, in its own try/catch,
    // because the tenant, request-log and control writes above have already
    // committed and a platform-object blip must not re-drive committed evidence.
    // The one-time CP1 backfill plus this ongoing dual-write reconcile any gap,
    // so a swallowed failure here is at most a briefly-stale platform read.
    if (unscopedRecords.length > 0) {
      try {
        const platformDb = platformDatabaseOf(env);
        if (platformDb !== undefined) {
          await platformDb.batch(platformRequestLogStatements(platformDb, unscopedRecords));
        }
      } catch (error) {
        console.warn(
          `[ferrogate] platform request-log dual-write failed for ${unscopedRecords.length} row(s); control projection is unaffected: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
    }

    // Zero-D1 Plan B (G1 dual-write): unscoped/platform evidence ALSO lands in
    // the PLATFORM_DATA singleton — the authoritative home it will be READ from
    // once the control projection is retired. Deliberately OUTSIDE the retry
    // contract, in its own try/catch: the tenant, request-log and control
    // projection writes above have already committed, so a platform-object blip
    // must NOT arm `retryAll()` and re-drive (or dead-letter) that committed
    // evidence. The one-time CP1 backfill plus this ongoing dual-write reconcile
    // any gap, so a swallowed failure here is at most a briefly-stale platform
    // read, never lost evidence.
    if (unscoped.length > 0) {
      try {
        const platformDb = platformDatabaseOf(env);
        if (platformDb !== undefined) {
          await platformDb.batch(platformGuardrailEvidenceStatements(platformDb, unscoped));
        }
      } catch (error) {
        console.warn(
          `[ferrogate] platform guardrail evidence dual-write failed for ${unscoped.length} row(s); control projection is unaffected: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
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
