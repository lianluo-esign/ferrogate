/**
 * `apps/gateway/src/requestlog` — a durable record of every decision the data
 * plane makes (#664).
 *
 * ============================================================================
 * THE DEFECT THIS SLICE CLOSES
 * ============================================================================
 *
 * `GET /admin/v1/request-logs` and `/admin/v1/request-log-exports` were
 * mounted, authenticated and contract-listed, and answered `200 []` on EVERY
 * deployment. The control schema had a `request_logs` table with **no writer
 * and no reader anywhere in `apps/<app>/src`** — zero `INSERT INTO
 * request_logs` across the tree. The gateway metered to
 * `billing_events`/`billing_ledger` and emitted telemetry, and persisted not
 * one request log row.
 *
 * That is the codebase's stated dominant failure mode in its most dangerous
 * form: a live, authenticated, contract-conformant API answering *nothing
 * happened* where an auditor expects a record. The absence of a row is how you
 * conclude a decision was not made, so this failure lies rather than errors.
 *
 * ============================================================================
 * WIRING — LIVE. `src/index.ts` builds it like this:
 * ============================================================================
 *
 * ```ts
 * const requestLogs = createRequestLogSink({ ...requestLogBindingsFromEnv });
 *
 * export const GATEWAY_MIDDLEWARE = [
 *   meteringDrain(usage),
 *   requestTelemetry(),
 *   requestLogging(requestLogs),   // ← ahead of rateLimit/guardrails, on purpose
 *   rateLimit(),
 *   guardrails(...),
 *   tenantDatabase(),
 * ];
 * ```
 *
 * and `src/worker.ts` exposes the Queue consumer:
 *
 * ```ts
 * const handler: ExportedHandler = {
 *   fetch, scheduled,
 *   queue: (batch, env) => gatewayQueue(batch, env),
 * };
 * ```
 *
 * `wrangler.toml` declares the bindings those read:
 * `[[queues.producers]] binding = "REQUEST_LOG"` with the matching
 * `[[queues.consumers]]`, the `TENANT_DATA` Durable Object, and the
 * `[[d1_databases]] binding = "CONTROL_DB"` compatibility projection.
 *
 * ============================================================================
 * THE SHAPE, AND THE ONE RULE
 * ============================================================================
 *
 * ```
 *   request  ─→ requestLogging()  ─→ … rateLimit / guardrails / routes …
 *                     │                         │           │
 *                     │                    contributes  contributes
 *                     │                     verdict      model/tokens
 *                     │                         └── facts.ts (WeakMap by Request)
 *                     └── ctx.waitUntil(sink.write(record))
 *                                │
 *                                ├── Queue REQUEST_LOG ─→ queue() ─→ tenant object batch
 *                                │                                      └→ D1 projection
 *                                └── (no queue) ────────────────→ tenant object → projection
 * ```
 *
 * **THE HOT PATH IS NEVER ON THE WRITE, AND A LOGGING FAILURE IS NEVER A
 * REQUEST FAILURE.** Every branch above runs inside `ctx.waitUntil`, after the
 * response object exists; every failure is swallowed and counted
 * (`RequestLogSink.stats`). The one thing that is deliberately deferred FURTHER
 * is a streamed response, whose token counts arrive from the usage tap near the
 * end of the body — see `./middleware.ts`.
 *
 * ### What is NOT here
 *
 * Two things the issue's suggested Cloudflare shape names are deliberately not
 * in this change, and neither is a "Done when" criterion:
 *
 *  - **R2 request/response BODIES keyed by request id.** A body archive is a
 *    different product decision from a decision LOG — it is the surface with
 *    the PII, the residency and the redaction questions attached, and shipping
 *    it as a side effect of an audit-trail slice would be shipping an
 *    unreviewed data-retention policy. The row carries the request id, so a
 *    later body store keys off it with no migration here.
 *  - **Analytics Engine aggregate counters.** `apps/telemetry` already owns the
 *    only `writeDataPoint` binding in the fleet and already receives a
 *    per-request metric point from `src/telemetry/emit.ts`. Adding a SECOND
 *    aggregate path from this slice would double-count exactly the series an
 *    operator bills from.
 */
export { contributeRequestLogFacts, requestLogFactsFor } from "./facts.js";
export type { RequestLogFacts } from "./facts.js";

export {
  REQUEST_LOG_OBJECT,
  requestLogFromWire,
  requestLogToWire,
} from "./record.js";
export type { GuardrailVerdict, RequestLogRecord, RequestLogWire } from "./record.js";

export {
  REQUEST_LOG_PROJECTION_TABLE,
  REQUEST_LOG_TABLE,
  REQUEST_LOG_UPSERT_SQL,
  TENANT_REQUEST_LOG_UPSERT_SQL,
  evidenceProjectionKey,
  requestLogBindings,
  tenantRequestLogBindings,
  requestLogTenantDatabaseFrom,
  writeRequestLogs,
  writeTenantRequestLogs,
} from "./d1.js";
export type { RequestLogDatabase } from "./d1.js";

export {
  RequestLogSink,
  createRequestLogSink,
  requestLogBindingsFromEnv,
  requestLogDatabaseFrom,
  requestLogPlatformDatabaseFrom,
  requestLogQueueFrom,
  requestLogTenantDatabaseFromEnv,
} from "./sink.js";
export type {
  RequestLogBindings,
  RequestLogDiagnostics,
  RequestLogQueue,
  RequestLogRuntime,
  RequestLogSinkOptions,
  RequestLogStats,
} from "./sink.js";

export { consumeRequestLogBatch } from "./queue.js";
export type { RequestLogConsumeResult, RequestLogMessageBatch } from "./queue.js";

export { requestLogRecordFrom, requestLogging } from "./middleware.js";

export {
  REQUEST_LOG_RETENTION_DAYS_VAR,
  REQUEST_LOG_RETENTION_POLICIES_VAR,
  REQUEST_LOG_SWEEP_MAX_ROWS,
  requestLogRetentionFromEnv,
  sweepPlatformRequestLogRetention,
  sweepRequestLogRetention,
  sweepRequestLogs,
} from "./retention.js";
export type { RequestLogRetentionScope, RequestLogSweepResult } from "./retention.js";
