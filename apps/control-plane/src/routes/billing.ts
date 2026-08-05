/**
 * Contract group `billing` (7 operations) — six read-only feeds plus the one
 * write: replaying a dead-lettered outbox report.
 *
 * ```
 *   GET  /admin/v1/billing-events                 (compat alias of metering-events)
 *   GET  /admin/v1/metering-events
 *   GET  /admin/v1/metering-export-status
 *   GET  /admin/v1/usage-aggregates
 *   GET  /admin/v1/usage-reports
 *   GET  /admin/v1/billing-outbox-dead-letters
 *   POST /admin/v1/billing-outbox-dead-letters/{report_id}/replay   admin.write
 * ```
 *
 * Everything except `replay` is a read: metering data is produced by the data
 * plane, and an admin-writable metering event would be a billing forgery
 * primitive. `listAdminBillingEventsCompat` is exactly what its name says — the
 * legacy spelling of the metering feed, kept because clients depend on it; it
 * reads the SAME collection so the two can never disagree.
 *
 * **`replay` is idempotent by dead-letter id and must not double-emit.** A
 * dead letter that has already been replayed is a `409`, not a second emission:
 * re-emitting a settled billing report is a double-charge. The replay marks the
 * row and records when, so the transition is auditable.
 *
 * `replay` addresses the ROW — `billing_report_outbox`, which is where the
 * gateway's sweeper actually dead-letters a report — and falls back to the
 * legacy `billing-outbox-dead-letters` document when one exists. The row half is
 * the 1:1 port of Rust `server/billing_outbox.rs`; see
 * {@link replayOutboxReportRow}.
 */
import type { Context } from "hono";
import { HttpError } from "../middleware/errors.js";
import type { CallerScope, ControlPlaneDeps, ControlPlaneEnv, StoreRecord } from "../ports.js";
import {
  adminListPaginated,
  adminListPaginatedWithMetadata,
  derivedControlProjectionMetadata,
  listResponse,
  parseListQuery,
} from "../responses.js";
import { tenantEvidenceDatabaseFor } from "../store/tenancy.js";
import {
  type GroupModule,
  crudGroup,
  json,
  pathParam,
  readOnlyCollection,
  scopeOf,
} from "./resource.js";

const METERING_EVENTS = "metering-events";
const DEAD_LETTERS = "billing-outbox-dead-letters";
const USAGE_AGGREGATE_TABLE = "usage_aggregate_rollups";

interface UsageAggregateRow {
  readonly id: string;
  readonly tenant?: string;
  readonly tenant_context_id: string;
  readonly organization_id: string | null;
  readonly project_id: string | null;
  readonly api_key_id: string | null;
  readonly logical_model: string;
  readonly provider: string;
  readonly prompt_tokens: number;
  readonly completion_tokens: number;
  readonly total_tokens: number;
}

const USAGE_AGGREGATE_COLUMNS =
  "r.id, r.tenant, r.tenant_context_id, r.organization_id, r.project_id, r.api_key_id, " +
  "r.logical_model, r.provider, r.prompt_tokens, r.completion_tokens, r.total_tokens";

const TENANT_USAGE_AGGREGATE_COLUMNS =
  "r.id, r.tenant_context_id, c.organization_id, c.project_id, c.api_key_id, " +
  "r.logical_model, r.provider, r.prompt_tokens, r.completion_tokens, r.total_tokens";

function usageAggregateDocument(row: UsageAggregateRow): StoreRecord {
  return {
    object: "usage_aggregate",
    id: row.id,
    organization_id: row.organization_id,
    project_id: row.project_id,
    api_key_id: row.api_key_id,
    logical_model: row.logical_model,
    provider: row.provider,
    usage: {
      prompt_tokens: row.prompt_tokens,
      completion_tokens: row.completion_tokens,
      total_tokens: row.total_tokens,
    },
  };
}

async function tenantUsageAggregatePage(
  deps: ControlPlaneDeps,
  tenantId: string,
  limit: number,
  offset: number,
): Promise<{ records: StoreRecord[]; total: number }> {
  const db = await tenantEvidenceDatabaseFor(deps.tenantStorage ?? deps.tenantDatabases, tenantId);
  const result = await db
    .prepare(
      `SELECT ${TENANT_USAGE_AGGREGATE_COLUMNS}, count(*) OVER() AS total
         FROM ${USAGE_AGGREGATE_TABLE} r
        JOIN tenant_contexts c ON c.id = r.tenant_context_id
        WHERE c.organization_id = ?
        ORDER BY r.updated_at_unix DESC, r.id ASC
        LIMIT ? OFFSET ?`,
    )
    .bind(tenantId, limit, offset)
    .all<UsageAggregateRow & { readonly total?: number }>();
  return {
    records: result.results.map(usageAggregateDocument),
    total: result.results[0]?.total ?? 0,
  };
}

async function controlUsageAggregatePage(
  db: D1Database,
  limit: number,
  offset: number,
): Promise<{ records: StoreRecord[]; total: number }> {
  const result = await db
    .prepare(
      `SELECT ${USAGE_AGGREGATE_COLUMNS}, count(*) OVER() AS total
         FROM ${USAGE_AGGREGATE_TABLE} r
        ORDER BY updated_at_unix DESC, id ASC
        LIMIT ? OFFSET ?`,
    )
    .bind(limit, offset)
    .all<UsageAggregateRow & { readonly total?: number }>();
  return {
    records: result.results.map(usageAggregateDocument),
    total: result.results[0]?.total ?? 0,
  };
}

function listAdminUsageAggregates(): (c: Context<ControlPlaneEnv>) => Promise<Response> {
  return async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);

    if (scope.kind === "tenant") {
      const page = await tenantUsageAggregatePage(deps, scope.tenantId, query.limit, query.offset);
      return json(c, 200, adminListPaginated(page.records, page.total, query.offset, query.limit));
    }

    if (deps.controlDatabase === null) {
      const page = await deps.store.list("usage-aggregates", scope, query);
      return json(c, 200, adminListPaginated(page.items, page.total, query.offset, query.limit));
    }

    const page = await controlUsageAggregatePage(
      deps.controlDatabase,
      query.limit,
      query.offset,
    );
    return json(
      c,
      200,
      adminListPaginatedWithMetadata(
        page.records,
        page.total,
        query.offset,
        query.limit,
        derivedControlProjectionMetadata(),
      ),
    );
  };
}

/** The shared gateway→billing outbox (`sql/d1-ts/control/0001_init_control.sql`). */
export const BILLING_OUTBOX_TABLE = "billing_report_outbox";

/**
 * Whether THIS deployment has the gateway's outbox table at all.
 *
 * The table belongs to the migrations slice, and a control database that has
 * never had the gateway's billing families applied simply does not have it —
 * which is a different thing from a database that has it and cannot be read.
 * The distinction is drawn STRUCTURALLY (a `sqlite_master` lookup) rather than
 * by string-matching a D1 error, because the two states must produce opposite
 * answers below: "not provisioned" degrades to the document-only transition
 * this route has always performed, while "provisioned but unreadable" must
 * REFUSE, so the operator can retry instead of burning the one-shot 409 guard
 * on a replay that re-armed nothing.
 */
async function outboxTableExists(db: D1Database): Promise<boolean> {
  const row = await db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
    .bind(BILLING_OUTBOX_TABLE)
    .first<{ name: string }>();
  return row !== null;
}

/**
 * Put a dead-lettered outbox row back on the sweeper's due list.
 *
 * The three columns are exactly the ones `BILLING_OUTBOX_LIST_DUE_SQL` in
 * `apps/gateway/src/metering/d1.ts` filters and orders on, which is why all
 * three move together: clearing `dead_lettered_at_unix` alone would leave the
 * row's `next_attempt_unix` wherever the backoff ladder had pushed it, and
 * resetting `attempts` alone would not make it selectable at all.
 *
 * Returns whether a row was actually re-armed. `RETURNING` (D1 supports it on a
 * native binding) is what makes that answer real rather than assumed.
 *
 * THROWS a 503 `HttpError` when the table is there and the write fails. Never a
 * silent `false`: "the re-arm did not happen" and "there was nothing to re-arm"
 * are different facts and the caller acts on them differently.
 */
async function rearmOutboxRow(
  router: { control(): D1Database },
  reportId: string,
  now: number,
): Promise<boolean> {
  const db = controlDatabase(router);
  if (db === null) {
    // No control database on this deployment — nothing to re-arm, and the
    // document transition below is still the correct, safe half.
    return false;
  }
  if (!(await outboxProvisioned(db))) return false;
  return (await casReplayOutboxRow(db, reportId, now)) !== null;
}

/** The control binding, or `null` on a deployment that has none. */
function controlDatabase(router: { control(): D1Database }): D1Database | null {
  try {
    return router.control();
  } catch {
    return null;
  }
}

/** {@link outboxTableExists}, with an unreadable database as a fail-closed 503. */
async function outboxProvisioned(db: D1Database): Promise<boolean> {
  try {
    return await outboxTableExists(db);
  } catch (error) {
    throw new HttpError(
      503,
      "storage_unavailable",
      `the billing outbox could not be reached: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/** The re-armed outbox row, as `RETURNING` reports it. */
interface RearmedRow {
  readonly id: string;
  readonly attempts: number;
  readonly next_attempt_unix: number;
}

/**
 * The compare-and-swap itself: put the row back on the sweeper's due list, but
 * ONLY while it is still dead-lettered.
 *
 * `AND dead_lettered_at_unix IS NOT NULL` is the whole at-most-once guard and is
 * not decoration — it refuses to touch a row that is already live in the retry
 * ladder, so a second replay cannot reset the `attempts` counter of a report the
 * sweeper is currently backing off on, and two concurrent replays resolve to a
 * single winner (Rust `billing_outbox_replay_test.rs::
 * concurrent_replays_of_one_row_resolve_to_a_single_winner`).
 *
 * `null` ⇒ the CAS did not fire. THROWS a 503 when the write itself failed:
 * "the re-arm did not happen" and "there was nothing to re-arm" are different
 * facts and the caller acts on them differently.
 */
async function casReplayOutboxRow(
  db: D1Database,
  reportId: string,
  now: number,
): Promise<RearmedRow | null> {
  try {
    return await db
      .prepare(
        `UPDATE ${BILLING_OUTBOX_TABLE}
            SET dead_lettered_at_unix = NULL,
                attempts = 0,
                next_attempt_unix = ?,
                updated_at_unix = ?
          WHERE id = ? AND dead_lettered_at_unix IS NOT NULL
          RETURNING id, attempts, next_attempt_unix`,
      )
      .bind(now, now, reportId)
      .first<RearmedRow>();
  } catch (error) {
    throw new HttpError(
      503,
      "storage_unavailable",
      `the billing outbox row could not be re-armed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/** One `billing_report_outbox` row, plus the tenant its event names. */
interface OutboxReportRow {
  readonly id: string;
  readonly deadLettered: boolean;
  /** Rust `entry.event.tenant.organization_id.as_deref().unwrap_or("")`. */
  readonly tenantId: string;
}

/**
 * Read the physical outbox row — the thing a REAL dead letter is.
 *
 * Rust `handle_admin_billing_outbox_dead_letter_replay` reads the row BEFORE the
 * CAS for one reason: it needs the report's owning tenant to authorize against,
 * and the row's owner never changes, so there is no time-of-use gap that matters
 * (the CAS re-checks the only thing that does change — the dead-letter state).
 *
 * `null` means the row is not there, which on this deployment also covers "no
 * control database" and "the billing families were never migrated". Both degrade
 * to the caller's 404, never to a fabricated success.
 */
async function readOutboxReportRow(
  router: { control(): D1Database },
  reportId: string,
): Promise<OutboxReportRow | null> {
  const db = controlDatabase(router);
  if (db === null) return null;
  if (!(await outboxProvisioned(db))) return null;

  let row: { id: string; dead_lettered_at_unix: number | null; event_json: string } | null;
  try {
    row = await db
      .prepare(
        `SELECT id, dead_lettered_at_unix, event_json
           FROM ${BILLING_OUTBOX_TABLE} WHERE id = ?`,
      )
      .bind(reportId)
      .first<{ id: string; dead_lettered_at_unix: number | null; event_json: string }>();
  } catch (error) {
    throw new HttpError(
      503,
      "storage_unavailable",
      `the billing outbox could not be read: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (row === null) return null;
  return {
    id: row.id,
    deadLettered: row.dead_lettered_at_unix !== null,
    tenantId: reportTenantOf(row.event_json),
  };
}

/**
 * The owning tenant of an outbox row, read off the `BillingEvent` it carries.
 *
 * Rust: `entry.event.tenant.organization_id.as_deref().unwrap_or("")`. The empty
 * string is the fail-closed answer, and it is fail-closed precisely because it
 * is unforgeable as a real tenant id — a row whose event names no tenant (or
 * whose document will not parse) is therefore reachable by a platform operator
 * and by nobody else, rather than by everybody.
 */
function reportTenantOf(eventJson: string): string {
  let document: unknown;
  try {
    document = JSON.parse(eventJson);
  } catch {
    return "";
  }
  if (typeof document !== "object" || document === null) return "";
  const tenant = (document as { tenant?: unknown }).tenant;
  if (typeof tenant !== "object" || tenant === null) return "";
  const organizationId = (tenant as { organization_id?: unknown }).organization_id;
  return typeof organizationId === "string" ? organizationId : "";
}

/**
 * Rust `auth.rs::authorize_tenant_scope` — a platform operator passes, a
 * tenant-scoped caller passes only on strict equality, and everything else is
 * `403 tenant_scope_denied`.
 *
 * This runs BEFORE the CAS. A refusal that had already mutated the row would be
 * the worst of both worlds: the report moves and the caller is told it did not.
 */
function authorizeReportTenant(scope: CallerScope, reportTenantId: string): void {
  if (scope.kind === "platform_operator") return;
  if (scope.tenantId === reportTenantId && reportTenantId !== "") return;
  throw new HttpError(
    403,
    "tenant_scope_denied",
    "API key is not authorized to access this tenant's resources",
  );
}

/**
 * Replay a REAL dead letter — a `billing_report_outbox` row — which is the only
 * kind that exists outside a test fixture.
 *
 * A 1:1 port of Rust
 * `server/billing_outbox.rs::handle_admin_billing_outbox_dead_letter_replay`,
 * including its status/code taxonomy:
 *
 * ```
 *   row absent                  404 dead_letter_not_found
 *   row owned by another tenant 403 tenant_scope_denied     (before the CAS)
 *   row not dead-lettered       409 dead_letter_not_replayable
 *   row vanished under the CAS  404 dead_letter_not_found
 *   CAS fired                   200 billing_outbox_dead_letter_replay
 * ```
 *
 * ## Why this is idempotent, and why it cannot double-charge
 *
 * There is exactly ONE idempotency key here and it is not a new one: the report
 * id IS `billing_ledger.id` IS `billing_events.billing_event_id`, the
 * ledger-entry key the billing service dedups on (Rust `responses.rs:1190` says
 * so in as many words). Replay does not write money — it clears the row's
 * dead-letter mark so `apps/gateway`'s cron sweeper picks it up again, and that
 * delivery path is already idempotent on the same key
 * (`BILLING_EVENT_INSERT_SQL` is `ON CONFLICT DO NOTHING`, and `listDue` reports
 * `settled: true` because its `JOIN billing_ledger` proves the charge already
 * committed). Nothing on this path parses, re-serializes or arithmetics the
 * stored credits, so the lossless integer in `entry_json.credits_exact` is never
 * routed through a float.
 *
 * The at-most-once property is therefore entirely the CAS in
 * {@link casReplayOutboxRow}, and the 409 above is what an operator sees when it
 * refuses.
 *
 * ## What this does NOT do
 *
 * It does not emit. The billing Queue producer binding is declared on
 * `apps/gateway/wrangler.toml` and Queue bindings resolve at DEPLOY time, so
 * this Worker authorizes and re-arms while the gateway's sweeper delivers on its
 * next minute. `emitted: true` would be the dangerous lie — an operator reading
 * it during a billing incident would stop chasing a report that has not gone
 * anywhere yet.
 */
async function replayOutboxReportRow(
  c: Context<ControlPlaneEnv>,
  router: { control(): D1Database },
  scope: CallerScope,
  reportId: string,
): Promise<Response> {
  const row = await readOutboxReportRow(router, reportId);
  if (row === null) {
    throw new HttpError(
      404,
      "dead_letter_not_found",
      `no billing-outbox report with id ${reportId}`,
    );
  }
  // Read-then-authorize BEFORE the CAS (Rust's own comment): the row's owning
  // tenant never changes, so this is a stable ownership check.
  authorizeReportTenant(scope, row.tenantId);

  const now = Math.floor(Date.now() / 1000);
  const db = controlDatabase(router);
  if (db === null) {
    // Unreachable — `readOutboxReportRow` just read a row through it — but a
    // silent `false` here would report a re-arm that never happened.
    throw new HttpError(503, "storage_unavailable", "the billing outbox is not reachable");
  }
  const rearmed = await casReplayOutboxRow(db, reportId, now);
  if (rearmed === null) {
    if (row.deadLettered) {
      // Dead-lettered at the read, gone at the CAS: either a concurrent replay
      // won, or a concurrent successful delivery reaped the row. Both mean this
      // caller must not be told it re-armed anything.
      const current = await readOutboxReportRow(router, reportId);
      if (current === null) {
        throw new HttpError(
          404,
          "dead_letter_not_found",
          `no billing-outbox report with id ${reportId}`,
        );
      }
    }
    throw new HttpError(
      409,
      "dead_letter_not_replayable",
      `billing report ${reportId} is not dead-lettered; nothing to replay`,
    );
  }

  return json(c, 200, {
    // Rust `responses.rs::AdminBillingOutboxReplayResponse`.
    object: "billing_outbox_dead_letter_replay",
    id: rearmed.id,
    replayed: true,
    dead_lettered: false,
    attempts: rearmed.attempts,
    next_attempt_unix: rearmed.next_attempt_unix,
    // Not Rust fields; carried over from the document path so an operator
    // driving either shape reads the same two facts about propagation.
    rearmed: true,
    emitted: false,
    propagation: "on_next_outbox_sweep",
  });
}

/**
 * PORT-TODO(P: inventory-data-billing §2.5) — the remaining billing READ feeds
 * page document collections that their typed writers never populate.
 *
 * `apps/gateway/src/metering/d1.ts` writes `billing_events`, `billing_ledger`
 * and `billing_report_outbox` (typed tables in the SAME control database this
 * Worker binds). This group lists `metering-events`, `usage-reports`,
 * `metering-export-status` and `billing-outbox-dead-letters` as
 * `control_plane_resources` documents — a disjoint set, empty on every
 * deployment. Rust `handle_admin_metering_events` pages
 * `state.metering_events_page(...)`, the real store.
 *
 * Closing it: page the typed tables directly (`billing_events` for the metering
 * feed, `billing_report_outbox WHERE dead_lettered_at_unix IS NOT NULL` for the
 * dead-letter feed) with the caller's tenant fence applied to the row's own
 * tenant.
 *
 * WHAT IS NO LONGER PART OF THIS MARKER, and why it was the sharp half: the
 * marker used to end "…and that breaks `replay` for the only rows that can
 * actually need it — `replayBillingOutboxDeadLetter` requires a
 * `billing-outbox-dead-letters` DOCUMENT to exist before it will re-arm the
 * physical row, and no document is ever created (the sweeper dead-letters the
 * ROW), so a real dead letter answers 404 and can never be replayed". That is
 * closed: {@link replayOutboxReportRow} addresses the row, is the 1:1 port of
 * Rust `server/billing_outbox.rs`, and is driven end-to-end against a real D1
 * binding by `test/billing-replay.test.ts` ("a REAL dead letter"). The read
 * feeds being empty is a discoverability problem — an operator has to learn the
 * report id from the sweeper's logs or an alert rather than from this list —
 * while the replay itself being unreachable was an unrecoverable one.
 */
export const billingRoutes: GroupModule = crudGroup(
  "billing",
  [
    readOnlyCollection(METERING_EVENTS, "metering_event"),
    readOnlyCollection("metering-export-status", "metering_export_status"),
    readOnlyCollection("usage-aggregates", "usage_aggregate"),
    readOnlyCollection("usage-reports", "usage_report"),
    readOnlyCollection(DEAD_LETTERS, "billing_outbox_dead_letter"),
  ],
  {
    listAdminUsageAggregates: listAdminUsageAggregates(),
    /**
     * The legacy `/admin/v1/billing-events` spelling. Reads the SAME rows as
     * `/admin/v1/metering-events` — a separate collection would let the two
     * feeds drift, which is precisely the bug a "compat alias" is supposed to
     * prevent.
     */
    listAdminBillingEventsCompat: async (c) => {
      const deps = c.get("deps");
      const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
      const page = await deps.store.list(METERING_EVENTS, scopeOf(c), query);
      return json(c, 200, listResponse(page, query));
    },

    replayBillingOutboxDeadLetter: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const reportId = pathParam(c, "report_id");

      const record = await deps.store.get(DEAD_LETTERS, scope, reportId);
      if (record === null) {
        // No DOCUMENT — which is the state a REAL dead letter is always in, so
        // this is the path that actually matters. See
        // {@link replayOutboxReportRow}.
        return await replayOutboxReportRow(c, deps.tenantDatabases, scope, reportId);
      }
      // Idempotence guard: re-emitting a settled report double-charges.
      if (record.replayed === true) {
        throw new HttpError(
          409,
          "conflict",
          `billing outbox dead letter ${reportId} has already been replayed`,
        );
      }

      // MARKER CLOSED — the `inventory-data-billing §2.5 "billing_report_outbox"`
      // marker that stood here, whose second reason read: "There is no
      // drainer to hand the row to … the Cron sweep that would drain it is
      // itself unbuilt … Re-arming a row nothing reads would look like a queued
      // re-emission and be a no-op, which is the worst of both. It closes when
      // the sweep lands (this route then re-arms the row in the same call)").
      //
      // The sweep landed. `apps/gateway/wrangler.toml` now carries
      // `[triggers] crons = ["* * * * *"]` on the DEFAULT export, and
      // `apps/gateway/src/metering/outbox.ts`'s `MeteringUsageSink.sweep`
      // selects due rows with `BILLING_OUTBOX_LIST_DUE_SQL`
      // (`dead_lettered_at_unix IS NULL AND next_attempt_unix <= now`). So this
      // route now does exactly what the marker said it would: it RE-ARMS the
      // shared row, which lives in the same control database this Worker binds
      // (`deps.tenantDatabases.control()`; the gateway binds it as
      // `BILLING_DB`, `database_name = "ferrogate-control"`).
      //
      // ORDER IS LOAD-BEARING — re-arm FIRST, mark the document SECOND. A crash
      // between them then leaves a re-armed row and an unmarked document, so
      // the operator can replay again and the sweep still delivers (it is
      // idempotent on the ledger entry id). The other order leaves a report
      // marked "replayed" that nothing will ever pick up — permanently stuck,
      // and invisible.
      //
      // The `AND dead_lettered_at_unix IS NOT NULL` in the WHERE is a CAS, not
      // decoration: it refuses to touch a row that is already live in the
      // retry ladder, so a replay cannot reset the `attempts` counter of a
      // report the sweeper is currently backing off on.
      //
      // WHAT REMAINS TRUE, and why `emitted` is still `false`: this Worker does
      // not perform the re-emission itself. The billing Queue producer binding
      // is declared on `apps/gateway/wrangler.toml`
      // (`[[queues.producers]] binding = "BILLING"`), Queue bindings resolve at
      // DEPLOY time, and this app's `wrangler.toml` does not name that queue.
      // The endpoint authorizes and re-arms; the gateway's sweeper emits, on its
      // next minute. `emitted: true` would be the dangerous lie — an operator
      // reading it during a billing incident would stop chasing a report that
      // has not gone anywhere yet.
      const now = Math.floor(Date.now() / 1000);
      const rearmed = await rearmOutboxRow(deps.tenantDatabases, reportId, now);

      const stored = await deps.store.merge(DEAD_LETTERS, scope, reportId, {
        replayed: true,
        replayed_at: now,
        status: "replayed",
        rearmed,
      });
      return json(c, 200, {
        object: "billing_outbox_dead_letter",
        billing_outbox_dead_letter: stored,
        replayed: true,
        /**
         * Whether the shared `billing_report_outbox` row was actually put back
         * on the sweeper's due list. `false` means the dead-letter DOCUMENT
         * existed but the physical row did not (already drained, already
         * re-armed, or never written), and an operator needs to see that
         * difference rather than infer it.
         */
        rearmed,
        emitted: false,
        propagation: "on_next_outbox_sweep",
      });
    },
  },
);
