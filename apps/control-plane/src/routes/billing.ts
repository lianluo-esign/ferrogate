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
 */
import { HttpError } from "../middleware/errors.js";
import { listResponse, parseListQuery } from "../responses.js";
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
  let db: D1Database;
  try {
    db = router.control();
  } catch {
    // No control database on this deployment — nothing to re-arm, and the
    // document transition below is still the correct, safe half.
    return false;
  }

  let provisioned: boolean;
  try {
    provisioned = await outboxTableExists(db);
  } catch (error) {
    throw new HttpError(
      503,
      "storage_unavailable",
      `the billing outbox could not be reached: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!provisioned) return false;

  try {
    const row = await db
      .prepare(
        `UPDATE ${BILLING_OUTBOX_TABLE}
            SET dead_lettered_at_unix = NULL,
                attempts = 0,
                next_attempt_unix = ?,
                updated_at_unix = ?
          WHERE id = ? AND dead_lettered_at_unix IS NOT NULL
          RETURNING id`,
      )
      .bind(now, now, reportId)
      .first<{ id: string }>();
    return row !== null;
  } catch (error) {
    throw new HttpError(
      503,
      "storage_unavailable",
      `the billing outbox row could not be re-armed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * PORT-TODO(P: inventory-data-billing §2.5) — the six READ feeds page document
 * collections that the metering path never writes, and that breaks `replay`
 * for the only rows that can actually need it.
 *
 * `apps/gateway/src/metering/d1.ts` writes `billing_events`, `billing_ledger`
 * and `billing_report_outbox` (typed tables in the SAME control database this
 * Worker binds). This group lists `metering-events`, `usage-aggregates`,
 * `usage-reports`, `metering-export-status` and `billing-outbox-dead-letters` as
 * `control_plane_resources` documents — a disjoint set, empty on every
 * deployment. Rust `handle_admin_metering_events` pages
 * `state.metering_events_page(...)`, the real store.
 *
 * The sharp edge is `replayBillingOutboxDeadLetter` below: it requires a
 * `billing-outbox-dead-letters` DOCUMENT to exist before it will re-arm the
 * physical row, and no document is ever created (the sweeper dead-letters the
 * ROW). So a real dead letter answers 404 and can never be replayed, while the
 * `rearmOutboxRow` half — which is correct, CAS-guarded and tested — is only
 * ever reached from a hand-seeded document.
 *
 * Closing it: page the typed tables directly (`billing_events` for the metering
 * feed, `billing_report_outbox WHERE dead_lettered_at_unix IS NOT NULL` for the
 * dead letters) with the caller's tenant fence applied to the row's own tenant
 * column, and make `replay` address the row rather than the document.
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
        throw new HttpError(404, "not_found", `billing outbox dead letter ${reportId} not found`);
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
