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

      // PORT-TODO(inventory-data-billing §2.5 "billing_report_outbox") — KEPT,
      // sharpened: this app cannot perform the RE-EMISSION, only record that one
      // was authorized. Two concrete reasons, neither of which a change here can
      // remove:
      //
      //  1. **The queue is not this Worker's.** The billing Queue producer
      //     binding is declared on `apps/gateway/wrangler.toml`
      //     (`[[queues.producers]] binding = "BILLING"`), whose consumer owns the
      //     dead-letter queue. A second producer here would be a `[[queues]]`
      //     block in this app's `wrangler.toml` naming a queue this app does not
      //     own, and Queue bindings — like every Workers binding — are resolved
      //     at DEPLOY time, so it cannot be picked up dynamically either.
      //  2. **There is no drainer to hand the row to.** The shared
      //     `billing_report_outbox` table does live in the SAME control database
      //     this Worker binds (`apps/gateway` binds it as `BILLING_DB`,
      //     `database_name = "ferrogate-control"`), so a re-arm — clearing
      //     `dead_lettered_at_unix`, resetting `attempts`, setting
      //     `next_attempt_unix` — is physically writable from here. It is
      //     deliberately NOT done, because the Cron sweep that would drain it is
      //     itself unbuilt (`apps/gateway/src/metering/outbox.ts` carries that
      //     PORT-TODO). Re-arming a row nothing reads would look like a queued
      //     re-emission and be a no-op, which is the worst of both.
      //
      // What IS implemented is the half that makes the operation SAFE, and it is
      // the half that matters most: the transition is durable and guarded, so a
      // replay is at-most-once. `test/billing-replay.test.ts` pins that a second
      // replay is refused and that the response never claims an emission
      // happened. It closes when the sweep lands (this route then re-arms the
      // row in the same call) or when a billing Queue producer is bound here.
      const stored = await deps.store.merge(DEAD_LETTERS, scope, reportId, {
        replayed: true,
        replayed_at: Math.floor(Date.now() / 1000),
        status: "replayed",
      });
      return json(c, 200, {
        object: "billing_outbox_dead_letter",
        billing_outbox_dead_letter: stored,
        replayed: true,
        // Says exactly what happened. `emitted: true` would be the dangerous
        // lie: an operator reading it during a billing incident would stop
        // chasing a report that has not actually gone anywhere.
        emitted: false,
        propagation: "on_next_outbox_sweep",
      });
    },
  },
);
