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
  crudGroup,
  json,
  pathParam,
  readOnlyCollection,
  scopeOf,
  type GroupModule,
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

      // PORT-TODO(inventory-data-billing §outbox): enqueue the re-emission on
      // the billing Queue via `@ferrogate/billing` once it lands. The marking
      // below is the durable half and is what makes the replay
      // at-most-once; the emission is the half still to be wired.
      const stored = await deps.store.merge(DEAD_LETTERS, scope, reportId, {
        replayed: true,
        replayed_at: Math.floor(Date.now() / 1000),
        status: "replayed",
      });
      return json(c, 200, {
        object: "billing_outbox_dead_letter",
        billing_outbox_dead_letter: stored,
        replayed: true,
      });
    },
  },
);
