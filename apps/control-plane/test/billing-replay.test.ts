/**
 * `POST /admin/v1/billing-outbox-dead-letters/{report_id}/replay`, against a
 * REAL D1 binding.
 *
 * Replaying a settled billing report twice is a DOUBLE CHARGE, so the
 * at-most-once guard is the property worth the most here. It is also the half of
 * the operation that is actually implemented — the re-emission itself is a kept
 * platform limit (see the sharpened PORT-TODO in `src/routes/billing.ts`), and
 * these tests pin that the endpoint never CLAIMS to have emitted.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, rawDocument, resetD1, seedD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

const KEY = operatorKey.secret;
const DEAD_LETTERS = "billing-outbox-dead-letters";

function replay(reportId: string, secret = KEY): Promise<Response> {
  return SELF.fetch(
    `${BASE}/admin/v1/billing-outbox-dead-letters/${reportId}/replay`,
    jsonRequest(secret, "POST", {}),
  );
}

beforeAll(applySchema);

describe("billing dead-letter replay: at-most-once (real D1)", () => {
  beforeEach(async () => {
    await resetD1();
    arm({ staticKeys: [operatorKey], store: "d1" });
    await seedD1(DEAD_LETTERS, [{ id: "rep_1", status: "dead_lettered", amount_cents: 1200 }]);
  });

  it("marks the row durably and reports the transition", async () => {
    const response = await replay("rep_1");
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      object: "billing_outbox_dead_letter",
      replayed: true,
      // The endpoint authorized a re-emission; it did not perform one.
      emitted: false,
      propagation: "on_next_outbox_sweep",
    });

    // Durable, not just in the response envelope.
    expect(await rawDocument(DEAD_LETTERS, "rep_1")).toMatchObject({
      replayed: true,
      status: "replayed",
    });
  });

  it("REFUSES a second replay with 409 — re-emitting a settled report double-charges", async () => {
    expect((await replay("rep_1")).status).toBe(200);

    const second = await replay("rep_1");
    expect(second.status).toBe(409);
    expect((await second.json()) as { error: { code: string } }).toMatchObject({
      error: { code: "conflict" },
    });
  });

  it("404s an unknown report id", async () => {
    expect((await replay("rep_missing")).status).toBe(404);
  });

  it("reports rearmed:false when there is no physical outbox row to re-arm", async () => {
    // The dead-letter DOCUMENT exists (seeded above) but the shared row does
    // not. The operator must be able to tell that apart from a real re-arm.
    const body = (await (await replay("rep_1")).json()) as { rearmed: boolean };
    expect(body.rearmed).toBe(false);
    expect(await rawDocument(DEAD_LETTERS, "rep_1")).toMatchObject({ rearmed: false });
  });
});

/**
 * The RE-ARM half — the marker in `src/routes/billing.ts` that used to say
 * "there is no drainer to hand the row to".
 *
 * `apps/gateway` now runs the sweep on a `[triggers] crons = ["* * * * *"]`
 * schedule, so this route puts the shared `billing_report_outbox` row back on
 * the sweeper's due list. The test that used to live here asserted the exact
 * opposite ("writes NOTHING to the shared billing_report_outbox table") and its
 * own comment said a change that starts writing the table "has to make this
 * assertion fail, which is the moment to check the sweep is real". It was
 * checked (`apps/gateway/src/metering/outbox.ts` + the cron trigger), and the
 * assertion is replaced by the stronger one below: not merely that the table is
 * written, but that the row becomes SELECTABLE by the sweeper's own predicate.
 */
describe("billing dead-letter replay: the outbox row is re-armed (real D1)", () => {
  /**
   * `BILLING_OUTBOX_LIST_DUE_SQL` from `apps/gateway/src/metering/d1.ts`,
   * reduced to its WHERE. Asserting through the SWEEPER'S predicate rather than
   * through the three columns separately is what makes this test mean
   * "the report will actually be delivered".
   */
  async function dueReportIds(now: number): Promise<string[]> {
    const rows = await db()
      .prepare(
        `SELECT id FROM billing_report_outbox
          WHERE dead_lettered_at_unix IS NULL AND next_attempt_unix <= ?
          ORDER BY next_attempt_unix ASC, id ASC`,
      )
      .bind(now)
      .all<{ id: string }>();
    return rows.results.map((row) => row.id);
  }

  async function seedOutboxRow(
    id: string,
    fields: { attempts: number; nextAttempt: number; deadLetteredAt: number | null },
  ): Promise<void> {
    await db()
      .prepare(
        `INSERT INTO billing_report_outbox
           (id, attempts, next_attempt_unix, dead_lettered_at_unix, created_at_unix,
            updated_at_unix, event_json)
         VALUES (?, ?, ?, ?, 1, 1, '{}')`,
      )
      .bind(id, fields.attempts, fields.nextAttempt, fields.deadLetteredAt)
      .run();
  }

  async function outboxRow(id: string) {
    return db()
      .prepare(
        "SELECT attempts, next_attempt_unix, dead_lettered_at_unix FROM billing_report_outbox WHERE id = ?",
      )
      .bind(id)
      .first<{
        attempts: number;
        next_attempt_unix: number;
        dead_lettered_at_unix: number | null;
      }>();
  }

  beforeEach(async () => {
    await resetD1();
    await db().prepare("DELETE FROM billing_report_outbox").run();
    arm({ staticKeys: [operatorKey], store: "d1" });
    await seedD1(DEAD_LETTERS, [{ id: "rep_1", status: "dead_lettered" }]);
  });

  it("makes a dead-lettered report DUE for the gateway's sweeper again", async () => {
    const future = Math.floor(Date.now() / 1000) + 86_400;
    await seedOutboxRow("rep_1", { attempts: 20, nextAttempt: future, deadLetteredAt: 1_700 });

    // Control: the sweeper cannot see it before the replay — dead-lettered AND
    // scheduled a day out, so neither half of the predicate is satisfied.
    expect(await dueReportIds(Math.floor(Date.now() / 1000))).toEqual([]);

    const body = (await (await replay("rep_1")).json()) as { rearmed: boolean; emitted: boolean };
    expect(body.rearmed).toBe(true);
    // Re-arming is not emitting, and the endpoint still says so.
    expect(body.emitted).toBe(false);

    expect(await dueReportIds(Math.floor(Date.now() / 1000))).toEqual(["rep_1"]);
    // All three columns moved together; a partial re-arm is not a re-arm.
    const row = await outboxRow("rep_1");
    expect(row?.dead_lettered_at_unix).toBeNull();
    expect(row?.attempts).toBe(0);
    expect(row?.next_attempt_unix).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
  });

  it("REFUSES to touch a row that is not dead-lettered", async () => {
    // A live row mid-backoff. Resetting its attempts would restart a retry
    // ladder the sweeper is deliberately backing off on.
    const future = Math.floor(Date.now() / 1000) + 600;
    await seedOutboxRow("rep_1", { attempts: 3, nextAttempt: future, deadLetteredAt: null });

    const body = (await (await replay("rep_1")).json()) as { rearmed: boolean };
    expect(body.rearmed).toBe(false);

    const row = await outboxRow("rep_1");
    expect(row?.attempts).toBe(3);
    expect(row?.next_attempt_unix).toBe(future);
  });

  it("never re-arms a report the caller did not name", async () => {
    await seedOutboxRow("rep_1", { attempts: 9, nextAttempt: 1, deadLetteredAt: 1_700 });
    await seedOutboxRow("rep_other", { attempts: 9, nextAttempt: 1, deadLetteredAt: 1_700 });

    await replay("rep_1");
    expect((await outboxRow("rep_other"))?.dead_lettered_at_unix).toBe(1_700);
  });
});

describe("billing dead-letter replay: cross-tenant isolation", () => {
  const TENANT_SECRET = "tenant-a-secret";

  beforeEach(async () => {
    await resetD1();
    arm({
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(TENANT_SECRET, "tenant-a")],
      store: "d1",
    });
    await seedD1(DEAD_LETTERS, [
      { id: "rep_a", tenant_id: "tenant-a", status: "dead_lettered" },
      { id: "rep_b", tenant_id: "tenant-b", status: "dead_lettered" },
    ]);
  });

  it("an admin of tenant A cannot replay tenant B's dead letter", async () => {
    const response = await replay("rep_b", TENANT_SECRET);
    expect(response.status).toBe(404);
    // And it stayed untouched — a 404 that had already mutated the row would
    // be the worst of both.
    expect(await rawDocument(DEAD_LETTERS, "rep_b")).toMatchObject({
      status: "dead_lettered",
    });
  });

  it("an admin of tenant A cannot even SEE tenant B's dead letter in the list", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/billing-outbox-dead-letters`, {
      headers: bearer(TENANT_SECRET),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: { id: string }[] };
    expect(body.data.map((row) => row.id)).toEqual(["rep_a"]);
  });

  it("but CAN replay its own", async () => {
    expect((await replay("rep_a", TENANT_SECRET)).status).toBe(200);
  });
});
