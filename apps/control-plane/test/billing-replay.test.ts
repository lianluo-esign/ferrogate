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

  it("writes NOTHING to the shared billing_report_outbox table", async () => {
    // The kept platform limit, pinned: `billing_report_outbox` lives in this
    // same control database (the gateway binds it as `BILLING_DB`), so a re-arm
    // is physically writable from here — and is deliberately not done, because
    // the Cron sweep that would drain it does not exist yet. A change that
    // starts writing the table has to make this assertion fail, which is the
    // moment to check the sweep is real.
    await replay("rep_1");
    const outbox = await db()
      .prepare("SELECT COUNT(*) AS total FROM billing_report_outbox")
      .first<{ total: number }>();
    expect(outbox?.total).toBe(0);
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
