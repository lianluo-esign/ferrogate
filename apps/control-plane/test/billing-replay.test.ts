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

// ---------------------------------------------------------------------------
// A REAL dead letter — the one an operator actually has to replay.
//
// Every describe above seeds a `billing-outbox-dead-letters` DOCUMENT. Nothing
// in the system ever writes one: `apps/gateway/src/metering/d1.ts`'s
// `D1DurableOutbox.deadLetter` marks the ROW
// (`UPDATE billing_report_outbox SET dead_lettered_at_unix = …`), and that is
// the only producer of a dead letter there is. So the suite above proves the
// endpoint against a fixture shape that only a test ever creates, and the shape
// that production produces was never driven through it at all.
//
// These tests drive the production shape: rows in `billing_events` /
// `billing_ledger` / `billing_report_outbox`, written the way
// `D1LedgerStore.record` writes them and then dead-lettered the way the sweeper
// dead-letters them, with NO document anywhere. Reference:
// `crates/ferrogate-gateway/src/server/billing_outbox.rs::
// handle_admin_billing_outbox_dead_letter_replay`.
// ---------------------------------------------------------------------------

/** `2^53 + 1` — the first integer a JSON `number` cannot hold. */
const CREDITS_BEYOND_FLOAT64 = "9007199254740993";

/**
 * The `entry_json` document `apps/gateway/src/metering/d1.ts::ledgerDocument`
 * writes, reduced to what this suite reads back. `credits_exact` is a DECIMAL
 * STRING on purpose — that module's docblock spells out that a JSON number here
 * "would defeat the whole point: 2^53+1 would come back as 2^53".
 */
function ledgerEntryJson(tenant: string, creditsExact: string): string {
  return JSON.stringify({
    id: "led_1",
    request_id: "req_1",
    tenant: { organization_id: tenant },
    credits: 9_007_199_254_740_992,
    credits_exact: creditsExact,
    occurred_at_unix: 1_700,
  });
}

/** The `BillingEvent` the outbox row carries; its tenant is the replay's fence. */
function outboxEventJson(tenant: string): string {
  return JSON.stringify({
    request_id: "req_1",
    tenant: { organization_id: tenant },
    logical_model: "chat",
    provider: "openai",
    provider_model: "gpt-4o-mini",
    status_code: 200,
    occurred_at_unix: 1_700,
  });
}

interface RealDeadLetter {
  readonly id: string;
  readonly tenant: string;
  /** `null` ⇒ a LIVE row mid-backoff, not a dead letter. */
  readonly deadLetteredAt: number | null;
  readonly attempts?: number;
  readonly nextAttempt?: number;
  readonly creditsExact?: string;
}

/**
 * Seed the three rows `D1LedgerStore.record` commits in ONE batch, then set the
 * outbox row's dead-letter mark the way `D1DurableOutbox.deadLetter` does.
 *
 * Raw SQL rather than a call into the gateway's store: a fixture built with the
 * code under test cannot show that the code under test reads what is actually
 * in the table.
 */
async function seedRealDeadLetter(letter: RealDeadLetter): Promise<void> {
  const creditsExact = letter.creditsExact ?? "1200";
  await db().batch([
    db()
      .prepare(
        `INSERT INTO billing_events
           (billing_event_id, request_id, provider_attempt_index, occurred_at_unix, event_json)
         VALUES (?, ?, 0, 1700, ?)`,
      )
      .bind(letter.id, `req_${letter.id}`, outboxEventJson(letter.tenant)),
    db()
      .prepare(
        `INSERT INTO billing_ledger
           (id, organization_id, project_id, api_key_id, created_at_unix, entry_json)
         VALUES (?, ?, NULL, NULL, 1700, ?)`,
      )
      .bind(letter.id, letter.tenant, ledgerEntryJson(letter.tenant, creditsExact)),
    db()
      .prepare(
        `INSERT INTO billing_report_outbox
           (id, attempts, next_attempt_unix, dead_lettered_at_unix, created_at_unix,
            updated_at_unix, event_json)
         VALUES (?, ?, ?, ?, 1700, 1700, ?)`,
      )
      .bind(
        letter.id,
        letter.attempts ?? 20,
        letter.nextAttempt ?? 1_700,
        letter.deadLetteredAt,
        outboxEventJson(letter.tenant),
      ),
  ]);
}

/**
 * `BILLING_OUTBOX_LIST_DUE_SQL` from `apps/gateway/src/metering/d1.ts`, VERBATIM
 * — including the `JOIN billing_ledger`.
 *
 * The join is the half that matters here: it is what rehydrates the priced
 * charge, so a row that satisfies the WHERE but has no ledger row is NOT
 * deliverable. Asserting through the sweeper's whole statement is what makes a
 * green here mean "this report will actually be re-delivered" rather than "three
 * columns changed".
 */
async function sweeperWouldDeliver(nowUnix: number): Promise<string[]> {
  const rows = await db()
    .prepare(
      "SELECT billing_report_outbox.id AS id, billing_report_outbox.attempts AS attempts, " +
        "billing_report_outbox.next_attempt_unix AS next_attempt_unix, " +
        "billing_ledger.entry_json AS entry_json, billing_report_outbox.event_json AS event_json " +
        "FROM billing_report_outbox " +
        "JOIN billing_ledger ON billing_ledger.id = billing_report_outbox.id " +
        "WHERE billing_report_outbox.dead_lettered_at_unix IS NULL " +
        "AND billing_report_outbox.next_attempt_unix <= CAST(? AS INTEGER) " +
        "ORDER BY billing_report_outbox.next_attempt_unix ASC, billing_report_outbox.id ASC " +
        "LIMIT CAST(? AS INTEGER)",
    )
    .bind(nowUnix, 100)
    .all<{ id: string }>();
  return rows.results.map((row) => row.id);
}

async function outboxRowOf(id: string) {
  return db()
    .prepare(
      "SELECT attempts, next_attempt_unix, dead_lettered_at_unix FROM billing_report_outbox WHERE id = ?",
    )
    .bind(id)
    .first<{ attempts: number; next_attempt_unix: number; dead_lettered_at_unix: number | null }>();
}

/** How many ledger rows carry this id. A replay that charges again makes it 2. */
async function ledgerRowCount(id: string): Promise<number> {
  const row = await db()
    .prepare("SELECT COUNT(*) AS n FROM billing_ledger WHERE id = ?")
    .bind(id)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

async function billingEventRowCount(id: string): Promise<number> {
  const row = await db()
    .prepare("SELECT COUNT(*) AS n FROM billing_events WHERE billing_event_id = ?")
    .bind(id)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

async function rawEntryJson(id: string): Promise<string | null> {
  const row = await db()
    .prepare("SELECT entry_json FROM billing_ledger WHERE id = ?")
    .bind(id)
    .first<{ entry_json: string }>();
  return row?.entry_json ?? null;
}

/** Wipe the three gateway-owned billing tables `resetD1()` does not know about. */
async function resetBillingTables(): Promise<void> {
  await db().batch([
    db().prepare("DELETE FROM billing_report_outbox"),
    db().prepare("DELETE FROM billing_ledger"),
    db().prepare("DELETE FROM billing_events"),
  ]);
}

describe("billing dead-letter replay: a REAL dead letter (row, no document)", () => {
  beforeEach(async () => {
    await resetD1();
    await resetBillingTables();
    arm({ staticKeys: [operatorKey], store: "d1" });
  });

  it("re-drives a lost billing report that has NO dead-letter document", async () => {
    await seedRealDeadLetter({ id: "rep_real", tenant: "tenant-a", deadLetteredAt: 1_800 });
    // There is no document — this is the shape production actually produces.
    expect(await rawDocument(DEAD_LETTERS, "rep_real")).toBeNull();
    // Control: the sweeper cannot see it, so the money is stuck.
    expect(await sweeperWouldDeliver(Math.floor(Date.now() / 1000))).toEqual([]);

    const response = await replay("rep_real");
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      // `crates/ferrogate-gateway/src/responses.rs:1196
      // AdminBillingOutboxReplayResponse`.
      object: "billing_outbox_dead_letter_replay",
      id: "rep_real",
      replayed: true,
      dead_lettered: false,
      attempts: 0,
    });

    // The EFFECT: the sweeper's own statement now selects it, exactly once.
    expect(await sweeperWouldDeliver(Math.floor(Date.now() / 1000))).toEqual(["rep_real"]);
    const row = await outboxRowOf("rep_real");
    expect(row?.dead_lettered_at_unix).toBeNull();
    expect(row?.attempts).toBe(0);
    // Re-driving is not charging: the ledger is untouched.
    expect(await ledgerRowCount("rep_real")).toBe(1);
    expect(await billingEventRowCount("rep_real")).toBe(1);
  });

  it("re-driving an already-replayed report lands ZERO additional ledger rows", async () => {
    await seedRealDeadLetter({ id: "rep_real", tenant: "tenant-a", deadLetteredAt: 1_800 });
    expect((await replay("rep_real")).status).toBe(200);
    expect(await sweeperWouldDeliver(Math.floor(Date.now() / 1000))).toEqual(["rep_real"]);

    const second = await replay("rep_real");
    expect(second.status).toBe(409);
    expect(await second.json()).toMatchObject({
      error: { code: "dead_letter_not_replayable" },
    });

    // One report on the sweeper's due list, one ledger row, one metering event.
    expect(await sweeperWouldDeliver(Math.floor(Date.now() / 1000))).toEqual(["rep_real"]);
    expect(await ledgerRowCount("rep_real")).toBe(1);
    expect(await billingEventRowCount("rep_real")).toBe(1);
  });

  it("a second replay cannot restart the retry ladder of a report already back in flight", async () => {
    await seedRealDeadLetter({ id: "rep_real", tenant: "tenant-a", deadLetteredAt: 1_800 });
    expect((await replay("rep_real")).status).toBe(200);

    // The sweeper picked the re-armed report up, failed once, and backed off —
    // exactly what `BILLING_OUTBOX_RESCHEDULE_SQL` writes.
    const backoff = Math.floor(Date.now() / 1000) + 3_600;
    await db()
      .prepare("UPDATE billing_report_outbox SET attempts = 7, next_attempt_unix = ? WHERE id = ?")
      .bind(backoff, "rep_real")
      .run();

    expect((await replay("rep_real")).status).toBe(409);
    const row = await outboxRowOf("rep_real");
    expect(row?.attempts).toBe(7);
    expect(row?.next_attempt_unix).toBe(backoff);
  });

  it("REFUSES a report that was never dead-lettered", async () => {
    // A live row mid-backoff, and no document to fall back on.
    const future = Math.floor(Date.now() / 1000) + 600;
    await seedRealDeadLetter({
      id: "rep_live",
      tenant: "tenant-a",
      deadLetteredAt: null,
      attempts: 3,
      nextAttempt: future,
    });

    const response = await replay("rep_live");
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({
      error: { code: "dead_letter_not_replayable" },
    });

    const row = await outboxRowOf("rep_live");
    expect(row?.attempts).toBe(3);
    expect(row?.next_attempt_unix).toBe(future);
  });

  it("404s `dead_letter_not_found` for a report id that exists nowhere", async () => {
    const response = await replay("rep_nowhere");
    expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({
      error: { code: "dead_letter_not_found" },
    });
  });

  it("never touches a report the caller did not name", async () => {
    await seedRealDeadLetter({ id: "rep_real", tenant: "tenant-a", deadLetteredAt: 1_800 });
    await seedRealDeadLetter({ id: "rep_other", tenant: "tenant-a", deadLetteredAt: 1_900 });

    expect((await replay("rep_real")).status).toBe(200);
    expect((await outboxRowOf("rep_other"))?.dead_lettered_at_unix).toBe(1_900);
    expect(await sweeperWouldDeliver(Math.floor(Date.now() / 1000))).toEqual(["rep_real"]);
  });

  it("re-drives the report WITHOUT rewriting the ledger's exact integer credits", async () => {
    await seedRealDeadLetter({
      id: "rep_big",
      tenant: "tenant-a",
      deadLetteredAt: 1_800,
      creditsExact: CREDITS_BEYOND_FLOAT64,
    });
    const before = await rawEntryJson("rep_big");

    expect((await replay("rep_big")).status).toBe(200);

    // Byte-identical: a replay that round-tripped the entry through a JSON
    // number would hand the billing service 9007199254740992 — one credit less
    // than was charged, on every replayed report past 2^53.
    expect(await rawEntryJson("rep_big")).toBe(before);
    expect(
      (JSON.parse((await rawEntryJson("rep_big")) ?? "{}") as { credits_exact: string })
        .credits_exact,
    ).toBe(CREDITS_BEYOND_FLOAT64);
  });
});

describe("billing dead-letter replay: a REAL dead letter is tenant-fenced", () => {
  const TENANT_A_SECRET = "tenant-a-secret";
  const TENANT_B_SECRET = "tenant-b-secret";

  beforeEach(async () => {
    await resetD1();
    await resetBillingTables();
    arm({
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(TENANT_A_SECRET, "tenant-a"), tenantKey(TENANT_B_SECRET, "tenant-b")],
      store: "d1",
    });
    await seedRealDeadLetter({ id: "rep_a", tenant: "tenant-a", deadLetteredAt: 1_800 });
  });

  it("an admin of tenant B cannot re-drive tenant A's lost billing report", async () => {
    const response = await replay("rep_a", TENANT_B_SECRET);
    // Rust `authorize_tenant_scope` (auth.rs:414) — the row's owning tenant is
    // read and authorized BEFORE the CAS.
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({
      error: { code: "tenant_scope_denied" },
    });

    // A refusal that had already mutated the row would be the worst of both:
    // the money moves and the caller is told it did not.
    const row = await outboxRowOf("rep_a");
    expect(row?.dead_lettered_at_unix).toBe(1_800);
    expect(row?.attempts).toBe(20);
    expect(await sweeperWouldDeliver(Math.floor(Date.now() / 1000))).toEqual([]);
  });

  it("but tenant A CAN re-drive its own", async () => {
    expect((await replay("rep_a", TENANT_A_SECRET)).status).toBe(200);
    expect(await sweeperWouldDeliver(Math.floor(Date.now() / 1000))).toEqual(["rep_a"]);
  });

  it("a read-only admin key cannot re-drive anything", async () => {
    // Re-arm only to add the reader credential; `rep_a` is already in D1 from
    // `beforeEach` and re-seeding it would violate the outbox row's PK.
    arm({
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey("reader-secret", "tenant-a", ["admin.read"])],
      store: "d1",
    });

    const response = await replay("rep_a", "reader-secret");
    expect(response.status).toBe(403);
    expect((await outboxRowOf("rep_a"))?.dead_lettered_at_unix).toBe(1_800);
  });

  it("a report whose event names no tenant is unreachable to a tenant key", async () => {
    // `event_json` with no `tenant.organization_id` — a row written before the
    // tenancy chain was threaded, or by a producer that lost it. Rust reads
    // `.unwrap_or("")`, and the empty string is unforgeable as a real tenant id,
    // so a tenant-scoped caller matches nothing. Fail CLOSED, not open.
    await db()
      .prepare(
        `INSERT INTO billing_report_outbox
           (id, attempts, next_attempt_unix, dead_lettered_at_unix, created_at_unix,
            updated_at_unix, event_json)
         VALUES ('rep_orphan', 20, 1700, 1800, 1700, 1700, '{"request_id":"req_x"}')`,
      )
      .run();

    expect((await replay("rep_orphan", TENANT_A_SECRET)).status).toBe(403);
    expect((await outboxRowOf("rep_orphan"))?.dead_lettered_at_unix).toBe(1_800);
    // The platform operator is not fenced and can still recover it.
    expect((await replay("rep_orphan")).status).toBe(200);
  });

  it("an api key that names no tenant at all cannot reach an orphan report", async () => {
    // `callerScope` confines an UNCLASSIFIED credential to the tenant id `""`
    // (`ports.ts:68` — "the empty string is unforgeable as a real tenant id").
    // A fence that compared for bare equality would let that caller and a report
    // whose event names no tenant match each other: the one pairing where two
    // absences authorize each other, and the only caller that can be minted
    // without naming a tenant.
    arm({
      staticKeys: [operatorKey],
      nativeKeys: [{ secret: "no-tenant-secret", id: "key_none", scopes: ["admin.write"] }],
      store: "d1",
    });
    await db()
      .prepare(
        `INSERT INTO billing_report_outbox
           (id, attempts, next_attempt_unix, dead_lettered_at_unix, created_at_unix,
            updated_at_unix, event_json)
         VALUES ('rep_orphan', 20, 1700, 1800, 1700, 1700, '{"request_id":"req_x"}')`,
      )
      .run();

    const response = await replay("rep_orphan", "no-tenant-secret");
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: { code: "tenant_scope_denied" } });
    expect((await outboxRowOf("rep_orphan"))?.dead_lettered_at_unix).toBe(1_800);
  });
});
