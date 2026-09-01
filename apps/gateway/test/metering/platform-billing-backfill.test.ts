/**
 * The one-time historical copy of CONTROL's unattributed billing into the
 * `PlatformDataObject` (`sweepPlatformBillingBackfill`) — the backup half of
 * "对旧的 d1 需要备份数据到新的 do 当中".
 *
 * G1's dual-write only shadows NEW settlements. Rows written to control before
 * that leg existed still live only in control D1, and an unattributed charge has
 * no roster tenant for any fan-out reader to reach — so removing control D1
 * would strand them. This leg copies them across, on the gateway Cron, gated
 * OFF, resumable, and idempotent.
 *
 * These run against the REAL control `BILLING_DB` (seeded with the deployed
 * `0020` compatibility columns) and the REAL `PLATFORM_DATA` object, so a copied
 * row genuinely crossed stores. The gate is driven through the `env` argument
 * only, so "on" here does not depend on any wrangler var.
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
  PLATFORM_BILLING_BACKFILL_FLAG,
  PLATFORM_BILLING_EVENTS_BACKFILL_MARK,
  PLATFORM_BILLING_LEDGER_BACKFILL_MARK,
  sweepPlatformBillingBackfill,
} from "../../src/metering/index.js";
import {
  billingDb,
  platformBillingDb,
  resetMeteringTables,
  resetPlatformBilling,
  storedPlatformBillingEvents,
  storedPlatformBillingLedger,
} from "./d1-harness.js";

const NOW_UNIX = 1_700_000_500;

/** Flag-on env for the sweep's gate; the object argument carries nothing else. */
const ON = { [PLATFORM_BILLING_BACKFILL_FLAG]: "on" } as const;

/**
 * Seed `count` unattributed (`tenant_id IS NULL`) + `attributed` attributed rows
 * into BOTH control billing tables, each with a unique, monotonic cursor tail.
 */
async function seedControl(count: number, attributed: number): Promise<void> {
  const db = billingDb();
  const eventInsert = db.prepare(
    "INSERT INTO billing_events " +
      "(billing_event_id, request_id, provider_attempt_index, occurred_at_unix, event_json, tenant_id) " +
      "VALUES (?, ?, ?, ?, ?, ?)",
  );
  const ledgerInsert = db.prepare(
    "INSERT INTO billing_ledger " +
      "(id, organization_id, project_id, api_key_id, created_at_unix, entry_json, tenant_id) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?)",
  );
  const statements: D1PreparedStatement[] = [];
  for (let i = 0; i < count; i += 1) {
    const at = 1_600_000_000 + i;
    const id = `evt-null-${String(i).padStart(5, "0")}`;
    statements.push(
      eventInsert.bind(id, `req-null-${i}`, 0, at, JSON.stringify({ request_id: `req-null-${i}` }), null),
      ledgerInsert.bind(id, null, null, null, at, JSON.stringify({ credits_exact: `${i}` }), null),
    );
  }
  for (let i = 0; i < attributed; i += 1) {
    const at = 1_500_000_000 + i;
    const id = `evt-tenant-${String(i).padStart(5, "0")}`;
    statements.push(
      eventInsert.bind(id, `req-tenant-${i}`, 0, at, JSON.stringify({ request_id: `req-tenant-${i}` }), "tenant_x"),
      ledgerInsert.bind(id, "tenant_x", null, null, at, JSON.stringify({ credits_exact: `${i}` }), "tenant_x"),
    );
  }
  // Chunk to keep each batch comfortably bounded.
  for (let i = 0; i < statements.length; i += 100) {
    await db.batch(statements.slice(i, i + 100));
  }
}

async function markDetail(mark: string): Promise<Record<string, unknown> | undefined> {
  const row = await platformBillingDb()
    .prepare("SELECT detail FROM platform_backfill_marks WHERE mark = ?")
    .bind(mark)
    .first<{ detail: string | null }>();
  return row?.detail == null ? undefined : (JSON.parse(row.detail) as Record<string, unknown>);
}

describe("sweepPlatformBillingBackfill — control → platform historical copy", () => {
  beforeEach(async () => {
    // The test control backend (the `CONTROL_DATA` object behind `BILLING_DB`)
    // already carries the deployed `0020` `tenant_id` column in its inlined
    // schema, so seeding and the `tenant_id IS NULL` cursor read work as-is.
    await resetMeteringTables();
    await resetPlatformBilling();
  });

  it("is a no-op while the gate is off", async () => {
    await seedControl(3, 1);

    const summary = await sweepPlatformBillingBackfill(env_off(), billingDb(), platformBillingDb(), NOW_UNIX);

    expect(summary).toEqual({ events: "skipped", ledger: "skipped", copied: 0 });
    expect(await storedPlatformBillingEvents()).toHaveLength(0);
    expect(await markDetail(PLATFORM_BILLING_EVENTS_BACKFILL_MARK)).toBeUndefined();
  });

  it("skips when a store is missing, without throwing", async () => {
    await seedControl(2, 0);

    expect(await sweepPlatformBillingBackfill(ON, null, platformBillingDb(), NOW_UNIX)).toEqual({
      events: "skipped",
      ledger: "skipped",
      copied: 0,
    });
    expect(await sweepPlatformBillingBackfill(ON, billingDb(), null, NOW_UNIX)).toEqual({
      events: "skipped",
      ledger: "skipped",
      copied: 0,
    });
    expect(await storedPlatformBillingEvents()).toHaveLength(0);
  });

  it("copies ONLY unattributed control rows, across page boundaries, and marks complete", async () => {
    // 150 unattributed spans two pages (PAGE_SIZE 100 → 100 + 50); 4 attributed
    // rows must never cross over.
    await seedControl(150, 4);

    const summary = await sweepPlatformBillingBackfill(ON, billingDb(), platformBillingDb(), NOW_UNIX);

    expect(summary.events).toBe("complete");
    expect(summary.ledger).toBe("complete");
    expect(summary.copied).toBe(300); // 150 events + 150 ledger

    const events = await storedPlatformBillingEvents();
    const ledger = await storedPlatformBillingLedger();
    expect(events).toHaveLength(150);
    expect(ledger).toHaveLength(150);
    // Every copied row is unattributed; not one attributed request_id leaked.
    expect(events.every((row) => row.tenant_id === null)).toBe(true);
    expect(events.some((row) => row.request_id.startsWith("req-tenant-"))).toBe(false);
    expect(ledger.every((row) => row.tenant_id === null)).toBe(true);
    // The cursor walked the whole set in order without skipping a boundary row.
    expect(events[0]?.request_id).toBe("req-null-0");
    expect(events[149]?.request_id).toBe("req-null-149");

    const eventsMark = await markDetail(PLATFORM_BILLING_EVENTS_BACKFILL_MARK);
    expect(eventsMark?.state).toBe("complete");
    expect(eventsMark?.rows).toBe(150);
  });

  it("is idempotent and does not re-scan control once complete", async () => {
    await seedControl(10, 0);
    await sweepPlatformBillingBackfill(ON, billingDb(), platformBillingDb(), NOW_UNIX);
    expect(await storedPlatformBillingEvents()).toHaveLength(10);

    // A NEW unattributed control row arriving after completion is the dual-write's
    // job, NOT the backfill's — a completed mark short-circuits before any read.
    await billingDb()
      .prepare(
        "INSERT INTO billing_events " +
          "(billing_event_id, request_id, provider_attempt_index, occurred_at_unix, event_json, tenant_id) " +
          "VALUES (?, ?, ?, ?, ?, ?)",
      )
      .bind("evt-null-late", "req-null-late", 0, 1_600_100_000, "{}", null)
      .run();

    const again = await sweepPlatformBillingBackfill(ON, billingDb(), platformBillingDb(), NOW_UNIX);
    expect(again).toEqual({ events: "complete", ledger: "complete", copied: 0 });
    expect(await storedPlatformBillingEvents()).toHaveLength(10);
  });

  it("copies nothing when control has no unattributed rows", async () => {
    await seedControl(0, 5);

    const summary = await sweepPlatformBillingBackfill(ON, billingDb(), platformBillingDb(), NOW_UNIX);

    expect(summary).toEqual({ events: "complete", ledger: "complete", copied: 0 });
    expect(await storedPlatformBillingEvents()).toHaveLength(0);
    expect(await markDetail(PLATFORM_BILLING_LEDGER_BACKFILL_MARK)).toMatchObject({ state: "complete" });
  });
});

/** Gate-off env: the flag simply absent. */
function env_off(): Record<string, unknown> {
  return {};
}
