/**
 * The audited CONTROL D1 → `ControlDataObject` backfill against a REAL
 * SQLite-backed Durable Object in workerd (Zero-D1 S5, #881).
 *
 * The claims a workerd boot is spent on, none of which a fake backend could
 * make honestly:
 *
 *  * the static manifest names EXACTLY the object's live user tables (minus the
 *    two migration ledgers) and its key columns ARE their primary keys, so a
 *    control migration that adds or renames a table turns this red;
 *  * a real copy through the `D1Database` facade lands every seeded row and the
 *    per-table row-count + checksum receipts agree across the two backends;
 *  * running the copy AGAIN inserts nothing and leaves the counts unchanged —
 *    idempotency by primary key, the property the issue names;
 *  * the copy runs in the REVERSE direction too (object → D1);
 *  * the verification is NOT vacuous: a row present at the source and missing at
 *    the destination is a reported mismatch, and disappears once re-copied.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  CONTROL_BACKFILL_EXCLUDED_TABLES,
  CONTROL_BACKFILL_TABLES,
  type ControlBackfillTable,
  backfillControlData,
  controlBackfillReceipts,
} from "../../src/control-backfill.js";
import { CONTROL_DATA_ADDRESS, type ControlDataNamespace } from "../../src/control-data-object.js";
import { type ControlDataNamespaceLike, controlDataObjectDatabase } from "../../src/control-do.js";
import { compareTableReceipts } from "../../src/tenant-backfill.js";

declare global {
  namespace Cloudflare {
    interface Env {
      CONTROL_DATA: ControlDataNamespace;
      CONTROL_DB: D1Database;
      CONTROL_MIGRATIONS: Parameters<typeof applyD1Migrations>[1];
    }
  }
}

/** The object facade — the same handle every Zero-D1 seam resolves in production. */
function objectDb(): D1Database {
  return controlDataObjectDatabase(env.CONTROL_DATA as unknown as ControlDataNamespaceLike);
}

/**
 * A subset of the manifest exercised end to end: a single-column key
 * (`tenants`), a two-column composite key (`control_plane_replay_floors_legacy`)
 * and a wider composite-key legacy table (`tenant_provider_credentials_legacy`).
 * The parity assertions are scoped to these so a row another test file left in
 * the shared control object cannot make them flap.
 */
const SUBSET_NAMES = [
  "tenants",
  "control_plane_replay_floors_legacy",
  "tenant_provider_credentials_legacy",
] as const;

const SUBSET: ControlBackfillTable[] = CONTROL_BACKFILL_TABLES.filter((t) =>
  (SUBSET_NAMES as readonly string[]).includes(t.name),
);

async function wipeSubset(db: D1Database): Promise<void> {
  for (const name of SUBSET_NAMES) {
    await db.prepare(`DELETE FROM ${name}`).run();
  }
}

async function seedSource(): Promise<void> {
  await env.CONTROL_DB.batch([
    env.CONTROL_DB.prepare("INSERT INTO tenants (id, name, slug) VALUES (?, ?, ?)").bind(
      "bf-t1",
      "Backfill One",
      "backfill-one",
    ),
    env.CONTROL_DB.prepare("INSERT INTO tenants (id, name, slug) VALUES (?, ?, ?)").bind(
      "bf-t2",
      "Backfill Two",
      "backfill-two",
    ),
    env.CONTROL_DB.prepare(
      "INSERT INTO control_plane_replay_floors_legacy " +
        "(tenant_id, deployment_id, last_accepted_revision, updated_at_unix) VALUES (?, ?, ?, ?)",
    ).bind("bf-t1", "dep-a", 7, 1_700_000_000),
    env.CONTROL_DB.prepare(
      "INSERT INTO control_plane_replay_floors_legacy " +
        "(tenant_id, deployment_id, last_accepted_revision, updated_at_unix) VALUES (?, ?, ?, ?)",
    ).bind("bf-t1", "dep-b", 3, 1_700_000_001),
    env.CONTROL_DB.prepare(
      "INSERT INTO tenant_provider_credentials_legacy " +
        "(tenant_id, alias, provider, key_version, iv, ciphertext, last4, created_at_unix, rotated_at_unix, revoked_at_unix) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(
      "bf-t1",
      "primary",
      "openai",
      1,
      "iv-1",
      "ct-1",
      "1234",
      1_700_000_002,
      1_700_000_002,
      null,
    ),
  ]);
}

/** The subset rows in a database, so a copy can be checked directly, not only via receipts. */
async function subsetSnapshot(db: D1Database): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  for (const name of SUBSET_NAMES) {
    const row = await db.prepare(`SELECT COUNT(*) AS n FROM ${name}`).first<{ n: number }>();
    out[name] = row?.n ?? -1;
  }
  return out;
}

beforeAll(async () => {
  await applyD1Migrations(env.CONTROL_DB, env.CONTROL_MIGRATIONS);
});

beforeEach(async () => {
  await wipeSubset(env.CONTROL_DB);
  await wipeSubset(objectDb());
  await seedSource();
});

describe("the manifest matches the live control object", () => {
  test("names exactly the object's user tables, minus the two ledgers", async () => {
    const { results } = await objectDb()
      .prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
      )
      .all<{ name: string }>();
    const live = results
      .map((row) => row.name)
      .filter((name) => !CONTROL_BACKFILL_EXCLUDED_TABLES.includes(name))
      .sort();
    const manifest = CONTROL_BACKFILL_TABLES.map((t) => t.name).sort();
    expect(manifest).toEqual(live);
    // The exclusion list is not vacuous: both ledgers really are live tables the
    // manifest omits.
    for (const ledger of CONTROL_BACKFILL_EXCLUDED_TABLES) {
      expect(results.some((row) => row.name === ledger)).toBe(true);
    }
  });

  test("each manifest key column set IS the object's primary key", async () => {
    for (const spec of CONTROL_BACKFILL_TABLES) {
      const { results } = await objectDb()
        .prepare(`PRAGMA table_info(${spec.name})`)
        .all<{ name: string; pk: number }>();
      const pk = results
        .filter((column) => column.pk > 0)
        .sort((a, b) => a.pk - b.pk)
        .map((column) => column.name);
      expect(pk, `${spec.name} primary key`).toEqual([...spec.keyColumns]);
    }
  });
});

describe("copies the control database into the object", () => {
  test("lands every seeded row and the receipts agree across backends", async () => {
    const report = await backfillControlData(env.CONTROL_DB, objectDb());

    // The seeded subset landed in the object.
    expect(await subsetSnapshot(objectDb())).toEqual({
      tenants: 2,
      control_plane_replay_floors_legacy: 2,
      tenant_provider_credentials_legacy: 1,
    });
    // Scope parity to the subset so another file's rows in the shared object
    // cannot make this flap; within the subset the two backends must agree.
    const cmp = compareTableReceipts(
      await controlBackfillReceipts(env.CONTROL_DB, SUBSET),
      await controlBackfillReceipts(objectDb(), SUBSET),
    );
    expect(cmp.mismatches).toEqual([]);
    expect(cmp.ok).toBe(true);

    // The report copied the rows it read for the subset tables.
    const subsetResults = report.tables.filter((t) =>
      (SUBSET_NAMES as readonly string[]).includes(t.table),
    );
    expect(subsetResults.map((t) => [t.table, t.sourceRows, t.copied]).sort()).toEqual(
      [
        ["control_plane_replay_floors_legacy", 2, 2],
        ["tenant_provider_credentials_legacy", 1, 1],
        ["tenants", 2, 2],
      ].sort(),
    );
  });

  test("is idempotent — a second run copies nothing and the counts hold", async () => {
    await backfillControlData(env.CONTROL_DB, objectDb());
    const before = await subsetSnapshot(objectDb());

    const second = await backfillControlData(env.CONTROL_DB, objectDb());
    const after = await subsetSnapshot(objectDb());

    expect(after).toEqual(before);
    for (const result of second.tables.filter((t) =>
      (SUBSET_NAMES as readonly string[]).includes(t.table),
    )) {
      expect(result.copied, `${result.table} re-copied`).toBe(0);
      expect(result.sourceRows).toBeGreaterThan(0);
    }
  });

  test("the verification is NOT vacuous — a divergence is reported, then healed", async () => {
    await backfillControlData(env.CONTROL_DB, objectDb());

    // A row added at the source and NOT copied must break the comparison.
    await env.CONTROL_DB.prepare("INSERT INTO tenants (id, name, slug) VALUES (?, ?, ?)")
      .bind("bf-t3", "Backfill Three", "backfill-three")
      .run();
    const diverged = compareTableReceipts(
      await controlBackfillReceipts(env.CONTROL_DB, SUBSET),
      await controlBackfillReceipts(objectDb(), SUBSET),
    );
    expect(diverged.ok).toBe(false);
    expect(diverged.mismatches.some((m) => m.table === "tenants" && m.reason === "row_count")).toBe(
      true,
    );

    // Re-running the copy heals it.
    await backfillControlData(env.CONTROL_DB, objectDb());
    const healed = compareTableReceipts(
      await controlBackfillReceipts(env.CONTROL_DB, SUBSET),
      await controlBackfillReceipts(objectDb(), SUBSET),
    );
    expect(healed.ok).toBe(true);
    const landed = await objectDb()
      .prepare("SELECT id FROM tenants WHERE id = ?")
      .bind("bf-t3")
      .first<{ id: string }>();
    expect(landed?.id).toBe("bf-t3");
  });

  test("runs in the reverse direction too (object → D1)", async () => {
    // Seed the object from the source, then wipe the source and copy back.
    await backfillControlData(env.CONTROL_DB, objectDb());
    await wipeSubset(env.CONTROL_DB);
    expect(await subsetSnapshot(env.CONTROL_DB)).toEqual({
      tenants: 0,
      control_plane_replay_floors_legacy: 0,
      tenant_provider_credentials_legacy: 0,
    });

    await backfillControlData(objectDb(), env.CONTROL_DB);
    expect(await subsetSnapshot(env.CONTROL_DB)).toEqual({
      tenants: 2,
      control_plane_replay_floors_legacy: 2,
      tenant_provider_credentials_legacy: 1,
    });
    const cmp = compareTableReceipts(
      await controlBackfillReceipts(objectDb(), SUBSET),
      await controlBackfillReceipts(env.CONTROL_DB, SUBSET),
    );
    expect(cmp.ok).toBe(true);
  });
});
