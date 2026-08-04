/**
 * `TenantDataObject` against a REAL SQLite-backed Durable Object in `workerd`.
 *
 * Every claim here is a property of the RUNTIME rather than of this package's
 * code, which is why the suite costs a workerd boot instead of being a fake:
 *
 *  * that `ctx.storage.sql` exists at all on a `new_sqlite_classes` namespace
 *    (this is the fleet's first SQL-API DO — the eight existing classes all use
 *    the key-value API, so `new_sqlite_classes` was proven only as a backend
 *    choice, never as a SQL surface);
 *  * that `transactionSync` really rolls back, so `batch()` is genuinely atomic
 *    and the 13 `requireAtomicBatch()` money paths can be admitted;
 *  * that the version gate really stops the 84-statement apply re-running on
 *    the second wake — SQLite has no `ADD COLUMN IF NOT EXISTS`, and four of the
 *    nine tenant migrations are ALTER-only;
 *  * that two `idFromName` objects really hold physically different databases.
 *
 * A fake namespace would agree with all four because the fake was written to
 * agree.
 */
import { env, listDurableObjectIds, runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, test } from "vitest";
import {
  type TenantDataNamespace,
  type TenantDataObject,
  sqlStatements,
} from "../../src/tenant-data-object.js";
import { TENANT_MIGRATIONS, TENANT_SCHEMA_VERSION } from "../../src/tenant-schema-sql.js";

declare global {
  namespace Cloudflare {
    interface Env {
      TENANT_DATA: TenantDataNamespace;
      FAULTY_TENANT_DATA: TenantDataNamespace;
    }
  }
}

/**
 * Every table `sql/d1-ts/tenant/*.sql` creates, as of migration 0009.
 *
 * Written out rather than derived from the migration text, for the reason
 * `packages/storage/test/d1/schema.test.ts` gives for its own list: a list
 * derived from the thing under test cannot disagree with it. Twenty-one of these
 * are the `TENANT_ONLY` set that file already pins against a real D1 tenant
 * database; `storage_schema_migrations` is shared with the control role and
 * `responses_conversations` post-dates that list.
 */
const TENANT_TABLES = [
  "agent_cost_burn",
  "agent_schedule_fires",
  "agent_schedules",
  "api_keys",
  "asset_bundle_files",
  "asset_channels",
  "catalog_model_offerings",
  "catalog_models",
  "catalog_revisions",
  "observed_agent_presence",
  "payment_methods",
  "projects",
  "provider_channels",
  "responses_conversations",
  "retention_policies",
  "storage_schema_migrations",
  "stored_assets",
  "tenant_contexts",
  "tenant_database_identity",
  "tenant_provisioning_marks",
  "usage_aggregate_rollups",
  "usage_metadata_rollups",
  "usage_monthly_rollups",
  "wallet_reservations",
  "wallet_settlements",
  "wallets",
  "workflow_run_budgets",
  "workspaces",
] as const;

const ACME = "tenant_acme";
const GLOBEX = "tenant_globex";

function objectFor(tenantId: string): DurableObjectStub<TenantDataObject> {
  return env.TENANT_DATA.get(env.TENANT_DATA.idFromName(tenantId));
}

/**
 * Await an RPC that must REJECT, and return its message.
 *
 * Used instead of `expect(...).rejects` throughout: this suite's subject IS
 * refusal, and a rejected Durable Object RPC promise that vitest holds is also
 * reported by workerd as an uncaught exception, so `.rejects` buries a
 * twenty-five-test run under a dozen stack traces that are not failures.
 * Consuming the rejection here and asserting on the returned message is the
 * same assertion, and it makes a REAL uncaught exception visible again.
 */
async function refusal(call: Promise<unknown>): Promise<string> {
  try {
    await call;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("expected the RPC to be refused, but it resolved");
}

/**
 * Force a COLD START: abort the instance, then re-address it.
 *
 * `abort()` poisons the stub that issued it (and every request in flight), so
 * the caller must fetch a fresh stub from the namespace. That is exactly the
 * production shape — an evicted object re-runs its constructor, and therefore
 * its `blockConcurrencyWhile` schema apply, against a database that already has
 * the schema.
 */
async function evict(tenantId: string): Promise<void> {
  const stub = objectFor(tenantId);
  await runInDurableObject(stub, (_instance, state) => {
    state.abort("test: forcing a cold start");
  }).catch(() => {
    // `abort()` rejects the very call that issued it; that IS the eviction.
  });
}

describe("the statement splitter", () => {
  // It lives in this suite rather than the pure one because
  // `tenant-data-object.ts` imports `cloudflare:workers`, which does not
  // resolve in node. The migration apply already exercises it end to end; these
  // pin the two properties that make it lossless over the real files, so a
  // future migration that breaks one is caught here instead of by a tenant.
  test("strips comments BEFORE splitting, so a `;` in prose is not a boundary", () => {
    // `0001_init_tenant.sql` has 18 comment lines carrying a mid-prose `;`.
    // Split-then-strip cuts statements in half at every one of them.
    expect(sqlStatements("-- a note; with a semicolon\nCREATE TABLE a (x TEXT);")).toEqual([
      "CREATE TABLE a (x TEXT)",
    ]);
  });

  test("recognises an INDENTED comment line", () => {
    // `0005_responses_conversations.sql` indents `--` comments BETWEEN columns.
    // A filter anchored at column 0 would leave them in and corrupt the table.
    expect(
      sqlStatements("CREATE TABLE a (\n  x TEXT,\n    -- why x exists; really\n  y TEXT\n);"),
    ).toEqual(["CREATE TABLE a (\n  x TEXT,\n  y TEXT\n)"]);
  });

  test("splits the real 0001 into every statement it contains", () => {
    const statements = sqlStatements(TENANT_MIGRATIONS[0]?.sql ?? "");
    expect(statements.length).toBe(49);
    expect(statements.filter((s) => s.startsWith("CREATE TABLE")).length).toBe(20);
    // Longest measured statement is 731 bytes against a 100 KB cap; asserted so
    // a migration that grows past the platform limit is caught before deploy.
    expect(Math.max(...statements.map((s) => s.length))).toBeLessThan(100_000);
  });

  test("the census `sqlStatements`' own docblock states is still the census", () => {
    // WHY A TEST AND NOT A COMMENT. `sqlStatements`' header carries a safety
    // ARGUMENT ("measured over all nine files, every non-comment `;` is at
    // end-of-line…") and `#migrate`'s header carries the statement breakdown
    // that justifies the version gate. Both are measurements, and a measurement
    // in a comment rots: a migration can land after the last census and
    // silently falsify four separate numbers in the file's most load-bearing
    // safety argument. Re-deriving them here means the next migration turns
    // this red and the docblock is corrected in the same commit — the forcing
    // function `test/mount-inventory.test.ts` is for the mount markers, applied
    // to the schema census.
    //
    // If this fails, do NOT change the numbers here alone. Update the four
    // sites in `src/tenant-data-object.ts` that state them: the comment-`;`
    // count and "all NINE files" in the `sqlStatements` docblock, the
    // "N statements" in the constructor comment, and the breakdown in
    // `#migrate`'s docblock.
    const all = TENANT_MIGRATIONS.flatMap((migration) => sqlStatements(migration.sql));
    const count = (pattern: RegExp): number => all.filter((s) => pattern.test(s)).length;
    expect({
      files: TENANT_MIGRATIONS.length,
      statements: all.length,
      createTable: count(/^CREATE TABLE IF NOT EXISTS/i),
      createIndex: count(/^CREATE INDEX/i),
      createUniqueIndex: count(/^CREATE UNIQUE INDEX/i),
      alterTable: count(/^ALTER TABLE/i),
      insert: count(/^INSERT/i),
    }).toEqual({
      files: 9,
      statements: 84,
      createTable: 30,
      createIndex: 33,
      createUniqueIndex: 5,
      alterTable: 9,
      insert: 6,
    });

    // The other half of the argument: the comment lines that carry a `;`, which
    // is what makes comment-stripping-before-splitting mandatory rather than
    // tidy. Per file, so a failure names the migration that moved the number.
    const commentSemicolons: Record<string, number> = Object.fromEntries(
      TENANT_MIGRATIONS.map((migration): [string, number] => [
        migration.name,
        migration.sql
          .split("\n")
          .filter((line) => line.trimStart().startsWith("--") && line.includes(";")).length,
      ]).filter(([, lines]) => lines !== 0),
    );
    expect(commentSemicolons).toEqual({
      "0001_init_tenant": 18,
      "0003_api_key_attribution_tags": 1,
      "0005_responses_conversations": 5,
      "0008_model_catalog": 3,
      "0009_model_catalog": 2,
    });
    expect(Object.values(commentSemicolons).reduce((total, n) => total + n, 0)).toBe(29);

    // The claim those two counts exist to support, asserted rather than
    // restated: NO statement the splitter produces still carries a `;`, i.e.
    // nothing was cut inside a literal and no comment survived the strip.
    expect(all.filter((statement) => statement.includes(";"))).toEqual([]);
    // And the trigger case the docblock says would break it, so a future
    // `CREATE TRIGGER` fails HERE — where the fix is described — rather than at
    // a tenant's cold start.
    expect(all.filter((statement) => /CREATE\s+TRIGGER/i.test(statement))).toEqual([]);
  });
});

describe("a fresh tenant object", () => {
  test("carries the whole tenant schema at the current version", async () => {
    const object = objectFor(ACME);
    const status = await object.schemaVersion();

    expect(status.failure).toBeNull();
    expect(status.version).toBe(TENANT_SCHEMA_VERSION);
    expect(status.latest).toBe(TENANT_SCHEMA_VERSION);
    // A guard on the fixture: if `TENANT_MIGRATIONS` were ever empty the
    // version assertions above would both read 0 and pass vacuously.
    expect(TENANT_MIGRATIONS.length).toBe(9);
    expect(status.appliedThisWake).toEqual(TENANT_MIGRATIONS.map((m) => m.name));

    const tables = await object.query({
      tenantId: ACME,
      sql: "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
    });
    const names = tables.results.map((row) => String(row.name));
    // `_cf_KV` is workerd's own table behind `ctx.storage.get/put`, which this
    // object uses for ONE key (the adopted tenant id). It is filtered rather
    // than folded into the expected list because the assertion being made is
    // that the tenant's SQL schema matches a D1 tenant database EXACTLY — the
    // reason the identity key lives in the KV API instead of a table is to keep
    // `sql/d1-ts/tenant/*.sql` the only thing that creates tenant tables.
    expect(names).toContain("_cf_KV");
    expect(names.filter((name) => !name.startsWith("_cf_"))).toEqual([...TENANT_TABLES]);
  });

  test("records every migration in storage_schema_migrations, not just 0001", async () => {
    // In D1 this ledger is vestigial: only `0001_init_tenant` writes a row, and
    // `wrangler`'s own `d1_migrations` table does the real bookkeeping. Inside a
    // DO there is no wrangler and no `d1_migrations`, so this table IS the
    // ledger and versions 2..8 have to be in it — otherwise the version gate
    // would replay the four ALTER-only migrations on the next wake and every
    // one of them would throw `duplicate column name`.
    const rows = await objectFor(ACME).query({
      tenantId: ACME,
      sql: "SELECT version, name FROM storage_schema_migrations ORDER BY version",
    });
    expect(rows.results).toEqual(
      TENANT_MIGRATIONS.map((m) => ({ version: m.version, name: m.name })),
    );
  });

  test("applied the ALTERed columns in APPENDED position, not folded into the CREATE", async () => {
    // `packages/storage/test/d1/schema.test.ts` pins this same ordered list
    // against a real D1 tenant database. Appended position is the evidence that
    // 0002/0003 ran as ALTERs after 0001 rather than being "optimized" into it —
    // an applier that folded them would produce a tenant object whose column
    // order differs from every migrated D1, silently, and `SELECT *` consumers
    // would disagree across the two backends.
    const columns = await objectFor(ACME).query({
      tenantId: ACME,
      sql: "SELECT name FROM pragma_table_info('usage_monthly_rollups')",
    });
    const names = columns.results.map((row) => row.name);
    expect(names.slice(-3)).toEqual([
      "cached_input_tokens",
      "cache_write_tokens",
      "reasoning_tokens",
    ]);
  });

  test("kept the scope_type CHECK, which is the quota join key", async () => {
    // Dropped, mis-scoped spend becomes invisible rather than loud.
    expect(
      await refusal(
        objectFor(ACME).query({
          tenantId: ACME,
          sql:
            "INSERT INTO usage_monthly_rollups (id, period_month, scope_type, scope_id) " +
            "VALUES ('r1', '2026-08', 'organisation', 's1')",
        }),
      ),
    ).toMatch(/CHECK constraint failed|constraint/i);
  });
});

describe("the second wake", () => {
  test("does a version read and NOTHING more", async () => {
    const first = await objectFor(ACME).schemaVersion();
    expect(first.appliedThisWake.length).toBe(TENANT_MIGRATIONS.length);

    await evict(ACME);

    const second = await objectFor(ACME).schemaVersion();
    // The assertion is on what the applier DID, not on how long it took: a
    // wall-time test would be a timing guess, and a test that only checked the
    // version would pass against an applier that re-ran all 84 statements.
    expect(second.appliedThisWake).toEqual([]);
    expect(second.version).toBe(TENANT_SCHEMA_VERSION);
    expect(second.failure).toBeNull();
  });

  test("survives at all, which is itself the ALTER-idempotence proof", async () => {
    // SQLite has no `ADD COLUMN IF NOT EXISTS`. Four of the nine tenant
    // migrations are ALTER-only, so an applier that re-ran them would throw
    // `duplicate column name` and this object would come back refusing.
    await evict(ACME);
    const object = objectFor(ACME);
    expect((await object.schemaVersion()).failure).toBeNull();
    const rows = await object.query({ tenantId: ACME, sql: "SELECT COUNT(*) AS n FROM wallets" });
    expect(rows.results).toEqual([{ n: 0 }]);
  });

  test("keeps the data written before the eviction", async () => {
    await objectFor(ACME).query({
      tenantId: ACME,
      sql: "INSERT INTO projects (id, tenant_id, slug, name) VALUES (?, ?, ?, ?)",
      params: ["p_survivor", ACME, "survivor", "Survivor"],
    });
    await evict(ACME);
    const rows = await objectFor(ACME).query({
      tenantId: ACME,
      sql: "SELECT id FROM projects WHERE id = ?",
      params: ["p_survivor"],
    });
    expect(rows.results).toEqual([{ id: "p_survivor" }]);
  });
});

describe("a schema that fails mid-file", () => {
  const FAULTY = "tenant_faulty";

  function faultyObject(): DurableObjectStub<TenantDataObject> {
    return env.FAULTY_TENANT_DATA.get(env.FAULTY_TENANT_DATA.idFromName(FAULTY));
  }

  test("leaves the version at the PREVIOUS value", async () => {
    const status = await faultyObject().schemaVersion();
    expect(status.version).toBe(1);
    expect(status.latest).toBe(3);
  });

  test("names the version it stopped at, rather than failing opaquely", async () => {
    const status = await faultyObject().schemaVersion();
    expect(status.failure).toContain("stopped at version 2");
    expect(status.failure).toContain("0002_faulty");
    expect(status.failure).toContain("still at version 1");
  });

  test("rolls the failed file back ENTIRELY — its first, VALID statement is gone too", async () => {
    // `0002_faulty`'s first statement is a good `CREATE TABLE faulty_partial`;
    // only the second is malformed. An applier that ran statements one at a
    // time outside a transaction would leave `faulty_partial` behind and report
    // a failure — a half-applied schema that looks like a clean one to any
    // later `CREATE TABLE IF NOT EXISTS`.
    await runInDurableObject(faultyObject(), (_instance, state) => {
      const tables = state.storage.sql
        .exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .toArray()
        .map((row) => row.name);
      expect(tables).toContain("storage_schema_migrations");
      expect(tables).not.toContain("faulty_partial");
      // 0003 must never have been reached: continuing past a failure would put
      // the object at version 3 with version 2's tables missing.
      expect(tables).not.toContain("never_runs");
    });
  });

  test("REFUSES every query while the schema is broken", async () => {
    expect(
      await refusal(faultyObject().query({ tenantId: FAULTY, sql: "SELECT 1 AS one" })),
    ).toMatch(/stopped at version 2/);
    expect(
      await refusal(
        faultyObject().batch({ tenantId: FAULTY, statements: [{ sql: "SELECT 1 AS one" }] }),
      ),
    ).toMatch(/stopped at version 2/);
  });
});

describe("batch() is ONE transaction", () => {
  beforeEach(async () => {
    await objectFor(ACME).query({ tenantId: ACME, sql: "DELETE FROM projects" });
  });

  test("rolls back ENTIRELY when a later statement throws", async () => {
    // This is the whole point of the object. Under the REST strategy this same
    // sequence was N independent round trips, which is why
    // `supportsAtomicBatch` was false and `requireAtomicBatch()` refused all 13
    // money paths.
    await refusal(
      objectFor(ACME).batch({
        tenantId: ACME,
        statements: [
          {
            sql: "INSERT INTO projects (id, tenant_id, slug, name) VALUES (?, ?, ?, ?)",
            params: ["p_first", ACME, "first", "First"],
          },
          {
            sql: "INSERT INTO projects (id, tenant_id, slug, name) VALUES (?, ?, ?, ?)",
            params: ["p_second", ACME, "second", "Second"],
          },
          // Same primary key as the first statement.
          {
            sql: "INSERT INTO projects (id, tenant_id, slug, name) VALUES (?, ?, ?, ?)",
            params: ["p_first", ACME, "third", "Third"],
          },
        ],
      }),
    );

    const rows = await objectFor(ACME).query({
      tenantId: ACME,
      sql: "SELECT id FROM projects ORDER BY id",
    });
    // Not merely "the third row is absent": the two EARLIER rows must be gone
    // too. A per-statement-autocommit backend passes the weaker assertion.
    expect(rows.results).toEqual([]);
  });

  test("commits every statement when none throws, and reports one result each", async () => {
    const results = await objectFor(ACME).batch({
      tenantId: ACME,
      statements: [
        {
          sql: "INSERT INTO projects (id, tenant_id, slug, name) VALUES (?, ?, ?, ?)",
          params: ["p_a", ACME, "a", "A"],
        },
        {
          sql: "INSERT INTO projects (id, tenant_id, slug, name) VALUES (?, ?, ?, ?)",
          params: ["p_b", ACME, "b", "B"],
        },
        { sql: "SELECT COUNT(*) AS n FROM projects" },
      ],
    });
    // Exactly one result per submitted statement, in order: `wallet-d1.ts:377`
    // and `billing-d1.ts:182` both refuse a short batch, because a short
    // response makes every settle look like a replay and nothing is ever billed.
    expect(results.length).toBe(3);
    expect(results[2]?.results).toEqual([{ n: 2 }]);
  });

  test("reports `changes` per statement, and 0 for a read", async () => {
    const results = await objectFor(ACME).batch({
      tenantId: ACME,
      statements: [
        {
          sql: "INSERT INTO projects (id, tenant_id, slug, name) VALUES (?, ?, ?, ?)",
          params: ["p_c", ACME, "c", "C"],
        },
        { sql: "SELECT id FROM projects" },
        { sql: "UPDATE projects SET name = 'renamed' WHERE id = 'no_such_row'" },
      ],
    });
    // `changes` is the CAS failure signal for five helpers under `src/d1/`:
    // `changes > 0` IS "the guarded write fired". The third statement matches
    // nothing and MUST report 0 — an overreported value publishes an unscanned
    // asset and skips a schedule fire forever.
    expect(results.map((r) => r.changes)).toEqual([1, 0, 0]);
  });

  test("returns RETURNING rows", async () => {
    const results = await objectFor(ACME).batch({
      tenantId: ACME,
      statements: [
        {
          sql:
            "INSERT INTO projects (id, tenant_id, slug, name) VALUES (?, ?, ?, ?) " +
            "ON CONFLICT (id) DO NOTHING RETURNING id",
          params: ["p_ret", ACME, "ret", "Ret"],
        },
      ],
    });
    // An empty `RETURNING` set is how the no-oversell reserve expresses "not
    // admitted" (`wallet-d1.ts:347`); a backend that dropped `RETURNING` rows
    // would refuse every admission.
    expect(results[0]?.results).toEqual([{ id: "p_ret" }]);
  });
});

describe("the value domain crossing the RPC boundary", () => {
  test("a credit balance past 2^53 round-trips EXACTLY", async () => {
    // 1 credit == 1 micro-USD, so int64 range is genuinely reachable on
    // `wallets.balance_credits`. The repo already dodges the 53-bit decode in
    // two places and both must keep working through this object:
    //   * `bindCredits()` sends a decimal STRING and relies on SQLite INTEGER
    //     affinity — `bind(<bigint>)` throws and the `number` form drifts;
    //   * `creditsFromText()` reads it back through `CAST(... AS TEXT)`, and
    //     THROWS if it is ever handed a lossy double.
    // A facade that quietly decoded the column as a `number` would pass every
    // other test in this file and lose money here.
    const huge = "9000000000000000000";
    // Its own object: the wallet-isolation test below asserts on the FULL
    // contents of acme's `wallets` table, and a probe row parked there would
    // make that test order-dependent.
    const wallet = "tenant_huge_credits";
    await objectFor(wallet).query({
      tenantId: wallet,
      sql:
        "INSERT INTO wallets (id, tenant_id, balance_credits, created_at_unix, updated_at_unix) " +
        "VALUES (?, ?, ?, 0, 0)",
      params: ["w_huge", wallet, huge],
    });
    const rows = await objectFor(wallet).query({
      tenantId: wallet,
      sql: "SELECT CAST(balance_credits AS TEXT) AS credits FROM wallets WHERE id = ?",
      params: ["w_huge"],
    });
    expect(rows.results).toEqual([{ credits: huge }]);
    expect(BigInt(String(rows.results[0]?.credits))).toBe(9000000000000000000n);
  });

  test("results are plain structured-cloneable rows, not a live cursor", async () => {
    // A `SqlStorageCursor` cannot cross an RPC boundary, and holding one across
    // an `await` has no isolation guarantee — it may observe rows a rollback
    // later removes. Every cursor is drained inside the `transactionSync`
    // callback; this asserts what arrives on the other side is inert data.
    const rows = await objectFor(ACME).query({
      tenantId: ACME,
      sql: "SELECT 'a' AS text_col, 1 AS int_col, 1.5 AS real_col, NULL AS null_col",
    });
    expect(rows.results).toEqual([{ text_col: "a", int_col: 1, real_col: 1.5, null_col: null }]);
    expect(structuredClone(rows.results)).toEqual(rows.results);
  });
});

describe("the cross-tenant guard", () => {
  test("refuses an RPC carrying another tenant's id", async () => {
    const acme = objectFor(ACME);
    await acme.query({ tenantId: ACME, sql: "SELECT 1 AS one" });

    // `idFromName` is one-way, so the object cannot derive its tenant from its
    // own id: it adopts the first id it is addressed with. Without this guard a
    // resolver that computed the wrong name would read and write another
    // tenant's ledger, and every row would look correct.
    expect(await refusal(acme.query({ tenantId: GLOBEX, sql: "SELECT 1 AS one" }))).toMatch(
      /holds tenant tenant_acme and was addressed as tenant_globex/,
    );
    expect(
      await refusal(acme.batch({ tenantId: GLOBEX, statements: [{ sql: "SELECT 1 AS one" }] })),
    ).toMatch(/refusing rather than serving one tenant's data to another/);
  });

  test("refuses a blank tenant id rather than adopting it", async () => {
    // `middleware.ts:108` returns `""` (never `null`) for an unclassified
    // credential precisely so it matches nothing. Adopting it here would turn
    // that unforgeable id into a shared object every unclassified caller lands in.
    const fresh = objectFor("tenant_blank_probe");
    expect(await refusal(fresh.query({ tenantId: "", sql: "SELECT 1 AS one" }))).toMatch(
      /empty tenant id/,
    );
    expect(await refusal(fresh.query({ tenantId: "   ", sql: "SELECT 1 AS one" }))).toMatch(
      /empty tenant id/,
    );
    // Still unadopted, so a legitimate caller can still claim it.
    expect((await fresh.schemaVersion()).tenantId).toBeNull();
  });

  test("CONCURRENT first RPCs cannot each adopt a different tenant", async () => {
    // The adoption is a read-modify-write across an `await` (the storage `put`),
    // which is exactly the shape that goes wrong under concurrency. Fired
    // together at a virgin object, an unsynchronized version would let both
    // callers past and the object would answer to two tenants.
    const name = "tenant_race_probe";
    const object = objectFor(name);
    const outcomes = await Promise.all([
      object.query({ tenantId: "tenant_race_a", sql: "SELECT 1 AS one" }).then(
        () => "admitted",
        () => "refused",
      ),
      object.query({ tenantId: "tenant_race_b", sql: "SELECT 1 AS one" }).then(
        () => "admitted",
        () => "refused",
      ),
    ]);
    expect(outcomes.filter((outcome) => outcome === "admitted").length).toBe(1);
    // And the id it settled on is durable, not whichever call happened last.
    const adopted = (await object.schemaVersion()).tenantId;
    expect(["tenant_race_a", "tenant_race_b"]).toContain(adopted);
    expect(
      await refusal(
        object.query({
          tenantId: adopted === "tenant_race_a" ? "tenant_race_b" : "tenant_race_a",
          sql: "SELECT 1 AS one",
        }),
      ),
    ).toMatch(/refusing rather than serving one tenant's data to another/);
  });

  test("the adopted id SURVIVES eviction", async () => {
    const name = "tenant_adopt_probe";
    await objectFor(name).query({ tenantId: name, sql: "SELECT 1 AS one" });
    await evict(name);
    expect(await objectFor(name).schemaVersion()).toMatchObject({ tenantId: name });
    // An in-memory-only identity would let a second caller re-adopt the object
    // after any eviction, which is the guard silently disappearing.
    expect(
      await refusal(objectFor(name).query({ tenantId: GLOBEX, sql: "SELECT 1 AS one" })),
    ).toMatch(/holds tenant tenant_adopt_probe/);
  });
});

describe("two tenants", () => {
  test("hold independent databases", async () => {
    await objectFor(ACME).query({
      tenantId: ACME,
      sql:
        "INSERT INTO wallets (id, tenant_id, balance_credits, created_at_unix, updated_at_unix) " +
        "VALUES (?, ?, ?, 0, 0)",
      params: ["w_acme", ACME, 777],
    });
    await objectFor(GLOBEX).query({
      tenantId: GLOBEX,
      sql:
        "INSERT INTO wallets (id, tenant_id, balance_credits, created_at_unix, updated_at_unix) " +
        "VALUES (?, ?, ?, 0, 0)",
      params: ["w_globex", GLOBEX, 3],
    });

    // Proved with DATA, not with object identity: a router that ignored its
    // argument would still hand back two distinct stubs.
    const acmeRows = await objectFor(ACME).query({
      tenantId: ACME,
      sql: "SELECT id, balance_credits FROM wallets",
    });
    const globexRows = await objectFor(GLOBEX).query({
      tenantId: GLOBEX,
      sql: "SELECT id, balance_credits FROM wallets",
    });
    expect(acmeRows.results).toEqual([{ id: "w_acme", balance_credits: 777 }]);
    expect(globexRows.results).toEqual([{ id: "w_globex", balance_credits: 3 }]);

    // And the namespace really did materialise two objects, not one.
    const ids = await listDurableObjectIds(env.TENANT_DATA);
    expect(ids.length).toBeGreaterThanOrEqual(2);
  });

  test("each migrated on its OWN first wake", async () => {
    // Schema migration is lazy and per tenant — there is no fleet-wide batch
    // job and no provisioning step. A tenant addressed for the first time pays
    // the whole apply; every tenant already addressed pays a version read.
    const fresh = objectFor("tenant_late_arrival");
    const status = await fresh.schemaVersion();
    expect(status.appliedThisWake.length).toBe(TENANT_MIGRATIONS.length);
    expect(status.version).toBe(TENANT_SCHEMA_VERSION);
  });
});
