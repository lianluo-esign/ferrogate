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
 *  * that the version gate really stops the 153-statement apply re-running on
 *    the second wake — SQLite has no `ADD COLUMN IF NOT EXISTS`, and four of the
 *    eighteen tenant migrations are covered by the census below;
 *  * that two `idFromName` objects really hold physically different databases.
 *
 * A fake namespace would agree with all four because the fake was written to
 * agree.
 */
import {
  applyD1Migrations,
  env,
  listDurableObjectIds,
  runDurableObjectAlarm,
  runInDurableObject,
} from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  TENANT_AGGREGATE_FLUSH_CALLBACK,
  TENANT_SCHEDULE_ALARM_CALLBACK,
  type TenantAggregateFlushAlarmCallback,
  type TenantDataBatchRequest,
  type TenantDataNamespace,
  type TenantDataObject,
  type TenantScheduleAlarmCallback,
  sqlStatements,
} from "../../src/tenant-data-object.js";
import type { TenantAggregateFlushAlarmMessage } from "../../src/tenant-data-object.js";
import type { TenantScheduleAlarmMessage } from "../../src/tenant-schedule-alarm.js";
import { TENANT_MIGRATIONS, TENANT_SCHEMA_VERSION } from "../../src/tenant-schema-sql.js";

declare global {
  namespace Cloudflare {
    interface Env {
      TENANT_DATA: TenantDataNamespace;
      FAULTY_TENANT_DATA: TenantDataNamespace;
      CONTROL_DB: D1Database;
      CONTROL_MIGRATIONS: Parameters<typeof applyD1Migrations>[1];
    }
  }
}

beforeAll(async () => {
  await applyD1Migrations(env.CONTROL_DB, env.CONTROL_MIGRATIONS);
});

beforeEach(async () => {
  // The control projection is shared by this workerd environment; keep rows
  // from a previous run from satisfying a freshness assertion.
  await env.CONTROL_DB.batch([
    env.CONTROL_DB.prepare("DELETE FROM tenant_databases"),
    env.CONTROL_DB.prepare("DELETE FROM tenant_agent_cost_rollups"),
    env.CONTROL_DB.prepare("DELETE FROM tenant_spend_rollups"),
    env.CONTROL_DB.prepare("DELETE FROM tenant_asset_rollups"),
  ]);
});

/**
 * Every table `sql/d1-ts/tenant/*.sql` creates, as of migration 0023.
 *
 * Written out rather than derived from the migration text, for the reason
 * `packages/storage/test/d1/schema.test.ts` gives for its own list: a list
 * derived from the thing under test cannot disagree with it. Twenty-one of these
 * are the `TENANT_ONLY` set that file already pins against a real D1 tenant
 * database; `storage_schema_migrations` is shared with the control role and
 * `responses_conversations` plus `tenant_resources` post-date the original
 * inventory and are included explicitly here.
 */
const TENANT_TABLES = [
  "agent_cost_burn",
  "agent_run_events",
  "agent_runs",
  "agent_schedule_fires",
  "agent_schedules",
  "agent_worker_instances",
  "api_keys",
  "asset_bundle_files",
  "asset_channels",
  "audit_events",
  // #698 — `0022_batches` and `0023_batch_execution`. SQLite orders `_` (0x5F)
  // before `e` (0x65), so `batch_request_results` sorts ahead of `batches`.
  "batch_request_results",
  "batches",
  "billing_events",
  "billing_ledger",
  "billing_report_outbox",
  "budget_alert_notifications",
  "catalog_audit_outbox",
  "catalog_model_offerings",
  "catalog_models",
  "catalog_revisions",
  "control_plane_replay_floors",
  "delegation_revocations",
  "experiment_shadow_legs",
  "guardrail_check_evaluations",
  "guardrail_evaluations",
  "managed_worker_isolation_evidence",
  "managed_worker_isolation_policies",
  "managed_worker_isolation_selections",
  "managed_worker_lifecycle_events",
  "managed_worker_sessions",
  "managed_worker_templates",
  "mcp_identity_generations",
  "mcp_oauth_credentials",
  "mcp_servers",
  "observed_agent_presence",
  "online_eval_regressions",
  "online_eval_scores",
  "payment_methods",
  "projects",
  "provider_channels",
  "request_logs",
  "responses_conversations",
  "retention_policies",
  "self_hosted_run_dispatches",
  "self_hosted_worker_artifacts",
  "self_hosted_worker_checkpoints",
  "self_hosted_worker_heartbeats",
  "self_hosted_worker_identities",
  "self_hosted_worker_telemetry_events",
  "semantic_cache_policies",
  "spend_anomaly_episodes",
  "sso_provider_configs",
  "storage_schema_migrations",
  "stored_assets",
  "tenant_contexts",
  "tenant_database_identity",
  "tenant_provider_credentials",
  "tenant_provisioning_marks",
  "tenant_resources",
  "tenant_role_bindings",
  "tenant_role_catalog",
  "tenant_write_fences",
  "usage_aggregate_rollups",
  "usage_event_claims",
  "usage_metadata_rollups",
  "usage_monthly_rollups",
  "usage_projection_retries",
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

type PrivilegedTenantObject = DurableObjectStub<TenantDataObject> & {
  privilegedBatch(request: TenantDataBatchRequest): Promise<unknown[]>;
};

type MigrationTenantObject = DurableObjectStub<TenantDataObject> & {
  setMigrationMode(request: {
    tenantId: string;
    mode: "shared" | "copying" | "verifying" | "cut" | "done";
    epoch: number;
  }): Promise<unknown>;
};

function privilegedObjectFor(tenantId: string): PrivilegedTenantObject {
  return objectFor(tenantId) as unknown as PrivilegedTenantObject;
}

type ScheduleAlarmStub = DurableObjectStub<TenantDataObject> & {
  setScheduleAlarm(request: { tenantId: string; scheduledAtUnix: number }): Promise<void>;
  clearScheduleAlarm(request: { tenantId: string }): Promise<void>;
};

type OperatorTenantObject = DurableObjectStub<TenantDataObject> & {
  operatorQuery(request: {
    tenantId: string;
    sql: string;
    params?: readonly (string | number | null)[];
    auditId: string;
    requestId: string;
    operator: string;
    occurredAtUnix: number;
  }): Promise<{
    results: Record<string, unknown>[];
    rowCount: number;
    auditId: string;
  }>;
  operatorExportPage(request: {
    tenantId: string;
    exportId: string;
    cursor: string | null;
    pageSize: number;
    auditId: string;
    requestId: string;
    operator: string;
    occurredAtUnix: number;
  }): Promise<{
    jsonl: string;
    rowCount: number;
    nextCursor: string | null;
    done: boolean;
    auditId: string;
  }>;
  operatorRestore(request: {
    tenantId: string;
    bookmark?: string;
    timestampUnix?: number;
    auditId: string;
    requestId: string;
    operator: string;
    occurredAtUnix: number;
  }): Promise<{ bookmark: string; auditId: string; scheduled: true }>;
};

function operatorObjectFor(tenantId: string): OperatorTenantObject {
  return objectFor(tenantId) as unknown as OperatorTenantObject;
}

type AggregateAlarmStub = ScheduleAlarmStub & {
  setAggregateFlushAlarm(request: { tenantId: string; scheduledAtUnix: number }): Promise<void>;
};

function scheduleAlarmObjectFor(tenantId: string): ScheduleAlarmStub {
  return objectFor(tenantId) as unknown as ScheduleAlarmStub;
}

function aggregateAlarmObjectFor(tenantId: string): AggregateAlarmStub {
  return objectFor(tenantId) as unknown as AggregateAlarmStub;
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
    // ARGUMENT ("measured over all seventeen files, every non-comment `;` is at
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
    // count and "all NINETEEN files" in the `sqlStatements` docblock, the
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
      // #698 slices 1-3: `0022_batches` (+1 table) and `0024_batch_execution`
      // (+1 table, +11 `ALTER TABLE … ADD COLUMN`). The ALTERs are the half
      // that matters — they are the statements the version gate exists to stop
      // re-running, and they more than doubled. Then two more tenant migrations
      // landed: `0023_online_eval_leg_index` (#894, +1 `CREATE INDEX`) and
      // `0025_request_log_routing_decision` (#699, +1 `ALTER TABLE … ADD COLUMN`).
      files: 25,
      statements: 433,
      createTable: 74,
      createIndex: 95,
      createUniqueIndex: 6,
      alterTable: 22,
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
      "0011_asset_file_metadata": 1,
      "0012_request_logs_agent_runs": 1,
      "0013_guardrail_evaluations": 1,
      "0015_tenant_configuration_policy": 1,
      "0016_control_plane_resources": 1,
      "0017_worker_schedule_state": 1,
      "0018_usage_evaluation_audit": 1,
      "0021_tenant_backfill_fence": 1,
      "0024_batch_execution": 1,
      "0025_request_log_routing_decision": 1,
    });
    expect(Object.values(commentSemicolons).reduce((total, n) => total + n, 0)).toBe(39);

    // Ordinary statements still have their terminator removed, while each
    // trigger stays whole because its body contains internal terminators.
    const triggers = all.filter((statement) => /CREATE\s+TRIGGER/i.test(statement));
    expect(triggers).toHaveLength(229);
    expect(
      all.filter((statement) => !/CREATE\s+TRIGGER/i.test(statement) && statement.includes(";")),
    ).toEqual([]);
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
    expect(TENANT_MIGRATIONS.length).toBe(25);
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

describe("tenant configuration and policy state", () => {
  test("rejects tenant-role binding writes on the ordinary RPC", async () => {
    const tenantId = "tenant_privileged_write";
    const message = await refusal(
      objectFor(tenantId).batch({
        tenantId,
        statements: [
          {
            sql:
              "INSERT INTO tenant_role_bindings (id, tenant_id, role_id, created_at_unix) " +
              "VALUES (?, ?, ?, ?)",
            params: ["binding_ordinary", tenantId, "role_operator", 100],
          },
        ],
      }),
    );
    expect(message).toMatch(/privileged/i);
  });

  test("rejects alternate SQLite write forms for protected role tables", async () => {
    const statements = [
      "UPDATE OR REPLACE tenant_role_bindings SET role_id = 'role_operator'",
      "DELETE FROM main.tenant_role_catalog",
      "WITH candidate AS (SELECT 1) INSERT INTO tenant_role_bindings (id) SELECT 'binding' FROM candidate",
      "CREATE TRIGGER role_projection_trigger AFTER INSERT ON projects BEGIN INSERT INTO tenant_role_catalog (role_id) VALUES ('role'); END",
      "CREATE TRIGGER role_projection_guard AFTER INSERT ON projects WHEN '--' = '--' BEGIN INSERT INTO tenant_role_catalog (role_id) VALUES ('role'); END",
    ];
    for (const [index, sql] of statements.entries()) {
      const tenantId = `tenant_privileged_syntax_${index}`;
      expect(await refusal(objectFor(tenantId).query({ tenantId, sql }))).toMatch(/privileged/i);
    }
  });

  test("accepts a role snapshot and binding only through the privileged RPC", async () => {
    const tenantId = "tenant_privileged_role";
    await privilegedObjectFor(tenantId).privilegedBatch({
      tenantId,
      statements: [
        {
          sql:
            "INSERT INTO tenant_role_catalog " +
            "(role_id, name, slug, description, permission_keys_json, created_at_unix, updated_at_unix) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
          params: ["role_operator", "Operator", "operator", "", '["tenant.read"]', 100, 100],
        },
        {
          sql:
            "INSERT INTO tenant_role_bindings (id, tenant_id, role_id, created_at_unix) " +
            "VALUES (?, ?, ?, ?)",
          params: ["binding_privileged", tenantId, "role_operator", 100],
        },
      ],
    });

    const rows = await objectFor(tenantId).query({
      tenantId,
      sql:
        "SELECT b.tenant_id, b.role_id, c.permission_keys_json " +
        "FROM tenant_role_bindings AS b " +
        "JOIN tenant_role_catalog AS c ON c.role_id = b.role_id " +
        "WHERE b.tenant_id = ?",
      params: [tenantId],
    });
    expect(rows.results).toEqual([
      { tenant_id: tenantId, role_id: "role_operator", permission_keys_json: '["tenant.read"]' },
    ]);
  });

  test("keeps configuration and policy rows physically isolated per tenant", async () => {
    const tenantA = "tenant_config_isolation_a";
    const tenantB = "tenant_config_isolation_b";
    await objectFor(tenantA).batch({
      tenantId: tenantA,
      statements: [
        {
          sql:
            "INSERT INTO tenant_provider_credentials " +
            "(tenant_id, alias, provider, key_version, iv, ciphertext, last4, created_at_unix, rotated_at_unix) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
          params: [tenantA, "primary", "openai", 1, "iv-a", "cipher-a", "1234", 1, 1],
        },
        {
          sql:
            "INSERT INTO semantic_cache_policies " +
            "(scope_type, scope_id, enabled, mode, similarity_threshold, ttl_seconds, " +
            "scoped_models, invalidation_epoch, updated_at_unix, updated_by, generation) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          params: ["tenant", tenantA, 1, "semantic", 0.9, 60, '["model-a"]', 1, 1, "operator", 1],
        },
        {
          sql:
            "INSERT INTO delegation_revocations " +
            "(tenant, subject, reason, revoked_by, revoked_at_unix, expires_at_unix) " +
            "VALUES (?, ?, ?, ?, ?, ?)",
          params: [tenantA, "subject-a", "test", "operator", 1, null],
        },
        {
          sql:
            "INSERT INTO control_plane_replay_floors " +
            "(tenant_id, deployment_id, last_accepted_revision, updated_at_unix) " +
            "VALUES (?, ?, ?, ?)",
          params: [tenantA, "deployment-a", 7, 1],
        },
        {
          sql:
            "INSERT INTO budget_alert_notifications " +
            "(id, tenant_id, scope_type, scope_id, period_month, threshold_pct, notified_at_unix) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
          params: ["alert-a", tenantA, "tenant", tenantA, "2026-08", 80, 1],
        },
      ],
    });

    const rows = await objectFor(tenantB).query({
      tenantId: tenantB,
      sql:
        "SELECT " +
        "(SELECT COUNT(*) FROM tenant_provider_credentials) AS credentials, " +
        "(SELECT COUNT(*) FROM semantic_cache_policies) AS cache_policies, " +
        "(SELECT COUNT(*) FROM delegation_revocations) AS revocations, " +
        "(SELECT COUNT(*) FROM control_plane_replay_floors) AS replay_floors, " +
        "(SELECT COUNT(*) FROM budget_alert_notifications WHERE tenant_id = ?) AS alerts",
      params: [tenantA],
    });
    expect(rows.results).toEqual([
      { credentials: 0, cache_policies: 0, revocations: 0, replay_floors: 0, alerts: 0 },
    ]);
  });
});

describe("tenant storage migration gate", () => {
  test("keeps the object frozen during cut until control reaches done", async () => {
    const tenant = "tenant_migration_gate_cut";
    const object = objectFor(tenant) as MigrationTenantObject;
    await object.setMigrationMode({ tenantId: tenant, mode: "shared", epoch: 1 });
    await object.setMigrationMode({ tenantId: tenant, mode: "copying", epoch: 1 });
    await object.setMigrationMode({ tenantId: tenant, mode: "verifying", epoch: 1 });
    await object.setMigrationMode({ tenantId: tenant, mode: "cut", epoch: 1 });
    expect(
      await refusal(
        object.query({
          tenantId: tenant,
          sql: "INSERT INTO projects (id, tenant_id, slug, name) VALUES (?, ?, ?, ?)",
          params: ["cut_frozen", tenant, "cut-frozen", "Cut frozen"],
        }),
      ),
    ).toMatch(/writes are frozen/);
    expect(
      await refusal(object.setScheduleAlarm({ tenantId: tenant, scheduledAtUnix: 1_800_000_500 })),
    ).toMatch(/schedule alarm writes are frozen/);
    await object.setMigrationMode({ tenantId: tenant, mode: "done", epoch: 1 });
    await object.query({
      tenantId: tenant,
      sql: "INSERT INTO projects (id, tenant_id, slug, name) VALUES (?, ?, ?, ?)",
      params: ["done_writable", tenant, "done-writable", "Done writable"],
    });
  });
});

describe("tenant-private request evidence", () => {
  test("keeps request logs and ordered agent evidence inside each object", async () => {
    const tenantA = "tenant_evidence_red_a";
    const tenantB = "tenant_evidence_red_b";

    await objectFor(tenantA).batch({
      tenantId: tenantA,
      statements: [
        {
          sql:
            "INSERT INTO request_logs (request_id, tenant, started_at_unix, request_json) " +
            "VALUES (?, ?, ?, ?)",
          params: ["req_a", tenantA, 100, '{"tenant":"a"}'],
        },
        {
          sql:
            "INSERT INTO agent_runs (id, request_id, tenant, started_at_unix, run_json) " +
            "VALUES (?, ?, ?, ?, ?)",
          params: ["run_a", "req_a", tenantA, 100, '{"run":"a"}'],
        },
        {
          sql:
            "INSERT INTO agent_run_events " +
            "(id, run_id, request_id, tenant, occurred_at_unix, event_json) " +
            "VALUES (?, ?, ?, ?, ?, ?)",
          params: ["event_a_2", "run_a", "req_a", tenantA, 102, '{"seq":2}'],
        },
        {
          sql:
            "INSERT INTO agent_run_events " +
            "(id, run_id, request_id, tenant, occurred_at_unix, event_json) " +
            "VALUES (?, ?, ?, ?, ?, ?)",
          params: ["event_a_1", "run_a", "req_a", tenantA, 101, '{"seq":1}'],
        },
      ],
    });

    await objectFor(tenantB).query({
      tenantId: tenantB,
      sql:
        "INSERT INTO request_logs (request_id, tenant, started_at_unix, request_json) " +
        "VALUES (?, ?, ?, ?)",
      params: ["req_b", tenantB, 200, '{"tenant":"b"}'],
    });

    const logsA = await objectFor(tenantA).query({
      tenantId: tenantA,
      sql: "SELECT request_id, tenant FROM request_logs ORDER BY started_at_unix",
    });
    const eventsA = await objectFor(tenantA).query({
      tenantId: tenantA,
      sql: "SELECT id FROM agent_run_events WHERE run_id = ? " + "ORDER BY occurred_at_unix, id",
      params: ["run_a"],
    });
    const logsB = await objectFor(tenantB).query({
      tenantId: tenantB,
      sql: "SELECT request_id, tenant FROM request_logs ORDER BY started_at_unix",
    });

    expect(logsA.results).toEqual([{ request_id: "req_a", tenant: tenantA }]);
    expect(eventsA.results).toEqual([{ id: "event_a_1" }, { id: "event_a_2" }]);
    expect(logsB.results).toEqual([{ request_id: "req_b", tenant: tenantB }]);
  });
});

describe("tenant-private guardrail evidence", () => {
  test("keeps reused evaluation/check ids isolated and cascades checks", async () => {
    const tenantA = "tenant_guardrail_red_a";
    const tenantB = "tenant_guardrail_red_b";
    const evaluationId = "evaluation_same_id";
    const checkId = "check_same_id";

    const parent = (tenant: string) => ({
      sql:
        "INSERT INTO guardrail_evaluations " +
        "(id, request_id, tenant, scope_type, target, protocol, stage, mode, " +
        "policy_id, policy_revision, verdict, action, enforcement_status, " +
        "occurred_at_unix, input_fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      params: [
        evaluationId,
        `request_${tenant}`,
        tenant,
        "organization",
        "gpt-4o-mini/openai",
        "chat_completions",
        "request",
        "enforce",
        "secret-scan",
        1,
        "fail",
        "block",
        "enforced",
        1_700_000_100,
        `hmac-sha256:${tenant}`,
      ],
    });
    const child = (tenant: string) => ({
      sql:
        "INSERT INTO guardrail_check_evaluations " +
        "(id, evaluation_id, tenant, check_id, detector_id, detector_version, " +
        "config_digest, verdict, action, enforcement_status) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      params: [
        checkId,
        evaluationId,
        tenant,
        "deterministic",
        "deterministic",
        "deterministic-1",
        "sha256:test",
        "fail",
        "block",
        "enforced",
      ],
    });

    await objectFor(tenantA).batch({
      tenantId: tenantA,
      statements: [parent(tenantA), child(tenantA)],
    });
    await objectFor(tenantB).batch({
      tenantId: tenantB,
      statements: [parent(tenantB), child(tenantB)],
    });

    for (const tenant of [tenantA, tenantB]) {
      const rows = await objectFor(tenant).query({
        tenantId: tenant,
        sql:
          "SELECT e.tenant, e.id, c.tenant AS check_tenant, c.id AS check_id " +
          "FROM guardrail_evaluations e " +
          "JOIN guardrail_check_evaluations c ON c.evaluation_id = e.id " +
          "WHERE e.id = ?",
        params: [evaluationId],
      });
      expect(rows.results).toEqual([
        {
          tenant,
          id: evaluationId,
          check_tenant: tenant,
          check_id: checkId,
        },
      ]);
    }

    await objectFor(tenantA).query({
      tenantId: tenantA,
      sql: "DELETE FROM guardrail_evaluations WHERE id = ?",
      params: [evaluationId],
    });
    const deletedChild = await objectFor(tenantA).query({
      tenantId: tenantA,
      sql: "SELECT COUNT(*) AS count FROM guardrail_check_evaluations",
    });
    const survivingChild = await objectFor(tenantB).query({
      tenantId: tenantB,
      sql: "SELECT COUNT(*) AS count FROM guardrail_check_evaluations",
    });
    expect(deletedChild.results).toEqual([{ count: 0 }]);
    expect(survivingChild.results).toEqual([{ count: 1 }]);
  });
});

describe("tenant audit chains", () => {
  test("assign a chain position and return the same row on replay", async () => {
    const tenant = "tenant_audit_chain";
    const object = objectFor(tenant);
    await object.query({ tenantId: tenant, sql: "DELETE FROM audit_events" });

    const first = await object.appendAudit({
      tenantId: tenant,
      id: "audit-1",
      requestId: "request-1",
      agentRunId: null,
      occurredAtUnix: 1_700_000_000,
      auditJson: '{"action":"asset.push"}',
    });
    const replay = await object.appendAudit({
      tenantId: tenant,
      id: "audit-1",
      requestId: "request-1",
      agentRunId: null,
      occurredAtUnix: 1_700_000_000,
      auditJson: '{"action":"asset.push"}',
    });
    expect(replay).toEqual(first);

    const second = await object.appendAudit({
      tenantId: tenant,
      id: "audit-2",
      requestId: "request-2",
      agentRunId: "run-2",
      occurredAtUnix: 1_700_000_001,
      auditJson: '{"action":"asset.yank"}',
    });
    expect(first.seq).toBe(1);
    expect(second.seq).toBe(2);
    expect(second.prevHash).toBe(first.rowHash);

    const rows = await object.query({
      tenantId: tenant,
      sql: "SELECT seq, prev_hash, row_hash FROM audit_events ORDER BY seq",
    });
    expect(rows.results).toHaveLength(2);
    expect(rows.results[0]).toMatchObject({ seq: 1, prev_hash: "0".repeat(64) });
    expect(rows.results[1]).toMatchObject({ seq: 2, prev_hash: first.rowHash });
  });
});

describe("operator tenant-data RPCs", () => {
  test("accepts a parsed read-only SELECT and audits the exact row count", async () => {
    const tenant = "tenant_operator_read";
    const object = operatorObjectFor(tenant);
    await object.query({ tenantId: tenant, sql: "DELETE FROM audit_events" });

    const result = await object.operatorQuery({
      tenantId: tenant,
      sql: "-- a leading comment\nWITH one AS (SELECT 1 AS answer) SELECT answer FROM one",
      auditId: "operator-read-audit",
      requestId: "operator-read-request",
      operator: "operator@example.test",
      occurredAtUnix: 1_754_000_000,
    });

    expect(result.results).toEqual([{ answer: 1 }]);
    expect(result.rowCount).toBe(1);
    expect(result.auditId).toBe("operator-read-audit");

    const audits = await object.query({
      tenantId: tenant,
      sql: "SELECT id, request_id, tenant, audit_json FROM audit_events WHERE id = ?",
      params: ["operator-read-audit"],
    });
    expect(audits.results).toHaveLength(1);
    expect(audits.results[0]).toMatchObject({
      id: "operator-read-audit",
      request_id: "operator-read-request",
      tenant,
    });
    expect(JSON.parse(String(audits.results[0]?.audit_json))).toMatchObject({
      operator: "operator@example.test",
      tenant_id: tenant,
      statement: "-- a leading comment\nWITH one AS (SELECT 1 AS answer) SELECT answer FROM one",
      row_count: 1,
    });
  });

  test.each([
    ["SELECT 1; DROP TABLE projects", "multiple statements"],
    ["WITH doomed AS (SELECT 1) DELETE FROM projects WHERE 0", "DML"],
    ["PRAGMA user_version = 828", "PRAGMA"],
    ["SELECT 1; SELECT 2", "multiple statements"],
  ])("rejects %s at parse level (%s)", async (sql) => {
    const tenant = "tenant_operator_read_rejections";
    const message = await refusal(
      operatorObjectFor(tenant).operatorQuery({
        tenantId: tenant,
        sql,
        auditId: `operator-rejection-${sql.slice(0, 8)}`,
        requestId: "operator-rejection-request",
        operator: "operator@example.test",
        occurredAtUnix: 1_754_000_001,
      }),
    );

    expect(message).toMatch(/read-only SELECT|exactly one SQL statement|PRAGMA/i);
  });

  test("exports bounded JSONL keyset pages without materialising the table", async () => {
    const tenant = "tenant_operator_export";
    const object = operatorObjectFor(tenant);
    await object.privilegedBatch({
      tenantId: tenant,
      statements: [
        {
          sql:
            "CREATE TABLE IF NOT EXISTS operator_export_rows " +
            "(id INTEGER PRIMARY KEY, payload TEXT NOT NULL)",
        },
        {
          sql: "DELETE FROM operator_export_rows",
        },
        {
          sql: "INSERT INTO operator_export_rows (id, payload) VALUES (?, ?)",
          params: [1, "one"],
        },
        {
          sql: "INSERT INTO operator_export_rows (id, payload) VALUES (?, ?)",
          params: [2, "two"],
        },
        {
          sql: "INSERT INTO operator_export_rows (id, payload) VALUES (?, ?)",
          params: [3, "three"],
        },
        {
          sql: "INSERT INTO operator_export_rows (id, payload) VALUES (?, ?)",
          params: [4, "four"],
        },
        {
          sql: "INSERT INTO operator_export_rows (id, payload) VALUES (?, ?)",
          params: [5, "five"],
        },
      ],
    });

    const pages: string[] = [];
    const exportedIds: number[] = [];
    let cursor: string | null = null;
    let page = 0;
    for (;;) {
      const result: {
        jsonl: string;
        rowCount: number;
        nextCursor: string | null;
        done: boolean;
        auditId: string;
      } = await object.operatorExportPage({
        tenantId: tenant,
        exportId: "export-828",
        cursor,
        pageSize: 2,
        auditId: `operator-export-audit-${page}`,
        requestId: `operator-export-request-${page}`,
        operator: "operator@example.test",
        occurredAtUnix: 1_754_000_100 + page,
      });
      pages.push(result.jsonl);
      expect(result.rowCount).toBeLessThanOrEqual(2);
      for (const line of result.jsonl.trim().split("\n")) {
        if (line === "") continue;
        const record = JSON.parse(line) as {
          kind: string;
          table?: string;
          values?: { id?: number };
        };
        if (record.kind === "row" && record.table === "operator_export_rows") {
          exportedIds.push(Number(record.values?.id));
        }
      }
      if (result.done) break;
      cursor = result.nextCursor;
      expect(cursor).not.toBeNull();
      page += 1;
      expect(page).toBeLessThan(20);
    }

    expect(pages.length).toBeGreaterThan(1);
    expect(exportedIds).toEqual([1, 2, 3, 4, 5]);
  });

  test.skip("PITR restore is gated: installed local workerd exposes the types but its SQLite backend reports that PITR is unavailable", async () => {
    const tenant = "tenant_operator_restore";
    const object = operatorObjectFor(tenant);
    const bookmark = await runInDurableObject(object, (_instance, state) =>
      state.storage.getCurrentBookmark(),
    );

    const result = await object.operatorRestore({
      tenantId: tenant,
      bookmark,
      auditId: "operator-restore-audit",
      requestId: "operator-restore-request",
      operator: "operator@example.test",
      occurredAtUnix: 1_754_000_200,
    });

    expect(result).toEqual({
      bookmark,
      auditId: "operator-restore-audit",
      scheduled: true,
    });
    const audit = await object.query({
      tenantId: tenant,
      sql: "SELECT audit_json FROM audit_events WHERE id = ?",
      params: ["operator-restore-audit"],
    });
    expect(audit.results).toHaveLength(1);
    expect(JSON.parse(String(audit.results[0]?.audit_json))).toMatchObject({
      operation: "restore",
      operator: "operator@example.test",
      bookmark,
    });
  });

  test("refuses a point before the retained bookmark window", async () => {
    const tenant = "tenant_operator_restore_without_bookmark";
    const message = await refusal(
      operatorObjectFor(tenant).operatorRestore({
        tenantId: tenant,
        timestampUnix: 0,
        auditId: "operator-restore-unavailable",
        requestId: "operator-restore-unavailable-request",
        operator: "operator@example.test",
        occurredAtUnix: 1_754_000_201,
      }),
    );

    expect(message).toMatch(/no usable bookmark/i);
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
    // version would pass against an applier that re-ran all 153 statements.
    expect(second.appliedThisWake).toEqual([]);
    expect(second.version).toBe(TENANT_SCHEMA_VERSION);
    expect(second.failure).toBeNull();
  });

  test("survives at all, which is itself the ALTER-idempotence proof", async () => {
    // SQLite has no `ADD COLUMN IF NOT EXISTS`. Four of the eighteen tenant
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

describe("tenant-owned worker and schedule state", () => {
  test("rolls back worker and schedule rows together in one transaction", async () => {
    const tenantId = "tenant_worker_transaction";
    const object = objectFor(tenantId);

    expect(
      await refusal(
        object.batch({
          tenantId,
          statements: [
            {
              sql: "INSERT INTO managed_worker_templates (id, template_json) VALUES (?, ?)",
              params: ["template_rollback", '{"tenant_id":"tenant_worker_transaction"}'],
            },
            {
              sql:
                "INSERT INTO self_hosted_run_dispatches " +
                "(dispatch_id, queued_at_unix, dispatch_json) VALUES (?, ?, ?)",
              params: ["dispatch_rollback", 100, '{"tenant_id":"tenant_worker_transaction"}'],
            },
            {
              sql:
                "INSERT INTO agent_schedules " +
                "(schedule_id, tenant_id, workspace_id, name, spec_kind, target_kind, " +
                "created_at_unix, updated_at_unix) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
              params: [
                "schedule_rollback",
                tenantId,
                "workspace_rollback",
                "Rollback",
                "interval",
                "agent_run",
                100,
                100,
              ],
            },
            {
              sql:
                "INSERT INTO agent_schedule_fires " +
                "(fire_id, schedule_id, scheduled_fire_at_unix, fired_at_unix, outcome) " +
                "VALUES (?, ?, ?, ?, ?)",
              params: ["fire_rollback", "schedule_rollback", 100, 100, "dispatched"],
            },
            {
              sql: "INSERT INTO managed_worker_templates (id, template_json) VALUES (?, ?)",
              params: ["template_rollback", '{"duplicate":true}'],
            },
          ],
        }),
      ),
    ).toMatch(/constraint|unique|primary key/i);

    const rows = await object.query({
      tenantId,
      sql:
        "SELECT " +
        "(SELECT COUNT(*) FROM managed_worker_templates) AS templates, " +
        "(SELECT COUNT(*) FROM self_hosted_run_dispatches) AS dispatches, " +
        "(SELECT COUNT(*) FROM agent_schedules) AS schedules, " +
        "(SELECT COUNT(*) FROM agent_schedule_fires) AS fires",
    });
    expect(rows.results).toEqual([{ templates: 0, dispatches: 0, schedules: 0, fires: 0 }]);
  });

  test("claims one schedule slot at most once inside the tenant object", async () => {
    const tenantId = "tenant_schedule_claim";
    const object = objectFor(tenantId);
    const claimSql =
      "INSERT INTO agent_schedule_fires " +
      "(fire_id, schedule_id, scheduled_fire_at_unix, fired_at_unix, node_id, outcome) " +
      "VALUES (?, ?, ?, ?, ?, ?) " +
      "ON CONFLICT (schedule_id, scheduled_fire_at_unix) DO NOTHING RETURNING fire_id";

    const results = await Promise.all(
      ["node_a", "node_b"].map((nodeId) =>
        object.batch({
          tenantId,
          statements: [
            {
              sql: claimSql,
              params: [
                `fire_${nodeId}`,
                "schedule_once",
                1_800_000_000,
                1_800_000_001,
                nodeId,
                "dispatched",
              ],
            },
          ],
        }),
      ),
    );

    expect(results.map((batch) => batch[0]?.results.length).sort()).toEqual([0, 1]);
    const ledger = await object.query({
      tenantId,
      sql:
        "SELECT schedule_id, scheduled_fire_at_unix, COUNT(*) AS claims " +
        "FROM agent_schedule_fires GROUP BY schedule_id, scheduled_fire_at_unix",
    });
    expect(ledger.results).toEqual([
      { schedule_id: "schedule_once", scheduled_fire_at_unix: 1_800_000_000, claims: 1 },
    ]);
  });

  test("keeps worker rows with the same ids isolated between tenant objects", async () => {
    const tenantA = "tenant_worker_isolation_a";
    const tenantB = "tenant_worker_isolation_b";
    const templateId = "template_same_id";

    await objectFor(tenantA).query({
      tenantId: tenantA,
      sql: "INSERT INTO managed_worker_templates (id, template_json) VALUES (?, ?)",
      params: [templateId, '{"tenant":"a"}'],
    });
    await objectFor(tenantB).query({
      tenantId: tenantB,
      sql: "INSERT INTO managed_worker_templates (id, template_json) VALUES (?, ?)",
      params: [templateId, '{"tenant":"b"}'],
    });

    const rowsA = await objectFor(tenantA).query({
      tenantId: tenantA,
      sql: "SELECT id, template_json FROM managed_worker_templates",
    });
    const rowsB = await objectFor(tenantB).query({
      tenantId: tenantB,
      sql: "SELECT id, template_json FROM managed_worker_templates",
    });
    expect(rowsA.results).toEqual([{ id: templateId, template_json: '{"tenant":"a"}' }]);
    expect(rowsB.results).toEqual([{ id: templateId, template_json: '{"tenant":"b"}' }]);
  });
});

describe("tenant schedule alarms", () => {
  test("sets and clears the native alarm through an admitted tenant RPC", async () => {
    const tenantId = "tenant_schedule_alarm_lifecycle";
    const object = scheduleAlarmObjectFor(tenantId);
    const scheduledAtUnix = 1_800_000_123;

    await object.setScheduleAlarm({ tenantId, scheduledAtUnix });
    expect(await runInDurableObject(object, (_instance, state) => state.storage.getAlarm())).toBe(
      scheduledAtUnix * 1000,
    );

    await object.clearScheduleAlarm({ tenantId });
    expect(
      await runInDurableObject(object, (_instance, state) => state.storage.getAlarm()),
    ).toBeNull();
  });

  test("keeps the alarm and callback isolated to one tenant object", async () => {
    type AlarmHookSeam = {
      alarmCallbackRuns: number;
      alarmCallbackActive: boolean;
      alarmCallbackMessage: TenantScheduleAlarmMessage | null;
      [TENANT_SCHEDULE_ALARM_CALLBACK]: TenantScheduleAlarmCallback;
    };
    const tenantA = "tenant_schedule_alarm_a";
    const tenantB = "tenant_schedule_alarm_b";
    const objectA = scheduleAlarmObjectFor(tenantA);
    const objectB = scheduleAlarmObjectFor(tenantB);
    const seam = async (instance: DurableObjectStub<TenantDataObject>) => {
      await runInDurableObject(instance, (current) => {
        const target = current as unknown as AlarmHookSeam;
        target.alarmCallbackRuns = 0;
        target.alarmCallbackActive = false;
        target.alarmCallbackMessage = null;
        target[TENANT_SCHEDULE_ALARM_CALLBACK] = async function (
          this: AlarmHookSeam,
          message: TenantScheduleAlarmMessage,
        ) {
          expect(this.alarmCallbackActive).toBe(false);
          this.alarmCallbackActive = true;
          await Promise.resolve();
          this.alarmCallbackMessage = message;
          this.alarmCallbackRuns += 1;
          this.alarmCallbackActive = false;
        };
      });
    };

    await seam(objectA);
    await seam(objectB);
    const scheduledAtUnixA = Math.floor(Date.now() / 1000) + 10;
    const scheduledAtUnixB = scheduledAtUnixA + 100;
    await objectA.setScheduleAlarm({ tenantId: tenantA, scheduledAtUnix: scheduledAtUnixA });
    await objectB.setScheduleAlarm({ tenantId: tenantB, scheduledAtUnix: scheduledAtUnixB });

    expect(await refusal(objectA.clearScheduleAlarm({ tenantId: tenantB }))).toMatch(
      /holds tenant tenant_schedule_alarm_a|another tenant/,
    );
    expect(await runInDurableObject(objectA, (_instance, state) => state.storage.getAlarm())).toBe(
      scheduledAtUnixA * 1000,
    );
    expect(await runDurableObjectAlarm(objectA)).toBe(true);
    expect(
      await runInDurableObject(objectA, (instance) => {
        const target = instance as unknown as AlarmHookSeam;
        return {
          runs: target.alarmCallbackRuns,
          active: target.alarmCallbackActive,
          message: target.alarmCallbackMessage,
        };
      }),
    ).toEqual({
      runs: 1,
      active: false,
      message: {
        kind: "tenant-schedule-alarm",
        version: 1,
        tenant_id: tenantA,
        scheduled_at_unix: scheduledAtUnixA,
      },
    });
    expect(
      await runInDurableObject(objectB, (instance) => {
        const target = instance as unknown as AlarmHookSeam;
        return {
          runs: target.alarmCallbackRuns,
          active: target.alarmCallbackActive,
          message: target.alarmCallbackMessage,
        };
      }),
    ).toEqual({ runs: 0, active: false, message: null });
    expect(await runDurableObjectAlarm(objectB)).toBe(true);

    expect(
      await runInDurableObject(objectA, (_instance, state) => state.storage.getAlarm()),
    ).toBeNull();
  });

  test("multiplexes schedule and aggregate deadlines independently", async () => {
    type AlarmHookSeam = {
      scheduleRuns: number;
      flushRuns: number;
      [TENANT_SCHEDULE_ALARM_CALLBACK]: TenantScheduleAlarmCallback;
      [TENANT_AGGREGATE_FLUSH_CALLBACK]: TenantAggregateFlushAlarmCallback;
    };
    const now = Math.floor(Date.now() / 1000);
    const scheduleOnly = aggregateAlarmObjectFor("tenant_alarm_schedule_only");
    const flushOnly = aggregateAlarmObjectFor("tenant_alarm_flush_only");
    const bothDue = aggregateAlarmObjectFor("tenant_alarm_both_due");

    const installHooks = async (instance: DurableObjectStub<TenantDataObject>) => {
      await runInDurableObject(instance, (current) => {
        const target = current as unknown as AlarmHookSeam;
        target.scheduleRuns = 0;
        target.flushRuns = 0;
        target[TENANT_SCHEDULE_ALARM_CALLBACK] = async function (this: AlarmHookSeam) {
          this.scheduleRuns += 1;
        };
        target[TENANT_AGGREGATE_FLUSH_CALLBACK] = async function (
          this: AlarmHookSeam,
          _message: TenantAggregateFlushAlarmMessage,
        ) {
          this.flushRuns += 1;
        };
      });
    };

    await Promise.all([installHooks(scheduleOnly), installHooks(flushOnly), installHooks(bothDue)]);

    await scheduleOnly.setScheduleAlarm({
      tenantId: "tenant_alarm_schedule_only",
      scheduledAtUnix: now + 10,
    });
    await scheduleOnly.setAggregateFlushAlarm({
      tenantId: "tenant_alarm_schedule_only",
      scheduledAtUnix: now + 120,
    });
    await runDurableObjectAlarm(scheduleOnly);
    expect(
      await runInDurableObject(scheduleOnly, (current) => {
        const target = current as unknown as AlarmHookSeam;
        return { scheduleRuns: target.scheduleRuns, flushRuns: target.flushRuns };
      }),
    ).toEqual({ scheduleRuns: 1, flushRuns: 0 });
    expect(
      await runInDurableObject(scheduleOnly, (_instance, state) => state.storage.getAlarm()),
    ).toBe((now + 120) * 1000);

    await flushOnly.setScheduleAlarm({
      tenantId: "tenant_alarm_flush_only",
      scheduledAtUnix: now + 120,
    });
    await flushOnly.setAggregateFlushAlarm({
      tenantId: "tenant_alarm_flush_only",
      scheduledAtUnix: now + 10,
    });
    await runDurableObjectAlarm(flushOnly);
    expect(
      await runInDurableObject(flushOnly, (current) => {
        const target = current as unknown as AlarmHookSeam;
        return { scheduleRuns: target.scheduleRuns, flushRuns: target.flushRuns };
      }),
    ).toEqual({ scheduleRuns: 0, flushRuns: 1 });
    expect(
      await runInDurableObject(flushOnly, (_instance, state) => state.storage.getAlarm()),
    ).toBeGreaterThanOrEqual((now + 60) * 1000);

    await bothDue.setScheduleAlarm({
      tenantId: "tenant_alarm_both_due",
      scheduledAtUnix: now + 10,
    });
    await bothDue.setAggregateFlushAlarm({
      tenantId: "tenant_alarm_both_due",
      scheduledAtUnix: now + 10,
    });
    await runDurableObjectAlarm(bothDue);
    expect(
      await runInDurableObject(bothDue, (current) => {
        const target = current as unknown as AlarmHookSeam;
        return { scheduleRuns: target.scheduleRuns, flushRuns: target.flushRuns };
      }),
    ).toEqual({ scheduleRuns: 1, flushRuns: 1 });
  });

  test("pushes tenant spend to control D1 and replaces it on the next flush", async () => {
    const tenantId = "tenant_aggregate_flush_projection";
    const object = aggregateAlarmObjectFor(tenantId);
    const period = "2026-08";
    await env.CONTROL_DB.prepare("INSERT INTO tenant_databases (tenant_id) VALUES (?)")
      .bind(tenantId)
      .run();
    await object.query({
      tenantId,
      sql:
        "INSERT INTO agent_cost_burn " +
        "(tenant_id, agent_key, period, accumulated_usd, first_seen_unix, updated_at_unix) " +
        "VALUES (?, ?, ?, ?, ?, ?)",
      params: [tenantId, "agent", period, 4.5, 10, 20],
    });
    await object.batch({
      tenantId,
      statements: [
        {
          sql:
            "INSERT INTO stored_assets " +
            "(id, tenant_id, project_id, asset_type, name, version, variant, content_type, " +
            "content_hash, size_bytes, storage_uri, visibility, yanked, created_at_unix, updated_at_unix) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          params: [
            "asset_rollup",
            tenantId,
            null,
            "model",
            "model",
            "1",
            "default",
            "application/octet-stream",
            "hash",
            12,
            "assets/rollup",
            "visible",
            0,
            10,
            20,
          ],
        },
        {
          sql:
            "INSERT INTO asset_channels " +
            "(id, tenant_id, asset_type, name, channel, version, updated_at_unix) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
          params: ["channel_rollup", tenantId, "model", "model", "stable", "1", 20],
        },
      ],
    });
    const before = Math.floor(Date.now() / 1000);
    await object.setAggregateFlushAlarm({ tenantId, scheduledAtUnix: before + 10 });
    await runDurableObjectAlarm(object);

    const first = await env.CONTROL_DB.prepare(
      `SELECT tenant_id, agent_key, period, accumulated_usd, as_of_unix
           FROM tenant_agent_cost_rollups
          WHERE tenant_id = ?`,
    )
      .bind(tenantId)
      .first<{
        tenant_id: string;
        agent_key: string;
        period: string;
        accumulated_usd: number;
        as_of_unix: number;
      }>();
    expect(first).toMatchObject({
      tenant_id: tenantId,
      agent_key: "agent",
      period,
      accumulated_usd: 4.5,
    });
    expect(first?.as_of_unix).toBeGreaterThanOrEqual(before);
    expect(
      await env.CONTROL_DB.prepare(
        "SELECT tenant_id, period, accumulated_usd, as_of_unix FROM tenant_spend_rollups WHERE tenant_id = ?",
      )
        .bind(tenantId)
        .first(),
    ).toMatchObject({ tenant_id: tenantId, period, accumulated_usd: 4.5 });
    expect(
      await env.CONTROL_DB.prepare(
        `SELECT asset_count, asset_bytes, channel_count
             FROM tenant_asset_rollups
            WHERE tenant_id = ?`,
      )
        .bind(tenantId)
        .first<{ asset_count: number; asset_bytes: number; channel_count: number }>(),
    ).toEqual({ asset_count: 1, asset_bytes: 12, channel_count: 1 });

    await object.query({
      tenantId,
      sql: "UPDATE agent_cost_burn SET accumulated_usd = ?, updated_at_unix = ? WHERE tenant_id = ?",
      params: [9.25, 30, tenantId],
    });
    await object.setAggregateFlushAlarm({
      tenantId,
      scheduledAtUnix: Math.floor(Date.now() / 1000) + 10,
    });
    await runDurableObjectAlarm(object);
    expect(
      await env.CONTROL_DB.prepare(
        "SELECT accumulated_usd FROM tenant_agent_cost_rollups WHERE tenant_id = ?",
      )
        .bind(tenantId)
        .first<{ accumulated_usd: number }>(),
    ).toEqual({ accumulated_usd: 9.25 });

    await env.CONTROL_DB.batch([
      env.CONTROL_DB.prepare("DELETE FROM tenant_databases WHERE tenant_id = ?").bind(tenantId),
      env.CONTROL_DB.prepare("DELETE FROM tenant_agent_cost_rollups WHERE tenant_id = ?").bind(
        tenantId,
      ),
      env.CONTROL_DB.prepare("DELETE FROM tenant_spend_rollups WHERE tenant_id = ?").bind(tenantId),
      env.CONTROL_DB.prepare("DELETE FROM tenant_asset_rollups WHERE tenant_id = ?").bind(tenantId),
    ]);
    await object.setAggregateFlushAlarm({
      tenantId,
      scheduledAtUnix: Math.floor(Date.now() / 1000) + 10,
    });
    await runDurableObjectAlarm(object);
    expect(
      await env.CONTROL_DB.prepare(
        "SELECT tenant_id FROM tenant_agent_cost_rollups WHERE tenant_id = ?",
      )
        .bind(tenantId)
        .first(),
    ).toBeNull();
    expect(
      await runInDurableObject(object, (_instance, state) => state.storage.getAlarm()),
    ).toBeNull();
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
