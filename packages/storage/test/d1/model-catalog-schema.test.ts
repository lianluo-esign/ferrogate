/**
 * The tenant model catalog schema (#811), against real D1 and the SQLite
 * Durable Object facade. These tests deliberately exercise the constraints
 * through the same D1-shaped handle that storage callers use.
 */
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import { TENANT_MIGRATIONS } from "../../src/tenant-schema-sql.js";
import { TENANT_A, setupDatabases, tenantDb } from "./harness.js";

const db = () => tenantDb(TENANT_A);

async function resetCatalog(): Promise<void> {
  await db().batch([
    db().prepare("DELETE FROM catalog_model_offerings"),
    db().prepare("DELETE FROM catalog_models"),
    db().prepare("DELETE FROM provider_channels"),
    db().prepare("DELETE FROM catalog_revisions"),
    db().prepare("DELETE FROM tenant_database_identity"),
  ]);
}

async function insertChannel(id: string, name = id): Promise<void> {
  await db()
    .prepare(
      "INSERT INTO provider_channels " +
        "(id, tenant_id, name, kind, base_url) VALUES (?, ?, ?, 'openai', 'https://example.test/v1')",
    )
    .bind(id, TENANT_A, name)
    .run();
}

async function insertModel(id = "model-1", name = "gpt-test"): Promise<void> {
  await db()
    .prepare("INSERT INTO catalog_models (id, tenant_id, name) VALUES (?, ?, ?)")
    .bind(id, TENANT_A, name)
    .run();
}

async function insertOffering(
  id: string,
  providerId: string,
  options: {
    modelId?: string;
    upstream?: string;
    role?: "primary" | "fallback" | "canary" | "shadow";
    inputPrice?: number | null;
  } = {},
): Promise<void> {
  await db()
    .prepare(
      "INSERT INTO catalog_model_offerings " +
        "(id, tenant_id, model_id, provider_id, upstream_model_id, role, input_price_per_1m) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(
      id,
      TENANT_A,
      options.modelId ?? "model-1",
      providerId,
      options.upstream ?? id,
      options.role ?? "fallback",
      options.inputPrice === undefined ? 1.0 : options.inputPrice,
    )
    .run();
}

function sqlStatements(sql: string): string[] {
  return sql
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n")
    .split(";")
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);
}

beforeAll(async () => {
  await setupDatabases();
});

beforeEach(async () => {
  await resetCatalog();
});

describe("tenant model catalog schema", () => {
  test("foreign keys are enabled before relying on RESTRICT/CASCADE", async () => {
    const row = await db().prepare("PRAGMA foreign_keys").first<{ foreign_keys: number }>();
    expect(row?.foreign_keys).toBe(1);
  });

  test("one model round-trips four offerings across four channels and prices", async () => {
    await Promise.all([
      insertChannel("channel-1"),
      insertChannel("channel-2"),
      insertChannel("channel-3"),
      insertChannel("channel-4"),
    ]);
    await insertModel();
    await insertOffering("offering-1", "channel-1", {
      role: "primary",
      inputPrice: 0.25,
      upstream: "provider-model-1",
    });
    await insertOffering("offering-2", "channel-2", {
      role: "fallback",
      inputPrice: 0.5,
      upstream: "provider-model-2",
    });
    await insertOffering("offering-3", "channel-3", {
      role: "canary",
      inputPrice: 0.75,
      upstream: "provider-model-3",
    });
    await insertOffering("offering-4", "channel-4", {
      role: "shadow",
      inputPrice: 1.0,
      upstream: "provider-model-4",
    });

    const result = await db()
      .prepare(
        "SELECT m.name, o.provider_id, o.upstream_model_id, o.role, o.input_price_per_1m " +
          "FROM catalog_models m " +
          "JOIN catalog_model_offerings o ON o.tenant_id = m.tenant_id AND o.model_id = m.id " +
          "WHERE m.tenant_id = ? ORDER BY o.input_price_per_1m",
      )
      .bind(TENANT_A)
      .all<{
        name: string;
        provider_id: string;
        upstream_model_id: string;
        role: string;
        input_price_per_1m: number;
      }>();

    expect(result.results).toEqual([
      {
        name: "gpt-test",
        provider_id: "channel-1",
        upstream_model_id: "provider-model-1",
        role: "primary",
        input_price_per_1m: 0.25,
      },
      {
        name: "gpt-test",
        provider_id: "channel-2",
        upstream_model_id: "provider-model-2",
        role: "fallback",
        input_price_per_1m: 0.5,
      },
      {
        name: "gpt-test",
        provider_id: "channel-3",
        upstream_model_id: "provider-model-3",
        role: "canary",
        input_price_per_1m: 0.75,
      },
      {
        name: "gpt-test",
        provider_id: "channel-4",
        upstream_model_id: "provider-model-4",
        role: "shadow",
        input_price_per_1m: 1,
      },
    ]);
  });

  test("allows zero and NULL input prices as distinct values", async () => {
    await insertChannel("free-channel");
    await insertChannel("unpriced-channel");
    await insertModel();
    await insertOffering("free-offering", "free-channel", { inputPrice: 0 });
    await insertOffering("unpriced-offering", "unpriced-channel", { inputPrice: null });

    const prices = await db()
      .prepare(
        "SELECT input_price_per_1m, input_price_per_1m IS NULL AS is_unpriced " +
          "FROM catalog_model_offerings ORDER BY id",
      )
      .all<{ input_price_per_1m: number | null; is_unpriced: number }>();
    expect(prices.results).toEqual([
      { input_price_per_1m: 0, is_unpriced: 0 },
      { input_price_per_1m: null, is_unpriced: 1 },
    ]);
  });

  test("allows at most one primary, canary, and shadow offering per model", async () => {
    await insertChannel("channel-1");
    await insertChannel("channel-2");
    await insertChannel("channel-3");
    await insertChannel("channel-4");
    await insertModel();
    await insertOffering("primary-1", "channel-1", { role: "primary" });
    await expect(insertOffering("primary-2", "channel-2", { role: "primary" })).rejects.toThrow();
    await insertOffering("canary-1", "channel-2", { role: "canary" });
    await expect(insertOffering("canary-2", "channel-3", { role: "canary" })).rejects.toThrow();
    await insertOffering("shadow-1", "channel-3", { role: "shadow" });
    await expect(insertOffering("shadow-2", "channel-4", { role: "shadow" })).rejects.toThrow();
  });

  test("rejects a duplicate model/channel/upstream binding", async () => {
    await insertChannel("channel-1");
    await insertModel();
    await insertOffering("offering-1", "channel-1", { upstream: "same-upstream" });
    await expect(
      insertOffering("offering-2", "channel-1", { upstream: "same-upstream" }),
    ).rejects.toThrow();
  });

  test("restricts channel deletion and cascades offerings on model deletion", async () => {
    await insertChannel("channel-1");
    await insertModel();
    await insertOffering("offering-1", "channel-1");

    await expect(
      db().prepare("DELETE FROM provider_channels WHERE id = ?").bind("channel-1").run(),
    ).rejects.toThrow();
    await db().prepare("DELETE FROM catalog_models WHERE id = ?").bind("model-1").run();
    const remaining = await db()
      .prepare("SELECT COUNT(*) AS count FROM catalog_model_offerings")
      .first<{ count: number }>();
    expect(remaining?.count).toBe(0);
  });

  test("allows exactly the identity row whose id is 1", async () => {
    await db()
      .prepare("INSERT INTO tenant_database_identity (id, tenant_id) VALUES (1, ?)")
      .bind(TENANT_A)
      .run();
    await expect(
      db()
        .prepare("INSERT INTO tenant_database_identity (id, tenant_id) VALUES (2, ?)")
        .bind(TENANT_A)
        .run(),
    ).rejects.toThrow();
    const rows = await db()
      .prepare("SELECT id, tenant_id FROM tenant_database_identity")
      .all<{ id: number; tenant_id: string }>();
    expect(rows.results).toEqual([{ id: 1, tenant_id: TENANT_A }]);
  });

  test("converts the legacy one-row catalog into a primary offering", async () => {
    await db().batch([
      db().prepare("DROP TABLE IF EXISTS catalog_model_offerings"),
      db().prepare("DROP TABLE IF EXISTS catalog_models"),
      db().prepare("DROP TABLE IF EXISTS provider_channels"),
      db().prepare("DROP TABLE IF EXISTS catalog_revisions"),
      db().prepare("DROP TABLE IF EXISTS tenant_database_identity"),
      db().prepare(
        "CREATE TABLE model_catalog (" +
          "tenant_id TEXT NOT NULL, model TEXT NOT NULL, provider TEXT NOT NULL DEFAULT '*', " +
          "provider_model TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, " +
          "input_price_per_1m REAL NOT NULL, output_price_per_1m REAL NOT NULL, " +
          "cached_input_multiplier REAL, cache_write_multiplier REAL, " +
          "audio_second_price_per_1m REAL, audio_character_price_per_1m REAL, " +
          "source TEXT NOT NULL DEFAULT 'platform_seed', created_at_unix INTEGER NOT NULL, " +
          "updated_at_unix INTEGER NOT NULL, PRIMARY KEY (tenant_id, model))",
      ),
      db()
        .prepare(
          "INSERT INTO model_catalog " +
            "(tenant_id, model, provider, provider_model, input_price_per_1m, " +
            "output_price_per_1m, cached_input_multiplier, source, created_at_unix, updated_at_unix) " +
            "VALUES (?, 'legacy-model', '*', 'legacy-upstream', 2.5, 10, 0.5, 'tenant', 10, 20)",
        )
        .bind(TENANT_A),
    ]);

    const migration = TENANT_MIGRATIONS.find((entry) => entry.version === 9);
    expect(migration).toBeDefined();
    const statements = sqlStatements(migration?.sql ?? "");
    await db().batch(statements.map((statement) => db().prepare(statement)));
    await db().batch(statements.map((statement) => db().prepare(statement)));

    const converted = await db()
      .prepare(
        "SELECT m.name, p.name AS channel, o.upstream_model_id, " +
          "o.input_price_per_1m, o.cached_input_price_per_1m, o.source " +
          "FROM catalog_models m " +
          "JOIN catalog_model_offerings o ON o.model_id = m.id AND o.tenant_id = m.tenant_id " +
          "JOIN provider_channels p ON p.id = o.provider_id AND p.tenant_id = o.tenant_id",
      )
      .first<Record<string, string | number>>();
    const legacyTable = await db()
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'model_catalog'")
      .first();

    expect(converted).toMatchObject({
      name: "legacy-model",
      channel: "platform-default",
      upstream_model_id: "legacy-upstream",
      input_price_per_1m: 2.5,
      cached_input_price_per_1m: 1.25,
      source: "tenant",
    });
    expect(legacyTable).toBeNull();
  });
});
