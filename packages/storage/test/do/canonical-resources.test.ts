import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, test } from "vitest";
import type { ControlDataNamespace } from "../../src/control-data-object.js";
import { CONTROL_MIGRATIONS } from "../../src/control-schema-sql.js";
import { type TenantDataNamespace, sqlStatements } from "../../src/tenant-data-object.js";
import { TENANT_MIGRATIONS } from "../../src/tenant-schema-sql.js";

const bindings = env as unknown as {
  CONTROL_DATA: ControlDataNamespace;
  TENANT_DATA: TenantDataNamespace;
};

describe("single-authority resource migrations in real workerd", () => {
  test("key upgrade preserves enforced permissions and custom metadata, with indexed SQL views", async () => {
    const tenantId = `canonical-key-${crypto.randomUUID()}`;
    const stub = bindings.TENANT_DATA.get(bindings.TENANT_DATA.idFromName(tenantId));
    await stub.query({ tenantId, sql: "SELECT 1", params: [] });
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.deleteAll();
      for (const migration of TENANT_MIGRATIONS.filter((m) => m.version <= 36)) {
        for (const statement of sqlStatements(migration.sql)) state.storage.sql.exec(statement);
      }
      state.storage.sql.exec(
        `INSERT INTO api_keys(id,tenant_id,workspace_id,project_id,name,key_prefix,key_hash,last4,enabled,scopes_json)
        VALUES('key',?,'ws','p','Key','prefix','hash','last',0,'["models.read"]')`,
        tenantId,
      );
      state.storage.sql.exec(
        `INSERT INTO tenant_resources(resource_kind,resource_id,document_json,revision,created_at_unix,updated_at_unix)
        VALUES('virtual-keys','key',?,3,10,20)`,
        JSON.stringify({
          id: "key",
          tenant_id: tenantId,
          enabled: true,
          scopes: ["*"],
          note: "preserved",
        }),
      );
      const migration = TENANT_MIGRATIONS.find((m) => m.version === 37);
      expect(migration).toBeDefined();
      state.storage.transactionSync(() => {
        for (const statement of sqlStatements(migration!.sql)) state.storage.sql.exec(statement);
      });
      expect(
        state.storage.sql.exec("SELECT type FROM sqlite_master WHERE name='api_keys'").toArray(),
      ).toEqual([{ type: "view" }]);
      expect(
        state.storage.sql.exec("SELECT enabled,scopes_json FROM api_keys WHERE id='key'").toArray(),
      ).toEqual([{ enabled: 0, scopes_json: '["models.read"]' }]);
      const doc = state.storage.sql
        .exec<{ document_json: string }>(
          "SELECT document_json FROM tenant_resources WHERE resource_kind='virtual-keys' AND resource_id='key'",
        )
        .toArray()[0];
      expect(JSON.parse(doc!.document_json)).toMatchObject({
        note: "preserved",
        enabled: false,
        scopes: ["models.read"],
      });
      for (const [column, value, index] of [
        ["key_hash", "hash", "idx_api_keys_document_hash"],
        ["key_prefix", "prefix", "idx_api_keys_document_prefix"],
      ]) {
        const plan = state.storage.sql
          .exec(`EXPLAIN QUERY PLAN SELECT id FROM api_keys WHERE ${column}=?`, value)
          .toArray();
        expect(JSON.stringify(plan)).toContain(index);
      }
      state.storage.sql.exec(
        "UPDATE tenant_resources SET document_json=json_set(document_json,'$.enabled',json('true')) WHERE resource_kind='virtual-keys' AND resource_id='key'",
      );
      expect(
        state.storage.sql.exec("SELECT enabled FROM api_keys WHERE id='key'").toArray(),
      ).toEqual([{ enabled: 1 }]);
    });
  });

  test("wallet cleanup retains unopened balances and removes adopted balance copies", async () => {
    const tenantId = `canonical-wallet-${crypto.randomUUID()}`;
    const stub = bindings.TENANT_DATA.get(bindings.TENANT_DATA.idFromName(tenantId));
    await stub.query({ tenantId, sql: "SELECT 1", params: [] });
    await runInDurableObject(stub, async (_instance, state) => {
      state.storage.sql.exec(
        "INSERT INTO wallets(tenant_id,balance_credits,created_at_unix,updated_at_unix) VALUES(?,12345,1,1)",
        tenantId,
      );
      for (const id of [tenantId, "unopened"])
        state.storage.sql.exec(
          `INSERT INTO tenant_resources(resource_kind,resource_id,document_json,revision,created_at_unix,updated_at_unix) VALUES('wallets',?,?,1,1,1)`,
          id,
          JSON.stringify({ id, balance_cents: 99, balance_credits: "990000", currency: "USD" }),
        );
      for (const sql of sqlStatements(TENANT_MIGRATIONS.find((m) => m.version === 38)!.sql))
        state.storage.sql.exec(sql);
      const rows = state.storage.sql
        .exec<{ resource_id: string; document_json: string }>(
          "SELECT resource_id,document_json FROM tenant_resources WHERE resource_kind='wallets'",
        )
        .toArray();
      expect(JSON.parse(rows.find((r) => r.resource_id === tenantId)!.document_json)).toEqual({
        id: tenantId,
        currency: "USD",
      });
      expect(
        JSON.parse(rows.find((r) => r.resource_id === "unopened")!.document_json),
      ).toHaveProperty("balance_cents", 99);
      expect(
        state.storage.sql
          .exec("SELECT balance_credits FROM wallets WHERE tenant_id=?", tenantId)
          .toArray(),
      ).toEqual([{ balance_credits: 12345 }]);
    });
  });

  test("payment and MCP upgrades preserve runtime fields and custom metadata without physical copies", async () => {
    const tenantId = `canonical-instruments-${crypto.randomUUID()}`;
    const stub = bindings.TENANT_DATA.get(bindings.TENANT_DATA.idFromName(tenantId));
    await stub.query({ tenantId, sql: "SELECT 1", params: [] });
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.deleteAll();
      for (const migration of TENANT_MIGRATIONS.filter((m) => m.version <= 38)) {
        for (const statement of sqlStatements(migration.sql)) state.storage.sql.exec(statement);
      }
      state.storage.sql.exec(
        "INSERT INTO payment_methods VALUES('pm',?,'stripe','customer','provider-pm',1,123)",
        tenantId,
      );
      state.storage.sql.exec(
        "INSERT INTO mcp_servers(tenant_id,name,transport,auth_type,tools_to_execute,tools_to_auto_execute,timeout_ms) VALUES(?,'search','sse','none','[\"search\"]','[]',3000)",
        tenantId,
      );
      state.storage.sql.exec(
        "INSERT INTO tenant_resources VALUES('mcp-servers','old-id',?,1,1,1)",
        JSON.stringify({
          id: "old-id",
          name: "search",
          tenant_id: tenantId,
          note: "keep",
          transport: "http",
        }),
      );
      for (const migration of TENANT_MIGRATIONS.filter((m) => m.version >= 39)) {
        state.storage.transactionSync(() => {
          for (const statement of sqlStatements(migration.sql)) state.storage.sql.exec(statement);
        });
      }
      expect(
        state.storage.sql
          .exec(
            "SELECT name,type FROM sqlite_master WHERE name IN ('payment_methods','mcp_servers') ORDER BY name",
          )
          .toArray(),
      ).toEqual([
        { name: "mcp_servers", type: "view" },
        { name: "payment_methods", type: "view" },
      ]);
      expect(
        state.storage.sql
          .exec("SELECT provider_payment_method_id,is_default,created_at_unix FROM payment_methods")
          .toArray(),
      ).toEqual([
        { provider_payment_method_id: "provider-pm", is_default: 1, created_at_unix: 123 },
      ]);
      const document = state.storage.sql
        .exec<{ document_json: string }>(
          "SELECT document_json FROM tenant_resources WHERE resource_kind='mcp-servers'",
        )
        .toArray()[0];
      expect(JSON.parse(document!.document_json)).toMatchObject({
        id: "old-id",
        note: "keep",
        transport: "sse",
        tools_to_execute: ["search"],
      });
    });
  });

  test("control cleanup refuses to discard a possibly unique legacy credential", async () => {
    const stub = bindings.CONTROL_DATA.get(
      bindings.CONTROL_DATA.idFromName(`canonical-guard-${crypto.randomUUID()}`),
    );
    await stub.query({ tenantId: "control-apac", sql: "SELECT 1", params: [] });
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.deleteAll();
      for (const migration of CONTROL_MIGRATIONS.filter(
        (m) => m.name !== "0050_remove_cross_object_details",
      )) {
        for (const statement of sqlStatements(migration.sql)) state.storage.sql.exec(statement);
      }
      state.storage.sql.exec(
        "INSERT INTO self_hosted_worker_registrations VALUES('legacy',1,?)",
        JSON.stringify({ worker_id: "legacy", tenant_id: "t", token_secret: "unique-secret" }),
      );
      const migration = CONTROL_MIGRATIONS.find(
        (m) => m.name === "0050_remove_cross_object_details",
      )!;
      expect(() =>
        state.storage.transactionSync(() => {
          for (const statement of sqlStatements(migration.sql)) state.storage.sql.exec(statement);
        }),
      ).toThrow(/CHECK constraint/);
      const row = state.storage.sql
        .exec<{ registration_json: string }>(
          "SELECT registration_json FROM self_hosted_worker_registrations WHERE id='legacy'",
        )
        .toArray()[0];
      expect(JSON.parse(row!.registration_json).token_secret).toBe("unique-secret");
    });
  });

  test("control schema keeps route fields and rejects renewed full mirrors", async () => {
    const stub = bindings.CONTROL_DATA.get(
      bindings.CONTROL_DATA.idFromName(`canonical-control-${crypto.randomUUID()}`),
    );
    await stub.query({ tenantId: "control-apac", sql: "SELECT 1", params: [] });
    await runInDurableObject(stub, (_instance, state) => {
      expect(
        state.storage.sql.exec("SELECT type FROM sqlite_master WHERE name='plans'").toArray(),
      ).toEqual([{ type: "view" }]);
      expect(state.storage.sql.exec("SELECT id FROM plans WHERE id='free'").toArray()).toEqual([
        { id: "free" },
      ]);
      const columns = state.storage.sql
        .exec<{ name: string }>("PRAGMA table_info(site_domain_verifications)")
        .toArray()
        .map((r) => r.name);
      expect(columns).toEqual([
        "tenant_id",
        "hostname",
        "state",
        "token_expires_at_unix",
        "verification_expires_at_unix",
      ]);
      expect(() =>
        state.storage.sql.exec(
          "INSERT INTO self_hosted_worker_registrations(id,registered_at_unix,registration_json) VALUES('worker',1,?)",
          JSON.stringify({
            worker_id: "worker",
            tenant_id: "t",
            workspace_id: "w",
            token_secret: "do-not-copy",
          }),
        ),
      ).toThrow(/credentials belong/);
      expect(() =>
        state.storage.sql.exec(
          "INSERT INTO control_plane_resources(resource_kind,resource_id,document_json,revision,created_at_unix,updated_at_unix) VALUES('mcp-servers','mcp',?,1,1,1)",
          JSON.stringify({ id: "mcp", tenant_id: "t", headers: { Authorization: "do-not-copy" } }),
        ),
      ).toThrow(/configuration belongs/);
    });
    const status = await stub.schemaStatus({ tenantId: "control-apac" });
    expect(status.appliedCount).toBe(CONTROL_MIGRATIONS.length);
    expect(status.failure).toBeNull();
  });
});
