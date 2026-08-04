/**
 * The Rust-era `control_plane_resources` registry DOCUMENT → `tenant_databases`
 * TABLE migration (inventory-data-billing §1.7), against REAL D1.
 *
 * Two properties carry the whole thing:
 *  1. a migrated row lands with `binding_name = NULL`, so the router FAILS
 *     CLOSED on it until a redeploy assigns a binding — a migration that
 *     invented a binding name would route to `undefined`, or to another
 *     tenant's database;
 *  2. re-running is idempotent AND non-destructive: an existing row (which is
 *     strictly richer than the document, because it carries the binding name)
 *     is never overwritten.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  ControlDatabaseTenantRegistry,
  EnvBindingTenantDatabaseRouter,
  StorageError,
  TENANT_DATABASE_REGISTRY_ID,
  TENANT_DATABASE_REGISTRY_KIND,
  migrateTenantDatabaseRegistryDocument,
  parseTenantDatabaseRegistryDocument,
} from "../../src/index.js";
import "./harness.js";

const NOW = 1_784_073_600;

async function writeDocument(documentJson: string): Promise<void> {
  await env.CONTROL_DB.prepare(
    "INSERT INTO control_plane_resources (resource_kind, resource_id, document_json) " +
      "VALUES (?, ?, ?) ON CONFLICT (resource_kind, resource_id) DO UPDATE SET " +
      "document_json = excluded.document_json",
  )
    .bind(TENANT_DATABASE_REGISTRY_KIND, TENANT_DATABASE_REGISTRY_ID, documentJson)
    .run();
}

const RUST_DOCUMENT = JSON.stringify({
  control_database_id: "uuid-control",
  tenant_databases: { zeta: "uuid-zeta", acme: "uuid-acme" },
});

beforeAll(async () => {
  await applyD1Migrations(env.CONTROL_DB, env.CONTROL_MIGRATIONS);
});

beforeEach(async () => {
  await env.CONTROL_DB.batch([
    env.CONTROL_DB.prepare("DELETE FROM tenant_databases"),
    env.CONTROL_DB.prepare("DELETE FROM control_plane_resources"),
  ]);
});

describe("the Rust-era document key", () => {
  test("is the Rust constant pair verbatim", () => {
    // A different pair here would make the migration read nothing and report a
    // successful, empty migration against a control database full of tenants.
    expect(TENANT_DATABASE_REGISTRY_KIND).toBe("d1_tenant_database");
    expect(TENANT_DATABASE_REGISTRY_ID).toBe("registry");
  });
});

describe("parseTenantDatabaseRegistryDocument", () => {
  test("decodes the serde snake_case shape", () => {
    expect(parseTenantDatabaseRegistryDocument(RUST_DOCUMENT)).toEqual({
      controlDatabaseId: "uuid-control",
      tenantDatabases: { zeta: "uuid-zeta", acme: "uuid-acme" },
    });
  });

  test("`#[serde(default)]` on both fields: an empty object decodes", () => {
    expect(parseTenantDatabaseRegistryDocument("{}")).toEqual({
      controlDatabaseId: "",
      tenantDatabases: {},
    });
  });

  test("refuses malformed JSON, a non-object, and a non-string uuid", () => {
    expect(() => parseTenantDatabaseRegistryDocument("{oops")).toThrow(StorageError);
    expect(() => parseTenantDatabaseRegistryDocument("[]")).toThrow(StorageError);
    expect(() => parseTenantDatabaseRegistryDocument('{"tenant_databases":{"a":42}}')).toThrow(
      StorageError,
    );
    expect(() => parseTenantDatabaseRegistryDocument('{"tenant_databases":{"a":"  "}}')).toThrow(
      StorageError,
    );
  });
});

describe("migrateTenantDatabaseRegistryDocument", () => {
  test("no document is a no-op, not an error", async () => {
    expect(await migrateTenantDatabaseRegistryDocument(env.CONTROL_DB, NOW)).toEqual({
      documentFound: false,
      inserted: [],
      skipped: [],
      controlDatabaseId: "",
    });
  });

  test("inserts one row per tenant, sorted, and reports the control database", async () => {
    await writeDocument(RUST_DOCUMENT);
    const result = await migrateTenantDatabaseRegistryDocument(env.CONTROL_DB, NOW);
    expect(result.documentFound).toBe(true);
    expect(result.inserted).toEqual(["acme", "zeta"]);
    expect(result.skipped).toEqual([]);
    expect(result.controlDatabaseId).toBe("uuid-control");

    const rows = await new ControlDatabaseTenantRegistry(env.CONTROL_DB).list();
    expect(rows).toEqual([
      // `native_binding` / `pending` are what a migrated row MEANS under #820's
      // vocabulary: it names a real D1 database whose `[[d1_databases]]` stanza
      // has not been deployed, i.e. "provisioned but not yet routable". They are
      // asserted rather than elided because the migration states them
      // explicitly — leaving them to the column defaults would give the same two
      // values by luck, and a later default change would move them silently.
      {
        tenantId: "acme",
        databaseUuid: "uuid-acme",
        databaseName: "ferrogate-tenant-acme",
        schemaVersion: 1,
        storageBackend: "native_binding",
        status: "pending",
      },
      {
        tenantId: "zeta",
        databaseUuid: "uuid-zeta",
        databaseName: "ferrogate-tenant-zeta",
        schemaVersion: 1,
        storageBackend: "native_binding",
        status: "pending",
      },
    ]);
  });

  test("a migrated tenant has NO binding name, so the router fails closed on it", async () => {
    await writeDocument(RUST_DOCUMENT);
    await migrateTenantDatabaseRegistryDocument(env.CONTROL_DB, NOW);

    const router = new EnvBindingTenantDatabaseRouter(
      env as unknown as Record<string, unknown>,
      env.CONTROL_DB,
      { registrationTtlMs: 0 },
    );
    // NOT the control database, NOT another tenant's — an error.
    await expect(router.forTenant("acme")).rejects.toThrow(StorageError);
  });

  test("re-running is idempotent", async () => {
    await writeDocument(RUST_DOCUMENT);
    await migrateTenantDatabaseRegistryDocument(env.CONTROL_DB, NOW);
    const second = await migrateTenantDatabaseRegistryDocument(env.CONTROL_DB, NOW + 500);
    expect(second.inserted).toEqual([]);
    expect(second.skipped).toEqual(["acme", "zeta"]);
    expect((await new ControlDatabaseTenantRegistry(env.CONTROL_DB).list()).length).toBe(2);
  });

  test("re-running after a redeploy does NOT erase the assigned binding name", async () => {
    await writeDocument(RUST_DOCUMENT);
    await migrateTenantDatabaseRegistryDocument(env.CONTROL_DB, NOW);
    const registry = new ControlDatabaseTenantRegistry(env.CONTROL_DB);
    await registry.upsert(
      {
        tenantId: "acme",
        databaseUuid: "uuid-acme",
        databaseName: "ferrogate-tenant-acme",
        bindingName: "TENANT_DB_A",
        schemaVersion: 3,
      },
      NOW + 10,
    );

    await migrateTenantDatabaseRegistryDocument(env.CONTROL_DB, NOW + 20);

    // The document has no binding name and no schema version; if the migration
    // were an upsert instead of an insert-if-absent it would clobber both and
    // un-route a live tenant.
    expect(await registry.get("acme")).toEqual({
      tenantId: "acme",
      databaseUuid: "uuid-acme",
      databaseName: "ferrogate-tenant-acme",
      bindingName: "TENANT_DB_A",
      schemaVersion: 3,
      storageBackend: "native_binding",
      status: "pending",
    });
  });

  test("two tenants claiming one database uuid is refused by UNIQUE(database_uuid)", async () => {
    await writeDocument(
      JSON.stringify({
        control_database_id: "uuid-control",
        tenant_databases: { alpha: "uuid-shared", beta: "uuid-shared" },
      }),
    );
    await expect(migrateTenantDatabaseRegistryDocument(env.CONTROL_DB, NOW)).rejects.toThrow(
      StorageError,
    );
    // `alpha` (sorted first) landed before `beta` was refused; the refusal is
    // the point — two tenants must never share one database.
    const rows = await new ControlDatabaseTenantRegistry(env.CONTROL_DB).list();
    expect(rows.map((r) => r.tenantId)).toEqual(["alpha"]);
  });

  test("the database name and schema version are overridable", async () => {
    await writeDocument(RUST_DOCUMENT);
    await migrateTenantDatabaseRegistryDocument(env.CONTROL_DB, NOW, {
      databaseName: (tenantId, uuid) => `db-${tenantId}-${uuid}`,
      schemaVersion: 7,
    });
    const acme = await new ControlDatabaseTenantRegistry(env.CONTROL_DB).get("acme");
    expect(acme?.databaseName).toBe("db-acme-uuid-acme");
    expect(acme?.schemaVersion).toBe(7);
  });
});
