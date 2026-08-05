/**
 * The control-plane half of MCP tenant storage (#862).
 *
 * These tests deliberately cross the Worker boundary: the admin document is
 * written to CONTROL D1, while the catalog row is read from the gateway-owned
 * TenantDataObject addressed by tenant id. A response-only test would miss the
 * old failure mode where CRUD succeeded and the data plane served no server.
 */
import { SELF, env } from "cloudflare:test";
import { DurableObjectD1Database } from "@ferrogate/storage";
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolveDeps } from "../src/adapters.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import { ensureTenantMcpServerCatalogBackfill } from "../src/store/mcp_server_catalog.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

const OPERATOR = operatorKey.secret;

function tenantNamespace(): TenantDataNamespace {
  const namespace = (env as unknown as { TENANT_DATA?: TenantDataNamespace }).TENANT_DATA;
  if (namespace === undefined) throw new Error("MCP control-plane tests require TENANT_DATA");
  return namespace;
}

function tenantDb(tenantId: string): D1Database {
  const namespace = tenantNamespace();
  return new DurableObjectD1Database(
    tenantId,
    namespace.get(namespace.idFromName(tenantId)),
  ).asD1Database();
}

function freshTenant(label: string): string {
  return `mcp_control_${label}_${crypto.randomUUID().slice(0, 8)}`;
}

const serverBody = (tenantId: string, name: string) => ({
  name,
  tenant_id: tenantId,
  url: "https://mcp.example.test/server",
  transport: "http",
  auth_type: "none",
  tools_to_execute: ["echo", "search"],
  tools_to_auto_execute: ["echo"],
  headers: { "x-tenant": tenantId },
  timeout_ms: 12_000,
});

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  arm({ store: "d1", staticKeys: [operatorKey] });
});

describe("MCP admin writes project into the tenant object", () => {
  it("writes, updates, and deletes the object catalog row", async () => {
    const tenantId = freshTenant("crud");
    const created = await SELF.fetch(
      `${BASE}/admin/v1/mcp-servers`,
      jsonRequest(OPERATOR, "POST", serverBody(tenantId, "search")),
    );
    expect(created.status, await created.clone().text()).toBe(201);

    const object = tenantDb(tenantId);
    const createdRow = await object
      .prepare(
        "SELECT tenant_id, name, transport, url, tools_to_execute, headers, timeout_ms FROM mcp_servers",
      )
      .first<{
        tenant_id: string;
        name: string;
        transport: string;
        url: string;
        tools_to_execute: string;
        headers: string;
        timeout_ms: number;
      }>();
    expect(createdRow).toMatchObject({
      tenant_id: tenantId,
      name: "search",
      transport: "streamable_http",
      url: "https://mcp.example.test/server",
      timeout_ms: 12_000,
    });
    expect(JSON.parse(createdRow?.tools_to_execute ?? "null")).toEqual(["echo", "search"]);
    expect(JSON.parse(createdRow?.headers ?? "null")).toEqual({ "x-tenant": tenantId });

    const patched = await SELF.fetch(
      `${BASE}/admin/v1/mcp-servers/search`,
      jsonRequest(OPERATOR, "PATCH", {
        tools_to_execute: ["search"],
        tools_to_auto_execute: [],
        tools_to_exclude: ["search"],
        timeout_ms: 3_000,
      }),
    );
    expect(patched.status, await patched.clone().text()).toBe(200);
    const patchedRow = await object
      .prepare(
        "SELECT tools_to_execute, tools_to_auto_execute, tools_to_exclude, timeout_ms FROM mcp_servers",
      )
      .first<{
        tools_to_execute: string;
        tools_to_auto_execute: string;
        tools_to_exclude: string;
        timeout_ms: number;
      }>();
    expect(JSON.parse(patchedRow?.tools_to_execute ?? "null")).toEqual(["search"]);
    expect(JSON.parse(patchedRow?.tools_to_auto_execute ?? "null")).toEqual([]);
    expect(JSON.parse(patchedRow?.tools_to_exclude ?? "null")).toEqual(["search"]);
    expect(patchedRow?.timeout_ms).toBe(3_000);

    const deleted = await SELF.fetch(`${BASE}/admin/v1/mcp-servers/search`, {
      method: "DELETE",
      headers: bearer(OPERATOR),
    });
    expect(deleted.status, await deleted.clone().text()).toBe(200);
    expect(
      await object.prepare("SELECT COUNT(*) AS total FROM mcp_servers").first<{ total: number }>(),
    ).toEqual({
      total: 0,
    });
    expect(
      await db()
        .prepare(
          "SELECT COUNT(*) AS total FROM control_plane_resources WHERE resource_kind = ? AND resource_id = ?",
        )
        .bind("mcp-servers", "search")
        .first<{ total: number }>(),
    ).toEqual({ total: 0 });
  });

  it("removes an invalidated server instead of leaving a serving row", async () => {
    const tenantId = freshTenant("disable");
    await SELF.fetch(
      `${BASE}/admin/v1/mcp-servers`,
      jsonRequest(OPERATOR, "POST", serverBody(tenantId, "disabled")),
    );

    const disabled = await SELF.fetch(
      `${BASE}/admin/v1/mcp-servers/disabled`,
      jsonRequest(OPERATOR, "PATCH", { enabled: false }),
    );
    expect(disabled.status, await disabled.clone().text()).toBe(200);
    expect(
      await tenantDb(tenantId)
        .prepare("SELECT COUNT(*) AS total FROM mcp_servers WHERE name = ?")
        .bind("disabled")
        .first<{ total: number }>(),
    ).toEqual({ total: 0 });
  });

  it("keeps two tenant catalogs physically fenced", async () => {
    const first = freshTenant("fence_a");
    const second = freshTenant("fence_b");
    await SELF.fetch(
      `${BASE}/admin/v1/mcp-servers`,
      jsonRequest(OPERATOR, "POST", serverBody(first, "first")),
    );
    await SELF.fetch(
      `${BASE}/admin/v1/mcp-servers`,
      jsonRequest(OPERATOR, "POST", serverBody(second, "second")),
    );

    const firstRows = await tenantDb(first)
      .prepare("SELECT DISTINCT tenant_id FROM mcp_servers")
      .all<{
        tenant_id: string;
      }>();
    const secondRows = await tenantDb(second)
      .prepare("SELECT DISTINCT tenant_id FROM mcp_servers")
      .all<{
        tenant_id: string;
      }>();
    expect(firstRows.results).toEqual([{ tenant_id: first }]);
    expect(secondRows.results).toEqual([{ tenant_id: second }]);
    expect(
      await tenantDb(first)
        .prepare("SELECT COUNT(*) AS total FROM mcp_servers WHERE name = ?")
        .bind("second")
        .first<{ total: number }>(),
    ).toEqual({ total: 0 });
  });
});

describe("MCP catalog backfill", () => {
  it("copies a legacy control document on a tenant-scoped read and then stops", async () => {
    const tenantId = freshTenant("backfill");
    const document = serverBody(tenantId, "legacy");
    await db()
      .prepare(
        `INSERT INTO control_plane_resources
           (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
         VALUES ('mcp-servers', ?, ?, 1, 1, 1)`,
      )
      .bind("legacy", JSON.stringify(document))
      .run();

    arm({ store: "d1", nativeKeys: [tenantKey("mcp-tenant-read", tenantId)] });
    const read = await SELF.fetch(`${BASE}/admin/v1/mcp-servers/legacy`, {
      headers: bearer("mcp-tenant-read"),
    });
    expect(read.status, await read.clone().text()).toBe(200);

    const object = tenantDb(tenantId);
    const row = await object
      .prepare("SELECT url FROM mcp_servers WHERE name = ?")
      .bind("legacy")
      .first<{
        url: string;
      }>();
    expect(row?.url).toBe(document.url);
    const mark = await object
      .prepare("SELECT detail FROM tenant_provisioning_marks WHERE tenant_id = ? AND mark = ?")
      .bind(tenantId, "mcp_server_catalog_backfill_v1")
      .first<{ detail: string }>();
    expect(JSON.parse(mark?.detail ?? "{}").state).toBe("complete");

    await object
      .prepare("UPDATE mcp_servers SET url = ? WHERE tenant_id = ? AND name = ?")
      .bind("https://object-authority.example.test", tenantId, "legacy")
      .run();
    await ensureTenantMcpServerCatalogBackfill(
      resolveDeps(env as unknown as ControlPlaneBindings),
      tenantId,
    );
    const authoritative = await object
      .prepare("SELECT url FROM mcp_servers WHERE tenant_id = ? AND name = ?")
      .bind(tenantId, "legacy")
      .first<{ url: string }>();
    expect(authoritative?.url).toBe("https://object-authority.example.test");
  });
});
