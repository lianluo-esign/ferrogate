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

describe("MCP control directory", () => {
  it("stores only the destination and cannot restore a deleted resource", async () => {
    const tenantId = freshTenant("directory");
    const created = await SELF.fetch(
      `${BASE}/admin/v1/mcp-servers`,
      jsonRequest(operatorKey.secret, "POST", serverBody(tenantId, "directory")),
    );
    expect(created.status).toBe(201);
    const row = await db()
      .prepare(
        "SELECT document_json FROM control_plane_resources WHERE resource_kind='mcp-servers' AND resource_id='directory'",
      )
      .first<{ document_json: string }>();
    expect(JSON.parse(row!.document_json)).toEqual({ id: "directory", tenant_id: tenantId });
    await tenantDb(tenantId)
      .prepare(
        "DELETE FROM tenant_resources WHERE resource_kind='mcp-servers' AND resource_id='directory'",
      )
      .run();
    arm({ store: "d1", nativeKeys: [tenantKey("mcp-directory-read", tenantId)] });
    const response = await SELF.fetch(`${BASE}/admin/v1/mcp-servers/directory`, {
      headers: bearer("mcp-directory-read"),
    });
    expect(response.status).toBe(404);
  });
});
