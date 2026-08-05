import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";
import { DurableObjectD1Database } from "@ferrogate/storage";
import {
  TenantObjectCredentialGrants,
  loadServerCatalog,
} from "../src/durable.js";
import type {
  McpIdentityActor,
  McpServerConfig,
  StoredMcpOauthCredential,
} from "../src/ports.js";

interface TenantBindings {
  TENANT_DATA: TenantDataNamespace;
}

const TENANT_DATA = (env as unknown as TenantBindings).TENANT_DATA;
const TENANT_A = "mcp-object-tenant-a";
const TENANT_B = "mcp-object-tenant-b";
const ACTOR_A: McpIdentityActor = { tenantId: TENANT_A, workspaceId: "w1", userId: "u1" };
const ACTOR_B: McpIdentityActor = { tenantId: TENANT_B, workspaceId: "w1", userId: "u1" };

function databaseFor(tenantId: string): D1Database {
  const stub = TENANT_DATA.get(TENANT_DATA.idFromName(tenantId));
  return new DurableObjectD1Database(tenantId, stub).asD1Database();
}

function credential(actor: McpIdentityActor): StoredMcpOauthCredential {
  return {
    id: `mcpid_${actor.tenantId}:w1:u1:search`,
    actor,
    serverName: "search",
    issuer: "https://idp.example.test",
    subject: "subject-1",
    tokenType: "Bearer",
    scopes: ["mcp.read"],
    accessTokenNonce: new Uint8Array([1, 2, 3]),
    accessTokenCiphertext: new Uint8Array([4, 5, 6, 7]),
    refreshTokenNonce: new Uint8Array([8, 9]),
    refreshTokenCiphertext: new Uint8Array([10, 11, 12]),
    expiresAtUnix: 2_000,
    keyVersion: 1,
    version: 1,
    authorizationGeneration: 0,
    createdAtUnix: 1_000,
    updatedAtUnix: 1_000,
  };
}

async function clearTenant(tenantId: string): Promise<void> {
  const db = databaseFor(tenantId);
  await db.batch([
    db.prepare("DELETE FROM mcp_oauth_credentials"),
    db.prepare("DELETE FROM mcp_identity_generations"),
    db.prepare("DELETE FROM mcp_servers"),
  ]);
}

beforeEach(async () => {
  await clearTenant(TENANT_A);
  await clearTenant(TENANT_B);
});

describe("MCP identity state in TenantDataObject", () => {
  it("is installed by the tenant migration ledger, not an isolate schema cache", async () => {
    const status = await TENANT_DATA.get(TENANT_DATA.idFromName(TENANT_A)).schemaVersion();
    expect(status.failure).toBeNull();
    expect(status.appliedThisWake).toContain("0014_mcp_identity");

    const tables = await databaseFor(TENANT_A)
      .prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (?, ?, ?) ORDER BY name",
      )
      .bind("mcp_servers", "mcp_oauth_credentials", "mcp_identity_generations")
      .all<{ name: string }>();
    expect(tables.results.map((row) => row.name)).toEqual([
      "mcp_identity_generations",
      "mcp_oauth_credentials",
      "mcp_servers",
    ]);
  });

  it("keeps catalogs physically and logically fenced by tenant", async () => {
    const server: McpServerConfig = {
      name: "search",
      transport: "streamable_http",
      url: "https://a.example.test/mcp",
      authType: "none",
      toolsToExecute: ["search"],
      toolsToAutoExecute: [],
      timeoutMs: 5_000,
    };
    const db = databaseFor(TENANT_A);
    await db
      .prepare(
        `INSERT INTO mcp_servers
          (tenant_id, name, transport, url, auth_type, tools_to_execute,
           tools_to_auto_execute, tools_to_exclude, headers, oauth,
           signed_jwt_audience, timeout_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        TENANT_A,
        server.name,
        server.transport,
        server.url,
        server.authType,
        JSON.stringify(server.toolsToExecute),
        JSON.stringify(server.toolsToAutoExecute),
        null,
        null,
        null,
        null,
        server.timeoutMs,
      )
      .run();

    expect(await loadServerCatalog(TENANT_DATA, TENANT_A)).toEqual([server]);
    expect(await loadServerCatalog(TENANT_DATA, TENANT_B)).toEqual([]);
  });

  it("preserves encrypted bytes, generation CAS, and revocation in the object", async () => {
    const grants = new TenantObjectCredentialGrants(TENANT_DATA);
    const stored = credential(ACTOR_A);
    await grants.put(stored);

    const reloaded = await grants.get(ACTOR_A, "search");
    expect([...((reloaded as StoredMcpOauthCredential).accessTokenCiphertext)]).toEqual([4, 5, 6, 7]);
    expect([...((reloaded as StoredMcpOauthCredential).refreshTokenCiphertext ?? [])]).toEqual([10, 11, 12]);
    expect(await grants.get(ACTOR_B, "search")).toBeUndefined();

    await grants.bumpGeneration(ACTOR_A, "search");
    expect(await grants.authorizationGeneration(ACTOR_A, "search")).toBe(1);
    expect(
      await grants.commit(
        { actor: ACTOR_A, serverName: "search", authorizationGeneration: 0 },
        credential(ACTOR_A),
      ),
    ).toBe(false);

    const revoked = await grants.revoke(ACTOR_A, "search", 1_500, "local_revoked");
    expect(revoked?.revokedAtUnix).toBe(1_500);
    expect(await grants.revoke(ACTOR_A, "search", 2_000, "second")).toBeUndefined();
    expect((await grants.get(ACTOR_A, "search"))?.revokedAtUnix).toBe(1_500);
  });
});
