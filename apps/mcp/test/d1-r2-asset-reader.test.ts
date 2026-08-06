/**
 * The D1+R2-backed {@link D1R2AssetReader} mount test.
 *
 * Asserts that `resolvePorts` selects `D1R2AssetReader` when `env.ASSETS` and
 * the gateway-owned `env.TENANT_DATA` namespace are present, and that
 * `resources/list` / `resources/read` return published assets through the
 * durable path.
 *
 * ## Why this test exists
 *
 * `InMemoryAssets` (`src/ports.ts`) was the ONLY implementation of
 * {@link AssetReaderPort}, and `resolvePorts` wired it unconditionally — so
 * every asset the MCP Worker published lived in one isolate's heap. The bytes
 * half was already durable (R2, through the gateway); only the metadata half
 * was not, which is the worst of the two shapes: the object is really there
 * and nothing can find it.
 *
 * This test seeds real rows into tenant Durable Objects and real objects into
 * `env.ASSETS`, then drives the Worker over `SELF.fetch` and asserts the
 * durable path serves them. Deleting the `assets` line in `resolvePorts`
 * turns this test RED.
 *
 * ## #366 withholding
 *
 * An asset whose `visibility` is not `'visible'` or whose `yanked` flag is
 * `true` must be indistinguishable from a missing one — on the listing AND
 * on the read. This test pins that property against the D1+R2 path.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { DurableObjectTenantDatabaseRouter } from "@ferrogate/storage";
import {
  type AuthContext,
  D1R2AssetReader,
  type McpEnv,
  inMemoryPorts,
  resetInMemoryPorts,
  resolvePorts,
} from "../src/ports.js";
import { READ_KEY, TENANT, rpcRequest } from "./fixtures.js";
import { registerDurableObjectTenant, tenantObjectDb } from "./tenant-object.js";
import { tenantDataNamespace } from "./tenant-storage.js";

const CONTENT = new TextEncoder().encode("echo hello");
const OTHER_TENANT = "some-other-tenant";

interface McpTestBindings {
  readonly ASSETS?: R2Bucket;
  readonly DB?: D1Database;
}

/** Assert that the production asset bindings are defined, then return them. */
function requireBindings(bindings: McpTestBindings): {
  ASSETS: R2Bucket;
  DB: D1Database;
} {
  const { ASSETS, DB } = bindings;
  if (ASSETS === undefined || DB === undefined) {
    throw new Error("ASSETS and DB must be defined in test bindings");
  }
  return { ASSETS, DB };
}

/** Seed one asset row in a tenant-object D1 facade and one object in R2. */
async function seedAsset(
  db: D1Database,
  bucket: R2Bucket,
  overrides: Record<string, unknown> = {},
): Promise<void> {
  const assetType = String(overrides.asset_type ?? "cli_tool");
  const name = String(overrides.name ?? "deploy");
  const version = String(overrides.version ?? "1.0.0");
  const tenantId = String(overrides.tenant_id ?? TENANT);
  const visibility = String(overrides.visibility ?? "visible");
  const yanked = overrides.yanked === true ? 1 : 0;
  const storageUri = `assets/v1/t/${tenantId}/obj/${assetType}/${name}/${version}//`;

  // Compute sha256 of the content for the content_hash column.
  const digest = await crypto.subtle.digest("SHA-256", CONTENT);
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");

  // Insert the metadata row into the tenant-object D1 facade.
  await db
    .prepare(
      "INSERT OR IGNORE INTO stored_assets " +
        "(id, tenant_id, asset_type, name, version, content_type, content_hash, " +
        "size_bytes, storage_uri, variant, yanked, visibility, created_at_unix, updated_at_unix) " +
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
    )
    .bind(
      `${tenantId}:${assetType}:${name}:${version}`,
      tenantId,
      assetType,
      name,
      version,
      "text/plain",
      hex,
      CONTENT.byteLength,
      storageUri,
      "",
      yanked,
      visibility,
      1_000_000,
      1_000_000,
    )
    .all();

  // Put the object body into the R2 bucket.
  await bucket.put(storageUri, CONTENT, {
    httpMetadata: { contentType: "text/plain" },
  });
}

async function clearTenantAssets(): Promise<void> {
  for (const tenantId of [TENANT, OTHER_TENANT]) {
    const db = tenantObjectDb(tenantId);
    const existing = await db.prepare("SELECT storage_uri FROM stored_assets").all<{
      storage_uri: string;
    }>();
    const { ASSETS } = requireBindings(env as unknown as McpTestBindings);
    for (const row of existing.results ?? []) {
      try {
        await ASSETS.delete(row.storage_uri);
      } catch {
        // Best-effort cleanup.
      }
    }
    await db.prepare("DELETE FROM stored_assets").run();
  }
}

function assetReader(bindings: McpTestBindings): D1R2AssetReader {
  const { ASSETS, DB } = requireBindings(bindings);
  const router = new DurableObjectTenantDatabaseRouter(tenantDataNamespace(env), DB);
  return new D1R2AssetReader((tenantId) => router.databaseFor(tenantId), ASSETS);
}

describe("D1R2AssetReader — production asset reader mount", () => {
  let bindings: McpTestBindings;

  beforeEach(async () => {
    resetInMemoryPorts();
    // Register the READ_KEY in the in-memory auth fallback so the durable
    // auth port can resolve it. The dev posture (FG_DEV_IN_MEMORY_PORTS === "1")
    // is active in tests, so the durable auth port consults the in-memory table
    // as its fallback.
    inMemoryPorts().auth.register(READ_KEY, {
      apiKeyId: "key-1",
      organizationId: TENANT,
      workspaceId: "ws-1",
      userId: "user-1",
      scopes: ["tools.read", "assets.read"],
      permissions: ["mcp.execute"],
      platformOperator: false,
    } satisfies AuthContext);
    bindings = env as unknown as McpTestBindings;

    // Clean up any assets left by previous tests in both tenant objects.
    await clearTenantAssets();
  });

  it("production posture reads each tenant's own Durable Object", async () => {
    const { ASSETS, DB } = requireBindings(bindings);
    const TENANT_DATA = tenantDataNamespace(env);
    const tenantA = tenantObjectDb(TENANT);
    const tenantB = tenantObjectDb(OTHER_TENANT);

    await seedAsset(tenantA, ASSETS, { name: "object-a" });
    await seedAsset(tenantB, ASSETS, {
      name: "object-b",
      tenant_id: OTHER_TENANT,
    });

    const ports = resolvePorts({
      ASSETS,
      DB,
      TENANT_DATA,
      FG_DEV_IN_MEMORY_PORTS: "0",
    } satisfies McpEnv);

    expect(ports.assets).toBeInstanceOf(D1R2AssetReader);
    await expect(ports.assets.list(TENANT)).resolves.toEqual([
      expect.objectContaining({ name: "object-a" }),
    ]);
    await expect(ports.assets.list(OTHER_TENANT)).resolves.toEqual([
      expect.objectContaining({ name: "object-b" }),
    ]);
    await expect(ports.assets.read(TENANT, "cli_tool", "object-b", "1.0.0")).resolves.toMatchObject(
      { ok: false, error: { kind: "not_found" } },
    );
  });

  it("resolvePorts selects D1R2AssetReader when ASSETS and tenant object bindings are present", () => {
    const { ASSETS, DB } = requireBindings(bindings);
    const TENANT_DATA = tenantDataNamespace(env);

    // Build a minimal env with both bindings and NO dev-mode flag.
    const mcpEnv: McpEnv = {
      ASSETS,
      DB,
      TENANT_DATA,
    };
    const ports = resolvePorts(mcpEnv);
    expect(ports.assets).toBeInstanceOf(D1R2AssetReader);
  });

  it("resolvePorts falls back to InMemoryAssets when ASSETS is absent", () => {
    const { DB } = requireBindings(bindings);
    const TENANT_DATA = tenantDataNamespace(env);

    const mcpEnv: McpEnv = {
      DB,
      TENANT_DATA: tenantDataNamespace(env),
      // ASSETS deliberately absent
    };
    const ports = resolvePorts(mcpEnv);
    expect(ports.assets).not.toBeInstanceOf(D1R2AssetReader);
  });

  it("resolvePorts falls back to InMemoryAssets when TENANT_DATA is absent", () => {
    const { ASSETS, DB } = requireBindings(bindings);

    const mcpEnv: McpEnv = {
      ASSETS,
      DB,
      // TENANT_DATA deliberately absent
    };
    const ports = resolvePorts(mcpEnv);
    expect(ports.assets).not.toBeInstanceOf(D1R2AssetReader);
  });

  it("D1R2AssetReader.list returns seeded assets", async () => {
    const { ASSETS } = requireBindings(bindings);
    await seedAsset(tenantObjectDb(TENANT), ASSETS);

    const reader = assetReader(bindings);
    const assets = await reader.list(TENANT);
    expect(assets).toHaveLength(1);
    expect(assets[0]).toMatchObject({
      assetType: "cli_tool",
      name: "deploy",
      version: "1.0.0",
      contentType: "text/plain",
      downloadable: true,
    });
  });

  it("D1R2AssetReader.read returns content for a downloadable asset", async () => {
    const { ASSETS } = requireBindings(bindings);
    await seedAsset(tenantObjectDb(TENANT), ASSETS);

    const reader = assetReader(bindings);
    const result = await reader.read(TENANT, "cli_tool", "deploy", "1.0.0");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.asset.name).toBe("deploy");
      expect(new TextDecoder().decode(result.content)).toBe("echo hello");
    }
  });

  it("D1R2AssetReader.read returns not_found for a non-visible asset (#366)", async () => {
    const { ASSETS } = requireBindings(bindings);
    await seedAsset(tenantObjectDb(TENANT), ASSETS, {
      name: "deploy-pending",
      visibility: "pending_scan",
    });

    const reader = assetReader(bindings);
    const result = await reader.read(TENANT, "cli_tool", "deploy-pending", "1.0.0");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe("not_found");
    }
  });

  it("D1R2AssetReader.read returns not_found for a yanked asset (#366)", async () => {
    const { ASSETS } = requireBindings(bindings);
    await seedAsset(tenantObjectDb(TENANT), ASSETS, {
      name: "deploy-yanked",
      yanked: true,
    });

    const reader = assetReader(bindings);
    const result = await reader.read(TENANT, "cli_tool", "deploy-yanked", "1.0.0");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe("not_found");
    }
  });

  it("D1R2AssetReader enforces cross-tenant isolation", async () => {
    const { ASSETS } = requireBindings(bindings);

    // Seed one asset in each tenant object.
    await seedAsset(tenantObjectDb(TENANT), ASSETS, {
      name: "deploy-tenant-a",
      tenant_id: TENANT,
    });
    await seedAsset(tenantObjectDb(OTHER_TENANT), ASSETS, {
      name: "deploy-tenant-b",
      tenant_id: OTHER_TENANT,
    });

    const reader = assetReader(bindings);

    // list() for tenant A returns only tenant A's assets.
    const assetsA = await reader.list(TENANT);
    expect(assetsA).toHaveLength(1);
    if (assetsA[0] !== undefined) {
      expect(assetsA[0].name).toBe("deploy-tenant-a");
    }

    // list() for tenant B returns only tenant B's assets.
    const assetsB = await reader.list(OTHER_TENANT);
    expect(assetsB).toHaveLength(1);
    if (assetsB[0] !== undefined) {
      expect(assetsB[0].name).toBe("deploy-tenant-b");
    }

    // read() for tenant A cannot read tenant B's asset.
    const resultA = await reader.read(TENANT, "cli_tool", "deploy-tenant-b", "1.0.0");
    expect(resultA.ok).toBe(false);
    if (!resultA.ok) {
      expect(resultA.error.kind).toBe("not_found");
    }

    // read() for tenant B cannot read tenant A's asset.
    const resultB = await reader.read(OTHER_TENANT, "cli_tool", "deploy-tenant-a", "1.0.0");
    expect(resultB.ok).toBe(false);
    if (!resultB.ok) {
      expect(resultB.error.kind).toBe("not_found");
    }
  });

  it("D1R2AssetReader.read returns not_found for a missing asset", async () => {
    const { ASSETS } = requireBindings(bindings);
    const reader = assetReader(bindings);
    const result = await reader.read(TENANT, "cli_tool", "ghost", "9.9.9");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe("not_found");
    }
  });

  it("D1R2AssetReader.read returns integrity error on hash mismatch", async () => {
    const { ASSETS } = requireBindings(bindings);
    // Seed with the correct hash, then PUT different content in R2 so the
    // stored hash no longer matches the body.
    await seedAsset(tenantObjectDb(TENANT), ASSETS, {
      name: "deploy-bad-hash",
    });
    // Overwrite the R2 object with different content.
    const storageUri = `assets/v1/t/${TENANT}/obj/cli_tool/deploy-bad-hash/1.0.0//`;
    await ASSETS.put(storageUri, new TextEncoder().encode("wrong content"));

    const reader = assetReader(bindings);
    const result = await reader.read(TENANT, "cli_tool", "deploy-bad-hash", "1.0.0");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe("integrity");
    }
  });
});

/**
 * End-to-end test: seeds tenant Durable Objects + R2 and drives the Worker over
 * SELF.fetch.
 *
 * This test switches to the non-dev posture (FG_DEV_IN_MEMORY_PORTS !== "1")
 * so that resolvePorts selects D1R2AssetReader. The READ_KEY is seeded into
 * the control database's static_api_keys table so the durable auth port can
 * authenticate the request.
 */
describe("D1R2AssetReader — end-to-end over SELF.fetch", () => {
  let bindings: McpTestBindings;
  let originalDevPorts: string | undefined;

  beforeEach(async () => {
    resetInMemoryPorts();
    bindings = env as unknown as McpTestBindings;
    const { DB } = requireBindings(bindings);
    const TENANT_DATA = tenantDataNamespace(env);

    // Switch to the non-dev posture so resolvePorts selects D1R2AssetReader.
    originalDevPorts = (env as unknown as Record<string, unknown>).FG_DEV_IN_MEMORY_PORTS as
      | string
      | undefined;
    (env as unknown as Record<string, unknown>).FG_DEV_IN_MEMORY_PORTS = "0";

    // Seed the READ_KEY into the control database's static_api_keys table.
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(READ_KEY.trim()));
    const keyHash = `sha256:${[...new Uint8Array(digest)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")}`;
    await DB.prepare(
      "INSERT OR REPLACE INTO static_api_keys " +
        "(key_hash, id, tenant_id, platform_operator, scopes_json, enabled, created_at_unix, updated_at_unix) " +
        "VALUES (?1, ?2, ?3, ?4, ?5, 1, 1000000, 1000000)",
    )
      .bind(keyHash, "key-1", TENANT, 0, JSON.stringify(["tools.read", "assets.read"]))
      .all();
    await registerDurableObjectTenant(TENANT);
    // Clean up any assets left by previous tests in both tenant objects.
    await clearTenantAssets();
  });

  afterEach(() => {
    // Restore the original dev posture.
    (env as unknown as Record<string, unknown>).FG_DEV_IN_MEMORY_PORTS = originalDevPorts;
  });

  it("resources/list returns seeded assets over SELF.fetch", async () => {
    const { ASSETS } = requireBindings(bindings);
    await seedAsset(tenantObjectDb(TENANT), ASSETS);

    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "resources/list", params: {} },
        { key: READ_KEY },
      ),
    );
    const body = (await res.json()) as {
      error?: { code: number; message: string };
      result?: { resources?: { uri: string; name: string }[] };
    };
    expect(body.error).toBeUndefined();
    expect(body.result?.resources).toHaveLength(1);
    expect(body.result?.resources?.[0]).toMatchObject({
      uri: "asset://cli_tool/deploy/1.0.0",
      name: "deploy@1.0.0",
    });
  });

  it("resources/list withholds pending_scan and yanked assets over SELF.fetch (#366)", async () => {
    const { ASSETS } = requireBindings(bindings);
    // Seed one visible asset (should appear), one pending_scan (should be hidden),
    // and one yanked (should be hidden).
    await seedAsset(tenantObjectDb(TENANT), ASSETS, { name: "deploy-visible" });
    await seedAsset(tenantObjectDb(TENANT), ASSETS, {
      name: "deploy-pending",
      visibility: "pending_scan",
    });
    await seedAsset(tenantObjectDb(TENANT), ASSETS, {
      name: "deploy-yanked",
      yanked: true,
    });

    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "resources/list", params: {} },
        { key: READ_KEY },
      ),
    );
    const body = (await res.json()) as {
      error?: { code: number; message: string };
      result?: { resources?: { uri: string; name: string }[] };
    };
    expect(body.error).toBeUndefined();
    // Only the visible asset should appear in the listing.
    expect(body.result?.resources).toHaveLength(1);
    expect(body.result?.resources?.[0]).toMatchObject({
      uri: "asset://cli_tool/deploy-visible/1.0.0",
      name: "deploy-visible@1.0.0",
    });
  });

  it("resources/read returns asset content over SELF.fetch", async () => {
    const { ASSETS } = requireBindings(bindings);
    await seedAsset(tenantObjectDb(TENANT), ASSETS);

    const res = await SELF.fetch(
      rpcRequest(
        {
          jsonrpc: "2.0",
          id: 1,
          method: "resources/read",
          params: { uri: "asset://cli_tool/deploy/1.0.0" },
        },
        { key: READ_KEY },
      ),
    );
    const body = (await res.json()) as {
      error?: { code: number; message: string };
      result?: { contents?: { uri: string; text?: string }[] };
    };
    expect(body.error).toBeUndefined();
    expect(body.result?.contents).toHaveLength(1);
    expect(body.result?.contents?.[0]).toMatchObject({
      uri: "asset://cli_tool/deploy/1.0.0",
      text: "echo hello",
    });
  });

  it("resources/read returns not_found for a non-visible asset over SELF.fetch (#366)", async () => {
    const { ASSETS } = requireBindings(bindings);
    await seedAsset(tenantObjectDb(TENANT), ASSETS, {
      name: "deploy-pending",
      visibility: "pending_scan",
    });

    const res = await SELF.fetch(
      rpcRequest(
        {
          jsonrpc: "2.0",
          id: 1,
          method: "resources/read",
          params: { uri: "asset://cli_tool/deploy-pending/1.0.0" },
        },
        { key: READ_KEY },
      ),
    );
    const body = (await res.json()) as {
      error?: { code: number; message: string };
    };
    expect(body.error).toBeDefined();
    expect(body.error?.code).toBe(-32602);
  });

  it("resources/list enforces cross-tenant isolation over SELF.fetch", async () => {
    const { ASSETS } = requireBindings(bindings);

    // Seed one asset in each tenant object.
    await seedAsset(tenantObjectDb(TENANT), ASSETS, {
      name: "deploy-tenant-a",
      tenant_id: TENANT,
    });
    await seedAsset(tenantObjectDb(OTHER_TENANT), ASSETS, {
      name: "deploy-tenant-b",
      tenant_id: OTHER_TENANT,
    });

    // list() for tenant A returns only tenant A's assets.
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "resources/list", params: {} },
        { key: READ_KEY },
      ),
    );
    const body = (await res.json()) as {
      error?: { code: number; message: string };
      result?: { resources?: { uri: string; name: string }[] };
    };
    expect(body.error).toBeUndefined();
    const resources = body.result?.resources;
    expect(resources).toHaveLength(1);
    if (resources !== undefined && resources[0] !== undefined) {
      expect(resources[0].name).toBe("deploy-tenant-a@1.0.0");
    }
  });
});
