/**
 * The D1+R2-backed {@link D1R2AssetReader} mount test.
 *
 * Asserts that `resolvePorts` selects `D1R2AssetReader` when both `env.ASSETS`
 * and `env.TENANT_DB` are present, and that `resources/list` / `resources/read`
 * return published assets through the durable path.
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
 * This test seeds real rows into `env.TENANT_DB` and real objects into
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
import { env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import {
  D1R2AssetReader,
  inMemoryPorts,
  resetInMemoryPorts,
  resolvePorts,
  type AuthContext,
  type McpEnv,
} from "../src/ports.js";
import { READ_KEY, TENANT, rpcRequest } from "./fixtures.js";

const CONTENT = new TextEncoder().encode("echo hello");

interface McpTestBindings {
  readonly ASSETS?: R2Bucket;
  readonly TENANT_DB?: D1Database;
}

/** Seed one asset row in the tenant D1 and one object in the R2 bucket. */
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

  // Insert the metadata row into the tenant D1.
  await db
    .prepare(
      "INSERT OR IGNORE INTO stored_assets " +
        "(id, tenant_id, asset_type, name, version, content_type, content_hash, " +
        "size_bytes, storage_uri, variant, yanked, visibility, created_at_unix, updated_at_unix) " +
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
    )
    .bind(
      `${tenantId}_${assetType}_${name}_${version}`,
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

async function rpc(method: string, params: Record<string, unknown>) {
  const res = await SELF.fetch(
    rpcRequest({ jsonrpc: "2.0", id: 1, method, params }, { key: READ_KEY }),
  );
  return (await res.json()) as {
    error?: { code: number; message: string };
    result?: { resources?: { uri: string }[]; contents?: unknown[] };
  };
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

    // Clean up any assets left by previous tests.
    const { ASSETS, TENANT_DB } = bindings;
    if (ASSETS !== undefined && TENANT_DB !== undefined) {
      const existing = await TENANT_DB.prepare("SELECT storage_uri FROM stored_assets").all<{
        storage_uri: string;
      }>();
      for (const row of existing.results ?? []) {
        try {
          await ASSETS.delete(row.storage_uri);
        } catch {
          // Best-effort cleanup.
        }
      }
      await TENANT_DB.prepare("DELETE FROM stored_assets").all();
    }
  });

  it("resolvePorts selects D1R2AssetReader when both ASSETS and TENANT_DB are present", () => {
    const { ASSETS, TENANT_DB } = bindings;
    expect(ASSETS).toBeDefined();
    expect(TENANT_DB).toBeDefined();

    // Build a minimal env with both bindings and NO dev-mode flag.
    const env: McpEnv = {
      ASSETS: ASSETS!,
      TENANT_DB: TENANT_DB!,
    };
    const ports = resolvePorts(env);
    expect(ports.assets).toBeInstanceOf(D1R2AssetReader);
  });

  it("resolvePorts falls back to InMemoryAssets when ASSETS is absent", () => {
    const { TENANT_DB } = bindings;
    expect(TENANT_DB).toBeDefined();

    const env: McpEnv = {
      TENANT_DB: TENANT_DB!,
      // ASSETS deliberately absent
    };
    const ports = resolvePorts(env);
    expect(ports.assets).not.toBeInstanceOf(D1R2AssetReader);
  });

  it("resolvePorts falls back to InMemoryAssets when TENANT_DB is absent", () => {
    const { ASSETS } = bindings;
    expect(ASSETS).toBeDefined();

    const env: McpEnv = {
      ASSETS: ASSETS!,
      // TENANT_DB deliberately absent
    };
    const ports = resolvePorts(env);
    expect(ports.assets).not.toBeInstanceOf(D1R2AssetReader);
  });

  it("D1R2AssetReader.list returns seeded assets", async () => {
    const { ASSETS, TENANT_DB } = bindings;
    await seedAsset(TENANT_DB!, ASSETS!);

    const reader = new D1R2AssetReader(TENANT_DB!, ASSETS!);
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
    const { ASSETS, TENANT_DB } = bindings;
    await seedAsset(TENANT_DB!, ASSETS!);

    const reader = new D1R2AssetReader(TENANT_DB!, ASSETS!);
    const result = await reader.read(TENANT, "cli_tool", "deploy", "1.0.0");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.asset.name).toBe("deploy");
      expect(new TextDecoder().decode(result.content)).toBe("echo hello");
    }
  });

  it("D1R2AssetReader.read returns not_found for a non-visible asset (#366)", async () => {
    const { ASSETS, TENANT_DB } = bindings;
    await seedAsset(TENANT_DB!, ASSETS!, {
      name: "deploy-pending",
      visibility: "pending_scan",
    });

    const reader = new D1R2AssetReader(TENANT_DB!, ASSETS!);
    const result = await reader.read(TENANT, "cli_tool", "deploy-pending", "1.0.0");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe("not_found");
    }
  });

  it("D1R2AssetReader.read returns not_found for a yanked asset (#366)", async () => {
    const { ASSETS, TENANT_DB } = bindings;
    await seedAsset(TENANT_DB!, ASSETS!, {
      name: "deploy-yanked",
      yanked: true,
    });

    const reader = new D1R2AssetReader(TENANT_DB!, ASSETS!);
    const result = await reader.read(TENANT, "cli_tool", "deploy-yanked", "1.0.0");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe("not_found");
    }
  });

  it("D1R2AssetReader.list scopes to tenant", async () => {
    const { ASSETS, TENANT_DB } = bindings;
    await seedAsset(TENANT_DB!, ASSETS!, {
      name: "deploy-other",
      tenant_id: "some-other-tenant",
    });

    const reader = new D1R2AssetReader(TENANT_DB!, ASSETS!);
    const assets = await reader.list(TENANT);
    expect(assets).toHaveLength(0);
  });

  it("D1R2AssetReader.read returns not_found for a missing asset", async () => {
    const { ASSETS, TENANT_DB } = bindings;
    const reader = new D1R2AssetReader(TENANT_DB!, ASSETS!);
    const result = await reader.read(TENANT, "cli_tool", "ghost", "9.9.9");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe("not_found");
    }
  });

  it("D1R2AssetReader.read returns integrity error on hash mismatch", async () => {
    const { ASSETS, TENANT_DB } = bindings;
    // Seed with the correct hash, then PUT different content in R2 so the
    // stored hash no longer matches the body.
    await seedAsset(TENANT_DB!, ASSETS!, {
      name: "deploy-bad-hash",
    });
    // Overwrite the R2 object with different content.
    const storageUri = `assets/v1/t/${TENANT}/obj/cli_tool/deploy-bad-hash/1.0.0//`;
    await ASSETS!.put(storageUri, new TextEncoder().encode("wrong content"));

    const reader = new D1R2AssetReader(TENANT_DB!, ASSETS!);
    const result = await reader.read(TENANT, "cli_tool", "deploy-bad-hash", "1.0.0");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe("integrity");
    }
  });
});
