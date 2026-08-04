import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { readAssetForMcp } from "../src/tools.js";
import {
  type AuthContext,
  type DispatchContext,
  type McpEnv,
  resolvePorts,
  resetInMemoryPorts,
  inMemoryPorts,
} from "../src/ports.js";
import { TENANT } from "./fixtures.js";

const API_KEY_ID = "key-mcp-asset-egress";
const CONTENT = new TextEncoder().encode("durable mcp asset");
const ASSET_ID = "stored-assets-real-variant-id";

interface Bindings {
  readonly ASSETS?: R2Bucket;
  readonly BILLING_DB?: D1Database;
  readonly TENANT_DB?: D1Database;
}

function requireBindings(): { ASSETS: R2Bucket; BILLING_DB: D1Database; TENANT_DB: D1Database } {
  const bindings = env as unknown as Bindings;
  if (bindings.ASSETS === undefined || bindings.BILLING_DB === undefined || bindings.TENANT_DB === undefined) {
    throw new Error("MCP D1 egress test requires ASSETS, BILLING_DB, and TENANT_DB bindings");
  }
  return {
    ASSETS: bindings.ASSETS,
    BILLING_DB: bindings.BILLING_DB,
    TENANT_DB: bindings.TENANT_DB,
  };
}

async function seedAsset(db: D1Database, bucket: R2Bucket): Promise<void> {
  const digest = await crypto.subtle.digest("SHA-256", CONTENT);
  const hash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const storageUri = `assets/v1/t/${TENANT}/obj/cli_tool/deploy/1.0.0/linux-x86_64/obj_durable`;
  await db
    .prepare(
      "INSERT INTO stored_assets " +
        "(id, tenant_id, asset_type, name, version, content_type, content_hash, size_bytes, storage_uri, variant, yanked, visibility, created_at_unix, updated_at_unix) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(
      ASSET_ID,
      TENANT,
      "cli_tool",
      "deploy",
      "1.0.0",
      "text/plain",
      hash,
      CONTENT.byteLength,
      storageUri,
      "linux-x86_64",
      0,
      "visible",
      1_800_000_000,
      1_800_000_000,
    )
    .run();
  await bucket.put(storageUri, CONTENT, { httpMetadata: { contentType: "text/plain" } });
}

function context(): DispatchContext {
  const auth: AuthContext = {
    apiKeyId: API_KEY_ID,
    organizationId: TENANT,
    workspaceId: "workspace-mcp-egress",
    userId: "user-mcp-egress",
    scopes: ["assets.read"],
    permissions: ["mcp.execute"],
    platformOperator: false,
  };
  return { requestId: "req_mcp_d1_egress", auth };
}

beforeEach(async () => {
  resetInMemoryPorts();
  const { BILLING_DB, ASSETS, TENANT_DB } = requireBindings();
  await BILLING_DB.batch([
    BILLING_DB.prepare("DELETE FROM billing_report_outbox"),
    BILLING_DB.prepare("DELETE FROM billing_ledger"),
    BILLING_DB.prepare("DELETE FROM billing_events"),
  ]);
  const rows = await TENANT_DB.prepare("SELECT storage_uri FROM stored_assets").all<{ storage_uri: string }>();
  for (const row of rows.results ?? []) await ASSETS.delete(row.storage_uri);
  await TENANT_DB.prepare("DELETE FROM stored_assets").run();
});

describe("#801 MCP non-dev D1 asset egress", () => {
  it("reads through D1/R2 and persists billing rows with api-key attribution", async () => {
    const { ASSETS, BILLING_DB, TENANT_DB } = requireBindings();
    await seedAsset(TENANT_DB, ASSETS);

    const ports = resolvePorts({ ASSETS, BILLING_DB, TENANT_DB } satisfies McpEnv);
    const result = await readAssetForMcp(ports, context(), "cli_tool", "deploy", "1.0.0");
    expect(result.ok).toBe(true);
    expect(ports.assetEgress.meter.constructor.name).toBe("LedgerAssetEgressMeter");

    const ledger = await BILLING_DB
      .prepare("SELECT api_key_id, entry_json FROM billing_ledger")
      .all<{ api_key_id: string | null; entry_json: string }>();
    const events = await BILLING_DB
      .prepare("SELECT event_json FROM billing_events")
      .all<{ event_json: string }>();
    expect(ledger.results).toHaveLength(1);
    expect(events.results).toHaveLength(1);
    expect(ledger.results?.[0]?.api_key_id).toBe(API_KEY_ID);
    expect(JSON.parse(ledger.results?.[0]?.entry_json ?? "{}").tenant.api_key_id).toBe(API_KEY_ID);
    expect(JSON.parse(events.results?.[0]?.event_json ?? "{}").tenant.api_key_id).toBe(API_KEY_ID);
  });
});
