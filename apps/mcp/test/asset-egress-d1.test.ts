import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { controlNamespace } from "./support/control-namespace.js";

import {
  type AuthContext,
  type DispatchContext,
  type McpEnv,
  inMemoryPorts,
  resetInMemoryPorts,
  resolvePorts,
} from "../src/ports.js";
import { readAssetForMcp } from "../src/tools.js";
import { TENANT } from "./fixtures.js";
import { tenantDataNamespace, tenantDatabase } from "./tenant-storage.js";

const API_KEY_ID = "key-mcp-asset-egress";
const CONTENT = new TextEncoder().encode("durable mcp asset");
const ASSET_ID = "stored-assets-real-variant-id";

interface Bindings {
  readonly ASSETS?: R2Bucket;
  readonly BILLING_DB?: D1Database;
  readonly DB?: D1Database;
}

function requireBindings(): {
  ASSETS: R2Bucket;
  BILLING_DB: D1Database;
  DB: D1Database;
  TENANT_DATA: ReturnType<typeof tenantDataNamespace>;
} {
  const bindings = env as unknown as Bindings;
  if (
    bindings.ASSETS === undefined ||
    bindings.BILLING_DB === undefined ||
    bindings.DB === undefined
  ) {
    throw new Error("MCP asset egress test requires ASSETS, BILLING_DB, and DB bindings");
  }
  return {
    ASSETS: bindings.ASSETS,
    BILLING_DB: bindings.BILLING_DB,
    DB: bindings.DB,
    TENANT_DATA: tenantDataNamespace(env),
  };
}

async function seedAsset(db: D1Database, bucket: R2Bucket): Promise<void> {
  const digest = await crypto.subtle.digest("SHA-256", CONTENT);
  const hash = [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
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
  const { BILLING_DB, ASSETS, TENANT_DATA } = requireBindings();
  await BILLING_DB.batch([
    BILLING_DB.prepare("DELETE FROM billing_report_outbox"),
    BILLING_DB.prepare("DELETE FROM billing_ledger"),
    BILLING_DB.prepare("DELETE FROM billing_events"),
  ]);
  const tenant = tenantDatabase(TENANT_DATA, TENANT);
  const rows = await tenant
    .prepare("SELECT storage_uri FROM stored_assets")
    .all<{ storage_uri: string }>();
  for (const row of rows.results ?? []) await ASSETS.delete(row.storage_uri);
  await tenant.prepare("DELETE FROM stored_assets").run();

  await tenant.batch([
    tenant.prepare("DELETE FROM billing_report_outbox"),
    tenant.prepare("DELETE FROM billing_ledger"),
    tenant.prepare("DELETE FROM billing_events"),
    tenant.prepare("DELETE FROM wallet_settlements"),
    tenant.prepare("DELETE FROM wallets"),
  ]);
});

describe("#801 MCP non-dev D1 asset egress", () => {
  it("reads through D1/R2 and persists billing rows with api-key attribution", async () => {
    const { ASSETS, BILLING_DB, DB, TENANT_DATA } = requireBindings();
    const tenant = tenantDatabase(TENANT_DATA, TENANT);
    await seedAsset(tenant, ASSETS);

    const ports = resolvePorts({
      ASSETS,
      BILLING_DB,
      DB,
      TENANT_DATA,
      CONTROL_DATA: controlNamespace() as DurableObjectNamespace,
    } satisfies McpEnv);
    const result = await readAssetForMcp(ports, context(), "cli_tool", "deploy", "1.0.0");
    expect(result.ok).toBe(true);
    expect(ports.assetEgress.meter.constructor.name).toBe("LedgerAssetEgressMeter");

    const ledger = await tenant
      .prepare("SELECT api_key_id, entry_json FROM billing_ledger")
      .all<{ api_key_id: string | null; entry_json: string }>();
    const events = await tenant
      .prepare("SELECT event_json FROM billing_events")
      .all<{ event_json: string }>();
    expect(ledger.results).toHaveLength(1);
    expect(events.results).toHaveLength(1);
    expect(ledger.results?.[0]?.api_key_id).toBe(API_KEY_ID);
    expect(JSON.parse(ledger.results?.[0]?.entry_json ?? "{}").tenant.api_key_id).toBe(API_KEY_ID);
    expect(JSON.parse(events.results?.[0]?.event_json ?? "{}").tenant.api_key_id).toBe(API_KEY_ID);
    const pull = ports.audit.events().find((event) => event.action === "asset.pull");
    expect(pull?.target).toBe(ASSET_ID);
    const controlRows = await BILLING_DB.prepare("SELECT id FROM billing_ledger").all();
    expect(controlRows.results).toEqual([]);
  });

  it("routes asset billing to the tenant Durable Object when it is bound", async () => {
    const { ASSETS, BILLING_DB, DB, TENANT_DATA } = requireBindings();
    await seedAsset(tenantDatabase(TENANT_DATA, TENANT), ASSETS);

    const ports = resolvePorts({
      ASSETS,
      BILLING_DB,
      DB,
      TENANT_DATA,
      CONTROL_DATA: controlNamespace() as DurableObjectNamespace,
    } satisfies McpEnv);
    const result = await readAssetForMcp(ports, context(), "cli_tool", "deploy", "1.0.0");
    expect(result.ok).toBe(true);

    const tenantRows = await tenantDatabase(TENANT_DATA, TENANT)
      .prepare("SELECT tenant_id, api_key_id FROM billing_ledger")
      .all<{ tenant_id: string; api_key_id: string | null }>();
    expect(tenantRows.results).toEqual([{ tenant_id: TENANT, api_key_id: API_KEY_ID }]);
    const controlRows = await BILLING_DB.prepare("SELECT id FROM billing_ledger").all();
    expect(controlRows.results).toEqual([]);
  });
});
