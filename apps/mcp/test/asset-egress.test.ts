/** Focused #801 regression coverage for the shared billing asset read path. */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  InMemoryAssetEgressCounters,
  InMemoryAssetEgressMeter,
  assetEgressTargetId,
} from "@ferrogate/billing";
import type { StoredAsset } from "../src/ports.js";
import {
  EXEC_KEY,
  READ_KEY,
  TENANT,
  type Fixture,
  rpcRequest,
  seedFixture,
} from "./fixtures.js";

const CONTENT = new TextEncoder().encode("echo hello");
const ASSET_ID = `${TENANT}:cli_tool:deploy:1.0.0`;

interface RpcBody {
  error?: { code: number; message: string };
  result?: { contents?: unknown[]; content?: unknown[] };
}

let fixture: Fixture;

function asset(): StoredAsset {
  return {
    id: ASSET_ID,
    assetType: "cli_tool",
    name: "deploy",
    version: "1.0.0",
    contentType: "text/plain",
    sizeBytes: CONTENT.byteLength,
    sha256: "a".repeat(64),
    downloadable: true,
  };
}

function configureEgress(quota: Record<string, unknown> = {}) {
  const counters = new InMemoryAssetEgressCounters();
  const meter = new InMemoryAssetEgressMeter();
  fixture.ports.assetEgress = { counters, meter, quota };
  return { counters, meter };
}

async function rpc(
  method: string,
  params: Record<string, unknown>,
  key: string,
): Promise<RpcBody> {
  const response = await SELF.fetch(
    rpcRequest({ jsonrpc: "2.0", id: 1, method, params }, { key }),
  );
  return (await response.json()) as RpcBody;
}

beforeEach(() => {
  fixture = seedFixture();
  fixture.ports.assets.seed(TENANT, asset(), CONTENT);
});

describe("#801 MCP asset egress uses one billing path", () => {
  it("fails closed instead of deriving an audit target when stored_assets.id is missing", () => {
    expect(() =>
      assetEgressTargetId(
        { ...asset(), id: undefined } as never,
        TENANT,
      ),
    ).toThrow("stored_assets.id");
  });

  it("meters both resources/read and builtin.fetch_asset and audits stored_assets.id", async () => {
    const { counters, meter } = configureEgress();

    const resource = await rpc(
      "resources/read",
      { uri: "asset://cli_tool/deploy/1.0.0" },
      READ_KEY,
    );
    const builtin = await rpc(
      "tools/call",
      {
        name: "builtin.fetch_asset",
        arguments: { asset_type: "cli_tool", name: "deploy", version: "1.0.0" },
      },
      EXEC_KEY,
    );

    expect(resource.error).toBeUndefined();
    expect(resource.result?.contents).toHaveLength(1);
    expect(builtin.error).toBeUndefined();
    expect(builtin.result?.content).toHaveLength(1);
    expect(meter.charges.map((charge) => charge.bytes)).toEqual([
      CONTENT.byteLength,
      CONTENT.byteLength,
    ]);
    expect(counters.bytesUsed(`egress:tenant:${TENANT}`)).toBe(CONTENT.byteLength * 2);

    const pulls = fixture.ports.audit.events().filter((event) => event.action === "asset.pull");
    expect(pulls).toHaveLength(2);
    expect(pulls.map((event) => event.target)).toEqual([ASSET_ID, ASSET_ID]);
    expect(pulls.map((event) => event.message)).toEqual([
      `asset ${ASSET_ID} downloaded (${CONTENT.byteLength} bytes)`,
      `asset ${ASSET_ID} downloaded (${CONTENT.byteLength} bytes)`,
    ]);
  });

  it.each([
    ["resources/read", READ_KEY, { uri: "asset://cli_tool/deploy/1.0.0" }],
    [
      "builtin.fetch_asset",
      EXEC_KEY,
      {
        name: "builtin.fetch_asset",
        arguments: { asset_type: "cli_tool", name: "deploy", version: "1.0.0" },
      },
    ],
  ] as const)("denies %s before storage, metering, or audit", async (method, key, params) => {
    const { counters, meter } = configureEgress({
      monthlyEgressBytesBudget: CONTENT.byteLength - 1,
    });
    const read = vi.spyOn(fixture.ports.assets, "read");

    const body = await rpc(method === "resources/read" ? method : "tools/call", params, key);

    expect(body.error?.code).toBe(-32007);
    expect(read).not.toHaveBeenCalled();
    expect(meter.charges).toHaveLength(0);
    expect(counters.bytesUsed(`egress:tenant:${TENANT}`)).toBe(0);
    expect(fixture.ports.audit.events().filter((event) => event.action === "asset.pull")).toHaveLength(
      0,
    );
  });
});
