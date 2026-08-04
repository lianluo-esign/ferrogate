/**
 * The #366 asset-visibility property, pinned against the app the Worker exports.
 *
 * `InMemoryAssets` in `src/ports.ts` carries a KEPT marker: the asset BYTES
 * live in R2 and this Worker declares no `[[r2_buckets]]` binding, so the store
 * is isolate-local until the composition step adds one (the marker names the
 * exact stanza). That is a durability limit.
 *
 * It is NOT a licence to get the SECURITY property wrong, and this file pins
 * the half that must hold whatever backs the port: a PENDING-scan or
 * QUARANTINED asset must be indistinguishable from one that does not exist —
 * on the listing AND on the read. A distinct signal ("this exists but you may
 * not have it") is an oracle: it tells a caller which asset names are real, and
 * for a quarantined asset it tells them a malware verdict landed.
 *
 * Driven over `SELF.fetch` so it is the deployed `resources/*` surface being
 * asserted, not a bespoke reader.
 */
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import type { InMemoryAssets } from "../src/ports.js";
import { type Fixture, READ_KEY, TENANT, rpcRequest, seedFixture } from "./fixtures.js";

const CONTENT = new TextEncoder().encode("echo hello");

let fixture: Fixture;

beforeEach(() => {
  fixture = seedFixture();
});

function asset(overrides: Record<string, unknown> = {}) {
  return {
    id: "stored-assets-mcp-visibility",
    assetType: "cli_tool",
    name: "deploy",
    version: "1.0.0",
    contentType: "text/plain",
    sizeBytes: CONTENT.byteLength,
    sha256: "a".repeat(64),
    downloadable: true,
    ...overrides,
  } as Parameters<InMemoryAssets["seed"]>[1];
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

describe("#366 — an undownloadable asset is indistinguishable from a missing one", () => {
  it("is withheld from resources/list exactly as an absent asset is", async () => {
    fixture.ports.assets.seed(TENANT, asset({ downloadable: false }), CONTENT);
    const listed = await rpc("resources/list", {});
    expect(listed.error).toBeUndefined();
    expect(listed.result?.resources ?? []).toHaveLength(0);
  });

  it("answers resources/read with the SAME error a never-created asset gets", async () => {
    // Arm 1 — the asset simply does not exist.
    const missing = await rpc("resources/read", { uri: "asset://cli_tool/ghost/9.9.9" });

    // Arm 2 — the asset EXISTS but is pending scan / quarantined.
    fixture.ports.assets.seed(TENANT, asset({ downloadable: false }), CONTENT);
    const withheld = await rpc("resources/read", { uri: "asset://cli_tool/deploy/1.0.0" });

    // Byte-identical refusals apart from the name the caller themselves supplied
    // — no code, no status and no wording distinguishes the two states.
    expect(withheld.error?.code).toBe(missing.error?.code);
    expect(withheld.error).toBeDefined();
    expect(withheld.result).toBeUndefined();
    expect(withheld.error?.message).not.toContain("quarantin");
    expect(withheld.error?.message).not.toContain("pending");
  });

  it("serves the asset once it IS downloadable — the control for the two above", async () => {
    // Without this, "everything is refused" would pass the two tests above.
    fixture.ports.assets.seed(TENANT, asset(), CONTENT);
    const listed = await rpc("resources/list", {});
    expect(listed.result?.resources ?? []).toHaveLength(1);
    const read = await rpc("resources/read", { uri: "asset://cli_tool/deploy/1.0.0" });
    expect(read.error).toBeUndefined();
    expect(read.result?.contents).toBeDefined();
  });

  it("never serves one tenant's asset to another tenant", async () => {
    // The seeded key belongs to TENANT; the asset belongs to somebody else.
    fixture.ports.assets.seed("some-other-tenant", asset(), CONTENT);
    const listed = await rpc("resources/list", {});
    expect(listed.result?.resources ?? []).toHaveLength(0);
    const read = await rpc("resources/read", { uri: "asset://cli_tool/deploy/1.0.0" });
    expect(read.error).toBeDefined();
    expect(read.result).toBeUndefined();
  });
});
