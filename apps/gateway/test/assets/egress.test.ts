/**
 * D4 — asset egress budgets enforce nothing and are never billed.
 *
 * Rust `server/asset_egress.rs` runs TWO things per download, and this tree ran
 * NEITHER before this suite:
 *
 *  - `asset_egress_quota_denial` (`asset_egress.rs:55`) — fail-closed, before a
 *    byte is served. The monthly egress BYTE budget first and READ-ONLY (so an
 *    exhausted budget never burns a download-RPM token), then the download RPM
 *    cap. `server/assets.rs:1114-1124` writes all three refusals with
 *    `StatusCode::TOO_MANY_REQUESTS`.
 *  - `record_asset_egress` (`asset_egress.rs:113`) — meters the bytes through
 *    the billing outbox (priced by `asset_egress_price_per_gb`), accumulates the
 *    monthly counter that backs the gate above, and writes the PULL-side audit
 *    event.
 *
 * The counter keys are the security-critical part and are derived HERE exactly
 * as Rust derives them: `egress:{scope.counter_key(api_key_id)}` and
 * `asset_egress_rpm:{scope.counter_key(api_key_id)}`, where the inner half comes
 * from `@ferrogate/policy`'s `QuotaScopeSelector.counterKey` — the same
 * `"{kind}:{id}"` namespacing that stops a tenant minting a key id of
 * `"tenant:<victim>"` and colliding another tenant's aggregate window.
 *
 * ## The accounting rule, and where it comes from
 *
 * The GATE is charged the resolved object size (`selected.size_bytes`,
 * `assets.rs:1114`) — fail-closed, so the budget can never be overshot by a
 * partial read. The BILL is the bytes this response actually put on the wire.
 * Both halves are asserted below:
 *
 *  - the meter is written BEFORE the body is returned, so a client that
 *    disconnects mid-download is still billed for what was served;
 *  - a 206 range response bills the SLICE, so two ranges that together cover an
 *    object bill the object's size in total and a resumed download is not
 *    double-billed;
 *  - a 304 bills nothing at all — no bytes left the gateway.
 */
import { QuotaScopeSelector } from "@ferrogate/policy";
import { describe, expect, it } from "vitest";
import { LedgerAssetEgressMeter } from "@ferrogate/billing/asset-egress";
import { D1LedgerStore } from "@ferrogate/billing/metering";
import {
  ASSET_EGRESS_LOGICAL_MODEL_PREFIX,
  ASSET_EGRESS_PROVIDER,
  ASSET_EGRESS_REFUSALS,
  InMemoryAssetEgressCounters,
  InMemoryAssetEgressMeter,
  assetEgressByteCounterKey,
  assetEgressBytePrice,
  assetEgressQuotaDenial,
  assetEgressRpmCounterKey,
} from "../../src/assets/egress.js";
import { storedAssetId, storedAssetVariantId } from "../../src/assets/keys.js";
import { billingDb, resetMeteringTables } from "../metering/d1-harness.js";
import type { AssetEgressCounters } from "../../src/assets/egress.js";
import { CTX, bytes, callerFor, harness } from "./helpers.js";

const TENANT = "tenant-a";
const KEY = "key_dev";

function quotaWith(overrides: Record<string, unknown> = {}) {
  return overrides;
}

/** A caller carrying the egress half of the resolved quota. */
function egressCaller(overrides: Record<string, unknown> = {}) {
  return callerFor(TENANT, {
    apiKeyId: KEY,
    effectiveQuota: quotaWith(overrides),
  } as never);
}

/** Publish a `size`-byte visible asset and return the harness. */
async function published(size: number, options: Parameters<typeof harness>[0] = {}) {
  const h = harness(options);
  const content = bytes("x".repeat(size));
  const put = await h.service.putAsset(
    callerFor(TENANT),
    { assetType: "cli_tool", name: "installer", version: "1.0.0" },
    { contentType: "application/octet-stream", content },
    CTX,
  );
  expect(put.ok).toBe(true);
  return h;
}

// ---------------------------------------------------------------------------
// Counter-key derivation
// ---------------------------------------------------------------------------

describe("D4 — counter keys are derived exactly as Rust derives them", () => {
  it("prefixes the policy scope key with `egress:` for the byte budget", () => {
    expect(
      assetEgressByteCounterKey(
        { monthlyEgressBytesScope: new QuotaScopeSelector("tenant", "org") },
        KEY,
        TENANT,
      ),
    ).toBe("egress:tenant:org");
    expect(
      assetEgressByteCounterKey(
        { monthlyEgressBytesScope: new QuotaScopeSelector("key", "ignored") },
        KEY,
        TENANT,
      ),
    ).toBe("egress:key:key_dev");
  });

  it("falls back to the tenant scope when the budget names no winning scope", () => {
    expect(assetEgressByteCounterKey({}, KEY, TENANT)).toBe("egress:tenant:tenant-a");
    expect(assetEgressByteCounterKey({}, KEY, "")).toBe("egress:tenant:");
  });

  it("prefixes the RPM window with `asset_egress_rpm:` and falls back to the key scope", () => {
    expect(
      assetEgressRpmCounterKey(
        { downloadRpmLimitScope: new QuotaScopeSelector("project", "proj") },
        KEY,
      ),
    ).toBe("asset_egress_rpm:project:proj");
    expect(assetEgressRpmCounterKey({}, KEY)).toBe("asset_egress_rpm:key:key_dev");
  });

  it("keeps a colon-bearing api key id inside the id half (no cross-tenant collision)", () => {
    // The `@ferrogate/policy` namespacing invariant, restated at this call site
    // because this is a NEW counter namespace: a tenant that mints the key id
    // `tenant:victim` must not address `egress:tenant:victim`.
    const hostile = "tenant:victim";
    expect(assetEgressByteCounterKey({}, hostile, TENANT)).toBe("egress:tenant:tenant-a");
    expect(assetEgressRpmCounterKey({}, hostile)).toBe("asset_egress_rpm:key:tenant:victim");
    expect(assetEgressRpmCounterKey({}, hostile) === `asset_egress_rpm:${"tenant:victim"}`).toBe(
      false,
    );
  });
});

// ---------------------------------------------------------------------------
// The deny gate
// ---------------------------------------------------------------------------

describe("D4 — the fail-closed pre-serve deny gate", () => {
  it("admits a download that fits under the monthly byte budget", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const denial = await assetEgressQuotaDenial({
      quota: { monthlyEgressBytesBudget: 1_000 },
      apiKeyId: KEY,
      tenantId: TENANT,
      bytes: 500,
      counters,
    });
    expect(denial).toBeNull();
  });

  it("denies with 429 asset_egress_quota_exceeded and the Rust message", async () => {
    const counters = new InMemoryAssetEgressCounters();
    counters.addBytes("egress:tenant:tenant-a", 800);
    const denial = await assetEgressQuotaDenial({
      quota: { monthlyEgressBytesBudget: 1_000 },
      apiKeyId: KEY,
      tenantId: TENANT,
      bytes: 500,
      counters,
    });
    expect(denial).not.toBeNull();
    expect(denial?.status).toBe(429);
    expect(denial?.code).toBe("asset_egress_quota_exceeded");
    expect(denial?.message).toBe(
      "monthly asset egress budget of 1000 bytes is exhausted for this scope (800 used, 500 requested)",
    );
  });

  it("checks the byte budget READ-ONLY, so an exhausted budget never burns an RPM token", async () => {
    // Rust runs the budget check first and read-only for exactly this reason
    // (`asset_egress.rs:47-52`). Reversing the two, or making the budget check
    // consume, reds this.
    const counters = new InMemoryAssetEgressCounters();
    counters.addBytes("egress:tenant:tenant-a", 1_000);
    const quota = { monthlyEgressBytesBudget: 1_000, downloadRpmLimit: 1 };

    const first = await assetEgressQuotaDenial({
      quota,
      apiKeyId: KEY,
      tenantId: TENANT,
      bytes: 1,
      counters,
    });
    expect(first?.code).toBe("asset_egress_quota_exceeded");
    expect(counters.downloadsConsumed("asset_egress_rpm:key:key_dev")).toBe(0);
  });

  it("denies with 429 asset_download_rate_limit_exceeded once the RPM cap is spent", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const quota = { downloadRpmLimit: 1 };
    expect(
      await assetEgressQuotaDenial({
        quota,
        apiKeyId: KEY,
        tenantId: TENANT,
        bytes: 10,
        counters,
      }),
    ).toBeNull();
    const denial = await assetEgressQuotaDenial({
      quota,
      apiKeyId: KEY,
      tenantId: TENANT,
      bytes: 10,
      counters,
    });
    expect(denial?.status).toBe(429);
    expect(denial?.code).toBe("asset_download_rate_limit_exceeded");
    expect(denial?.message).toBe("asset download rate limit of 1/min is exhausted for this scope");
  });

  it("refuses when the counter backend is unavailable — never admits", async () => {
    const broken: AssetEgressCounters = {
      bytesUsed: () => 0,
      addBytes: () => undefined,
      tryConsumeDownload: () => "unavailable",
    };
    const denial = await assetEgressQuotaDenial({
      quota: { downloadRpmLimit: 10 },
      apiKeyId: KEY,
      tenantId: TENANT,
      bytes: 10,
      counters: broken,
    });
    expect(denial?.code).toBe("governance_counter_unavailable");
    expect(denial?.message).toBe(ASSET_EGRESS_REFUSALS.governance_counter_unavailable.message());
  });

  it("does nothing at all when neither limit is configured", async () => {
    const counters = new InMemoryAssetEgressCounters();
    for (let i = 0; i < 50; i += 1) {
      expect(
        await assetEgressQuotaDenial({
          quota: {},
          apiKeyId: KEY,
          tenantId: TENANT,
          bytes: 1_000_000,
          counters,
        }),
      ).toBeNull();
    }
  });
});

// ---------------------------------------------------------------------------
// Pricing
// ---------------------------------------------------------------------------

describe("D4 — pricing", () => {
  it("prices 2 GB at $0.09/GB as exactly $0.18, matching the Rust acceptance test", () => {
    const cost = assetEgressBytePrice(2_000_000_000, 0.09);
    expect(cost).toBeDefined();
    expect(Math.abs((cost ?? 0) - 0.18)).toBeLessThan(1e-9);
  });

  it("leaves an unpriced deployment metered but uncharged (no fabricated cost)", () => {
    expect(assetEgressBytePrice(1_000_000, undefined)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The pull path
// ---------------------------------------------------------------------------

describe("D4 — getAsset enforces the budget and bills the bytes", () => {
  it("REFUSES an over-budget pull with 429 and serves no bytes", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = await published(100, { egress: { counters, meter } });
    counters.addBytes("egress:tenant:tenant-a", 95);

    const result = await h.service.pullAsset(
      egressCaller({ monthlyEgressBytesBudget: 100 }),
      { assetType: "cli_tool", name: "installer", reference: "1.0.0" },
      { headers: new Headers() },
      CTX,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(429);
    expect(result.code).toBe("asset_egress_quota_exceeded");
    // Nothing was served, so nothing was billed and the counter did not move.
    expect(meter.charges).toHaveLength(0);
    expect(counters.bytesUsed("egress:tenant:tenant-a")).toBe(95);
  });

  it("REFUSES an over-RPM pull with 429 asset_download_rate_limit_exceeded", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = await published(10, { egress: { counters, meter } });
    const caller = egressCaller({ downloadRpmLimit: 1 });
    const ref = { assetType: "cli_tool", name: "installer", reference: "1.0.0" };

    const first = await h.service.pullAsset(caller, ref, { headers: new Headers() }, CTX);
    expect(first.ok).toBe(true);
    const second = await h.service.pullAsset(caller, ref, { headers: new Headers() }, CTX);
    expect(second.ok).toBe(false);
    if (second.ok) return;
    expect(second.status).toBe(429);
    expect(second.code).toBe("asset_download_rate_limit_exceeded");
    expect(meter.charges).toHaveLength(1);
  });

  it("bills the served bytes and accumulates the monthly counter on a permitted pull", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = await published(4_096, { egress: { counters, meter, pricePerGb: 0.09 } });

    const result = await h.service.pullAsset(
      egressCaller({ monthlyEgressBytesBudget: 10_000_000 }),
      { assetType: "cli_tool", name: "installer", reference: "1.0.0" },
      { headers: new Headers() },
      { requestId: "req_pull", agentRunId: "run-egress-1" },
    );
    expect(result.ok).toBe(true);

    expect(meter.charges).toHaveLength(1);
    const charge = meter.charges[0];
    expect(charge?.bytes).toBe(4_096);
    expect(charge?.tenantId).toBe(TENANT);
    expect(charge?.assetType).toBe("cli_tool");
    expect(charge?.name).toBe("installer");
    expect(charge?.version).toBe("1.0.0");
    expect(charge?.provider).toBe(ASSET_EGRESS_PROVIDER);
    expect(charge?.logicalModel).toBe(`${ASSET_EGRESS_LOGICAL_MODEL_PREFIX}cli_tool/installer`);
    expect(charge?.agentRunId).toBe("run-egress-1");
    expect(charge?.requestId).toBe("req_pull");
    expect(charge?.apiKeyId).toBe(KEY);
    // 4096 bytes @ $0.09/GB.
    expect(charge?.costUsd).toBeCloseTo((4_096 / 1_000_000_000) * 0.09, 15);

    expect(counters.bytesUsed("egress:tenant:tenant-a")).toBe(4_096);
  });

  it("writes the PULL-side audit event, joined to the agent run", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = await published(512, { egress: { counters, meter } });

    await h.service.pullAsset(
      egressCaller({}),
      { assetType: "cli_tool", name: "installer", reference: "1.0.0" },
      { headers: new Headers() },
      { requestId: "req_pull", agentRunId: "run-egress-2" },
    );

    const pull = h.audit.events.find((event) => event.action === "asset.pull");
    expect(pull).toBeDefined();
    expect(pull?.outcome).toBe("served");
    expect(pull?.target).toBe("tenant-a:cli_tool:installer:1.0.0");
    expect(pull?.message).toContain("512 bytes");
    expect(pull?.agentRunId).toBe("run-egress-2");
  });

  it("audits the resolved variant row's stored_assets.id", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = harness({ egress: { counters, meter } });
    const content = bytes("variant payload");
    const put = await h.service.putAsset(
      callerFor(TENANT),
      {
        assetType: "cli_tool",
        name: "installer",
        version: "1.0.0",
        variant: "linux-x86_64",
      },
      { contentType: "application/octet-stream", content },
      CTX,
    );
    expect(put.ok).toBe(true);

    const result = await h.service.pullAsset(
      egressCaller(),
      { assetType: "cli_tool", name: "installer", reference: "1.0.0" },
      { headers: new Headers(), platform: "linux-x86_64" },
      { requestId: "req_variant" },
    );
    expect(result.ok).toBe(true);

    const pull = h.audit.events.find((event) => event.action === "asset.pull");
    expect(pull?.target).toBe(
      storedAssetVariantId(TENANT, "cli_tool", "installer", "1.0.0", "linux-x86_64"),
    );
  });

  it("fails closed before serving when the stored asset ID is empty", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = await published(64, { egress: { counters, meter } });
    const id = storedAssetId(TENANT, "cli_tool", "installer", "1.0.0");
    const stored = h.metadata.assets.get(id);
    expect(stored).toBeDefined();
    if (stored === undefined) return;
    stored.id = "";

    const result = await h.service.pullAsset(
      egressCaller(),
      { assetType: "cli_tool", name: "installer", reference: "1.0.0" },
      { headers: new Headers() },
      { requestId: "req_invalid_asset_id" },
    );
    expect(result).toMatchObject({ ok: false, status: 500, code: "asset_identity_invalid" });
    expect(meter.charges).toHaveLength(0);
    expect(counters.bytesUsed("egress:tenant:tenant-a")).toBe(0);
  });

  it("persists gateway egress with the authenticated api key in D1", async () => {
    await resetMeteringTables();
    const db = billingDb();
    const h = await published(64, {
      egress: {
        counters: new InMemoryAssetEgressCounters(),
        meter: new LedgerAssetEgressMeter(new D1LedgerStore(db)),
        pricePerGb: 0.09,
      },
    });

    const result = await h.service.pullAsset(
      egressCaller(),
      { assetType: "cli_tool", name: "installer", reference: "1.0.0" },
      { headers: new Headers() },
      { requestId: "req_gateway_d1" },
    );
    expect(result.ok).toBe(true);

    const ledger = await db
      .prepare("SELECT api_key_id, entry_json FROM billing_ledger")
      .all<{ api_key_id: string | null; entry_json: string }>();
    const events = await db
      .prepare("SELECT event_json FROM billing_events")
      .all<{ event_json: string }>();
    expect(ledger.results).toHaveLength(1);
    expect(events.results).toHaveLength(1);
    expect(ledger.results?.[0]?.api_key_id).toBe(KEY);
    expect(JSON.parse(ledger.results?.[0]?.entry_json ?? "{}").tenant.api_key_id).toBe(KEY);
    expect(JSON.parse(events.results?.[0]?.event_json ?? "{}").tenant.api_key_id).toBe(KEY);
  });

  it("bills before the body is handed back, so a client disconnect cannot lose the charge", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = await published(64, { egress: { counters, meter } });

    const result = await h.service.pullAsset(
      egressCaller({}),
      { assetType: "cli_tool", name: "installer", reference: "1.0.0" },
      { headers: new Headers() },
      CTX,
    );
    // The caller never touches `result.bytes` — exactly what a client that
    // vanished mid-download looks like from here. The charge is already on the
    // meter the instant `pullAsset` resolves.
    expect(result.ok).toBe(true);
    expect(meter.charges).toHaveLength(1);
    expect(meter.charges[0]?.bytes).toBe(64);
  });

  it("bills a HEAD at zero — headers are not egress", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = await published(1_000, { egress: { counters, meter } });

    const result = await h.service.pullAsset(
      egressCaller({}),
      { assetType: "cli_tool", name: "installer", reference: "1.0.0" },
      { headers: new Headers(), method: "HEAD" },
      CTX,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe(200);
    expect(result.bytes).toBeNull();
    expect(meter.charges).toHaveLength(0);
    expect(counters.bytesUsed("egress:tenant:tenant-a")).toBe(0);
  });
});

describe("D4 — range and conditional requests are not double-billed", () => {
  it("bills a 206 for the SLICE, so a resumed download totals the object size once", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = await published(1_000, { egress: { counters, meter } });
    const caller = egressCaller({});
    const ref = { assetType: "cli_tool", name: "installer", reference: "1.0.0" };

    const first = await h.service.pullAsset(
      caller,
      ref,
      { headers: new Headers({ range: "bytes=0-399" }) },
      CTX,
    );
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(first.status).toBe(206);

    const resumed = await h.service.pullAsset(
      caller,
      ref,
      { headers: new Headers({ range: "bytes=400-999" }) },
      CTX,
    );
    expect(resumed.ok).toBe(true);
    if (!resumed.ok) return;
    expect(resumed.status).toBe(206);

    expect(meter.charges.map((charge) => charge.bytes)).toEqual([400, 600]);
    // The two halves of ONE download bill the object exactly once, not twice.
    expect(counters.bytesUsed("egress:tenant:tenant-a")).toBe(1_000);
  });

  it("bills a 304 at zero — no bytes left the gateway", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = await published(1_000, { egress: { counters, meter } });
    const caller = egressCaller({});
    const ref = { assetType: "cli_tool", name: "installer", reference: "1.0.0" };

    const full = await h.service.pullAsset(caller, ref, { headers: new Headers() }, CTX);
    expect(full.ok).toBe(true);
    if (!full.ok) return;
    const etag = full.headers.etag;
    expect(etag).toBeDefined();

    const revalidated = await h.service.pullAsset(
      caller,
      ref,
      { headers: new Headers({ "if-none-match": etag ?? "" }) },
      CTX,
    );
    expect(revalidated.ok).toBe(true);
    if (!revalidated.ok) return;
    expect(revalidated.status).toBe(304);

    expect(meter.charges).toHaveLength(1);
    expect(counters.bytesUsed("egress:tenant:tenant-a")).toBe(1_000);
  });

  it("bills a 416 at zero", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = await published(10, { egress: { counters, meter } });

    const result = await h.service.pullAsset(
      egressCaller({}),
      { assetType: "cli_tool", name: "installer", reference: "1.0.0" },
      { headers: new Headers({ range: "bytes=500-600" }) },
      CTX,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe(416);
    expect(meter.charges).toHaveLength(0);
  });

  it("still gates a range request on the FULL object size (fail-closed, as Rust does)", async () => {
    // `assets.rs:1114` passes `selected.size_bytes` to the gate, never the
    // slice: a caller must not be able to drain a budget one range at a time.
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = await published(1_000, { egress: { counters, meter } });

    const result = await h.service.pullAsset(
      egressCaller({ monthlyEgressBytesBudget: 500 }),
      { assetType: "cli_tool", name: "installer", reference: "1.0.0" },
      { headers: new Headers({ range: "bytes=0-9" }) },
      CTX,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("asset_egress_quota_exceeded");
  });
});

describe("D4 — the presigned download bills at issuance", () => {
  it("meters the whole object when the URL is issued (bytes leave the bucket directly)", async () => {
    // Rust `asset_presign.rs:1629`: the presigned direct path bills at URL
    // issuance using the object size, since those bytes never traverse the
    // gateway and can never be observed later.
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = await published(2_048, { egress: { counters, meter } });

    const result = await h.service.downloadUrl(
      egressCaller({}),
      { assetType: "cli_tool", name: "installer", version: "1.0.0" },
      CTX,
    );
    expect(result.ok).toBe(true);
    expect(meter.charges).toHaveLength(1);
    expect(meter.charges[0]?.bytes).toBe(2_048);
    expect(counters.bytesUsed("egress:tenant:tenant-a")).toBe(2_048);
  });

  it("REFUSES to issue a presigned URL that would exceed the budget", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = await published(2_048, { egress: { counters, meter } });

    const result = await h.service.downloadUrl(
      egressCaller({ monthlyEgressBytesBudget: 1_024 }),
      { assetType: "cli_tool", name: "installer", version: "1.0.0" },
      CTX,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.status).toBe(429);
    expect(result.code).toBe("asset_egress_quota_exceeded");
    expect(meter.charges).toHaveLength(0);
  });

  it("fails closed before issuing a presigned URL with an empty stored asset ID", async () => {
    const counters = new InMemoryAssetEgressCounters();
    const meter = new InMemoryAssetEgressMeter();
    const h = await published(2_048, { egress: { counters, meter } });
    const id = storedAssetId(TENANT, "cli_tool", "installer", "1.0.0");
    const stored = h.metadata.assets.get(id);
    expect(stored).toBeDefined();
    if (stored === undefined) return;
    stored.id = "";

    const result = await h.service.downloadUrl(
      egressCaller(),
      { assetType: "cli_tool", name: "installer", version: "1.0.0" },
      CTX,
    );
    expect(result).toMatchObject({ ok: false, status: 500, code: "asset_identity_invalid" });
    expect(h.presigner.gets).toHaveLength(0);
    expect(meter.charges).toHaveLength(0);
  });
});
