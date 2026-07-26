// Unit coverage for the overview consumer layer (issue #343).
//
// These tests pin the two rules the cockpit's honesty depends on:
//   * a section payload is PARSED, not cast — a field whose type drifted (or
//     vanished) becomes `undefined`, so the UI can render N/A instead of
//     handing a non-number to `Intl.NumberFormat` (which prints "NaN");
//   * "healthy workers" is derived from the status labels the gateway really
//     writes, and is UNKNOWN — never zero — when the histogram cannot be
//     classified.
import { describe, expect, it } from "vitest";
import {
  classifyWorkerStatus,
  healthyWorkerCount,
  parseAlerts,
  parseControlPlane,
  parseRuntime,
  parseUsage,
  sectionView,
  type AdminOverviewSection,
} from "@/lib/overview";
import {
  overviewAlertsData,
  overviewControlPlaneData,
  overviewRuntimeData,
  overviewSectionOk,
  overviewSectionUnavailable,
  overviewUsageData,
} from "@/test/fixtures/ops";

describe("parseControlPlane", () => {
  it("reads the contract shape the gateway sends today", () => {
    const parsed = parseControlPlane(
      overviewControlPlaneData() as unknown as Record<string, unknown>,
    );
    expect(parsed.virtual_keys).toEqual({ total: 15, enabled: 11 });
    expect(parsed.assets?.referenced).toBe(96);
    expect(parsed.assets?.storage_quota_bytes).toBeNull();
    expect(parsed.pending_tool_approvals).toBe(4);
    expect(parsed.quota_pressure).toHaveLength(1);
    expect(parsed.policy_governance?.quota_policies).toBe(3);
    expect(parsed.self_hosted_workers?.by_status).toEqual({
      online: 8,
      registered: 1,
      stale: 2,
      draining: 1,
    });
  });

  it("drops a field whose type drifted instead of passing it to a formatter", () => {
    // The pre-#458 wire shape: `virtual_keys` was a bare number.
    const parsed = parseControlPlane({ ...overviewControlPlaneData(), virtual_keys: 15 });
    expect(parsed.virtual_keys).toBeUndefined();
    // Every sibling field survives: one drifted field degrades one cell.
    expect(parsed.tenants).toBe(24);
    expect(parsed.assets?.count).toBe(128);
  });

  it("never yields a NaN-producing value for a non-numeric count", () => {
    const parsed = parseControlPlane({
      tenants: "24",
      projects: null,
      workspaces: Number.NaN,
      assets: { count: 1, storage_bytes: "big", referenced: 0, unreferenced: 1 },
      agent_runs: { total: 3, by_status: { failed: "many" } },
    });
    expect(parsed.tenants).toBeUndefined();
    expect(parsed.projects).toBeUndefined();
    expect(parsed.workspaces).toBeUndefined();
    expect(parsed.assets).toBeUndefined();
    expect(parsed.agent_runs).toBeUndefined();
  });

  it("keeps `null` policy governance distinct from a missing field", () => {
    expect(parseControlPlane({ policy_governance: null }).policy_governance).toBeNull();
    expect(parseControlPlane({}).policy_governance).toBeUndefined();
  });
});

describe("parseRuntime / parseUsage / parseAlerts", () => {
  it("reads the runtime and usage payloads the gateway sends", () => {
    const runtime = parseRuntime(overviewRuntimeData() as unknown as Record<string, unknown>);
    expect(runtime.providers).toEqual({ total: 4, enabled: 3 });
    expect(runtime.mcp_servers?.connected).toBe(4);

    const usage = parseUsage(overviewUsageData() as unknown as Record<string, unknown>);
    expect(usage.lifetime?.total_tokens).toBe(12_000_000);
    expect(usage.current_period_month).toBe("2026-07");
  });

  it("counts unreadable alert entries instead of silently dropping them", () => {
    const parsed = parseAlerts({
      total: 2,
      truncated: false,
      unavailable_sources: ["control_plane_store"],
      entries: [overviewAlertsData().entries[0], { severity: "critical" }],
    });
    expect(parsed.entries).toHaveLength(1);
    expect(parsed.malformed_entries).toBe(1);
    expect(parsed.unavailable_sources).toEqual(["control_plane_store"]);
  });
});

describe("sectionView", () => {
  it("parses an ok section and reports an unavailable one", () => {
    const ok = sectionView(
      overviewSectionOk(overviewControlPlaneData()) as AdminOverviewSection,
      parseControlPlane,
    );
    expect(ok.status).toBe("ok");
    expect(ok.status === "ok" && ok.data.tenants).toBe(24);

    const failed = sectionView(overviewSectionUnavailable("store down"), parseControlPlane);
    expect(failed).toEqual({
      status: "unavailable",
      source: "control_plane_store",
      error: "store down",
    });
  });

  it("treats an ok section with no payload object as unavailable", () => {
    const view = sectionView(
      { status: "ok", source: "control_plane_store" },
      parseControlPlane,
    );
    expect(view.status).toBe("unavailable");
  });
});

describe("worker health", () => {
  it("classifies the labels the gateway actually writes", () => {
    // Registration writes `registered`; a heartbeat overwrites it with the
    // worker-reported label (`online`).
    expect(classifyWorkerStatus("registered")).toBe("healthy");
    expect(classifyWorkerStatus("online")).toBe("healthy");
    // Mirrors the gateway's own `is_worker_pressure_status` needles.
    expect(classifyWorkerStatus("stale")).toBe("pressure");
    expect(classifyWorkerStatus("draining")).toBe("pressure");
    expect(classifyWorkerStatus("heartbeat_timeout")).toBe("pressure");
    // Anything else is unknown — not silently healthy. `active` in particular:
    // no gateway code path writes it, so it can never stand in for "healthy".
    expect(classifyWorkerStatus("warming_up")).toBe("unknown");
    expect(classifyWorkerStatus("active")).toBe("unknown");
  });

  it("sums the healthy buckets of a fully classifiable histogram", () => {
    expect(healthyWorkerCount({ online: 8, registered: 1, stale: 2, draining: 1 })).toBe(9);
    // All twelve are known-unhealthy: zero healthy is a fact here, not a guess.
    expect(healthyWorkerCount({ stale: 12 })).toBe(0);
    // No workers at all is a real zero.
    expect(healthyWorkerCount({})).toBe(0);
  });

  it("returns unknown when a bucket cannot be classified", () => {
    expect(healthyWorkerCount({ online: 8, warming_up: 4 })).toBeUndefined();
    expect(healthyWorkerCount(undefined)).toBeUndefined();
    // An empty bucket classifies nothing, so it cannot make the count unknown.
    expect(healthyWorkerCount({ online: 8, warming_up: 0 })).toBe(8);
  });
});
