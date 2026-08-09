import {
  contractOperation,
  contractSchema,
  fieldShapes,
  responseSchemaRef,
  sortedRequired,
} from "@/lib/contract-pin";
import { parseAlerts, parseControlPlane, parseRuntime, parseUsage } from "@/lib/overview";
// Wire-contract drift alarm for GET /admin/v1/overview (issue #343).
//
// Why this exists: the #339 contract types each section's `data` as an OPEN
// object, so `tsc` and the generated-client drift guard CANNOT see inside it.
// #458 changed `virtual_keys` from a number to a `{total,enabled}` object a day
// after the cockpit landed; nothing failed, and the console rendered "NaN" in
// production while its own fixtures stayed green.
//
// RE-ANCHORED (2026-08): this test used to read the Rust server structs
// (`crates/ferrogate-gateway/src/server/admin_overview.rs`); the Rust tree was
// deleted on 2026-08-02. The surviving authority for the overview document is
// the shared contract, `docs/openapi/admin-api.openapi.json` (`AdminOverview` +
// `AdminOverviewSection` and the `getAdminOverview` operation), and the deep
// per-section field tree survives in exactly two places: the operation's
// DESCRIPTION (the #458 fields are documented there, not in a schema — `data`
// is `additionalProperties: true`) and this console's own parser,
// `src/lib/overview.ts`.
//
// NOTE the TS backend has NOT yet ported the rich overview document:
// `apps/control-plane/src/adapters.ts`'s `overview()` returns only
// `{ object: "overview", status }` until the overview backend port (#884)
// lands. THIS test therefore holds the console↔contract half of the pin:
//
//   1. a contract edit that would break `sectionView`/the parsers (envelope
//      required-ness, section status enum, the open `data` object, the #458
//      field names in the operation description) goes red here, and
//   2. the parser's own field tree — the ~12 struct shapes the Rust test
//      pinned — is asserted field-for-field through the parse functions, so a
//      console-side rename/retype no longer matches the documented wire shape
//      and fails with the diff.
//
// The server↔contract half (the backend actually serializing this document) is
// #884's acceptance, not this file's.
import { describe, expect, it } from "vitest";

describe("admin overview envelope (docs/openapi/admin-api.openapi.json)", () => {
  it("GET /admin/v1/overview still answers 200 with AdminOverview", () => {
    const operation = contractOperation("/admin/v1/overview", "get");
    expect(operation.operationId).toBe("getAdminOverview");
    expect(responseSchemaRef(operation, "200")).toBe("#/components/schemas/AdminOverview");
  });

  it("AdminOverview still carries the envelope the console parses", () => {
    const overview = contractSchema("AdminOverview");
    expect(fieldShapes(overview)).toEqual({
      object: "enum:control_plane.overview",
      generated_at_unix: "integer:int64",
      scope: "object",
      runtime: "ref:AdminOverviewSection",
      control_plane: "ref:AdminOverviewSection",
      usage: "ref:AdminOverviewSection",
      alerts: "ref:AdminOverviewSection",
    });
    // Every envelope field is REQUIRED: the console reads all four sections
    // unconditionally and renders per-section availability, never a 404-shaped
    // partial document.
    expect(sortedRequired(overview)).toEqual([
      "alerts",
      "control_plane",
      "generated_at_unix",
      "object",
      "runtime",
      "scope",
      "usage",
    ]);
    // The scope discriminator drives the console's global/tenant framing.
    const scope = overview.properties?.scope;
    expect(fieldShapes(scope ?? {})).toEqual({
      kind: "enum:global|tenant",
      tenant_id: "string",
    });
    expect(sortedRequired(scope ?? {})).toEqual(["kind"]);
  });

  it("AdminOverviewSection still carries the availability envelope sectionView narrows", () => {
    const section = contractSchema("AdminOverviewSection");
    expect(fieldShapes(section)).toEqual({
      status: "enum:ok|unavailable",
      source: "string",
      generated_at_unix: "integer:int64",
      error: "string",
      data: "object",
    });
    // `status`+`source` required, `data`/`error` conditional — exactly the
    // shape `sectionView` (src/lib/overview.ts) narrows: `ok` without `data`
    // is contract-illegal and rendered unavailable, never a fabricated zero.
    expect(sortedRequired(section)).toEqual(["source", "status"]);
    // `data` is deliberately OPEN (`additionalProperties: true`). This is the
    // whole reason the runtime parsers below exist: the generated client sees
    // `{ [key: string]: unknown }` here and can catch nothing inside it.
    expect(section.properties?.data?.additionalProperties).toBe(true);
  });

  it("the operation description still documents every #458 control_plane field the parser reads", () => {
    // Until #884 the deep payload fields appear in the contract ONLY as the
    // operation's prose (the schema keeps `data` open). Pinning the prose is
    // deliberately weak but not vacuous: deleting a documented field from the
    // contract goes red here, pointing at parseControlPlane and the fixtures.
    const description = contractOperation("/admin/v1/overview", "get").description ?? "";
    for (const needle of [
      "virtual_keys",
      "{total,enabled}",
      "assets.referenced",
      "assets.unreferenced",
      "assets.storage_quota_bytes",
      "pending_tool_approvals",
      "quota_pressure",
      "policy_governance",
    ]) {
      expect(description, `operation description no longer documents ${needle}`).toContain(needle);
    }
  });
});

// ---------------------------------------------------------------------------
// The deep field tree (the ~12 Rust struct pins), held via the parsers.
//
// Struct-name lineage, for anyone diffing against the deleted Rust test:
//   AdminOverviewRuntime        -> OverviewRuntimeWire      (parseRuntime)
//   AdminOverviewControlPlane   -> OverviewControlPlaneWire (parseControlPlane)
//   AdminOverviewAssets         -> OverviewAssets
//   AdminOverviewQuotaPressure  -> OverviewQuotaPressure
//   AdminOverviewPolicyGovernance -> OverviewPolicyGovernance
//   AdminOverviewCountByStatus  -> OverviewCountByStatus
//   AdminOverviewEnabledCount   -> OverviewEnabledCount
//   AdminOverviewActiveCount    -> OverviewActiveCount
//   AdminOverviewMcpServers     -> OverviewMcpServers
//   AdminOverviewUsage          -> OverviewUsageWire        (parseUsage)
//   AdminOverviewTokens         -> OverviewTokens
//   AdminOverviewAlerts         -> OverviewAlertsWire       (parseAlerts)
//   AdminOverviewAlert          -> OverviewAlert
//   AdminOverviewEvidence       -> OverviewEvidence
//
// Each fixture below is a fully-populated canonical wire document. The
// round-trip (`parse(fixture) == fixture`) proves the parser reads EVERY field
// under its wire name and type — a renamed or retyped field parses to
// `undefined` and fails with the diff — and the key-set pin proves the parser
// emits exactly the documented field list, nothing dropped, nothing invented.
// ---------------------------------------------------------------------------

const RUNTIME_WIRE = {
  providers: { total: 4, enabled: 3 },
  models: { total: 9, enabled: 7 },
  static_api_keys: 2,
  prompt_templates: 5,
  upstreams: { total: 3, enabled: 2 },
  routes: { total: 6, enabled: 6 },
  plugins: { total: 2, active: 1 },
  tools: 8,
  mcp_servers: { total: 3, connected: 2, disconnected: 1 },
};

const CONTROL_PLANE_WIRE = {
  tenants: 3,
  projects: 4,
  workspaces: 5,
  virtual_keys: { total: 12, enabled: 11 },
  assets: {
    count: 30,
    storage_bytes: 1024,
    referenced: 20,
    unreferenced: 10,
    storage_quota_bytes: 2048,
  },
  agent_runs: { total: 7, by_status: { running: 2, completed: 5 } },
  self_hosted_workers: { total: 2, by_status: { online: 2 } },
  pending_tool_approvals: 1,
  quota_pressure: [
    {
      scope_type: "tenant",
      scope_id: "tenant-1",
      dimension: "asset_storage",
      unit: "bytes",
      used: 80,
      cap: 100,
      utilization_pct: 80,
    },
  ],
  policy_governance: {
    guardrail_policy_revisions: 1,
    guardrail_policy_bindings: 2,
    quota_policies: 3,
    policy_rules: 4,
  },
};

const TOKENS_WIRE = {
  prompt_tokens: 10,
  completion_tokens: 5,
  total_tokens: 15,
  cost_usd: 0.5,
  request_count: 3,
  error_count: 1,
};

const USAGE_WIRE = {
  current_period_month: "2026-08",
  lifetime: TOKENS_WIRE,
  current_month: { ...TOKENS_WIRE, total_tokens: 7, request_count: 1 },
};

const ALERTS_WIRE = {
  total: 2,
  truncated: false,
  unavailable_sources: ["request_logs"],
  entries: [
    {
      kind: "quota_pressure",
      severity: "warning",
      summary: "tenant tenant-1 at 80% of asset storage",
      count: 1,
      detected_at_unix: 1754000000,
      evidence: [
        {
          id: "tenant-1",
          detail: "asset_storage",
          at_unix: 1754000000,
          reference: "tenant/tenant-1",
        },
      ],
      evidence_truncated: false,
    },
  ],
};

describe("admin overview deep field tree (console parser half)", () => {
  it("parseRuntime round-trips the documented runtime payload field-for-field", () => {
    const parsed = parseRuntime({ ...RUNTIME_WIRE });
    expect(parsed).toEqual(RUNTIME_WIRE);
    expect(Object.keys(parsed).sort()).toEqual(Object.keys(RUNTIME_WIRE).sort());
  });

  it("parseControlPlane round-trips the documented control_plane payload field-for-field", () => {
    const parsed = parseControlPlane({ ...CONTROL_PLANE_WIRE });
    expect(parsed).toEqual(CONTROL_PLANE_WIRE);
    expect(Object.keys(parsed).sort()).toEqual(Object.keys(CONTROL_PLANE_WIRE).sort());
  });

  it("parseControlPlane preserves the explicit nulls (#458 not-applicable states)", () => {
    // `storage_quota_bytes: null` and `policy_governance: null` are the
    // server's honest "not applicable", NOT missing fields; the parser must
    // keep them distinct from `undefined`.
    const parsed = parseControlPlane({
      ...CONTROL_PLANE_WIRE,
      assets: { ...CONTROL_PLANE_WIRE.assets, storage_quota_bytes: null },
      policy_governance: null,
    });
    expect(parsed.assets?.storage_quota_bytes).toBeNull();
    expect(parsed.policy_governance).toBeNull();
  });

  it("a retyped virtual_keys parses to undefined, never a NaN feed (#458 regression)", () => {
    // The exact production bug this file guards: the pre-#458 scalar shape
    // must be rejected as unreadable (rendered N/A), not formatted.
    const parsed = parseControlPlane({ ...CONTROL_PLANE_WIRE, virtual_keys: 12 });
    expect(parsed.virtual_keys).toBeUndefined();
  });

  it("parseUsage round-trips the documented usage payload field-for-field", () => {
    const parsed = parseUsage({ ...USAGE_WIRE });
    expect(parsed).toEqual(USAGE_WIRE);
    expect(Object.keys(parsed).sort()).toEqual(Object.keys(USAGE_WIRE).sort());
  });

  it("parseAlerts round-trips the documented alerts payload field-for-field", () => {
    const parsed = parseAlerts({ ...ALERTS_WIRE });
    expect(parsed).toEqual({ ...ALERTS_WIRE, malformed_entries: 0 });
    expect(Object.keys(parsed).sort()).toEqual(
      [...Object.keys(ALERTS_WIRE), "malformed_entries"].sort(),
    );
  });

  it("the parsers validate rather than cast (an empty payload is all-undefined, and a bad alert is counted)", () => {
    // Non-vacuity check on the pins above: if the parsers degenerated into
    // casts, an empty object would "round-trip" too. It must instead produce
    // no readable field at all.
    for (const parsed of [parseRuntime({}), parseControlPlane({}), parseUsage({})]) {
      expect(Object.values(parsed).every((value) => value === undefined)).toBe(true);
    }
    const alerts = parseAlerts({ entries: [{ severity: "critical" }] });
    expect(alerts.entries).toEqual([]);
    expect(alerts.malformed_entries).toBe(1);
  });
});
