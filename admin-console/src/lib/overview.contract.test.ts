// Wire-contract drift alarm for GET /admin/v1/overview (issue #343).
//
// Why this exists: the #339 contract types each section's `data` as an OPEN
// object, so `tsc` and the generated-client drift guard CANNOT see inside it.
// #458 changed `virtual_keys` from a number to a `{total,enabled}` object a day
// after the cockpit landed; nothing failed, and the console rendered "NaN" in
// production while its own fixtures stayed green.
//
// So this test reads the SERVER structs directly and asserts that the field
// set — and each field's Rust type — is exactly what `src/lib/overview.ts`
// claims. Add, rename, or retype a field on the gateway and this fails with the
// diff, pointing at the console types and fixtures that must move with it.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Vitest runs with `admin-console/` as its root, so the gateway source sits one
// directory up. Reading it (rather than a checked-in copy) is the whole point:
// there is no second artifact to forget to update.
const SOURCE = resolve(
  process.cwd(),
  "../crates/ferrogate-gateway/src/server/admin_overview.rs",
);

/**
 * The serialized shape `src/lib/overview.ts` mirrors. Keys are Rust struct
 * names; values map each serialized field to its Rust type as written.
 */
const EXPECTED: Record<string, Record<string, string>> = {
  AdminOverviewRuntime: {
    providers: "AdminOverviewEnabledCount",
    models: "AdminOverviewEnabledCount",
    static_api_keys: "usize",
    prompt_templates: "usize",
    upstreams: "AdminOverviewEnabledCount",
    routes: "AdminOverviewEnabledCount",
    plugins: "AdminOverviewActiveCount",
    tools: "usize",
    mcp_servers: "AdminOverviewMcpServers",
  },
  AdminOverviewControlPlane: {
    tenants: "u64",
    projects: "u64",
    workspaces: "u64",
    virtual_keys: "AdminOverviewEnabledCount",
    assets: "AdminOverviewAssets",
    agent_runs: "AdminOverviewCountByStatus",
    self_hosted_workers: "AdminOverviewCountByStatus",
    pending_tool_approvals: "u64",
    quota_pressure: "Vec<AdminOverviewQuotaPressure>",
    policy_governance: "Option<AdminOverviewPolicyGovernance>",
  },
  AdminOverviewAssets: {
    count: "u64",
    storage_bytes: "u64",
    referenced: "u64",
    unreferenced: "u64",
    storage_quota_bytes: "Option<u64>",
  },
  AdminOverviewQuotaPressure: {
    scope_type: "String",
    scope_id: "String",
    dimension: "String",
    unit: "String",
    used: "f64",
    cap: "f64",
    utilization_pct: "f64",
  },
  AdminOverviewPolicyGovernance: {
    guardrail_policy_revisions: "u64",
    guardrail_policy_bindings: "u64",
    quota_policies: "u64",
    policy_rules: "u64",
  },
  AdminOverviewCountByStatus: {
    total: "u64",
    by_status: "BTreeMap<String, u64>",
  },
  AdminOverviewEnabledCount: { total: "usize", enabled: "usize" },
  AdminOverviewActiveCount: { total: "usize", active: "usize" },
  AdminOverviewMcpServers: { total: "usize", connected: "usize", disconnected: "usize" },
  AdminOverviewUsage: {
    current_period_month: "String",
    lifetime: "AdminOverviewTokens",
    current_month: "AdminOverviewTokens",
  },
  AdminOverviewTokens: {
    prompt_tokens: "u64",
    completion_tokens: "u64",
    total_tokens: "u64",
    cost_usd: "f64",
    request_count: "u64",
    error_count: "u64",
  },
  AdminOverviewAlerts: {
    total: "usize",
    truncated: "bool",
    unavailable_sources: "Vec<&'static str>",
    entries: "Vec<AdminOverviewAlert>",
  },
  AdminOverviewAlert: {
    kind: "&'static str",
    severity: "&'static str",
    summary: "String",
    count: "Option<u64>",
    detected_at_unix: "u64",
    evidence: "Vec<AdminOverviewEvidence>",
    evidence_truncated: "bool",
  },
  AdminOverviewEvidence: {
    id: "String",
    detail: "Option<String>",
    at_unix: "Option<u64>",
    reference: "Option<String>",
  },
};

/** Extract `field: Type` pairs from one `pub(crate) struct <name> { … }` body. */
function structFields(source: string, name: string): Record<string, string> {
  const match = new RegExp(
    `pub\\(crate\\) struct ${name} \\{\\n([\\s\\S]*?)\\n\\}`,
    "m",
  ).exec(source);
  if (!match) throw new Error(`struct ${name} not found in ${SOURCE}`);
  const fields: Record<string, string> = {};
  for (const line of match[1].split("\n")) {
    const field = /^\s*pub\(crate\) (\w+): (.+),$/.exec(line);
    if (field) fields[field[1]] = field[2];
  }
  return fields;
}

describe("admin overview wire contract", () => {
  const source = readFileSync(SOURCE, "utf8");

  for (const [name, expected] of Object.entries(EXPECTED)) {
    it(`${name} still serializes the fields the console parses`, () => {
      expect(structFields(source, name)).toEqual(expected);
    });
  }
});
