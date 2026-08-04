import { describe, expect, test } from "vitest";
import {
  type CheckBinding,
  type PolicyRevision,
  type PolicyScopeSelector,
  admitPolicyRevision,
  aggregateCheckOutcomes,
  administrativeRank,
  immutableId,
  localDetectorDefinition,
  policyActions,
  scopeMatches,
  selectPolicyRevisions,
  validatePolicyRevision,
} from "../src/index.js";

function emptyScope(overrides: Partial<PolicyScopeSelector> = {}): PolicyScopeSelector {
  return {
    tenant_ids: [],
    organization_ids: [],
    project_ids: [],
    workspace_ids: [],
    api_key_ids: [],
    gateway_config_ids: [],
    models: [],
    providers: [],
    ...overrides,
  };
}

function localCheck(id: string): CheckBinding {
  return {
    id,
    enabled: true,
    stage: "request",
    sources: ["user"],
    detector: localDetectorDefinition(["forbidden"], [], undefined),
  };
}

function revision(overrides: Partial<PolicyRevision> = {}): PolicyRevision {
  return {
    policy_id: "p1",
    revision: 1,
    name: "policy",
    enforced: true,
    scope: emptyScope(),
    checks: [localCheck("c1")],
    aggregation: { type: "all" },
    execution: "sequential",
    mode: "enforce",
    streaming: "buffer_and_enforce",
    on_pass: [policyActions.allow()],
    on_fail: [policyActions.block("blocked", "denied")],
    on_error: [policyActions.block("error", "failed")],
    deadline_ms: 2000,
    created_at_unix: 0,
    created_by: "admin",
    ...overrides,
  };
}

describe("aggregateCheckOutcomes", () => {
  test("All: any fail wins, else any error, else pass", () => {
    expect(aggregateCheckOutcomes({ type: "all" }, ["pass", "fail"])).toBe("fail");
    expect(aggregateCheckOutcomes({ type: "all" }, ["pass", "error"])).toBe("error");
    expect(aggregateCheckOutcomes({ type: "all" }, ["pass", "pass"])).toBe("pass");
  });

  test("Any: any pass wins", () => {
    expect(aggregateCheckOutcomes({ type: "any" }, ["fail", "pass"])).toBe("pass");
    expect(aggregateCheckOutcomes({ type: "any" }, ["fail", "error"])).toBe("error");
    expect(aggregateCheckOutcomes({ type: "any" }, ["fail", "fail"])).toBe("fail");
  });

  test("Threshold on failures then failures+errors", () => {
    expect(aggregateCheckOutcomes({ type: "threshold", minimum: 2 }, ["fail", "fail", "pass"])).toBe("fail");
    expect(aggregateCheckOutcomes({ type: "threshold", minimum: 2 }, ["fail", "error", "pass"])).toBe("error");
    expect(aggregateCheckOutcomes({ type: "threshold", minimum: 2 }, ["fail", "pass", "pass"])).toBe("pass");
  });

  test("all-disabled aggregates to error", () => {
    expect(aggregateCheckOutcomes({ type: "all" }, ["disabled", "disabled"])).toBe("error");
  });
});

describe("scope matching + administrative rank", () => {
  test("rejects a service-account scope with no data-plane identity source", () => {
    const candidate: unknown = {
      ...revision(),
      scope: { ...emptyScope(), service_account_ids: ["service-account-1"] },
    };

    const result = admitPolicyRevision(candidate);

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("service-account scopes must not be admitted");
    expect(result.error.field).toBe("scope");
  });

  test("model-content policy only matches model content (not managed actions)", () => {
    const scope = emptyScope({ tenant_ids: ["t1"] });
    expect(scopeMatches(scope, { organization_id: "t1" })).toBe(true);
    expect(
      scopeMatches(scope, { organization_id: "t1", managed_action: { class: "mcp" } }),
    ).toBe(false);
  });

  test("managed-action selector matches only its class", () => {
    const scope = emptyScope({ managed_action: { classes: ["mcp"], targets: [] } });
    expect(scopeMatches(scope, { managed_action: { class: "mcp" } })).toBe(true);
    expect(scopeMatches(scope, { managed_action: { class: "cli" } })).toBe(false);
    expect(scopeMatches(scope, {})).toBe(false);
  });

  test("administrative rank ordering", () => {
    expect(administrativeRank(emptyScope({ gateway_config_ids: ["g"] }))).toBe(5);
    expect(administrativeRank(emptyScope({ api_key_ids: ["k"] }))).toBe(4);
    expect(administrativeRank(emptyScope({ workspace_ids: ["w"] }))).toBe(3);
    expect(administrativeRank(emptyScope({ project_ids: ["p"] }))).toBe(2);
    expect(administrativeRank(emptyScope({ tenant_ids: ["t"] }))).toBe(1);
    expect(administrativeRank(emptyScope())).toBe(0);
  });
});

describe("selectPolicyRevisions ordering", () => {
  test("sorts by (rank, policy_id, revision)", () => {
    const broad = revision({ policy_id: "a", scope: emptyScope({ tenant_ids: ["t"] }) });
    const specific = revision({ policy_id: "b", scope: emptyScope({ api_key_ids: ["k"] }) });
    const selected = selectPolicyRevisions([specific, broad], { organization_id: "t", api_key_id: "k" });
    expect(selected.map((r) => r.policy_id)).toEqual(["a", "b"]);
  });
});

describe("validatePolicyRevision", () => {
  test("accepts a well-formed revision", () => {
    expect(() => validatePolicyRevision(revision())).not.toThrow();
    expect(immutableId(revision())).toBe("p1@1");
  });

  test("revision 0 is rejected", () => {
    expect(() => validatePolicyRevision(revision({ revision: 0 }))).toThrow(/revision/);
  });

  test("threshold above enabled check count is rejected", () => {
    expect(() =>
      validatePolicyRevision(revision({ aggregation: { type: "threshold", minimum: 5 } })),
    ).toThrow(/threshold/);
  });

  test("enforcing action without code+message is rejected", () => {
    expect(() =>
      validatePolicyRevision(revision({ on_fail: [{ kind: "block" }] })),
    ).toThrow(/code and message/);
  });

  test("non-local fallback detector is rejected", () => {
    const check: CheckBinding = {
      ...localCheck("c1"),
      fallback_detector: {
        kind: "custom_http",
        endpoint: "https://x.example.com/s",
        timeout_ms: 2000,
        max_concurrency: 4,
        circuit_failure_threshold: 3,
        circuit_cooldown_ms: 1000,
        max_retries: 0,
        max_payload_bytes: 1024,
        max_response_bytes: 1024,
        allow_private_network: false,
      },
    };
    expect(() => validatePolicyRevision(revision({ checks: [check] }))).toThrow(/fallback_detector must be local/);
  });
});
