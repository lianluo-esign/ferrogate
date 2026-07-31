import { describe, expect, test } from "vitest";
import type { RequestContext } from "@ferrogate/core";
import { ALLOW, BasicPolicyEngine, denyRule } from "../src/index.js";

function request(organizationId: string, projectId: string, apiKeyId: string): RequestContext {
  return {
    request_id: "fg-test",
    route: "openai.chat.completions",
    upstream: "openai",
    tenant: {
      organization_id: organizationId,
      project_id: projectId,
      api_key_id: apiKeyId,
    },
  };
}

describe("BasicPolicyEngine", () => {
  test("default (no rules) allows", () => {
    const engine = new BasicPolicyEngine();
    expect(engine.evaluate(request("org", "project", "key"), "fast-chat", "openai")).toEqual(ALLOW);
  });

  test("deny rule matches tenant, model and provider; non-matching model allows", () => {
    const engine = new BasicPolicyEngine([
      denyRule(
        { organizationId: "org", projectId: "project", apiKeyId: "key" },
        ["fast-chat"],
        ["openai"],
        "policy_denied",
        "blocked by policy",
      ),
    ]);
    const req = request("org", "project", "key");
    expect(engine.evaluate(req, "fast-chat", "openai")).toEqual({
      kind: "deny",
      code: "policy_denied",
      message: "blocked by policy",
    });
    // A different model no longer matches the rule → Allow.
    expect(engine.evaluate(req, "smart-chat", "openai")).toEqual(ALLOW);
  });

  test("rule ignores a non-matching tenant (wildcard fields still constrained)", () => {
    const engine = new BasicPolicyEngine([
      denyRule({ organizationId: "other" }, [], ["openai"], "policy_denied", "blocked"),
    ]);
    expect(engine.evaluate(request("org", "project", "key"), "fast-chat", "openai")).toEqual(ALLOW);
  });

  test("empty model/provider lists are wildcards; first matching rule wins", () => {
    const engine = new BasicPolicyEngine([
      denyRule({}, [], [], "first", "first rule"),
      denyRule({}, [], [], "second", "second rule"),
    ]);
    const decision = engine.evaluate(request("o", "p", "k"), undefined, undefined);
    expect(decision).toEqual({ kind: "deny", code: "first", message: "first rule" });
  });

  test("edge: a provider allowlist with an absent requested provider does not match", () => {
    const engine = new BasicPolicyEngine([
      denyRule({}, [], ["openai"], "needs_provider", "requires provider"),
    ]);
    // provider is undefined ⇒ non-empty allowlist can't match ⇒ Allow.
    expect(engine.evaluate(request("o", "p", "k"), "fast-chat", undefined)).toEqual(ALLOW);
  });
});
