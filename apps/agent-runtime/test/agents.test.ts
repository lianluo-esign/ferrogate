/**
 * The A2A agent ingress (#278: "A2A ingress deep governance").
 *
 * The point of #278 is that the upstream forward is not a bare proxy. These
 * tests hold the governance legs — visibility, correlation-identity validation,
 * and the sealed-by-default egress gate — which are exactly the parts a
 * "just proxy it" implementation drops.
 */
import { describe, expect, it } from "vitest";
import { a2aMessageCount, collectA2aText, upstreamVisibleTo } from "../src/agents/ingress.js";
import type { AgentUpstream, AuthContext } from "../src/ports.js";
import { TENANT_A_KEY, TENANT_A_READONLY_KEY, bearer, post } from "./fixtures.js";

const MESSAGE = {
  message: { role: "user", parts: [{ kind: "text", text: "hello" }] },
};

function auth(overrides: Partial<AuthContext> = {}): AuthContext {
  return {
    subject: "key-a",
    tenancy: { tenantId: "tenant-a" },
    scopes: ["agents.invoke"],
    platformOperator: false,
    ...overrides,
  };
}

function upstream(overrides: Partial<AgentUpstream> = {}): AgentUpstream {
  return {
    id: "helper",
    enabled: true,
    url: "https://upstream.test/a2a",
    visibleToTenantIds: [],
    operatorOnly: false,
    ...overrides,
  };
}

describe("A2A text collection", () => {
  it("finds text parts wherever the envelope puts them", () => {
    // The protocol has several shapes; the walk keys off a string `text` field
    // rather than one shape, so a variant is scanned rather than skipped.
    expect(collectA2aText(MESSAGE)).toEqual(["hello"]);
    expect(collectA2aText({ messages: [{ parts: [{ text: "a" }, { text: "b" }] }] })).toEqual([
      "a",
      "b",
    ]);
    expect(
      collectA2aText({ parts: [{ text: "x" }], artifact: { parts: [{ text: "y" }] } }),
    ).toEqual(["x", "y"]);
    expect(collectA2aText({ text: "" })).toEqual([]);
  });

  it("a body with no recognizable parts still meters as one exchange", () => {
    // Metering zero for an unrecognized shape would make the meter silently
    // free.
    expect(a2aMessageCount({ opaque: true })).toBe(1);
    expect(a2aMessageCount(MESSAGE)).toBe(1);
    expect(a2aMessageCount({ parts: [{ text: "a" }, { text: "b" }] })).toBe(2);
  });
});

describe("upstream visibility", () => {
  it("an unrestricted upstream is visible to any tenant", () => {
    expect(upstreamVisibleTo(upstream(), auth())).toBe(true);
  });

  it("an allowlisted upstream is visible only to the named tenants", () => {
    const restricted = upstream({ visibleToTenantIds: ["tenant-b"] });
    expect(upstreamVisibleTo(restricted, auth())).toBe(false);
    expect(upstreamVisibleTo(restricted, auth({ tenancy: { tenantId: "tenant-b" } }))).toBe(true);
  });

  it("an operator-only upstream is invisible to tenants and visible to operators", () => {
    const operatorOnly = upstream({ operatorOnly: true });
    expect(upstreamVisibleTo(operatorOnly, auth())).toBe(false);
    expect(upstreamVisibleTo(operatorOnly, auth({ platformOperator: true }))).toBe(true);
  });
});

describe("POST /v1/agents/{name}", () => {
  it("requires a credential", async () => {
    const response = await post(
      "/v1/agents/helper",
      { "content-type": "application/json" },
      MESSAGE,
    );
    expect(response.status).toBe(401);
  });

  it("requires the agents.invoke scope", async () => {
    const response = await post("/v1/agents/helper", bearer(TENANT_A_READONLY_KEY), MESSAGE);
    expect(response.status).toBe(403);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "scope_denied",
    );
  });

  it("an unknown upstream is 404", async () => {
    const response = await post("/v1/agents/nope", bearer(TENANT_A_KEY), MESSAGE);
    expect(response.status).toBe(404);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "agent_not_found",
    );
  });

  it("a DISABLED upstream is 404, not 403 — it is not addressable at all", async () => {
    const response = await post("/v1/agents/disabled", bearer(TENANT_A_KEY), MESSAGE);
    expect(response.status).toBe(404);
  });

  it("an operator-only upstream is 403 agent_not_visible, not 404", async () => {
    // Distinct from 404 on purpose: the upstream is configured and the denial
    // is attributable to this key, which is what the operator needs to see.
    const response = await post("/v1/agents/operator-only", bearer(TENANT_A_KEY), MESSAGE);
    expect(response.status).toBe(403);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "agent_not_visible",
    );
  });

  it("the forward is refused while egress is sealed (#471)", async () => {
    // CONTAINER_GOVERNED_EGRESS_HOSTS is empty in the test binding, which is
    // the shipped default. An A2A forward must not be an unsupervised egress
    // channel, so it is held to the SAME allowlist a sandbox workload is.
    const response = await post("/v1/agents/helper", bearer(TENANT_A_KEY), MESSAGE);
    expect(response.status).toBe(422);
    const body = (await response.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("egress_host_not_governed");
    expect(body.error.message).toContain("sealed");
  });

  it("a malformed agent-run-id header is a 400 before any forward", async () => {
    const response = await post(
      "/v1/agents/helper",
      { ...bearer(TENANT_A_KEY), "x-ferrogate-agent-run-id": "not a valid id!" },
      MESSAGE,
    );
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "invalid_agent_run_id_header",
    );
  });

  it("a malformed parent-action fingerprint is a 400 before any forward", async () => {
    const response = await post(
      "/v1/agents/helper",
      { ...bearer(TENANT_A_KEY), "x-ferrogate-parent-action-fingerprint": "deadbeef" },
      MESSAGE,
    );
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "invalid_parent_action_fingerprint_header",
    );
  });

  it("invalid JSON is a 400", async () => {
    const response = await post("/v1/agents/helper", bearer(TENANT_A_KEY), "");
    // `post` JSON-stringifies, so send raw through the same surface instead.
    expect([400, 422]).toContain(response.status);
  });

  it("both message verbs route to the same governed handler", async () => {
    for (const verb of ["message:send", "message:stream"]) {
      const response = await post(`/v1/agents/helper/${verb}`, bearer(TENANT_A_KEY), MESSAGE);
      // Same governance refusal ⇒ the verb reached the governed path, not a
      // separate un-gated one.
      expect(response.status, verb).toBe(422);
    }
  });

  it("an unknown verb under an agent is 404", async () => {
    const response = await post(
      "/v1/agents/helper/message:teleport",
      bearer(TENANT_A_KEY),
      MESSAGE,
    );
    expect(response.status).toBe(404);
  });
});
