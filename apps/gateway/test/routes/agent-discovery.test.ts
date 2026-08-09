/**
 * `GET /.well-known/agent.json` — ported from `handle_agent_discovery`.
 *
 * Driven through the real `createGatewayApp` (so `contractAuth` runs exactly as
 * it does in the Worker) with the `[[agent_upstreams]]` table supplied as the
 * Worker var the port reads.
 */
import { describe, expect, it } from "vitest";

import { agentDiscoveryDocument, parseAgentUpstreams } from "../../src/routes/agent-discovery.js";
import { createGatewayApp } from "../../src/routes/index.js";

const UPSTREAMS = [
  {
    id: "planner",
    name: "Planner Agent",
    description: "decomposes goals",
    endpoint: "https://planner.example/a2a",
    capabilities: ["invoke", "read"],
  },
  // Disabled: never in the document, for any caller.
  {
    id: "retired",
    name: "Retired Agent",
    enabled: false,
    endpoint: "https://retired.example/a2a",
  },
  // Restricted: only the credential whose id is listed sees it.
  {
    id: "private",
    name: "Private Agent",
    endpoint: "https://private.example/a2a",
    tenant_ids: ["key_agents"],
    protocol: "a2a",
  },
];

const ENV = {
  GATEWAY_NATIVE_API_KEYS: JSON.stringify([
    { key: "fg_agents", id: "key_agents", tenant_id: "tenant_a", scopes: ["agents.read"] },
    { key: "fg_other", id: "key_other", tenant_id: "tenant_a", scopes: ["agents.read"] },
    { key: "fg_noscope", id: "key_noscope", tenant_id: "tenant_a", scopes: ["skills.read"] },
  ]),
  GATEWAY_AGENT_UPSTREAMS: JSON.stringify(UPSTREAMS),
};

interface DiscoveryDocument {
  object: string;
  data: { object: string; id: string; endpoint: string; capabilities: string[] }[];
}

function call(token: string | null, env: Record<string, string> = ENV): Promise<Response> {
  const { app } = createGatewayApp();
  const headers = new Headers();
  if (token !== null) headers.set("authorization", `Bearer ${token}`);
  return Promise.resolve(app.request("https://gw.test/.well-known/agent.json", { headers }, env));
}

describe("GET /.well-known/agent.json", () => {
  it("is a bearer operation guarded by agents.read", async () => {
    // The contract says `bearer` + `agents.read`; the route being IMPLEMENTED
    // must not have loosened either.
    expect((await call(null)).status).toBe(401);
    const denied = await call("fg_noscope");
    expect(denied.status).toBe(403);
    expect(((await denied.json()) as { error: { code: string } }).error.code).toBe("scope_denied");
  });

  it("lists the enabled, caller-visible upstreams in an AdminList envelope", async () => {
    const res = await call("fg_agents");
    expect(res.status).toBe(200);
    const body = (await res.json()) as DiscoveryDocument;

    expect(body.object).toBe("list");
    // `AdminList::new` leaves total/offset/limit unset and serde skips them.
    expect(Object.keys(body).sort()).toStrictEqual(["data", "object"]);
    expect(body.data.map((entry) => entry.id)).toStrictEqual(["planner", "private"]);
    expect(body.data[0]).toStrictEqual({
      object: "agent_upstream",
      id: "planner",
      name: "Planner Agent",
      description: "decomposes goals",
      protocol: "a2a",
      endpoint: "https://planner.example/a2a",
      capabilities: ["invoke", "read"],
    });
  });

  it("hides a restricted upstream from a credential that is not listed", async () => {
    const body = (await (await call("fg_other")).json()) as DiscoveryDocument;
    expect(body.data.map((entry) => entry.id)).toStrictEqual(["planner"]);
  });

  it("never lists a disabled upstream", async () => {
    for (const token of ["fg_agents", "fg_other"]) {
      const body = (await (await call(token)).json()) as DiscoveryDocument;
      expect(body.data.map((entry) => entry.id)).not.toContain("retired");
    }
  });

  it("answers an empty list when no table is configured", async () => {
    const body = (await (
      await call("fg_agents", { GATEWAY_NATIVE_API_KEYS: ENV.GATEWAY_NATIVE_API_KEYS })
    ).json()) as DiscoveryDocument;
    expect(body).toStrictEqual({ object: "list", data: [] });
  });

  it("fails closed on a malformed table rather than serving a partial one", async () => {
    const body = (await (
      await call("fg_agents", {
        GATEWAY_NATIVE_API_KEYS: ENV.GATEWAY_NATIVE_API_KEYS,
        GATEWAY_AGENT_UPSTREAMS: "{not json",
      })
    ).json()) as DiscoveryDocument;
    expect(body.data).toStrictEqual([]);
  });
});

describe("projection details (`agent_upstream_discovery`)", () => {
  it("defaults protocol to a2a and omits nothing", () => {
    const [record] = parseAgentUpstreams(
      JSON.stringify([{ id: "a", name: "A", endpoint: "https://a.example" }]),
    );
    expect(record).toBeDefined();
    const doc = agentDiscoveryDocument([record as NonNullable<typeof record>], null);
    expect(doc.data[0]).toStrictEqual({
      object: "agent_upstream",
      id: "a",
      name: "A",
      // `Option<&str>` serializes as an explicit null.
      description: null,
      protocol: "a2a",
      endpoint: "https://a.example",
      capabilities: [],
    });
  });

  it("drops records missing a required config member", () => {
    expect(
      parseAgentUpstreams(
        JSON.stringify([
          { id: "no-endpoint", name: "x" },
          { name: "no-id", endpoint: "https://x.example" },
          { id: "ok", name: "ok", endpoint: "https://ok.example" },
        ]),
      ).map((record) => record.id),
    ).toStrictEqual(["ok"]);
  });

  it("an unrestricted upstream is visible even with no credential resolved", () => {
    const upstreams = parseAgentUpstreams(
      JSON.stringify([{ id: "open", name: "Open", endpoint: "https://open.example" }]),
    );
    expect(agentDiscoveryDocument(upstreams, null).data).toHaveLength(1);
  });
});
