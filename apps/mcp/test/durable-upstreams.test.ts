/**
 * The SHARED upstream-MCP session (`src/session.ts`) and the composition seam
 * that puts it on the request path (`src/upstreams.ts`).
 *
 * Two things are held here, and they are different kinds of claim:
 *
 *  1. **The Durable Object behaves like Rust's `McpSession`.** Exercised
 *     against the REAL `env.MCP_SESSION` namespace booted by
 *     `@cloudflare/vitest-pool-workers` in workerd — the same DO implementation
 *     `wrangler dev --local` runs. No fake store.
 *
 *  2. **It is MOUNTED.** `HttpMcpUpstreams`, `loadServerCatalog` and
 *     `DurableMcpSessionStore` were previously implemented, tested and
 *     unreachable: `resolvePorts` bound `InMemoryUpstreams` in every posture, so
 *     no deployed request could ever reach them. The `SELF` tests at the bottom
 *     drive the app the Worker actually exports and assert a catalog that ONLY
 *     the D1 path can produce, so deleting the `withTenantUpstreams` call from
 *     `src/routes/ingress.ts` turns them red instead of leaving 248 tests green.
 *     Each one is paired with a CONTROL in the in-memory posture, because
 *     "the list does not contain srv-echo" proves nothing on its own.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { ensureMcpIdentitySchema } from "../src/durable.js";
import { type McpEnv, type McpTool, inMemoryPorts } from "../src/ports.js";
import { MCP_PROTOCOL_VERSION, type McpNegotiatedProtocol } from "../src/protocol.js";
import {
  DEFAULT_RECONNECT_POLICY,
  DurableMcpSessionStore,
  HEALTH_CHECK_FAILED,
  sessionKey,
  statusOf,
} from "../src/session.js";
import { HttpMcpUpstreams } from "../src/transport.js";
import {
  durableUpstreamsBound,
  resolveUpstreams,
  upstreamCatalogTenant,
} from "../src/upstreams.js";
import {
  EXEC_KEY,
  READ_KEY,
  TENANT,
  rpcRequest,
  seedFixture,
  setMcpEnvVar,
  tenantAuth,
} from "./fixtures.js";

const DB = env.DB as unknown as D1Database;
const SESSIONS = env.MCP_SESSION as unknown as DurableObjectNamespace;

const MODERN: McpNegotiatedProtocol = { mode: "modern", version: "2026-07-28" };

function tool(name: string): McpTool {
  return {
    name: `srv-${name}`,
    serverName: "srv",
    remoteName: name,
    inputSchema: { type: "object" },
    autoExecute: false,
  };
}

/**
 * A store for one tenant. Two calls with the same tenant model TWO ISOLATES
 * reaching the same object — which is the entire point of the DO.
 */
function store(tenantId: string): DurableMcpSessionStore {
  return new DurableMcpSessionStore(
    env.MCP_SESSION as NonNullable<typeof env.MCP_SESSION>,
    tenantId,
  );
}

describe("FerroGateMcpSession — the binding exists at all", () => {
  it("binds MCP_SESSION to a resolvable Durable Object class", async () => {
    // If `FerroGateMcpSession` were not re-exported from `src/worker.ts`, or the
    // `[[durable_objects.bindings]]` block were missing, workerd would refuse to
    // start this Worker and no test in this file would run. Reaching a stub and
    // getting an answer out of it is the positive half of that proof.
    expect(SESSIONS).toBeDefined();
    const state = await store("t-binding").read("srv");
    expect(state.connected).toBe(false);
    expect(state.reconnectAttempts).toBe(0);
    expect(state.nextReconnectBackoffSecs).toBe(DEFAULT_RECONNECT_POLICY.minReconnectBackoffSecs);
  });
});

describe("FerroGateMcpSession — Rust McpSession transitions, on the real DO", () => {
  it("shares a negotiated session across two independent store instances", async () => {
    const written = await store("t1").connected("srv", MODERN, [tool("echo")], 1_700);
    expect(written.connected).toBe(true);

    // A DIFFERENT store object — the model of a second isolate. Before the DO
    // existed this read returned a fresh, unconnected session every time.
    const read = await store("t1").read("srv");
    expect(read.connected).toBe(true);
    expect(read.negotiation).toEqual(MODERN);
    expect(read.tools.map((each) => each.name)).toEqual(["srv-echo"]);
    expect(read.lastConnectedAtUnix).toBe(1_700);
  });

  it("keeps two tenants' same-named upstreams in separate objects", async () => {
    await store("t-a").connected("srv", MODERN, [tool("echo")], 1_700);
    const other = await store("t-b").read("srv");
    expect(other.connected).toBe(false);
    expect(other.tools).toEqual([]);
    // The isolation is a property of the ADDRESS, not of a check inside the DO.
    expect(sessionKey("t-a", "srv")).not.toBe(sessionKey("t-b", "srv"));
  });

  it("drops the tool list and doubles the backoff on a failed connect", async () => {
    await store("t2").connected("srv", MODERN, [tool("echo")], 1_700);
    const first = await store("t2").failed("srv", "connect refused");
    expect(first.connected).toBe(false);
    expect(first.tools).toEqual([]);
    expect(first.negotiation).toBeUndefined();
    expect(first.lastError).toBe("connect refused");
    expect(first.reconnectAttempts).toBe(1);
    expect(first.nextReconnectBackoffSecs).toBe(2);

    const second = await store("t2").failed("srv", "connect refused again");
    expect(second.reconnectAttempts).toBe(2);
    expect(second.nextReconnectBackoffSecs).toBe(4);
  });

  it("caps the doubled backoff at the policy maximum", async () => {
    for (let i = 0; i < 8; i += 1) await store("t3").failed("srv", "down");
    const state = await store("t3").read("srv");
    expect(state.nextReconnectBackoffSecs).toBe(DEFAULT_RECONNECT_POLICY.maxReconnectBackoffSecs);
  });

  it("clears the error and resets the counters when a reconnect succeeds", async () => {
    await store("t4").failed("srv", "down");
    const healthy = await store("t4").connected("srv", MODERN, [tool("echo")], 2_000);
    expect(healthy.lastError).toBeUndefined();
    expect(healthy.reconnectAttempts).toBe(0);
    expect(healthy.nextReconnectBackoffSecs).toBe(DEFAULT_RECONNECT_POLICY.minReconnectBackoffSecs);
  });

  it("a failed health PROBE keeps the tools and the backoff untouched", async () => {
    await store("t5").connected("srv", MODERN, [tool("echo")], 1_700);
    const probed = await store("t5").unhealthy("srv");
    expect(probed.connected).toBe(false);
    expect(probed.lastError).toBe(HEALTH_CHECK_FAILED);
    // Rust clears these only once a RECONNECT has also failed.
    expect(probed.tools.map((each) => each.name)).toEqual(["srv-echo"]);
    expect(probed.reconnectAttempts).toBe(0);
    expect(probed.nextReconnectBackoffSecs).toBe(DEFAULT_RECONNECT_POLICY.minReconnectBackoffSecs);
  });

  it("reset drops the shared session, as a reconfigure must", async () => {
    await store("t6").connected("srv", MODERN, [tool("echo")], 1_700);
    await store("t6").reset("srv");
    const state = await store("t6").read("srv");
    expect(state.connected).toBe(false);
    expect(state.tools).toEqual([]);
  });

  it("reports a disconnected session as degraded and hides its protocol", async () => {
    await store("t7").connected("srv", MODERN, [tool("echo")], 1_700);
    expect(statusOf("srv", await store("t7").read("srv"))).toMatchObject({
      connected: true,
      health: "ok",
      tools: 1,
      protocolVersion: MODERN.version,
      protocolMode: "modern",
    });

    await store("t7").failed("srv", "down");
    const degraded = statusOf("srv", await store("t7").read("srv"));
    expect(degraded.health).toBe("degraded");
    expect(degraded.protocolVersion).toBeUndefined();
    expect(degraded.protocolMode).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// THE MOUNT
// ---------------------------------------------------------------------------

/** Insert one upstream row into the tenant's D1 catalog. */
async function seedServerRow(
  tenantId: string,
  name: string,
  transport: string,
  url: string | null,
): Promise<void> {
  await ensureMcpIdentitySchema(DB);
  await DB.prepare(
    `INSERT OR REPLACE INTO mcp_servers
       (tenant_id, name, transport, url, auth_type, tools_to_execute,
        tools_to_auto_execute, headers, oauth, signed_jwt_audience, timeout_ms)
     VALUES (?, ?, ?, ?, 'none', ?, ?, NULL, NULL, NULL, 5000)`,
  )
    .bind(tenantId, name, transport, url, JSON.stringify(["echo"]), JSON.stringify([]))
    .run();
}

/** The REST transport of the same chokepoint — `POST /v1/mcp/tool/execute`. */
function executeTool(name: string, key: string): Promise<Response> {
  return SELF.fetch(
    new Request("https://ferrogate.test/v1/mcp/tool/execute", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
      body: JSON.stringify({ name, arguments: {} }),
    }),
  );
}

/**
 * An upstream that completes the modern handshake and advertises one tool.
 *
 * Deliberately NOT the real network: `@cloudflare/vitest-pool-workers` 0.18.8
 * exports no `fetchMock`, so the only honest way to exercise a SUCCESSFUL
 * handshake is to hand `HttpMcpUpstreams` its `fetchImpl` directly.
 */
function discoveringFetch(): typeof fetch {
  return (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body ?? "{}")) as { method: string };
    const result =
      body.method === "server/discover"
        ? {
            resultType: "complete",
            capabilities: {},
            supportedVersions: [MCP_PROTOCOL_VERSION],
          }
        : { tools: [{ name: "echo", inputSchema: { type: "object" } }] };
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

async function toolNames(key: string): Promise<string[]> {
  const res = await SELF.fetch(
    rpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" }, { key }),
  );
  expect(res.status).toBe(200);
  const body = (await res.json()) as { result: { tools: Array<{ name: string }> } };
  return body.result.tools.map((each) => each.name);
}

describe("the durable upstream catalog is MOUNTED on the exported Worker", () => {
  beforeEach(async () => {
    seedFixture();
    await ensureMcpIdentitySchema(DB);
    await DB.prepare("DELETE FROM mcp_servers").run();
  });

  afterEach(() => {
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", undefined);
  });

  it("CONTROL: without the durable opt-in, the in-memory host still answers", async () => {
    // Without this control, the assertion below ("srv-echo is absent") would
    // also pass if `tools/list` were broken outright.
    expect(await toolNames(READ_KEY)).toContain("srv-echo");
  });

  it("serves the D1 catalog, not the in-memory host, once the durable path is on", async () => {
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", "1");
    // The tenant has NO rows, so the honest answer is no MCP tools at all. The
    // in-memory host would still be advertising `srv-echo` here, which is
    // exactly what this catches: delete the `withTenantUpstreams` call in
    // `src/routes/ingress.ts` and this line fails.
    const names = await toolNames(READ_KEY);
    expect(names).not.toContain("srv-echo");
    // Builtins are not upstream tools and must survive the swap — otherwise
    // "no srv-echo" could just mean the whole tool list collapsed.
    expect(names).toContain("builtin.fetch_asset");
  });

  it("still refuses an unknown tool at the chokepoint once the host is swapped", async () => {
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", "1");
    const res = await SELF.fetch(
      rpcRequest(
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "srv-echo", arguments: {} },
        },
        { key: EXEC_KEY },
      ),
    );
    // `srv-echo` is the IN-MEMORY host's tool. Under the durable host the
    // tenant has no such row, so deny-by-default must refuse it rather than
    // falling through to the seeded in-memory handler.
    expect(JSON.stringify(await res.json())).toContain("not allowlisted for execution");
  });

  /**
   * The REST transport of the SAME chokepoint (#764).
   *
   * `src/routes/ingress.ts` mounts `withTenantUpstreams` TWICE — once on
   * `POST /v1/mcp` and once on `POST /v1/mcp/tool/execute` — and its comment
   * claims "both ingress paths must resolve the tenant's real host or the two
   * transports disagree about which tools exist". Only the JSON-RPC half was
   * held: the #764 sweep deleted the REST one and all 537 tests stayed green,
   * so the claim about the pair was proven for one of the pair.
   */
  it("resolves the tenant's durable host on the REST transport too", async () => {
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", "1");
    const res = await executeTool("srv-echo", EXEC_KEY);
    // Same reasoning as the JSON-RPC case above: `srv-echo` belongs to the
    // seeded IN-MEMORY host. Under the durable host this tenant has no such
    // row, so leaving the REST leg on `ports` would execute the in-memory
    // handler and answer 200 — the two transports disagreeing about which
    // tools exist, which is precisely what the mount exists to prevent.
    expect(res.status).toBe(403);
    expect(JSON.stringify(await res.json())).toContain("not allowlisted for execution");
  });

  it("CONTROL: the REST transport serves the in-memory host without the opt-in", async () => {
    // Without this, "403" above would also be satisfied by a REST transport
    // that refuses `srv-echo` under every posture.
    const res = await executeTool("srv-echo", EXEC_KEY);
    expect(res.status).toBe(200);
    expect(JSON.stringify(await res.json())).toContain("tool_execution");
  });
});

// ---------------------------------------------------------------------------
// The WIRE between HttpMcpUpstreams and the shared MCP_SESSION (#764)
// ---------------------------------------------------------------------------

/**
 * `DurableMcpSessionStore` is exercised directly at the top of this file, and
 * `HttpMcpUpstreams` is exercised against a stub fetch elsewhere. The #764
 * sweep found that the WIRE between them was held by nothing: deleting the
 * `#store?.connected(...)` publish, the `#store?.failed(...)` report, or even
 * the `{ sessions: ... }` argument in `resolveUpstreams` left the whole suite
 * green. Without that wire the shared session is a Durable Object nobody
 * writes to — every isolate re-handshakes, and an upstream outage is a
 * per-isolate fact rather than a fleet-wide one, which is the entire reason
 * the object exists.
 *
 * `test/env-var-drift.test.ts` does assert `MCP_SESSION` is READ somewhere in
 * the source text. That is a scanner over the file contents, not a test of
 * behaviour: it passes against a mount that is present and broken.
 */
describe("the shared MCP_SESSION is WRITTEN by the host on the request path", () => {
  beforeEach(async () => {
    seedFixture();
    await ensureMcpIdentitySchema(DB);
    await DB.prepare("DELETE FROM mcp_servers").run();
  });

  afterEach(async () => {
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", undefined);
    await DB.prepare("DELETE FROM mcp_servers").run();
  });

  it("records an upstream failure observed by a REAL request on the shared session", async () => {
    // A `streamable_http` row with no url: the handshake refuses for want of
    // an endpoint BEFORE any fetch, so this needs no network and no
    // interceptor (pool-workers 0.18.8 exports no `fetchMock`).
    await seedServerRow(TENANT, "offline", "streamable_http", null);
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", "1");

    // The control: nothing has been written yet, so a non-zero counter below
    // cannot be left over from another test's tenant.
    expect((await store(TENANT).read("offline")).reconnectAttempts).toBe(0);

    // ONE ordinary request through the Worker the deploy entrypoint exports.
    expect(await toolNames(READ_KEY)).not.toContain("offline-ping");

    // The failure the request observed is now a fact on the SHARED object, so
    // the next isolate — and the operator's view of the fleet — sees it. This
    // is the leg `resolveUpstreams` supplies with `{ sessions: ... }`; drop
    // that argument and the host has no store to write to.
    const state = await store(TENANT).read("offline");
    expect(state.connected).toBe(false);
    expect(state.reconnectAttempts).toBe(1);
    expect(state.lastError).toContain("requires url");
  });

  it("publishes a discovered catalogue to the shared session for the next isolate", async () => {
    const tenantId = "t-publish";
    const config = {
      name: "srv",
      transport: "streamable_http" as const,
      url: "https://srv.upstream.test/mcp",
      authType: "none" as const,
      toolsToExecute: ["echo"],
      toolsToAutoExecute: ["echo"],
      timeoutMs: 5_000,
    };
    const shared = store(tenantId);
    // The control: the shared session starts empty, so the tool list below can
    // only have been put there by the discovery this test ran.
    expect((await shared.read("srv")).tools).toEqual([]);

    const host = new HttpMcpUpstreams([config], discoveringFetch(), { sessions: shared });
    expect((await host.fanIn()).tools.map((tool) => tool.name)).toEqual(["srv-echo"]);

    const state = await shared.read("srv");
    expect(state.connected).toBe(true);
    // The tool LIST specifically, not merely `connected`: the handshake writes
    // a connected session with an empty list one line earlier, so asserting
    // only `connected` would leave the publish of the catalogue unheld.
    expect(state.tools.map((tool) => tool.name)).toEqual(["srv-echo"]);
    expect(state.negotiation?.mode).toBe("modern");
  });
});

describe("resolveUpstreams — the tenant filter is the isolation boundary", () => {
  beforeEach(async () => {
    seedFixture();
    await ensureMcpIdentitySchema(DB);
    await DB.prepare("DELETE FROM mcp_servers").run();
  });

  afterEach(() => {
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", undefined);
  });

  it("loads the caller's own rows and none of another tenant's", async () => {
    await seedServerRow(TENANT, "mine", "stdio", null);
    await seedServerRow("some-other-tenant", "theirs", "stdio", null);
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", "1");

    const host = await resolveUpstreams(env as McpEnv, inMemoryPorts(), TENANT);
    expect(host.getServer("mine")).toBeDefined();
    // The control that makes the line above mean something: a row that exists
    // in the SAME table and is invisible purely because of the tenant filter.
    expect(host.getServer("theirs")).toBeUndefined();
  });

  it("loads NO catalog for a credential that names no tenant", async () => {
    await seedServerRow(TENANT, "mine", "stdio", null);
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", "1");

    const ports = inMemoryPorts();
    // An unattributed credential (or a platform operator) must not be handed
    // some other tenant's upstreams; it keeps the bundle's own host.
    expect(await resolveUpstreams(env as McpEnv, ports, undefined)).toBe(ports.upstreams);
    expect(upstreamCatalogTenant(tenantAuth({ organizationId: undefined }))).toBeUndefined();
    expect(upstreamCatalogTenant(tenantAuth())).toBe(TENANT);
  });

  it("keeps the in-memory host when the durable path is not bound", async () => {
    const ports = inMemoryPorts();
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", undefined);
    expect(durableUpstreamsBound(env as McpEnv)).toBe(false);
    expect(await resolveUpstreams(env as McpEnv, ports, TENANT)).toBe(ports.upstreams);
  });
});
