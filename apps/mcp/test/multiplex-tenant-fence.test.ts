/**
 * The CROSS-TENANT fence on the multiplexed catalogue (#687 leg 4), end to end
 * over the exported Worker.
 *
 * ## What was actually missing, and what was not
 *
 * The audit on PR #754 read `fanIn()` and `resolveTool()` taking no tenant
 * argument and `resolvePorts(env)` taking only `env`, and concluded that any
 * tenant entitled to MCP could reach every configured upstream. The FENCE is in
 * fact already structural and already on the request path, and it is worth
 * being precise about where:
 *
 *  - `src/upstreams.ts:83` `resolveUpstreams` builds a host from
 *    `loadServerCatalog(env.DB, tenantId)` — the tenant is a BOUND parameter of
 *    the `mcp_servers` read (`src/durable.ts`) and of the admin-document read
 *    (`src/catalog.ts:264`);
 *  - `src/routes/ingress.ts:94` and `:203` call `withTenantUpstreams` on BOTH
 *    ingress transports, after authentication;
 *  - so `fanIn()` needs no tenant argument precisely because the HOST is
 *    per-tenant. The population is per-tenant AT THE SOURCE, which is the shape
 *    the audit asked for; a tenant filter bolted on top of a global list is
 *    what is absent, and it is absent on purpose.
 *
 * What was genuinely missing is a proof of that fence THROUGH THE DEPLOYED
 * WORKER with two real credentials. `test/durable-upstreams.test.ts:260` proves
 * it at the `resolveUpstreams` function boundary, which cannot see whether the
 * request path calls it; the `SELF` tests there drive one tenant only, so
 * "tenant A does not see tenant B" was never executed over HTTP.
 *
 * ## Why the session descriptor is the probe
 *
 * Under the durable posture the host is `HttpMcpUpstreams`, and asking it for
 * TOOLS would require every upstream to answer a real `tools/list` over the
 * network. `listServers()` needs no network at all, and #687's unified session
 * binds exactly that list at `initialize` and reports it in the result's
 * `_meta`. So one `initialize` per credential reads the tenant's catalogue
 * straight out of D1, over the real Worker, with no upstream reachable — and it
 * ties the two legs together: a session's fan-out is per-tenant BECAUSE the
 * catalogue is.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { inMemoryPorts } from "../src/ports.js";
import { parseSseEvents } from "../src/transport.js";
import { EXEC_KEY, TENANT, rpcRequest, seedFixture, setMcpEnvVar, tenantAuth } from "./fixtures.js";
import { clearMcpIdentityTables, tenantDataNamespace, tenantDatabase } from "./tenant-storage.js";

const TENANT_DATA = tenantDataNamespace(env);

const OTHER_TENANT = "tenant-fence-b";
const OTHER_KEY = "fg_test_fence_b_key";

/** One `mcp_servers` row. `stdio` needs no network to be LISTED. */
async function seedServerRow(tenantId: string, name: string): Promise<void> {
  await tenantDatabase(TENANT_DATA, tenantId).prepare(
    `INSERT OR REPLACE INTO mcp_servers
       (tenant_id, name, transport, url, auth_type, tools_to_execute,
        tools_to_auto_execute, tools_to_exclude, headers, oauth,
        signed_jwt_audience, timeout_ms)
     VALUES (?, ?, 'stdio', NULL, 'none', ?, ?, NULL, NULL, NULL, NULL, 5000)`,
  )
    .bind(tenantId, name, JSON.stringify(["ping"]), JSON.stringify(["ping"]))
    .run();
}

/** The upstream names one credential's session binds at `initialize`. */
async function sessionUpstreams(key: string): Promise<string[] | undefined> {
  const res = await SELF.fetch(
    rpcRequest(
      { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
      { key, headers: { accept: "text/event-stream" } },
    ),
  );
  expect(res.status).toBe(200);
  const frame = parseSseEvents(await res.text())[0];
  const body = JSON.parse(frame?.data ?? "{}") as {
    result?: { _meta?: Record<string, unknown> };
  };
  const session = body.result?._meta?.["ferrogate/session"] as { upstreams?: string[] } | undefined;
  return session?.upstreams?.slice().sort();
}

beforeEach(async () => {
  seedFixture();
  inMemoryPorts().auth.register(OTHER_KEY, tenantAuth({ organizationId: OTHER_TENANT }));
  await Promise.all([
    clearMcpIdentityTables(TENANT_DATA, TENANT),
    clearMcpIdentityTables(TENANT_DATA, OTHER_TENANT),
  ]);
  await seedServerRow(TENANT, "alpha-owned-by-a");
  await seedServerRow(OTHER_TENANT, "beta-owned-by-b");
});

afterEach(() => {
  setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", undefined);
});

describe("the D1 catalogue is keyed by tenant on the deployed request path", () => {
  it("CONTROL: with the durable path off, neither row reaches either caller", async () => {
    // Without this control, "tenant A does not see beta-owned-by-b" below would
    // also pass if the D1 read were broken outright, or if `initialize` had
    // stopped reporting its fan-out.
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", undefined);
    expect(await sessionUpstreams(EXEC_KEY)).toEqual(["srv"]);
  });

  it("gives each tenant its OWN upstreams and none of the other's", async () => {
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", "1");

    const a = await sessionUpstreams(EXEC_KEY);
    const b = await sessionUpstreams(OTHER_KEY);

    // Both rows live in the SAME table, in the same database, read by the same
    // code on the same request path. The ONLY thing separating them is the
    // tenant the credential authenticated as.
    expect(a).toEqual(["alpha-owned-by-a"]);
    expect(b).toEqual(["beta-owned-by-b"]);
    expect(a).not.toContain("beta-owned-by-b");
    expect(b).not.toContain("alpha-owned-by-a");
  });

  it("refuses a tool call naming the other tenant's upstream", async () => {
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", "1");
    const res = await SELF.fetch(
      rpcRequest(
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "beta-owned-by-b-ping", arguments: {} },
        },
        { key: EXEC_KEY },
      ),
    );
    // Deny-by-default at the chokepoint: the name resolves against tenant A's
    // catalogue, which does not contain that upstream at all.
    expect(JSON.stringify(await res.json())).toContain("not allowlisted for execution");
  });

  it("refuses even when the caller names the other tenant's upstream EXPLICITLY", async () => {
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", "1");
    const res = await SELF.fetch(
      rpcRequest(
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "beta-owned-by-b-ping",
            arguments: {},
            // The multiplex selector this PR added. It NARROWS within the
            // caller's own catalogue; it can never widen it to another one.
            _meta: { "ferrogate/server": "beta-owned-by-b" },
          },
        },
        { key: EXEC_KEY },
      ),
    );
    expect(JSON.stringify(await res.json())).toContain("not allowlisted for execution");
  });

  it("keeps each tenant's client session in its own Durable Object", async () => {
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", "1");
    const opened = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
        { key: EXEC_KEY, headers: { accept: "text/event-stream" } },
      ),
    );
    const sessionId = opened.headers.get("mcp-session-id") as string;
    expect(sessionId).toBeTruthy();

    // Tenant B presents tenant A's session id. The id is half of a Durable
    // Object NAME whose other half is the tenant, so this addresses an object
    // that was never opened — unknown, not forbidden.
    const crossed = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 2, method: "tools/list" },
        { key: OTHER_KEY, headers: { "mcp-session-id": sessionId } },
      ),
    );
    expect(crossed.status).toBe(404);
    // The control: the tenant that opened it is still served.
    const own = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 3, method: "tools/list" },
        { key: EXEC_KEY, headers: { "mcp-session-id": sessionId } },
      ),
    );
    expect(own.status).toBe(200);
  });
});
