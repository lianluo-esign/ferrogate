/**
 * The durable MCP upstream catalog, and the OPERATOR surface that feeds it.
 *
 * This file was `server-catalog-gap.test.ts`, and it characterized a gap:
 * `/admin/v1/mcp-servers` used to write only a control-plane document while
 * `apps/mcp` read a typed table nobody wrote. The cutover now projects valid
 * documents into each tenant object and the MCP reader uses only that object.
 * This file is the MOUNT GATE for the object-backed catalog.
 *
 * Four claims are held here.
 *
 *  1. **The mount.** A projected `/admin/v1/mcp-servers` document BECOMES an
 *     upstream on the durable host through the tenant object.
 *  2. **It is still fail-CLOSED.** No document, or an undecodable one, leaves an
 *     EMPTY catalog that refuses; it never falls back to the in-memory dev host
 *     and never widens to another tenant's rows.
 *  3. **Tenant scope.** Another tenant's document, and a PLATFORM-scoped
 *     document naming no tenant, are both invisible.
 *  4. **The vocabulary drift is still fail-closed at the typed reader.**
 *     `decodeServerRow` REFUSES the admin enum's `http` rather than guessing —
 *     which is exactly why `src/catalog.ts` has to map it by an explicit table
 *     entry. That assertion survives the close and is the reason it must.
 */
import { SELF, type applyD1Migrations, env } from "cloudflare:test";
import { DurableObjectTenantDatabaseRouter } from "@ferrogate/storage";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { RESOURCE_TABLE, TENANT_RESOURCE_TABLE } from "../src/approvals.js";
import {
  ADMIN_TRANSPORTS,
  DEFAULT_UPSTREAM_TIMEOUT_MS,
  decodeServerDocument,
} from "../src/catalog.js";
import { decodeServerRow, loadServerCatalog } from "../src/durable.js";
import type { McpEnv } from "../src/ports.js";
import { inMemoryPorts } from "../src/ports.js";
import { resolveUpstreams, withTenantUpstreams } from "../src/upstreams.js";
import { READ_KEY, TENANT, rpcRequest, seedFixture, setMcpEnvVar, tenantAuth } from "./fixtures.js";
import { clearMcpIdentityTables, tenantDataNamespace, tenantDatabase } from "./tenant-storage.js";

const TENANT_DATA = tenantDataNamespace(env);
const DB = env.DB as unknown as D1Database;
const TENANT_ROUTER = new DurableObjectTenantDatabaseRouter(TENANT_DATA, DB);

async function loadCatalog(tenantId: string) {
  return loadServerCatalog(TENANT_DATA, tenantId, DB, TENANT_ROUTER);
}

async function tenantDb(tenantId: string): Promise<D1Database> {
  const namespace = (
    env as unknown as {
      TENANT_DATA?: import("@ferrogate/storage/durable-objects").TenantDataNamespace;
    }
  ).TENANT_DATA;
  if (namespace === undefined) throw new Error("server catalog test expects TENANT_DATA");
  return (await new DurableObjectTenantDatabaseRouter(namespace, DB).forTenant(tenantId)).db;
}

interface ControlSchemaBindings {
  readonly DB: D1Database;
  readonly TEST_CONTROL_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
}

// The CONTROL migrations own `control_plane_resources` — the table the admin
// surface writes into. Applying the DEPLOYED migration (not a fixture copy) is
// what makes "the document is written the way apps/control-plane writes it"
// mean something.
beforeAll(async () => {
  const bindings = env as unknown as ControlSchemaBindings;
  // Zero-D1 S5 (#881): the ControlDataObject self-applies its schema on first
  // wake; there is no control D1 to migrate here.
});

/**
 * The row `apps/control-plane` writes for `POST /admin/v1/mcp-servers`.
 *
 * The transport is the ADMIN schema's `http` (`routes/admin_mcp_server.ts`),
 * not this app's `streamable_http`: bridging that is the point.
 */
async function seedAdminMcpServerDocument(
  tenantId: string | null,
  name: string,
  overrides: Record<string, unknown> = {},
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const document = JSON.stringify({
    id: name,
    name,
    tenant_id: tenantId,
    transport: "http",
    url: "https://upstream.test/mcp",
    enabled: true,
    tools_to_execute: ["echo"],
    ...overrides,
  });
  await DB.prepare(
    `INSERT OR REPLACE INTO ${RESOURCE_TABLE}
       (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
     VALUES ('mcp-servers', ?, ?, 1, ?, ?)`,
  )
    .bind(name, document, now, now)
    .run();
  if (tenantId !== null) {
    await (await tenantDb(tenantId))
      .prepare(
        `INSERT OR REPLACE INTO ${TENANT_RESOURCE_TABLE}
           (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
         VALUES (?, ?, ?, 1, ?, ?)`,
      )
      .bind("mcp-servers", name, document, now, now)
      .run();
  }
}

async function clearAdminDocuments(): Promise<void> {
  await DB.prepare(`DELETE FROM ${RESOURCE_TABLE} WHERE resource_kind = 'mcp-servers'`).run();
  await Promise.all(
    [TENANT, "tenant-other"].map(async (tenantId) => {
      await (await tenantDb(tenantId))
        .prepare(`DELETE FROM ${TENANT_RESOURCE_TABLE} WHERE resource_kind = 'mcp-servers'`)
        .run();
    }),
  );
}

/** One typed catalog row, the native shape. */
async function seedTypedServerRow(tenantId: string, name: string): Promise<void> {
  await tenantDatabase(TENANT_DATA, tenantId)
    .prepare(
      `INSERT OR REPLACE INTO mcp_servers
       (tenant_id, name, transport, url, auth_type, tools_to_execute,
        tools_to_auto_execute, headers, oauth, signed_jwt_audience, timeout_ms)
     VALUES (?, ?, 'streamable_http', 'https://upstream.test/mcp', 'none', ?, ?, NULL, NULL, NULL, 5000)`,
    )
    .bind(tenantId, name, JSON.stringify(["echo"]), JSON.stringify([]))
    .run();
}

async function toolNames(): Promise<string[]> {
  const res = await SELF.fetch(
    rpcRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" }, { key: READ_KEY }),
  );
  expect(res.status).toBe(200);
  const body = (await res.json()) as { result: { tools: Array<{ name: string }> } };
  return body.result.tools.map((tool) => tool.name);
}

describe("MOUNT: an /admin/v1/mcp-servers document feeds the durable catalog", () => {
  beforeEach(async () => {
    seedFixture();
    await clearMcpIdentityTables(TENANT_DATA, TENANT);
    await clearAdminDocuments();
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", "1");
  });

  afterEach(() => {
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", undefined);
  });

  it("becomes an upstream on the host the request path actually resolves", async () => {
    await seedAdminMcpServerDocument(TENANT, "admincfg");
    // CONTROL, in the same call: the typed row keeps working, so this proves the
    // document was ADDED rather than the typed leg being replaced.
    await seedTypedServerRow(TENANT, "typed");

    const host = await resolveUpstreams(env as McpEnv, inMemoryPorts(), TENANT);
    expect(host.getServer("typed")).toBeDefined();
    // The operator configured a server through the documented admin API and the
    // MCP host can now see it. Deleting the merge loop in `loadServerCatalog`
    // turns exactly this line red.
    expect(host.getServer("admincfg")).toMatchObject({
      name: "admincfg",
      // The admin enum's `http`, mapped explicitly.
      transport: "streamable_http",
      url: "https://upstream.test/mcp",
      authType: "none",
      toolsToExecute: ["echo"],
      // Absent in the document ⇒ EMPTY, i.e. nothing runs without an approval.
      toolsToAutoExecute: [],
      timeoutMs: DEFAULT_UPSTREAM_TIMEOUT_MS,
    });
  });

  it("reaches the bundle the REQUEST PATH carries, not just the loader", async () => {
    // `withTenantUpstreams` is the exact function `routes/ingress.ts` calls on
    // both MCP entry points (lines 83 and 180) after authenticating, so this
    // drives the composed seam — `upstreamCatalogTenant` → `resolveUpstreams` →
    // `loadServerCatalog` → `loadAdminServerCatalog` — end to end.
    //
    // It is driven directly rather than over `SELF` because an upstream tool
    // only appears in `tools/list` after a real HTTP connect to the upstream,
    // and this suite is offline by rule: there is no network-free way to see an
    // upstream's TOOLS through the deployed endpoint. What the `SELF` tests
    // below cover instead is the fail-closed half, which needs no connect.
    await seedAdminMcpServerDocument(TENANT, "admincfg");
    const tenantPorts = await withTenantUpstreams(env as McpEnv, inMemoryPorts(), tenantAuth());
    expect(tenantPorts.upstreams.getServer("admincfg")).toBeDefined();
    // The bundle was REPLACED, not passed through: the in-memory dev host's
    // server must not still be the one the request path would dispatch on.
    expect(tenantPorts.upstreams.getServer("srv")).toBeUndefined();
  });

  it("a typed row WINS over a document of the same name", async () => {
    await seedTypedServerRow(TENANT, "dup");
    await seedAdminMcpServerDocument(TENANT, "dup", { url: "https://document.test/mcp" });
    // A second, non-colliding document is the CONTROL: it proves the admin
    // surface was read at all, so "one `dup`" is de-duplication rather than the
    // documents being invisible.
    await seedAdminMcpServerDocument(TENANT, "docOnly");
    const configs = await loadCatalog(TENANT);
    expect(configs.map((config) => config.name).sort()).toEqual(["docOnly", "dup"]);
    expect(configs.find((config) => config.name === "dup")?.url).toBe("https://upstream.test/mcp");
  });
});

describe("the catalog stays fail-CLOSED after the close", () => {
  beforeEach(async () => {
    seedFixture();
    await clearMcpIdentityTables(TENANT_DATA, TENANT);
    await clearAdminDocuments();
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", "1");
  });

  afterEach(() => {
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", undefined);
  });

  it("an empty catalog REFUSES a call rather than falling through to another host", async () => {
    const res = await SELF.fetch(
      rpcRequest(
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "srv-echo" } },
        { key: READ_KEY },
      ),
    );
    // A permissive "fix" for the empty catalog — any global default host, any
    // cross-tenant widening — turns this red.
    expect(res.status).not.toBe(200);
  });

  it("leaves tools/list empty of upstream tools when no server is configured", async () => {
    const names = await toolNames();
    expect(names).not.toContain("srv-echo");
    // Builtins survive, so "empty" is the catalog and not a collapsed handler.
    expect(names).toContain("builtin.fetch_asset");
  });

  it("does NOT serve another tenant's document", async () => {
    await seedAdminMcpServerDocument("tenant-other", "neighbour");
    const host = await resolveUpstreams(env as McpEnv, inMemoryPorts(), TENANT);
    expect(host.getServer("neighbour")).toBeUndefined();
    expect(await loadCatalog("tenant-other")).toHaveLength(1);
  });

  it("does NOT serve a PLATFORM-scoped document (null tenant_id) to a tenant", async () => {
    await seedAdminMcpServerDocument(null, "platformwide");
    const host = await resolveUpstreams(env as McpEnv, inMemoryPorts(), TENANT);
    // Deny-by-default: a null tenant column must not hand every tenant an
    // upstream. This is the scope decision, in executable form.
    expect(host.getServer("platformwide")).toBeUndefined();
  });

  it("a DISABLED document is not an upstream", async () => {
    // The `on` document is the CONTROL: without it "length 0" would also be the
    // answer when the admin surface is not read at all, and this test would pass
    // on the very gap it is meant to guard.
    await seedAdminMcpServerDocument(TENANT, "off", { enabled: false });
    await seedAdminMcpServerDocument(TENANT, "on");
    expect((await loadCatalog(TENANT)).map((config) => config.name)).toEqual(["on"]);
  });

  it("an unknown transport or auth_type REFUSES the document", async () => {
    await seedAdminMcpServerDocument(TENANT, "badtransport", { transport: "grpc" });
    await seedAdminMcpServerDocument(TENANT, "badauth", { auth_type: "mtls" });
    await seedAdminMcpServerDocument(TENANT, "good");
    expect((await loadCatalog(TENANT)).map((config) => config.name)).toEqual(["good"]);
  });
});

describe("decodeServerDocument — the fail-closed rules, directly", () => {
  const base = { name: "srv", transport: "http", url: "https://upstream.test/mcp" };

  it("maps the admin enum's `http` to streamable_http by an EXPLICIT entry", () => {
    expect(ADMIN_TRANSPORTS.http).toBe("streamable_http");
    expect(decodeServerDocument(base)).toMatchObject({ transport: "streamable_http" });
  });

  it("never coerces stdio to a network transport", () => {
    // The platform limit (Workers cannot spawn a process) is reported at
    // DISPATCH by `transport.ts`, not by silently rewriting the config.
    expect(decodeServerDocument({ ...base, transport: "stdio" })).toMatchObject({
      transport: "stdio",
    });
  });

  it("refuses an unrecognized transport instead of defaulting to HTTP", () => {
    expect(decodeServerDocument({ ...base, transport: "grpc" })).toBeUndefined();
    expect(decodeServerDocument({ ...base, transport: 7 })).toBeUndefined();
    expect(decodeServerDocument({ name: "srv" })).toBeUndefined();
  });

  it("refuses an unrecognized auth_type instead of downgrading it to none", () => {
    expect(decodeServerDocument({ ...base, auth_type: "mtls" })).toBeUndefined();
    // The Rust `#[serde(alias = "headers")]` alias is honoured.
    expect(decodeServerDocument({ ...base, auth_type: "headers" })).toMatchObject({
      authType: "shared_headers",
    });
  });

  it("treats an absent allowlist as EMPTY, never as all tools", () => {
    expect(decodeServerDocument(base)).toMatchObject({
      toolsToExecute: [],
      toolsToAutoExecute: [],
    });
  });

  it("refuses a malformed allowlist rather than filtering it down", () => {
    // Dropping the bad entries would silently change what the allowlist permits.
    expect(decodeServerDocument({ ...base, tools_to_execute: "echo" })).toBeUndefined();
    expect(decodeServerDocument({ ...base, tools_to_execute: ["echo", 3] })).toBeUndefined();
  });

  it("refuses a non-positive or non-numeric timeout rather than aborting every call", () => {
    expect(decodeServerDocument({ ...base, timeout_ms: 0 })).toBeUndefined();
    expect(decodeServerDocument({ ...base, timeout_ms: -1 })).toBeUndefined();
    expect(decodeServerDocument({ ...base, timeout_ms: "5000" })).toBeUndefined();
    expect(decodeServerDocument({ ...base, timeout_ms: 5000 })).toMatchObject({
      timeoutMs: 5000,
    });
  });

  it("refuses a half-configured oauth block", () => {
    expect(
      decodeServerDocument({ ...base, oauth: { issuer: "https://idp.test" } }),
    ).toBeUndefined();
    expect(
      decodeServerDocument({
        ...base,
        auth_type: "per_user_oauth",
        oauth: { issuer: "https://idp.test", client_id: "cid" },
      }),
    ).toMatchObject({
      authType: "per_user_oauth",
      oauth: {
        issuer: "https://idp.test",
        clientId: "cid",
        scopes: ["openid", "profile", "email"],
      },
    });
  });

  it("refuses a header map holding a non-string value", () => {
    expect(decodeServerDocument({ ...base, headers: { "X-A": 1 } })).toBeUndefined();
    expect(decodeServerDocument({ ...base, headers: { "X-A": "b" } })).toMatchObject({
      headers: { "X-A": "b" },
    });
  });
});

describe("the two surfaces disagree on the transport vocabulary, fail-closed", () => {
  const row = {
    name: "srv",
    url: "https://upstream.test/mcp",
    auth_type: "none",
    tools_to_execute: '["echo"]',
    tools_to_auto_execute: "[]",
    headers: null,
    oauth: null,
    signed_jwt_audience: null,
    timeout_ms: 5000,
  };

  it("REFUSES the admin enum's `http` rather than guessing streamable_http", () => {
    // `routes/admin_mcp_server.ts` offers `http | sse | stdio`; this app speaks
    // `streamable_http | sse | stdio`. That is why `src/catalog.ts` maps the two
    // deliberately — silently accepting the string HERE, in the TYPED reader,
    // would be the same class of guess that "read an unknown transport as HTTP"
    // is, and it stays refused.
    expect(decodeServerRow({ ...row, transport: "http" } as never)).toBeUndefined();
  });

  it("accepts the vocabulary this app actually speaks — the control", () => {
    expect(decodeServerRow({ ...row, transport: "streamable_http" } as never)).toMatchObject({
      transport: "streamable_http",
    });
    expect(decodeServerRow({ ...row, transport: "sse" } as never)).toMatchObject({
      transport: "sse",
    });
  });
});
