/**
 * The NEW `PORT-TODO(inventory-edge-control §MCP "server catalog")` marker on
 * `loadServerCatalog` (`src/durable.ts`), pinned.
 *
 * The finding it records: **nothing in this repo writes a `mcp_servers` row.**
 * The reader, the decoder, `resolveUpstreams` and the `MCP_SESSION` Durable
 * Object are all implemented, mounted and green — against rows the TESTS
 * insert. The one operator-facing surface for MCP upstreams is
 * `apps/control-plane`'s `/admin/v1/mcp-servers`, which writes a
 * `control_plane_resources` document of kind `mcp-servers` into the CONTROL
 * database this Worker already binds as `env.DB`, and this app does not read
 * it. So a deployed tenant's catalog is empty forever.
 *
 * Two different claims are held here.
 *
 *  1. **The gap is real and it is fail-CLOSED** — an admin document does not
 *     become an upstream, and the empty catalog denies rather than falling back
 *     to something permissive. DELETE THIS BLOCK WHEN THE MARKER IS CLOSED; it
 *     is a characterization of a gap, not a property worth keeping.
 *  2. **The vocabulary drift between the two surfaces is fail-closed too** —
 *     the admin schema's `transport: "http"` is REFUSED by `decodeServerRow`,
 *     not coerced. That assertion survives the close: it is the reason the
 *     closing change has to map the vocabulary explicitly instead of copying
 *     the document's field across.
 */
import { SELF, applyD1Migrations, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { RESOURCE_TABLE } from "../src/approvals.js";
import { decodeServerRow, ensureMcpIdentitySchema } from "../src/durable.js";
import type { McpEnv } from "../src/ports.js";
import { inMemoryPorts } from "../src/ports.js";
import { resolveUpstreams } from "../src/upstreams.js";
import { READ_KEY, TENANT, rpcRequest, seedFixture, setMcpEnvVar } from "./fixtures.js";

const DB = env.DB as unknown as D1Database;

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
  await applyD1Migrations(bindings.DB, bindings.TEST_CONTROL_D1_SCHEMA);
});

/** The row `apps/control-plane` writes for `POST /admin/v1/mcp-servers`. */
async function seedAdminMcpServerDocument(tenantId: string, name: string): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await DB.prepare(
    `INSERT OR REPLACE INTO ${RESOURCE_TABLE}
       (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
     VALUES ('mcp-servers', ?, ?, 1, ?, ?)`,
  )
    .bind(
      name,
      JSON.stringify({
        id: name,
        name,
        tenant_id: tenantId,
        // The admin schema's own enum (`routes/admin_mcp_server.ts`), which is
        // NOT this app's `McpTransport` vocabulary — see the second block.
        transport: "http",
        url: "https://upstream.test/mcp",
        enabled: true,
        tools_to_execute: ["echo"],
      }),
      now,
      now,
    )
    .run();
}

/** One typed catalog row, the shape the reader DOES understand. */
async function seedTypedServerRow(tenantId: string, name: string): Promise<void> {
  await DB.prepare(
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

describe("MARKER: no operator surface feeds the durable MCP server catalog", () => {
  beforeEach(async () => {
    seedFixture();
    await ensureMcpIdentitySchema(DB);
    await DB.prepare("DELETE FROM mcp_servers").run();
    await DB.prepare(`DELETE FROM ${RESOURCE_TABLE} WHERE resource_kind = 'mcp-servers'`).run();
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", "1");
  });

  afterEach(() => {
    setMcpEnvVar("FG_DEV_MCP_DURABLE_UPSTREAMS", undefined);
  });

  it("an /admin/v1/mcp-servers document does NOT become an upstream (the gap)", async () => {
    await seedAdminMcpServerDocument(TENANT, "admincfg");
    // CONTROL, in the same call: a TYPED row for the same tenant IS resolved,
    // so "the admin document is invisible" is the document's fault and not a
    // catalog that is broken end to end. (Tool NAMES cannot be the control:
    // listing a tool requires connecting to the upstream, and this suite makes
    // no network calls.)
    await seedTypedServerRow(TENANT, "typed");

    const host = await resolveUpstreams(env as McpEnv, inMemoryPorts(), TENANT);
    expect(host.getServer("typed")).toBeDefined();
    // The operator configured a server through the documented admin API and the
    // MCP host cannot see it. This is the marker, in executable form.
    expect(host.getServer("admincfg")).toBeUndefined();
  });

  it("leaves the deployed tools/list EMPTY of upstream tools, fail-closed", async () => {
    await seedAdminMcpServerDocument(TENANT, "admincfg");
    const names = await toolNames();
    expect(names).not.toContain("admincfg-echo");
    // Fail-CLOSED: no fall-back to the in-memory dev host, which would still be
    // advertising `srv-echo` here.
    expect(names).not.toContain("srv-echo");
    // Builtins survive, so "empty" is the catalog and not a collapsed handler.
    expect(names).toContain("builtin.fetch_asset");
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
    // `streamable_http | sse | stdio`. Whoever closes the catalog marker must
    // map the two deliberately — silently accepting the string here would be
    // the same class of guess that "read an unknown transport as HTTP" is.
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
