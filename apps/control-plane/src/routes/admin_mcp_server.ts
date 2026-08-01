/**
 * Contract group `admin_mcp_server` (6 operations) — CRUD over
 * `/admin/v1/mcp-servers`.
 *
 * Keyed by `{name}`, not `{id}`: the contract's item path is
 * `/admin/v1/mcp-servers/{name}` and the MCP server's name is its identity
 * across the tool namespace. `idField: "name"` makes the create body's `name`
 * the store key so `POST` then `GET /{name}` round-trips.
 *
 * PORT-TODO(inventory-edge-control §MCP "server catalog") — the OTHER HALF of
 * the marker on `apps/mcp/src/durable.ts`'s `loadServerCatalog`, recorded here
 * too because this is the surface an operator actually calls and neither file
 * alone tells the whole story.
 *
 * These six operations store a `control_plane_resources` document and nothing
 * else. `apps/mcp` resolves a tenant's upstreams from a TYPED `mcp_servers`
 * table in the same CONTROL database, and **nothing in this repo writes that
 * table**, so a server created here never reaches the MCP host: the document
 * round-trips through this CRUD surface perfectly while the deployed MCP tool
 * plane serves zero tools. Fail-CLOSED (the empty catalog denies), and pinned
 * from the reader's side by `apps/mcp/test/server-catalog-gap.test.ts`.
 *
 * Two things the closing change must decide, and this file is where the first
 * one bites:
 *
 *  * **Vocabulary.** {@link mcpServerSchema} accepts `http | sse | stdio` while
 *    `apps/mcp`'s `McpTransport` is `streamable_http | sse | stdio`, and that
 *    app's `decodeServerRow` REFUSES an unrecognized transport rather than
 *    guessing. So `http` must be mapped explicitly by whoever bridges the two.
 *  * **The full config surface.** A working upstream also needs `auth_type`,
 *    the deny-by-default `tools_to_execute` / `tools_to_auto_execute`
 *    allowlists, `timeout_ms` and (for per-user identity) `oauth`. The base
 *    `adminRecordSchema` is `passthrough()`, so an operator CAN send them today
 *    and they are stored — they are simply not declared here and not read by
 *    anything.
 */
import { z } from "zod";
import { type GroupModule, adminRecordSchema, crudGroup } from "./resource.js";

export const mcpServerSchema = adminRecordSchema.extend({
  name: z.string().trim().min(1),
  url: z.string().url().optional(),
  transport: z.enum(["http", "sse", "stdio"]).optional(),
  enabled: z.boolean().optional(),
});

export const adminMcpServerRoutes: GroupModule = crudGroup("admin_mcp_server", [
  { segment: "mcp-servers", object: "mcp_server", idField: "name", body: mcpServerSchema },
]);
