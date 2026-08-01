/**
 * Contract group `admin_mcp_server` (6 operations) — CRUD over
 * `/admin/v1/mcp-servers`.
 *
 * Keyed by `{name}`, not `{id}`: the contract's item path is
 * `/admin/v1/mcp-servers/{name}` and the MCP server's name is its identity
 * across the tool namespace. `idField: "name"` makes the create body's `name`
 * the store key so `POST` then `GET /{name}` round-trips.
 *
 * ## The former `PORT-TODO(inventory-edge-control §MCP "server catalog")` — CLOSED
 *
 * This was the OTHER HALF of the marker on `apps/mcp/src/durable.ts`'s
 * `loadServerCatalog`. These six operations store a `control_plane_resources`
 * document and nothing else; `apps/mcp` resolved a tenant's upstreams from a
 * TYPED `mcp_servers` table that **nothing in this repo wrote**, so a server
 * created here round-tripped through this CRUD surface perfectly while the
 * deployed MCP tool plane served zero tools.
 *
 * `apps/mcp/src/catalog.ts` now READS these documents out of the control
 * database — the same database that app already binds as `env.DB` — so a
 * `POST /admin/v1/mcp-servers` here becomes an upstream there. The reader owns
 * the bridge (it is the side that has to be fail-closed), and
 * `apps/mcp/test/server-catalog.test.ts` is the mount gate: deleting the merge
 * turns it red.
 *
 * ## Two things this file's SCHEMA still under-declares, deliberately
 *
 *  * **Vocabulary.** {@link mcpServerSchema} accepts `http | sse | stdio` while
 *    `apps/mcp`'s `McpTransport` is `streamable_http | sse | stdio`, and that
 *    app's `decodeServerRow` REFUSES an unrecognized transport rather than
 *    guessing. The bridge maps `http → streamable_http` by an EXPLICIT table
 *    entry (`ADMIN_TRANSPORTS`), never a default. The enum is left as-is here
 *    because it is the vocabulary an operator already writes against; changing
 *    it would break stored documents to move a mapping that exists anyway.
 *  * **The full config surface.** A working upstream also reads `auth_type`,
 *    the deny-by-default `tools_to_execute` / `tools_to_auto_execute`
 *    allowlists, `timeout_ms`, `headers`, `signed_jwt_audience` and (for
 *    per-user identity) `oauth`. The base `adminRecordSchema` is
 *    `passthrough()`, so an operator sends them today and they are stored and
 *    now READ. Declaring each one here is the same blocked-on-`@ferrogate/schemas`
 *    work the kept marker in `routes/resource.ts` records: the authority for a
 *    per-resource mutation schema belongs in that package, not hand-written into
 *    sixty route files. Until then the reader validates — an undecodable
 *    document is skipped rather than becoming a mis-configured upstream.
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
