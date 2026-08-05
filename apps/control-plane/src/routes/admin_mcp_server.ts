/**
 * Contract group `admin_mcp_server` (6 operations) — CRUD over
 * `/admin/v1/mcp-servers`.
 *
 * Keyed by `{name}`, not `{id}`: the contract's item path is
 * `/admin/v1/mcp-servers/{name}` and the MCP server's name is its identity
 * across the tool namespace. `idField: "name"` makes the create body's `name`
 * the store key so `POST` then `GET /{name}` round-trips.
 *
 * The control document remains lossless and auditable, while the tenant
 * object's `mcp_servers` row is the runtime authority. Mutations project the
 * decoded document into that object, and tenant-scoped reads run the bounded
 * legacy backfill before serving the control document. `apps/mcp` never opens
 * this Worker's `DB` for its catalog.
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
import {
  ensureTenantMcpServerCatalogBackfill,
  removeMcpServerControlProjection,
  projectMcpServer,
  unprojectMcpServer,
} from "../store/mcp_server_catalog.js";
import {
  type CollectionSpec,
  type GroupModule,
  type Handler,
  adminRecordSchema,
  crudGroup,
  depsOf,
  listHandler,
  readHandler,
  resolveSpec,
  scopeOf,
} from "./resource.js";

export const mcpServerSchema = adminRecordSchema.extend({
  name: z.string().trim().min(1),
  url: z.string().url().optional(),
  transport: z.enum(["http", "sse", "stdio"]).optional(),
  enabled: z.boolean().optional(),
});

/** PATCH merges fields and keeps the natural-key resource id structural. */
export const mcpServerPatchSchema = mcpServerSchema.partial();

const mcpServerSpec: CollectionSpec = {
  segment: "mcp-servers",
  object: "mcp_server",
  idField: "name",
  body: mcpServerSchema,
  patch: mcpServerPatchSchema,
  tenantProject: projectMcpServer,
  tenantUnproject: unprojectMcpServer,
  tenantUnprojectAfter: removeMcpServerControlProjection,
};

const resolvedMcpServerSpec = resolveSpec(mcpServerSpec);

async function backfillTenantRead(c: Parameters<Handler>[0]): Promise<void> {
  const scope = scopeOf(c);
  if (scope.kind === "tenant") {
    await ensureTenantMcpServerCatalogBackfill(depsOf(c), scope.tenantId);
  }
}

const readOverrides: Readonly<Record<string, Handler>> = {
  listAdminMcpServers: async (c) => {
    await backfillTenantRead(c);
    return listHandler(resolvedMcpServerSpec)(c);
  },
  getAdminMcpServer: async (c) => {
    await backfillTenantRead(c);
    return readHandler(resolvedMcpServerSpec, "name")(c);
  },
};

export const adminMcpServerRoutes: GroupModule = crudGroup(
  "admin_mcp_server",
  [mcpServerSpec],
  readOverrides,
);
