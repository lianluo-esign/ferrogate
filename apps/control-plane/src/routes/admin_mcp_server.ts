/**
 * Contract group `admin_mcp_server` (6 operations) — CRUD over
 * `/admin/v1/mcp-servers`.
 *
 * Keyed by `{name}`, not `{id}`: the contract's item path is
 * `/admin/v1/mcp-servers/{name}` and the MCP server's name is its identity
 * across the tool namespace. `idField: "name"` makes the create body's `name`
 * the store key so `POST` then `GET /{name}` round-trips.
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
