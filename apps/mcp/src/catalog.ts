/**
 * MCP admin-document decoding.
 *
 * The control plane uses the same pure decoder before writing a tenant's
 * `mcp_servers` row. Runtime catalog reads never open the control database;
 * they consume the object-local row through `src/durable.ts`.
 */
import {
  ADMIN_AUTH_TYPES,
  ADMIN_TRANSPORTS,
  DEFAULT_UPSTREAM_TIMEOUT_MS,
  decodeTenantMcpServerDocument,
} from "@ferrogate/storage";
import type { McpServerConfig } from "./ports.js";

export { ADMIN_AUTH_TYPES, ADMIN_TRANSPORTS, DEFAULT_UPSTREAM_TIMEOUT_MS };

export function decodeServerDocument(document: unknown): McpServerConfig | undefined {
  return decodeTenantMcpServerDocument(document) as McpServerConfig | undefined;
}
