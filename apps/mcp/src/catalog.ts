/**
 * MCP admin-document decoding.
 *
 * Runtime catalog reads validate tenant documents through
 * `src/durable.ts`; this module only owns the document-row loader used by that
 * composition.
 */
import {
  ADMIN_AUTH_TYPES,
  ADMIN_TRANSPORTS,
  DEFAULT_UPSTREAM_TIMEOUT_MS,
  decodeTenantMcpServerDocument,
} from "@ferrogate/storage";
import type { McpServerConfig } from "./ports.js";

/** The resource kind written by `apps/control-plane`'s MCP admin routes. */
export const MCP_SERVER_COLLECTION = "mcp-servers";

export { ADMIN_AUTH_TYPES, ADMIN_TRANSPORTS, DEFAULT_UPSTREAM_TIMEOUT_MS };

export function decodeServerDocument(document: unknown): McpServerConfig | undefined {
  return decodeTenantMcpServerDocument(document) as McpServerConfig | undefined;
}
