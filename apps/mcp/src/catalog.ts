/**
 * MCP admin-document decoding.
 *
 * The control plane uses the same pure decoder before writing a tenant's
 * `mcp_servers` row. Runtime catalog reads consume object-local rows through
 * `src/durable.ts`; this module only owns the document-row loader used by that
 * composition.
 */
import {
  ADMIN_AUTH_TYPES,
  ADMIN_TRANSPORTS,
  DEFAULT_UPSTREAM_TIMEOUT_MS,
  decodeTenantMcpServerDocument,
} from "@ferrogate/storage";
import type { TenantDatabaseRouter } from "@ferrogate/storage";
import { RESOURCE_TABLE, TENANT_RESOURCE_TABLE } from "./approvals.js";
import type { McpServerConfig } from "./ports.js";

/** The resource kind written by `apps/control-plane`'s MCP admin routes. */
export const MCP_SERVER_COLLECTION = "mcp-servers";

export { ADMIN_AUTH_TYPES, ADMIN_TRANSPORTS, DEFAULT_UPSTREAM_TIMEOUT_MS };

export function decodeServerDocument(document: unknown): McpServerConfig | undefined {
  return decodeTenantMcpServerDocument(document) as McpServerConfig | undefined;
}

/**
 * Read one tenant's admin MCP documents from the object-local resource table.
 *
 * The control-table query is retained only for deployments/tests that have no
 * tenant router. Once a router is supplied, object storage is authoritative:
 * an object read failure returns no admin rows instead of falling back to the
 * control table.
 */
export async function loadAdminServerCatalog(
  db: D1Database,
  tenantId: string,
  router?: TenantDatabaseRouter,
): Promise<McpServerConfig[]> {
  const decodeRows = (
    rows: readonly { document_json: string }[],
    expectedTenantId?: string,
  ): McpServerConfig[] => {
    const configs: McpServerConfig[] = [];
    for (const row of rows) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(row.document_json);
      } catch {
        continue;
      }
      if (
        expectedTenantId !== undefined &&
        (typeof parsed !== "object" ||
          parsed === null ||
          Array.isArray(parsed) ||
          (parsed as Record<string, unknown>).tenant_id !== expectedTenantId)
      ) {
        continue;
      }
      const config = decodeServerDocument(parsed);
      if (config !== undefined) configs.push(config);
    }
    return configs;
  };

  if (router !== undefined && tenantId.trim() !== "") {
    try {
      const handle = await router.forTenant(tenantId);
      const rows = await handle.db
        .prepare(
          `SELECT document_json FROM ${TENANT_RESOURCE_TABLE}
             WHERE resource_kind = ?
             ORDER BY resource_id`,
        )
        .bind(MCP_SERVER_COLLECTION)
        .all<{ document_json: string }>();
      return decodeRows(rows.results, tenantId);
    } catch (error) {
      console.warn("mcp: tenant server catalog unreadable; serving no admin rows", error);
      return [];
    }
  }

  let rows: { results: Array<{ document_json: string }> };
  try {
    rows = await db
      .prepare(
        `SELECT document_json FROM ${RESOURCE_TABLE}
           WHERE resource_kind = ?
             AND json_extract(document_json, '$.tenant_id') = ?
           ORDER BY resource_id`,
      )
      .bind(MCP_SERVER_COLLECTION, tenantId)
      .all<{ document_json: string }>();
  } catch (error) {
    console.warn("mcp: admin server catalog unreadable; serving no admin rows", error);
    return [];
  }
  return decodeRows(rows.results, tenantId);
}
