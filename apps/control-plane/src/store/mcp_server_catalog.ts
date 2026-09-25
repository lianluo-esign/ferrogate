/** Tenant-owned MCP configuration with a minimal platform id-to-tenant directory.
 * No control document is used to backfill missing tenant configuration. */
import {
  type TenantDatabaseRouter,
  type TenantMcpServerConfig,
  decodeTenantMcpServerDocument,
} from "@ferrogate/storage";
import { HttpError } from "../middleware/errors.js";
import type { ControlPlaneDeps, StoreRecord } from "../ports.js";
import { tenantDatabaseFor } from "./tenancy.js";

function tenantIdOf(record: StoreRecord): string | null {
  if (typeof record.tenant_id !== "string") return null;
  const tenantId = record.tenant_id.trim();
  return tenantId === "" ? null : tenantId;
}

function resourceName(record: StoreRecord): string {
  if (typeof record.id === "string" && record.id.trim() !== "") return record.id.trim();
  if (typeof record.name === "string" && record.name.trim() !== "") return record.name.trim();
  return "";
}

function catalogValues(tenantId: string, config: TenantMcpServerConfig): readonly unknown[] {
  return [
    tenantId,
    config.name,
    config.transport,
    config.url ?? null,
    config.authType,
    JSON.stringify(config.toolsToExecute),
    JSON.stringify(config.toolsToAutoExecute),
    config.toolsToExclude === undefined ? null : JSON.stringify(config.toolsToExclude),
    config.headers === undefined ? null : JSON.stringify(config.headers),
    config.oauth === undefined ? null : JSON.stringify(config.oauth),
    config.signedJwtAudience ?? null,
    config.timeoutMs,
  ];
}

function insertCatalogStatement(
  db: D1Database,
  tenantId: string,
  config: TenantMcpServerConfig,
): D1PreparedStatement {
  const values = catalogValues(tenantId, config);
  return db
    .prepare(
      `INSERT INTO mcp_servers
           (tenant_id, name, transport, url, auth_type, tools_to_execute,
            tools_to_auto_execute, tools_to_exclude, headers, oauth,
            signed_jwt_audience, timeout_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (tenant_id, name) DO UPDATE SET
           transport = excluded.transport,
           url = excluded.url,
           auth_type = excluded.auth_type,
           tools_to_execute = excluded.tools_to_execute,
           tools_to_auto_execute = excluded.tools_to_auto_execute,
           tools_to_exclude = excluded.tools_to_exclude,
           headers = excluded.headers,
           oauth = excluded.oauth,
           signed_jwt_audience = excluded.signed_jwt_audience,
           timeout_ms = excluded.timeout_ms`,
    )
    .bind(...values);
}

async function catalogDatabaseFor(deps: ControlPlaneDeps, tenantId: string): Promise<D1Database> {
  const router: TenantDatabaseRouter = deps.tenantStorage ?? deps.tenantDatabases;
  const handle = await tenantDatabaseFor(router, tenantId);
  if (handle === null || handle.source !== "durable_object") {
    throw new HttpError(
      503,
      "mcp_catalog_unavailable",
      `tenant ${tenantId} has no reachable authoritative TenantDataObject MCP catalog`,
    );
  }
  return handle.db;
}

/**
 * Keep only an id → tenant directory for platform-operator
 * lookup. The tenant object remains authoritative; this row is only the
 * directory that lets an operator address a newly-created object resource by
 * its id before the tenant appears in the roster fan-out.
 */
async function upsertControlDirectory(
  controlDb: D1Database,
  record: StoreRecord,
  nowUnix: number,
): Promise<void> {
  await controlDb
    .prepare(
      `INSERT INTO control_plane_resources
         (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
       VALUES ('mcp-servers', ?, ?, 1, ?, ?)
       ON CONFLICT (resource_kind, resource_id) DO UPDATE SET
         document_json = excluded.document_json,
         revision = control_plane_resources.revision + 1,
         updated_at_unix = excluded.updated_at_unix
       WHERE control_plane_resources.document_json <> excluded.document_json`,
    )
    .bind(
      record.id,
      JSON.stringify({ id: record.id, tenant_id: record.tenant_id }),
      nowUnix,
      nowUnix,
    )
    .run();
}

async function removeControlProjection(controlDb: D1Database, id: string): Promise<void> {
  await controlDb
    .prepare("DELETE FROM control_plane_resources WHERE resource_kind = ? AND resource_id = ?")
    .bind("mcp-servers", id)
    .run();
}

/** Remove the operator lookup row after the tenant object's document is gone. */
export async function removeMcpServerControlProjection(
  deps: ControlPlaneDeps,
  id: string,
  _record: StoreRecord,
): Promise<void> {
  if (deps.controlDatabase === null) return;
  try {
    await removeControlProjection(deps.controlDatabase, id);
  } catch (error) {
    // The tenant object is authoritative and has already been deleted. A
    // stale directory row is harmless to runtime reads and is repaired by the
    // next platform lookup that finds no object record.
    console.warn("control-plane: MCP compatibility projection cleanup failed", {
      id,
      error,
    });
  }
}

/** Project a committed admin MCP document into the tenant object. */
export async function projectMcpServer(
  deps: ControlPlaneDeps,
  record: StoreRecord,
  nowUnix: number,
): Promise<void> {
  if (deps.controlDatabase === null) return;
  const tenantId = tenantIdOf(record);
  if (tenantId === null) return;

  const tenantDb = await catalogDatabaseFor(deps, tenantId);
  const schema = await tenantDb
    .prepare("SELECT type FROM sqlite_master WHERE name='mcp_servers'")
    .first<{ type: string }>();
  if (schema?.type === "view") {
    await upsertControlDirectory(deps.controlDatabase, record, nowUnix);
    return;
  }
  const config = decodeTenantMcpServerDocument(record);
  const oldName = resourceName(record);
  const statements: D1PreparedStatement[] = [];

  if (config === undefined) {
    if (oldName !== "") {
      statements.push(
        tenantDb
          .prepare("DELETE FROM mcp_servers WHERE tenant_id = ? AND name = ?")
          .bind(tenantId, oldName),
      );
    }
  } else {
    // Natural-key PATCHes retain the control resource id. Remove the old name
    // in the same object transaction if an older document changed it.
    if (oldName !== "" && oldName !== config.name) {
      statements.push(
        tenantDb
          .prepare("DELETE FROM mcp_servers WHERE tenant_id = ? AND name = ?")
          .bind(tenantId, oldName),
      );
    }
    statements.push(insertCatalogStatement(tenantDb, tenantId, config));
  }
  await tenantDb.batch(statements);

  await upsertControlDirectory(deps.controlDatabase, record, nowUnix);
}

/** Remove the tenant authority row before its control document is deleted. */
export async function unprojectMcpServer(
  deps: ControlPlaneDeps,
  id: string,
  record: StoreRecord,
): Promise<void> {
  if (deps.controlDatabase === null) return;
  const tenantId = tenantIdOf(record);
  if (tenantId === null) return;
  const tenantDb = await catalogDatabaseFor(deps, tenantId);

  const schema = await tenantDb
    .prepare("SELECT type FROM sqlite_master WHERE name='mcp_servers'")
    .first<{ type: string }>();
  if (schema?.type === "view") return;
  const names = new Set<string>([id.trim(), resourceName(record)]);
  const statements = [...names]
    .filter((name) => name !== "")
    .map((name) =>
      tenantDb
        .prepare("DELETE FROM mcp_servers WHERE tenant_id = ? AND name = ?")
        .bind(tenantId, name),
    );
  if (statements.length > 0) await tenantDb.batch(statements);
}
