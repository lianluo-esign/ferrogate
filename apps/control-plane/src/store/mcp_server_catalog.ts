/**
 * The control-plane bridge for the tenant-owned MCP server catalog (#862).
 *
 * `control_plane_resources` remains the lossless admin document store. The
 * tenant object's `mcp_servers` table is the data-plane authority, so writes
 * project there and historical documents are copied through a resumable mark
 * stored in that same object. The object is never replaced by a flat CONTROL
 * D1 read at request time.
 */
import {
  type TenantDatabaseRouter,
  type TenantMcpServerConfig,
  decodeTenantMcpServerDocument,
} from "@ferrogate/storage";
import { HttpError } from "../middleware/errors.js";
import type { ControlPlaneDeps, StoreRecord } from "../ports.js";
import { tenantDatabaseFor } from "./tenancy.js";

/** The object-local ledger mark for the pre-#862 MCP catalog copy. */
export const MCP_SERVER_CATALOG_BACKFILL_MARK = "mcp_server_catalog_backfill_v1";

const PAGE_SIZE = 100;
const MAX_PAGES_PER_READ = 16;

interface ControlCatalogRow {
  readonly resource_id: string;
  readonly document_json: string;
}

interface BackfillMark {
  readonly state: "in_progress" | "complete";
  readonly cursor: string | null;
  readonly resources: number;
}

function parseMark(detail: string | null | undefined): BackfillMark | undefined {
  if (detail === undefined || detail === null || detail.trim() === "") return undefined;
  try {
    const value: unknown = JSON.parse(detail);
    if (typeof value !== "object" || value === null) return undefined;
    const candidate = value as Record<string, unknown>;
    if (candidate.state !== "in_progress" && candidate.state !== "complete") return undefined;
    return {
      state: candidate.state,
      cursor: typeof candidate.cursor === "string" ? candidate.cursor : null,
      resources:
        typeof candidate.resources === "number" && Number.isSafeInteger(candidate.resources)
          ? Math.max(0, candidate.resources)
          : 0,
    };
  } catch {
    return undefined;
  }
}

function markDetail(
  state: BackfillMark["state"],
  cursor: string | null,
  resources: number,
): string {
  return JSON.stringify({ version: 1, state, cursor, resources });
}

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
  guarded: boolean,
): D1PreparedStatement {
  const values = catalogValues(tenantId, config);
  if (!guarded) {
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

  return db
    .prepare(
      `INSERT OR IGNORE INTO mcp_servers
         (tenant_id, name, transport, url, auth_type, tools_to_execute,
          tools_to_auto_execute, tools_to_exclude, headers, oauth,
          signed_jwt_audience, timeout_ms)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1 FROM tenant_provisioning_marks
           WHERE tenant_id = ? AND mark = ?
             AND detail NOT LIKE '%"state":"complete"%'
        )`,
    )
    .bind(...values, tenantId, MCP_SERVER_CATALOG_BACKFILL_MARK);
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

async function readMark(db: D1Database, tenantId: string): Promise<BackfillMark | undefined> {
  const row = await db
    .prepare("SELECT detail FROM tenant_provisioning_marks WHERE tenant_id = ? AND mark = ?")
    .bind(tenantId, MCP_SERVER_CATALOG_BACKFILL_MARK)
    .first<{ detail: string | null }>();
  return parseMark(row?.detail);
}

async function controlPage(
  controlDb: D1Database,
  tenantId: string,
  cursor: string | null,
): Promise<ControlCatalogRow[]> {
  const predicate =
    cursor === null
      ? "json_extract(document_json, '$.tenant_id') = ?"
      : "json_extract(document_json, '$.tenant_id') = ? AND resource_id > ?";
  const values = cursor === null ? [tenantId, PAGE_SIZE] : [tenantId, cursor, PAGE_SIZE];
  const rows = await controlDb
    .prepare(
      `SELECT resource_id, document_json
         FROM control_plane_resources
        WHERE resource_kind = 'mcp-servers' AND ${predicate}
        ORDER BY resource_id ASC
        LIMIT ?`,
    )
    .bind(...values)
    .all<ControlCatalogRow>();
  return rows.results;
}

/**
 * Copy a tenant's legacy MCP documents into its object, bounded and resumable.
 *
 * `INSERT OR IGNORE` is intentional: a live object projection wins over a
 * stale control document. The marker and every guarded insert share one object
 * batch, so a stale concurrent backfill cannot write after another call marks
 * the tenant complete.
 */
export async function ensureTenantMcpServerCatalogBackfill(
  deps: ControlPlaneDeps,
  tenantId: string,
): Promise<void> {
  const controlDb = deps.controlDatabase;
  if (controlDb === null) return;
  const normalizedTenantId = tenantId.trim();
  if (normalizedTenantId === "") return;

  const tenantDb = await catalogDatabaseFor(deps, normalizedTenantId);
  const existing = await readMark(tenantDb, normalizedTenantId);
  if (existing?.state === "complete") return;

  let cursor = existing?.cursor ?? null;
  let resources = existing?.resources ?? 0;

  for (let pageNumber = 0; pageNumber < MAX_PAGES_PER_READ; pageNumber += 1) {
    const rows = await controlPage(controlDb, normalizedTenantId, cursor);
    const nextCursor = rows.at(-1)?.resource_id ?? cursor;
    resources += rows.length;
    const complete = rows.length < PAGE_SIZE;
    const statements: D1PreparedStatement[] = [
      tenantDb
        .prepare(
          `INSERT OR IGNORE INTO tenant_provisioning_marks
             (tenant_id, mark, detail, applied_at_unix)
           VALUES (?, ?, ?, ?)`,
        )
        .bind(
          normalizedTenantId,
          MCP_SERVER_CATALOG_BACKFILL_MARK,
          markDetail("in_progress", cursor, resources),
          Math.floor(Date.now() / 1000),
        ),
    ];

    for (const row of rows) {
      let document: unknown;
      try {
        document = JSON.parse(row.document_json);
      } catch {
        continue;
      }
      const config = decodeTenantMcpServerDocument(document);
      if (config === undefined) continue;
      statements.push(insertCatalogStatement(tenantDb, normalizedTenantId, config, true));
    }

    statements.push(
      tenantDb
        .prepare(
          `INSERT INTO tenant_provisioning_marks
             (tenant_id, mark, detail, applied_at_unix)
           VALUES (?, ?, ?, ?)
           ON CONFLICT (tenant_id, mark) DO UPDATE SET
             detail = excluded.detail,
             applied_at_unix = excluded.applied_at_unix
           WHERE tenant_provisioning_marks.detail NOT LIKE '%"state":"complete"%'`,
        )
        .bind(
          normalizedTenantId,
          MCP_SERVER_CATALOG_BACKFILL_MARK,
          markDetail(complete ? "complete" : "in_progress", nextCursor, resources),
          Math.floor(Date.now() / 1000),
        ),
    );
    await tenantDb.batch(statements);

    if (complete) return;
    cursor = nextCursor;
  }

  throw new HttpError(
    503,
    "mcp_catalog_backfill_incomplete",
    `tenant ${normalizedTenantId} MCP catalog backfill is still in progress; retry`,
  );
}

/** Project a committed admin MCP document into the tenant object. */
export async function projectMcpServer(
  deps: ControlPlaneDeps,
  record: StoreRecord,
  nowUnix: number,
): Promise<void> {
  void nowUnix;
  if (deps.controlDatabase === null) return;
  const tenantId = tenantIdOf(record);
  if (tenantId === null) return;

  const tenantDb = await catalogDatabaseFor(deps, tenantId);
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
    statements.push(insertCatalogStatement(tenantDb, tenantId, config, false));
  }
  await tenantDb.batch(statements);

  // The current projection is already authoritative. Backfill only fills rows
  // that are absent, and its marker makes this repair path one-shot per tenant.
  await ensureTenantMcpServerCatalogBackfill(deps, tenantId);
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
  await ensureTenantMcpServerCatalogBackfill(deps, tenantId);

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
