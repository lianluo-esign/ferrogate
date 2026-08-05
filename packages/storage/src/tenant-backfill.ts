/**
 * Pure metadata and verification primitives for the shared-tenant backfill.
 *
 * The table names, key columns, and ownership predicates in this file are a
 * static allow-list. A future copier may interpolate a table name only after
 * selecting one of these entries; it must never accept an identifier from an
 * operator request or from a database row.
 */

import type { TenantMigrationState } from "./tenant-router.js";

// ---------------------------------------------------------------------------
// Static tenant-table manifest
// ---------------------------------------------------------------------------

export const TENANT_MIGRATION_STATES = Object.freeze([
  "shared",
  "copying",
  "verifying",
  "cut",
  "done",
] as const);

export interface DirectTenantOwnership {
  readonly kind: "direct";
  readonly tenantColumn: "tenant_id" | "tenant";
  /** A static WHERE predicate for a source table aliased as `t`. */
  readonly query: string;
  readonly whereSql: string;
  readonly parameterCount: 1;
}

export interface JoinTenantOwnership {
  readonly kind: "join";
  /** The relationship is descriptive; the query is the executable contract. */
  readonly relationship: string;
  /** A static WHERE predicate for a source table aliased as `t`. */
  readonly query: string;
  readonly whereSql: string;
  readonly parameterCount: number;
}

export interface ScopeTenantOwnership {
  readonly kind: "scope";
  readonly scopeColumns: readonly string[];
  /** A static WHERE predicate for a source table aliased as `t`. */
  readonly query: string;
  readonly whereSql: string;
  readonly parameterCount: number;
}

export interface DocumentTenantOwnership {
  readonly kind: "document";
  readonly documentColumn: "document_json";
  readonly jsonPath: "$.tenant_id";
  /** A static WHERE predicate for a source table aliased as `t`. */
  readonly query: string;
  readonly whereSql: string;
  readonly parameterCount: 1;
}

export interface UnresolvedTenantOwnership {
  readonly kind: "unresolved";
  /** Unresolved tables are fail-closed and have no executable predicate. */
  readonly query: null;
  readonly whereSql: null;
  readonly parameterCount: 0;
  readonly reason: string;
}

export type TenantTableOwnership =
  | DirectTenantOwnership
  | JoinTenantOwnership
  | ScopeTenantOwnership
  | DocumentTenantOwnership
  | UnresolvedTenantOwnership;

export interface TenantBackfillTable {
  readonly name: string;
  /** Stable ordering columns for keyset pagination and receipt computation. */
  readonly keyColumns: readonly string[];
  readonly ownership: TenantTableOwnership;
  /** Convenience alias for a future copier; null means fail closed. */
  readonly ownershipQuery: string | null;
}

const DIRECT_TENANT_ID = Object.freeze({
  kind: "direct",
  tenantColumn: "tenant_id",
  query: "t.tenant_id = ?",
  whereSql: "t.tenant_id = ?",
  parameterCount: 1,
} satisfies DirectTenantOwnership);

const DIRECT_TENANT = Object.freeze({
  kind: "direct",
  tenantColumn: "tenant",
  query: "t.tenant = ?",
  whereSql: "t.tenant = ?",
  parameterCount: 1,
} satisfies DirectTenantOwnership);

const TENANT_CONTEXT_QUERY = [
  "t.organization_id = ?",
  "OR EXISTS (SELECT 1 FROM projects AS p",
  "WHERE p.id = t.project_id AND p.tenant_id = ?)",
  "OR EXISTS (SELECT 1 FROM workspaces AS w",
  "WHERE w.id = t.workspace_id AND w.tenant_id = ?)",
  "OR EXISTS (SELECT 1 FROM api_keys AS k",
  "WHERE k.id = t.api_key_id AND k.tenant_id = ?)",
].join(" ");

const USAGE_AGGREGATE_QUERY = [
  "EXISTS (SELECT 1 FROM tenant_contexts AS c",
  "WHERE c.id = t.tenant_context_id AND (",
  "c.organization_id = ?",
  "OR EXISTS (SELECT 1 FROM projects AS p",
  "WHERE p.id = c.project_id AND p.tenant_id = ?)",
  "OR EXISTS (SELECT 1 FROM workspaces AS w",
  "WHERE w.id = c.workspace_id AND w.tenant_id = ?)",
  "OR EXISTS (SELECT 1 FROM api_keys AS k",
  "WHERE k.id = c.api_key_id AND k.tenant_id = ?)",
  "))",
].join(" ");

const MONTHLY_SCOPE_QUERY = [
  "(t.scope_type = 'tenant' AND t.scope_id = ?)",
  "OR (t.scope_type = 'project' AND EXISTS (",
  "SELECT 1 FROM projects AS p WHERE p.id = t.scope_id AND p.tenant_id = ?))",
  "OR (t.scope_type = 'workspace' AND EXISTS (",
  "SELECT 1 FROM workspaces AS w WHERE w.id = t.scope_id AND w.tenant_id = ?))",
  "OR (t.scope_type = 'key' AND EXISTS (",
  "SELECT 1 FROM api_keys AS k WHERE k.id = t.scope_id AND k.tenant_id = ?))",
].join(" ");

const TENANT_CONTEXT_OWNERSHIP = Object.freeze({
  kind: "join",
  relationship: "tenant_contexts -> projects|workspaces|api_keys",
  query: TENANT_CONTEXT_QUERY,
  whereSql: TENANT_CONTEXT_QUERY,
  parameterCount: 4,
} satisfies JoinTenantOwnership);

const USAGE_AGGREGATE_OWNERSHIP = Object.freeze({
  kind: "join",
  relationship: "usage_aggregate_rollups -> tenant_contexts -> projects|workspaces|api_keys",
  query: USAGE_AGGREGATE_QUERY,
  whereSql: USAGE_AGGREGATE_QUERY,
  parameterCount: 4,
} satisfies JoinTenantOwnership);

const SCHEDULE_FIRE_OWNERSHIP = Object.freeze({
  kind: "join",
  relationship: "agent_schedule_fires -> agent_schedules",
  query:
    "EXISTS (SELECT 1 FROM agent_schedules AS s " +
    "WHERE s.schedule_id = t.schedule_id AND s.tenant_id = ?)",
  whereSql:
    "EXISTS (SELECT 1 FROM agent_schedules AS s " +
    "WHERE s.schedule_id = t.schedule_id AND s.tenant_id = ?)",
  parameterCount: 1,
} satisfies JoinTenantOwnership);

const SELF_HOSTED_WORKER_OWNERSHIP = Object.freeze({
  kind: "join",
  relationship: "self-hosted worker row -> self_hosted_worker_identities",
  query:
    "EXISTS (SELECT 1 FROM self_hosted_worker_identities AS w " +
    "WHERE w.worker_id = t.worker_id AND w.tenant_id = ?)",
  whereSql:
    "EXISTS (SELECT 1 FROM self_hosted_worker_identities AS w " +
    "WHERE w.worker_id = t.worker_id AND w.tenant_id = ?)",
  parameterCount: 1,
} satisfies JoinTenantOwnership);

const MONTHLY_SCOPE_OWNERSHIP = Object.freeze({
  kind: "scope",
  scopeColumns: Object.freeze(["scope_type", "scope_id"]),
  query: MONTHLY_SCOPE_QUERY,
  whereSql: MONTHLY_SCOPE_QUERY,
  parameterCount: 4,
} satisfies ScopeTenantOwnership);

const TENANT_ONLY_SCOPE_OWNERSHIP = Object.freeze({
  kind: "scope",
  scopeColumns: Object.freeze(["scope_type", "scope_id"]),
  query: "t.scope_type = 'tenant' AND t.scope_id = ?",
  whereSql: "t.scope_type = 'tenant' AND t.scope_id = ?",
  parameterCount: 1,
} satisfies ScopeTenantOwnership);

const ORGANIZATION_SCOPE_OWNERSHIP = Object.freeze({
  kind: "scope",
  scopeColumns: Object.freeze(["organization_id"]),
  query: "t.organization_id = ?",
  whereSql: "t.organization_id = ?",
  parameterCount: 1,
} satisfies ScopeTenantOwnership);

const TENANT_RESOURCE_OWNERSHIP = Object.freeze({
  kind: "document",
  documentColumn: "document_json",
  jsonPath: "$.tenant_id",
  query: "json_extract(t.document_json, '$.tenant_id') = ?",
  whereSql: "json_extract(t.document_json, '$.tenant_id') = ?",
  parameterCount: 1,
} satisfies DocumentTenantOwnership);

function unresolved(reason: string): UnresolvedTenantOwnership {
  return Object.freeze({
    kind: "unresolved",
    query: null,
    whereSql: null,
    parameterCount: 0,
    reason,
  });
}

function table(
  name: string,
  keyColumns: readonly string[],
  ownership: TenantTableOwnership,
): TenantBackfillTable {
  if (!/^[a-z][a-z0-9_]*$/.test(name)) {
    throw new Error(`unsafe tenant backfill table identifier: ${name}`);
  }
  for (const column of keyColumns) {
    if (!/^[a-z][a-z0-9_]*$/.test(column)) {
      throw new Error(`unsafe tenant backfill column identifier: ${column}`);
    }
  }

  return Object.freeze({
    name,
    keyColumns: Object.freeze([...keyColumns]),
    ownership,
    ownershipQuery: ownership.query,
  });
}

/**
 * All live tables in the current tenant migrations, in migration order.
 *
 * The three excluded names are object bookkeeping (`storage_schema_migrations`
 * and `tenant_provisioning_marks`) or a retired source table (`model_catalog`).
 * Tables without a provable source ownership predicate remain in this manifest
 * as `unresolved`; a copier must handle them explicitly rather than copying
 * every shared row into each tenant object.
 */
export const TENANT_BACKFILL_TABLES: readonly TenantBackfillTable[] = Object.freeze([
  table("projects", ["id"], DIRECT_TENANT_ID),
  table("workspaces", ["id"], DIRECT_TENANT_ID),
  table("api_keys", ["id"], DIRECT_TENANT_ID),
  table("wallets", ["id"], DIRECT_TENANT_ID),
  table("wallet_reservations", ["id"], DIRECT_TENANT_ID),
  table("wallet_settlements", ["id"], DIRECT_TENANT_ID),
  table("payment_methods", ["id"], DIRECT_TENANT_ID),
  table("tenant_contexts", ["id"], TENANT_CONTEXT_OWNERSHIP),
  table("usage_aggregate_rollups", ["id"], USAGE_AGGREGATE_OWNERSHIP),
  table("usage_monthly_rollups", ["id"], MONTHLY_SCOPE_OWNERSHIP),
  table("usage_metadata_rollups", ["id"], ORGANIZATION_SCOPE_OWNERSHIP),
  table("stored_assets", ["id"], DIRECT_TENANT_ID),
  table("asset_channels", ["id"], DIRECT_TENANT_ID),
  table("retention_policies", ["id"], DIRECT_TENANT_ID),
  table("workflow_run_budgets", ["id"], DIRECT_TENANT_ID),
  table("agent_schedules", ["schedule_id"], DIRECT_TENANT_ID),
  table("agent_schedule_fires", ["fire_id"], SCHEDULE_FIRE_OWNERSHIP),
  table("observed_agent_presence", ["tenant_id", "api_key_id"], DIRECT_TENANT_ID),
  table("agent_cost_burn", ["tenant_id", "agent_key", "period"], DIRECT_TENANT_ID),
  table("asset_bundle_files", ["asset_id", "path"], DIRECT_TENANT_ID),
  table(
    "responses_conversations",
    ["tenant_id", "project_id", "response_id"],
    DIRECT_TENANT_ID,
  ),
  table("tenant_database_identity", ["id"], DIRECT_TENANT_ID),
  table("provider_channels", ["id"], DIRECT_TENANT_ID),
  table("catalog_models", ["id"], DIRECT_TENANT_ID),
  table("catalog_model_offerings", ["id"], DIRECT_TENANT_ID),
  table("catalog_revisions", ["tenant_id", "id"], DIRECT_TENANT_ID),
  table("catalog_audit_outbox", ["id"], DIRECT_TENANT_ID),
  table("request_logs", ["request_id"], DIRECT_TENANT),
  table("agent_runs", ["id"], DIRECT_TENANT),
  table("agent_run_events", ["id"], DIRECT_TENANT),
  table("guardrail_evaluations", ["id"], DIRECT_TENANT),
  table("guardrail_check_evaluations", ["id"], DIRECT_TENANT),
  table("mcp_servers", ["tenant_id", "name"], DIRECT_TENANT_ID),
  table("mcp_oauth_credentials", ["id"], DIRECT_TENANT_ID),
  table(
    "mcp_identity_generations",
    ["tenant_id", "workspace_id", "user_id", "server_name"],
    DIRECT_TENANT_ID,
  ),
  table("tenant_provider_credentials", ["tenant_id", "alias"], DIRECT_TENANT_ID),
  table("sso_provider_configs", ["tenant_id"], DIRECT_TENANT_ID),
  table("tenant_role_catalog", ["role_id"], unresolved("role catalog has no tenant key")),
  table("tenant_role_bindings", ["id"], DIRECT_TENANT_ID),
  table("semantic_cache_policies", ["scope_type", "scope_id"], TENANT_ONLY_SCOPE_OWNERSHIP),
  table("delegation_revocations", ["tenant", "subject"], DIRECT_TENANT),
  table("control_plane_replay_floors", ["tenant_id", "deployment_id"], DIRECT_TENANT_ID),
  table("budget_alert_notifications", ["id"], DIRECT_TENANT_ID),
  table("tenant_resources", ["resource_kind", "resource_id"], TENANT_RESOURCE_OWNERSHIP),
  table(
    "managed_worker_templates",
    ["id"],
    unresolved("managed worker template rows have no tenant or parent key"),
  ),
  table(
    "agent_worker_instances",
    ["id"],
    unresolved("worker instance rows have no tenant or parent key"),
  ),
  table(
    "managed_worker_sessions",
    ["id"],
    unresolved("managed worker session rows have no tenant or parent key"),
  ),
  table(
    "managed_worker_lifecycle_events",
    ["id"],
    unresolved("worker lifecycle event rows have no tenant or parent key"),
  ),
  table(
    "managed_worker_isolation_selections",
    ["session_id"],
    unresolved("worker isolation selection rows have no tenant key"),
  ),
  table(
    "managed_worker_isolation_policies",
    ["session_id"],
    unresolved("worker isolation policy rows have no tenant key"),
  ),
  table("self_hosted_worker_heartbeats", ["id"], SELF_HOSTED_WORKER_OWNERSHIP),
  table("self_hosted_worker_identities", ["worker_id"], DIRECT_TENANT_ID),
  table("self_hosted_worker_artifacts", ["id"], SELF_HOSTED_WORKER_OWNERSHIP),
  table("self_hosted_worker_checkpoints", ["id"], SELF_HOSTED_WORKER_OWNERSHIP),
  table("self_hosted_worker_telemetry_events", ["id"], SELF_HOSTED_WORKER_OWNERSHIP),
  table(
    "self_hosted_run_dispatches",
    ["dispatch_id"],
    unresolved("run dispatch rows have no tenant or worker key"),
  ),
  table("online_eval_scores", ["request_id", "criterion_id"], DIRECT_TENANT),
  table("online_eval_regressions", ["claim_key"], DIRECT_TENANT),
  table("experiment_shadow_legs", ["leg_id"], DIRECT_TENANT),
  table("spend_anomaly_episodes", ["id"], TENANT_ONLY_SCOPE_OWNERSHIP),
  table(
    "managed_worker_isolation_evidence",
    ["id"],
    unresolved("worker isolation evidence rows have no tenant key"),
  ),
  table("usage_projection_retries", ["source_id"], DIRECT_TENANT_ID),
  table("audit_events", ["id"], DIRECT_TENANT),
  table("usage_event_claims", ["source_id"], unresolved("usage claims have no tenant key")),
  table("billing_ledger", ["id"], DIRECT_TENANT_ID),
  table("billing_report_outbox", ["id"], DIRECT_TENANT_ID),
  table("billing_events", ["billing_event_id"], DIRECT_TENANT_ID),
]);

// A descriptive alias makes call sites read naturally without creating a
// second mutable copy of the allow-list.
export const TENANT_BACKFILL_TABLE_MANIFEST = TENANT_BACKFILL_TABLES;

// ---------------------------------------------------------------------------
// State transitions
// ---------------------------------------------------------------------------

const NEXT_TENANT_MIGRATION_STATE: Readonly<Record<TenantMigrationState, TenantMigrationState>> =
  Object.freeze({
    shared: "copying",
    copying: "verifying",
    verifying: "cut",
    cut: "done",
    done: "done",
  });

export function isTenantMigrationState(value: string): value is TenantMigrationState {
  return (TENANT_MIGRATION_STATES as readonly string[]).includes(value);
}

/**
 * Validate the control-plane state machine before a database CAS.
 *
 * Rollback is deliberately narrow: only a cut-over object may return to the
 * retained shared source. A copier can still retry its current page without a
 * state transition.
 */
export function assertTenantMigrationTransition(
  from: TenantMigrationState,
  to: TenantMigrationState,
): void {
  if (!isTenantMigrationState(from) || !isTenantMigrationState(to)) {
    throw new Error(`unknown tenant migration state transition: ${from} -> ${to}`);
  }
  if ((from === "cut" || from === "done") && to === "shared") {
    return;
  }
  if (from === "done") {
    throw new Error(`tenant migration state ${from} is terminal; it cannot transition to ${to}`);
  }
  const expected = NEXT_TENANT_MIGRATION_STATE[from];
  if (to !== expected) {
    throw new Error(
      `invalid tenant migration transition ${from} -> ${to}; expected ${from} -> ${expected}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Deterministic row checksums
// ---------------------------------------------------------------------------

export type CanonicalRow = Readonly<Record<string, unknown>>;

const MISSING_VALUE = Symbol("missing-row-column");

function assertSafeColumnIdentifier(column: string): void {
  if (!/^[a-z][a-z0-9_]*$/.test(column)) {
    throw new Error(`unsafe checksum column identifier: ${column}`);
  }
}

function frame(tag: string, value: string): string {
  return `${tag}${value.length}:${value}`;
}

function bytesToHex(bytes: Uint8Array): string {
  let result = "";
  for (const byte of bytes) {
    result += byte.toString(16).padStart(2, "0");
  }
  return result;
}

function canonicalValue(value: unknown, seen: Set<object>): string {
  if (value === MISSING_VALUE) {
    return "missing";
  }
  if (value === null) {
    return "null";
  }
  if (value === undefined) {
    return "undefined";
  }
  switch (typeof value) {
    case "string":
      return frame("string", value);
    case "boolean":
      return value ? "boolean:true" : "boolean:false";
    case "number":
      if (Number.isNaN(value)) return "number:NaN";
      if (Object.is(value, -0)) return "number:-0";
      if (value === Infinity) return "number:+Infinity";
      if (value === -Infinity) return "number:-Infinity";
      return frame("number", String(value));
    case "bigint":
      return frame("bigint", value.toString(10));
    case "symbol":
    case "function":
      throw new TypeError(`unsupported value type in tenant checksum: ${typeof value}`);
    default:
      break;
  }

  if (value instanceof Date) {
    const time = value.getTime();
    if (Number.isNaN(time)) {
      throw new TypeError("invalid Date in tenant checksum");
    }
    return frame("date", value.toISOString());
  }

  if (value instanceof ArrayBuffer) {
    return frame("bytes", bytesToHex(new Uint8Array(value)));
  }
  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    return frame(
      "bytes",
      bytesToHex(new Uint8Array(view.buffer, view.byteOffset, view.byteLength)),
    );
  }

  if (seen.has(value)) {
    throw new TypeError("cyclic value in tenant checksum");
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const items = value.map((item) => canonicalValue(item, seen));
      return frame("array", items.join("|"));
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("unsupported object value in tenant checksum");
    }
    const record = value as Record<string, unknown>;
    const entries = Object.keys(record)
      .sort()
      .map((key) => `${frame("key", key)}=${canonicalValue(record[key], seen)}`);
    return frame("object", entries.join("|"));
  } finally {
    seen.delete(value);
  }
}

function canonicalRow(row: CanonicalRow, columns: readonly string[]): string {
  if (row === null || typeof row !== "object" || Array.isArray(row)) {
    throw new TypeError("tenant checksum rows must be plain objects");
  }
  const seen = new Set<object>();
  const values = columns.map((column) => {
    const hasColumn = Object.prototype.hasOwnProperty.call(row, column);
    const value = hasColumn ? row[column] : MISSING_VALUE;
    return `${frame("column", column)}=${canonicalValue(value, seen)}`;
  });
  return frame("row", values.join("|"));
}

function compareCanonicalStrings(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

/**
 * SHA-256 of a versioned, type-preserving, sorted row stream.
 *
 * `columns` is an explicit allow-list. It is sorted for canonicalisation, so
 * caller object property order and caller column order cannot change a receipt.
 */
export async function checksumRows(
  rows: readonly CanonicalRow[],
  columns: readonly string[],
): Promise<string> {
  const canonicalColumns = [...columns];
  const seenColumns = new Set<string>();
  for (const column of canonicalColumns) {
    assertSafeColumnIdentifier(column);
    if (seenColumns.has(column)) {
      throw new Error(`duplicate checksum column identifier: ${column}`);
    }
    seenColumns.add(column);
  }
  canonicalColumns.sort(compareCanonicalStrings);

  const canonicalRows = rows
    .map((row) => canonicalRow(row, canonicalColumns))
    .sort(compareCanonicalStrings);
  const payload = [
    "ferrogate-tenant-backfill-checksum-v1",
    frame("columns", canonicalColumns.join("|")),
    frame("rows", String(canonicalRows.length)),
    ...canonicalRows.map((row) => frame("entry", row)),
  ].join("\n");

  const runtimeCrypto = (globalThis as unknown as {
    crypto?: {
      subtle: {
        digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer>;
      };
    };
  }).crypto;
  if (runtimeCrypto === undefined) {
    throw new Error("Web Crypto is required for tenant backfill checksums");
  }
  const digest = await runtimeCrypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(payload),
  );
  return bytesToHex(new Uint8Array(digest));
}

// ---------------------------------------------------------------------------
// Receipt comparison
// ---------------------------------------------------------------------------

export interface TenantTableReceipt {
  readonly table: string;
  readonly rowCount: number;
  readonly checksum: string;
}

export type TenantTableReceiptMismatch =
  | {
      readonly table: string;
      readonly reason: "missing_destination";
      readonly source: TenantTableReceipt;
    }
  | {
      readonly table: string;
      readonly reason: "missing_source";
      readonly destination: TenantTableReceipt;
    }
  | {
      readonly table: string;
      readonly reason: "row_count";
      readonly source: TenantTableReceipt;
      readonly destination: TenantTableReceipt;
    }
  | {
      readonly table: string;
      readonly reason: "checksum";
      readonly source: TenantTableReceipt;
      readonly destination: TenantTableReceipt;
    };

export interface TenantTableReceiptComparison {
  readonly ok: boolean;
  readonly mismatches: readonly TenantTableReceiptMismatch[];
}

/** Compare complete table receipts, including omitted and unexpected tables. */
export function compareTableReceipts(
  source: readonly TenantTableReceipt[],
  destination: readonly TenantTableReceipt[],
): TenantTableReceiptComparison {
  const sourceByTable = new Map(source.map((receipt) => [receipt.table, receipt]));
  const destinationByTable = new Map(destination.map((receipt) => [receipt.table, receipt]));
  const tables = [...new Set([...sourceByTable.keys(), ...destinationByTable.keys()])].sort(
    compareCanonicalStrings,
  );
  const mismatches: TenantTableReceiptMismatch[] = [];

  for (const tableName of tables) {
    const sourceReceipt = sourceByTable.get(tableName);
    const destinationReceipt = destinationByTable.get(tableName);
    if (sourceReceipt === undefined) {
      mismatches.push({
        table: tableName,
        reason: "missing_source",
        destination: destinationReceipt!,
      });
      continue;
    }
    if (destinationReceipt === undefined) {
      mismatches.push({
        table: tableName,
        reason: "missing_destination",
        source: sourceReceipt,
      });
      continue;
    }
    if (sourceReceipt.rowCount !== destinationReceipt.rowCount) {
      mismatches.push({
        table: tableName,
        reason: "row_count",
        source: sourceReceipt,
        destination: destinationReceipt,
      });
      continue;
    }
    if (sourceReceipt.checksum !== destinationReceipt.checksum) {
      mismatches.push({
        table: tableName,
        reason: "checksum",
        source: sourceReceipt,
        destination: destinationReceipt,
      });
    }
  }

  return { ok: mismatches.length === 0, mismatches };
}
