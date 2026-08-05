/**
 * Tenant-authoritative agent evidence persistence (#859).
 *
 * `AgentRunState` keeps live state and subscribers in its run-shaped object.
 * These helpers write durable evidence into the tenant's `TenantDataObject`
 * first, then update the control-D1 compatibility mirror for existing platform
 * pages. A mirror failure is observable but never changes object authority.
 */
import { DurableObjectD1Database } from "@ferrogate/storage";
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";
import type { AgentRuntimeBindings } from "../ports.js";
import type { StoredAgentRun, StoredRunEvent } from "./model.js";

/** Keep this key format identical to sql/d1-ts/control/0014. */
function evidenceProjectionKey(tenantId: string, logicalId: string): string {
  // SQLite length() counts Unicode code points; JS string.length counts UTF-16 units.
  return `${Array.from(tenantId).length}:${tenantId}:${logicalId}`;
}

const TENANT_AGENT_RUN_UPSERT_SQL = `INSERT INTO agent_runs (
  id, request_id, tenant, started_at_unix, completed_at_unix, run_json
) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
  request_id = CASE WHEN excluded.request_id = '' THEN agent_runs.request_id ELSE excluded.request_id END,
  tenant = excluded.tenant,
  started_at_unix = MIN(excluded.started_at_unix, agent_runs.started_at_unix),
  completed_at_unix = COALESCE(excluded.completed_at_unix, agent_runs.completed_at_unix),
  run_json = excluded.run_json`;

const CONTROL_AGENT_RUN_UPSERT_SQL = `INSERT INTO agent_runs (
  projection_key, id, request_id, tenant, started_at_unix, completed_at_unix, run_json
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (projection_key) DO UPDATE SET
  request_id = CASE WHEN excluded.request_id = '' THEN agent_runs.request_id ELSE excluded.request_id END,
  tenant = excluded.tenant,
  started_at_unix = MIN(excluded.started_at_unix, agent_runs.started_at_unix),
  completed_at_unix = COALESCE(excluded.completed_at_unix, agent_runs.completed_at_unix),
  run_json = excluded.run_json`;

const TENANT_AGENT_RUN_EVENT_UPSERT_SQL = `INSERT INTO agent_run_events (
  id, run_id, request_id, tenant, occurred_at_unix, event_json
) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
  run_id = excluded.run_id,
  request_id = CASE WHEN excluded.request_id = '' THEN agent_run_events.request_id ELSE excluded.request_id END,
  tenant = excluded.tenant,
  occurred_at_unix = excluded.occurred_at_unix,
  event_json = excluded.event_json`;

const CONTROL_AGENT_RUN_EVENT_UPSERT_SQL = `INSERT INTO agent_run_events (
  projection_key, id, run_id, request_id, tenant, occurred_at_unix, event_json
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (projection_key) DO UPDATE SET
  run_id = excluded.run_id,
  request_id = CASE WHEN excluded.request_id = '' THEN agent_run_events.request_id ELSE excluded.request_id END,
  tenant = excluded.tenant,
  occurred_at_unix = excluded.occurred_at_unix,
  event_json = excluded.event_json`;

function tenantDatabase(env: AgentRuntimeBindings, tenantId: string): D1Database {
  const namespace = env.TENANT_DATA as TenantDataNamespace | undefined;
  if (namespace === undefined) {
    throw new Error(
      "AgentRunState requires the TENANT_DATA binding for authoritative agent evidence",
    );
  }
  const stub = namespace.get(namespace.idFromName(tenantId));
  return new DurableObjectD1Database(tenantId, stub).asD1Database();
}
function controlDatabase(env: AgentRuntimeBindings): D1Database | undefined {
  return env.CONTROL_DB;
}

/** Write one agent run to the tenant object, then to the derived mirror. */
export async function persistAgentRunEvidence(
  env: AgentRuntimeBindings,
  run: StoredAgentRun,
): Promise<void> {
  const params = [
    run.run_id,
    run.request_id ?? "",
    run.tenant_id,
    run.started_at_unix ?? run.submitted_at_unix ?? 0,
    run.completed_at_unix,
    JSON.stringify(run),
  ] as const;
  const db = tenantDatabase(env, run.tenant_id);
  const statement = db.prepare(TENANT_AGENT_RUN_UPSERT_SQL);
  await db.batch([statement.bind(...params)]);
  await mirrorBestEffort(controlDatabase(env), CONTROL_AGENT_RUN_UPSERT_SQL, [
    evidenceProjectionKey(run.tenant_id, run.run_id),
    ...params,
  ]);
}

/** Write one append-only event to the tenant object, then to the mirror. */
export async function persistAgentRunEventEvidence(
  env: AgentRuntimeBindings,
  tenantId: string,
  event: StoredRunEvent,
): Promise<void> {
  const params = [
    event.id,
    event.run_id,
    event.request_id ?? "",
    tenantId,
    event.occurred_at_unix,
    JSON.stringify(event),
  ] as const;
  const db = tenantDatabase(env, tenantId);
  const statement = db.prepare(TENANT_AGENT_RUN_EVENT_UPSERT_SQL);
  await db.batch([statement.bind(...params)]);
  await mirrorBestEffort(controlDatabase(env), CONTROL_AGENT_RUN_EVENT_UPSERT_SQL, [
    evidenceProjectionKey(tenantId, event.id),
    ...params,
  ]);
}

async function mirrorBestEffort(
  db: D1Database | undefined,
  sql: string,
  params: readonly (string | number | null)[],
): Promise<void> {
  if (db === undefined) return;
  try {
    const statement = db.prepare(sql);
    await db.batch([statement.bind(...params)]);
  } catch (error) {
    console.error("agent evidence control projection failed; tenant object remains authoritative", error);
  }
}
