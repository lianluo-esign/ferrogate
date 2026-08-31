/**
 * Tenant-authoritative agent evidence persistence (#859).
 *
 * `AgentRunState` keeps live state and subscribers in its run-shaped object.
 * These helpers write durable evidence into the tenant's `TenantDataObject`
 * first, then update the control-D1 `agent_runs` / `agent_run_events`
 * compatibility mirror for existing platform pages. A mirror failure is
 * observable but never changes object authority.
 *
 * Managed isolation evidence is NOT mirrored to control D1 (the no-tenant-data
 * mirror red line): its only authoritative copy is the tenant object, and the
 * gateway's scheduled managed-evidence rebuild sweep was removed with it.
 */
import {
  ControlDatabaseTenantRegistry,
  DurableObjectD1Database,
  tenantObjectStubFor,
} from "@ferrogate/storage";
import type {
  TenantDataStub,
  TenantObjectAddress,
  TenantObjectNamespaceLike,
} from "@ferrogate/storage";
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";
import { controlDatabaseFrom } from "../control-data.js";
import type { AgentRuntimeBindings, IsolationGrant } from "../ports.js";
import type { StoredAgentRun, StoredRunEvent } from "./model.js";

export interface ManagedWorkerEvidenceContext {
  readonly sessionId?: string | null;
  readonly frameworkAdapter?: string | null;
  readonly isolationGrant?: IsolationGrant | null;
}

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

const TENANT_MANAGED_INSTANCE_UPSERT_SQL = `INSERT INTO agent_worker_instances (
  id, started_at_unix, instance_json
) VALUES (?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
  started_at_unix = COALESCE(agent_worker_instances.started_at_unix, excluded.started_at_unix),
  instance_json = excluded.instance_json`;

const TENANT_MANAGED_SESSION_UPSERT_SQL = `INSERT INTO managed_worker_sessions (
  id, requested_at_unix, session_json
) VALUES (?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
  requested_at_unix = COALESCE(managed_worker_sessions.requested_at_unix, excluded.requested_at_unix),
  session_json = excluded.session_json`;

const TENANT_MANAGED_TEMPLATE_UPSERT_SQL = `INSERT INTO managed_worker_templates (
  id, template_json
) VALUES (?, ?)
ON CONFLICT (id) DO UPDATE SET template_json = excluded.template_json`;

const TENANT_MANAGED_SELECTION_UPSERT_SQL = `INSERT INTO managed_worker_isolation_selections (
  session_id, selected_at_unix, selection_json
) VALUES (?, ?, ?)
ON CONFLICT (session_id) DO UPDATE SET
  selected_at_unix = excluded.selected_at_unix,
  selection_json = excluded.selection_json`;

const TENANT_MANAGED_POLICY_UPSERT_SQL = `INSERT INTO managed_worker_isolation_policies (
  session_id, policy_json
) VALUES (?, ?)
ON CONFLICT (session_id) DO UPDATE SET policy_json = excluded.policy_json`;

const TENANT_MANAGED_ISOLATION_EVIDENCE_UPSERT_SQL = `INSERT INTO managed_worker_isolation_evidence (
  id, occurred_at_unix, evidence_json
) VALUES (?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
  occurred_at_unix = excluded.occurred_at_unix,
  evidence_json = excluded.evidence_json`;

const TENANT_MANAGED_EVENT_UPSERT_SQL = `INSERT INTO managed_worker_lifecycle_events (
  id, occurred_at_unix, event_json
) VALUES (?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
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

const TENANT_ADDRESS_CACHE = new WeakMap<
  object,
  Map<string, Promise<TenantObjectAddress | undefined>>
>();

function tenantAddress(
  env: AgentRuntimeBindings,
  tenantId: string,
): Promise<TenantObjectAddress | undefined> {
  const controlDatabase = controlDatabaseFrom(env);
  if (controlDatabase === undefined) return Promise.resolve(undefined);
  let cache = TENANT_ADDRESS_CACHE.get(env);
  if (cache === undefined) {
    cache = new Map();
    TENANT_ADDRESS_CACHE.set(env, cache);
  }
  const cached = cache.get(tenantId);
  if (cached !== undefined) return cached;
  const lookup = new ControlDatabaseTenantRegistry(controlDatabase)
    .get(tenantId)
    .then((registration) => {
      if (registration === undefined) return undefined;
      return {
        ...(registration.locationHint === undefined
          ? {}
          : { locationHint: registration.locationHint }),
        ...(registration.jurisdiction === undefined
          ? {}
          : { jurisdiction: registration.jurisdiction }),
      };
    });
  cache.set(tenantId, lookup);
  return lookup;
}

async function tenantDatabase(env: AgentRuntimeBindings, tenantId: string): Promise<D1Database> {
  const namespace = env.TENANT_DATA as TenantDataNamespace | undefined;
  if (namespace === undefined) {
    throw new Error(
      "AgentRunState requires the TENANT_DATA binding for authoritative agent evidence",
    );
  }
  const address = await tenantAddress(env, tenantId);
  const stub = tenantObjectStubFor(
    namespace as unknown as TenantObjectNamespaceLike<TenantDataStub, DurableObjectId>,
    tenantId,
    address,
  );
  return new DurableObjectD1Database(tenantId, stub).asD1Database();
}
function controlDatabase(env: AgentRuntimeBindings): D1Database | undefined {
  return controlDatabaseFrom(env);
}

/** Write one agent run to the tenant object, then to the derived mirror. */
export async function persistAgentRunEvidence(
  env: AgentRuntimeBindings,
  run: StoredAgentRun,
  managed?: ManagedWorkerEvidenceContext,
): Promise<void> {
  const params = [
    run.run_id,
    run.request_id ?? "",
    run.tenant_id,
    run.started_at_unix ?? run.submitted_at_unix ?? 0,
    run.completed_at_unix,
    JSON.stringify(run),
  ] as const;
  const db = await tenantDatabase(env, run.tenant_id);
  const frameworkAdapter = managed?.frameworkAdapter ?? run.framework_adapter;
  const managedEvidence =
    managed?.sessionId !== undefined &&
    managed.sessionId !== null &&
    managed.sessionId.trim() !== "" &&
    managed.isolationGrant !== undefined &&
    managed.isolationGrant !== null
      ? {
          id: `managed:${managed.sessionId.trim()}:${run.run_id}`,
          tenantId: run.tenant_id,
          occurredAtUnix: run.submitted_at_unix ?? run.started_at_unix ?? 0,
          evidenceJson: JSON.stringify({
            session_id: managed.sessionId.trim(),
            run_id: run.run_id,
            tenant_id: run.tenant_id,
            isolation_grant: managed.isolationGrant,
          }),
        }
      : undefined;
  const statements: D1PreparedStatement[] = [
    db.prepare(TENANT_AGENT_RUN_UPSERT_SQL).bind(...params),
    db.prepare(TENANT_MANAGED_INSTANCE_UPSERT_SQL).bind(
      run.run_id,
      run.started_at_unix,
      JSON.stringify({
        run_id: run.run_id,
        tenant_id: run.tenant_id,
        workspace_id: run.workspace_id,
        framework_adapter: run.framework_adapter,
        required_capabilities: run.required_capabilities,
        workload_ref: run.workload_ref,
        status: run.status,
      }),
    ),
  ];
  if (frameworkAdapter !== null && frameworkAdapter.trim() !== "") {
    statements.push(
      db
        .prepare(TENANT_MANAGED_TEMPLATE_UPSERT_SQL)
        .bind(
          frameworkAdapter.trim(),
          JSON.stringify({ framework_adapter: frameworkAdapter.trim() }),
        ),
    );
  }
  const sessionId = managed?.sessionId?.trim();
  if (sessionId !== undefined && sessionId !== "") {
    const isolation = managed?.isolationGrant ?? null;
    statements.push(
      db.prepare(TENANT_MANAGED_SESSION_UPSERT_SQL).bind(
        sessionId,
        run.submitted_at_unix ?? 0,
        JSON.stringify({
          session_id: sessionId,
          run_id: run.run_id,
          workspace_id: run.workspace_id,
          framework_adapter: run.framework_adapter,
          status: run.status,
        }),
      ),
    );
    if (isolation !== null && isolation !== undefined) {
      const isolationJson = JSON.stringify(isolation);
      statements.push(
        db
          .prepare(TENANT_MANAGED_SELECTION_UPSERT_SQL)
          .bind(sessionId, run.submitted_at_unix ?? 0, isolationJson),
        db.prepare(TENANT_MANAGED_POLICY_UPSERT_SQL).bind(sessionId, isolationJson),
        db.prepare(TENANT_MANAGED_ISOLATION_EVIDENCE_UPSERT_SQL).bind(
          managedEvidence?.id ?? `managed:${sessionId}:${run.run_id}`,
          managedEvidence?.occurredAtUnix ?? run.submitted_at_unix ?? run.started_at_unix ?? 0,
          managedEvidence?.evidenceJson ??
            JSON.stringify({
              session_id: sessionId,
              run_id: run.run_id,
              tenant_id: run.tenant_id,
              isolation_grant: isolation,
            }),
        ),
      );
    }
  }
  await db.batch(statements);
  await mirrorBestEffort(controlDatabase(env), CONTROL_AGENT_RUN_UPSERT_SQL, [
    evidenceProjectionKey(run.tenant_id, run.run_id),
    ...params,
  ]);
  // Managed isolation evidence is tenant-object authoritative and is NOT
  // mirrored to control D1 (no-tenant-data mirror red line). The `managedEvidence`
  // object above still drives the authoritative `TENANT_MANAGED_ISOLATION_EVIDENCE`
  // write in the tenant batch.
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
  const db = await tenantDatabase(env, tenantId);
  await db.batch([
    db.prepare(TENANT_AGENT_RUN_EVENT_UPSERT_SQL).bind(...params),
    db
      .prepare(TENANT_MANAGED_EVENT_UPSERT_SQL)
      .bind(event.id, event.occurred_at_unix, JSON.stringify(event)),
  ]);
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
    console.error(
      "agent evidence control projection failed; tenant object remains authoritative",
      error,
    );
  }
}
