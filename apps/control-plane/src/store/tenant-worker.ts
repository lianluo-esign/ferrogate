/**
 * Tenant-owned worker state for the Durable Object backend (#856).
 *
 * The control-plane document collections remain compatibility projections for
 * admin listing. These rows are the authoritative worker state once a tenant
 * is addressed through its object: credentials, heartbeat evidence, artifacts,
 * checkpoints, telemetry, and dispatch records never need a cross-tenant scan.
 */
import type { TenantDatabaseRouter } from "@ferrogate/storage";
import type { StoreRecord } from "../ports.js";
import { tenantDatabaseFor } from "./tenancy.js";

export interface TenantWorkerIdentity {
  readonly tenantId: string;
  readonly workerId: string;
  readonly workspaceId: string;
  readonly tokenId: string;
  readonly tokenSecret: string;
  readonly status: string;
  readonly document: StoreRecord;
  readonly registeredAtUnix: number;
  readonly updatedAtUnix: number;
}

export interface TenantWorkerRepository {
  readonly tenantId: string;
  upsertIdentity(identity: TenantWorkerIdentity): Promise<void>;
  recordHeartbeat(
    workerId: string,
    document: Record<string, unknown>,
    occurredAtUnix: number,
  ): Promise<void>;
  recordArtifact(
    workerId: string,
    document: Record<string, unknown>,
    createdAtUnix: number,
  ): Promise<void>;
  recordCheckpoint(
    workerId: string,
    document: Record<string, unknown>,
    createdAtUnix: number,
  ): Promise<void>;
  recordTelemetry(
    workerId: string,
    document: Record<string, unknown>,
    occurredAtUnix: number,
  ): Promise<void>;
  recordDispatch(
    dispatchId: string,
    document: Record<string, unknown>,
    queuedAtUnix: number,
  ): Promise<void>;
}

export interface TenantManagedWorkerRepository {
  readonly tenantId: string;
  upsertTemplate(id: string, document: Record<string, unknown>): Promise<void>;
  upsertInstance(
    id: string,
    document: Record<string, unknown>,
    startedAtUnix: number,
  ): Promise<void>;
  upsertSession(
    id: string,
    document: Record<string, unknown>,
    requestedAtUnix: number,
  ): Promise<void>;
  appendLifecycleEvent(
    id: string,
    document: Record<string, unknown>,
    occurredAtUnix: number,
  ): Promise<void>;
  upsertIsolationSelection(
    sessionId: string,
    document: Record<string, unknown>,
    selectedAtUnix: number,
  ): Promise<void>;
  upsertIsolationPolicy(sessionId: string, document: Record<string, unknown>): Promise<void>;
}

function json(document: Record<string, unknown>): string {
  return JSON.stringify(document);
}

function requireWorkerId(workerId: string): string {
  const value = workerId.trim();
  if (value === "") throw new Error("tenant worker state requires a non-empty worker id");
  return value;
}

function requireText(value: string, field: string): string {
  const normalized = value.trim();
  if (normalized === "") throw new Error(`tenant worker state requires a non-empty ${field}`);
  return normalized;
}

function requireTimestamp(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`tenant worker state requires a non-negative integer ${field}`);
  }
  return value;
}

function repositoryFor(tenantId: string, db: D1Database): TenantWorkerRepository {
  const ensureIdentity = async (workerId: string): Promise<void> => {
    const row = await db
      .prepare(
        "SELECT worker_id FROM self_hosted_worker_identities WHERE worker_id = ? AND tenant_id = ?",
      )
      .bind(requireWorkerId(workerId), tenantId)
      .first<{ worker_id: string }>();
    if (row === null) {
      throw new Error(`tenant ${tenantId} has no self-hosted worker identity ${workerId}`);
    }
  };

  return {
    tenantId,

    async upsertIdentity(identity): Promise<void> {
      const workerId = requireWorkerId(identity.workerId);
      const identityTenantId = requireText(identity.tenantId, "tenant id");
      if (identityTenantId !== tenantId) {
        throw new Error(
          `tenant worker identity ${workerId} belongs to ${identityTenantId}, not ${tenantId}`,
        );
      }
      const workspaceId = requireText(identity.workspaceId, "workspace id");
      const tokenId = requireText(identity.tokenId, "token id");
      const tokenSecret = requireText(identity.tokenSecret, "token secret");
      const status = requireText(identity.status, "worker status");
      const registeredAtUnix = requireTimestamp(identity.registeredAtUnix, "registered_at_unix");
      const updatedAtUnix = requireTimestamp(identity.updatedAtUnix, "updated_at_unix");
      const document = {
        ...identity.document,
        id: workerId,
        tenant_id: tenantId,
        workspace_id: workspaceId,
      };
      await db
        .prepare(
          `INSERT INTO self_hosted_worker_identities
             (worker_id, tenant_id, workspace_id, token_id, token_secret, status,
              identity_json, registered_at_unix, updated_at_unix)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (worker_id) DO UPDATE SET
             tenant_id = excluded.tenant_id,
             workspace_id = excluded.workspace_id,
             token_id = excluded.token_id,
             token_secret = excluded.token_secret,
             status = excluded.status,
             identity_json = excluded.identity_json,
             registered_at_unix = excluded.registered_at_unix,
             updated_at_unix = excluded.updated_at_unix`,
        )
        .bind(
          workerId,
          tenantId,
          workspaceId,
          tokenId,
          tokenSecret,
          status,
          json(document),
          registeredAtUnix,
          updatedAtUnix,
        )
        .run();
    },

    async recordHeartbeat(workerId, document, occurredAtUnix): Promise<void> {
      await ensureIdentity(workerId);
      await db
        .prepare(
          `INSERT INTO self_hosted_worker_heartbeats
             (id, worker_id, reported_at_unix, heartbeat_json)
           VALUES (?, ?, ?, ?)`,
        )
        .bind(
          crypto.randomUUID(),
          requireWorkerId(workerId),
          requireTimestamp(occurredAtUnix, "reported_at_unix"),
          json(document),
        )
        .run();
    },

    async recordArtifact(workerId, document, createdAtUnix): Promise<void> {
      await ensureIdentity(workerId);
      await db
        .prepare(
          `INSERT INTO self_hosted_worker_artifacts
             (id, worker_id, created_at_unix, artifact_json)
           VALUES (?, ?, ?, ?)`,
        )
        .bind(
          crypto.randomUUID(),
          requireWorkerId(workerId),
          requireTimestamp(createdAtUnix, "created_at_unix"),
          json(document),
        )
        .run();
    },

    async recordCheckpoint(workerId, document, createdAtUnix): Promise<void> {
      await ensureIdentity(workerId);
      await db
        .prepare(
          `INSERT INTO self_hosted_worker_checkpoints
             (id, worker_id, created_at_unix, checkpoint_json)
           VALUES (?, ?, ?, ?)`,
        )
        .bind(
          crypto.randomUUID(),
          requireWorkerId(workerId),
          requireTimestamp(createdAtUnix, "created_at_unix"),
          json(document),
        )
        .run();
    },

    async recordTelemetry(workerId, document, occurredAtUnix): Promise<void> {
      await ensureIdentity(workerId);
      const runId = typeof document.run_id === "string" ? document.run_id : null;
      const ingestedAtUnix =
        typeof document.ingested_at_unix === "number" &&
        Number.isSafeInteger(document.ingested_at_unix) &&
        document.ingested_at_unix >= 0
          ? document.ingested_at_unix
          : null;
      await db
        .prepare(
          `INSERT INTO self_hosted_worker_telemetry_events
             (id, worker_id, run_id, occurred_at_unix, ingested_at_unix, event_json)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          crypto.randomUUID(),
          requireWorkerId(workerId),
          runId,
          requireTimestamp(occurredAtUnix, "occurred_at_unix"),
          ingestedAtUnix,
          json(document),
        )
        .run();
    },

    async recordDispatch(dispatchId, document, queuedAtUnix): Promise<void> {
      const normalizedDispatchId = requireText(dispatchId, "dispatch id");
      await ensureIdentity(String(document.worker_id ?? ""));
      await db
        .prepare(
          `INSERT INTO self_hosted_run_dispatches
             (dispatch_id, queued_at_unix, dispatch_json)
           VALUES (?, ?, ?)
           ON CONFLICT (dispatch_id) DO UPDATE SET
             queued_at_unix = excluded.queued_at_unix,
             dispatch_json = excluded.dispatch_json`,
        )
        .bind(
          normalizedDispatchId,
          requireTimestamp(queuedAtUnix, "queued_at_unix"),
          json(document),
        )
        .run();
    },
  };
}

function managedRepositoryFor(tenantId: string, db: D1Database): TenantManagedWorkerRepository {
  return {
    tenantId,

    async upsertTemplate(id, document): Promise<void> {
      await db
        .prepare(
          `INSERT INTO managed_worker_templates (id, template_json)
           VALUES (?, ?)
           ON CONFLICT (id) DO UPDATE SET template_json = excluded.template_json`,
        )
        .bind(requireWorkerId(id), json(document))
        .run();
    },

    async upsertInstance(id, document, startedAtUnix): Promise<void> {
      await db
        .prepare(
          `INSERT INTO agent_worker_instances (id, started_at_unix, instance_json)
           VALUES (?, ?, ?)
           ON CONFLICT (id) DO UPDATE SET
             started_at_unix = excluded.started_at_unix,
             instance_json = excluded.instance_json`,
        )
        .bind(
          requireWorkerId(id),
          requireTimestamp(startedAtUnix, "started_at_unix"),
          json(document),
        )
        .run();
    },

    async upsertSession(id, document, requestedAtUnix): Promise<void> {
      await db
        .prepare(
          `INSERT INTO managed_worker_sessions (id, requested_at_unix, session_json)
           VALUES (?, ?, ?)
           ON CONFLICT (id) DO UPDATE SET
             requested_at_unix = excluded.requested_at_unix,
             session_json = excluded.session_json`,
        )
        .bind(
          requireWorkerId(id),
          requireTimestamp(requestedAtUnix, "requested_at_unix"),
          json(document),
        )
        .run();
    },

    async appendLifecycleEvent(id, document, occurredAtUnix): Promise<void> {
      await db
        .prepare(
          `INSERT INTO managed_worker_lifecycle_events
             (id, occurred_at_unix, event_json)
           VALUES (?, ?, ?)
           ON CONFLICT (id) DO UPDATE SET
             occurred_at_unix = excluded.occurred_at_unix,
             event_json = excluded.event_json`,
        )
        .bind(
          requireWorkerId(id),
          requireTimestamp(occurredAtUnix, "occurred_at_unix"),
          json(document),
        )
        .run();
    },

    async upsertIsolationSelection(sessionId, document, selectedAtUnix): Promise<void> {
      await db
        .prepare(
          `INSERT INTO managed_worker_isolation_selections
             (session_id, selected_at_unix, selection_json)
           VALUES (?, ?, ?)
           ON CONFLICT (session_id) DO UPDATE SET
             selected_at_unix = excluded.selected_at_unix,
             selection_json = excluded.selection_json`,
        )
        .bind(
          requireWorkerId(sessionId),
          requireTimestamp(selectedAtUnix, "selected_at_unix"),
          json(document),
        )
        .run();
    },

    async upsertIsolationPolicy(sessionId, document): Promise<void> {
      await db
        .prepare(
          `INSERT INTO managed_worker_isolation_policies (session_id, policy_json)
           VALUES (?, ?)
           ON CONFLICT (session_id) DO UPDATE SET policy_json = excluded.policy_json`,
        )
        .bind(requireWorkerId(sessionId), json(document))
        .run();
    },
  };
}

async function tenantObjectDatabase(
  router: TenantDatabaseRouter,
  tenantId: string,
): Promise<{ readonly tenantId: string; readonly db: D1Database } | null> {
  const normalizedTenantId = tenantId.trim();
  if (normalizedTenantId === "") return null;
  const handle = await tenantDatabaseFor(router, normalizedTenantId);
  if (handle === null || handle.source !== "durable_object") return null;
  return { tenantId: normalizedTenantId, db: handle.db };
}

/**
 * Open the authoritative tenant worker store. A missing tenant database is a
 * legacy/unprovisioned posture and returns null; a reachable non-DO backend is
 * also null because this adapter must never present shared D1 as object state.
 */
export async function openTenantWorkerRepository(
  router: TenantDatabaseRouter,
  tenantId: string,
): Promise<TenantWorkerRepository | null> {
  const target = await tenantObjectDatabase(router, tenantId);
  return target === null ? null : repositoryFor(target.tenantId, target.db);
}

/** Open the managed-worker state repository inside one tenant object. */
export async function openTenantManagedWorkerRepository(
  router: TenantDatabaseRouter,
  tenantId: string,
): Promise<TenantManagedWorkerRepository | null> {
  const target = await tenantObjectDatabase(router, tenantId);
  return target === null ? null : managedRepositoryFor(target.tenantId, target.db);
}

function decodeDocument(id: string, tenantId: string, raw: string | null): StoreRecord {
  try {
    const parsed: unknown = raw === null ? null : JSON.parse(raw);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      return {
        ...(parsed as Record<string, unknown>),
        id,
        tenant_id: tenantId,
      };
    }
  } catch {
    // A malformed compatibility document is still represented by its stable
    // key; the admin reader must not invent fields from another tenant.
  }
  return { id, tenant_id: tenantId };
}

/** Read managed worker instances from one tenant object for the admin fan-out. */
export async function listTenantManagedWorkers(
  router: TenantDatabaseRouter,
  tenantId: string,
  limit = 500,
): Promise<readonly StoreRecord[] | null> {
  const target = await tenantObjectDatabase(router, tenantId);
  if (target === null) return null;
  const rows = await target.db
    .prepare(
      "SELECT id, instance_json FROM agent_worker_instances ORDER BY started_at_unix ASC, id ASC LIMIT ?",
    )
    .bind(Math.max(1, Math.min(5000, Math.floor(limit))))
    .all<{ id: string; instance_json: string | null }>();
  return rows.results.map((row) => decodeDocument(row.id, target.tenantId, row.instance_json));
}

/** Read managed sessions from one tenant object for the admin fan-out. */
export async function listTenantManagedWorkerSessions(
  router: TenantDatabaseRouter,
  tenantId: string,
  limit = 500,
): Promise<readonly StoreRecord[] | null> {
  const target = await tenantObjectDatabase(router, tenantId);
  if (target === null) return null;
  const rows = await target.db
    .prepare(
      "SELECT id, session_json FROM managed_worker_sessions ORDER BY requested_at_unix ASC, id ASC LIMIT ?",
    )
    .bind(Math.max(1, Math.min(5000, Math.floor(limit))))
    .all<{ id: string; session_json: string | null }>();
  return rows.results.map((row) => decodeDocument(row.id, target.tenantId, row.session_json));
}
