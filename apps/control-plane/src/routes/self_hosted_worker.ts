/**
 * Contract group `self_hosted_worker` (10 operations) — the operator-run worker
 * plane's ADMIN face.
 *
 * ```
 *   GET       /admin/v1/self-hosted-worker-records
 *   GET/POST  /admin/v1/self-hosted-workers
 *   GET       /admin/v1/self-hosted-workers/{id}
 *   POST      /admin/v1/self-hosted-workers/{id}/heartbeat
 *   POST      /admin/v1/self-hosted-workers/{id}/rotate
 *   POST      /admin/v1/self-hosted-workers/{id}/artifacts
 *   POST      /admin/v1/self-hosted-workers/{id}/checkpoints
 *   GET/POST  /admin/v1/self-hosted-workers/{id}/events
 * ```
 *
 * **These are NOT the six `auth.kind: "internal"` callbacks.** Those live at
 * `/v1/self-hosted-workers/*` and belong to `apps/agent-runtime`; they are
 * verified by a signed worker transport envelope and are unreachable with a
 * tenant bearer. The ten here are the `/admin/v1` mirror: ordinary
 * `admin.read`/`admin.write` bearer operations for an operator. Same nouns,
 * different auth kind — collapsing them would open the internal plane to any
 * admin key, or lock the operator out of the admin views.
 *
 * **Every sub-route resolves the worker for the caller's scope first.** Issue
 * #186: every self-hosted-worker sub-handler (rotate, heartbeat, event,
 * artifact, checkpoint, and the single-worker GET) originally looked the worker
 * up by bare `worker_id` with no tenant check, letting a tenant-scoped caller
 * read or mutate — including ROTATING THE IDENTITY FINGERPRINT, a takeover
 * primitive — any other tenant's worker. Here the store enforces scope on every
 * read, and each action loads before it writes.
 */
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import { StoreConflictError, type StoreRecord } from "../ports.js";
import { adminItem } from "../responses.js";
import { type TenantWorkerRepository, openTenantWorkerRepository } from "../store/tenant-worker.js";
import {
  type TransportCredential,
  mintTransportCredential,
  projectWorkerRegistration,
  readWorkerRegistration,
  registrationBlocker,
  stripCredentialFields,
  workerRegistrationDocument,
} from "../store/worker_registry.js";
import {
  type CollectionSpec,
  type GroupModule,
  type Handler,
  actionHandler,
  adminRecordSchema,
  crudGroup,
  depsOf,
  json,
  pathParam,
  readJson,
  readOnlyCollection,
  resolveSpec,
  scopeOf,
  subListHandler,
} from "./resource.js";

const WORKERS = "self-hosted-workers";
const EVENTS = "self-hosted-worker-events";
const ARTIFACTS = "self-hosted-worker-artifacts";
const CHECKPOINTS = "self-hosted-worker-checkpoints";

export const selfHostedWorkerSchema = adminRecordSchema.extend({
  name: z.string().trim().min(1).optional(),
  workspace_id: z.string().trim().min(1).nullish(),
  status: z.enum(["active", "inactive", "draining"]).optional(),
});

/** Shared with `admin_overview`, which serves `POST /admin/v1/status` onto it. */
export const SELF_HOSTED_WORKER_SPEC: CollectionSpec = {
  segment: WORKERS,
  object: "self_hosted_worker",
  body: selfHostedWorkerSchema,
};

export const workerEventSchema = z
  .object({
    event_id: z.string().trim().min(1).optional(),
    kind: z.string().trim().min(1).optional(),
    payload: z.record(z.unknown()).optional(),
  })
  .passthrough();

export const workerArtifactSchema = z
  .object({
    artifact_id: z.string().trim().min(1).optional(),
    uri: z.string().trim().min(1).optional(),
    sha256: z.string().trim().min(1).optional(),
  })
  .passthrough();

export const workerCheckpointSchema = z
  .object({
    checkpoint_id: z.string().trim().min(1).optional(),
    run_id: z.string().trim().min(1).optional(),
  })
  .passthrough();

// ---------------------------------------------------------------------------
// The transport identity — the WRITE half of the agent-runtime registry
// ---------------------------------------------------------------------------

/**
 * The control database, or a `503` naming what is missing.
 *
 * A worker registration that wrote only the document would be a worker the
 * operator can SEE and that authenticates NOBODY — precisely the state
 * `apps/agent-runtime`'s §8.1 marker described. Refusing is the honest answer:
 * an operator can act on "no control database bound", not on a 201 whose
 * credential silently does nothing.
 */
function controlDatabaseOr503(c: Parameters<Handler>[0]): D1Database {
  const db = depsOf(c).controlDatabase;
  if (db === null) {
    throw new HttpError(
      503,
      "control_database_unavailable",
      "self-hosted worker transport identities require the control database (bind [[d1_databases]] DB, or this deployment cannot provision one)",
    );
  }
  return db;
}

/**
 * Write the typed registry row for a stored worker document.
 *
 * The document is ALREADY stored when this runs — see the ordering table in
 * `store/worker_registry.ts` for why that direction is the safe one.
 */
async function provision(
  db: D1Database,
  record: StoreRecord,
  credential: TransportCredential,
): Promise<void> {
  await projectWorkerRegistration(
    db,
    workerRegistrationDocument(record, credential, Math.floor(Date.now() / 1000)),
  );
}

function tenantIdOf(record: StoreRecord): string | null {
  return typeof record.tenant_id === "string" && record.tenant_id.trim() !== ""
    ? record.tenant_id.trim()
    : null;
}

async function tenantWorkerRepository(
  c: Parameters<Handler>[0],
  record: StoreRecord,
): Promise<TenantWorkerRepository | null> {
  const tenantId = tenantIdOf(record);
  if (tenantId === null) return null;
  const deps = depsOf(c);
  // Worker state follows the tenant roster. `tenantStorage` is the provisioning
  // router and may default to Durable Objects even while this tenant still
  // lives on a native binding in a mixed-backend deployment.
  return openTenantWorkerRepository(deps.tenantDatabases, tenantId);
}

/**
 * Resolve a worker for an action. The object-local generic store is the normal
 * path; the bootstrap registry supplies the tenant id for a platform operator
 * whose request only carries the worker id. This avoids a fleet object scan and
 * keeps the registry as a lookup directory, not as the worker-state authority.
 */
async function visibleWorker(
  c: Parameters<Handler>[0],
  db: D1Database | null,
  scope: ReturnType<typeof scopeOf>,
  workerId: string,
): Promise<StoreRecord | null> {
  const deps = depsOf(c);
  const direct = await deps.store.get(WORKERS, scope, workerId);
  if (direct !== null || scope.kind !== "platform_operator") return direct;
  if (db === null) return null;

  const registration = await readWorkerRegistration(db, workerId);
  const tenantId = registration?.tenant_id?.trim();
  if (tenantId === undefined || tenantId === "") return null;
  return deps.store.get(WORKERS, { kind: "tenant", tenantId }, workerId);
}

function tenantWorkerIdentity(
  record: StoreRecord,
  credential: TransportCredential,
  nowUnix: number,
  registeredAtUnix = nowUnix,
): {
  readonly tenantId: string;
  readonly workerId: string;
  readonly workspaceId: string;
  readonly tokenId: string;
  readonly tokenSecret: string;
  readonly status: string;
  readonly document: StoreRecord;
  readonly registeredAtUnix: number;
  readonly updatedAtUnix: number;
} {
  const tenantId = tenantIdOf(record);
  const workspaceId = typeof record.workspace_id === "string" ? record.workspace_id.trim() : "";
  if (tenantId === null || workspaceId === "") {
    throw new HttpError(
      400,
      "invalid_request_body",
      "tenant_id and workspace_id are required for tenant worker state",
    );
  }
  return {
    tenantId,
    workerId: record.id,
    workspaceId,
    tokenId: credential.token_id,
    tokenSecret: credential.token_secret,
    status: typeof record.status === "string" ? record.status : "active",
    document: { ...stripCredentialFields(record), id: record.id },
    registeredAtUnix,
    updatedAtUnix: nowUnix,
  };
}

/**
 * Backfill the tenant identity for a worker created before #856.
 *
 * The control registry remains the bootstrap directory, so it has the
 * credential needed to reconstruct the object row. Refuse a missing or
 * mismatched directory entry before creating the child projection; otherwise a
 * child could be visible in the compatibility collection while its authoritative
 * tenant row was rejected.
 */
async function hydrateTenantWorkerIdentity(
  db: D1Database | null,
  repository: TenantWorkerRepository,
  record: StoreRecord,
  nowUnix: number,
): Promise<void> {
  if (db === null) {
    throw new HttpError(
      503,
      "control_database_unavailable",
      "tenant worker identity hydration requires the control database",
    );
  }
  const registration = await readWorkerRegistration(db, record.id);
  const tenantId = tenantIdOf(record);
  const workspaceId = typeof record.workspace_id === "string" ? record.workspace_id.trim() : "";
  if (
    registration === null ||
    registration.tenant_id !== tenantId ||
    registration.workspace_id !== workspaceId
  ) {
    throw new HttpError(
      409,
      "conflict",
      `self-hosted worker ${record.id} has no matching bootstrap identity`,
    );
  }
  await repository.upsertIdentity(
    tenantWorkerIdentity(
      record,
      { token_id: registration.token_id, token_secret: registration.token_secret },
      nowUnix,
      registration.registered_at_unix,
    ),
  );
}

const WORKER_SPEC = resolveSpec(SELF_HOSTED_WORKER_SPEC);

/**
 * `POST /admin/v1/self-hosted-workers` — Rust
 * `AgentRuntimeState::register_self_hosted_worker`.
 *
 * Mints a transport credential, stores the document WITHOUT the secret, writes
 * the typed registry row WITH it, and returns the secret exactly ONCE. Every
 * later read of this worker (`GET`, `list`) carries `token_id` and never
 * `transport_token_secret` — a caller that loses it rotates rather than
 * re-reads, which is what makes rotation the only way to obtain a working
 * secret and therefore auditable.
 */
export const registerSelfHostedWorkerHandler: Handler = async (c) => {
  const deps = depsOf(c);
  const db = controlDatabaseOr503(c);
  const body = (await readJson(c, WORKER_SPEC.body)) as Record<string, unknown>;
  const declaredId = body[WORKER_SPEC.idField];
  const id =
    typeof declaredId === "string" && declaredId.trim() !== ""
      ? declaredId.trim()
      : crypto.randomUUID();

  const credential = mintTransportCredential();
  // `stripCredentialFields` first: `adminRecordSchema` is `passthrough()`, so an
  // operator-supplied `token_secret` would otherwise be stored in a document
  // every `admin.read` caller can list.
  const record: StoreRecord = {
    ...stripCredentialFields(body),
    [WORKER_SPEC.idField]: id,
    id,
    token_id: credential.token_id,
  };
  const blocker = registrationBlocker(record);
  if (blocker !== null) throw new HttpError(400, "invalid_request_body", blocker);
  const existingRegistration = await readWorkerRegistration(db, id);
  const workspaceId = typeof record.workspace_id === "string" ? record.workspace_id.trim() : "";
  if (
    existingRegistration !== null &&
    (existingRegistration.tenant_id !== tenantIdOf(record) ||
      existingRegistration.workspace_id !== workspaceId)
  ) {
    throw new HttpError(
      409,
      "conflict",
      `self-hosted worker ${id} is already registered for another tenant or workspace`,
    );
  }

  let stored: StoreRecord;
  try {
    stored = await deps.store.create(WORKER_SPEC.collection, scopeOf(c), record);
  } catch (error) {
    if (error instanceof StoreConflictError) {
      throw new HttpError(409, "conflict", `${WORKER_SPEC.object} ${id} already exists`);
    }
    throw error;
  }
  const now = Math.floor(Date.now() / 1000);
  const tenantRepository = await tenantWorkerRepository(c, stored);
  if (tenantRepository !== null) {
    await tenantRepository.upsertIdentity(tenantWorkerIdentity(stored, credential, now));
  }
  await provision(db, stored, credential);
  return json(c, 201, {
    ...adminItem(WORKER_SPEC.object, stored),
    // Rust returns the provisioned secret to the caller exactly once, here.
    transport_token_secret: credential.token_secret,
  });
};

/**
 * `POST /admin/v1/self-hosted-workers/{id}/rotate` — Rust
 * `rotate_self_hosted_worker_identity`.
 *
 * Rotation is the takeover primitive issue #186 was about, so the worker is
 * loaded through the SCOPED store read first: a tenant naming another tenant's
 * worker gets `404`, never a rotated credential.
 *
 * A rotation mints a FRESH `token_secret` as well as a new fingerprint. That is
 * the point rather than a detail — rotating the fingerprint alone would leave a
 * leaked secret working, so the response is a remediation only because the
 * secret changes with it. Returned once, alongside the previous fingerprint so
 * an operator can correlate what was replaced.
 */
export const rotateSelfHostedWorkerIdentityHandler: Handler = async (c) => {
  const deps = depsOf(c);
  const db = controlDatabaseOr503(c);
  const scope = scopeOf(c);
  const id = pathParam(c, "id");
  const existing = await visibleWorker(c, db, scope, id);
  if (existing === null) {
    throw new HttpError(404, "not_found", `self-hosted worker ${id} not found`);
  }
  const workerScope =
    scope.kind === "platform_operator" && tenantIdOf(existing) !== null
      ? { kind: "tenant" as const, tenantId: tenantIdOf(existing) as string }
      : scope;
  const previous = await readWorkerRegistration(db, id);
  const now = Math.floor(Date.now() / 1000);
  const credential = mintTransportCredential();
  const stored = await deps.store.merge(WORKER_SPEC.collection, workerScope, id, {
    identity_fingerprint: crypto.randomUUID(),
    identity_rotated_at: now,
    token_id: credential.token_id,
  });
  if (stored === null) {
    throw new HttpError(404, "not_found", `self-hosted worker ${id} not found`);
  }
  const tenantRepository = await tenantWorkerRepository(c, stored);
  if (tenantRepository !== null) {
    await tenantRepository.upsertIdentity(
      tenantWorkerIdentity(
        stored,
        credential,
        now,
        typeof previous?.registered_at_unix === "number" ? previous.registered_at_unix : now,
      ),
    );
  }
  await provision(db, stored, credential);
  return json(c, 200, {
    object: "self_hosted_worker_identity_rotation",
    [WORKER_SPEC.object]: stored,
    transport_token_secret: credential.token_secret,
    previous_identity_fingerprint: previous?.identity_fingerprint ?? null,
    previous_identity_expires_at_unix: previous?.identity_expires_at_unix ?? null,
  });
};

/**
 * `POST /admin/v1/self-hosted-workers/{id}/heartbeat`.
 *
 * The heartbeat writes `status: "active"`, and `active` on the registry row is
 * DERIVED from that status — so the row has to be re-projected or the admin
 * document and the credential row disagree about whether the worker may take
 * work. The credential itself is PRESERVED (read back and re-written): a
 * heartbeat is not a rotation, and minting a new secret here would break the
 * running worker that just sent it.
 */
export const heartbeatSelfHostedWorkerHandler: Handler = async (c) => {
  const deps = depsOf(c);
  const db = controlDatabaseOr503(c);
  const scope = scopeOf(c);
  const id = pathParam(c, "id");
  const existing = await visibleWorker(c, db, scope, id);
  if (existing === null) {
    throw new HttpError(404, "not_found", `self-hosted worker ${id} not found`);
  }
  const workerScope =
    scope.kind === "platform_operator" && tenantIdOf(existing) !== null
      ? { kind: "tenant" as const, tenantId: tenantIdOf(existing) as string }
      : scope;
  const now = Math.floor(Date.now() / 1000);
  const stored = await deps.store.merge(WORKER_SPEC.collection, workerScope, id, {
    last_heartbeat_at: now,
    status: "active",
  });
  if (stored === null) {
    throw new HttpError(404, "not_found", `self-hosted worker ${id} not found`);
  }
  const registration = await readWorkerRegistration(db, id);
  const tenantRepository = await tenantWorkerRepository(c, stored);
  if (tenantRepository !== null) {
    // A typed tenant worker cannot acknowledge a heartbeat until its bootstrap
    // directory can reconstruct the authoritative object identity.
    await hydrateTenantWorkerIdentity(db, tenantRepository, stored, now);
    await tenantRepository.recordHeartbeat(
      id,
      { id: crypto.randomUUID(), worker_id: id, status: "active", last_heartbeat_at: now },
      now,
    );
  }
  if (registration !== null) {
    await provision(db, stored, {
      token_id: registration.token_id,
      token_secret: registration.token_secret,
    });
  }
  return json(c, 200, adminItem(WORKER_SPEC.object, stored));
};

/**
 * Append a child row under a worker the caller can actually see. Returns 404
 * (never 403) when the worker belongs to another tenant — the same
 * indistinguishability the read paths use.
 */
function appendChild(
  collection: string,
  object: string,
  schema: z.ZodTypeAny,
  writeTenantState: (
    repository: TenantWorkerRepository,
    workerId: string,
    record: StoreRecord,
    nowUnix: number,
  ) => Promise<void>,
): Handler {
  return async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const workerId = pathParam(c, "id");
    const db = deps.controlDatabase;
    const parent = await visibleWorker(c, db, scope, workerId);
    if (parent === null) {
      throw new HttpError(404, "not_found", `self-hosted worker ${workerId} not found`);
    }
    const body = (await readJson(c, schema)) as Record<string, unknown>;
    const now = Math.floor(Date.now() / 1000);
    const childScope =
      scope.kind === "platform_operator" && tenantIdOf(parent) !== null
        ? { kind: "tenant" as const, tenantId: tenantIdOf(parent) as string }
        : scope;
    const tenantRepository = await tenantWorkerRepository(c, parent);
    if (tenantRepository !== null) {
      await hydrateTenantWorkerIdentity(db, tenantRepository, parent, now);
    }
    const stored = await deps.store.create(collection, childScope, {
      ...body,
      ...(tenantIdOf(parent) === null ? {} : { tenant_id: tenantIdOf(parent) }),
      id: crypto.randomUUID(),
      worker_id: workerId,
      recorded_at: now,
    });
    const storedTenantRepository = await tenantWorkerRepository(c, stored);
    if (storedTenantRepository !== null) {
      await writeTenantState(storedTenantRepository, workerId, stored, now);
    }
    return json(c, 201, { object, [object]: stored });
  };
}

export const selfHostedWorkerRoutes: GroupModule = crudGroup(
  "self_hosted_worker",
  [
    SELF_HOSTED_WORKER_SPEC,
    readOnlyCollection("self-hosted-worker-records", "self_hosted_worker_record"),
  ],
  {
    registerSelfHostedWorker: registerSelfHostedWorkerHandler,
    recordAdminSelfHostedWorkerHeartbeat: heartbeatSelfHostedWorkerHandler,
    rotateAdminSelfHostedWorkerIdentity: rotateSelfHostedWorkerIdentityHandler,

    recordAdminSelfHostedWorkerArtifact: appendChild(
      ARTIFACTS,
      "self_hosted_worker_artifact",
      workerArtifactSchema,
      (repository, workerId, record, now) => repository.recordArtifact(workerId, record, now),
    ),
    recordAdminSelfHostedWorkerCheckpoint: appendChild(
      CHECKPOINTS,
      "self_hosted_worker_checkpoint",
      workerCheckpointSchema,
      (repository, workerId, record, now) => repository.recordCheckpoint(workerId, record, now),
    ),
    recordAdminSelfHostedWorkerTelemetryEvent: appendChild(
      EVENTS,
      "self_hosted_worker_event",
      workerEventSchema,
      (repository, workerId, record, now) => repository.recordTelemetry(workerId, record, now),
    ),

    listAdminSelfHostedWorkerTelemetryEvents: subListHandler({
      parent: SELF_HOSTED_WORKER_SPEC,
      parentParam: "id",
      collection: EVENTS,
      parentField: "worker_id",
    }),
  },
);
