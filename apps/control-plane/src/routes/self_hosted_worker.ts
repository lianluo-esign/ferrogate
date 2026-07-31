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
import {
  actionHandler,
  adminRecordSchema,
  crudGroup,
  json,
  pathParam,
  readJson,
  readOnlyCollection,
  scopeOf,
  subListHandler,
  type CollectionSpec,
  type GroupModule,
  type Handler,
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

/**
 * Append a child row under a worker the caller can actually see. Returns 404
 * (never 403) when the worker belongs to another tenant — the same
 * indistinguishability the read paths use.
 */
function appendChild(collection: string, object: string, schema: z.ZodTypeAny): Handler {
  return async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const workerId = pathParam(c, "id");
    if ((await deps.store.get(WORKERS, scope, workerId)) === null) {
      throw new HttpError(404, "not_found", `self-hosted worker ${workerId} not found`);
    }
    const body = (await readJson(c, schema)) as Record<string, unknown>;
    const stored = await deps.store.create(collection, scope, {
      ...body,
      id: crypto.randomUUID(),
      worker_id: workerId,
      recorded_at: Math.floor(Date.now() / 1000),
    });
    return json(c, 201, { object, [object]: stored });
  };
}

export const selfHostedWorkerRoutes: GroupModule = crudGroup(
  "self_hosted_worker",
  [SELF_HOSTED_WORKER_SPEC, readOnlyCollection("self-hosted-worker-records", "self_hosted_worker_record")],
  {
    recordAdminSelfHostedWorkerHeartbeat: actionHandler({
      spec: SELF_HOSTED_WORKER_SPEC,
      param: "id",
      apply: (_record, _body, now) => ({ last_heartbeat_at: now, status: "active" }),
    }),

    /**
     * Identity rotation — the takeover primitive issue #186 was about. It
     * mutates the worker's identity fingerprint, so it goes through the scoped
     * load like every other action rather than a bare-id lookup.
     */
    rotateAdminSelfHostedWorkerIdentity: actionHandler({
      spec: SELF_HOSTED_WORKER_SPEC,
      param: "id",
      apply: (_record, _body, now) => ({
        identity_fingerprint: crypto.randomUUID(),
        identity_rotated_at: now,
      }),
    }),

    recordAdminSelfHostedWorkerArtifact: appendChild(
      ARTIFACTS,
      "self_hosted_worker_artifact",
      workerArtifactSchema,
    ),
    recordAdminSelfHostedWorkerCheckpoint: appendChild(
      CHECKPOINTS,
      "self_hosted_worker_checkpoint",
      workerCheckpointSchema,
    ),
    recordAdminSelfHostedWorkerTelemetryEvent: appendChild(
      EVENTS,
      "self_hosted_worker_event",
      workerEventSchema,
    ),

    listAdminSelfHostedWorkerTelemetryEvents: subListHandler({
      parent: SELF_HOSTED_WORKER_SPEC,
      parentParam: "id",
      collection: EVENTS,
      parentField: "worker_id",
    }),
  },
);
