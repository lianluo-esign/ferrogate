/**
 * The six `auth.kind: "internal"` worker-plane callbacks.
 *
 * `POST /v1/self-hosted-workers/{heartbeat,events,artifacts,checkpoints,
 * runs/poll,runs/ack}` — clean-room port of
 * `crates/ferrogate-gateway/src/server/local.rs::handle_self_hosted_worker_transport`
 * plus the decision logic in
 * `crates/ferrogate-runtime/src/self_hosted_worker.rs`.
 *
 * ## The security invariant
 *
 * A normal tenant bearer key must NOT be able to call any of these. Nothing in
 * this file reads `Authorization` or `x-api-key`; the caller has already been
 * resolved to a {@link RegisteredSelfHostedWorker} by the INTERNAL leg of
 * `middleware/auth.ts`, which is the only consumer of the worker-plane
 * credential authority. A handler here reads `c.get("worker")` and nothing
 * else, so there is no path by which a tenant credential reaches this code.
 *
 * ## Trust level
 *
 * Everything a worker reports is stamped `reported_by_self_hosted_worker` —
 * Rust's `SelfHostedTelemetryTrustLevel` has exactly one variant, and it is not
 * "trusted". The gateway records what the worker CLAIMS, attributed as such.
 */
import { Hono } from "hono";
import { depsOrThrow } from "../middleware/auth.js";
import { HttpError } from "../middleware/errors.js";
import {
  type AgentRuntimeEnv,
  type RegisteredSelfHostedWorker,
  SELF_HOSTED_WORKER_PROTOCOL_VERSION,
} from "../ports.js";
import { runStateStub, workerPlaneStub } from "../runs/addressing.js";
import { workerReportedRunState } from "../runs/model.js";
import {
  ACK_STATUSES,
  RUN_ACTIONS,
  type SelfHostedRunAckStatus,
  type SelfHostedRunAction,
  TRUST_LEVEL,
} from "./plane.js";

export const workerRoutes = new Hono<AgentRuntimeEnv>();

// ---------------------------------------------------------------------------
// Shared validation (Rust `validate_*`)
// ---------------------------------------------------------------------------

function invalidTransport(message: string): HttpError {
  return new HttpError(400, "invalid_self_hosted_worker_transport", message);
}

function invalidTelemetry(message: string): HttpError {
  return new HttpError(400, "invalid_self_hosted_worker_telemetry", message);
}

/** Rust `validate_worker_protocol_version`. Absent is treated as v1. */
function requireProtocolVersion(body: Record<string, unknown>): void {
  const declared = body.protocol_version;
  if (declared === undefined) return;
  if (declared !== SELF_HOSTED_WORKER_PROTOCOL_VERSION) {
    throw invalidTransport(
      `unsupported self-hosted worker protocol_version ${String(declared)}; expected ${SELF_HOSTED_WORKER_PROTOCOL_VERSION}`,
    );
  }
}

/** Rust `require_transport_non_empty` / `require_telemetry_non_empty`. */
function requireNonEmpty(
  body: Record<string, unknown>,
  field: string,
  fail: (message: string) => HttpError,
): string {
  const value = body[field];
  if (typeof value !== "string" || value.trim() === "") {
    throw fail(`${field} must not be empty`);
  }
  return value;
}

/** Rust: `reported_at_unix == 0` is a refusal, not a default. */
function requirePositiveUnix(
  body: Record<string, unknown>,
  field: string,
  fail: (message: string) => HttpError,
): number {
  const value = body[field];
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
    throw fail(`${field} must be greater than zero`);
  }
  return value;
}

function optionalStringList(
  body: Record<string, unknown>,
  field: string,
  fail: (message: string) => HttpError,
): readonly string[] {
  const value = body[field];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw fail(`${field} must be an array of strings`);
  }
  if ((value as string[]).some((item) => item.trim() === "")) {
    throw fail(`${field} must not contain empty values`);
  }
  return value as readonly string[];
}

/**
 * The PLAINTEXT transport document.
 *
 * `middleware/auth.ts` already read, size-checked, and — for a sealed
 * `symmetric_aead` frame — DECRYPTED the body, publishing the result as
 * `workerEnvelope`. Reading that is not an optimisation: on the sealed path the
 * raw request bytes are ciphertext, so re-parsing `c.req.text()` would hand
 * every handler `{ sealed: … }` and fail every field check.
 *
 * The raw-body fallback stays for the (test-only) case of a handler reached
 * without the middleware; Hono caches the parsed body, so it does not re-read
 * the stream.
 */
async function envelope(c: {
  req: { text(): Promise<string> };
  get(key: "workerEnvelope"): Record<string, unknown> | undefined;
}): Promise<Record<string, unknown>> {
  const published = c.get("workerEnvelope");
  if (published !== undefined) return published;
  const raw = await c.req.text();
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    throw invalidTransport("self-hosted worker transport body must be JSON");
  }
}

/**
 * The authenticated worker. `undefined` here would be a routing bug — an
 * internal route reached without the internal auth leg — so it fails closed
 * rather than serving anonymously.
 */
function requireWorker(c: {
  get(key: "worker"): RegisteredSelfHostedWorker | undefined;
}): RegisteredSelfHostedWorker {
  const worker = c.get("worker");
  if (worker === undefined) {
    throw new HttpError(
      401,
      "invalid_self_hosted_worker_identity",
      "self-hosted worker identity was not established",
    );
  }
  return worker;
}

// ---------------------------------------------------------------------------
// POST /v1/self-hosted-workers/heartbeat
// ---------------------------------------------------------------------------

/** `recordSelfHostedWorkerHeartbeat`. Rust answers 201 Created. */
workerRoutes.post("/v1/self-hosted-workers/heartbeat", async (c) => {
  const worker = requireWorker(c);
  const body = await envelope(c);
  requireProtocolVersion(body);
  const status = requireNonEmpty(body, "status", invalidTelemetry);
  const reportedAtUnix = requirePositiveUnix(body, "reported_at_unix", invalidTelemetry);

  return c.json(
    {
      object: "self_hosted_worker_heartbeat",
      worker: {
        worker_id: worker.worker_id,
        tenant_id: worker.tenant_id,
        workspace_id: worker.workspace_id,
        framework_adapter: worker.framework_adapter,
        capabilities: worker.capabilities,
      },
      heartbeat: {
        worker_id: worker.worker_id,
        tenant_id: worker.tenant_id,
        workspace_id: worker.workspace_id,
        status,
        reported_at_unix: reportedAtUnix,
      },
      request_id: c.get("requestId") ?? "",
    },
    201,
  );
});

// ---------------------------------------------------------------------------
// POST /v1/self-hosted-workers/events
// ---------------------------------------------------------------------------

/** Rust `SelfHostedTelemetryKind`. */
const TELEMETRY_KINDS = [
  "lifecycle",
  "log",
  "tool_call",
  "mcp_call",
  "cli_command",
  "skill_invocation",
  "artifact",
  "checkpoint",
  "usage",
] as const;

/**
 * `recordSelfHostedWorkerEvent` — the worker→gateway telemetry bridge.
 *
 * This is also the seam that makes an agent job ever become TERMINAL: a
 * lifecycle event carrying a recognized run state is projected onto the SAME
 * run row and timeline `/v1/agent-jobs/{run_id}` reads, so `/result` returns
 * the runtime's real output rather than a permanent
 * `409 agent_job_not_terminal`. An UNRECOGNIZED lifecycle word leaves the run
 * exactly as it was — never guessed into a state the caller would then collect.
 */
workerRoutes.post("/v1/self-hosted-workers/events", async (c) => {
  const worker = requireWorker(c);
  const body = await envelope(c);
  requireProtocolVersion(body);
  const deps = depsOrThrow(c);
  const limits = deps.config.agentRuntime();

  const sessionId = requireNonEmpty(body, "session_id", invalidTelemetry);
  const runId = requireNonEmpty(body, "run_id", invalidTelemetry);
  const eventId = requireNonEmpty(body, "event_id", invalidTelemetry);
  const reportedAtUnix = requirePositiveUnix(body, "reported_at_unix", invalidTelemetry);

  const kind = body.kind;
  if (typeof kind !== "string" || !(TELEMETRY_KINDS as readonly string[]).includes(kind)) {
    throw invalidTelemetry(`kind must be one of ${TELEMETRY_KINDS.join(", ")}`);
  }

  const eventBody = body.event_json ?? body.body ?? {};
  const payloadBytes = new TextEncoder().encode(JSON.stringify(eventBody)).length;
  if (payloadBytes > limits.telemetryMaxPayloadBytes) {
    throw invalidTelemetry(
      `payload exceeds maximum size of ${limits.telemetryMaxPayloadBytes} bytes`,
    );
  }

  // A worker that sends a JSON *string* is normalized to the parsed document,
  // so both dialects reach `workerReportedRunState` identically.
  const parsedBody =
    typeof eventBody === "string"
      ? (() => {
          try {
            return JSON.parse(eventBody) as unknown;
          } catch {
            return { message: eventBody };
          }
        })()
      : eventBody;

  const stub = runStateStub(c.env, worker.tenant_id, runId);
  const correlation = {
    workerId: worker.worker_id,
    requestId: (body.request_id as string | undefined) ?? null,
    traceId: (body.trace_id as string | undefined) ?? null,
    agentRunId: (body.agent_run_id as string | undefined) ?? runId,
    parentActionFingerprint: (body.parent_action_fingerprint as string | undefined) ?? null,
  };

  await stub.recordWorkerEvidence(worker.tenant_id, {
    kind,
    body: { event_id: eventId, session_id: sessionId, ...(typeof parsedBody === "object" && parsedBody !== null ? parsedBody : { value: parsedBody }) },
    nowUnix: reportedAtUnix,
    source: "self_hosted_worker",
    ...correlation,
  });

  const reported = workerReportedRunState(kind, parsedBody);
  if (reported !== undefined) {
    await stub.applyWorkerReportedState(worker.tenant_id, reported, {
      nowUnix: reportedAtUnix,
      ...correlation,
    });
  }

  return c.json(
    {
      object: "self_hosted_worker_event",
      event: {
        tenant_id: worker.tenant_id,
        workspace_id: worker.workspace_id,
        worker_id: worker.worker_id,
        session_id: sessionId,
        run_id: runId,
        event_id: eventId,
        kind,
        trust_level: TRUST_LEVEL,
        reported_at_unix: reportedAtUnix,
      },
      // `null` when the word was not a recognized lifecycle state: the run was
      // left alone rather than guessed into a state.
      applied_run_status: reported?.status ?? null,
      request_id: c.get("requestId") ?? "",
    },
    201,
  );
});

// ---------------------------------------------------------------------------
// POST /v1/self-hosted-workers/artifacts
// ---------------------------------------------------------------------------

/** Rust `InMemorySelfHostedWorkerTransport::max_artifact_bytes` default. */
const MAX_ARTIFACT_BYTES = 32 * 1024 * 1024;

/** `uploadSelfHostedWorkerArtifact`. */
workerRoutes.post("/v1/self-hosted-workers/artifacts", async (c) => {
  const worker = requireWorker(c);
  const body = await envelope(c);
  requireProtocolVersion(body);

  const sessionId = requireNonEmpty(body, "session_id", invalidTelemetry);
  const runId = requireNonEmpty(body, "run_id", invalidTelemetry);
  const artifactId = requireNonEmpty(body, "artifact_id", invalidTelemetry);
  const name = requireNonEmpty(body, "name", invalidTelemetry);
  const mediaType = requireNonEmpty(body, "media_type", invalidTelemetry);
  const reportedAtUnix = requirePositiveUnix(body, "reported_at_unix", invalidTelemetry);

  const byteLen = body.byte_len;
  if (typeof byteLen !== "number" || !Number.isInteger(byteLen) || byteLen <= 0) {
    throw invalidTelemetry("artifact byte_len must be greater than zero");
  }
  if (byteLen > MAX_ARTIFACT_BYTES) {
    throw invalidTelemetry(`artifact exceeds maximum size of ${MAX_ARTIFACT_BYTES} bytes`);
  }

  const artifact = {
    tenant_id: worker.tenant_id,
    workspace_id: worker.workspace_id,
    worker_id: worker.worker_id,
    session_id: sessionId,
    run_id: runId,
    artifact_id: artifactId,
    name,
    media_type: mediaType,
    byte_len: byteLen,
    trust_level: TRUST_LEVEL,
    reported_at_unix: reportedAtUnix,
  };

  // The artifact rides the run timeline, which is where `/result` collects it
  // — a work product has no life outside its run, so it needs no parallel
  // store.
  //
  // This is AT PARITY with Rust and is not a deferral: the Rust transport type
  // `SelfHostedArtifactUpload` (`ferrogate-runtime/src/self_hosted_worker.rs`)
  // carries `artifact_id` / `name` / `media_type` / `byte_len` and NO bytes
  // either — the callback registers an artifact, it does not upload one. If a
  // future slice adds a byte-carrying upload verb, its home is R2
  // (`[[r2_buckets]] ARTIFACTS`, noted in `wrangler.toml`); nothing about the
  // reference recorded here changes when it does.
  await runStateStub(c.env, worker.tenant_id, runId).recordWorkerEvidence(worker.tenant_id, {
    kind: "artifact",
    body: artifact,
    nowUnix: reportedAtUnix,
    source: "self_hosted_worker",
    workerId: worker.worker_id,
    agentRunId: runId,
  });

  return c.json(
    { object: "self_hosted_worker_artifact", artifact, request_id: c.get("requestId") ?? "" },
    201,
  );
});

// ---------------------------------------------------------------------------
// POST /v1/self-hosted-workers/checkpoints
// ---------------------------------------------------------------------------

/** `uploadSelfHostedWorkerCheckpoint`. */
workerRoutes.post("/v1/self-hosted-workers/checkpoints", async (c) => {
  const worker = requireWorker(c);
  const body = await envelope(c);
  requireProtocolVersion(body);

  const sessionId = requireNonEmpty(body, "session_id", invalidTelemetry);
  const runId = requireNonEmpty(body, "run_id", invalidTelemetry);
  const checkpointId = requireNonEmpty(body, "checkpoint_id", invalidTelemetry);
  const createdAtUnix = requirePositiveUnix(body, "created_at_unix", invalidTelemetry);

  const checkpoint = {
    tenant_id: worker.tenant_id,
    workspace_id: worker.workspace_id,
    worker_id: worker.worker_id,
    session_id: sessionId,
    run_id: runId,
    checkpoint_id: checkpointId,
    checkpoint_name: (body.checkpoint_name as string | undefined) ?? null,
    size_bytes: typeof body.size_bytes === "number" ? body.size_bytes : null,
    created_at_unix: createdAtUnix,
    trust_level: TRUST_LEVEL,
  };

  await runStateStub(c.env, worker.tenant_id, runId).recordWorkerEvidence(worker.tenant_id, {
    kind: "checkpoint",
    body: checkpoint,
    nowUnix: createdAtUnix,
    source: "self_hosted_worker",
    workerId: worker.worker_id,
    agentRunId: runId,
  });

  return c.json(
    { object: "self_hosted_worker_checkpoint", checkpoint, request_id: c.get("requestId") ?? "" },
    201,
  );
});

// ---------------------------------------------------------------------------
// POST /v1/self-hosted-workers/runs/poll
// ---------------------------------------------------------------------------

/**
 * `pollSelfHostedWorkerRun` — lease the next dispatch for this worker.
 *
 * `200` with the lease, or **`204 No Content`** when nothing is leasable. The
 * 204 is load-bearing: a polling worker distinguishes "no work" from "work"
 * without parsing a body, exactly as Rust's `write_empty_response` does.
 */
workerRoutes.post("/v1/self-hosted-workers/runs/poll", async (c) => {
  const worker = requireWorker(c);
  const body = await envelope(c);
  requireProtocolVersion(body);
  const deps = depsOrThrow(c);

  const supportedCapabilities = optionalStringList(
    body,
    "supported_capabilities",
    invalidTransport,
  );
  // The worker's clock is accepted (Rust takes `now_unix` from the request),
  // but a missing/zero value falls back to the gateway clock rather than
  // leasing against epoch 0.
  const nowUnix =
    typeof body.now_unix === "number" && Number.isInteger(body.now_unix) && body.now_unix > 0
      ? body.now_unix
      : deps.clock.nowUnix();
  const leaseDurationSecs = body.lease_duration_secs;
  if (
    typeof leaseDurationSecs !== "number" ||
    !Number.isInteger(leaseDurationSecs) ||
    leaseDurationSecs <= 0
  ) {
    throw invalidTransport("lease_duration_secs must be greater than zero");
  }

  const plane = workerPlaneStub(c.env, worker.tenant_id, worker.workspace_id);
  const lease = await plane.poll(worker, { supportedCapabilities, nowUnix, leaseDurationSecs });
  if (lease === null) return c.body(null, 204);

  return c.json({ object: "self_hosted_run_lease", lease, request_id: c.get("requestId") ?? "" });
});

// ---------------------------------------------------------------------------
// POST /v1/self-hosted-workers/runs/ack
// ---------------------------------------------------------------------------

/**
 * `acknowledgeSelfHostedWorkerRun` — settle a leased dispatch.
 *
 * A settling ack (`completed` / `failed` / `cancelled`) is ALSO projected onto
 * the run row, which is what releases the submitter's open-job slot and makes
 * `/result` answer 200. `accepted` only confirms receipt: it moves the run to
 * `running` and settles nothing.
 */
workerRoutes.post("/v1/self-hosted-workers/runs/ack", async (c) => {
  const worker = requireWorker(c);
  const body = await envelope(c);
  requireProtocolVersion(body);
  const deps = depsOrThrow(c);

  const dispatchId = requireNonEmpty(body, "dispatch_id", invalidTransport);
  const leaseId = requireNonEmpty(body, "lease_id", invalidTransport);
  const runId = requireNonEmpty(body, "run_id", invalidTransport);
  const reportedAtUnix = requirePositiveUnix(body, "reported_at_unix", invalidTransport);

  const action = body.action;
  if (typeof action !== "string" || !(RUN_ACTIONS as readonly string[]).includes(action)) {
    throw invalidTransport(`action must be one of ${RUN_ACTIONS.join(", ")}`);
  }
  const status = body.status;
  if (typeof status !== "string" || !(ACK_STATUSES as readonly string[]).includes(status)) {
    throw invalidTransport(`status must be one of ${ACK_STATUSES.join(", ")}`);
  }

  const plane = workerPlaneStub(c.env, worker.tenant_id, worker.workspace_id);
  const result = await plane.ack(worker, {
    dispatchId,
    action: action as SelfHostedRunAction,
    leaseId,
    runId,
    status: status as SelfHostedRunAckStatus,
    reportedAtUnix,
  });
  if (result.outcome === "refused") {
    throw new HttpError(400, result.refusal.code, result.refusal.message);
  }

  // Project the ack onto the run. `accepted` means "I have the work" →
  // `running`; the other three settle the run.
  const runStatus =
    result.ack.status === "accepted"
      ? ("running" as const)
      : result.ack.status === "completed"
        ? ("completed" as const)
        : result.ack.status === "failed"
          ? ("failed" as const)
          : ("cancelled" as const);

  const stub = runStateStub(c.env, worker.tenant_id, runId);
  const output = typeof body.output === "string" && body.output !== "" ? body.output : undefined;
  const run = await stub.applyWorkerReportedState(
    worker.tenant_id,
    { status: runStatus, ...(output === undefined ? {} : { output }) },
    {
      nowUnix: reportedAtUnix,
      workerId: worker.worker_id,
      agentRunId: runId,
    },
  );

  // A settled run's dispatch rows become reclaimable (#502) — the retention
  // half of the open-job budget, so a healthy tenant is never locked out.
  if (run !== undefined && runStatus !== "running") {
    await plane.reclaimRun(runId);
  }
  void deps;

  return c.json({
    object: "self_hosted_run_ack",
    ack: result.ack,
    run_status: run?.status ?? null,
    request_id: c.get("requestId") ?? "",
  });
});
