/**
 * The caller-facing run surface: `POST /v1/agent-runs` plus the async agent-job
 * protocol (`submit` / `status` / `events` / `result` / `cancel`, issue #474).
 *
 * Clean-room port of `crates/ferrogate-gateway/src/server/agent_jobs.rs` and
 * `server/agent_runs.rs`. The load-bearing properties, all preserved:
 *
 *  - **Idempotency is first-class.** The run id is DERIVED from
 *    `(tenant, idempotency key)` by {@link agentJobRunId}, so a retried submit
 *    ADDRESSES the same run by construction rather than minting a random id and
 *    hunting for a duplicate afterwards (which races). `deduplicated: true` +
 *    200 on a retry, `false` + 202 on the first submit, always the ORIGINAL id.
 *  - **Tenant isolation is applied before anything is shaped.** Runs are
 *    addressed through `runStateStub(env, tenantId, runId)`, so a cross-tenant
 *    run id resolves to an empty Durable Object and is reported **404, not
 *    403** — the surface is not an existence oracle.
 *  - **Concurrency admission and the enqueue are ONE operation.** Splitting
 *    them made the check a check-then-act; `WorkerPlane.admitAndEnqueue`
 *    recounts inside the method that performs the insert.
 *  - **Cancel is idempotent** and reports WHICH runtime remedy ran
 *    (`runtime_cancel_dispatched`), never whether the cancel took effect.
 */
import { Hono } from "hono";
import type { Context } from "hono";
import { agentJobRunId } from "../crypto.js";
import { depsOrThrow, requireAuth, tenantIdOf } from "../middleware/auth.js";
import { HttpError } from "../middleware/errors.js";
import type { AgentRuntimeEnv } from "../ports.js";
import type { SelfHostedRunDispatch } from "../workers/plane.js";
import { runStateStub, workerPlaneStub } from "./addressing.js";
import { SSE_HEADERS, clampEventLimit, resumeCursor, wantsEventStream } from "./events.js";
import {
  authorizeOrThrow,
  declaredAgentRunId,
  declaredParentActionFingerprint,
  idempotencyKey,
  isAddressableRunId,
} from "./governance.js";
import { SUBMITTED_INPUT_EVIDENCE_MAX_CHARS, isTerminalStatus, truncate } from "./model.js";
import type { StoredAgentRun } from "./model.js";

/**
 * Dispatch-id namespace of the START dispatches THIS surface mints — the only
 * thing that distinguishes a caller's submit from the other producers of
 * `start_run` dispatches sharing the queue (schedule fires, registration
 * seeds), so the submit budget can be scoped to work the caller asked for.
 */
export const AGENT_JOB_START_DISPATCH_PREFIX = "agent-job-start-";

/** Deterministic ids, so a racing double submit/cancel enqueues the SAME row. */
export function startDispatchId(runId: string): string {
  return `${AGENT_JOB_START_DISPATCH_PREFIX}${runId}`;
}
export function cancelDispatchId(runId: string): string {
  return `agent-job-cancel-${runId}`;
}

/**
 * What `runtime_cancel_dispatched` means, written ONCE (Rust #551 rework: it
 * had been written twice and the two copies disagreed).
 *
 * `true` when a `cancel_run` dispatch was handed to the runtime transport,
 * which happens whenever a `StartRun` dispatch exists but the serving node
 * could not withdraw an unleased copy from its own queue. `false` means no
 * `cancel_run` was emitted: the node withdrew its local unleased copy, no
 * `StartRun` existed, or the run was already terminal. The field reports WHICH
 * runtime remedy ran, never whether the cancel took effect — `cancelled`
 * reports whether THIS call terminalized the run.
 */
export const RUNTIME_CANCEL_DISPATCHED_DESCRIPTION =
  "true when a cancel_run dispatch was handed to the runtime transport, which happens whenever a StartRun dispatch exists but the serving node could not withdraw an unleased copy from its own queue. false means no cancel_run was emitted: the serving node withdrew its local unleased copy, no StartRun dispatch existed, or the run was already terminal. The field reports WHICH runtime remedy ran, never whether the cancel took effect — `cancelled` reports whether this call terminalized the run.";

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

interface SubmitRequest {
  readonly input: string;
  readonly idempotency_key?: unknown;
  readonly framework_adapter?: unknown;
  readonly required_capabilities?: unknown;
  readonly workload_ref?: unknown;
  readonly egress_allowlist?: unknown;
  readonly session_id?: unknown;
  readonly workspace_id?: unknown;
}

async function readJsonBody(
  c: Context<AgentRuntimeEnv>,
  maxBytes: number,
): Promise<Record<string, unknown>> {
  const declared = Number(c.req.header("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new HttpError(
      413,
      "payload_too_large",
      `request body exceeds maximum size of ${maxBytes} bytes`,
    );
  }
  const raw = await c.req.text();
  if (new TextEncoder().encode(raw).length > maxBytes) {
    throw new HttpError(
      413,
      "payload_too_large",
      `request body exceeds maximum size of ${maxBytes} bytes`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new HttpError(400, "invalid_json", `invalid agent request JSON: ${String(error)}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new HttpError(400, "invalid_request", "request body must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}

function requireStringList(value: unknown, field: string): readonly string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new HttpError(400, "invalid_request", `${field} must be an array of strings`);
  }
  return value as readonly string[];
}

function optionalString(value: unknown, field: string): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw new HttpError(400, "invalid_request", `${field} must be a string`);
  }
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
}

// ---------------------------------------------------------------------------
// Response shaping
// ---------------------------------------------------------------------------

function statusBody(run: StoredAgentRun, requestId: string): Record<string, unknown> {
  return {
    object: "agent_job",
    run_id: run.run_id,
    status: run.status,
    terminal: isTerminalStatus(run.status),
    provider: run.provider,
    turns_executed: run.turns_executed,
    output_recorded: run.output !== null,
    started_at_unix: run.started_at_unix,
    completed_at_unix: run.completed_at_unix,
    submitted_at_unix: run.submitted_at_unix,
    runtime_reported_state: run.runtime_reported_state,
    runtime_reported_event_count: run.runtime_reported_event_count,
    cancel_requested: run.cancel_requested,
    request_id: requestId,
  };
}

// ---------------------------------------------------------------------------
// The routes
// ---------------------------------------------------------------------------

export const runRoutes = new Hono<AgentRuntimeEnv>();

/** Guard every run verb behind the operator's `agent_runtime.enabled` flag. */
function requireRuntimeEnabled(enabled: boolean): void {
  if (!enabled) {
    throw new HttpError(
      403,
      "agent_runtime_disabled",
      "agent runtime is disabled by operator config",
    );
  }
}

/**
 * Shared create path for `POST /v1/agent-runs` (synchronous) and
 * `POST /v1/agent-jobs` (async). They address the SAME `agent_runs` evidence —
 * the async protocol adds caller-facing verbs on top of it rather than building
 * a parallel job stack.
 */
async function createRun(
  c: Context<AgentRuntimeEnv>,
  options: { readonly initialStatus: "queued" | "running"; readonly enqueueDispatch: boolean },
): Promise<Response> {
  const deps = depsOrThrow(c);
  const config = deps.config.agentRuntime();
  requireRuntimeEnabled(config.enabled);

  const auth = requireAuth(c);
  const tenantId = tenantIdOf(auth);
  const requestId = c.get("requestId") ?? "";
  const traceId = c.get("traceId") ?? null;

  const body = (await readJsonBody(c, config.agentIngressBodyMaxBytes)) as unknown as SubmitRequest;
  if (typeof body.input !== "string" || body.input.trim() === "") {
    throw new HttpError(400, "invalid_request", "input must be a non-empty string");
  }

  // #305/#307: declared correlation identity. Malformed is a 400 (never
  // persisted); absent records an explicit NULL — never fabricated.
  const declaredRunId = declaredAgentRunId(c.req.raw.headers);
  const parentActionFingerprint = declaredParentActionFingerprint(c.req.raw.headers);

  const workspaceId =
    optionalString(body.workspace_id, "workspace_id") ?? auth.tenancy.workspaceId ?? "default";
  const frameworkAdapter =
    optionalString(body.framework_adapter, "framework_adapter") ?? config.defaultFrameworkAdapter;
  const requiredCapabilities = requireStringList(
    body.required_capabilities,
    "required_capabilities",
  );
  const egressAllowlist = requireStringList(body.egress_allowlist, "egress_allowlist");
  const workloadRef = optionalString(body.workload_ref, "workload_ref");
  const sessionId = optionalString(body.session_id, "session_id") ?? `session-${requestId}`;

  // The governance chokepoint: capability envelope + isolation posture +
  // sealed-by-default egress. Refusals leave here verbatim.
  const grant = await authorizeOrThrow(deps.governance, {
    tenantId,
    workspaceId,
    frameworkAdapter,
    requiredCapabilities,
    egressAllowlist,
    parentActionFingerprint,
  });

  // Idempotency: the key derives the run id. A caller that supplies none gets a
  // fresh random key, so an un-keyed submit is a NEW job every time (it cannot
  // be retried safely, which is exactly what "no key" means).
  const key = idempotencyKey(c.req.raw.headers, body.idempotency_key);
  const effectiveKey = key?.key ?? crypto.randomUUID();
  const keySource = key?.source ?? "generated";
  // A declared `agent_run_id` addresses an EXISTING run rather than deriving a
  // new one — the caller is attaching work to a run it already holds.
  const runId = declaredRunId ?? (await agentJobRunId(tenantId, effectiveKey));

  const nowUnix = deps.clock.nowUnix();
  const stub = runStateStub(c.env, tenantId, runId);
  const created = await stub.create({
    runId,
    tenantId,
    workspaceId,
    frameworkAdapter,
    requiredCapabilities,
    workloadRef,
    idempotencyKey: effectiveKey,
    input: truncate(body.input, SUBMITTED_INPUT_EVIDENCE_MAX_CHARS),
    nowUnix,
    requestId,
    traceId,
    parentActionFingerprint,
    initialStatus: options.initialStatus,
  });

  // A retry of an existing key deduplicates BEFORE the budget is consulted, so
  // a caller can always re-poll and cancel what it already has.
  if (!created.deduplicated && options.enqueueDispatch) {
    const dispatch: SelfHostedRunDispatch = {
      dispatch_id: startDispatchId(runId),
      action: "start_run",
      tenant_id: tenantId,
      workspace_id: workspaceId,
      session_id: sessionId,
      run_id: runId,
      framework_adapter: frameworkAdapter,
      required_capabilities: requiredCapabilities,
      workload_ref: workloadRef ?? body.input,
      queued_at_unix: nowUnix,
      request_id: requestId === "" ? null : requestId,
      trace_id: traceId,
      // Normally equal to `run_id`, carried explicitly so lease/evidence joins
      // are uniform across tables (#305).
      agent_run_id: runId,
      parent_action_fingerprint: parentActionFingerprint,
    };
    const plane = workerPlaneStub(c.env, tenantId, workspaceId);
    const admission = await plane.admitAndEnqueue(dispatch, {
      openPrefix: AGENT_JOB_START_DISPATCH_PREFIX,
      maxOpen: config.maxOpenJobsPerTenant,
      ttlSecs: config.dispatchTtlSecs,
      nowUnix,
    });
    if (admission.outcome === "over_budget") {
      throw new HttpError(
        429,
        "agent_job_open_limit_reached",
        `tenant already has ${admission.open} agent jobs in flight (limit ${config.maxOpenJobsPerTenant}); a job stops counting as soon as its run reaches a terminal state, so wait for a running job to finish or release one now with POST /v1/agent-jobs/{run_id}/cancel`,
      );
    }
  }

  const base = `/v1/agent-jobs/${encodeURIComponent(runId)}`;
  return c.json(
    {
      object: options.initialStatus === "queued" ? "agent_job" : "agent_run",
      run_id: runId,
      status: created.run.status,
      idempotency_key: effectiveKey,
      idempotency_key_source: keySource,
      deduplicated: created.deduplicated,
      terminal: isTerminalStatus(created.run.status),
      submitted_at_unix: created.run.submitted_at_unix,
      // The isolation posture actually granted — evidence, and the honest
      // answer to "what could this workload reach".
      isolation: grant,
      status_url: base,
      events_url: `${base}/events`,
      result_url: `${base}/result`,
      request_id: requestId,
    },
    // `deduplicated` is the observable proof of idempotency: 202 the first
    // time, 200 on every retry of the same key.
    created.deduplicated ? 200 : 202,
  );
}

/** `POST /v1/agent-runs` — `createAgentRun`, scope `agents.invoke`. */
runRoutes.post("/v1/agent-runs", (c) =>
  createRun(c, { initialStatus: "running", enqueueDispatch: true }),
);

/** `POST /v1/agent-jobs` — `submitAgentJob`, scope `agent.runs.create`. */
runRoutes.post("/v1/agent-jobs", (c) =>
  createRun(c, { initialStatus: "queued", enqueueDispatch: true }),
);

/** Resolve `{run_id}` to a run in the caller's tenant, or 404. */
async function loadRun(
  c: Context<AgentRuntimeEnv>,
): Promise<{ readonly run: StoredAgentRun; readonly tenantId: string }> {
  const auth = requireAuth(c);
  const tenantId = tenantIdOf(auth);
  const runId = c.req.param("run_id") ?? "";
  // A malformed run id is a 404 for the same reason a cross-tenant one is: the
  // surface must not distinguish "does not exist" from "not yours".
  if (!isAddressableRunId(runId)) {
    throw new HttpError(404, "agent_job_not_found", "agent job was not found");
  }
  const run = await runStateStub(c.env, tenantId, runId).snapshot(tenantId);
  if (run === undefined) {
    throw new HttpError(404, "agent_job_not_found", "agent job was not found");
  }
  return { run, tenantId };
}

/** `GET /v1/agent-jobs/{run_id}` — `getAgentJob`, scope `agent.runs.read`. */
runRoutes.get("/v1/agent-jobs/:run_id", async (c) => {
  const deps = depsOrThrow(c);
  requireRuntimeEnabled(deps.config.agentRuntime().enabled);
  const { run } = await loadRun(c);
  return c.json(statusBody(run, c.get("requestId") ?? ""));
});

/**
 * `GET /v1/agent-jobs/{run_id}/events` — `listAgentJobEvents`,
 * scope `agent.runs.read`.
 *
 * Two representations of the SAME timeline, selected by `Accept`:
 *  - `text/event-stream` → the live SSE feed, backlog-replayed from the cursor
 *    then streamed, terminated by `[DONE]` when the run settles. This is the
 *    streaming surface `ROUTE-MAP.md` names.
 *  - anything else → the Rust cursored JSON page, so an existing client that
 *    polls with `after_event_id` keeps working unchanged.
 */
runRoutes.get("/v1/agent-jobs/:run_id/events", async (c) => {
  const deps = depsOrThrow(c);
  requireRuntimeEnabled(deps.config.agentRuntime().enabled);
  const { run, tenantId } = await loadRun(c);
  const url = new URL(c.req.url);
  const cursor = resumeCursor(c.req.raw.headers, url.searchParams);

  if (wantsEventStream(c.req.raw.headers)) {
    const stub = runStateStub(c.env, tenantId, run.run_id);
    const streamUrl = new URL("https://agent-run-state.internal/events");
    streamUrl.searchParams.set("tenant_id", tenantId);
    if (cursor !== null) streamUrl.searchParams.set("after_event_id", cursor);
    const upstream = await stub.fetch(streamUrl.toString());
    if (upstream.body === null) {
      throw new HttpError(500, "internal_error", "run event stream is unavailable");
    }
    // Preserve the upstream framing byte for byte — the body is passed
    // through, never re-encoded.
    return new Response(upstream.body, { status: 200, headers: { ...SSE_HEADERS } });
  }

  const page = await runStateStub(c.env, tenantId, run.run_id).listEvents(tenantId, {
    afterEventId: cursor,
    limit: clampEventLimit(url.searchParams.get("limit")),
  });
  if (page === undefined) {
    throw new HttpError(404, "agent_job_not_found", "agent job was not found");
  }
  return c.json({
    object: "list",
    run_id: run.run_id,
    data: page.data,
    limit: page.limit,
    after_event_id: page.afterEventId,
    next_after_event_id: page.nextAfterEventId,
    has_more: page.hasMore,
    cursor_reset: page.cursorReset,
    request_id: c.get("requestId") ?? "",
  });
});

/**
 * `GET /v1/agent-jobs/{run_id}/result` — `getAgentJobResult`,
 * scope `agent.runs.read`.
 *
 * Answers 200 only in a terminal state; a still-running job is
 * `409 agent_job_not_terminal`, which is what makes the worker→gateway bridge
 * (`applyWorkerReportedState`) load-bearing rather than decorative.
 */
runRoutes.get("/v1/agent-jobs/:run_id/result", async (c) => {
  const deps = depsOrThrow(c);
  requireRuntimeEnabled(deps.config.agentRuntime().enabled);
  const { run, tenantId } = await loadRun(c);
  if (!isTerminalStatus(run.status)) {
    throw new HttpError(
      409,
      "agent_job_not_terminal",
      `agent job is ${run.status}; the result is available once the run reaches a terminal state`,
    );
  }
  const page = await runStateStub(c.env, tenantId, run.run_id).listEvents(tenantId, {
    afterEventId: null,
    limit: 500,
  });
  const artifacts = (page?.data ?? [])
    .filter((event) => event.kind === "artifact" || event.kind === "checkpoint")
    .map((event) => ({
      id: event.id,
      kind: event.kind,
      worker_id: event.worker_id,
      occurred_at_unix: event.occurred_at_unix,
      event_json: event.event_json,
    }));

  return c.json({
    object: "agent_job_result",
    run_id: run.run_id,
    status: run.status,
    terminal: true,
    turns_executed: run.turns_executed,
    output_recorded: run.output !== null,
    // `null` is honest absence — nothing is fabricated.
    output: run.output,
    artifacts,
    completed_at_unix: run.completed_at_unix,
    request_id: c.get("requestId") ?? "",
  });
});

/**
 * `POST /v1/agent-jobs/{run_id}/cancel` — `cancelAgentJob`,
 * scope `agent.runs.create` (starting and stopping tenant-billed work is the
 * same privilege).
 */
runRoutes.post("/v1/agent-jobs/:run_id/cancel", async (c) => {
  const deps = depsOrThrow(c);
  const config = deps.config.agentRuntime();
  requireRuntimeEnabled(config.enabled);
  const { run, tenantId } = await loadRun(c);
  const nowUnix = deps.clock.nowUnix();
  const requestId = c.get("requestId") ?? "";

  const outcome = await runStateStub(c.env, tenantId, run.run_id).cancel(tenantId, {
    nowUnix,
    requestId: requestId === "" ? null : requestId,
  });
  if (outcome === undefined) {
    throw new HttpError(404, "agent_job_not_found", "agent job was not found");
  }

  // The runtime remedy. Try to withdraw the unleased start dispatch first; if a
  // worker already holds it (or only a durable copy is visible), emit a
  // `cancel_run` the runtime will lease instead.
  const plane = workerPlaneStub(c.env, tenantId, run.workspace_id);
  const startId = startDispatchId(run.run_id);
  let runtimeCancelDispatched = false;
  if (outcome.cancelled && (await plane.hasDispatch(startId))) {
    const withdrawn = await plane.withdrawUnleased(startId);
    if (!withdrawn) {
      await plane.enqueue({
        dispatch_id: cancelDispatchId(run.run_id),
        action: "cancel_run",
        tenant_id: tenantId,
        workspace_id: run.workspace_id,
        session_id: `session-${run.run_id}`,
        run_id: run.run_id,
        framework_adapter: run.framework_adapter,
        required_capabilities: run.required_capabilities,
        workload_ref: run.workload_ref ?? run.run_id,
        queued_at_unix: nowUnix,
        request_id: requestId === "" ? null : requestId,
        trace_id: c.get("traceId") ?? null,
        agent_run_id: run.run_id,
        parent_action_fingerprint: run.parent_action_fingerprint,
      });
      runtimeCancelDispatched = true;
    }
  }

  return c.json({
    object: "agent_job_cancel",
    run_id: run.run_id,
    status: outcome.run.status,
    terminal: isTerminalStatus(outcome.run.status),
    // `true` when THIS call terminalized the run; `false` when it was already
    // terminal — cancel is idempotent.
    cancelled: outcome.cancelled,
    runtime_cancel_dispatched: runtimeCancelDispatched,
    cancelled_at_unix: outcome.run.completed_at_unix,
    request_id: requestId,
  });
});
