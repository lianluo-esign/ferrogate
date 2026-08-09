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
import type { AgentRunPlan, AgentRunToolCall, SelfHostedRunDispatch } from "../workers/plane.js";
import { runStateStub, workerPlaneStub } from "./addressing.js";
import { SSE_HEADERS, parseEventLimit, resumeCursor, wantsEventStream } from "./events.js";
import {
  authorizeOrThrow,
  declaredAgentRunId,
  declaredParentActionFingerprint,
  idempotencyKey,
  isAddressableRunId,
} from "./governance.js";
import { SUBMITTED_INPUT_EVIDENCE_MAX_CHARS, isTerminalStatus, truncate } from "./model.js";
import type { StoredAgentRun } from "./model.js";
import {
  type WorkflowUse,
  enforceWorkflowToolPolicy,
  workflowCallerFrom,
  workflowHeadersFrom,
} from "./workflow.js";

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
  /** `AgentRunCreateRequest.run_id` — the body half of the run identity. */
  readonly run_id?: unknown;
  readonly max_turns?: unknown;
  readonly timeout_millis?: unknown;
  readonly tool_calls?: unknown;
}

/**
 * `agent_runs.rs::harness_config` + the `tool_calls` shape check, as one
 * ladder — each refusal carrying Rust's OWN code rather than the generic
 * `invalid_request` this route used to collapse them onto.
 *
 * The codes are not decoration. A client that branches on `error.code` cannot
 * tell "your prompt was empty" from "your tool call was malformed" from "your
 * turn budget exceeds the operator's" while all three share one code, and all
 * three have different fixes.
 */
function parseRunPlan(
  body: SubmitRequest,
  limits: { readonly maxTurns: number; readonly timeoutMillis: number },
): { readonly plan: AgentRunPlan; readonly declared: boolean } {
  const toolCalls = parseToolCalls(body.tool_calls);

  const maxTurns = optionalPositiveInt(
    body.max_turns,
    "invalid_agent_run_max_turns",
    `agent run max_turns must be between 1 and operator limit ${limits.maxTurns}`,
  );
  if (maxTurns !== null && maxTurns > limits.maxTurns) {
    throw new HttpError(
      400,
      "invalid_agent_run_max_turns",
      `agent run max_turns must be between 1 and operator limit ${limits.maxTurns}`,
    );
  }
  const effectiveMaxTurns = maxTurns ?? limits.maxTurns;
  // One turn per scripted call, plus the final turn that consumes their
  // results. Refused up front rather than silently truncating the caller's
  // tool calls to whatever the budget happens to admit.
  if (toolCalls.length + 1 > effectiveMaxTurns) {
    throw new HttpError(
      400,
      "invalid_agent_run_max_turns",
      `agent run max_turns must allow ${toolCalls.length} scripted tool call(s) plus one final turn`,
    );
  }

  const timeoutMillis = optionalPositiveInt(
    body.timeout_millis,
    "invalid_agent_run_timeout",
    `agent run timeout_millis must be between 1 and operator limit ${limits.timeoutMillis}`,
  );
  if (timeoutMillis !== null && timeoutMillis > limits.timeoutMillis) {
    throw new HttpError(
      400,
      "invalid_agent_run_timeout",
      `agent run timeout_millis must be between 1 and operator limit ${limits.timeoutMillis}`,
    );
  }

  return {
    plan: {
      max_turns: effectiveMaxTurns,
      timeout_millis: timeoutMillis ?? limits.timeoutMillis,
      tool_calls: toolCalls,
    },
    // Whether the CALLER stated a plan, as opposed to inheriting the operator
    // defaults. Only a declared plan rides the dispatch: a worker must be able
    // to distinguish "asked for 4 turns" from "asked for nothing", or the
    // operator default silently becomes a caller instruction.
    declared: maxTurns !== null || timeoutMillis !== null || toolCalls.length > 0,
  };
}

/**
 * Rust's `Option<u32>` / `Option<u64>` members: absent stays absent; present
 * must be a positive integer. `0` is refused explicitly — it is not a sentinel
 * for "unbounded", it is a plan that can never run a turn.
 */
function optionalPositiveInt(value: unknown, code: string, message: string): number | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new HttpError(400, code, message);
  }
  return value;
}

/** `Vec<AgentRunToolCallRequest>` — a blank name is `invalid_agent_tool_call`. */
function parseToolCalls(value: unknown): readonly AgentRunToolCall[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw new HttpError(400, "invalid_agent_tool_call", "tool_calls must be an array of objects");
  }
  const calls: AgentRunToolCall[] = [];
  for (const raw of value) {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      throw new HttpError(400, "invalid_agent_tool_call", "each tool call must be a JSON object");
    }
    const entry = raw as Record<string, unknown>;
    const name = entry.name;
    if (typeof name !== "string" || name.trim() === "") {
      throw new HttpError(400, "invalid_agent_tool_call", "agent tool call name must not be empty");
    }
    const route = entry.route;
    const sessionId = entry.session_id;
    if (route !== undefined && route !== null && typeof route !== "string") {
      throw new HttpError(400, "invalid_agent_tool_call", "tool call route must be a string");
    }
    if (sessionId !== undefined && sessionId !== null && typeof sessionId !== "string") {
      throw new HttpError(400, "invalid_agent_tool_call", "tool call session_id must be a string");
    }
    calls.push({
      name: name.trim(),
      ...(entry.arguments === undefined ? {} : { arguments: entry.arguments }),
      ...(typeof route === "string" ? { route } : {}),
      ...(typeof sessionId === "string" ? { session_id: sessionId } : {}),
    });
  }
  return calls;
}

/**
 * `requested_agent_run_id`'s BODY half.
 *
 * The header half stays `declaredAgentRunId` (`400
 * invalid_agent_run_id_header`, the code the whole tree already uses for the
 * header — `apps/gateway/src/assets/handlers.ts`, `apps/mcp/src/http.ts`). The
 * body field carries Rust's handler-local `invalid_agent_run_id`, because that
 * is the code `handle_agent_run_create` answers and a Rust-written client
 * branches on it. Two codes for two inputs, each matching where it came from.
 */
function bodyRunId(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw new HttpError(400, "invalid_agent_run_id", "run_id must be a string");
  }
  const trimmed = value.trim();
  if (trimmed === "") return null;
  if (!isAddressableRunId(trimmed)) {
    throw new HttpError(
      400,
      "invalid_agent_run_id",
      "agent run id must be at most 128 characters of letters, numbers, _, -, ., or :",
    );
  }
  return trimmed;
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
 * Run the tool-side graph ladder and, if it passes, DEBIT the run's envelope.
 *
 * Two Durable Object round trips, and both are necessary: the ladder's edge and
 * timeout rules are functions of what the run has already done, and the budget
 * debit must be atomic with the check. Splitting the second one into a read and
 * a write is the check-then-act shape this Worker already removed once from the
 * dispatch admission path.
 *
 * Returns the `WorkflowUse` for an admitted step, or `null` when the request
 * declared no workflow at all. Refusals leave here as {@link HttpError} with
 * Rust's code and status verbatim.
 */
async function admitWorkflowStep(
  c: Context<AgentRuntimeEnv>,
  input: {
    readonly stub: ReturnType<typeof runStateStub>;
    readonly tenantId: string;
    readonly runId: string;
    readonly nowUnix: number;
    readonly toolCalls: readonly AgentRunToolCall[];
  },
): Promise<WorkflowUse | null> {
  const deps = depsOrThrow(c);
  const auth = requireAuth(c);
  const declaration = workflowHeadersFrom(c.req.raw.headers);
  // A malformed declaration is refused BEFORE the catalog is read, so a
  // deployment with no workflows still reports the header error rather than
  // `workflow_not_found` — the ladder's first rung is the shape of the request.
  if (declaration.kind === "absent") return null;

  const workflows = await deps.workflows.forTenant(auth.tenancy.tenantId);
  // Facts are read for the DECLARED workflow only, which is why the ladder
  // needs its id first. An invalid declaration never gets this far.
  const facts =
    declaration.kind === "declared"
      ? await input.stub.workflowFacts(
          input.tenantId,
          declaration.workflowId,
          declaration.workflowVersion ??
            selectDeclaredVersion(workflows, declaration.workflowId) ??
            1,
          input.runId,
        )
      : { previousSuccessfulNodeId: null, runStartedAtUnix: null };

  const decision = enforceWorkflowToolPolicy(
    workflows,
    {
      caller: workflowCallerFrom(auth),
      declaration,
      toolCalls: input.toolCalls,
      nowUnixSeconds: input.nowUnix,
    },
    {
      ...(facts.previousSuccessfulNodeId === null
        ? {}
        : { previousSuccessfulNodeId: facts.previousSuccessfulNodeId }),
      ...(facts.runStartedAtUnix === null ? {} : { runStartedAtUnix: facts.runStartedAtUnix }),
    },
  );
  if (!decision.ok) {
    throw new HttpError(
      decision.rejection.status,
      decision.rejection.code,
      decision.rejection.message,
    );
  }
  const use = decision.use;
  if (use === null) return null;

  const admission = await input.stub.admitWorkflowStep(input.tenantId, {
    workflowId: use.id,
    workflowVersion: use.version,
    runId: input.runId,
    nodeId: use.nodeId,
    caps: use.caps,
    toolCalls: input.toolCalls.length,
    nowUnix: input.nowUnix,
  });
  if (admission.outcome === "exceeded") {
    // Rust answers the UNQUALIFIED code with a dimension-bearing message
    // (`agent_workflow_use` → `StatusCode::PAYMENT_REQUIRED`,
    // `"workflow_budget_exceeded"`), so a client branches on one code while an
    // operator reads which dimension broke.
    throw new HttpError(402, "workflow_budget_exceeded", admission.message);
  }
  return use;
}

/**
 * The version the ledger is keyed by when the caller declared none.
 *
 * `select_agent_workflow` with no version resolves to the HIGHEST configured
 * one, and the ledger must be keyed by the SAME row the gate will select — key
 * it by a guessed `1` and an unversioned multi-step run would read one run's
 * history and write another's. Falls back to `1` only when nothing matches, in
 * which case the ladder is about to answer `workflow_not_found` anyway.
 */
function selectDeclaredVersion(
  workflows: readonly { readonly id: string; readonly version: number }[],
  workflowId: string,
): number | undefined {
  let selected: number | undefined;
  for (const workflow of workflows) {
    if (workflow.id !== workflowId) continue;
    if (selected === undefined || workflow.version > selected) selected = workflow.version;
  }
  return selected;
}

/**
 * Shared create path for `POST /v1/agent-runs` (synchronous) and
 * `POST /v1/agent-jobs` (async). They address the SAME `agent_runs` evidence —
 * the async protocol adds caller-facing verbs on top of it rather than building
 * a parallel job stack.
 */
async function createRun(
  c: Context<AgentRuntimeEnv>,
  options: {
    readonly initialStatus: "queued" | "running";
    readonly enqueueDispatch: boolean;
    /**
     * `agent_runs.rs`'s own `invalid_agent_run_input`, or the async job
     * protocol's generic `invalid_request`. `POST /v1/agent-runs` is the
     * operation the reference gives a dedicated code, and `POST /v1/agent-jobs`
     * (#474) is not — changing the latter would break a client for no gain.
     */
    readonly emptyInputCode: "invalid_agent_run_input" | "invalid_request";
  },
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
    throw new HttpError(400, options.emptyInputCode, "agent run input must not be empty");
  }
  // The execution plan (`max_turns` / `timeout_millis` / `tool_calls`). Parsed
  // BEFORE anything durable happens, exactly as Rust parses it before the run
  // row is written: a refused plan must leave nothing behind.
  const { plan, declared: planDeclared } = parseRunPlan(body, config);

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
  // new one — the caller is attaching work to a run it already holds. Rust
  // takes the same id from the header OR the body field; the body half had no
  // reader here at all, so `run_id` was accepted and silently ignored.
  //
  // With NEITHER, the id is derived from `(tenant, idempotency key)` rather
  // than from Rust's `run-{request_id}`. Both give an uncorrelated request its
  // OWN run — which is what the edge gate depends on — but the derived id
  // additionally makes a keyed retry ADDRESS the same run instead of minting a
  // second one, which the reference cannot do at all.
  const runId =
    declaredRunId ?? bodyRunId(body.run_id) ?? (await agentJobRunId(tenantId, effectiveKey));

  const nowUnix = deps.clock.nowUnix();
  const stub = runStateStub(c.env, tenantId, runId);

  // ---------------------------------------------------------------------
  // The TOOL-side workflow graph gate (`./workflow.ts`).
  //
  // Placed HERE — after governance, before `create` — for the reason Rust
  // places `agent_workflow_use` before `record_agent_run`: a step the graph
  // refuses must leave no run behind, or a caller could materialise runs it is
  // not allowed to take by walking the refusals.
  // ---------------------------------------------------------------------
  const workflowUse = await admitWorkflowStep(c, {
    stub,
    tenantId,
    runId,
    nowUnix,
    toolCalls: plan.tool_calls,
  });
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
    sessionId,
    isolationGrant: grant,
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
      // THE READER the cutover finding said these three fields did not have.
      // Carried only when the CALLER stated a plan: an omitted key tells the
      // worker to apply its own defaults, a present one is an instruction.
      run_plan: planDeclared ? plan : null,
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
  const synchronousShape = options.initialStatus === "running";
  return c.json(
    {
      object: synchronousShape ? "agent_run" : "agent_job",
      // `AgentRunCreateResponse.id` — Rust's name for the run. Emitted ONLY on
      // the operation that names it, and always equal to `run_id`: two keys for
      // one value, so a client written against either reference finds its
      // field. An `id` that could disagree with `run_id` would be worse than an
      // absent one.
      ...(synchronousShape ? { id: runId } : {}),
      run_id: runId,
      status: created.run.status,
      // The three members a Rust-written client reads off this response, all of
      // them honest rather than fabricated. Nothing has executed at the moment
      // this is written — the run is dispatched, not finished — so the counts
      // are zero, the output is an explicit absence, and the tool results are
      // an empty list. The settled values are collected from
      // `GET /v1/agent-jobs/{run_id}/result` once the executor reports.
      //
      // WHY THIS RESPONSE IS NOT THE FINISHED RUN, in one place: Rust's
      // handler builds an `AgentHarness` and loops turns inside the request,
      // and it can only do that through `agent_provider`, whose two arms are
      // (a) `ManagedWorker` — the serde DEFAULT — which returns
      // `agent_worker_transport_unavailable` / "not implemented yet", so a
      // default reference deployment answers 503 here; and (b) `External`,
      // which SPAWNS A LOCAL CHILD PROCESS. workerd has no process spawn
      // (`src/runs/governance.ts` records why that is a property of the sandbox
      // rather than a missing API), so the synchronous half is both the
      // unfinished half of the reference and the unportable one. The run is
      // dispatched to the executor instead, and the plan the caller declared
      // rides the dispatch.
      ...(synchronousShape
        ? {
            turns_executed: created.run.turns_executed,
            output: created.run.output,
            tool_results: [],
            // The ACCEPTED bounds, echoed so a caller can see which limits were
            // applied rather than guessing whether its request or the
            // operator's ceiling won.
            max_turns: plan.max_turns,
            timeout_millis: plan.timeout_millis,
          }
        : {}),
      ...(workflowUse === null
        ? {}
        : {
            // Evidence that the step really passed the graph gate, and WHICH
            // node it was admitted at — the `AgentWorkflowUse` Rust stamps onto
            // every audit row for the run.
            workflow: {
              id: workflowUse.id,
              version: workflowUse.version,
              node_id: workflowUse.nodeId,
            },
          }),
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

/**
 * `POST /v1/agent-runs` — `createAgentRun`, scope `agents.invoke`.
 *
 * ## The wave-19 HOLD item A2, and exactly which half of it was portable
 *
 * The certification recorded this route as "not the operation the contract
 * names": it answered the async-job envelope, and `max_turns`,
 * `timeout_millis` and `tool_calls` had **no reader anywhere in
 * `apps/agent-runtime/src`**. Both halves of that are now closed, but they were
 * closed differently, and the difference is the point.
 *
 * ### PORTABLE, and restored (`agent_runs.rs:95-470`)
 *
 * | Rust refusal | status | restored as |
 * |---|---|---|
 * | `invalid_agent_run_input` | 400 | `createRun`'s `emptyInputCode` |
 * | `invalid_agent_run_id` | 400 | {@link bodyRunId} — the BODY half, which had no reader |
 * | `invalid_agent_tool_call` | 400 | {@link parseToolCalls} |
 * | `invalid_agent_run_max_turns` | 400 | {@link parseRunPlan}, incl. the `len + 1` turn rule |
 * | `invalid_agent_run_timeout` | 400 | {@link parseRunPlan} |
 * | `workflow_node_not_tool` | 403 | `./workflow.ts` |
 * | `workflow_tool_not_allowed` | 403 | `./workflow.ts` |
 * | `workflow_edge_not_allowed` | 403 | `./workflow.ts` |
 * | `workflow_parallelism_limit_exceeded` | 429 | `./workflow.ts` |
 * | `workflow_tool_call_limit_exceeded` | 429 | `./workflow.ts` |
 * | `workflow_iteration_limit_exceeded` | 429 | `./workflow.ts` |
 * | `workflow_timeout_exceeded` | 429 | `./workflow.ts` |
 * | `workflow_budget_exceeded` | 402 | `AgentRunState.admitWorkflowStep` — the DEBIT |
 *
 * The response now carries `id`, `turns_executed`, `output` and `tool_results`,
 * so a client written against the reference finds its fields.
 *
 * ### NOT PORTABLE, and why — a REASONED decision, not a copied stub
 *
 * The one thing that is still not here is the synchronous turn loop, and the
 * reason is that the reference's own version of it is unfinished.
 * `agent_provider` (`agent_runs.rs:971`) has exactly two arms:
 *
 *  * **`ManagedWorker`** — `AgentRuntimeProvider::default()`
 *    (`ferrogate-config/src/config/types.rs:1149`), i.e. what EVERY deployment
 *    that does not override it gets — returns
 *    `Err(("agent_worker_transport_unavailable", "managed agent runtime
 *    requires the external agent-worker Firecracker microVM transport, which is
 *    not implemented yet"))`. A default reference deployment answers **503** to
 *    every request on this path.
 *  * **`External`** — `ExternalAgentProvider::with_input`, which spawns a local
 *    child process from `agent_runtime.external.command`.
 *
 * So the working backend is process spawn, which workerd does not have, and the
 * default backend is an explicit "not implemented yet". Copying either would
 * mean shipping a 503 under a contract operation. What this Worker does instead
 * is DISPATCH the run — to a leased self-hosted worker through the
 * `/v1/self-hosted-workers/*` protocol, or to the `@cloudflare/sandbox`
 * container — and carry the caller's accepted plan onto that dispatch
 * ({@link SelfHostedRunDispatch.run_plan}), which is what gives `max_turns`,
 * `timeout_millis` and `tool_calls` a real reader for the first time.
 *
 * The response is therefore `202` rather than Rust's `201`: `outcome_status_code`
 * answers `CREATED` only for `AgentRunStatus::Completed`, and `ACCEPTED` for
 * every non-final outcome — which is what a dispatched run is.
 * `agent_run_id_conflict` (409) stays unreachable for the reason `submitAgentJob`
 * already records: a run id addresses one Durable Object per tenant, so a
 * cross-tenant collision cannot be constructed.
 */
runRoutes.post("/v1/agent-runs", (c) =>
  createRun(c, {
    initialStatus: "running",
    enqueueDispatch: true,
    emptyInputCode: "invalid_agent_run_input",
  }),
);

/**
 * `POST /v1/agent-jobs` — `submitAgentJob`, scope `agent.runs.create`.
 *
 * Gated by the SAME tool-side workflow ladder as `/v1/agent-runs`, which the
 * reference does not do — `agent_jobs.rs` (#474) was added after
 * `agent_workflow_use` and never grew one. Leaving the twin ungated here would
 * make the gate a formality: both URLs reach this one create path, so a caller
 * refused at a node would simply submit the identical work one route over. The
 * gate is opt-in by header, so an undeclared submission is untouched and no
 * existing client changes behaviour.
 */
runRoutes.post("/v1/agent-jobs", (c) =>
  createRun(c, {
    initialStatus: "queued",
    enqueueDispatch: true,
    emptyInputCode: "invalid_request",
  }),
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
    // `400 invalid_event_cursor` on a non-integer or zero limit — see
    // `./events.ts::parseEventLimit`. Only the upper bound is clamped.
    limit: parseEventLimit(url.searchParams.get("limit")),
  });
  if (page === undefined) {
    throw new HttpError(404, "agent_job_not_found", "agent job was not found");
  }
  return c.json({
    // Rust `AgentJobEventPage.object` (`agent_jobs.rs:838`). NOT `"list"`: a
    // client discriminating on `object` cannot tell this page from any other
    // collection if it is, which is cutover finding D7.1.
    object: "agent_job_event_page",
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
 * Timeline `kind` a work-product envelope rides on, and the discriminator
 * INSIDE its payload — `coding_agent::WORK_PRODUCT_ARTIFACT_EVENT_KIND` /
 * `WORK_PRODUCT_ARTIFACT_OBJECT`, verbatim.
 *
 * A work product is not given its own event kind: it shares `"artifact"` with
 * every other evidence row and is distinguished by the payload discriminator,
 * so the storage layer never has to learn about it.
 */
const WORK_PRODUCT_EVENT_KIND = "artifact";
const WORK_PRODUCT_OBJECT = "coding_agent.work_product";

/**
 * `WorkProductView::from_timeline_events` — the #472 coding-agent work products
 * carried by a run's own artifact events.
 *
 * ## Why this exists (cutover finding D7, the aside)
 *
 * The certification recorded that `getAgentJobResult` "drops Rust's
 * `work_products` and substitutes a raw `artifacts` array". Reading
 * `agent_jobs.rs:876-905` shows the substitution never happened: Rust emits
 * BOTH keys, and this handler simply had no `work_products` at all — so a
 * client that reads it saw the field vanish, and one that skipped an unfamiliar
 * artifact envelope had nowhere else to look.
 *
 * ## What IS ported, exactly
 *
 * The three things that are pure functions of the timeline this DO already
 * stores, and that carry the security-relevant part of the Rust behaviour:
 *
 *  1. the FILTER — `kind === "artifact"` AND payload `object` equal to the
 *     discriminator. An unrecognised artifact is SKIPPED, never an error: "a
 *     run's timeline legitimately carries artifacts that are not work
 *     products", and failing the whole result read on one would be worse.
 *  2. the un-parseable payload is skipped for the same reason (Rust's `parse`
 *     returns `Option`, never `Result`).
 *  3. `attribution_verified` — RE-DERIVED here against the `run_id` in the
 *     PATH, never copied from the payload. That is the whole point of the Rust
 *     projection existing ("`run_id` is the caller's, not the payload's"), and
 *     it is the half a relabelled envelope would otherwise fake.
 *
 * ## PORT-TODO(`ferrogate-runtime::coding_agent`): the RE-DERIVED half
 *
 * `WorkProductView::from_artifact` also re-derives `product_id` from the
 * product's own fields and reports `repo_verified` /
 * `published.matches_work_product` from that derivation
 * (`extract.rs::id_is_consistent`, `work_product_artifact.rs::receipt_publishes`).
 * Those need the `WorkProduct` / `RepoCoordinates` / `WriteBackReceipt` model,
 * and `crates/ferrogate-runtime/src/coding_agent/` has NO TypeScript port
 * anywhere in this tree — it is not in `PORT-PLAN.md` either. Inventing the
 * derivation here would produce a verdict with nothing behind it, which is
 * strictly worse than not reporting one, so the evidence is carried WITHOUT
 * those two verdicts rather than with fabricated ones. This is an under-claim,
 * not a wrong claim, and it is why the payload is passed through verbatim under
 * `work_product` rather than flattened into `WorkProductView`'s field set.
 *
 * NOTHING in this tree writes such an envelope today, so the array is `[]` for
 * every job it can currently produce — which is also Rust's answer for every
 * non-coding job.
 */
export function workProductsFor(
  events: readonly { readonly kind: string; readonly event_json: string }[],
  runId: string,
): readonly Record<string, unknown>[] {
  const products: Record<string, unknown>[] = [];
  for (const event of events) {
    if (event.kind !== WORK_PRODUCT_EVENT_KIND) continue;
    let payload: unknown;
    try {
      payload = JSON.parse(event.event_json);
    } catch {
      continue;
    }
    if (typeof payload !== "object" || payload === null) continue;
    const envelope = payload as Record<string, unknown>;
    if (envelope.object !== WORK_PRODUCT_OBJECT) continue;

    const product = envelope.work_product;
    const declaredRun =
      typeof product === "object" && product !== null
        ? (product as { run?: { run_id?: unknown } }).run?.run_id
        : undefined;
    products.push({
      object: "coding_agent_work_product",
      run_id: runId,
      work_product: product ?? null,
      ...(envelope.write_back === undefined ? {} : { write_back: envelope.write_back }),
      // Re-derived against the PATH run id. A payload claiming another run is
      // reported `false`, not filtered out — the evidence is still on this
      // run's timeline and hiding it would lose the anomaly.
      attribution_verified: declaredRun === runId,
    });
  }
  return products;
}

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
    // Rust carries BOTH: the raw `artifacts` evidence rows AND the decoded
    // `work_products` projection (`agent_jobs.rs:890`). The certification read
    // this as "`work_products` was replaced by `artifacts`"; the truth is that
    // the projection was simply absent, so a client saw the key disappear.
    work_products: workProductsFor(page?.data ?? [], run.run_id),
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
