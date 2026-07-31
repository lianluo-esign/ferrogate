/**
 * The agent-run vocabulary: statuses, events, and the wire shapes the
 * `/v1/agent-jobs/**` surface returns.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/state_agent_runtime.rs`
 * (`agent_run_status_is_terminal`, `canonical_agent_run_status`,
 * `worker_reported_run_state`, `worker_reported_output`) and the response
 * structs in `crates/ferrogate-gateway/src/server/agent_jobs.rs`.
 */

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/** Statuses that mean "this run will not change again" (Rust, verbatim). */
export const TERMINAL_STATUSES = [
  "completed",
  "failed",
  "cancelled",
  "timed_out",
  "max_turns_exceeded",
  "exhausted",
] as const;

export type TerminalStatus = (typeof TERMINAL_STATUSES)[number];
export type RunStatus = TerminalStatus | "queued" | "running";

/** Rust `agent_run_status_is_terminal`. */
export function isTerminalStatus(status: string): boolean {
  return (TERMINAL_STATUSES as readonly string[]).includes(status);
}

/**
 * Rust `canonical_agent_run_status`.
 *
 * Workers speak several dialects for the same event (`run.completed` as a
 * telemetry *kind*, `{"state":"completed"}` / `{"status":"succeeded"}` as
 * lifecycle bodies), so the token is normalized before matching. An
 * unrecognized word returns `undefined` — the run is left exactly as it was
 * rather than guessed into a state the caller would then collect.
 */
export function canonicalRunStatus(raw: string): RunStatus | undefined {
  const normalized = raw
    .trim()
    .toLowerCase()
    .replace(/[.\- ]/g, "_");
  let token = normalized;
  for (const prefix of ["run_", "job_", "agent_run_"]) {
    if (token.startsWith(prefix)) {
      token = token.slice(prefix.length);
      break;
    }
  }
  switch (token) {
    case "started":
    case "running":
    case "in_progress":
    case "accepted":
    case "resumed":
      return "running";
    case "completed":
    case "complete":
    case "succeeded":
    case "success":
    case "finished":
    case "done":
      return "completed";
    case "failed":
    case "failure":
    case "error":
    case "errored":
      return "failed";
    case "cancelled":
    case "canceled":
    case "aborted":
      return "cancelled";
    case "timed_out":
    case "timeout":
    case "deadline_exceeded":
      return "timed_out";
    case "max_turns_exceeded":
    case "turn_limit_exceeded":
      return "max_turns_exceeded";
    case "exhausted":
    case "budget_exhausted":
    case "quota_exhausted":
      return "exhausted";
    default:
      return undefined;
  }
}

/** Max characters of worker-reported output retained (Rust `truncate_worker_output`). */
export const WORKER_OUTPUT_MAX_CHARS = 64 * 1024;

/** Max characters of submitted input kept on the `job_submitted` event. */
export const SUBMITTED_INPUT_EVIDENCE_MAX_CHARS = 2_000;

export function truncate(text: string, maxChars: number): string {
  return text.length <= maxChars ? text : `${text.slice(0, maxChars)}…[truncated]`;
}

/**
 * Rust `worker_reported_output`: the terminal output a worker attached to its
 * report. A JSON string is taken verbatim; a structured value is re-serialized
 * compactly so `{"output": {"pull_request": "..."}}` (the #472 work-product
 * shape) is not silently dropped. Empty values stay absent.
 */
export function workerReportedOutput(body: unknown): string | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const record = body as Record<string, unknown>;
  for (const field of ["output", "result", "final_output", "summary", "message"]) {
    const value = record[field];
    if (value === undefined || value === null) continue;
    const rendered = typeof value === "string" ? value.trim() : JSON.stringify(value);
    if (rendered !== undefined && rendered !== "")
      return truncate(rendered, WORKER_OUTPUT_MAX_CHARS);
  }
  return undefined;
}

/** Rust `WorkerReportedRunState`. */
export interface WorkerReportedRunState {
  readonly status: RunStatus;
  readonly output?: string;
  readonly turnsExecuted?: number;
}

/**
 * Rust `worker_reported_run_state`. The lifecycle BODY wins over the event
 * kind, because a worker that sends `kind: "lifecycle"` puts the state in the
 * body while a worker that names the event `run.completed` carries it in the
 * kind. Either dialect is accepted, neither is required.
 */
export function workerReportedRunState(
  kind: string,
  body: unknown,
): WorkerReportedRunState | undefined {
  const record =
    typeof body === "object" && body !== null ? (body as Record<string, unknown>) : undefined;
  const declaredRaw = record?.state ?? record?.status;
  const declared = typeof declaredRaw === "string" ? canonicalRunStatus(declaredRaw) : undefined;
  const status = declared ?? canonicalRunStatus(kind);
  if (status === undefined) return undefined;

  const turnsRaw = record?.turns_executed ?? record?.turns ?? record?.turn;
  const turnsExecuted =
    typeof turnsRaw === "number" && Number.isInteger(turnsRaw) && turnsRaw >= 0
      ? turnsRaw
      : undefined;

  const output = workerReportedOutput(record);
  return {
    status,
    ...(output === undefined ? {} : { output }),
    ...(turnsExecuted === undefined ? {} : { turnsExecuted }),
  };
}

// ---------------------------------------------------------------------------
// Durable run record + timeline
// ---------------------------------------------------------------------------

/** One row of the run timeline (Rust `StoredAgentRunEvent`). */
export interface StoredRunEvent {
  readonly id: string;
  readonly run_id: string;
  readonly seq: number;
  /** e.g. `job_submitted`, `run.started`, `artifact`, `job_cancelled`. */
  readonly kind: string;
  /** Free-form JSON body, stored as a compact string exactly as Rust does. */
  readonly event_json: string;
  readonly occurred_at_unix: number;
  /** Who reported it: the control plane, or a self-hosted worker. */
  readonly source: "control_plane" | "self_hosted_worker";
  readonly worker_id: string | null;
  // #305/#307 correlation keys. Absent stays absent — never fabricated.
  readonly request_id: string | null;
  readonly trace_id: string | null;
  readonly agent_run_id: string | null;
  readonly parent_action_fingerprint: string | null;
}

/** The durable run row (Rust `StoredAgentRun`). */
export interface StoredAgentRun {
  readonly run_id: string;
  readonly tenant_id: string;
  readonly workspace_id: string;
  readonly status: RunStatus;
  readonly provider: string | null;
  readonly framework_adapter: string;
  readonly required_capabilities: readonly string[];
  readonly workload_ref: string | null;
  readonly idempotency_key: string | null;
  readonly turns_executed: number;
  readonly output: string | null;
  readonly submitted_at_unix: number | null;
  readonly started_at_unix: number | null;
  readonly completed_at_unix: number | null;
  /** Latest lifecycle word the runtime itself reported. */
  readonly runtime_reported_state: string | null;
  readonly runtime_reported_event_count: number;
  // #305/#307 correlation keys of the submitting request.
  readonly request_id: string | null;
  readonly trace_id: string | null;
  readonly parent_action_fingerprint: string | null;
  /** The cancel latch — cooperative cancellation, durable across restarts. */
  readonly cancel_requested: boolean;
}
