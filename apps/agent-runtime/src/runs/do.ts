/**
 * `AgentRunState` — the Durable Object that IS an agent run.
 *
 * Agent runs are long-lived (minutes to hours) and streaming, so run state
 * cannot live in a request. In Rust it lives in Postgres (`agent_runs` +
 * `agent_run_events`) behind `AppState`; on Cloudflare the natural equivalent is
 * one Durable Object per run — single-threaded, durable, and colocated with the
 * SSE subscribers it fans out to. This replaces `workers/agent-gateway`'s
 * `AgentGateway` Agents-SDK DO with a run-shaped one.
 *
 * ## Tenant isolation is structural
 *
 * The instance name is `${tenant_id}:${run_id}` (see {@link runStateStub}), so
 * one tenant's `run_id` addresses a DIFFERENT object than another tenant's. A
 * cross-tenant read therefore resolves to an EMPTY instance and is reported 404
 * — not 403 — so the surface is not an existence oracle. That is the Rust
 * behaviour (`agent_jobs.rs` module docs: "a cross-tenant `run_id` resolves to
 * `None` and is reported as 404"), obtained here without a filter that could be
 * forgotten on one query. Every method additionally re-checks the tenant it was
 * created with, so a mis-addressed stub cannot read a run either.
 *
 * ## Storage layout
 *
 *  - `run`            → the {@link StoredAgentRun} row.
 *  - `seq`            → the event sequence counter.
 *  - `evt:<016d seq>` → one {@link StoredRunEvent}. Zero-padded so
 *                       `storage.list()`'s lexicographic order IS sequence
 *                       order, which is what makes the cursor feed cheap.
 *
 * // PORT-TODO(L: inventory-edge-control §agent-worker §8.2): PLATFORM LIMIT —
 * // this Durable Object owns run STATE, and it can never own run EXECUTION,
 * // because three of Rust's four isolation backends need kernel facilities
 * // workerd does not expose (KVM/vsock, process spawn, namespaces). The full
 * // reasoning is on `src/runs/governance.ts`; the consequence HERE is the
 * // architectural one: a DO records what happened, it does not run it.
 * //
 * // IMPLEMENTED INSTEAD: execution is delegated, two ways, and both are real.
 * // Either the `@cloudflare/sandbox` Container path (`AgentSandbox`, declared
 * // but commented in `wrangler.toml` because Containers need a PAID account,
 * // so it is not in the offline harness), or a self-hosted worker leasing the
 * // dispatch through `/v1/self-hosted-workers/runs/poll` — which IS fully
 * // implemented, and is the path this DO's dispatch queue exists to serve.
 */
import { DurableObject } from "cloudflare:workers";
import type { AgentRuntimeBindings } from "../ports.js";
import {
  comparePosition,
  doneFrame,
  eventCursorToken,
  eventPosition,
  resolveEventCursor,
  runEventFrame,
  sseComment,
  sseFrame,
} from "./events.js";
import {
  type RunStatus,
  type StoredAgentRun,
  type StoredRunEvent,
  type WorkerReportedRunState,
  isTerminalStatus,
} from "./model.js";

/** Heartbeat cadence for an idle SSE stream. */
const SSE_HEARTBEAT_MS = 15_000;

/** Reconnect hint sent once at stream open. */
const SSE_RETRY_MS = 3_000;

/** Cap on retained timeline rows. The timeline is evidence, not a job store. */
const MAX_RETAINED_EVENTS = 5_000;

const RUN_KEY = "run";
const SEQ_KEY = "seq";
const EVENT_PREFIX = "evt:";

function eventKey(seq: number): string {
  return `${EVENT_PREFIX}${String(seq).padStart(16, "0")}`;
}

// ---------------------------------------------------------------------------
// RPC argument / result shapes (structured-cloneable only)
// ---------------------------------------------------------------------------

export interface CreateRunInput {
  readonly runId: string;
  readonly tenantId: string;
  readonly workspaceId: string;
  readonly frameworkAdapter: string;
  readonly requiredCapabilities: readonly string[];
  readonly workloadRef: string | null;
  readonly idempotencyKey: string | null;
  readonly input: string;
  readonly nowUnix: number;
  readonly requestId: string | null;
  readonly traceId: string | null;
  readonly parentActionFingerprint: string | null;
  /** `"queued"` for the async job protocol, `"running"` for a synchronous run. */
  readonly initialStatus: Extract<RunStatus, "queued" | "running">;
}

export interface CreateRunOutcome {
  readonly run: StoredAgentRun;
  /** `true` when the run already existed — the observable proof of idempotency. */
  readonly deduplicated: boolean;
}

export interface AppendEventInput {
  readonly kind: string;
  readonly body: unknown;
  readonly nowUnix: number;
  readonly source: StoredRunEvent["source"];
  readonly workerId?: string | null;
  readonly requestId?: string | null;
  readonly traceId?: string | null;
  readonly agentRunId?: string | null;
  readonly parentActionFingerprint?: string | null;
}

export interface EventPage {
  readonly data: readonly StoredRunEvent[];
  readonly limit: number;
  readonly afterEventId: string | null;
  readonly nextAfterEventId: string | null;
  readonly hasMore: boolean;
  /**
   * `true` when the supplied cursor could not be located in the run's current
   * event set (retention pruned it, or the caller invented it) and the page
   * restarts from the oldest retained event. The caller may see events it has
   * already seen; it is never left with a permanently unusable cursor.
   */
  readonly cursorReset: boolean;
}

export interface CancelOutcome {
  readonly run: StoredAgentRun;
  /** `true` when THIS call terminalized the run; cancel is idempotent. */
  readonly cancelled: boolean;
}

export class AgentRunState extends DurableObject<AgentRuntimeBindings> {
  /** Live SSE subscribers. In-memory: they are, by definition, connected now. */
  readonly #subscribers = new Set<WritableStreamDefaultWriter<Uint8Array>>();
  readonly #encoder = new TextEncoder();

  // -------------------------------------------------------------------------
  // Reads
  // -------------------------------------------------------------------------

  async #load(): Promise<StoredAgentRun | undefined> {
    return await this.ctx.storage.get<StoredAgentRun>(RUN_KEY);
  }

  /**
   * The run row, or `undefined`. `tenantId` is re-checked even though the
   * instance name already encodes it — defence in depth against a caller that
   * derives the stub name wrongly.
   */
  async snapshot(tenantId: string): Promise<StoredAgentRun | undefined> {
    const run = await this.#load();
    if (run === undefined || run.tenant_id !== tenantId) return undefined;
    return run;
  }

  // -------------------------------------------------------------------------
  // Create
  // -------------------------------------------------------------------------

  /**
   * Create the run, or return the existing one.
   *
   * The DO is single-threaded, so this check-then-insert cannot race — which is
   * the property the Rust path had to obtain with a fused
   * `admit_and_enqueue_agent_job_dispatch` under one guard, after a split
   * check/act version let K concurrent submits all pass a `cap - 1` check.
   */
  async create(input: CreateRunInput): Promise<CreateRunOutcome> {
    const existing = await this.#load();
    if (existing !== undefined) {
      // Address-collision safety: a derived run id belongs to exactly one
      // tenant by construction, so a mismatch means the caller mis-derived the
      // stub name. Report it as "not yours" rather than serving another
      // tenant's row.
      if (existing.tenant_id !== input.tenantId) {
        throw new Error("agent run belongs to a different tenant");
      }
      return { run: existing, deduplicated: true };
    }

    const run: StoredAgentRun = {
      run_id: input.runId,
      tenant_id: input.tenantId,
      workspace_id: input.workspaceId,
      status: input.initialStatus,
      provider: null,
      framework_adapter: input.frameworkAdapter,
      required_capabilities: input.requiredCapabilities,
      workload_ref: input.workloadRef,
      idempotency_key: input.idempotencyKey,
      turns_executed: 0,
      output: null,
      submitted_at_unix: input.nowUnix,
      started_at_unix: input.initialStatus === "running" ? input.nowUnix : null,
      completed_at_unix: null,
      runtime_reported_state: null,
      runtime_reported_event_count: 0,
      request_id: input.requestId,
      trace_id: input.traceId,
      parent_action_fingerprint: input.parentActionFingerprint,
      cancel_requested: false,
    };
    await this.ctx.storage.put(RUN_KEY, run);
    await this.ctx.storage.put(SEQ_KEY, 0);
    await this.#append({
      kind: "job_submitted",
      body: {
        input: input.input,
        framework_adapter: input.frameworkAdapter,
        required_capabilities: input.requiredCapabilities,
        workload_ref: input.workloadRef,
      },
      nowUnix: input.nowUnix,
      source: "control_plane",
      requestId: input.requestId,
      traceId: input.traceId,
      agentRunId: input.runId,
      parentActionFingerprint: input.parentActionFingerprint,
    });
    return { run, deduplicated: false };
  }

  // -------------------------------------------------------------------------
  // Timeline
  // -------------------------------------------------------------------------

  async #append(input: AppendEventInput): Promise<StoredRunEvent> {
    const run = await this.#load();
    const seq = ((await this.ctx.storage.get<number>(SEQ_KEY)) ?? 0) + 1;
    const event: StoredRunEvent = {
      id: `${run?.run_id ?? "run"}-evt-${String(seq).padStart(6, "0")}`,
      run_id: run?.run_id ?? "",
      seq,
      kind: input.kind,
      event_json: JSON.stringify(input.body ?? {}),
      occurred_at_unix: input.nowUnix,
      source: input.source,
      worker_id: input.workerId ?? null,
      request_id: input.requestId ?? null,
      trace_id: input.traceId ?? null,
      agent_run_id: input.agentRunId ?? null,
      parent_action_fingerprint: input.parentActionFingerprint ?? null,
    };
    await this.ctx.storage.put(eventKey(seq), event);
    await this.ctx.storage.put(SEQ_KEY, seq);

    if (seq > MAX_RETAINED_EVENTS) {
      // Prune the oldest row so the timeline stays bounded. The cursor feed
      // reports `cursor_reset` when a caller's cursor was one of these.
      await this.ctx.storage.delete(eventKey(seq - MAX_RETAINED_EVENTS));
    }
    this.#fanOut(runEventFrame(event));
    return event;
  }

  /** Append a timeline row (tenant-checked). */
  async appendEvent(
    tenantId: string,
    input: AppendEventInput,
  ): Promise<StoredRunEvent | undefined> {
    const run = await this.snapshot(tenantId);
    if (run === undefined) return undefined;
    return await this.#append(input);
  }

  async #allEvents(): Promise<StoredRunEvent[]> {
    const rows = await this.ctx.storage.list<StoredRunEvent>({ prefix: EVENT_PREFIX });
    return [...rows.values()];
  }

  /**
   * One page of the incremental event feed — Rust `page_agent_job_events`.
   *
   * ## Cutover finding D7.3: the cursor is a POSITION, not an event id
   *
   * The rows are ordered by `(occurred_at_unix, id)` before anything is sliced,
   * and the cursor is resolved to a key in that order rather than to an index
   * in the storage listing. The two together are what make the token cursor
   * outlive its own event: `#append` prunes past `MAX_RETAINED_EVENTS`, and the
   * previous implementation — `findIndex(event.id === afterEventId)` — could
   * only answer `cursorReset: true` once the named event was gone, re-delivering
   * the whole retained history to a poll loop on every subsequent call.
   *
   * `cursorReset` therefore survives ONLY for the case Rust also resets on: a
   * BARE event id that is not in the set. A composite token always resolves, so
   * a resuming client is never reset. See `./events.ts::resolveEventCursor`.
   *
   * The sort is explicit for the same reason Rust's is: `evt:<016d seq>` makes
   * `storage.list()` sequence-ordered, and sequence order is only incidentally
   * timestamp order — a worker reporting an event with an earlier
   * `reported_at_unix` than its predecessor would otherwise be paged into a
   * position the cursor key can never address.
   */
  async listEvents(
    tenantId: string,
    options: { readonly afterEventId: string | null; readonly limit: number },
  ): Promise<EventPage | undefined> {
    const run = await this.snapshot(tenantId);
    if (run === undefined) return undefined;

    const events = (await this.#allEvents()).sort((left, right) =>
      comparePosition(eventPosition(left), eventPosition(right)),
    );

    const resolved =
      options.afterEventId === null ? null : resolveEventCursor(options.afterEventId, events);
    // Rust `let cursor_reset = matches!(resolved, Some(None));` — a cursor was
    // supplied and could not be resolved at all.
    const cursorReset = options.afterEventId !== null && resolved === null;
    const start =
      resolved === null
        ? 0
        : (() => {
            const index = events.findIndex(
              (event) => comparePosition(eventPosition(event), resolved) > 0,
            );
            return index === -1 ? events.length : index;
          })();

    const page = events.slice(start, start + options.limit);
    const hasMore = start + page.length < events.length;
    const last = page[page.length - 1];
    return {
      data: page,
      limit: options.limit,
      afterEventId: options.afterEventId,
      // Rust: `data.last().map(token).or_else(|| after.clone().filter(|_| !reset))`.
      // Carrying the caller's cursor forward on an EMPTY page is what keeps a
      // caught-up poller from restarting; dropping it to `null` would.
      nextAfterEventId:
        last !== undefined ? eventCursorToken(last) : cursorReset ? null : options.afterEventId,
      hasMore,
      cursorReset,
    };
  }

  // -------------------------------------------------------------------------
  // Worker-reported state (the bridge that makes a run terminal)
  // -------------------------------------------------------------------------

  /**
   * Project a worker's report onto the run row — Rust
   * `AppState::apply_worker_reported_run_state`.
   *
   * This is what makes `/result` return the runtime's real output rather than a
   * permanent `409 agent_job_not_terminal`. A report for an ALREADY-terminal
   * run is ignored: the first terminal state wins, so a late duplicate cannot
   * rewrite a settled run.
   */
  async applyWorkerReportedState(
    tenantId: string,
    report: WorkerReportedRunState,
    context: {
      readonly nowUnix: number;
      readonly workerId: string | null;
      readonly requestId?: string | null;
      readonly traceId?: string | null;
      readonly agentRunId?: string | null;
      readonly parentActionFingerprint?: string | null;
    },
  ): Promise<StoredAgentRun | undefined> {
    const run = await this.snapshot(tenantId);
    if (run === undefined) return undefined;

    const alreadyTerminal = isTerminalStatus(run.status);
    const nowTerminal = isTerminalStatus(report.status);
    const next: StoredAgentRun = {
      ...run,
      status: alreadyTerminal ? run.status : report.status,
      output: report.output ?? run.output,
      turns_executed: report.turnsExecuted ?? run.turns_executed,
      started_at_unix: run.started_at_unix ?? context.nowUnix,
      completed_at_unix: !alreadyTerminal && nowTerminal ? context.nowUnix : run.completed_at_unix,
      runtime_reported_state: report.status,
      runtime_reported_event_count: run.runtime_reported_event_count + 1,
    };
    await this.ctx.storage.put(RUN_KEY, next);
    await this.#append({
      kind: `run.${report.status}`,
      body: {
        state: report.status,
        ...(report.output === undefined ? {} : { output: report.output }),
        ...(report.turnsExecuted === undefined ? {} : { turns_executed: report.turnsExecuted }),
      },
      nowUnix: context.nowUnix,
      source: "self_hosted_worker",
      workerId: context.workerId,
      requestId: context.requestId ?? null,
      traceId: context.traceId ?? null,
      agentRunId: context.agentRunId ?? run.run_id,
      parentActionFingerprint: context.parentActionFingerprint ?? null,
    });
    if (isTerminalStatus(next.status)) this.#closeSubscribers();
    return next;
  }

  /** Record a worker-reported artifact / checkpoint / telemetry row. */
  async recordWorkerEvidence(
    tenantId: string,
    input: AppendEventInput,
  ): Promise<StoredRunEvent | undefined> {
    return await this.appendEvent(tenantId, input);
  }

  // -------------------------------------------------------------------------
  // Cancel
  // -------------------------------------------------------------------------

  /**
   * Terminalize the run and raise the durable cancel latch.
   *
   * Idempotent: a second cancel of an already-terminal run answers 200 with
   * `cancelled: false`. The latch is durable rather than an in-memory
   * `AbortSignal` so a worker that leases the run AFTER the cancel still sees
   * it — the cooperative half of Rust's "durable latch + `AbortSignal`" pair.
   */
  async cancel(
    tenantId: string,
    context: { readonly nowUnix: number; readonly requestId: string | null },
  ): Promise<CancelOutcome | undefined> {
    const run = await this.snapshot(tenantId);
    if (run === undefined) return undefined;
    if (isTerminalStatus(run.status)) {
      return { run: { ...run, cancel_requested: true }, cancelled: false };
    }
    const next: StoredAgentRun = {
      ...run,
      status: "cancelled",
      cancel_requested: true,
      completed_at_unix: context.nowUnix,
    };
    await this.ctx.storage.put(RUN_KEY, next);
    await this.#append({
      kind: "job_cancelled",
      body: { state: "cancelled", reason: "cancelled by caller" },
      nowUnix: context.nowUnix,
      source: "control_plane",
      requestId: context.requestId,
      agentRunId: run.run_id,
    });
    this.#closeSubscribers();
    return { run: next, cancelled: true };
  }

  // -------------------------------------------------------------------------
  // SSE fan-out
  // -------------------------------------------------------------------------

  #fanOut(frame: string): void {
    const bytes = this.#encoder.encode(frame);
    for (const writer of this.#subscribers) {
      // A disconnected client throws on write; drop it rather than let one dead
      // subscriber stall the run.
      writer.write(bytes).catch(() => this.#subscribers.delete(writer));
    }
  }

  #closeSubscribers(): void {
    const bytes = this.#encoder.encode(doneFrame());
    for (const writer of this.#subscribers) {
      writer
        .write(bytes)
        .then(() => writer.close())
        .catch(() => undefined);
    }
    this.#subscribers.clear();
  }

  /**
   * The SSE leg. Driven through `stub.fetch()` rather than an RPC method
   * because the response is a live stream held open for the life of the run.
   *
   * Contract: `GET /events?tenant_id=…&after_event_id=…`. Replays the backlog
   * from the cursor, then streams live frames, then `[DONE]` when the run
   * settles. A run that is ALREADY terminal replays and closes immediately, so
   * a late subscriber never hangs.
   */
  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== "/events") return new Response("not found", { status: 404 });

    const tenantId = url.searchParams.get("tenant_id") ?? "";
    const run = await this.snapshot(tenantId);
    if (run === undefined) return new Response("not found", { status: 404 });

    const afterEventId = url.searchParams.get("after_event_id");
    // The SAME order and the SAME cursor resolution the paged feed uses
    // (`listEvents`). Sharing them is the point: `resumeCursor` feeds BOTH
    // representations from one `Last-Event-ID`/`after_event_id`, so a client
    // that resumes the stream with a composite token must not have its whole
    // backlog replayed just because this branch only understood bare ids.
    const events = (await this.#allEvents()).sort((left, right) =>
      comparePosition(eventPosition(left), eventPosition(right)),
    );
    let backlog = events;
    if (afterEventId !== null && afterEventId !== "") {
      const resolved = resolveEventCursor(afterEventId, events);
      backlog =
        resolved === null
          ? events
          : events.filter((event) => comparePosition(eventPosition(event), resolved) > 0);
    }

    // Open frame: the reconnect hint plus the run's current status, so a client
    // that attaches to a running job knows where it stands without a second
    // request. Then the backlog.
    let head = sseFrame({
      retryMs: SSE_RETRY_MS,
      event: "run.status",
      data: JSON.stringify({ run_id: run.run_id, status: run.status }),
    });
    for (const event of backlog) head += runEventFrame(event);

    const headers = {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      "x-accel-buffering": "no",
    };

    // An ALREADY-terminal run has nothing live to say: replay, terminate, done.
    // Returning a buffered body rather than a stream also means a late
    // subscriber can never hang waiting for a `[DONE]` that will never come.
    if (isTerminalStatus(run.status)) {
      return new Response(`${head}${doneFrame()}`, { status: 200, headers });
    }

    const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
    const writer = writable.getWriter();
    this.#subscribers.add(writer);

    // The head is written WITHOUT awaiting, deliberately: a `TransformStream`
    // has a one-chunk high-water mark, so awaiting a second write before the
    // `Response` is returned deadlocks — nothing is reading the readable end
    // yet. Writes queue on the writer in order, so framing is still exact.
    writer.write(this.#encoder.encode(head)).catch(() => this.#subscribers.delete(writer));

    // Keep the connection warm so an intermediary does not reap an idle run.
    const heartbeat = setInterval(() => {
      if (!this.#subscribers.has(writer)) {
        clearInterval(heartbeat);
        return;
      }
      writer.write(this.#encoder.encode(sseComment("keep-alive"))).catch(() => {
        this.#subscribers.delete(writer);
        clearInterval(heartbeat);
      });
    }, SSE_HEARTBEAT_MS);

    return new Response(readable, { status: 200, headers });
  }
}
