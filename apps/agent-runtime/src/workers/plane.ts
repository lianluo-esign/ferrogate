/**
 * `WorkerPlane` — the Durable Object that owns the self-hosted run dispatch
 * queue and its lease bookkeeping.
 *
 * Clean-room port of `InMemorySelfHostedRunQueue` in
 * `crates/ferrogate-runtime/src/self_hosted_worker.rs`. In Rust the queue is an
 * in-process map rebuilt from `self_hosted_run_dispatches` on startup; on
 * Cloudflare a Durable Object gives the same single-threaded semantics WITH
 * durability, so the "rebuild on restart" step disappears.
 *
 * One instance per `${tenant_id}:${workspace_id}` — the exact scope
 * `can_lease_to` filters on, so a worker can only ever be handed dispatches
 * from its own tenant AND workspace. The scoping is structural, not a
 * predicate that could be dropped from one query.
 *
 * Every lease rule from the Rust `can_lease_to` is preserved:
 *  - never re-hand an ACKed dispatch;
 *  - **#502**: a `start_run` whose run already carries a `cancel_run` is
 *    SUPERSEDED — the cancel is leasable, the start is not. Without this, the
 *    start-holder's lease expiring would let a second worker lease and START
 *    work the caller had cancelled;
 *  - tenant / workspace / framework-adapter must match the worker;
 *  - required capabilities must be supported by BOTH the poll request and the
 *    worker's registration;
 *  - a live (unexpired) lease blocks re-leasing.
 */
import { DurableObject } from "cloudflare:workers";
import type { AgentRuntimeBindings, RegisteredSelfHostedWorker } from "../ports.js";
import { normalizedCapabilities } from "../ports.js";

/** Rust `SelfHostedRunAction`. */
export const RUN_ACTIONS = ["start_run", "cancel_run", "resume_run", "close_session"] as const;
export type SelfHostedRunAction = (typeof RUN_ACTIONS)[number];

/** Rust `SelfHostedRunAckStatus`. */
export const ACK_STATUSES = ["accepted", "completed", "failed", "cancelled"] as const;
export type SelfHostedRunAckStatus = (typeof ACK_STATUSES)[number];

/** Rust `SelfHostedTelemetryTrustLevel` — one variant, and it is not "trusted". */
export const TRUST_LEVEL = "reported_by_self_hosted_worker" as const;

/** Rust `SelfHostedRunDispatch`. */
export interface SelfHostedRunDispatch {
  readonly dispatch_id: string;
  readonly action: SelfHostedRunAction;
  readonly tenant_id: string;
  readonly workspace_id: string;
  readonly session_id: string;
  readonly run_id: string;
  readonly framework_adapter: string;
  readonly required_capabilities: readonly string[];
  readonly workload_ref: string;
  readonly queued_at_unix: number;
  // #305 correlation keys of the dispatching context. All optional so a
  // dispatch created outside any inbound request carries `null` rather than a
  // fabricated id.
  readonly request_id: string | null;
  readonly trace_id: string | null;
  readonly agent_run_id: string | null;
  /** #307: `sha256:<hex>` of the UPSTREAM governed action, or `null`. */
  readonly parent_action_fingerprint: string | null;
}

/** Rust `SelfHostedRunLease`. */
export interface SelfHostedRunLease {
  readonly dispatch_id: string;
  readonly action: SelfHostedRunAction;
  readonly lease_id: string;
  readonly tenant_id: string;
  readonly workspace_id: string;
  readonly worker_id: string;
  readonly session_id: string;
  readonly run_id: string;
  readonly framework_adapter: string;
  readonly required_capabilities: readonly string[];
  readonly workload_ref: string;
  readonly attempt: number;
  readonly lease_expires_at_unix: number;
  readonly trust_level: typeof TRUST_LEVEL;
  // #305/#307: the dispatch's correlation identity rides the lease VERBATIM so
  // the worker stamps its evidence with the same keys the control plane stored.
  readonly request_id?: string;
  readonly trace_id?: string;
  readonly agent_run_id?: string;
  readonly parent_action_fingerprint?: string;
}

/** Rust `SelfHostedRunAck`. */
export interface SelfHostedRunAck {
  readonly dispatch_id: string;
  readonly action: SelfHostedRunAction;
  readonly lease_id: string;
  readonly tenant_id: string;
  readonly workspace_id: string;
  readonly worker_id: string;
  readonly run_id: string;
  readonly status: SelfHostedRunAckStatus;
  readonly accepted_at_unix: number;
  readonly trust_level: typeof TRUST_LEVEL;
}

/** Rust `QueuedSelfHostedRun`. */
interface QueuedRun {
  dispatch: SelfHostedRunDispatch;
  assigned_worker_id: string | null;
  lease_id: string | null;
  lease_expires_at_unix: number | null;
  attempt: number;
  acknowledged_status: SelfHostedRunAckStatus | null;
  acknowledged_at_unix: number | null;
}

/** Rust `SelfHostedWorkerError::InvalidTransport` messages, as a result type. */
export type QueueRefusal = { readonly code: string; readonly message: string };

export type EnqueueResult =
  | { readonly outcome: "enqueued" }
  | { readonly outcome: "duplicate" }
  | { readonly outcome: "over_budget"; readonly open: number };

export type AckResult =
  | { readonly outcome: "acked"; readonly ack: SelfHostedRunAck }
  | { readonly outcome: "refused"; readonly refusal: QueueRefusal };

const DISPATCH_PREFIX = "disp:";

function dispatchKey(dispatchId: string): string {
  return `${DISPATCH_PREFIX}${dispatchId}`;
}

/** Rust `required_capabilities_supported`. */
function capabilitiesSupported(
  required: readonly string[],
  supported: readonly string[],
): boolean {
  const have = new Set(normalizedCapabilities(supported));
  return normalizedCapabilities(required).every((capability) => have.has(capability));
}

export class WorkerPlane extends DurableObject<AgentRuntimeBindings> {
  async #all(): Promise<QueuedRun[]> {
    const rows = await this.ctx.storage.list<QueuedRun>({ prefix: DISPATCH_PREFIX });
    return [...rows.values()];
  }

  // -------------------------------------------------------------------------
  // Enqueue (the caller-facing submit path)
  // -------------------------------------------------------------------------

  /**
   * Rust `AppState::admit_and_enqueue_agent_job_dispatch` — the concurrency
   * gate AND the enqueue, as ONE operation.
   *
   * They are fused deliberately (#502). Splitting them left the admission check
   * check-then-act: the count took the queue lock, released it, and the enqueue
   * took a fresh one, so K concurrent submits at `cap - 1` all read "below the
   * cap" and all landed. The DO is single-threaded, so recounting inside the
   * same method that performs the insert closes that window by construction.
   *
   * `openPrefix` scopes the budget to dispatches the CALLER actually asked for
   * (`agent-job-start-`), not to schedule fires or registration seeds that
   * share the queue.
   */
  async admitAndEnqueue(
    dispatch: SelfHostedRunDispatch,
    budget: { readonly openPrefix: string; readonly maxOpen: number; readonly ttlSecs: number; readonly nowUnix: number },
  ): Promise<EnqueueResult> {
    const existing = await this.ctx.storage.get<QueuedRun>(dispatchKey(dispatch.dispatch_id));
    // A racing double submit derives the SAME dispatch id, so the queue dedups
    // on id and both callers converge on one job.
    if (existing !== undefined) return { outcome: "duplicate" };

    // Sweep aged, NEVER-LEASED dispatches BEFORE counting (Rust
    // `AGENT_JOB_DISPATCH_TTL_SECS`). A tenant with no registered worker
    // otherwise fills the budget with dispatches nothing will ever lease or
    // ack and is locked out for the lifetime of the deployment. The sweep only
    // touches dispatches NO worker has leased, so a job already running is
    // never withdrawn by age.
    const rows = await this.#all();
    let open = 0;
    for (const queued of rows) {
      if (!queued.dispatch.dispatch_id.startsWith(budget.openPrefix)) continue;
      if (queued.acknowledged_status !== null) continue;
      const aged = budget.nowUnix - queued.dispatch.queued_at_unix >= budget.ttlSecs;
      if (aged && queued.assigned_worker_id === null) {
        await this.ctx.storage.delete(dispatchKey(queued.dispatch.dispatch_id));
        continue;
      }
      open += 1;
    }
    if (open >= budget.maxOpen) return { outcome: "over_budget", open };

    await this.ctx.storage.put(dispatchKey(dispatch.dispatch_id), {
      dispatch,
      assigned_worker_id: null,
      lease_id: null,
      lease_expires_at_unix: null,
      attempt: 0,
      acknowledged_status: null,
      acknowledged_at_unix: null,
    } satisfies QueuedRun);
    return { outcome: "enqueued" };
  }

  /** Enqueue without the caller budget (cancel dispatches, scheduler ticks). */
  async enqueue(dispatch: SelfHostedRunDispatch): Promise<EnqueueResult> {
    const existing = await this.ctx.storage.get<QueuedRun>(dispatchKey(dispatch.dispatch_id));
    if (existing !== undefined) return { outcome: "duplicate" };
    await this.ctx.storage.put(dispatchKey(dispatch.dispatch_id), {
      dispatch,
      assigned_worker_id: null,
      lease_id: null,
      lease_expires_at_unix: null,
      attempt: 0,
      acknowledged_status: null,
      acknowledged_at_unix: null,
    } satisfies QueuedRun);
    return { outcome: "enqueued" };
  }

  /**
   * Rust `withdraw_unleased_run`: remove a dispatch NO worker has leased.
   * Returns `false` when a worker already holds it — the caller must then emit
   * a `cancel_run` instead. A local withdrawal never proves the copy was
   * unique, which is why the caller reports WHICH remedy ran rather than
   * whether the cancel took effect.
   */
  async withdrawUnleased(dispatchId: string): Promise<boolean> {
    const queued = await this.ctx.storage.get<QueuedRun>(dispatchKey(dispatchId));
    if (queued === undefined || queued.assigned_worker_id !== null) return false;
    await this.ctx.storage.delete(dispatchKey(dispatchId));
    return true;
  }

  /** `true` when a dispatch with this id exists (leased or not). */
  async hasDispatch(dispatchId: string): Promise<boolean> {
    return (await this.ctx.storage.get<QueuedRun>(dispatchKey(dispatchId))) !== undefined;
  }

  /** Rust `reclaim_settled_run_dispatches`: drop every dispatch for a settled run. */
  async reclaimRun(runId: string): Promise<number> {
    let reclaimed = 0;
    for (const queued of await this.#all()) {
      if (queued.dispatch.run_id !== runId) continue;
      await this.ctx.storage.delete(dispatchKey(queued.dispatch.dispatch_id));
      reclaimed += 1;
    }
    return reclaimed;
  }

  // -------------------------------------------------------------------------
  // Poll (lease)
  // -------------------------------------------------------------------------

  /**
   * Rust `InMemorySelfHostedRunQueue::poll_run`.
   *
   * Returns the first leasable dispatch, or `null` (which the route renders as
   * `204 No Content`, exactly as Rust does). The caller has already validated
   * the worker identity — this method only decides *what work that worker may
   * be handed*.
   */
  async poll(
    worker: RegisteredSelfHostedWorker,
    request: {
      readonly supportedCapabilities: readonly string[];
      readonly nowUnix: number;
      readonly leaseDurationSecs: number;
    },
  ): Promise<SelfHostedRunLease | null> {
    const rows = await this.#all();

    // #502: runs the control plane has already told the runtime to CANCEL. A
    // `start_run` for one of these must never be handed out again — nothing
    // else `canLeaseTo` tests knows the run is over.
    const supersededRuns = new Set(
      rows
        .filter((queued) => queued.dispatch.action === "cancel_run")
        .map((queued) => queued.dispatch.run_id),
    );

    const supported = normalizedCapabilities(request.supportedCapabilities);
    // Stable order: the queue is a map in Rust (BTreeMap over dispatch id), so
    // sort by id to get the same deterministic pick.
    rows.sort((a, b) => a.dispatch.dispatch_id.localeCompare(b.dispatch.dispatch_id));

    const queued = rows.find((candidate) =>
      canLeaseTo(candidate, worker, supported, request.nowUnix, supersededRuns),
    );
    if (queued === undefined) return null;

    queued.attempt += 1;
    const leaseId = `${queued.dispatch.dispatch_id}:attempt-${queued.attempt}`;
    const leaseExpiresAtUnix = request.nowUnix + request.leaseDurationSecs;
    queued.assigned_worker_id = worker.worker_id;
    queued.lease_id = leaseId;
    queued.lease_expires_at_unix = leaseExpiresAtUnix;
    await this.ctx.storage.put(dispatchKey(queued.dispatch.dispatch_id), queued);

    const dispatch = queued.dispatch;
    return {
      dispatch_id: dispatch.dispatch_id,
      action: dispatch.action,
      lease_id: leaseId,
      tenant_id: dispatch.tenant_id,
      workspace_id: dispatch.workspace_id,
      worker_id: worker.worker_id,
      session_id: dispatch.session_id,
      run_id: dispatch.run_id,
      framework_adapter: dispatch.framework_adapter,
      required_capabilities: dispatch.required_capabilities,
      workload_ref: dispatch.workload_ref,
      attempt: queued.attempt,
      lease_expires_at_unix: leaseExpiresAtUnix,
      trust_level: TRUST_LEVEL,
      // `skip_serializing_if = "Option::is_none"` in Rust: an absent key is
      // OMITTED, never emitted as null, so a keyless dispatch rides `None`
      // end-to-end and the worker records NULL rather than a fabricated id.
      ...(dispatch.request_id === null ? {} : { request_id: dispatch.request_id }),
      ...(dispatch.trace_id === null ? {} : { trace_id: dispatch.trace_id }),
      ...(dispatch.agent_run_id === null ? {} : { agent_run_id: dispatch.agent_run_id }),
      ...(dispatch.parent_action_fingerprint === null
        ? {}
        : { parent_action_fingerprint: dispatch.parent_action_fingerprint }),
    };
  }

  // -------------------------------------------------------------------------
  // Ack
  // -------------------------------------------------------------------------

  /**
   * Rust `InMemorySelfHostedRunQueue::ack_run`, refusal for refusal.
   *
   * Every check exists because skipping it would let a worker settle work it
   * does not hold: the dispatch must exist, be in the worker's tenant AND
   * workspace, name the same run and action, be leased BY THIS WORKER under
   * THIS lease id, within the lease window, and not already acknowledged.
   */
  async ack(
    worker: RegisteredSelfHostedWorker,
    request: {
      readonly dispatchId: string;
      readonly action: SelfHostedRunAction;
      readonly leaseId: string;
      readonly runId: string;
      readonly status: SelfHostedRunAckStatus;
      readonly reportedAtUnix: number;
    },
  ): Promise<AckResult> {
    const refuse = (message: string): AckResult => ({
      outcome: "refused",
      refusal: { code: "invalid_self_hosted_worker_transport", message },
    });

    const queued = await this.ctx.storage.get<QueuedRun>(dispatchKey(request.dispatchId));
    if (queued === undefined) return refuse("unknown dispatch");
    if (
      queued.dispatch.tenant_id !== worker.tenant_id ||
      queued.dispatch.workspace_id !== worker.workspace_id
    ) {
      return refuse("worker identity is outside dispatch tenant/workspace scope");
    }
    if (queued.dispatch.run_id !== request.runId) {
      return refuse("ack run_id does not match dispatch");
    }
    if (queued.dispatch.action !== request.action) {
      return refuse("ack action does not match dispatch");
    }
    if (queued.assigned_worker_id !== worker.worker_id) {
      return refuse("ack worker does not own the active lease");
    }
    if (queued.lease_id !== request.leaseId) {
      return refuse("ack lease_id does not match active lease");
    }
    if (
      queued.lease_expires_at_unix === null ||
      request.reportedAtUnix > queued.lease_expires_at_unix
    ) {
      return refuse("ack lease has expired");
    }
    if (queued.acknowledged_status !== null) {
      return refuse("dispatch lease was already acknowledged");
    }

    queued.acknowledged_status = request.status;
    queued.acknowledged_at_unix = request.reportedAtUnix;
    await this.ctx.storage.put(dispatchKey(request.dispatchId), queued);

    return {
      outcome: "acked",
      ack: {
        dispatch_id: queued.dispatch.dispatch_id,
        action: queued.dispatch.action,
        lease_id: request.leaseId,
        tenant_id: worker.tenant_id,
        workspace_id: worker.workspace_id,
        worker_id: worker.worker_id,
        run_id: request.runId,
        status: request.status,
        accepted_at_unix: request.reportedAtUnix,
        trust_level: TRUST_LEVEL,
      },
    };
  }
}

/** Rust `QueuedSelfHostedRun::can_lease_to`, predicate for predicate. */
function canLeaseTo(
  queued: QueuedRun,
  worker: RegisteredSelfHostedWorker,
  supportedCapabilities: readonly string[],
  nowUnix: number,
  supersededRuns: ReadonlySet<string>,
): boolean {
  if (queued.acknowledged_status !== null) return false;
  // #502: a `start_run` whose run already carries a `cancel_run` is superseded
  // — the cancel is leasable, the start is not.
  if (
    queued.dispatch.action === "start_run" &&
    supersededRuns.has(queued.dispatch.run_id)
  ) {
    return false;
  }
  if (queued.dispatch.tenant_id !== worker.tenant_id) return false;
  if (queued.dispatch.workspace_id !== worker.workspace_id) return false;
  if (queued.dispatch.framework_adapter !== worker.framework_adapter) return false;
  if (!capabilitiesSupported(queued.dispatch.required_capabilities, supportedCapabilities)) {
    return false;
  }
  if (!capabilitiesSupported(queued.dispatch.required_capabilities, worker.capabilities)) {
    return false;
  }
  // A live lease blocks re-leasing; an EXPIRED one does not.
  if (queued.lease_expires_at_unix !== null && queued.lease_expires_at_unix > nowUnix) {
    return false;
  }
  return true;
}
