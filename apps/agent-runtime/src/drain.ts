/**
 * `503 node_draining` on `apps/agent-runtime` — the operator drain, honoured on
 * the agent spend path.
 *
 * ## The defect this closes (FLEET-CONSISTENCY FC-1)
 *
 * `POST /admin/v1/drain` wrote the durable `runtime-state/drain` document and
 * **nothing read it**. `apps/gateway` refused its five spend operations off an
 * unrelated deploy-time var (`GATEWAY_DRAIN`); this Worker had no drain gate on
 * either source. An operator draining a deployment ahead of a migration
 * therefore watched `/v1/chat/completions` stop while `POST /v1/agent-runs`,
 * `POST /v1/agent-jobs` and the A2A ingress kept accepting new work — and every
 * one of those spends real provider money through the gateway on the run's
 * behalf, for minutes or hours after the drain. It is finding D1's shape
 * exactly, one control later.
 *
 * `src/routes/health.ts` already reported `draining` on `/readyz` and had
 * nothing but `AGENT_RUNTIME_ENABLED` to source it from, noting that a
 * dedicated `AGENT_RUNTIME_DRAIN` var was deliberately not invented because
 * `wrangler.toml` is a composition root this slice may not edit. The durable
 * document is the source that needed no var: it is a BINDING read, so it costs
 * no `wrangler.toml` change and no `test/env-var-drift.test.ts` exception.
 *
 * ## Read per request, never memoised
 *
 * A module-scoped `const draining = …` would pin the FIRST request's answer for
 * the life of the isolate, so a deployment drained after an isolate warmed
 * would keep serving from it — draining is useless exactly when it matters.
 * `test/durable/drain.spec.ts` flips the document both ways inside one isolate
 * for that reason.
 *
 * ## Which operations, and why not the others
 *
 * The ones that START NEW BILLABLE WORK. What is deliberately NOT guarded is
 * the point of a drain rather than an omission:
 *
 *  - **the six worker-plane callbacks** (`auth.kind: "internal"`) — heartbeats,
 *    events, artifacts, checkpoints, poll, ack. These are IN-FLIGHT work
 *    reporting back. Refusing them during a drain would strand every running
 *    job, lose its artifacts and its checkpoint, and make the drain destroy the
 *    work it exists to let finish.
 *  - **the four agent-job READS** (`getAgentJob`, `listAgentJobEvents`,
 *    `getAgentJobResult`) — a client must be able to watch its outstanding work
 *    complete on a draining node.
 *  - **`cancelAgentJob`** — the operation an operator most needs while
 *    draining.
 *
 * The gate lives on the BEARER leg only (`middleware/auth.ts::bearerAuth`),
 * which is structurally why no internal callback can reach it.
 *
 * ## THIS FILE IS A LEAF, ON PURPOSE
 *
 * It imports nothing. `apps/mcp/test/drain-fleet.test.ts` reads three Workers'
 * drain tables out of one test bundle, which is only sound while each side is
 * dependency-free — the constraint
 * `apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts` documents
 * and asserts for `registry.ts`. The parse/precedence logic below is a COPY of
 * `apps/mcp/src/drain.ts`'s deliberately (five separately-bundled Workers may
 * not import one another), and `drain-fleet.test.ts` compares the copies as
 * DATA so they cannot drift.
 */

/** The `control_plane_resources` table the admin API writes. */
export const RESOURCE_TABLE = "control_plane_resources";
import { controlDatabaseFrom } from "./control-data.js";
/** `resource_kind` of the singleton runtime-state rows. */
export const DRAIN_COLLECTION = "runtime-state";
/** `resource_id` of the singleton drain row. */
export const DRAIN_ID = "drain";

/** Rust's drain refusal, byte for byte (`chat.rs:2862` and its four siblings). */
export const NODE_DRAINING_STATUS = 503;
export const NODE_DRAINING_CODE = "node_draining";
export const NODE_DRAINING_MESSAGE =
  "gateway node is draining and is not accepting new AI requests";

/** The drain document could not be READ. Refuse, and say so honestly. */
export const DRAIN_UNAVAILABLE_STATUS = 503;
export const DRAIN_UNAVAILABLE_CODE = "drain_state_unavailable";

export type DrainSource = "durable" | "deploy_var" | "none" | "unavailable";

export interface DrainState {
  readonly draining: boolean;
  readonly accepting_new_requests: boolean;
  readonly reason: string | null;
  readonly source: DrainSource;
  readonly detail?: string;
}

/** The `{status, code, message}` shape `middleware/errors.ts::HttpError` takes. */
export interface DrainRefusal {
  readonly status: number;
  readonly code: string;
  readonly message: string;
}

/** No drain in effect — Rust's default state. */
export const NOT_DRAINING: DrainState = {
  draining: false,
  accepting_new_requests: true,
  reason: null,
  source: "none",
};

/**
 * Read a stored `runtime-state/drain` document.
 *
 * Strict in both directions, and both matter:
 *
 *  - only the JSON boolean `true` drains, so a half-written row cannot take a
 *    deployment out of rotation;
 *  - a document carrying a non-null `tenant_id` is IGNORED. The operator drain
 *    is deployment state read by every Worker by primary key; a tenant-
 *    attributed row is either a bug or one tenant's admin key trying to drain
 *    the whole fleet, and honouring it would be a cross-tenant denial of
 *    service. `apps/control-plane` refuses to write one; this refuses to
 *    believe one.
 */
export function parseDrainDocument(document: Record<string, unknown> | null): DrainState {
  if (document === null) return NOT_DRAINING;
  const tenantId = document.tenant_id;
  if (tenantId !== null && tenantId !== undefined) return NOT_DRAINING;
  if (document.draining !== true) return NOT_DRAINING;
  const rawReason = document.reason;
  return {
    draining: true,
    accepting_new_requests: false,
    reason: typeof rawReason === "string" && rawReason !== "" ? rawReason : null,
    source: "durable",
  };
}

/**
 * THE PRECEDENCE RULE — durable document OR deploy-time var, never "latest
 * wins".
 *
 * The two sources are not redundant: the document is flipped at RUNTIME by
 * `POST /admin/v1/drain` and is read by every Worker with the control database
 * bound; `GATEWAY_DRAIN` is flipped by a DEPLOY and is declared only in
 * `apps/gateway/wrangler.toml`. Under "latest wins", a stale deploy var
 * silently un-drains a deployment an operator just drained by API, or a
 * `{"draining": false}` API call silently re-admits traffic to a deployment
 * drained at deploy time for a migration. Both are FC-1 again. So: either
 * source drains, neither cancels the other, and a lookup FAILURE outranks both
 * because it is not an answer.
 */
export function combineDrain(durable: DrainState, deployVar: boolean): DrainState {
  if (durable.source === "unavailable") return durable;
  if (durable.draining) return durable;
  if (deployVar) {
    return { draining: true, accepting_new_requests: false, reason: null, source: "deploy_var" };
  }
  return NOT_DRAINING;
}

/** Only the exact string `"true"` drains, matching `GATEWAY_DRAIN`'s parse. */
export function drainVarSet(value: string | undefined): boolean {
  return value?.trim().toLowerCase() === "true";
}

/**
 * Read the durable document out of the CONTROL database.
 *
 * `apps/agent-runtime` binds it as `env.CONTROL_DB` (`src/ports.ts`), the same
 * database `d1WorkerIdentityPort` and the durable agent-upstream registry read.
 *
 * **FAIL CLOSED.** An unbound database means this deployment has no control
 * plane at all — `resolveDeps` already refuses every authenticated surface with
 * `503 agent_runtime_unavailable` unless a dev bundle is installed — so "no
 * document" is the honest answer and {@link NOT_DRAINING} is returned. A
 * database that IS bound and then FAILS is different: the control exists and
 * could not be evaluated, so the answer is a refusal (`source: "unavailable"`),
 * never an admit. `src/admission/admit.ts` takes the identical posture for the
 * identical reason.
 */
export async function readDurableDrain(db: D1Database | undefined): Promise<DrainState> {
  if (db === undefined) return NOT_DRAINING;
  let json: string | null;
  try {
    const row = await db
      .prepare(
        `SELECT document_json FROM ${RESOURCE_TABLE}
          WHERE resource_kind = ? AND resource_id = ?`,
      )
      .bind(DRAIN_COLLECTION, DRAIN_ID)
      .first<{ document_json: string }>();
    json = row === null ? null : row.document_json;
  } catch (cause) {
    return {
      draining: true,
      accepting_new_requests: false,
      reason: null,
      source: "unavailable",
      detail: cause instanceof Error ? cause.message : String(cause),
    };
  }
  if (json === null) return NOT_DRAINING;
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (cause) {
    // An unreadable row is NOT "no drain". "The document is corrupt" and "there
    // is no document" are different facts and only one of them is safe to serve
    // traffic on.
    return {
      draining: true,
      accepting_new_requests: false,
      reason: null,
      source: "unavailable",
      detail: `runtime-state/drain holds unparseable document_json: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return {
      draining: true,
      accepting_new_requests: false,
      reason: null,
      source: "unavailable",
      detail: "runtime-state/drain document_json is not an object",
    };
  }
  return parseDrainDocument(parsed as Record<string, unknown>);
}

/** Bindings this module reads. */
export interface DrainBindings {
  readonly CONTROL_DATA?: unknown;
}

/**
 * Resolve the drain for THIS request.
 *
 * `deployVar` is a parameter rather than an `env` read so the fleet-wide
 * precedence rule ({@link combineDrain}) is expressed and tested here even
 * though `apps/agent-runtime/wrangler.toml` declares no drain var — and so that
 * adding one later is a one-line change at the call site rather than a second,
 * divergent copy of the rule. The production call site passes `false`.
 */
export async function resolveDrain(
  env: DrainBindings | undefined,
  deployVar = false,
): Promise<DrainState> {
  const durable = await readDurableDrain(controlDatabaseFrom(env));
  return combineDrain(durable, deployVar);
}

/**
 * The refusal a drain state produces, or `null` when the request may proceed.
 *
 * Two codes, both 503 and both refusals: `node_draining` is Rust's answer for
 * "the operator drained this deployment", and `drain_state_unavailable` is
 * "the control could not be evaluated". Collapsing them would tell an operator
 * the node is draining while `GET /admin/v1/drain` says it is not — the
 * incident-time lie this repo refused to ship as `applied: true`.
 */
export function drainRefusal(state: DrainState): DrainRefusal | null {
  if (state.source === "unavailable") {
    return {
      status: DRAIN_UNAVAILABLE_STATUS,
      code: DRAIN_UNAVAILABLE_CODE,
      message: `operator drain state is unavailable: ${state.detail ?? "control database lookup failed"}`,
    };
  }
  if (!state.draining) return null;
  return {
    status: NODE_DRAINING_STATUS,
    code: NODE_DRAINING_CODE,
    message: NODE_DRAINING_MESSAGE,
  };
}

/**
 * The contract operations refused while draining — the ones that start NEW
 * billable work.
 *
 * Five of the fifteen this Worker owns. The other ten are enumerated in this
 * file's header with the reason each one keeps serving; the short version is
 * that a drain must let outstanding work finish, be watched, and be cancelled.
 */
export const DRAIN_GUARDED_OPERATION_IDS: readonly string[] = [
  "createAgentRun",
  "submitAgentJob",
  "invokeAgent",
  "sendAgentMessage",
  "streamAgentMessage",
];

/** Does this contract operation start new billable work? */
export function isDrainGuardedOperation(operationId: string): boolean {
  return DRAIN_GUARDED_OPERATION_IDS.includes(operationId);
}
