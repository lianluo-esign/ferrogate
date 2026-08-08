/**
 * `503 node_draining` on `apps/mcp` — the operator drain, honoured on the MCP
 * spend path.
 *
 * ## The defect this closes (FLEET-CONSISTENCY FC-1)
 *
 * `POST /admin/v1/drain` wrote the durable `runtime-state/drain` document and
 * **nothing read it**. `apps/gateway` refused its five spend operations off an
 * unrelated deploy-time var (`GATEWAY_DRAIN`); this Worker had no drain gate on
 * either source. So an operator draining a deployment ahead of a migration
 * watched `/v1/chat/completions` stop and `POST /v1/mcp` `tools/call` keep
 * running — reaching a paid upstream, a paid asset pull and a paid tool
 * execution on every request. It is finding D1's shape exactly ("the exploit is
 * call the other endpoint"), one control later.
 *
 * ## Why the durable document and not a var
 *
 * `apps/gateway/src/routes/readiness.ts` argues at length that a Worker has no
 * long-lived process, so a runtime drain must be a durable read rather than an
 * `AtomicBool` — and then approximates it with a deploy-time var because the
 * only read site was an ANONYMOUS `/readyz`, where a per-request durable lookup
 * is a free amplification target.
 *
 * That objection does not apply here, and saying why is the design:
 *
 *  - **This gate is behind authentication AND admission.** It runs after
 *    `ports.auth.authenticate` has resolved a credential and after
 *    `ports.admission.admit` has already charged the caller's quota chain,
 *    monthly budget, wallet and RPM window — which are themselves control-
 *    database reads. An authenticated caller who can reach this line has
 *    already paid for several D1 lookups; one more primary-key row read is not
 *    a new amplification surface.
 *  - **`apps/mcp` declares no drain var and cannot declare one.**
 *    `wrangler.toml` is a composition root this slice may not edit and
 *    `test/env-var-drift.test.ts` (rightly) fails an undeclared `env` read, so
 *    the durable document is not merely the better source here — it is the only
 *    one available. See {@link resolveDrain}'s `deployVar` parameter for how the
 *    fleet-wide precedence rule stays expressible anyway.
 *
 * ## Read per request, never memoised
 *
 * A module-scoped `const draining = …` would pin the FIRST request's answer for
 * the life of the isolate, so a deployment drained after an isolate warmed
 * would keep serving from it — draining is useless exactly when it matters.
 * `test/drain-fleet.test.ts` flips the document both ways inside one isolate
 * for that reason, and `test/drain.test.ts` mutation-proves the read.
 *
 * ## Which operations, and why not all of them
 *
 * The ones that SPEND. `tools/list`, `resources/list`, `initialize` and `ping`
 * are catalogue and handshake reads that produce no upstream call; refusing
 * them would break a client's failover discovery at the moment it needs it most
 * — the same reason `apps/gateway/src/routes/drain.ts` deliberately leaves
 * `listModels` unguarded. The identity operations
 * (`authorizeMcpIdentity` / `getMcpIdentity` / `revokeMcpIdentity`) are
 * likewise not spend, and `revokeMcpIdentity` in particular must keep working
 * while draining: an operator draining a deployment during a credential
 * incident still has to be able to revoke.
 *
 * ## THIS FILE IS A LEAF, ON PURPOSE
 *
 * It imports nothing. `apps/mcp/test/drain-fleet.test.ts` reads the same three
 * Workers' drain tables out of one test bundle, which is only sound while each
 * side is dependency-free — the constraint
 * `apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts` documents
 * and asserts for `registry.ts`. The copy of the parse/precedence logic below
 * is a copy DELIBERATELY (five separately-bundled Workers may not import one
 * another), and `drain-fleet.test.ts` compares the copies as DATA so they
 * cannot drift.
 */
import { controlDatabaseFrom } from "./control-data.js";

/** The `control_plane_resources` table the admin API writes. */
export const RESOURCE_TABLE = "control_plane_resources";
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

/** The `{status, code, message}` shape `src/ports.ts::AuthError` uses. */
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
 * `apps/mcp` binds the control database as `env.DB` — see `src/ports.ts`
 * ("`env.DB` already IS the control database"), which is why no new binding is
 * needed and none is declared.
 *
 * **FAIL CLOSED.** An unbound database means this deployment has no control
 * plane at all and every authenticated surface already answers
 * `503 mcp_auth_unavailable`, so "no document" is the honest answer and
 * {@link NOT_DRAINING} is returned. A database that IS bound and then FAILS is
 * different: the control exists and could not be evaluated, so the answer is a
 * refusal (`source: "unavailable"`), never an admit. `src/admission/gate.ts`
 * takes the identical posture for the identical reason.
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
 * though `apps/mcp/wrangler.toml` declares no drain var — and so that adding one
 * later is a one-line change at the call site rather than a second, divergent
 * copy of the rule. The production call site passes `false`.
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
 * The JSON-RPC methods on `POST /v1/mcp` that SPEND, and are therefore refused
 * while draining.
 *
 * `tools/call` executes a governed tool against a per-tenant upstream;
 * `resources/read` and `prompts/get` dereference upstream content. Those are
 * exactly the three `protocol.ts::methodRequiresName` treats as targeted
 * operations, and the three whose dispatch reaches a remote server.
 *
 * Absent, deliberately: `initialize`, `ping`, `notifications/initialized`,
 * `server/discover`, `tools/list`, `resources/list`. A draining node must keep
 * answering discovery, or a client cannot learn where to fail over to.
 */
export const DRAIN_GUARDED_RPC_METHODS: readonly string[] = [
  "tools/call",
  "resources/read",
  "prompts/get",
];

/**
 * The contract operations refused while draining.
 *
 * `executeMcpTool` is the REST transport for the same governed tool chokepoint
 * `tools/call` runs, so it is guarded for the same reason. `mcpJsonRpc` is NOT
 * listed: it is one operation carrying many methods, and guarding it wholesale
 * would refuse `initialize` and `tools/list` too — the method-level table above
 * is what applies there.
 */
export const DRAIN_GUARDED_OPERATION_IDS: readonly string[] = ["executeMcpTool"];

/** Does this JSON-RPC method spend, and therefore stop while draining? */
export function isDrainGuardedRpcMethod(method: string): boolean {
  return DRAIN_GUARDED_RPC_METHODS.includes(method);
}
