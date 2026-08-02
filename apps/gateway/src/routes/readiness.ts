/**
 * `GET /readyz` — port of `server/local.rs::handle_readyz` +
 * `AppState::cluster_status` / `ClusterStatus::new` / `drain_status`.
 *
 * The Rust readiness answer is NOT an upstream-health probe (an earlier note
 * here said it was; it is not). It is exactly two conditions on the node's own
 * state, ANDed:
 *
 *   state_ready = the node has an ACTIVE CONFIG REVISION loaded
 *                 (`ClusterSyncStatus.active_revision` non-empty)
 *   accepting   = the operator has not put the node into DRAIN
 *
 * `ready == false` answers **503** with `status: "not_ready"` and a
 * `readiness_reason` naming which condition failed. That decision table is
 * ported verbatim below; only its two INPUTS have Workers-specific sources.
 *
 * ## The PLATFORM-LIMIT marker that stood here is CLOSED (FLEET-CONSISTENCY FC-1,
 * wave 22 — the last of its three legs)
 *
 * It read: in Rust `drain` is an `AtomicBool` inside the one long-lived process,
 * flipped at RUNTIME by an operator call; a Worker has no process, isolates
 * share no mutable memory, so the approximation is the DEPLOY-TIME
 * `GATEWAY_DRAIN` var and closing it "means a `DRAIN` DO/KV binding plus the
 * operator route that writes it, which is a control-plane slice, not a routing
 * one."
 *
 * **The control-plane slice exists.** `POST /admin/v1/drain` has written the
 * durable `runtime-state/drain` document in `control_plane_resources` since
 * wave 20, and wave 22 joined `apps/mcp` and `apps/agent-runtime` to it. This
 * Worker was the last one still refusing off a different variable from the one
 * the operator writes — so `POST /admin/v1/drain` shut MCP `tools/call` and
 * `POST /v1/agent-jobs` and left `/v1/chat/completions` serving. That is FC-1's
 * exact shape ("call the other endpoint"), inverted: the joined Workers were
 * durable and this one was var-only.
 *
 * {@link resolveDrainState} closes it. The durable document is read from
 * `CONTROL_DB` — a binding this Worker already declares and already reads for
 * RBAC, guardrail policy and the agent-upstream registry — and OR-ed with the
 * var by {@link combineDrain}, the precedence rule
 * `apps/mcp/src/drain.ts::combineDrain` states for the whole fleet.
 *
 * ### The amplification objection, answered rather than inherited
 *
 * The old marker's live concern was real and is the reason the var was chosen:
 * `/readyz` is ANONYMOUS, so a durable read there is a free amplification
 * target. Three things bound it, and they are why this is now safe to mount:
 *
 *  - the read is ONE primary-key row (`resource_kind`, `resource_id`) against
 *    the indexed `control_plane_resources`, not a scan and not a hot single-DO
 *    key — D1 is a replicated SQLite read, so it has none of the single-object
 *    serialization a DO drain would have had;
 *  - `/readyz` sits BEHIND the pre-auth network gate (`middleware/network.ts`,
 *    mounted ahead of `contractAuth` in `createGatewayApp`), which is where an
 *    unauthenticated flood is refused. It is not an unprotected surface;
 *  - the DATA-PLANE read — the one that actually stops spend — happens in
 *    `./drain.ts::nodeDrainGate`, which runs after `contractAuth` and after
 *    admission, i.e. after the caller has already paid for several control-
 *    database lookups. This is the same argument `apps/mcp/src/drain.ts` makes
 *    for its own mount, and it is why both Workers now answer the same way.
 *
 * `/healthz` is deliberately NOT touched: liveness must not flip on a drain or
 * an orchestrator restarts the node and destroys the in-flight work the drain
 * exists to let finish.
 *
 * What DOES remain a platform difference, stated so it is not re-discovered as
 * a defect: a `wrangler versions` var flip still takes a deploy, and a durable
 * flip is visible to the next request rather than to an in-process
 * `AtomicBool`'s readers instantly. Neither changes the decision table.
 *
 * ## The `node_draining` marker that stood here is CLOSED (cutover D6)
 *
 * It read: "the drain is READ by this endpoint and by nothing else, so it
 * advertises a posture the data plane does not honour", and it was right —
 * `GATEWAY_DRAIN=true` flipped `/readyz` to 503 and left
 * `/v1/chat/completions` serving, so an operator draining a deployment before a
 * migration still took new billable traffic.
 *
 * `./drain.ts` now mounts the guard the marker specified: `nodeDrainGate()`,
 * mounted by `createGatewayApp` after the post-auth middleware chain, refuses
 * the five spend-producing operations with Rust's exact
 * `503 node_draining "gateway node is draining and is not accepting new AI
 * requests"` (`chat.rs:2862`, `embeddings.rs:98`, `images.rs:115`,
 * `messages.rs:145`). It calls {@link drainStatus} — this file's parse, not a
 * second one — so the endpoint and the data plane can never disagree about
 * whether a deployment is draining, and `test/routes/drain.test.ts` asserts
 * that agreement directly over every spelling of the var.
 *
 * That was never the platform limit described above: THAT one is about how fast
 * the FLAG can be flipped, and it stands. This was about the flag being read on
 * one route out of 31, and it is now read on six.
 *
 * PORT-TODO(cert3-dataplane · `responses.rs:77 ReadinessResponse`): this
 * Worker's `/readyz` answers `{status, service, runtime, cluster}` and omits
 * `version`, which Rust's `ReadinessResponse` carries and which `apps/mcp`,
 * `apps/agent-runtime`, `apps/control-plane` and `apps/telemetry` all now
 * emit. It is the LAST readiness-identity divergence in the fleet, and
 * `apps/telemetry/test/fleet-health-contract.test.ts` records it as an exact
 * computed exception set (`expect(omitting).toEqual(["gateway"])`) — so adding
 * `version: SERVICE_VERSION` to `readinessResponse` turns that gate RED until
 * the exception is deleted with it. Both halves land together, on purpose.
 *
 * The `ClusterStatus` members that describe a PEER TOPOLOGY — `cluster_id`,
 * `node_id`, `node_region`, `node_zone`, `state_backend`, `counter_backend`,
 * `last_sync_at_unix` — are deliberately absent rather than faked: they
 * describe FerroGate's own gossip/shared-state cluster, which is replaced
 * wholesale by the Cloudflare edge (Workers isolates are not peers, an isolate
 * has no stable node identity, and there is no config-sync loop to report a
 * `last_sync_at` for). `stale`/`last_sync_error` are reported as the constants
 * that no-sync implies, because the decision table reads them.
 */
import { configSnapshotId } from "@ferrogate/config";
import type { Context } from "hono";
import type { GatewayEnv } from "../ports.js";

/** Worker var: `"true"` puts this deployment into operator drain. */
export const DRAIN_VAR = "GATEWAY_DRAIN";

/**
 * The durable half of the drain, named exactly as every other Worker names it.
 *
 * These three constants are the same strings `apps/mcp/src/drain.ts`,
 * `apps/agent-runtime/src/drain.ts` and
 * `apps/control-plane/src/store/runtime_state.ts` use. They are RESTATED here
 * rather than imported because the five Workers are separately bundled and no
 * app may import another's module graph; `apps/mcp/test/drain-fleet.test.ts`
 * and `apps/gateway/test/fleet-control-matrix.test.ts` compare the copies as
 * DATA so they cannot drift apart silently.
 */
export const RESOURCE_TABLE = "control_plane_resources";
/** `resource_kind` of the singleton runtime-state rows. */
export const DRAIN_COLLECTION = "runtime-state";
/** `resource_id` of the singleton drain row. */
export const DRAIN_ID = "drain";

/** The drain document could not be READ. Refuse, and say so honestly. */
export const DRAIN_UNAVAILABLE_CODE = "drain_state_unavailable";

/** Where a drain answer came from. */
export type DrainSource = "durable" | "deploy_var" | "none" | "unavailable";

/** One request's drain answer. */
export interface DrainState {
  readonly draining: boolean;
  readonly accepting_new_requests: boolean;
  readonly reason: string | null;
  readonly source: DrainSource;
  readonly detail?: string;
}

/** No drain in effect — Rust's default state. */
export const NOT_DRAINING: DrainState = {
  draining: false,
  accepting_new_requests: true,
  reason: null,
  source: "none",
};

/** Bindings this module reads. */
export interface ReadinessBindings {
  readonly GATEWAY_DRAIN?: string | undefined;
  /** The CONTROL database: `control_plane_resources`. Same handle RBAC uses. */
  readonly CONTROL_DB?: D1Database | undefined;
}

/** `ClusterStatus`, restricted to the members the Workers port can answer. */
export interface ReadinessClusterStatus {
  /** `config.cluster.enabled` — always false: there is no peer cluster here. */
  readonly enabled: boolean;
  /** `ClusterSyncStatus.active_revision` — the config snapshot being served. */
  readonly active_revision: string;
  readonly stale: boolean;
  readonly last_sync_error: string | null;
  readonly ready: boolean;
  readonly readiness_reason: string;
  readonly draining: boolean;
  readonly accepting_new_requests: boolean;
}

/**
 * `AppState::drain_status`, DEPLOY-TIME half only.
 *
 * This is one of the drain's two sources, not the answer. {@link resolveDrainState}
 * is the answer, and it is what `/readyz` and `./drain.ts` call. This function
 * stays exported and stays synchronous because the var decision table
 * (`test/routes/drain.test.ts` holds every spelling of it) is worth testing on
 * its own, and because {@link combineDrain} needs the boolean.
 */
export function drainStatus(env: ReadinessBindings | undefined): {
  draining: boolean;
  accepting_new_requests: boolean;
} {
  // Only the exact string `"true"` drains. A typo'd var must not take a
  // deployment out of rotation, and must not silently keep a drained one in it
  // either — anything else is "not draining", which is the Rust default state.
  const draining = env?.GATEWAY_DRAIN?.trim().toLowerCase() === "true";
  return { draining, accepting_new_requests: !draining };
}

/**
 * Read a stored `runtime-state/drain` document.
 *
 * Strict in both directions, byte for byte with
 * `apps/mcp/src/drain.ts::parseDrainDocument`:
 *
 *  - only the JSON boolean `true` drains, so a half-written row cannot take a
 *    deployment out of rotation;
 *  - a document carrying a non-null `tenant_id` is IGNORED. The operator drain
 *    is DEPLOYMENT state read by every Worker by primary key; a tenant-
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
 * Read the durable document out of the CONTROL database.
 *
 * **FAIL CLOSED, and specifically NOT back to the var.** An UNBOUND database
 * means this deployment has no control plane at all — `depsFromEnv` already
 * falls back to the `TENANT_RBAC_ACTIONS` / `GATEWAY_GUARDRAIL_POLICIES` vars
 * in that posture — so "no document" is the honest answer and
 * {@link NOT_DRAINING} is returned, leaving `GATEWAY_DRAIN` as the only source.
 * A database that IS bound and then FAILS is a different fact: the control
 * exists and could not be evaluated, so the answer is a refusal
 * (`source: "unavailable"`), never an admit. `routes/agent-upstreams.ts` takes
 * the identical posture on the sibling capability, for the identical reason.
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

/**
 * THE PRECEDENCE RULE — durable document OR deploy-time var, never "latest
 * wins". Restated from `apps/mcp/src/drain.ts::combineDrain`, which states the
 * reasoning for the fleet:
 *
 * The two sources are not redundant. The document is flipped at RUNTIME by
 * `POST /admin/v1/drain` and is read by every Worker with the control database
 * bound; `GATEWAY_DRAIN` is flipped by a DEPLOY and is declared only here.
 * Under "latest wins" a stale deploy var silently un-drains a deployment an
 * operator just drained by API, or a `{"draining": false}` API call silently
 * re-admits traffic to a deployment drained at deploy time for a migration.
 * Both are FC-1 again, wearing the other half's clothes. So: either source
 * drains, neither cancels the other, and a lookup FAILURE outranks both because
 * it is not an answer.
 */
export function combineDrain(durable: DrainState, deployVar: boolean): DrainState {
  if (durable.source === "unavailable") return durable;
  if (durable.draining) return durable;
  if (deployVar) {
    return { draining: true, accepting_new_requests: false, reason: null, source: "deploy_var" };
  }
  return NOT_DRAINING;
}

/**
 * Resolve the drain for THIS request — the whole answer, both sources.
 *
 * Read per request and NEVER memoised. A module-scoped `const draining = …`
 * would pin the first request's answer for the life of the isolate, so a
 * deployment drained after an isolate warmed would keep serving from it —
 * draining is useless exactly when it matters.
 * `test/fleet-control-matrix.test.ts` §5.2 flips the document both ways inside
 * one isolate for that reason.
 */
export async function resolveDrainState(
  env: ReadinessBindings | undefined,
): Promise<DrainState> {
  const durable = await readDurableDrain(env?.CONTROL_DB);
  return combineDrain(durable, drainStatus(env).draining);
}

/**
 * `ClusterStatus::new` — the readiness decision table, verbatim.
 *
 * `activeRevision` empty ⇒ the node has no config loaded ⇒ `revision_missing`.
 * That arm is reachable here (a caller can pass `""`), and it is what keeps the
 * port honest: the Workers config source always yields a revision, so the arm
 * is proven by the unit test rather than by the deployment.
 */
export function clusterStatus(options: {
  activeRevision: string;
  draining: boolean;
  stale?: boolean;
  lastSyncError?: string | null;
  /**
   * The durable drain document is bound and could NOT be read.
   *
   * A separate input rather than `draining: true`, and the distinction is the
   * one FC-1 settled for the whole fleet: refusing is non-negotiable (a control
   * that admits when its backend is unavailable recreates the bypass), but
   * telling an operator the node is DRAINING while `GET /admin/v1/drain` says
   * otherwise is the incident-time lie this repo refused to ship. So the node
   * is not ready and is not accepting, and `readiness_reason` says
   * `drain_state_unavailable` rather than `operator_drain`. Same split as the
   * two 503 codes `apps/mcp/src/drain.ts::drainRefusal` answers with.
   */
  drainUnavailable?: boolean;
}): ReadinessClusterStatus {
  const { activeRevision, draining } = options;
  const stale = options.stale ?? false;
  const lastSyncError = options.lastSyncError ?? null;
  const drainUnavailable = options.drainUnavailable ?? false;

  const hasRevision = activeRevision.trim() !== "";
  const stateReady = hasRevision;
  const acceptingNewRequests = !draining && !drainUnavailable;
  const ready = stateReady && acceptingNewRequests;

  const readinessReason = drainUnavailable
    ? DRAIN_UNAVAILABLE_CODE
    : draining
      ? "operator_drain"
        : stale && hasRevision
          ? "stale_state"
          : stateReady
            ? "state_loaded"
            : lastSyncError !== null
              ? "sync_error"
              : "revision_missing";

  return {
    enabled: false,
    active_revision: activeRevision,
    stale,
    last_sync_error: lastSyncError,
    ready,
    readiness_reason: readinessReason,
    draining,
    accepting_new_requests: acceptingNewRequests,
  };
}

/**
 * The Workers source of `active_revision`.
 *
 * Rust hashes the whole loaded `Config`; here the equivalent input is the bound
 * env — the vars ARE the config on this platform. Bindings that are objects
 * (D1, R2, DO, Queues) are reduced to their NAMES: their handles are not
 * serializable and their identity is fixed at deploy time, so the name is the
 * part that distinguishes one deployment's config from another's.
 */
export function activeRevisionFor(env: Record<string, unknown> | undefined): string {
  const snapshot: Record<string, unknown> = {};
  for (const key of Object.keys(env ?? {}).sort()) {
    const value = (env as Record<string, unknown>)[key];
    snapshot[key] = typeof value === "string" || typeof value === "number" ? value : "[binding]";
  }
  return configSnapshotId(snapshot);
}

/**
 * `handle_readyz` — 200 `ready` / 503 `not_ready`, with the cluster block.
 *
 * ASYNC since wave 22: the drain input is now the durable document OR the var
 * ({@link resolveDrainState}), so readiness flips on `POST /admin/v1/drain`
 * without a deploy. Readiness MUST flip, or the probe keeps telling a load
 * balancer to send traffic that every spend request then refuses — the drain
 * would be invisible to exactly the component it exists to inform.
 * `/healthz` is untouched and stays synchronous: see the module header.
 */
export async function readinessResponse(
  c: Context<GatewayEnv>,
  service: string,
  runtime: string,
): Promise<Response> {
  const env = c.env as (Record<string, unknown> & ReadinessBindings) | undefined;
  const drain = await resolveDrainState(env);
  const cluster = clusterStatus({
    activeRevision: activeRevisionFor(env),
    draining: drain.draining && drain.source !== "unavailable",
    drainUnavailable: drain.source === "unavailable",
  });
  return c.json(
    {
      status: cluster.ready ? "ready" : "not_ready",
      service,
      runtime,
      cluster,
    },
    cluster.ready ? 200 : 503,
  );
}
