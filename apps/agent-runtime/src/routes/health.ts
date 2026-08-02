/**
 * The three shared anonymous probes — `GET /healthz`, `GET /readyz`,
 * `GET /health` — in the shape `ROUTE-MAP.md` requires of EVERY Worker.
 *
 * ## The divergence this closes (cutover certification, operations 53 + 54)
 *
 * `apps/gateway` and `apps/mcp` answer `{status, service, runtime, …}` and port
 * the Rust readiness DECISION TABLE (`ready`/`not_ready`, 200/**503**, a
 * `readiness_reason`). `apps/agent-runtime` answered a flat
 * `200 {"ok":true}` on BOTH probes — "a different document entirely" — with no
 * state check, no operator check, and no way to ever answer 503. The
 * certification's verdict was blunt and correct:
 *
 * > *A load balancer pointed at agent-runtime's `/readyz` gets "ready" from a
 * > Worker that cannot serve, forever.*
 *
 * That is not cosmetic. `resolveDeps(env)` returning `undefined` is the
 * FAIL-CLOSED posture this Worker already has for its credential authorities:
 * every authenticated surface then answers `503 agent_runtime_unavailable`
 * (`middleware/auth.ts::depsOrThrow`). A health-checked rollout of a Worker in
 * exactly that state was never rolled back, because the probe said `ok`.
 *
 * ## The decision table, and why it is the gateway's
 *
 * `apps/gateway/src/routes/readiness.ts` ports `ClusterStatus::new` verbatim:
 * `state_ready ∧ accepting` → 200 `ready`, otherwise 503 `not_ready` with a
 * `readiness_reason` naming which conjunct failed, and DRAIN outranks state in
 * the reason. The same two conjuncts are reproduced here against this Worker's
 * own inputs, using the SAME reason vocabulary so an operator's dashboard does
 * not need a second one:
 *
 * | condition | `readiness_reason` | status |
 * |---|---|---|
 * | operator disabled the runtime (`AGENT_RUNTIME_ENABLED=0`) | `operator_drain` | 503 |
 * | ports unresolvable (`resolveDeps` → `undefined`) | `revision_missing` | 503 |
 * | otherwise | `state_loaded` | 200 |
 *
 * Two deliberate mappings:
 *
 *  - **`operator_drain` is `AGENT_RUNTIME_ENABLED`, not a new var.** It is the
 *    operator switch this Worker already honours — `requireRuntimeEnabled`
 *    refuses every agent-job operation with `agent_runtime_disabled` when it is
 *    off — so it is exactly "the operator has taken this deployment out of
 *    service for agent work". A dedicated `AGENT_RUNTIME_DRAIN` would be the
 *    closer analogue of `GATEWAY_DRAIN`, and it is deliberately NOT invented:
 *    `wrangler.toml` is a composition root this slice may not edit, and
 *    `test/env-var-drift.test.ts` would (rightly) fail an undeclared read.
 *  - **`revision_missing` is the unresolvable-ports case.** Rust's
 *    `revision_missing` means "the node has no active state loaded". This
 *    Worker has no config-revision loop; the equivalent "cannot serve from its
 *    own state" condition is the fail-closed `resolveDeps`.
 *
 * Peer-topology members (`cluster_id`, `node_id`, `last_sync_at_unix`, …) are
 * absent for the reason `readiness.ts` gives at length: they describe
 * FerroGate's gossip cluster, which the Cloudflare edge replaces wholesale.
 *
 * ## MOUNTING — wired in wave 17 (the integrate step)
 *
 * `src/index.ts` used to carry three inline handlers:
 *
 * ```ts
 * app.get("/healthz", (c) => c.json({ ok: true }));
 * app.get("/readyz", (c) => c.json({ ok: true }));
 * app.get("/health", (c) => c.json({ ok: true }));
 * ```
 *
 * They are now one line — `app.route("/", healthRoutes);` — placed AHEAD of
 * `app.use("/v1/*", contractAuth)` and of the three `app.route("/", …)` groups,
 * because Hono runs matched handlers in registration order and all three probes
 * are contract-`anonymous`.
 *
 * **Mount gate (proven):** delete the `app.route("/", healthRoutes)` line and
 * `bun run test` goes RED in `test/routes/health-contract.test.ts`
 * ("the deployed Worker serves the contract probes"), which drives `SELF`
 * rather than a locally-built app precisely so it cannot be satisfied by this
 * module existing. Observed on the mutated tree: `SELF.fetch("/healthz")` →
 * 404, and re-inlining `{ok:true}` fails the member assertions on `/readyz`.
 * Seam row **AR-C10** in `docs/rewrite/MOUNT-SEAMS.md`.
 */
import { Hono } from "hono";
import {
  DRAIN_UNAVAILABLE_CODE,
  type DrainBindings,
  type DrainState,
  NOT_DRAINING,
  resolveDrain,
} from "../drain.js";
import type { AgentRuntimeBindings, AgentRuntimeEnv } from "../ports.js";
import { configFromEnv, resolveDeps } from "../ports.js";

/** Rust `SERVICE_NAME` for this front. */
export const SERVICE_NAME = "ferrogate-agent-runtime";
/** Rust reports `runtime: "pingora"`; the Pingora data plane is eliminated. */
export const RUNTIME_NAME = "workers";
/**
 * Rust `HealthResponse.version` is `env!("CARGO_PKG_VERSION")`.
 *
 * The TypeScript equivalent is the workspace version — `package.json`'s
 * `"0.0.0"` — carried as a constant rather than imported, because a
 * `resolveJsonModule` import of the ROOT manifest would bundle it into every
 * Worker. `apps/control-plane/src/adapters.ts` reports the same value for the
 * same reason.
 */
export const SERVICE_VERSION = "0.0.0";

/** Body of `GET /healthz` (Rust `HealthResponse`). */
export interface HealthReport {
  readonly status: "ok";
  readonly service: string;
  readonly version: string;
  readonly runtime: string;
}

/** Body of `GET /readyz` (Rust `ReadinessResponse` + `ClusterStatus`). */
export interface ReadinessReport {
  readonly status: "ready" | "not_ready";
  readonly service: string;
  readonly version: string;
  readonly runtime: string;
  readonly ready: boolean;
  readonly readiness_reason: string;
  readonly draining: boolean;
  readonly accepting_new_requests: boolean;
  readonly dependencies: { readonly ready: boolean };
}

/**
 * `AGENT_RUNTIME_ENABLED` — the operator switch.
 *
 * DELEGATED to `configFromEnv`, never re-parsed. The rule is narrow and easy to
 * get wrong independently — only the exact trimmed string `"0"` disables, so
 * `"false"` and `"off"` leave the runtime ON — and a probe that disagreed with
 * `requireRuntimeEnabled` about which deployments are serving would be a worse
 * lie than the flat `{ok:true}` it replaces. One parse site, one answer.
 */
export function runtimeEnabled(env: AgentRuntimeBindings | undefined): boolean {
  if (env === undefined) return true;
  return configFromEnv(env).enabled;
}

/** `GET /healthz` — liveness. 200 as soon as the isolate runs, as in Rust. */
export function healthReport(): HealthReport {
  return {
    status: "ok",
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    runtime: RUNTIME_NAME,
  };
}

/**
 * `GET /readyz` — the decision table above, evaluated PER REQUEST.
 *
 * Per request, not memoised at module scope: `resolveDeps` reads the bindings
 * of the request being served, and a probe answering from a snapshot taken on
 * some earlier request is the same class of lie the flat `{ok:true}` was.
 */
export function readinessReport(
  env: AgentRuntimeBindings | undefined,
  operatorDrain: DrainState = NOT_DRAINING,
): {
  readonly status: 200 | 503;
  readonly body: ReadinessReport;
} {
  // TWO drain sources, ORed (`src/drain.ts::combineDrain` argues the rule):
  // `AGENT_RUNTIME_ENABLED=0` is the deploy-time operator switch this Worker
  // already honoured, and `operatorDrain` is the durable `runtime-state/drain`
  // document `POST /admin/v1/drain` writes at RUNTIME. Neither cancels the
  // other. Before FC-1 only the first existed here, so a fleet-wide operator
  // drain left this probe answering `ready` — "a load balancer pointed at
  // agent-runtime's /readyz gets ready from a Worker that will refuse every
  // spend request it sends", which is the same certification verdict that made
  // this decision table exist in the first place.
  // "The operator drained this deployment" and "the drain document could not be
  // READ" are DIFFERENT FACTS and only one of them is a drain. Both refuse —
  // a probe that reports ready when its control could not be evaluated is the
  // bypass again — but reporting `operator_drain` when `GET /admin/v1/drain`
  // says the fleet is NOT draining is the incident-time lie `src/drain.ts`
  // refused to ship on the data plane (`drainRefusal` splits the two codes), so
  // the probe splits the same two reasons. `apps/mcp` and `apps/gateway` answer
  // identically; found by the wave-22 INTEGRATE boot proof, which is the only
  // place the arm is reachable — every vitest harness migrates the database.
  const drainUnavailable = operatorDrain.source === "unavailable";
  const draining = (!runtimeEnabled(env) || operatorDrain.draining) && !drainUnavailable;
  const stateReady = env !== undefined && resolveDeps(env) !== undefined;
  const acceptingNewRequests = !draining && !drainUnavailable;
  const ready = stateReady && acceptingNewRequests;

  // Drain outranks state in the REASON, exactly as `clusterStatus` orders it:
  // an operator who drained a node wants to be told that, not told about the
  // state a drained node was never going to serve from. An UNEVALUABLE drain
  // outranks both, because it is the reason the other two cannot be trusted.
  const readinessReason = drainUnavailable
    ? DRAIN_UNAVAILABLE_CODE
    : draining
      ? "operator_drain"
      : stateReady
        ? "state_loaded"
        : "revision_missing";

  return {
    status: ready ? 200 : 503,
    body: {
      status: ready ? "ready" : "not_ready",
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      runtime: RUNTIME_NAME,
      ready,
      readiness_reason: readinessReason,
      draining,
      accepting_new_requests: acceptingNewRequests,
      dependencies: { ready: stateReady },
    },
  };
}

/**
 * The three probes as a mountable group.
 *
 * A `Hono` sub-app rather than a `registerHealthRoutes(app)` function so the
 * composition root's edit is a single `app.route("/", healthRoutes)` — the same
 * shape `runRoutes` / `agentRoutes` / `workerRoutes` already use, so the wiring
 * line looks like its three neighbours instead of like an exception.
 */
export const healthRoutes = new Hono<AgentRuntimeEnv>();

healthRoutes.get("/healthz", (c) => c.json(healthReport()));

healthRoutes.get("/readyz", async (c) => {
  // The durable read happens HERE, on the probe, and nowhere upstream of it:
  // `/healthz` must stay a pure liveness answer with no backend dependency, or
  // a control-database blip would make an orchestrator RESTART every node in
  // the fleet — destroying exactly the in-flight work a drain exists to let
  // finish. `/readyz` is the probe whose whole job is to reflect backend state,
  // so it is the one that pays for the row read.
  const report = readinessReport(c.env, await resolveDrain(c.env as DrainBindings));
  return c.json(report.body, report.status);
});

// Retained from the pre-contract scaffold so existing probes keep working.
// NOT a contract operation, and deliberately still the terse document: it is
// the one probe no client contract describes.
healthRoutes.get("/health", (c) => c.json({ ok: true }));
