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
 * PORT-TODO(inventory-request-path §readiness): PLATFORM LIMIT on the drain
 * input. In Rust `drain` is an `AtomicBool` inside the one long-lived process,
 * flipped at RUNTIME by an operator call and observed instantly by every
 * request the process serves. A Worker has no process: each request may run in
 * a different isolate, isolates share no mutable memory, and there is no
 * runtime hook to mark a deployment "draining" — so a per-request runtime drain
 * would have to be a Durable Object or KV read on an ANONYMOUS, unauthenticated
 * endpoint (a free amplification target and a hot single-DO key).
 * The approximation implemented here is a DEPLOY-TIME drain: the `GATEWAY_DRAIN`
 * var, which `wrangler deploy`/`wrangler versions` can flip without a code
 * change. It reproduces the Rust decision table exactly and differs only in how
 * fast an operator can flip it (a deploy, not an API call).
 * Closing this properly means a `DRAIN` DO/KV binding plus the operator route
 * that writes it, which is a control-plane slice, not a routing one.
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

/** Bindings this module reads. */
export interface ReadinessBindings {
  readonly GATEWAY_DRAIN?: string | undefined;
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

/** `AppState::drain_status`. */
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
}): ReadinessClusterStatus {
  const { activeRevision, draining } = options;
  const stale = options.stale ?? false;
  const lastSyncError = options.lastSyncError ?? null;

  const hasRevision = activeRevision.trim() !== "";
  const stateReady = hasRevision;
  const acceptingNewRequests = !draining;
  const ready = stateReady && acceptingNewRequests;

  const readinessReason = draining
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

/** `handle_readyz` — 200 `ready` / 503 `not_ready`, with the cluster block. */
export function readinessResponse(
  c: Context<GatewayEnv>,
  service: string,
  runtime: string,
): Response {
  const env = c.env as (Record<string, unknown> & ReadinessBindings) | undefined;
  const cluster = clusterStatus({
    activeRevision: activeRevisionFor(env),
    draining: drainStatus(env).draining,
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
