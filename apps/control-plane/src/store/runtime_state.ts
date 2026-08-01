/**
 * `runtime-state/drain` — the ONE durable document the operator drain lives in.
 *
 * ## The defect this module exists to make un-repeatable (FC-1)
 *
 * `POST /admin/v1/drain` wrote a `control_plane_resources` row of kind
 * `runtime-state`, id `drain`, and answered `200 {"draining": true}`.
 * **Nothing read it.** `grep -rn "runtime-state" apps/` returned this
 * Worker and nothing else, while `apps/gateway` enforced draining off an
 * unrelated deploy-time var (`GATEWAY_DRAIN`) and `apps/mcp` /
 * `apps/agent-runtime` enforced nothing at all. Both halves were built and
 * never joined, so an operator draining a deployment before a migration kept
 * taking new billable traffic on every Worker in the fleet — the "control
 * applied in one place, enforced in another" class recorded in
 * `docs/rewrite/FLEET-CONSISTENCY.md`.
 *
 * The join needs one thing this repo did not have: a single place that says
 * what the row IS. This file is it. The writer (`routes/admin_config_ops.ts`)
 * builds its document with {@link drainDocument} and reads it back with
 * {@link parseDrainDocument}; the enforcing Workers parse the same document
 * with their own copy of {@link parseDrainDocument} (they are separately
 * bundled and may not import this file), and
 * `apps/mcp/test/drain-fleet.test.ts` compares the copies as DATA so the three
 * cannot drift.
 *
 * ## Why this module has NO imports
 *
 * It is imported by the fleet test out of another Worker's test bundle, which
 * is only sound while it is a leaf — the constraint
 * `apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts` documents
 * and asserts for `registry.ts`. Keep it dependency-free.
 */

/** The `control_plane_resources` table every durable admin document lives in. */
export const RESOURCE_TABLE = "control_plane_resources";

/** `resource_kind` for singleton runtime state (drain, active config, …). */
export const DRAIN_COLLECTION = "runtime-state";

/** `resource_id` of the singleton drain row. */
export const DRAIN_ID = "drain";

/**
 * ## The refusal constants live with the ENFORCERS, not here
 *
 * `503 node_draining` and `503 drain_state_unavailable` are spelled in
 * `apps/mcp/src/drain.ts` and `apps/agent-runtime/src/drain.ts` — the Workers
 * that actually answer them — and in `apps/gateway/src/routes/drain.ts`. This
 * Worker never refuses a request on the drain; it only WRITES the document. A
 * copy here would make `apps/gateway/test/fleet-consistency.test.ts`'s
 * `emitsNodeDraining` probe report the control plane as an enforcer, which is
 * exactly the kind of "the code says it, so it must do it" reading that audit
 * exists to defeat.
 */

/** Where a resolved drain answer came from. */
export type DrainSource =
  /** The durable `runtime-state/drain` document (the operator API). */
  | "durable"
  /** A deploy-time var (`GATEWAY_DRAIN`). Gateway only — see below. */
  | "deploy_var"
  /** No document and no var: the Rust default state, "not draining". */
  | "none"
  /** The durable lookup FAILED. Fail closed: refuse, and say why. */
  | "unavailable";

/** The resolved answer to "is this deployment accepting new billable work?". */
export interface DrainState {
  readonly draining: boolean;
  readonly accepting_new_requests: boolean;
  readonly reason: string | null;
  readonly source: DrainSource;
  /** Set only for `source: "unavailable"` — the lookup error, for the operator. */
  readonly detail?: string;
}

/** The stored document's fields, as written by `POST /admin/v1/drain`. */
export interface DrainDocumentFields {
  readonly draining: boolean;
  readonly reason: string | null;
  readonly changed_at: number;
  /**
   * ALWAYS `null`. The operator drain is DEPLOYMENT state, not tenant state:
   * every Worker in the fleet reads this one row by primary key. If a
   * tenant-scoped admin could mint it under their own `tenant_id`, one tenant
   * would drain the whole deployment — so `setAdminDrain` refuses a non-
   * platform caller AND pins this field, and the enforcers additionally refuse
   * to honour a row that carries a tenant.
   */
  readonly tenant_id: null;
}

/** The full document, including the store's structural `id`. */
export interface DrainDocument extends DrainDocumentFields {
  readonly id: typeof DRAIN_ID;
}

/** Build the exact document `POST /admin/v1/drain` stores. */
export function drainDocument(input: {
  draining: boolean;
  reason?: string | null;
  changedAt: number;
}): DrainDocument {
  return {
    id: DRAIN_ID,
    draining: input.draining,
    reason: input.reason ?? null,
    changed_at: input.changedAt,
    tenant_id: null,
  };
}

/** `DrainState` for a deployment with no drain in effect. */
export const NOT_DRAINING: DrainState = {
  draining: false,
  accepting_new_requests: true,
  reason: null,
  source: "none",
};

/**
 * Read a stored document into a {@link DrainState}.
 *
 * Deliberately strict, in both directions:
 *
 *  - `draining` must be the JSON boolean `true`. A truthy string, a `1`, or a
 *    missing field is NOT draining — the Rust default state — so a half-written
 *    row cannot take a deployment out of rotation.
 *  - a document carrying a non-null `tenant_id` is **ignored** (`none`). The
 *    drain is deployment state; a tenant-attributed row is either a bug or an
 *    attempt to drain the fleet from one tenant's admin key, and honouring it
 *    would be a cross-tenant denial of service. See {@link DrainDocumentFields}.
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
 * THE PRECEDENCE RULE, stated once for the whole fleet.
 *
 * There are two sources and they are NOT redundant:
 *
 * | source | who sets it | how fast | which Workers |
 * |---|---|---|---|
 * | `runtime-state/drain` | `POST /admin/v1/drain` | immediately, at runtime | every Worker with the control database bound |
 * | `GATEWAY_DRAIN` | `wrangler deploy` / `wrangler versions` | a deploy | `apps/gateway` only (it is the only `wrangler.toml` that declares it) |
 *
 * The rule is **OR**, and it is the fail-safe direction: a deployment is
 * draining if EITHER source says so, and neither source can cancel the other.
 * The alternative — "the newest write wins" — means a stale deploy-time var
 * silently un-drains a deployment an operator just drained by API, or a
 * `{"draining": false}` API call silently re-admits traffic to a deployment
 * that was drained at deploy time for a migration. Both are the FC-1 defect
 * again, wearing the other half's clothes.
 *
 * A lookup FAILURE outranks both: it is not an answer, so it refuses.
 */
export function combineDrain(durable: DrainState, deployVar: boolean): DrainState {
  if (durable.source === "unavailable") return durable;
  if (durable.draining) return durable;
  if (deployVar) {
    return {
      draining: true,
      accepting_new_requests: false,
      reason: null,
      source: "deploy_var",
    };
  }
  return NOT_DRAINING;
}
