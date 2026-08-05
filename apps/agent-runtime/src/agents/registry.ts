/**
 * THE DURABLE A2A UPSTREAM REGISTRY — the second reach path of
 * `DELETE /admin/v1/agent-upstreams/{id}`.
 *
 * ## Why this module exists (CUTOVER-READINESS CLASS A, item A3 — leg 2)
 *
 * Rust holds ONE `[[agent_upstreams]]` table in the live config snapshot, and
 * every surface that can reach an upstream reads THAT table:
 * `handle_admin_agent_upstream_delete` (`server/local.rs:9702`) →
 * `state.rs:796 delete_agent_upstream` rebuilds and hot-reloads the config, so
 * both `GET /.well-known/agent.json` AND `handle_agent_ingress` answer from the
 * mutated table on the very next request. One withdrawal, one process, every
 * door.
 *
 * In this tree the doors are in different Workers. Wave 20 gave `apps/gateway`
 * a durable read (`apps/gateway/src/routes/agent-upstreams.ts`), which closed
 * the DISCOVERY door. This Worker owns the other one — the A2A DISPATCH path
 * `POST /v1/agents/{name}` and the two `message:*` verbs — and it resolved its
 * catalog from its own deploy-time `AGENT_UPSTREAMS` var through
 * `inMemoryAgentUpstreamPort`, with no durable reference anywhere. The
 * consequence is the one the cutover verdict would not sign off, restated for
 * this Worker:
 *
 * > **An operator who withdraws a COMPROMISED upstream sees it gone from
 * > discovery and it stays reachable for dispatch.** The admin API answers
 * > `200 {"deleted": true}` and traffic keeps flowing to the endpoint until
 * > someone edits `wrangler.toml` and redeploys.
 *
 * That is the wave-16 admission-bypass shape ("call the other endpoint") in a
 * second capability. Correctness per Worker does not imply correctness of the
 * fleet, so the remedy is not a second copy of the rule — it is the SAME ROWS:
 * `control_plane_resources` of kind `agent-upstreams`, in `CONTROL_DB`, which
 * this Worker already binds and `apps/control-plane`'s `admin_agent_upstream`
 * group already writes.
 *
 * ## Precedence: the durable table REPLACES the var, it does not merge with it
 *
 * When `CONTROL_DB` is bound the durable registry is the WHOLE registry; the
 * var is the source only for a deployment with no control database. Byte for
 * byte the rule `apps/gateway/src/routes/agent-upstreams.ts` states, and for
 * this collection the alternative is not a style choice:
 *
 * > **A union would defeat the withdrawal.** An id declared in BOTH the var and
 * > the durable table would keep dispatching after its document is deleted,
 * > because the var half survives — the very defect this module removes, one
 * > operator misconfiguration away.
 *
 * It is also why this is the ONE catalog in this Worker that does not follow
 * `runs/workflow.ts`'s merge rule. That table is a GATE: an extra entry can
 * only add refusals, so materialising a deploy-time pin over the durable rows
 * is safe. This table is a REACH SET: an extra entry is an extra endpoint that
 * receives traffic. Opposite blast radii, opposite composition.
 *
 * ## Failure direction: fail CLOSED, and loudly
 *
 * A read that throws yields `{"outcome":"unavailable"}` and the ingress refuses
 * the dispatch with `503 agent_upstream_unavailable`. It does NOT fall back to
 * the var and it does NOT report `404`:
 *
 *  - falling back to the var would republish exactly the ids the operator
 *    removed, i.e. undo a withdrawal because a database blinked;
 *  - answering `404` would make an outage indistinguishable from a successful
 *    withdrawal, so an operator watching the dispatch surface would read
 *    "gone" and stop looking.
 *
 * This is the posture `apps/gateway/src/ratelimit/quota.ts` argues for the
 * admission ladder (`503 quota_resolution_unavailable`, never "no policies"),
 * applied to the one other control whose failure would re-open money and
 * security. It is deliberately the OPPOSITE of the gateway's DISCOVERY read,
 * which fails quiet to an empty table — and the difference is the surface, not
 * an inconsistency: an unreadable table there only deletes DISCLOSURES, while
 * here it would decide whether a request LEAVES this Worker.
 *
 * A single undecodable document is skipped rather than failing the batch: one
 * malformed row must not take down every other upstream, and the direction of
 * skipping is removal.
 *
 * ## No cache, deliberately
 *
 * The table is read PER DISPATCH and nothing about it is memoised. A withdrawal
 * has to take effect on the very NEXT dispatch, and a process-lifetime cache is
 * precisely the defect this reads around: the Worker would keep forwarding to
 * an upstream the operator deleted for as long as the isolate lived, with no
 * invalidation channel from another Worker to flush it. One indexed lookup on
 * the request path is the cheaper side of that trade, and it is what
 * `test/durable/agent-upstream-withdrawal.spec.ts` holds ("stays withdrawn
 * across repeated dispatches").
 *
 * ## Tenancy
 *
 * The fence is `apps/control-plane/src/store/d1.ts::tenantScopeSql` — the READ
 * fence of the surface that wrote the rows, and the same one
 * `apps/gateway/src/routes/agent-upstreams.ts` reads with, so the two doors
 * agree about who may reach what:
 *
 *  - a platform operator sees every document;
 *  - a tenant-scoped caller sees its own documents AND the un-attributed
 *    platform ones. The `IS NULL` disjunct is load-bearing rather than lax:
 *    Rust's `[[agent_upstreams]]` is a GLOBAL operator table visible to every
 *    caller, so dropping un-attributed rows for tenants would HIDE upstreams
 *    that dispatch today.
 *
 * The tenant id is a BOUND PARAMETER, never interpolated: an id that reached
 * this point from a credential must not be able to alter the predicate that
 * fences it.
 *
 * `AgentUpstream.visibleToTenantIds` (the document's `tenant_ids`) is a SECOND,
 * independent filter applied on top by `ingress.ts::upstreamVisibleTo`.
 */
import { DurableObjectTenantDatabaseRouter, type TenantDatabaseRouter } from "@ferrogate/storage";

// TYPE-ONLY, and it has to stay that way: `../ports.ts` imports the factories
// below, so a VALUE import back into it would close a module cycle. Same rule
// `durable/adapters.ts` follows.
import type {
  AgentUpstream,
  AgentUpstreamLookup,
  AgentUpstreamPort,
  AgentUpstreamScope,
} from "../ports.js";

/**
 * `control_plane_resources.resource_kind` written by `apps/control-plane`'s
 * `admin_agent_upstream` group. It is the collection name, which
 * `CollectionSpec.collection` defaults to the path segment `agent-upstreams`.
 * Identical to `apps/gateway/src/routes/agent-upstreams.ts`'s constant — the
 * two Workers must name the SAME rows or the withdrawal covers one door again.
 */
export const AGENT_UPSTREAM_COLLECTION = "agent-upstreams";

/** The generic control-plane document table, in the CONTROL database. */
export const RESOURCE_TABLE = "control_plane_resources";
/** The object-local document table for tenant-private resource kinds. */
export const TENANT_RESOURCE_TABLE = "tenant_resources";

/**
 * Insertion order, byte for byte the control plane's own `LIST_ORDER`
 * (`store/d1.ts:113`) and the gateway's, so a duplicate id resolves the same
 * way on both reach paths.
 */
const LIST_ORDER = "ORDER BY created_at_unix ASC, rowid ASC";

/** `ferrogate_config::AgentUpstreamProtocol` — one variant, `#[default]`. */
const PROTOCOLS: ReadonlySet<string> = new Set(["a2a"]);

/**
 * Bindings this module reads — ONE, and deliberately only one.
 *
 * `AGENT_UPSTREAMS` and `FG_DEV_AGENT_UPSTREAMS` are NOT listed: the var half
 * is parsed by `resolveDeps` and handed in as `varPort`, so listing them here
 * would declare a dependency this module does not have. A binding named in an
 * interface and never read is the shape `docs/rewrite/parity-audit-dead-packages.md`
 * catalogues, and it is cheap to not create.
 */
export interface AgentUpstreamRegistryBindings {
  /** The CONTROL database: `control_plane_resources`. */
  readonly CONTROL_DB?: D1Database | undefined;
  /** The shared TenantDataObject namespace for tenant-private documents. */
  readonly TENANT_DATA?: import("@ferrogate/storage/durable-objects").TenantDataNamespace;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

/**
 * A stored admin document → this Worker's {@link AgentUpstream}, or `undefined`
 * to DROP it.
 *
 * The field mapping is stated here ONCE, because getting it wrong is silent —
 * the admin document uses the RUST spellings (`AdminAgentUpstreamMutation`) and
 * this Worker's port uses its own:
 *
 * | document (`agentUpstreamSchema`) | {@link AgentUpstream} |
 * |---|---|
 * | `id` (required) | `id` |
 * | `endpoint`, or the accepted alias `url` (required) | `url` |
 * | `enabled` (`#[serde(default = "default_true")]`) | `enabled` |
 * | `tenant_ids` (`#[serde(default)]`) | `visibleToTenantIds` |
 * | `operator_only` | `operatorOnly` |
 *
 * `id` and `endpoint` are two of the three REQUIRED members of the Rust struct
 * (`config/types.rs:2597`), and `agent_upstream_from_mutation` refuses a
 * mutation missing any of them. `apps/control-plane`'s generic
 * `adminRecordSchema` is `passthrough()` with every field optional, so a
 * partial row CAN exist in the table; dropping it is the stricter reading and
 * matches the gateway's decoder. `name` is required THERE because the discovery
 * document publishes it; nothing on the dispatch path reads it, so requiring it
 * here would refuse to route an upstream the admin API accepted — the direction
 * that turns a decode nit into an outage.
 *
 * `url` is accepted as an alias of `endpoint` because
 * `routes/admin_agent_upstream.ts` documents it as the app's earlier spelling
 * and states that stored rows carry it.
 *
 * An unrecognised `protocol` REFUSES the document rather than being coerced to
 * `a2a`: reading it as A2A would forward traffic over a protocol the operator
 * did not name.
 *
 * `operator_only` is not a member of the Rust struct and is not in
 * `agentUpstreamSchema` — but that schema is `passthrough()`, so an operator
 * CAN store the key, and this Worker's port has carried the flag since it was
 * written. Reading it (default `false`, non-boolean ⇒ drop the document) is
 * strictly narrower than ignoring it: ignoring would publish an
 * operator-restricted upstream to tenants.
 */
export function decodeAgentUpstreamDocument(value: unknown): AgentUpstream | undefined {
  if (!isObject(value)) return undefined;

  const id = nonEmptyString(value["id"]);
  const url = nonEmptyString(value["endpoint"]) ?? nonEmptyString(value["url"]);
  if (id === undefined || url === undefined) return undefined;

  // A relative or otherwise unparseable endpoint would throw inside the
  // ingress's `new URL(upstream.url)` — after the guardrail, on the request
  // path. Refusing it here keeps a malformed row from becoming a 500.
  try {
    new URL(url);
  } catch {
    return undefined;
  }

  const rawEnabled = value["enabled"];
  if (rawEnabled !== undefined && rawEnabled !== null && typeof rawEnabled !== "boolean") {
    return undefined;
  }

  const rawProtocol = value["protocol"];
  if (rawProtocol !== undefined && rawProtocol !== null && !PROTOCOLS.has(rawProtocol as string)) {
    return undefined;
  }

  const rawTenantIds = value["tenant_ids"];
  let visibleToTenantIds: readonly string[] = [];
  if (rawTenantIds !== undefined && rawTenantIds !== null) {
    if (!Array.isArray(rawTenantIds) || rawTenantIds.some((e) => typeof e !== "string")) {
      return undefined;
    }
    visibleToTenantIds = rawTenantIds as readonly string[];
  }

  const rawOperatorOnly = value["operator_only"];
  if (
    rawOperatorOnly !== undefined &&
    rawOperatorOnly !== null &&
    typeof rawOperatorOnly !== "boolean"
  ) {
    return undefined;
  }

  return {
    id,
    enabled: (rawEnabled as boolean | null | undefined) ?? true,
    url,
    visibleToTenantIds,
    operatorOnly: (rawOperatorOnly as boolean | null | undefined) ?? false,
  };
}

/**
 * The `control_plane_resources` predicate for one caller.
 *
 * `tenantId === null` means a platform operator: no ownership predicate.
 */
export function agentUpstreamScopeSql(tenantId: string | null): {
  readonly sql: string;
  readonly params: readonly string[];
} {
  if (tenantId === null) return { sql: "", params: [] };
  return {
    sql: " AND (json_extract(document_json, '$.tenant_id') IS NULL OR json_extract(document_json, '$.tenant_id') = ?)",
    params: [tenantId],
  };
}

async function controlAgentUpstream(
  db: D1Database,
  agentId: string,
  tenantId: string | null,
): Promise<AgentUpstreamLookup> {
  const fence = agentUpstreamScopeSql(tenantId);
  let rows: { results: { document_json: string }[] };
  try {
    rows = await db
      .prepare(
        `SELECT document_json FROM ${RESOURCE_TABLE}
           WHERE resource_kind = ? AND resource_id = ?${fence.sql}
           ${LIST_ORDER}`,
      )
      .bind(AGENT_UPSTREAM_COLLECTION, agentId, ...fence.params)
      .all<{ document_json: string }>();
  } catch (error) {
    return {
      outcome: "unavailable",
      detail: `cloudflare d1: agent upstream lookup failed: ${String(error)}`,
    };
  }

  for (const row of rows.results) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(row.document_json);
    } catch {
      continue;
    }
    const decoded = decodeAgentUpstreamDocument(parsed);
    if (decoded !== undefined && decoded.id === agentId) {
      return { outcome: "found", upstream: decoded };
    }
  }
  return { outcome: "not_found" };
}

async function controlPlatformAgentUpstream(
  db: D1Database,
  agentId: string,
): Promise<AgentUpstreamLookup> {
  let rows: { results: { document_json: string }[] };
  try {
    rows = await db
      .prepare(
        `SELECT document_json FROM ${RESOURCE_TABLE}
           WHERE resource_kind = ?
             AND resource_id = ?
             AND json_extract(document_json, '$.tenant_id') IS NULL
           ${LIST_ORDER}`,
      )
      .bind(AGENT_UPSTREAM_COLLECTION, agentId)
      .all<{ document_json: string }>();
  } catch (error) {
    return {
      outcome: "unavailable",
      detail: `cloudflare d1: platform agent upstream projection failed: ${String(error)}`,
    };
  }
  for (const row of rows.results) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(row.document_json);
    } catch {
      continue;
    }
    const decoded = decodeAgentUpstreamDocument(parsed);
    if (decoded !== undefined && decoded.id === agentId) {
      return { outcome: "found", upstream: decoded };
    }
  }
  return { outcome: "not_found" };
}

interface TenantObjectLookup {
  readonly present: boolean;
  readonly result: AgentUpstreamLookup;
}

async function tenantObjectAgentUpstream(
  router: TenantDatabaseRouter,
  tenantId: string,
  agentId: string,
): Promise<TenantObjectLookup> {
  const handle = await router.forTenant(tenantId);
  const rows = await handle.db
    .prepare(
      `SELECT document_json FROM ${TENANT_RESOURCE_TABLE}
         WHERE resource_kind = ? AND resource_id = ?
         ORDER BY resource_id`,
    )
    .bind(AGENT_UPSTREAM_COLLECTION, agentId)
    .all<{ document_json: string }>();
  for (const row of rows.results) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(row.document_json);
    } catch {
      continue;
    }
    if (!isObject(parsed) || parsed["tenant_id"] !== tenantId) continue;
    const decoded = decodeAgentUpstreamDocument(parsed);
    if (decoded !== undefined && decoded.id === agentId) {
      return { present: true, result: { outcome: "found", upstream: decoded } };
    }
  }
  return { present: rows.results.length > 0, result: { outcome: "not_found" } };
}

/**
 * The DURABLE {@link AgentUpstreamPort}: one indexed lookup per dispatch,
 * fenced to the caller, fail-closed on error.
 *
 * The `resource_id` predicate is a bound parameter and the row is re-checked
 * against the DECODED `id` afterwards, so a document whose `resource_id` and
 * whose body disagree cannot route traffic under a name it does not carry.
 */
export function d1AgentUpstreamPort(
  db: D1Database,
  router?: TenantDatabaseRouter,
): AgentUpstreamPort {
  return {
    async lookup(agentId: string, scope: AgentUpstreamScope): Promise<AgentUpstreamLookup> {
      if (agentId === "") return { outcome: "not_found" };
      if (router !== undefined && scope.tenantId !== null && scope.tenantId.trim() !== "") {
        try {
          const object = await tenantObjectAgentUpstream(router, scope.tenantId, agentId);
          if (object.result.outcome !== "not_found") return object.result;
          // Tenant callers inherit platform-global reach-set entries from the
          // named control-D1 projection. This is a destination decision, not a
          // fallback for an object read failure: the catch below remains
          // unavailable, and tenant-owned rows never come from control D1.
          return controlPlatformAgentUpstream(db, agentId);
        } catch (error) {
          return {
            outcome: "unavailable",
            detail: `tenant object: agent upstream lookup failed: ${String(error)}`,
          };
        }
      } else if (router !== undefined && scope.tenantId === null) {
        const matches: AgentUpstream[] = [];
        try {
          for (const tenantId of await router.provisionedTenants()) {
            const object = await tenantObjectAgentUpstream(router, tenantId, agentId);
            if (object.result.outcome === "found") matches.push(object.result.upstream);
          }
        } catch (error) {
          // Platform-global upstreams have a named control-D1 projection. A
          // roster failure must not hide that projection; tenant-scoped
          // lookups remain object-only and still fail closed above.
          const projection = await controlPlatformAgentUpstream(db, agentId);
          if (projection.outcome !== "not_found") return projection;
          return {
            outcome: "unavailable",
            detail: `tenant object roster lookup failed: ${String(error)}`,
          };
        }
        if (matches.length > 1) {
          return {
            outcome: "unavailable",
            detail: `agent upstream ${agentId} has multiple tenant destinations`,
          };
        }
        if (matches[0] !== undefined) return { outcome: "found", upstream: matches[0] };
        return controlPlatformAgentUpstream(db, agentId);
      }
      // CONTROL_DB is the compatibility reader only when this Worker has no
      // TenantDataObject topology. A configured object topology must never
      // resurrect a tenant-local row from the control database.
      return controlAgentUpstream(db, agentId, scope.tenantId);
    },
  };
}

/**
 * The registry for a Worker `env`: the durable table when a control database is
 * bound, the deploy-time var otherwise.
 *
 * `varPort` is passed in rather than imported so the module cycle stays one-way
 * (`ports.ts` → here); `resolveDeps` supplies `inMemoryAgentUpstreamPort` over
 * the parsed var.
 *
 * **The deployed path prefers durable**, and it does so even when
 * `FG_DEV_IN_MEMORY_PORTS` is still set — the same "a bound database wins over
 * the dev flag" rule the credential adapters follow, and for the same reason:
 * a deployment that provisions real databases but forgets to delete one
 * leftover variable must still get the real database
 * (`docs/rewrite/parity-audit-dead-packages.md` §7.2).
 */
export function agentUpstreamPortFromEnv(
  env: AgentUpstreamRegistryBindings,
  varPort: AgentUpstreamPort,
): AgentUpstreamPort {
  const db = env.CONTROL_DB;
  // `typeof prepare` guards the same case `workflowCatalogFromEnv` guards: a
  // binding present but not a D1 database (a stub env in a unit test) must fall
  // back rather than throw on the request path.
  if (db === undefined || typeof db.prepare !== "function") return varPort;
  const router =
    env.TENANT_DATA === undefined
      ? undefined
      : new DurableObjectTenantDatabaseRouter(env.TENANT_DATA, db);
  return d1AgentUpstreamPort(db, router);
}
