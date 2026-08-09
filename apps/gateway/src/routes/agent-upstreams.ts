/**
 * The DURABLE agent-upstream registry — the read half of
 * `DELETE /admin/v1/agent-upstreams/{id}`.
 *
 * ## What this closes (CUTOVER-READINESS CLASS A, item A3)
 *
 * Rust holds one `[[agent_upstreams]]` table in the live config snapshot, and
 * the admin surface mutates THAT table:
 * `state.rs:774 upsert_agent_upstream` / `state.rs:796 delete_agent_upstream`
 * persist the control-plane document, rebuild the candidate config,
 * `validate()` it and hot-reload — so `GET /.well-known/agent.json` answers
 * from the mutated table on the very next request.
 *
 * In this tree the two halves are two Workers, and until this module only the
 * WRITE half existed. `apps/control-plane`'s `admin_agent_upstream` group
 * (`routes/admin_agent_upstream.ts`) stored each upstream as a
 * `control_plane_resources` document of kind `agent-upstreams` and answered
 * `201`/`200`/`200 {"deleted": true}` — while `./agent-discovery.ts` built the
 * document exclusively from the DEPLOY-TIME var `GATEWAY_AGENT_UPSTREAMS`. The
 * consequence is the one the cutover verdict called security-shaped and would
 * not sign off: **an operator who discovers a malicious or compromised upstream
 * calls DELETE, is told `200`, and the gateway keeps publishing the upstream's
 * endpoint until someone edits `wrangler.toml` and redeploys.**
 *
 * The remedy needs no new binding and no new service — this Worker already
 * binds `CONTROL_DB`, and the documents are already there. It is the same shape
 * `apps/mcp/src/catalog.ts` used for the MCP server catalog and
 * `src/inference/workflow.ts` for the workflow graph gate: read the table the
 * operator surface already writes.
 *
 * ## Precedence: the durable table REPLACES the var, it does not merge with it
 *
 * When `CONTROL_DB` is bound the durable registry is the WHOLE registry; the
 * var is the source only for a deployment with no control database. That is the
 * three-line shape `routes/admin_agent_upstream.ts` prescribes ("a `CONTROL_DB`
 * source ahead of the var, defaulting to the var when the binding is absent"),
 * and for this collection the alternative is not merely a style choice:
 *
 * > **A union would defeat the withdrawal.** An id declared in BOTH the var and
 * > the durable table would keep being published after its document is deleted,
 * > because the var half survives — i.e. exactly the defect this module exists
 * > to remove, reachable by an operator who configured the upstream twice.
 *
 * Nothing is lost by it today: `apps/gateway/wrangler.toml` pins
 * `GATEWAY_AGENT_UPSTREAMS = "{}"`, which is not an array and therefore already
 * configures no upstreams (`parseAgentUpstreams` fails closed on it).
 *
 * ## Failure direction — every failure REMOVES an upstream, none adds one
 *
 * A read that throws yields an EMPTY table, never a fallback to the var: a
 * withdrawal must not be undone by a database outage, and falling back would
 * republish exactly the ids the operator removed. An undecodable document is
 * skipped. So the worst case is the pre-existing empty document, which
 * publishes nothing.
 *
 * This is the OPPOSITE of `src/inference/workflow.ts`'s catalog, deliberately
 * and for the same reason stated there: an unreadable workflow table would
 * delete REFUSALS, so it answers 503; an unreadable upstream table only deletes
 * DISCLOSURES, so failing quiet is the safe direction here.
 *
 * ## Tenancy
 *
 * The fence is `apps/control-plane/src/store/d1.ts::tenantScopeSql` — the READ
 * fence of the surface that wrote the rows, so the data plane serves a caller
 * exactly the documents the admin API shows it:
 *
 *  - a platform operator sees every document;
 *  - a tenant-scoped caller sees its own documents AND the un-attributed
 *    platform ones. The `IS NULL` disjunct is load-bearing rather than lax:
 *    Rust's `[[agent_upstreams]]` is a GLOBAL operator table visible to every
 *    caller, so dropping un-attributed rows for tenants would HIDE upstreams
 *    that are published today — a regression in the other direction.
 *
 * `AgentUpstreamRecord.tenant_ids` is a SECOND, independent filter applied on
 * top by `agentUpstreamVisibleToAuth` (and it matches the API-KEY id, not the
 * tenant — a Rust quirk documented in `./agent-discovery.ts`).
 */

import type { TenantDatabaseRouter } from "@ferrogate/storage";
import { controlDatabaseFrom } from "../control-data.js";
import type { AuthContext } from "../ports.js";
import { callerScope } from "../ports.js";
import { type TenancyBindings, resolverForEnv } from "../tenancy/index.js";
import type {
  AgentUpstreamCapability,
  AgentUpstreamProtocol,
  AgentUpstreamRecord,
} from "./agent-discovery.js";

/**
 * `control_plane_resources.resource_kind` written by `apps/control-plane`'s
 * `admin_agent_upstream` group. It is the collection name, which
 * `CollectionSpec.collection` defaults to the path segment `agent-upstreams`.
 */
export const AGENT_UPSTREAM_COLLECTION = "agent-upstreams";

/** The generic control-plane document table, in the CONTROL database. */
export const RESOURCE_TABLE = "control_plane_resources";
/** The object-local document table for tenant-private resource kinds. */
export const TENANT_RESOURCE_TABLE = "tenant_resources";

/**
 * Insertion order, byte for byte the control plane's own `LIST_ORDER`
 * (`store/d1.ts:113`), so the discovery document lists upstreams in the same
 * order `GET /admin/v1/agent-upstreams` does.
 */
const LIST_ORDER = "ORDER BY created_at_unix ASC, rowid ASC";

/** Bindings this module reads. */
export interface AgentUpstreamRegistryBindings extends TenancyBindings {
  /** `[[agent_upstreams]]`, the deploy-time table — see the precedence note. */
  readonly GATEWAY_AGENT_UPSTREAMS?: string | undefined;
}

/**
 * Rust `agent_upstream_from_mutation` (`local.rs:10633`) materialises
 * `[invoke, read]` when the admin mutation names no capabilities — BEFORE the
 * document is stored, so the read path never sees the absence. A stored
 * document that omits the field is therefore an upstream with those two
 * capabilities, not one with none.
 *
 * The VAR path keeps `?? []` (`./agent-discovery.ts::agentUpstreamDiscovery`)
 * and that difference is correct: there the table IS the operator's file, and
 * the read path serialises whatever it holds.
 */
export const ADMIN_DEFAULT_CAPABILITIES: readonly AgentUpstreamCapability[] = ["invoke", "read"];

/** `ferrogate_config::AgentUpstreamCapability`, as a total set. */
const CAPABILITIES: ReadonlySet<string> = new Set<AgentUpstreamCapability>([
  "invoke",
  "read",
  "stream",
  "discover",
]);

/** `ferrogate_config::AgentUpstreamProtocol` — one variant, `#[default]`. */
const PROTOCOLS: ReadonlySet<string> = new Set<AgentUpstreamProtocol>(["a2a"]);

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

/**
 * A stored admin document → `AgentUpstreamConfig`, or `undefined` to DROP it.
 *
 * `id`, `name` and `endpoint` are the three REQUIRED members of the Rust struct
 * (`config/types.rs:2597`) and of `agent_upstream_from_mutation`, which refuses
 * a mutation missing any of them. `apps/control-plane`'s generic
 * `adminRecordSchema` is `passthrough()` with every field optional, so a
 * partial row CAN exist in the table; dropping it is the stricter reading and
 * matches `parseAgentUpstreams`.
 *
 * `url` is accepted as an alias of `endpoint` because
 * `routes/admin_agent_upstream.ts` documents it as the app's earlier spelling
 * and states that stored rows carry it. An upstream the admin API accepted must
 * not become invisible here.
 *
 * Unknown enum values REFUSE the document rather than being coerced: reading an
 * unrecognised `protocol` as `a2a` would send traffic somewhere over a protocol
 * the operator did not name, and an unrecognised capability would either be
 * dropped silently or published as-is off-contract.
 */
export function decodeAgentUpstreamDocument(value: unknown): AgentUpstreamRecord | undefined {
  if (!isObject(value)) return undefined;

  const id = nonEmptyString(value.id);
  const name = nonEmptyString(value.name);
  const endpoint = nonEmptyString(value.endpoint) ?? nonEmptyString(value.url);
  if (id === undefined || name === undefined || endpoint === undefined) return undefined;

  const rawDescription = value.description;
  if (
    rawDescription !== undefined &&
    rawDescription !== null &&
    typeof rawDescription !== "string"
  ) {
    return undefined;
  }

  const rawEnabled = value.enabled;
  if (rawEnabled !== undefined && typeof rawEnabled !== "boolean") return undefined;

  const rawProtocol = value.protocol;
  if (rawProtocol !== undefined && rawProtocol !== null && !PROTOCOLS.has(rawProtocol as string)) {
    return undefined;
  }

  const rawTenantIds = value.tenant_ids;
  let tenantIds: readonly string[] | undefined;
  if (rawTenantIds !== undefined && rawTenantIds !== null) {
    if (!Array.isArray(rawTenantIds) || rawTenantIds.some((e) => typeof e !== "string")) {
      return undefined;
    }
    tenantIds = rawTenantIds as readonly string[];
  }

  const rawCapabilities = value.capabilities;
  let capabilities: readonly AgentUpstreamCapability[];
  if (rawCapabilities === undefined || rawCapabilities === null) {
    capabilities = ADMIN_DEFAULT_CAPABILITIES;
  } else {
    if (!Array.isArray(rawCapabilities)) return undefined;
    for (const entry of rawCapabilities) {
      if (typeof entry !== "string" || !CAPABILITIES.has(entry)) return undefined;
    }
    capabilities = rawCapabilities as readonly AgentUpstreamCapability[];
  }

  return {
    id,
    name,
    description: (rawDescription as string | null | undefined) ?? null,
    enabled: rawEnabled ?? true,
    protocol: (rawProtocol as AgentUpstreamProtocol | undefined) ?? "a2a",
    endpoint,
    tenant_ids: tenantIds ?? [],
    capabilities,
  };
}

/**
 * The `control_plane_resources` SELECT for one caller.
 *
 * The tenant id is a BOUND PARAMETER, never interpolated: an id that reached
 * this point from a credential must not be able to alter the predicate that
 * fences it.
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

/**
 * Read the durable registry for one caller.
 *
 * `tenantId === null` means a platform operator (no predicate).
 */
async function decodeRows(
  rows: readonly { document_json: string }[],
  expectedTenantId?: string,
): Promise<AgentUpstreamRecord[]> {
  const upstreams: AgentUpstreamRecord[] = [];
  for (const row of rows) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(row.document_json);
    } catch {
      continue;
    }
    if (
      expectedTenantId !== undefined &&
      (!isObject(parsed) || parsed.tenant_id !== expectedTenantId)
    ) {
      continue;
    }
    const decoded = decodeAgentUpstreamDocument(parsed);
    if (decoded !== undefined) upstreams.push(decoded);
  }
  return upstreams;
}

async function controlAgentUpstreams(
  db: D1Database,
  tenantId: string | null,
): Promise<readonly AgentUpstreamRecord[]> {
  const scope = agentUpstreamScopeSql(tenantId);
  let rows: { results: { document_json: string }[] };
  try {
    rows = await db
      .prepare(
        `SELECT document_json FROM ${RESOURCE_TABLE}
           WHERE resource_kind = ?${scope.sql}
           ${LIST_ORDER}`,
      )
      .bind(AGENT_UPSTREAM_COLLECTION, ...scope.params)
      .all<{ document_json: string }>();
  } catch {
    // Fail CLOSED, and specifically NOT back to the var: see the failure
    // direction note at the top of this file.
    return [];
  }

  return decodeRows(rows.results);
}

/** Platform projection for legacy/unattributed reach-set documents. */
async function controlPlatformAgentUpstreams(
  db: D1Database,
): Promise<readonly AgentUpstreamRecord[]> {
  let rows: { results: { document_json: string }[] };
  try {
    rows = await db
      .prepare(
        `SELECT document_json FROM ${RESOURCE_TABLE}
           WHERE resource_kind = ?
             AND json_extract(document_json, '$.tenant_id') IS NULL
           ${LIST_ORDER}`,
      )
      .bind(AGENT_UPSTREAM_COLLECTION)
      .all<{ document_json: string }>();
  } catch {
    return [];
  }
  return decodeRows(rows.results);
}

async function tenantObjectAgentUpstreams(
  router: TenantDatabaseRouter,
  tenantId: string,
): Promise<readonly AgentUpstreamRecord[]> {
  const handle = await router.forTenant(tenantId);
  const rows = await handle.db
    .prepare(
      `SELECT document_json FROM ${TENANT_RESOURCE_TABLE}
         WHERE resource_kind = ?
         ORDER BY resource_id`,
    )
    .bind(AGENT_UPSTREAM_COLLECTION)
    .all<{ document_json: string }>();
  return decodeRows(rows.results, tenantId);
}

export async function durableAgentUpstreams(
  db: D1Database,
  tenantId: string | null,
  router?: TenantDatabaseRouter,
): Promise<readonly AgentUpstreamRecord[]> {
  if (router === undefined) {
    return controlAgentUpstreams(db, tenantId);
  }
  if (tenantId === null || tenantId.trim() === "") {
    return controlPlatformAgentUpstreams(db);
  }

  let objectRows: readonly AgentUpstreamRecord[];
  try {
    objectRows = await tenantObjectAgentUpstreams(router, tenantId);
  } catch {
    // A tenant-object read failure must not resurrect a legacy control row or
    // turn a discovery request into an unbounded error response.
    return [];
  }
  const rows = [...objectRows];
  const seen = new Set(rows.map((upstream) => upstream.id));
  for (const upstream of await controlPlatformAgentUpstreams(db)) {
    if (seen.has(upstream.id)) continue;
    seen.add(upstream.id);
    rows.push(upstream);
  }
  return rows;
}

/**
 * The registry for one request: the durable table when a control database is
 * bound, the deploy-time var otherwise.
 *
 * `parseAgentUpstreams` is passed in rather than imported to keep the module
 * cycle one-way (`agent-discovery` → here), which is why this takes the parser
 * as an argument.
 */
export async function agentUpstreamsForCaller(
  env: AgentUpstreamRegistryBindings | undefined,
  auth: AuthContext | null,
  parseVar: (raw: string | undefined) => readonly AgentUpstreamRecord[],
): Promise<readonly AgentUpstreamRecord[]> {
  const db = controlDatabaseFrom(env);
  if (db === undefined) return parseVar(env?.GATEWAY_AGENT_UPSTREAMS);
  // An unauthenticated caller is confined to a tenant no row can carry, exactly
  // as `callerScope` confines an unclassified credential — it therefore sees
  // only the un-attributed platform documents. Unreachable behind
  // `contractAuth` (this operation is `bearer`), and fail-closed if it ever is.
  const scope = auth === null ? { kind: "tenant" as const, tenantId: "" } : callerScope(auth);
  let router: TenantDatabaseRouter | undefined;
  if (env?.TENANT_DATA !== undefined || env?.GATEWAY_TENANT_DB_ROUTING !== undefined) {
    try {
      router = resolverForEnv(env).router;
    } catch {
      // A configured object topology with no resolvable binding is an outage,
      // not a reason to publish a stale control-plane compatibility row.
      return [];
    }
  }
  if (scope.kind === "platform_operator" && router !== undefined) {
    const objectRows: AgentUpstreamRecord[] = [];
    try {
      for (const tenantId of await router.provisionedTenants()) {
        objectRows.push(...(await tenantObjectAgentUpstreams(router, tenantId)));
      }
    } catch {
      // The platform projection has a named control-D1 destination and does
      // not require tenant roster enumeration. Keep it available while the
      // tenant roster is unavailable; tenant-local readers remain object-only.
      return controlPlatformAgentUpstreams(db);
    }
    const seen = new Set(objectRows.map((upstream) => upstream.id));
    for (const upstream of await controlPlatformAgentUpstreams(db)) {
      if (seen.has(upstream.id)) continue;
      seen.add(upstream.id);
      objectRows.push(upstream);
    }
    return objectRows;
  }
  return durableAgentUpstreams(
    db,
    scope.kind === "platform_operator" ? null : scope.tenantId,
    router,
  );
}
