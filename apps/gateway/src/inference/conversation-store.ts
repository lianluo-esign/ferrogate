/**
 * The DURABLE half of Responses conversation state (#689) — the port, the D1
 * implementation, the in-memory one, and the retention sweep.
 *
 * `sql/d1-ts/tenant/0005_responses_conversations.sql` carries the argument for
 * D1 over a Durable Object per conversation; it is not repeated here. What this
 * file owns is the property that argument rests on: **every statement carries
 * the tenant/project fence**, in the same expression that resolves the
 * caller-supplied id. There is no code path that resolves a `response_id`
 * alone.
 */
import type { TenancyBindings } from "../tenancy/ports.js";
import { parseTenantDatabaseRoutingMode, resolverForEnv } from "../tenancy/resolver.js";
import { type ConversationOwner, MAX_CONVERSATION_TURNS, outputItemsOf } from "./conversation.js";

/** One persisted turn. */
export interface StoredResponseTurn {
  readonly responseId: string;
  readonly previousResponseId: string | null;
  /** The credential under which this turn's guardrails were decided. */
  readonly screeningApiKeyId?: string | null;
  /** The complete selected active policy-revision set, or NULL when unknown. */
  readonly screeningPolicyRevision?: string | null;
  /** 0 for the first turn of a chain. */
  readonly turnIndex: number;
  readonly model: string;
  /** This turn's own input items — the delta, not the accumulated prefix. */
  readonly input: readonly unknown[];
  /** The body served to the caller, verbatim. */
  readonly response: Record<string, unknown>;
  readonly createdAtUnix: number;
  readonly expiresAtUnix: number;
}

/** Why a chain could not be replayed. See `conversation.ts` for the vocabulary. */
export type ChainFailure = "not_found" | "expired" | "broken" | "too_long";

export type ChainResolution =
  | { readonly ok: true; readonly turns: readonly StoredResponseTurn[] }
  | { readonly ok: false; readonly reason: ChainFailure };

/**
 * The seam `handlers.ts` codes against.
 *
 * Every method takes the {@link ConversationOwner} as its FIRST argument, and
 * that is deliberate rather than stylistic: there is no overload without it, so
 * "forgot the fence" is not expressible.
 */
export interface ConversationStore {
  /**
   * The chain ENDING at `responseId`, root first, or why it cannot be replayed.
   *
   * Expiry is evaluated on read as well as by the sweep: a deployment whose
   * Cron is not firing must refuse expired state, not serve it.
   */
  chain(owner: ConversationOwner, responseId: string, nowUnix: number): Promise<ChainResolution>;
  /** Persist one turn. Throws on a storage failure — the caller decides. */
  append(owner: ConversationOwner, turn: StoredResponseTurn): Promise<void>;
  /** One turn, for `GET /v1/responses/{id}`. `null` = absent or expired. */
  get(
    owner: ConversationOwner,
    responseId: string,
    nowUnix: number,
  ): Promise<StoredResponseTurn | null>;
  /** `true` when a row was actually removed. */
  remove(owner: ConversationOwner, responseId: string, nowUnix: number): Promise<boolean>;
}

/**
 * The "this deployment persists nothing" store.
 *
 * Every read answers `not_found` and `append` THROWS. Throwing rather than
 * silently succeeding is the point: a deployment that lost its binding must not
 * hand a caller an id that resolves to nothing, and `handlers.ts` decides
 * whether a request may reach here at all (`responseStoreDecision`'s `durable`
 * input) long before it does.
 */
export const NO_CONVERSATION_STORE: ConversationStore = {
  async chain() {
    return { ok: false, reason: "not_found" };
  },
  async append() {
    throw new Error("no conversation store is bound");
  },
  async get() {
    return null;
  },
  async remove() {
    return false;
  },
};

/** Is a durable store actually available? */
export function isDurableConversationStore(store: ConversationStore): boolean {
  return store !== NO_CONVERSATION_STORE;
}

// ---------------------------------------------------------------------------
// Chain assembly, shared by both implementations
// ---------------------------------------------------------------------------

/**
 * Turn the rows of one walk into a resolution.
 *
 * Written once, over a `Map`, so the D1 and in-memory stores cannot disagree
 * about what "broken" means — that disagreement is how an in-memory test comes
 * to prove something the deployed path does not do.
 *
 * The order of the checks matters. EXPIRY first: an expired ancestor makes the
 * prefix unreplayable whatever else is true, and reporting "broken" for it
 * would send an operator looking for a deletion that never happened.
 */
export function assembleChain(
  rows: ReadonlyMap<string, StoredResponseTurn>,
  headId: string,
  nowUnix: number,
): ChainResolution {
  const head = rows.get(headId);
  if (head === undefined) return { ok: false, reason: "not_found" };

  const reversed: StoredResponseTurn[] = [];
  let cursor: StoredResponseTurn | undefined = head;
  const seen = new Set<string>();
  while (cursor !== undefined) {
    if (cursor.expiresAtUnix <= nowUnix) return { ok: false, reason: "expired" };
    if (seen.has(cursor.responseId)) {
      // A cycle cannot be created by the write path (a parent always predates
      // its child), so this is corrupted state. It is reported as "broken"
      // rather than looped on, because the alternative is a request that never
      // returns.
      return { ok: false, reason: "broken" };
    }
    seen.add(cursor.responseId);
    reversed.push(cursor);
    if (reversed.length > MAX_CONVERSATION_TURNS) return { ok: false, reason: "too_long" };
    const parentId: string | null = cursor.previousResponseId;
    if (parentId === null) break;
    const parent: StoredResponseTurn | undefined = rows.get(parentId);
    if (parent === undefined) {
      // The row names a parent and the parent is gone — deleted through
      // `DELETE /v1/responses/{id}`, or swept. REFUSED, never silently served
      // as a shorter conversation.
      return { ok: false, reason: "broken" };
    }
    cursor = parent;
  }
  reversed.reverse();
  return { ok: true, turns: reversed };
}

/** The `{ input, output }` pairs `conversationInput` consumes. */
export function turnItems(
  turns: readonly StoredResponseTurn[],
): readonly { input: readonly unknown[]; output: readonly unknown[] }[] {
  return turns.map((turn) => ({ input: turn.input, output: outputItemsOf(turn.response) }));
}

// ---------------------------------------------------------------------------
// In-memory
// ---------------------------------------------------------------------------

/**
 * The store a deployment with no D1 binding would use if it were allowed one —
 * it is NOT wired into `resolveDeps`, on purpose.
 *
 * An isolate-local map would give a caller an id that resolves on one request
 * and 404s on the next, depending on which isolate answered: worse than
 * refusing, because the failure is intermittent. It exists for the unit tests
 * that exercise the request path without a database, and for that it is exact —
 * it shares {@link assembleChain} with the D1 store.
 */
export class InMemoryConversationStore implements ConversationStore {
  readonly #rows = new Map<string, StoredResponseTurn>();

  /**
   * `[tenant, project, id]` as JSON.
   *
   * JSON rather than a delimiter-joined string because a tenant or project
   * id containing the delimiter would otherwise make two different owners
   * collide — which on this map is a cross-tenant read.
   */
  #key(owner: ConversationOwner, responseId: string): string {
    return JSON.stringify([owner.tenantId, owner.projectId, responseId]);
  }

  /** Every row of one owner, keyed by response id — the walk's working set. */
  #ownerRows(owner: ConversationOwner): Map<string, StoredResponseTurn> {
    const out = new Map<string, StoredResponseTurn>();
    for (const [key, row] of this.#rows) {
      if (key === this.#key(owner, row.responseId)) out.set(row.responseId, row);
    }
    return out;
  }

  async chain(
    owner: ConversationOwner,
    responseId: string,
    nowUnix: number,
  ): Promise<ChainResolution> {
    return assembleChain(this.#ownerRows(owner), responseId, nowUnix);
  }

  async append(owner: ConversationOwner, turn: StoredResponseTurn): Promise<void> {
    this.#rows.set(this.#key(owner, turn.responseId), turn);
  }

  async get(
    owner: ConversationOwner,
    responseId: string,
    nowUnix: number,
  ): Promise<StoredResponseTurn | null> {
    const row = this.#rows.get(this.#key(owner, responseId));
    if (row === undefined || row.expiresAtUnix <= nowUnix) return null;
    return row;
  }

  async remove(owner: ConversationOwner, responseId: string, nowUnix: number): Promise<boolean> {
    const key = this.#key(owner, responseId);
    const row = this.#rows.get(key);
    if (row === undefined || row.expiresAtUnix <= nowUnix) return false;
    this.#rows.delete(key);
    return true;
  }

  /** Test/diagnostic read: how many rows are held. */
  get size(): number {
    return this.#rows.size;
  }
}

// ---------------------------------------------------------------------------
// D1
// ---------------------------------------------------------------------------

const COLUMNS =
  "response_id, previous_response_id, screening_api_key_id, screening_policy_revision, turn_index, " +
  "model, input_json, response_json, created_at_unix, expires_at_unix";

interface ConversationRow {
  response_id: string;
  previous_response_id: string | null;
  screening_api_key_id: string | null;
  screening_policy_revision: string | null;
  turn_index: number;
  model: string;
  input_json: string;
  response_json: string;
  created_at_unix: number;
  expires_at_unix: number;
}

function rowToTurn(row: ConversationRow): StoredResponseTurn {
  return {
    responseId: row.response_id,
    previousResponseId: row.previous_response_id,
    screeningApiKeyId: row.screening_api_key_id,
    screeningPolicyRevision: row.screening_policy_revision,
    turnIndex: Number(row.turn_index),
    model: row.model,
    input: safeArray(row.input_json),
    response: safeObject(row.response_json),
    createdAtUnix: Number(row.created_at_unix),
    expiresAtUnix: Number(row.expires_at_unix),
  };
}

function safeArray(json: string): unknown[] {
  try {
    const parsed: unknown = JSON.parse(json);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function safeObject(json: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(json);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

/**
 * The deployed store.
 *
 * ## The walk is ONE query
 *
 * A parent-at-a-time walk would be up to {@link MAX_CONVERSATION_TURNS} D1 round
 * trips on the request path, which is the cost that would make "D1 instead of a
 * DO" a bad trade. SQLite's recursive CTE collapses it to one, and the tenant
 * fence is repeated in BOTH the anchor and the recursive term — the recursive
 * term needs it independently, because without it the walk would follow a
 * `previous_response_id` out of the caller's tenant the moment two tenants share
 * a physical database — which is what `GATEWAY_TENANT_DB_ROUTING = "off"` still
 * means, and what this store still gets: `conversationStoreFromEnv` reads
 * `env.DB` directly rather than the routed handle, so under the
 * `durable_object` default (#819) it is a shared database holding no routed
 * tenant's rows. Moving it onto `tenantDatabaseOf(c)` is its own slice; until
 * then the fence is the only isolation this table has, and
 * `test/inference/conversation-tenancy.test.ts` mutates exactly that clause.
 *
 * The depth guard inside the CTE is a second, independent bound: a corrupted
 * cycle in the rows must not become an unbounded query, whatever the write path
 * believes it enforced.
 */
export class D1ConversationStore implements ConversationStore {
  constructor(private readonly db: D1Database) {}

  async chain(
    owner: ConversationOwner,
    responseId: string,
    nowUnix: number,
  ): Promise<ChainResolution> {
    const sql =
      // biome-ignore lint/style/useTemplate: Clauses stay split so both tenant fences remain reviewable.
      `WITH RECURSIVE chain(${COLUMNS}, depth) AS (` +
      `SELECT ${COLUMNS}, 0 FROM responses_conversations ` +
      " WHERE tenant_id = ? AND project_id = ? AND response_id = ?" +
      " UNION ALL " +
      "SELECT r.response_id, r.previous_response_id, r.screening_api_key_id, " +
      " r.screening_policy_revision, r.turn_index, r.model, r.input_json, r.response_json, " +
      " r.created_at_unix, r.expires_at_unix, chain.depth + 1 " +
      " FROM responses_conversations r JOIN chain ON r.response_id = chain.previous_response_id " +
      " WHERE r.tenant_id = ? AND r.project_id = ? AND chain.depth < ?" +
      `) SELECT ${COLUMNS} FROM chain`;
    const result = await this.db
      .prepare(sql)
      .bind(
        owner.tenantId,
        owner.projectId,
        responseId,
        owner.tenantId,
        owner.projectId,
        MAX_CONVERSATION_TURNS + 1,
      )
      .all<ConversationRow>();
    const rows = new Map<string, StoredResponseTurn>();
    for (const row of result.results ?? []) {
      const turn = rowToTurn(row);
      rows.set(turn.responseId, turn);
    }
    return assembleChain(rows, responseId, nowUnix);
  }

  async append(owner: ConversationOwner, turn: StoredResponseTurn): Promise<void> {
    // `INSERT OR REPLACE` rather than a plain INSERT: the id is minted here and
    // is 128 bits of randomness, so a conflict is not reachable in practice —
    // but if it ever were, replacing the row we just wrote is strictly better
    // than a 500 on a response the tenant has already paid for, and the row
    // being replaced would be one this same request created.
    await this.db
      .prepare(
        "INSERT OR REPLACE INTO responses_conversations " +
          "(tenant_id, project_id, response_id, previous_response_id, screening_api_key_id, " +
          " screening_policy_revision, turn_index, model, input_json, response_json, " +
          " created_at_unix, expires_at_unix) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .bind(
        owner.tenantId,
        owner.projectId,
        turn.responseId,
        turn.previousResponseId,
        turn.screeningApiKeyId ?? null,
        turn.screeningPolicyRevision ?? null,
        turn.turnIndex,
        turn.model,
        JSON.stringify(turn.input),
        JSON.stringify(turn.response),
        turn.createdAtUnix,
        turn.expiresAtUnix,
      )
      .run();
  }

  async get(
    owner: ConversationOwner,
    responseId: string,
    nowUnix: number,
  ): Promise<StoredResponseTurn | null> {
    const row = await this.db
      .prepare(
        `SELECT ${COLUMNS} FROM responses_conversations WHERE tenant_id = ? AND project_id = ? AND response_id = ? AND expires_at_unix > ?`,
      )
      .bind(owner.tenantId, owner.projectId, responseId, nowUnix)
      .first<ConversationRow>();
    return row === null || row === undefined ? null : rowToTurn(row);
  }

  async remove(owner: ConversationOwner, responseId: string, nowUnix: number): Promise<boolean> {
    const result = await this.db
      .prepare(
        "DELETE FROM responses_conversations " +
          "WHERE tenant_id = ? AND project_id = ? AND response_id = ? AND expires_at_unix > ?",
      )
      .bind(owner.tenantId, owner.projectId, responseId, nowUnix)
      .run();
    // D1 reports `changes` in `meta`; a driver that omits it is treated as "no
    // row removed", which makes DELETE answer 404 rather than claim a deletion
    // it cannot evidence.
    return Number(result.meta?.changes ?? 0) > 0;
  }
}

/** `env.DB` when it is really a D1 binding (a `[vars]` `DB` is a string). */
function tenantDatabaseOf(env: unknown): D1Database | undefined {
  const candidate = (env as { DB?: unknown } | undefined)?.DB;
  return typeof candidate === "object" &&
    candidate !== null &&
    typeof (candidate as D1Database).prepare === "function"
    ? (candidate as D1Database)
    : undefined;
}

/**
 * The routed store (#821 PR2a): each read/write resolves the OWNER tenant's own
 * database through the same router `tenantDatabaseOf(c)` uses, so multi-turn
 * chaining reads and writes `responses_conversations` in that tenant's own
 * Durable Object rather than the shared `env.DB` a routed deployment never
 * writes. `conversationStoreFromEnv`'s docblock called this its own deferred
 * slice; this is that slice.
 *
 * The tenant fence in the SQL stays exactly as strict — it is the isolation the
 * `"off"`/`shared_development` posture still leans on, and a routed object
 * holds one tenant's rows anyway, so the two defences compose rather than
 * duplicate.
 *
 * `resolverForEnv` is memoized per `env`, and `forTenant` under the routed
 * default is a pure `idFromName`, so this costs an allocation per call and no
 * extra round trip. A routing failure throws from the method and is rendered by
 * the responses handler exactly as an `env.DB` outage was.
 */
class RoutedConversationStore implements ConversationStore {
  constructor(private readonly env: unknown) {}

  private async store(tenantId: string): Promise<D1ConversationStore> {
    const handle = await resolverForEnv(this.env as TenancyBindings).forTenant(tenantId);
    return new D1ConversationStore(handle.db);
  }

  async chain(
    owner: ConversationOwner,
    responseId: string,
    nowUnix: number,
  ): Promise<ChainResolution> {
    return (await this.store(owner.tenantId)).chain(owner, responseId, nowUnix);
  }

  async append(owner: ConversationOwner, turn: StoredResponseTurn): Promise<void> {
    return (await this.store(owner.tenantId)).append(owner, turn);
  }

  async get(
    owner: ConversationOwner,
    responseId: string,
    nowUnix: number,
  ): Promise<StoredResponseTurn | null> {
    return (await this.store(owner.tenantId)).get(owner, responseId, nowUnix);
  }

  async remove(owner: ConversationOwner, responseId: string, nowUnix: number): Promise<boolean> {
    return (await this.store(owner.tenantId)).remove(owner, responseId, nowUnix);
  }
}

/**
 * The production resolver: the caller tenant's OWN database under the routed
 * default, the shared `env.DB` under `"off"`, and {@link NO_CONVERSATION_STORE}
 * when no tenant storage is bound at all.
 *
 * Fail-closed by construction — a deployment that binds nothing REFUSES
 * `store: true` and `previous_response_id` (503 `response_store_disabled`)
 * rather than accepting them and forgetting, and serves every other
 * `/v1/responses` request exactly as it did before this slice.
 */
export function conversationStoreFromEnv(env: unknown): ConversationStore {
  const routing = (env as { GATEWAY_TENANT_DB_ROUTING?: unknown } | undefined)
    ?.GATEWAY_TENANT_DB_ROUTING;
  const mode = parseTenantDatabaseRoutingMode(typeof routing === "string" ? routing : undefined);
  // Explicit `"off"`: the shared `env.DB` IS the tenant database, so read it
  // directly. This is the legacy arm the later stanza-removal PR deletes.
  if (mode === "off") {
    const db = tenantDatabaseOf(env);
    return db === undefined ? NO_CONVERSATION_STORE : new D1ConversationStore(db);
  }
  // Routed (the `durable_object` default and the `binding*` modes). With NO
  // tenant storage bound at all — no `TENANT_DATA` namespace AND no shared
  // `env.DB` — there is nowhere any tenant's rows could live, so it fails closed
  // exactly as the unbound `env.DB` case did. Otherwise route per owner tenant.
  const hasTenantData = (env as { TENANT_DATA?: unknown } | undefined)?.TENANT_DATA !== undefined;
  if (!hasTenantData && tenantDatabaseOf(env) === undefined) return NO_CONVERSATION_STORE;
  return new RoutedConversationStore(env);
}

// ---------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------

/**
 * Delete every expired row, on the Cron tick, for every tenant at once.
 *
 * This is the half #765 is missing on MCP sessions, and the reason the storage
 * decision went to D1: the reaper is one statement over one index, it needs no
 * knowledge of which conversations exist, and it cannot be defeated by an
 * isolate that was never woken.
 *
 * Never throws. A retention outage must not take the billing-outbox sweep down
 * with it — the same contract `sweepRequestLogs` has, and `gatewayScheduled`
 * calls the two in sequence.
 */
export async function sweepResponseConversations(env: unknown, nowUnix: number): Promise<number> {
  const db = tenantDatabaseOf(env);
  if (db === undefined) return 0;
  try {
    const result = await db
      .prepare("DELETE FROM responses_conversations WHERE expires_at_unix <= ?")
      .bind(nowUnix)
      .run();
    return Number(result.meta?.changes ?? 0);
  } catch (error) {
    console.warn(
      `[ferrogate] responses: conversation retention sweep failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    return 0;
  }
}
