/**
 * The D1-backed {@link ControlPlaneStore} — what makes the admin surface
 * PERSIST.
 *
 * ## Where the rows go
 *
 * Every collection lands in the control database's generic document table.
 * The DDL below is the TS-era migration `sql/d1-ts/control/0001_init_control.sql`
 * verbatim, which is itself column-for-column the Rust-era reference
 * `sql/d1/001_init_d1.sql`:
 *
 * ```sql
 * CREATE TABLE control_plane_resources (
 *     resource_kind    TEXT NOT NULL,   -- the store collection ("api-keys")
 *     resource_id      TEXT NOT NULL,   -- StoreRecord.id
 *     document_json    TEXT NOT NULL,   -- the WHOLE record, verbatim
 *     revision         INTEGER NOT NULL DEFAULT 1,
 *     created_at_unix  INTEGER NOT NULL DEFAULT (unixepoch()),
 *     updated_at_unix  INTEGER NOT NULL DEFAULT (unixepoch()),
 *     PRIMARY KEY (resource_kind, resource_id));
 * ```
 *
 * That is the same table, with the same `resource_kind`/`document_json`
 * vocabulary, the Rust D1 backend used for its own generic control-plane
 * documents (`crates/ferrogate-storage/src/control_plane_store_d1/`), so nothing
 * here invents schema — see the "schema notes" section at the bottom of this
 * file for the two places the reference schema and this port do not line up, and
 * the report that accompanies this slice.
 *
 * **Why documents and not the typed tables.** The control migration also has
 * first-class `tenants` / `projects` / `workspaces` / `api_keys` /
 * `quota_policies` / `plans` / `wallets` / `site_domains` tables. They are NOT
 * used as the backing store here, because the admin bodies this app accepts are
 * open-ended `passthrough()` documents and those tables have no overflow column:
 * projecting a record onto their fixed columns would silently discard every
 * operator-supplied field they do not name, which is a behaviour regression, not
 * a storage detail. The lossless document is therefore canonical.
 *
 * Projecting a document INTO its typed table is a separate, ADDITIVE job, and it
 * does not belong in this store: the typed rows for `projects` / `workspaces`
 * live in the tenant's OWN database, so they cannot share a `batch()` with the
 * control-database document at all. `routes/tenant_hierarchy.ts` owns that pair
 * and `src/store/tenancy.ts` states the ordering that makes it safe. See the
 * schema notes at the bottom of this file for what is still un-projected.
 *
 * ## Tenant isolation
 *
 * Isolation is a property of the STORE, exactly as in the in-memory reference:
 * every read and every mutation carries {@link tenantScopeSql}, and a
 * tenant-scoped caller's statement can only ever match its own rows (plus
 * un-attributed platform rows). The Rust tree's repeat defect (issues #185/#186)
 * was a handler that resolved a row by bare id; here there is no code path that
 * can — the predicate is appended by one helper that every statement builder
 * calls, so breaking it breaks every collection at once (which is what the
 * mutation test in `test/d1-store.test.ts` demonstrates).
 *
 * `json_extract(document_json, '$.tenant_id')` yields SQL `NULL` both for a
 * JSON `null` and for an absent key, which is precisely the in-memory store's
 * `owner === undefined || owner === null` branch. The two agree by construction.
 *
 * ## Concurrency
 *
 * D1 has no interactive transactions, so `replace`/`merge` are a read, a
 * compute, and an UPDATE guarded on the revision that was read
 * (`AND revision = ?`). A racing writer moves the revision, the guarded UPDATE
 * matches zero rows, and the operation retries against the new state instead of
 * silently clobbering it — the lost-update the naive read-modify-write has.
 *
 * ## Audit
 *
 * Every applied mutation appends an `audit_events` row (the reference schema's
 * table), which is the durable half of the mutation-receipt contract the CLI
 * renders: `docs/legacy/inventory-edge-control.md` §1.2 "mutating verbs can only
 * emit a `MutationReceipt`". The admin response envelope is unchanged — Rust's
 * admin endpoints returned no `audit_id` either, which is exactly why
 * `apps/cli/src/receipt.ts` carries the `endpoint_returns_no_audit_id` absence
 * reason — so the evidence lives in the table, not in the body.
 */
import { AUDIT_CHAIN_GENESIS_HASH, auditChainKey, auditRowHash } from "@ferrogate/storage";
import {
  type CallerScope,
  type ControlPlaneStore,
  type ListPage,
  type ListQuery,
  type MergeIfOutcome,
  StoreConflictError,
  type StoreMutation,
  type StoreRecord,
} from "../ports.js";
import { isUnfilteredQuery, pageOf } from "./query.js";

/** The generic control-plane document table (`sql/d1-ts/control/`). */
export const RESOURCE_TABLE = "control_plane_resources";
/** The durable admin-mutation evidence table (`sql/d1-ts/control/`). */
export const AUDIT_TABLE = "audit_events";
/**
 * The durable per-inference-decision evidence table (`sql/d1-ts/control/`).
 *
 * READ-ONLY from this Worker. The writer is `apps/gateway`'s
 * `src/requestlog/` (#664) — a different Worker on the same CONTROL database —
 * so nothing in `D1ControlPlaneStore` inserts here; the constant lives with its
 * siblings so the reader in `routes/admin_request_log.ts` names the table once.
 */
export const REQUEST_LOG_TABLE = "request_logs";

/** `audit_json.object` — names the document shape for a later reader. */
export const AUDIT_OBJECT = "control_plane_mutation";

/** The mutating operations an audit row records. */
export type AuditAction = "create" | "replace" | "merge" | "remove";

/**
 * Bounded retry for the revision-guarded UPDATE. Three is not a magic number:
 * it bounds an unbounded livelock while being more attempts than the admin
 * surface's contention (two operators editing the same row in the same second)
 * can realistically need.
 */
const UPDATE_ATTEMPTS = 3;

/**
 * Attempts at the chain-guarded audit append (#684).
 *
 * Higher than {@link UPDATE_ATTEMPTS} because the contended resource is
 * different: two operators editing the SAME ROW in the same second is rare,
 * but every mutation in a tenant appends to that tenant's ONE audit chain, so
 * the head is contended by all of them at once. Five bounds a livelock while
 * leaving room for a burst (a bulk import, a console doing several PATCHes in
 * parallel) to land without dropping evidence.
 */
const AUDIT_APPEND_ATTEMPTS = 5;

/**
 * Insertion-order listing, deterministic across calls, matching the in-memory
 * store's `Map` iteration order. `created_at_unix` is second-granular, so
 * `rowid` is the tiebreak that makes two rows written in the same second come
 * back in the order they were written.
 */
const LIST_ORDER = "ORDER BY created_at_unix ASC, rowid ASC";

/**
 * THE tenant isolation guard, READ side.
 *
 * A platform operator gets no predicate (it sees every row); a tenant-scoped
 * caller gets one that admits its own rows AND un-attributed platform rows.
 * Every SELECT in this file appends it, so there is no "read by bare id" path
 * to forget it on.
 *
 * The `IS NULL` disjunct is a deliberate widening of Rust
 * `auth::filter_by_tenant_scope` (strict equality, `auth.rs:428`), argued for
 * READS only and pinned on purpose (`test/store-conformance.test.ts` "shows an
 * un-attributed platform row to every tenant"): it is how a global plan or a
 * shared provider row stays visible to the tenant it applies to, which
 * `GET /admin/v1/tenant-accounts/{id}/resolved-defaults` depends on.
 *
 * It stops at the read. {@link tenantWriteScopeSql} is what every UPDATE and
 * DELETE appends, and it is Rust's strict equality — see its docblock for the
 * cross-tenant WRITE that the single shared predicate used to allow.
 */
export function tenantScopeSql(scope: CallerScope): {
  readonly sql: string;
  readonly params: readonly string[];
} {
  if (scope.kind === "platform_operator") return { sql: "", params: [] };
  return {
    sql: " AND (json_extract(document_json, '$.tenant_id') IS NULL OR json_extract(document_json, '$.tenant_id') = ?)",
    params: [scope.tenantId],
  };
}

/**
 * The same fence for a MUTATION — strictly narrower, and the SQL half of
 * `query.ts::writableBy`.
 *
 * {@link tenantScopeSql} keeps the `IS NULL` disjunct so a tenant can READ the
 * deployment's un-attributed platform rows (`resolved-defaults` depends on it).
 * That disjunct must not survive into an `UPDATE`/`DELETE`: with it, a
 * tenant-scoped caller holding `admin.write` — a tenant administrator, an
 * intended configuration — could edit or delete any platform row: a global
 * `role`, a shared `policy`, a `plan` other tenants are billed against. Rust
 * `filter_by_tenant_scope` (`auth.rs:428`) is strict equality and makes that
 * unreachable; this restores it.
 *
 * `json_extract` yields SQL `NULL` for both a JSON `null` and an absent key, and
 * `NULL = ?` is `NULL` (never true), so an un-attributed row simply fails to
 * match — which is exactly `writableBy`'s `record.tenant_id === scope.tenantId`
 * over `undefined`/`null`. The two agree by construction.
 */
export function tenantWriteScopeSql(scope: CallerScope): {
  readonly sql: string;
  readonly params: readonly string[];
} {
  if (scope.kind === "platform_operator") return { sql: "", params: [] };
  return {
    sql: " AND json_extract(document_json, '$.tenant_id') = ?",
    params: [scope.tenantId],
  };
}

/**
 * The identity of one row, `(collection, id)`, as a single map/set key.
 *
 * The separator is an explicit `\u0000` ESCAPE, not a literal NUL byte: a raw
 * NUL in the source makes every text tool (grep, diff, review) treat this file
 * as binary and silently stop showing its contents. It is still the right
 * separator — no collection name or resource id can contain it, so
 * `("a", "b:c")` and `("a:b", "c")` cannot collide.
 */
function rowIdentity(collection: string, id: string): string {
  return `${collection}\u0000${id}`;
}

interface ResourceRow {
  readonly document_json: string;
  readonly revision: number;
}

/** A stored row: the caller's document plus the storage revision it sits at. */
interface LoadedRecord {
  readonly record: StoreRecord;
  readonly revision: number;
}

function parseDocument(collection: string, id: string, json: string): StoreRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    // Refusing loudly beats returning `null`: "the row is unreadable" and "there
    // is no such row" are different facts and only one of them is safe to treat
    // as "free to create over".
    throw new Error(`control_plane_resources ${collection}/${id} holds unparseable document_json`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`control_plane_resources ${collection}/${id} document_json is not an object`);
  }
  return parsed as StoreRecord;
}

/** Options the composition root supplies per request. */
export interface D1ControlPlaneStoreOptions {
  /**
   * The `x-request-id` this mutation belongs to, stamped on every audit row
   * (`audit_events.request_id` is NOT NULL). Absent outside a request.
   */
  readonly requestId?: string | null;
  /** Injected clock, so tests can pin `occurred_at_unix`. */
  readonly now?: () => number;
  /** Injected id minting, so tests can pin audit ids. */
  readonly newId?: () => string;
}

export class D1ControlPlaneStore implements ControlPlaneStore {
  readonly #db: D1Database;
  readonly #requestId: string;
  readonly #now: () => number;
  readonly #newId: () => string;

  constructor(db: D1Database, options: D1ControlPlaneStoreOptions = {}) {
    this.#db = db;
    // `audit_events.request_id` is NOT NULL; an absent correlation id is the
    // empty string rather than a fabricated one, so a reader can tell the
    // difference between "unattributed" and "attributed to request ''".
    this.#requestId = options.requestId ?? "";
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.#newId = options.newId ?? (() => crypto.randomUUID());
  }

  // -------------------------------------------------------------------------
  // Reads
  // -------------------------------------------------------------------------

  async list(collection: string, scope: CallerScope, query: ListQuery): Promise<ListPage> {
    const tenant = tenantScopeSql(scope);
    const where = `WHERE resource_kind = ?${tenant.sql}`;
    const whereParams = [collection, ...tenant.params];

    // Fast path: nothing to match in JS, so the window and the count are SQL's
    // job. Same rows, same order, same `total` — just not read into the isolate.
    if (query.paginate && isUnfilteredQuery(query)) {
      const [pageResult, countResult] = await this.#db.batch<Record<string, unknown>>([
        this.#db
          .prepare(
            `SELECT resource_id, document_json FROM ${RESOURCE_TABLE} ${where} ${LIST_ORDER} LIMIT ? OFFSET ?`,
          )
          .bind(...whereParams, query.limit, query.offset),
        this.#db
          .prepare(`SELECT COUNT(*) AS total FROM ${RESOURCE_TABLE} ${where}`)
          .bind(...whereParams),
      ]);
      const items = (pageResult?.results ?? []).map((row) =>
        parseDocument(
          collection,
          String(row.resource_id),
          String((row as { document_json: string }).document_json),
        ),
      );
      const total = Number(
        (countResult?.results?.[0] as { total?: number } | undefined)?.total ?? 0,
      );
      return { items, total };
    }

    // `?search=` / `?k=v` are matched by the SAME predicates the in-memory store
    // uses (`./query.ts`), because pushing them into SQL would change their
    // meaning (`json_extract` yields `1` for a JSON `true`, where the reference
    // compares against the string `"true"`).
    //
    // PORT-TODO(L: inventory-edge-control §9.3) — KEPT, sharpened. This reads the
    // collection's tenant-visible rows into the isolate before filtering, and
    // that is NOT a shortcut that a cleverer predicate closes: pushing either
    // half into SQL over `document_json` CHANGES ITS MEANING, in both
    // directions, and `test/store-conformance.test.ts` pins both cases against
    // both stores:
    //
    //   * `?search=` folds case with JS `toLowerCase()`, i.e. full Unicode.
    //     SQLite's `LIKE` folds ASCII ONLY, so a `document_json LIKE ?`
    //     pre-filter DROPS a row that matches (`search=ärzte` vs `"ÄRZTE"`) —
    //     it is not even a safe superset. It would also match on field NAMES and
    //     on fields outside `SEARCH_FIELDS`, i.e. over-match at the same time.
    //   * `?k=v` compares `String(value) === expected`, so a JSON `true` matches
    //     the string `"true"`. `json_extract(document_json, '$.k')` yields the
    //     INTEGER `1` for that row, so the SQL predicate matches nothing.
    //
    // The real close is therefore a SCHEMA change, not a query change: typed
    // projection columns (plus a `tenant_id` generated column, see the schema
    // notes at the bottom of this file) for the high-cardinality collections
    // — `request-logs`, `agent-run-events`, `metering-events` — with a
    // collation that matches the reference. `sql/d1-ts/` belongs to the
    // migrations slice, so this is reported rather than a column invented here.
    // Until then the admin/low-volume path is what Rust's own D1 backend
    // documents for these surfaces, and correctness is preferred to the seek.
    const rows = await this.#db
      .prepare(`SELECT resource_id, document_json FROM ${RESOURCE_TABLE} ${where} ${LIST_ORDER}`)
      .bind(...whereParams)
      .all<{ resource_id: string; document_json: string }>();
    const visible = rows.results.map((row) =>
      parseDocument(collection, row.resource_id, row.document_json),
    );
    return pageOf(visible, query);
  }

  async get(collection: string, scope: CallerScope, id: string): Promise<StoreRecord | null> {
    const loaded = await this.#load(collection, scope, id);
    return loaded === null ? null : loaded.record;
  }

  /**
   * Resolve one row for a caller.
   *
   * `fence` picks which tenant predicate is appended: `"read"` lets a tenant see
   * the deployment's un-attributed platform rows, `"write"` does not. Every
   * mutation below loads with `"write"` so the guarded `UPDATE`/`DELETE` that
   * follows cannot match a row this load did not — otherwise a tenant's PATCH of
   * a platform row would load it, fail the narrowed UPDATE, and burn the retry
   * loop into a 500 instead of the 404 it must be.
   */
  async #load(
    collection: string,
    scope: CallerScope,
    id: string,
    fence: "read" | "write" = "read",
  ): Promise<LoadedRecord | null> {
    const tenant = fence === "write" ? tenantWriteScopeSql(scope) : tenantScopeSql(scope);
    const row = await this.#db
      .prepare(
        `SELECT document_json, revision FROM ${RESOURCE_TABLE} WHERE resource_kind = ? AND resource_id = ?${tenant.sql}`,
      )
      .bind(collection, id, ...tenant.params)
      .first<ResourceRow>();
    if (row === null) return null;
    return { record: parseDocument(collection, id, row.document_json), revision: row.revision };
  }

  // -------------------------------------------------------------------------
  // Mutations
  // -------------------------------------------------------------------------

  async create(collection: string, scope: CallerScope, record: StoreRecord): Promise<StoreRecord> {
    const stored: StoreRecord = {
      ...record,
      // A tenant-scoped caller cannot mint a row into another tenant.
      tenant_id: scope.kind === "tenant" ? scope.tenantId : (record.tenant_id ?? null),
    };
    const now = this.#now();
    // `DO NOTHING` + `RETURNING` is the atomic form of "insert if absent": a
    // colliding id returns no row, so there is no read-then-insert window in
    // which two requests both see "absent" and one silently overwrites.
    //
    // The conflict is on `(resource_kind, resource_id)` and therefore ignores
    // the caller's tenant, matching the in-memory reference: an id taken by
    // another tenant is a 409, not a silent second row under the same id.
    const inserted = await this.#db
      .prepare(
        `INSERT INTO ${RESOURCE_TABLE}
           (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
         VALUES (?, ?, ?, 1, ?, ?)
         ON CONFLICT (resource_kind, resource_id) DO NOTHING
         RETURNING revision`,
      )
      .bind(collection, stored.id, JSON.stringify(stored), now, now)
      .first<{ revision: number }>();
    if (inserted === null) throw new StoreConflictError(collection, stored.id);

    await this.#audit("create", collection, stored, inserted.revision, scope);
    return stored;
  }

  replace(
    collection: string,
    scope: CallerScope,
    id: string,
    record: Omit<StoreRecord, "id">,
  ): Promise<StoreRecord | null> {
    // A replace is a FULL swap of the document, but `id` and `tenant_id` are
    // structural: the caller may not move a row to another tenant by PUTting a
    // different `tenant_id`, exactly as in the in-memory reference.
    return this.#update(collection, scope, id, "replace", (existing) => ({
      ...record,
      id,
      tenant_id: existing.tenant_id ?? null,
    }));
  }

  merge(
    collection: string,
    scope: CallerScope,
    id: string,
    patch: Readonly<Record<string, unknown>>,
  ): Promise<StoreRecord | null> {
    const { id: _ignoredId, tenant_id: _ignoredTenant, ...fields } = patch;
    return this.#update(collection, scope, id, "merge", (existing) => ({
      ...existing,
      ...fields,
      id,
      tenant_id: existing.tenant_id ?? null,
    }));
  }

  /**
   * {@link ControlPlaneStore.mergeIf} — the compare-and-set.
   *
   * The atomicity is the SAME revision guard `#update` uses, and that is the
   * whole trick: the predicate is evaluated on the record read at revision `r`,
   * and the write only lands `WHERE revision = r`. So the pair
   * (decision, write) is indivisible with respect to any other writer —
   * a concurrent commit moves the revision, this UPDATE matches zero rows, and
   * the next attempt RE-EVALUATES the precondition against the state that writer
   * left. The stale snapshot can never be the one a write is authorized by.
   *
   * That re-evaluation is the difference between this and `get` + `merge`, and
   * it is not a micro-optimization: with `get` + `merge`, two concurrent
   * `POST /admin/v1/site-domains/{h}/verify` calls both read
   * `last_checked_at_unix = NULL`, both are told the cooldown is clear, and both
   * reach the DNS resolver — which is precisely the burst #576 exists to stop.
   * Here the loser re-reads the winner's `last_checked_at_unix`, the predicate
   * refuses, and it never touches the network.
   *
   * Exhausting the retries is reported as a lost race (a 500 the caller may
   * retry) rather than as `precondition_failed`, because "I could not decide"
   * and "the answer is no" are different facts and only one of them is safe to
   * cache in a caller's head.
   */
  async mergeIf(
    collection: string,
    scope: CallerScope,
    id: string,
    patch: Readonly<Record<string, unknown>>,
    precondition: (current: StoreRecord) => boolean,
  ): Promise<MergeIfOutcome> {
    const tenant = tenantWriteScopeSql(scope);
    const { id: _ignoredId, tenant_id: _ignoredTenant, ...fields } = patch;

    for (let attempt = 0; attempt < UPDATE_ATTEMPTS; attempt += 1) {
      const existing = await this.#load(collection, scope, id, "write");
      if (existing === null) return { kind: "not_found" };
      if (!precondition(existing.record)) {
        return { kind: "precondition_failed", current: existing.record };
      }

      const next: StoreRecord = {
        ...existing.record,
        ...fields,
        id,
        tenant_id: existing.record.tenant_id ?? null,
      };
      const result = await this.#db
        .prepare(
          `UPDATE ${RESOURCE_TABLE}
             SET document_json = ?, revision = revision + 1, updated_at_unix = ?
           WHERE resource_kind = ? AND resource_id = ? AND revision = ?${tenant.sql}`,
        )
        .bind(
          JSON.stringify(next),
          this.#now(),
          collection,
          id,
          existing.revision,
          ...tenant.params,
        )
        .run();
      if ((result.meta.changes ?? 0) > 0) {
        await this.#audit("merge", collection, next, existing.revision + 1, scope);
        return { kind: "merged", record: next };
      }
    }
    throw new Error(
      `control_plane_resources ${collection}/${id} lost ${UPDATE_ATTEMPTS} conditional write races; retry`,
    );
  }

  async remove(collection: string, scope: CallerScope, id: string): Promise<boolean> {
    // Loaded first so the audit row can name the tenant the deleted row
    // actually belonged to (which, for a platform operator deleting a global
    // row, is not the caller's).
    const existing = await this.#load(collection, scope, id, "write");
    const tenant = tenantWriteScopeSql(scope);
    const result = await this.#db
      .prepare(
        `DELETE FROM ${RESOURCE_TABLE} WHERE resource_kind = ? AND resource_id = ?${tenant.sql}`,
      )
      .bind(collection, id, ...tenant.params)
      .run();
    if ((result.meta.changes ?? 0) === 0) return false;

    await this.#audit(
      "remove",
      collection,
      existing?.record ?? { id },
      existing?.revision ?? 0,
      scope,
    );
    return true;
  }

  // -------------------------------------------------------------------------
  // Atomic multi-row units
  // -------------------------------------------------------------------------

  /**
   * {@link ControlPlaneStore.atomic} on a real SQLite transaction.
   *
   * `D1Database.batch()` runs its statements in ONE implicit transaction, so
   * either every statement below commits or none of them does. That alone is
   * not enough, though, and the reason is the whole design of this method:
   *
   * > **A guard that FAILS QUIETLY cannot make a batch all-or-nothing.**
   *
   * A `DO NOTHING` insert and a `WHERE revision = ?` update both *succeed*
   * while matching zero rows. The transaction then has nothing to roll back, so
   * the statements that DID match commit — a half-applied unit that looks like
   * a committed one. On `routes/wallets.ts` that is a ledger entry with no
   * balance movement, or a balance movement with no ledger entry.
   *
   * So every guard here is expressed as
   * `document_json = CASE WHEN <guard> THEN ? ELSE NULL END`, and
   * `control_plane_resources.document_json` is `NOT NULL`. A failed guard is
   * therefore a **constraint violation** — a real SQLite error, which rolls the
   * whole transaction back and skips the statements after it. Four things
   * follow:
   *
   *  1. **A taken `create` id ERRORS the batch.** The insert carries no
   *     `ON CONFLICT … DO NOTHING`, so a colliding id is a UNIQUE violation; it
   *     is translated back into the same `StoreConflictError` `create` raises.
   *  2. **Every statement is guarded on the revisions it expects to see AT ITS
   *     OWN POSITION in the batch.** The statements of a `batch()` run in one
   *     transaction and therefore SEE EACH OTHER'S WRITES, so a single
   *     "pre-state" guard replicated onto every statement is self-defeating.
   *     The updates run first, in mutation order, and:
   *
   *       - update #p requires its own target at the revision that target holds
   *         when #p runs, plus every OTHER merge target at the revision *it*
   *         holds at that same moment (`rev + 1` once this batch has updated
   *         it, `rev` before);
   *       - every insert then requires EVERY merge target at its post-update
   *         revision.
   *
   *     Because a failed guard now ABORTS, "the row sits at `rev + 1`" is
   *     unambiguous by the time a later statement reads it: the only way to
   *     REACH that statement is for this batch's own update to have applied.
   *     Reading `rev + 1` as proof of the sibling write was the defect — a
   *     CONCURRENT writer's `+ 1` satisfied it just as well, so the loser of a
   *     two-charge wallet race committed its ledger entry (a fresh uuid, so the
   *     insert always succeeded) while its balance update matched nothing: a
   *     ledger permanently disagreeing with the balance it exists to explain,
   *     reported to the operator as a 500.
   *  3. A merge target DELETED between the load and the batch makes its own
   *     UPDATE match zero rows WITHOUT erroring — there is no row left to
   *     violate a constraint. Every sibling statement's cross-guard requires
   *     that row to EXIST, so a sibling aborts the transaction. A unit whose
   *     *only* statement is that update simply matches nothing, which is
   *     already "wrote nothing", and the retry re-reads and answers `null`.
   *  4. A `create` id repeated INSIDE one unit is refused before any statement
   *     is built — the second insert would otherwise collide with the first
   *     one's uncommitted row, which is a caller bug, not a lost race.
   *
   * A rolled-back batch is then explained by RE-READING state
   * ({@link #explainRolledBackBatch}) rather than by parsing a driver message:
   * a vanished target is `null`, a taken id is `StoreConflictError`, a moved
   * revision is a lost race and retries, and anything else is re-thrown as the
   * genuine fault it is.
   */
  async atomic(
    scope: CallerScope,
    mutations: readonly StoreMutation[],
  ): Promise<readonly StoreRecord[] | null> {
    if (mutations.length === 0) return [];
    const tenant = tenantWriteScopeSql(scope);

    // (4) above: two `create`s of the same id in one unit.
    const mintedIds = new Set<string>();
    for (const mutation of mutations) {
      if (mutation.kind !== "create") continue;
      if (mintedIds.has(rowIdentity(mutation.collection, mutation.record.id))) {
        throw new StoreConflictError(mutation.collection, mutation.record.id);
      }
      mintedIds.add(rowIdentity(mutation.collection, mutation.record.id));
    }

    for (let attempt = 0; attempt < UPDATE_ATTEMPTS; attempt += 1) {
      // Resolve every merge target first, so the guard revisions are the ones
      // the computed documents were derived from.
      const loaded = new Map<number, LoadedRecord>();
      /**
       * The merge targets, in the order their UPDATEs will run — each already
       * carrying the row it addresses and the revision it was read at, so the
       * guard builders below never have to re-derive either from `mutations`.
       */
      const targets: {
        readonly index: number;
        readonly collection: string;
        readonly id: string;
        readonly key: string;
        readonly revision: number;
      }[] = [];
      for (const [index, mutation] of mutations.entries()) {
        if (mutation.kind !== "merge") continue;
        const existing = await this.#load(mutation.collection, scope, mutation.id, "write");
        // A missing/invisible merge target aborts the WHOLE unit before a
        // single statement runs — "nothing was written" has to be true on this
        // path too, not just on the transaction's.
        if (existing === null) return null;
        loaded.set(index, existing);
        targets.push({
          index,
          collection: mutation.collection,
          id: mutation.id,
          // Two merges in ONE unit may address the same row; `key` is what makes
          // that visible to the guards below.
          key: rowIdentity(mutation.collection, mutation.id),
          revision: existing.revision,
        });
      }

      /**
       * The revision the target at update-position `position` HOLDS when that
       * statement runs: its loaded revision, plus one for every EARLIER update
       * in this same batch that targets the same row. Normally none — but two
       * merges of one row in a single unit is legal (the in-memory reference
       * applies both), and assuming otherwise would guard the second one on a
       * revision its own predecessor has already moved past.
       */
      const revisionAt = (target: { key: string; revision: number }, position: number): number => {
        let applied = 0;
        for (const [otherPosition, other] of targets.entries()) {
          if (otherPosition < position && other.key === target.key) applied += 1;
        }
        return target.revision + applied;
      };

      /**
       * The guard for the statement at update-position `position`
       * (`targets.length` = "runs after every update", i.e. an insert),
       * covering every merge target OTHER than the row `ownKey` names.
       *
       * Each is required to EXIST at the revision it will actually hold when
       * this statement runs. Requiring EXISTENCE is what turns a
       * concurrently-deleted sibling into an abort — see (3) on the method.
       */
      const crossGuard = (
        position: number,
        ownKey: string | null,
      ): { readonly clauses: readonly string[]; readonly params: readonly unknown[] } => {
        const clauses: string[] = [];
        const params: unknown[] = [];
        const seen = new Set<string>();
        for (const target of targets) {
          if (target.key === ownKey || seen.has(target.key)) continue;
          seen.add(target.key);
          clauses.push(
            `EXISTS (SELECT 1 FROM ${RESOURCE_TABLE} WHERE resource_kind = ? AND resource_id = ? AND revision = ?)`,
          );
          params.push(target.collection, target.id, revisionAt(target, position));
        }
        return { clauses, params };
      };

      const now = this.#now();
      /** Updates first (mutation order), then inserts — see {@link crossGuard}. */
      const updateStatements: D1PreparedStatement[] = [];
      const insertStatements: D1PreparedStatement[] = [];
      const next: StoreRecord[] = [];
      const audits: {
        action: AuditAction;
        collection: string;
        record: StoreRecord;
        revision: number;
      }[] = [];

      for (const [index, mutation] of mutations.entries()) {
        if (mutation.kind === "create") {
          const stored: StoreRecord = {
            ...mutation.record,
            tenant_id:
              scope.kind === "tenant" ? scope.tenantId : (mutation.record.tenant_id ?? null),
          };
          next.push(stored);
          audits.push({
            action: "create",
            collection: mutation.collection,
            record: stored,
            revision: 1,
          });
          // Runs after every update, so every merge target is expected at its
          // post-update revision. The guard is a `CASE … ELSE NULL`, NOT a
          // `WHERE`: a failed guard has to abort, not insert nothing. And no
          // `ON CONFLICT` clause, so a taken id is a UNIQUE violation that
          // rolls the transaction back (see (1) on the method).
          const guard = crossGuard(targets.length, null);
          insertStatements.push(
            this.#db
              .prepare(
                `INSERT INTO ${RESOURCE_TABLE}
                   (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
                 SELECT ?, ?, ${
                   guard.clauses.length === 0
                     ? "?"
                     : `CASE WHEN ${guard.clauses.join(" AND ")} THEN ? ELSE NULL END`
                 }, 1, ?, ?`,
              )
              .bind(
                mutation.collection,
                stored.id,
                ...guard.params,
                JSON.stringify(stored),
                now,
                now,
              ),
          );
          continue;
        }

        const existing = loaded.get(index);
        // Unreachable: every `merge` was loaded above or the unit returned.
        if (existing === undefined) throw new Error("atomic: unresolved merge target");
        const { id: _ignoredId, tenant_id: _ignoredTenant, ...fields } = mutation.patch;
        const merged: StoreRecord = {
          ...existing.record,
          ...fields,
          id: mutation.id,
          tenant_id: existing.record.tenant_id ?? null,
        };
        const position = targets.findIndex((target) => target.index === index);
        const own = targets[position];
        // Unreachable for the same reason as `existing` above.
        if (own === undefined) throw new Error("atomic: unplanned merge target");
        const ownRevision = revisionAt(own, position);
        next.push(merged);
        audits.push({
          action: "merge",
          collection: mutation.collection,
          record: merged,
          revision: ownRevision + 1,
        });
        const guard = crossGuard(position, own.key);
        // The row is addressed by PRIMARY KEY alone and every predicate that
        // can deny the write — the tenant fence included — sits in the `CASE`,
        // so denying is an abort rather than a silent no-op. In an UPDATE's SET
        // expressions a bare column reference is the row's PRE-update value,
        // which is exactly what both `revision = ?` and the tenant fence mean.
        updateStatements.push(
          this.#db
            .prepare(
              `UPDATE ${RESOURCE_TABLE}
                 SET document_json = CASE WHEN revision = ?${tenant.sql}${
                   guard.clauses.length === 0 ? "" : ` AND ${guard.clauses.join(" AND ")}`
                 } THEN ? ELSE NULL END,
                     revision = revision + 1,
                     updated_at_unix = ?
               WHERE resource_kind = ? AND resource_id = ?`,
            )
            .bind(
              ownRevision,
              ...tenant.params,
              ...guard.params,
              JSON.stringify(merged),
              now,
              mutation.collection,
              mutation.id,
            ),
        );
      }

      const statements = [...updateStatements, ...insertStatements];
      let results: D1Result[];
      try {
        results = await this.#db.batch(statements);
      } catch (error) {
        // The transaction rolled back, so NOTHING was written. Which of the
        // answers this method owns applies is decided by re-reading state, not
        // by the driver's opaque message.
        const explained = await this.#explainRolledBackBatch(scope, mutations, loaded);
        if (explained === "missing") return null;
        if (explained === "race") continue;
        if (explained !== "unknown") {
          throw new StoreConflictError(explained.collection, explained.id);
        }
        throw error;
      }
      const changes = results.map((result) => result.meta.changes ?? 0);
      if (changes.every((count) => count > 0)) {
        for (const entry of audits) {
          await this.#audit(entry.action, entry.collection, entry.record, entry.revision, scope);
        }
        return next;
      }
      if (changes.some((count) => count > 0)) {
        // Cannot happen: every way a statement can be DENIED is a constraint
        // violation that aborts the transaction, and the only statement that
        // can match zero rows without erroring (an update whose row was deleted
        // concurrently) makes every sibling abort. If it ever does happen the
        // unit is no longer all-or-nothing, and saying so beats returning a
        // half-written result as a success.
        throw new Error(
          `control_plane_resources atomic unit applied ${changes.filter((c) => c > 0).length} of ${changes.length} statements`,
        );
      }
      // Zero rows everywhere: every statement was an update whose row is gone.
      // Re-read and retry; the next pass resolves it to `null`.
    }
    throw new Error(
      `control_plane_resources atomic unit lost ${UPDATE_ATTEMPTS} write races; retry`,
    );
  }

  /**
   * Why a batch rolled back, decided by RE-READING state rather than by parsing
   * the driver's error text (opaque, and version-dependent).
   *
   * Precedence matches the in-memory reference, which resolves every merge
   * target BEFORE it looks at `create` ids: an unresolvable target answers
   * `null` (→ 404) even when the same unit also carries a taken id.
   *
   *  - `"missing"` — a merge target is gone or invisible → `null`, exactly as
   *    if it had been missing at load time;
   *  - `{collection, id}` — a `create` id is taken → `StoreConflictError`;
   *  - `"race"` — a merge target moved on underneath us → retry against the
   *    state the winner left;
   *  - `"unknown"` — none of the above, so the error is a genuine fault and the
   *    caller re-throws it instead of dressing it up as a conflict.
   */
  async #explainRolledBackBatch(
    scope: CallerScope,
    mutations: readonly StoreMutation[],
    loaded: ReadonlyMap<number, LoadedRecord>,
  ): Promise<
    "missing" | "race" | "unknown" | { readonly collection: string; readonly id: string }
  > {
    let raced = false;
    for (const [index, mutation] of mutations.entries()) {
      if (mutation.kind !== "merge") continue;
      // The WRITE fence, like the load that built `loaded`: this re-read has to
      // ask the same question the batch asked, or a row the unit could never
      // have mutated would be explained as a race instead of as missing.
      const current = await this.#load(mutation.collection, scope, mutation.id, "write");
      if (current === null) return "missing";
      if (current.revision !== loaded.get(index)?.revision) raced = true;
    }
    const conflict = await this.#firstTakenCreateId(mutations);
    if (conflict !== null) return conflict;
    return raced ? "race" : "unknown";
  }

  /**
   * The first `create` id in the unit that is already stored, or `null`.
   *
   * Used ONLY to explain a rolled-back batch: `INSERT` without `ON CONFLICT`
   * raises a UNIQUE violation, and D1 reports that as an opaque error, so the
   * offending id is read back rather than parsed out of a driver message.
   * Deliberately unscoped by tenant, matching {@link create}: an id another
   * tenant holds is a conflict, not an invisible row.
   */
  async #firstTakenCreateId(
    mutations: readonly StoreMutation[],
  ): Promise<{ readonly collection: string; readonly id: string } | null> {
    for (const mutation of mutations) {
      if (mutation.kind !== "create") continue;
      const taken = await this.#db
        .prepare(
          `SELECT 1 AS present FROM ${RESOURCE_TABLE} WHERE resource_kind = ? AND resource_id = ?`,
        )
        .bind(mutation.collection, mutation.record.id)
        .first<{ present: number }>();
      if (taken !== null) return { collection: mutation.collection, id: mutation.record.id };
    }
    return null;
  }

  /**
   * Read-compute-write with an optimistic revision guard.
   *
   * The UPDATE carries BOTH the tenant predicate (so a cross-tenant id can
   * never be written) and `AND revision = ?` (so a concurrent writer's change
   * is not clobbered). Zero matched rows means one of two things, told apart by
   * re-reading: the row went away (→ `null`, a 404) or it moved on (→ retry
   * against the new state).
   */
  async #update(
    collection: string,
    scope: CallerScope,
    id: string,
    action: AuditAction,
    build: (existing: StoreRecord) => StoreRecord,
  ): Promise<StoreRecord | null> {
    const tenant = tenantWriteScopeSql(scope);
    for (let attempt = 0; attempt < UPDATE_ATTEMPTS; attempt += 1) {
      const existing = await this.#load(collection, scope, id, "write");
      if (existing === null) return null;

      const next = build(existing.record);
      const result = await this.#db
        .prepare(
          `UPDATE ${RESOURCE_TABLE}
             SET document_json = ?, revision = revision + 1, updated_at_unix = ?
           WHERE resource_kind = ? AND resource_id = ? AND revision = ?${tenant.sql}`,
        )
        .bind(
          JSON.stringify(next),
          this.#now(),
          collection,
          id,
          existing.revision,
          ...tenant.params,
        )
        .run();
      if ((result.meta.changes ?? 0) > 0) {
        await this.#audit(action, collection, next, existing.revision + 1, scope);
        return next;
      }
    }
    // Refusing beats looping: an operator gets a 500 they can retry, not a
    // request that never returns.
    throw new Error(
      `control_plane_resources ${collection}/${id} lost ${UPDATE_ATTEMPTS} write races; retry`,
    );
  }

  // -------------------------------------------------------------------------
  // Audit
  // -------------------------------------------------------------------------

  /**
   * Append the durable evidence row for an APPLIED mutation, LINKED to the row
   * before it (#684).
   *
   * A failure here is warned about and swallowed, matching the Rust backend's
   * documented `()`-returning evidence surfaces ("swallow-with-warn like the
   * Postgres backend"): the mutation has already landed, so answering the
   * operator with an error would report a failure for a change that happened —
   * a worse lie than a missing audit row.
   *
   * ## The chain
   *
   * The row's digest commits to its own fields AND to its predecessor's digest
   * (`packages/storage/src/audit-chain.ts`), so editing or deleting any row
   * invalidates every row after it. That is what turns "append-only by
   * convention" into "alteration is detectable", which is the whole of #684.
   *
   * ## Why read-then-insert is safe here without a transaction
   *
   * D1 has no interactive transactions, so this reads the chain head, computes
   * the digest in the isolate, and inserts — a classic lost-update shape. What
   * makes it sound is the UNIQUE `(chain_key, seq)` index
   * (`sql/d1-ts/control/0003_audit_chain.sql`): a racing writer that read the
   * same head inserts the same `seq` and the constraint REFUSES it, so the
   * loser retries against the new head instead of forking the chain. Same
   * argument as `#updateGuarded`'s revision guard, one table over.
   */
  async #audit(
    action: AuditAction,
    collection: string,
    record: StoreRecord,
    revision: number,
    scope: CallerScope,
  ): Promise<void> {
    const tenantId = typeof record.tenant_id === "string" ? record.tenant_id : null;
    const auditJson = JSON.stringify({
      object: AUDIT_OBJECT,
      action,
      collection,
      resource_id: record.id,
      revision,
      actor_scope: scope.kind,
      actor_tenant_id: scope.kind === "tenant" ? scope.tenantId : null,
      resource_tenant_id: tenantId,
    });

    // ONE CHAIN PER TENANT. The audit READ fence is strict equality on
    // `tenant`, so a tenant only ever sees its own rows; a single global chain
    // would look like a trail full of holes to every tenant and be
    // unverifiable by any of them. See `auditChainKey`'s docblock.
    const chainKey = auditChainKey(tenantId);
    const id = this.#newId();
    const occurredAt = this.#now();

    for (let attempt = 1; attempt <= AUDIT_APPEND_ATTEMPTS; attempt += 1) {
      try {
        const head = await this.#db
          .prepare(
            `SELECT seq, row_hash FROM ${AUDIT_TABLE}
              WHERE chain_key = ? AND seq IS NOT NULL
              ORDER BY seq DESC LIMIT 1`,
          )
          .bind(chainKey)
          .first<{ seq: number; row_hash: string | null }>();

        const seq = (head?.seq ?? 0) + 1;
        const prevHash = head?.row_hash ?? AUDIT_CHAIN_GENESIS_HASH;
        const rowHash = await auditRowHash({
          chain_key: chainKey,
          seq,
          prev_hash: prevHash,
          id,
          request_id: this.#requestId,
          agent_run_id: null,
          tenant: tenantId,
          occurred_at_unix: occurredAt,
          audit_json: auditJson,
        });

        await this.#db
          .prepare(
            `INSERT INTO ${AUDIT_TABLE}
               (id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json,
                chain_key, seq, prev_hash, row_hash)
             VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind(
            id,
            this.#requestId,
            tenantId,
            occurredAt,
            auditJson,
            chainKey,
            seq,
            prevHash,
            rowHash,
          )
          .run();
        return;
      } catch (error) {
        // A UNIQUE violation on `(chain_key, seq)` is the EXPECTED outcome of a
        // race and is retried; anything else (and a race that keeps losing) is
        // reported on the last attempt. The two are not distinguished by
        // message on purpose — D1 wraps SQLite's text and matching on it is how
        // an error handler silently stops handling anything.
        if (attempt === AUDIT_APPEND_ATTEMPTS) {
          console.warn(
            `control-plane: audit append failed for ${action} ${collection}/${String(record.id)}`,
            error,
          );
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Schema notes (reported rather than invented — see the slice report)
// ---------------------------------------------------------------------------
//
// PORT-TODO(P: inventory-edge-control §9.3) — KEPT, sharpened: two gaps between
// this port and `sql/d1-ts/control/0001_init_control.sql`.
//
// **Why these stay open rather than being fixed here:** both are DDL, and
// `sql/d1-ts/` is the migrations slice's, not this app's — `wrangler.toml`
// points `migrations_dir` at it and `vitest.config.ts` reads the same directory,
// so a column added here without a migration would make the tests and the
// deployment disagree about the schema, which is the exact failure the shared
// directory exists to prevent. Both are also PERFORMANCE/ergonomics, not
// correctness: every statement above is correct against the schema as shipped.
//
// (2) has since been closed for every family that was actually blocking
// something, and the ANSWER was the second of the two options it named — the
// minting routes write both, rather than the store gaining an overflow column.
// Note that this deliberately did NOT put the projections in this store: for
// the per-tenant families the typed rows are in a DIFFERENT database from the
// document, so they cannot share a `batch()` at all, and the ordering that
// makes each pair safe is a route-level decision that differs per family.
//
// What is projected today, and by whom:
//
//   * `projects`, `workspaces` (tenant) — `routes/tenant_hierarchy.ts` through
//     `store/tenancy.ts`, plus `@ferrogate/storage`'s reference-guarded deletes.
//   * `plans`, `tenants`, `quota_policies` (control) — `store/quota_registry.ts`,
//     via the `CollectionSpec.project` hook on `plans`/`tenant-accounts` and
//     explicit calls in the `quota_policy` overrides. These are the three the
//     gateway's `d1QuotaPolicySource` reads on the admission path of EVERY
//     authenticated request; while they were unwritten, every operator-configured
//     rpm/tpm/budget/allowlist resolved to no limit at all.
//   * `api_key_directory` (control) + `api_keys` (tenant) — `store/virtual_keys.ts`,
//     from every leg of `routes/admin_virtual_key.ts`. These are the two hops
//     every native-credential authenticator in the repo makes, so while they were
//     unwritten a minted virtual key answered `401` everywhere and `revoke` was
//     a no-op outside the admin console. The SECRET question this note used to
//     defer is answered the way `store/worker_registry.ts` answered it: the
//     plaintext is returned exactly once (create and rotate) and only the
//     `sha256:`-tagged hash is ever stored, so the projection needs no access to
//     it — it reads `key_hash`/`key_prefix`/`last4` off the document.
//
//  1. `control_plane_resources` has no `tenant_id` column. Tenant isolation
//     therefore runs through `json_extract(document_json, '$.tenant_id')`,
//     which is CORRECT but unindexable as written. A generated column
//     (`tenant_id TEXT GENERATED ALWAYS AS (json_extract(document_json,
//     '$.tenant_id')) VIRTUAL`) plus an index on `(resource_kind, tenant_id)`
//     would make the predicate index-backed without changing a single
//     statement above. The Rust schema did not need it because its D1 topology
//     isolated tenants PHYSICALLY (one database per tenant); this Worker holds
//     one control database, so the fence is logical.
//  2. The REMAINING typed tables are still not written: `gateway_providers`,
//     `gateway_models`, `site_domains` (control) and `wallets` (tenant). The
//     pattern is settled (see above) and the rest is mechanical rather than
//     undecided, but each remaining one is load-bearing for a DIFFERENT slice
//     and is reported here rather than guessed: the gateway's model resolver
//     reads `gateway_providers`/`gateway_models` and owns what a "deployed
//     model" means, `site_domains` is verified by `routes/site_domain.ts`'s
//     rate-limited DNS challenge (whose CAS lives in the document today), and
//     `wallets` is money, whose ledger/balance pair `routes/wallets.ts` already
//     writes through `store.atomic()` and must not gain a second, unguarded
//     writer.
