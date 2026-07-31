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
 * a storage detail. The lossless document is therefore canonical. Projecting it
 * INTO those tables (so the data plane's key lookup can read `api_keys`
 * directly) is a follow-up that needs a schema decision from the migrations
 * slice — see `PORT-TODO(inventory-edge-control §9.3)` below.
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
import {
  type CallerScope,
  type ControlPlaneStore,
  type ListPage,
  type ListQuery,
  StoreConflictError,
  type StoreRecord,
} from "../ports.js";
import { isUnfilteredQuery, pageOf } from "./query.js";

/** The generic control-plane document table (`sql/d1-ts/control/`). */
export const RESOURCE_TABLE = "control_plane_resources";
/** The durable admin-mutation evidence table (`sql/d1-ts/control/`). */
export const AUDIT_TABLE = "audit_events";

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
 * Insertion-order listing, deterministic across calls, matching the in-memory
 * store's `Map` iteration order. `created_at_unix` is second-granular, so
 * `rowid` is the tiebreak that makes two rows written in the same second come
 * back in the order they were written.
 */
const LIST_ORDER = "ORDER BY created_at_unix ASC, rowid ASC";

/**
 * THE tenant isolation guard.
 *
 * A platform operator gets no predicate (it sees every row); a tenant-scoped
 * caller gets one that admits only its own rows and un-attributed platform
 * rows. Every statement in this file — SELECT, UPDATE and DELETE alike —
 * appends it, so there is no "read by bare id" path to forget it on.
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
    // PORT-TODO(inventory-edge-control §9.3): this reads the collection's
    // tenant-visible rows into the isolate before filtering. That is the
    // admin/low-volume path Rust's own D1 backend documents, but the
    // high-cardinality collections (`request-logs`, `agent-run-events`) want
    // their own projection columns and a SQL predicate before they grow.
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

  async #load(collection: string, scope: CallerScope, id: string): Promise<LoadedRecord | null> {
    const tenant = tenantScopeSql(scope);
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

  async remove(collection: string, scope: CallerScope, id: string): Promise<boolean> {
    // Loaded first so the audit row can name the tenant the deleted row
    // actually belonged to (which, for a platform operator deleting a global
    // row, is not the caller's).
    const existing = await this.#load(collection, scope, id);
    const tenant = tenantScopeSql(scope);
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
    const tenant = tenantScopeSql(scope);
    for (let attempt = 0; attempt < UPDATE_ATTEMPTS; attempt += 1) {
      const existing = await this.#load(collection, scope, id);
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
   * Append the durable evidence row for an APPLIED mutation.
   *
   * A failure here is warned about and swallowed, matching the Rust backend's
   * documented `()`-returning evidence surfaces ("swallow-with-warn like the
   * Postgres backend"): the mutation has already landed, so answering the
   * operator with an error would report a failure for a change that happened —
   * a worse lie than a missing audit row.
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
    try {
      await this.#db
        .prepare(
          `INSERT INTO ${AUDIT_TABLE} (id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json)
           VALUES (?, ?, NULL, ?, ?, ?)`,
        )
        .bind(this.#newId(), this.#requestId, tenantId, this.#now(), auditJson)
        .run();
    } catch (error) {
      console.warn(
        `control-plane: audit append failed for ${action} ${collection}/${String(record.id)}`,
        error,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Schema notes (reported rather than invented — see the slice report)
// ---------------------------------------------------------------------------
//
// PORT-TODO(inventory-edge-control §9.3): two gaps between this port and
// `sql/d1-ts/control/0001_init_control.sql`, both of which want a decision from
// the migrations slice rather than a column invented here.
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
//  2. The typed tables (`tenants`, `api_key_directory`, `gateway_providers`,
//     `gateway_models`, `quota_policies`, `plans`, `site_domains` in the
//     control database; `projects`, `workspaces`, `api_keys`, `wallets` in the
//     tenant databases) are not written by this store, because none of them has
//     an overflow column for the open-ended admin document (see the file
//     header). The data plane's durable key lookup reads `api_key_directory` /
//     `api_keys` directly and the model resolver reads `gateway_providers` /
//     `gateway_models`, so either those tables gain a `document_json` overflow
//     column and this store projects into them in the same `batch()`, or the
//     minting routes write both. That is a schema decision, so it is reported,
//     not guessed.
