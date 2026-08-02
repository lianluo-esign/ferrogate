/**
 * The WRITE half of the per-tenant response-cache governance — issue #695.
 *
 * `apps/gateway/src/cache/governance.ts` reads `semantic_cache_policies` on the
 * request path of every cacheable AI call. This module is the only thing that
 * writes it, projected from the admin DOCUMENT that
 * `/admin/v1/semantic-cache-policies/**` stores in `control_plane_resources`.
 *
 * ## Same two-write shape as `./quota_registry.ts`, same ordering rule
 *
 * The document and the typed row are two statements in one database, written by
 * the store and by the route respectively, so they are not one `batch()`. The
 * ordering is chosen by what a crash in between leaves:
 *
 * | path | order | a crash in between leaves |
 * |---|---|---|
 * | create / replace | document, then row | a policy the operator can SEE and the gateway has not applied yet — the deployment's vars still govern, which is where it was one millisecond earlier. Healed idempotently by the next PUT. |
 * | invalidate | row FIRST, no document write | see below. |
 * | delete | document, then row | a governance row with no document: the tenant's settings keep applying and the operator cannot see them. For a limiter that is the safe direction; for a CACHE it is the safe direction too, because every governed value is either narrowing or neutral — the widening one (`enabled`) can only widen back to the deployment default, which is what deleting the row means anyway. |
 *
 * **Invalidation is the exception and it is deliberate.** `POST …/invalidate`
 * writes the ROW ONLY, and does not touch the document at all. A purge is not a
 * configuration change: it is an imperative act whose entire meaning is "the
 * bodies keyed under the old epoch must stop being served, now". Writing the
 * document first would put a window in which the operator has been told the
 * purge is recorded and the gateway is still serving the old bodies — the one
 * outcome a purge must never produce. The epoch lives only in the typed row for
 * the same reason; {@link readInvalidationEpoch} reads it back so a subsequent
 * PUT of the configuration cannot roll it backwards.
 *
 * ## The epoch is monotonic, and the bump is a SQL expression
 *
 * `invalidation_epoch = invalidation_epoch + 1` is evaluated by SQLite, not by
 * the Worker, so two concurrent purges cannot both read 3 and both write 4. A
 * read-modify-write in TypeScript would lose one of them, and a lost purge is
 * indistinguishable from a purge that never happened.
 */
import { HttpError } from "../middleware/errors.js";
import type { StoreRecord } from "../ports.js";

/** The typed table in `sql/d1-ts/control/0004_semantic_cache_policies.sql`. */
export const SEMANTIC_CACHE_POLICIES_TABLE = "semantic_cache_policies";

/** Scope kinds a governance row may be written for. Mirrors the gateway's. */
export const SEMANTIC_CACHE_SCOPE_KINDS = ["tenant"] as const;
export type SemanticCacheScopeKind = (typeof SEMANTIC_CACHE_SCOPE_KINDS)[number];

/**
 * A governance document decoded to the row's own vocabulary.
 *
 * `undefined` is the tri-state's third value and it means INHERIT: the column
 * is written NULL and the gateway falls back to the deployment var. It is NOT
 * the same as `false` or `0`, and conflating them is how "this tenant pinned one
 * field" would silently freeze every other field at whatever the schema
 * defaulted to.
 */
export interface SemanticCacheGovernanceRow {
  readonly enabled: boolean | undefined;
  readonly mode: "exact_match" | "semantic" | undefined;
  readonly similarityThreshold: number | undefined;
  readonly ttlSeconds: number | undefined;
  readonly scopedModels: readonly string[] | undefined;
}

function optionalBoolean(value: unknown, field: string): boolean | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === "boolean") return value;
  throw new HttpError(400, "invalid_request_body", `${field} must be a boolean`);
}

function optionalMode(value: unknown): "exact_match" | "semantic" | undefined {
  if (value === undefined || value === null) return undefined;
  if (value === "exact_match" || value === "semantic") return value;
  throw new HttpError(400, "invalid_request_body", 'mode must be "exact_match" or "semantic"');
}

function optionalThreshold(value: unknown): number | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value) || !(value > 0 && value <= 1)) {
    // The SAME `(0.0, 1.0]` interval `packages/config`'s `validate_cache` and
    // `apps/gateway/src/cache/config.ts` enforce on the var. Refusing here is
    // what stops an unusable value reaching the request path at all: the
    // gateway treats an out-of-range durable value as UNREADABLE and bypasses
    // the cache, so accepting it would silently disable a tenant's caching and
    // report 200.
    throw new HttpError(
      400,
      "invalid_request_body",
      "similarity_threshold must be a number within (0.0, 1.0]",
    );
  }
  return value;
}

function optionalPositiveInt(value: unknown, field: string): number | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new HttpError(400, "invalid_request_body", `${field} must be a positive integer`);
  }
  return value;
}

function optionalModelList(value: unknown): readonly string[] | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new HttpError(400, "invalid_request_body", "scoped_models must be an array of strings");
  }
  const names = (value as string[]).map((entry) => entry.trim()).filter((entry) => entry !== "");
  return names.length === 0 ? undefined : names;
}

/** Decode the stored admin document into the row shape. Throws 400 on garbage. */
export function storedSemanticCachePolicy(record: StoreRecord): SemanticCacheGovernanceRow {
  return {
    enabled: optionalBoolean(record.enabled, "enabled"),
    mode: optionalMode(record.mode),
    similarityThreshold: optionalThreshold(record.similarity_threshold),
    ttlSeconds: optionalPositiveInt(record.ttl_seconds, "ttl_seconds"),
    scopedModels: optionalModelList(record.scoped_models),
  };
}

/**
 * Write (or update) the row the gateway reads.
 *
 * `invalidation_epoch` is NOT in the `DO UPDATE SET` list. A configuration edit
 * must never move the purge counter — forward (a surprise cache flush the
 * operator did not ask for) or, far worse, backward (every body purged a moment
 * ago becomes addressable again, because the key is a function of the epoch).
 * The INSERT arm seeds it at 0 because a scope that has no row has nothing to
 * purge.
 */
export async function projectSemanticCachePolicy(
  db: D1Database,
  record: StoreRecord,
  scopeType: SemanticCacheScopeKind,
  scopeId: string,
  nowUnix: number,
  updatedBy: string | null,
): Promise<void> {
  const row = storedSemanticCachePolicy(record);
  await db
    .prepare(
      `INSERT INTO ${SEMANTIC_CACHE_POLICIES_TABLE} (
         scope_type, scope_id, enabled, mode, similarity_threshold, ttl_seconds,
         scoped_models, invalidation_epoch, updated_at_unix, updated_by, generation
       )
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 1)
       ON CONFLICT (scope_type, scope_id) DO UPDATE SET
         enabled = excluded.enabled,
         mode = excluded.mode,
         similarity_threshold = excluded.similarity_threshold,
         ttl_seconds = excluded.ttl_seconds,
         scoped_models = excluded.scoped_models,
         updated_at_unix = excluded.updated_at_unix,
         updated_by = excluded.updated_by,
         generation = ${SEMANTIC_CACHE_POLICIES_TABLE}.generation + 1`,
    )
    .bind(
      scopeType,
      scopeId,
      row.enabled === undefined ? null : row.enabled ? 1 : 0,
      row.mode ?? null,
      row.similarityThreshold ?? null,
      row.ttlSeconds ?? null,
      row.scopedModels === undefined ? null : JSON.stringify(row.scopedModels),
      nowUnix,
      updatedBy,
    )
    .run();
}

/**
 * Bump the purge counter, returning the epoch now in force.
 *
 * The `INSERT … ON CONFLICT DO UPDATE` arm exists because a tenant may purge
 * before ever writing a configuration: "throw away what you are holding for me"
 * is a complete request on its own, and requiring a policy document first would
 * make the emergency path depend on the non-emergency one.
 */
export async function bumpSemanticCacheEpoch(
  db: D1Database,
  scopeType: SemanticCacheScopeKind,
  scopeId: string,
  nowUnix: number,
  updatedBy: string | null,
): Promise<number> {
  const row = await db
    .prepare(
      `INSERT INTO ${SEMANTIC_CACHE_POLICIES_TABLE} (
         scope_type, scope_id, invalidation_epoch, updated_at_unix, updated_by, generation
       )
       VALUES (?, ?, 1, ?, ?, 1)
       ON CONFLICT (scope_type, scope_id) DO UPDATE SET
         invalidation_epoch = ${SEMANTIC_CACHE_POLICIES_TABLE}.invalidation_epoch + 1,
         updated_at_unix = excluded.updated_at_unix,
         updated_by = excluded.updated_by,
         generation = ${SEMANTIC_CACHE_POLICIES_TABLE}.generation + 1
       RETURNING invalidation_epoch`,
    )
    .bind(scopeType, scopeId, nowUnix, updatedBy)
    .first<{ invalidation_epoch: number }>();
  return Number(row?.invalidation_epoch ?? 0);
}

/** The epoch currently in force, or 0 when the scope has no row. */
export async function readInvalidationEpoch(
  db: D1Database,
  scopeType: SemanticCacheScopeKind,
  scopeId: string,
): Promise<number> {
  const row = await db
    .prepare(
      `SELECT invalidation_epoch FROM ${SEMANTIC_CACHE_POLICIES_TABLE} WHERE scope_type = ? AND scope_id = ?`,
    )
    .bind(scopeType, scopeId)
    .first<{ invalidation_epoch: number }>();
  return Number(row?.invalidation_epoch ?? 0);
}

/**
 * Drop the row.
 *
 * Deleting the governance is NOT the same as purging: the tenant falls back to
 * the deployment vars, and because the key material goes from the governed
 * string back to `"ungoverned"`, entries written under the governed policy stop
 * being addressable anyway. That is a side effect worth naming rather than a
 * design goal — an operator who wants a purge should call `…/invalidate`, which
 * says so and leaves the configuration intact.
 */
export async function deleteSemanticCachePolicyRow(
  db: D1Database,
  scopeType: SemanticCacheScopeKind,
  scopeId: string,
): Promise<void> {
  await db
    .prepare(`DELETE FROM ${SEMANTIC_CACHE_POLICIES_TABLE} WHERE scope_type = ? AND scope_id = ?`)
    .bind(scopeType, scopeId)
    .run();
}
