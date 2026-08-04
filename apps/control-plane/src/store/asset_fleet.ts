/**
 * The ASSET FLEET reader (#743): `stored_assets` across tenant databases, for
 * the operator surface in `../routes/admin_asset.ts`.
 *
 * ## Why this file exists at all
 *
 * `stored_assets` lives in the TENANT migration (`sql/d1-ts/tenant/`), not the
 * control one, because a tenant's artifacts are tenant data. Every existing
 * read of it is therefore tenant-scoped by construction — the gateway resolves
 * the caller's tenant from the credential and makes exactly one routed call —
 * and there was no way for an operator to see the fleet. That is fine right up
 * until a version is WITHHELD: `pending_scan` and `quarantined` rows are
 * excluded from every read path by `AssetService.#resolveArtifact`
 * (`isDownloadable`), so the platform holds bytes nobody can review and nobody
 * can release. This module is the operator's read of those rows.
 *
 * ## What it is NOT
 *
 * **It is not a second artifact read path.** It answers ROWS, and the row
 * projection ({@link fleetAssetRow}) deliberately omits `storage_uri` — the R2
 * object key. Listing what a tenant has published and being able to fetch it
 * are two different permissions, and this surface only ever grants the first;
 * a key is a locator, and a locator handed to an operator surface is the first
 * half of an exfiltration path that the withholding in `#resolveArtifact` was
 * built to close. `content_hash` IS carried, because a digest identifies bytes
 * you already have rather than telling you where to get them.
 *
 * **It does not read around the withholding.** The release action
 * ({@link applyAssetReview}) moves `visibility`, which is the SAME column
 * `#resolveArtifact` filters on — so a released version becomes servable
 * through the one enforcement point rather than through a bypass beside it.
 * #737 and #738 both faced this temptation (serve a bundle without going
 * through the registry) and both resisted; so does this.
 *
 * ## The fan-out, and its bound
 *
 * A fleet-wide read is O(tenants) round trips. `TenantDatabaseRouter`'s own
 * docblock says that fan-out "belongs on admin paths only — never on the
 * inference hot path", which is exactly where this is; but "admin path" is not
 * "unbounded", so {@link FLEET_FANOUT_MAX_TENANTS} refuses a fan-out wider
 * than the cap and tells the caller to name a tenant. Truncating silently
 * would be the worse answer: an inventory that is quietly partial is one an
 * operator will read as complete.
 *
 * ## One unreachable tenant does not fail the fleet
 *
 * A tenant registered with a `binding_name` this deployment cannot resolve is a
 * misconfiguration of THAT tenant. On a single-tenant request it is a 503 (the
 * request was entirely about that tenant, so there is no partial answer to
 * give); on a fan-out the readable tenants are answered and the unreadable ones
 * are NAMED in `unreadable_tenants`, which is always present — an absent field
 * would be indistinguishable from "nothing was missed". Failing the whole
 * inventory because one tenant is misconfigured would take the abuse-response
 * surface offline at exactly the moment it is needed.
 */
import { StorageError, type TenantDatabaseRouter } from "@ferrogate/storage";
import { HttpError } from "../middleware/errors.js";

/** The tenant-database table this module reads. */
export const STORED_ASSET_TABLE = "stored_assets";

/** Rust/gateway `AssetVisibility` — the trust-screening state (#366). */
export const ASSET_VISIBILITIES = ["visible", "pending_scan", "quarantined"] as const;
export type AssetVisibility = (typeof ASSET_VISIBILITIES)[number];

/**
 * The two states `isDownloadable` refuses, i.e. the review queue.
 *
 * Spelled as the complement of `visible` rather than as a hand-listed pair so a
 * future third withheld state joins the queue automatically instead of silently
 * disappearing from it.
 */
export const WITHHELD_VISIBILITIES: readonly AssetVisibility[] = ASSET_VISIBILITIES.filter(
  (visibility) => visibility !== "visible",
);

/**
 * Widest fan-out a single fleet read will perform.
 *
 * Not a tuning knob dressed as a constant: each tenant is a separate D1
 * round trip, and a Worker request has a wall-clock budget. Past the cap the
 * request is REFUSED with an instruction (`?tenant_id=`), never truncated.
 */
export const FLEET_FANOUT_MAX_TENANTS = 50;

/** One inventory row, as the admin surface renders it. */
export interface FleetAssetRow {
  readonly object: string;
  readonly id: string;
  readonly tenant_id: string;
  readonly project_id: string | null;
  readonly asset_type: string;
  readonly name: string;
  readonly version: string;
  readonly variant: string;
  readonly content_type: string;
  readonly content_hash: string;
  readonly size_bytes: number;
  readonly visibility: AssetVisibility;
  readonly yanked: boolean;
  readonly downloadable: boolean;
  readonly created_at_unix: number;
  readonly updated_at_unix: number;
}

/** What one fleet read returned, and what it could not reach. */
export interface FleetAssetPage {
  readonly rows: readonly FleetAssetRow[];
  readonly unreadableTenants: readonly string[];
}

/** Filters the inventory understands. `visibility` is already validated. */
export interface FleetAssetFilter {
  readonly assetType?: string | undefined;
  readonly name?: string | undefined;
  readonly visibilities?: readonly AssetVisibility[] | undefined;
}

/** The raw column set. `storage_uri` is deliberately absent — see the header. */
interface StoredAssetRow {
  readonly id: string;
  readonly tenant_id: string;
  readonly project_id: string | null;
  readonly asset_type: string;
  readonly name: string;
  readonly version: string;
  readonly variant: string;
  readonly content_type: string;
  readonly content_hash: string;
  readonly size_bytes: number;
  readonly visibility: string;
  readonly yanked: number;
  readonly created_at_unix: number;
  readonly updated_at_unix: number;
}

/**
 * The SELECT list, exported so a test pins the columns rather than restating
 * them. `storage_uri` is not here and must never be: this constant IS the
 * "metadata, not content" decision, in one place where a diff shows it.
 */
export const FLEET_ASSET_COLUMNS =
  "id, tenant_id, project_id, asset_type, name, version, variant, content_type, " +
  "content_hash, size_bytes, visibility, yanked, created_at_unix, updated_at_unix";

/** An unparseable visibility is never a servable one — fail closed. */
function visibilityOf(value: string): AssetVisibility {
  return (ASSET_VISIBILITIES as readonly string[]).includes(value)
    ? (value as AssetVisibility)
    : "quarantined";
}

/** Row → the wire projection. `object` distinguishes inventory from queue. */
export function fleetAssetRow(row: StoredAssetRow, object: string): FleetAssetRow {
  const visibility = visibilityOf(row.visibility);
  return {
    object,
    id: row.id,
    tenant_id: row.tenant_id,
    project_id: row.project_id,
    asset_type: row.asset_type,
    name: row.name,
    version: row.version,
    variant: row.variant,
    content_type: row.content_type,
    content_hash: row.content_hash,
    size_bytes: row.size_bytes,
    visibility,
    yanked: row.yanked === 1,
    // Stated rather than left to the reader: `visible` is the ONLY downloadable
    // state, and an operator triaging a queue should not have to know that.
    downloadable: visibility === "visible",
    created_at_unix: row.created_at_unix,
    updated_at_unix: row.updated_at_unix,
  };
}

/**
 * Resolve one tenant's database handle, or `null` when it has none.
 *
 * Same two-way split as `./tenancy.ts::tenantDatabaseFor`, and for the same
 * reason: "no registry row" is a deployment that never onboarded this tenant
 * (there is no `stored_assets` table, so "no assets" is the whole truth), while
 * "registered but unroutable" is an operator asking for isolation the
 * deployment cannot deliver. The two are NOT the same answer and collapsing
 * them would turn a fixable misconfiguration into silently missing rows.
 */
async function databaseFor(
  router: TenantDatabaseRouter,
  tenantId: string,
): Promise<D1Database | null> {
  try {
    return (await router.forTenant(tenantId)).db;
  } catch (error) {
    if (error instanceof StorageError && error.kind === "not_found") return null;
    throw new UnroutableTenantError(tenantId, error);
  }
}

/** A tenant with a registry row this deployment cannot resolve to a binding. */
export class UnroutableTenantError extends Error {
  readonly tenantId: string;
  constructor(tenantId: string, cause: unknown) {
    super(
      `tenant ${tenantId} has a provisioned database that this deployment cannot reach: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
    this.name = "UnroutableTenantError";
    this.tenantId = tenantId;
  }
}

/** {@link UnroutableTenantError} as the 503 a single-tenant request answers. */
export function unroutableTenantHttpError(error: UnroutableTenantError): HttpError {
  return new HttpError(503, "tenant_database_unavailable", error.message);
}

/**
 * Read `stored_assets` for one tenant.
 *
 * Every predicate is bound, and `tenant_id` is bound on every statement even
 * though a per-tenant database makes it redundant: under
 * `GATEWAY_TENANT_DB_ROUTING = "off"` one physical database holds many tenants
 * and the predicate IS the isolation, exactly as it is for `api_keys`. A read
 * that dropped it would be correct on the routed topology and a cross-tenant
 * leak on the shared one — the failure mode nobody notices in a test that runs
 * only the routed shape. That is not hypothetical now that `durable_object` is
 * the gateway default (#819): the two shapes coexist across a fleet.
 */
async function tenantAssets(
  db: D1Database,
  tenantId: string,
  filter: FleetAssetFilter,
  object: string,
): Promise<FleetAssetRow[]> {
  const predicates = ["tenant_id = ?"];
  const params: unknown[] = [tenantId];
  if (filter.assetType !== undefined) {
    predicates.push("asset_type = ?");
    params.push(filter.assetType);
  }
  if (filter.name !== undefined) {
    predicates.push("name = ?");
    params.push(filter.name);
  }
  const visibilities = filter.visibilities;
  if (visibilities !== undefined) {
    // An EMPTY set means "nothing matches", which `IN ()` cannot express in
    // SQLite. Returning early is the only reading that is not accidentally
    // "everything".
    if (visibilities.length === 0) return [];
    predicates.push(`visibility IN (${visibilities.map(() => "?").join(", ")})`);
    params.push(...visibilities);
  }

  const result = await db
    .prepare(
      `SELECT ${FLEET_ASSET_COLUMNS} FROM ${STORED_ASSET_TABLE}
        WHERE ${predicates.join(" AND ")}
        ORDER BY tenant_id ASC, asset_type ASC, name ASC, version ASC, variant ASC`,
    )
    .bind(...params)
    .all<StoredAssetRow>();
  return (result.results ?? []).map((row) => fleetAssetRow(row, object));
}

/**
 * Read the inventory for a resolved, ALREADY-AUTHORIZED set of tenants.
 *
 * This function does no authorization: `../routes/admin_asset.ts` decides the
 * tenant set and this reads it. That split is deliberate — the fence is one
 * function with one set of tests, not a predicate smeared through the SQL
 * builder where a new call site can forget it.
 */
export async function readFleetAssets(
  router: TenantDatabaseRouter,
  tenantIds: readonly string[],
  filter: FleetAssetFilter,
  object: string,
  options: { readonly failOnUnreachable: boolean },
): Promise<FleetAssetPage> {
  const rows: FleetAssetRow[] = [];
  const unreadable: string[] = [];
  for (const tenantId of tenantIds) {
    let db: D1Database | null;
    try {
      db = await databaseFor(router, tenantId);
    } catch (error) {
      if (error instanceof UnroutableTenantError && !options.failOnUnreachable) {
        unreadable.push(error.tenantId);
        continue;
      }
      if (error instanceof UnroutableTenantError) throw unroutableTenantHttpError(error);
      throw error;
    }
    if (db === null) continue;
    rows.push(...(await tenantAssets(db, tenantId, filter, object)));
  }
  // Sorted per tenant by SQL; sorted again across tenants so the fan-out order
  // is not the wire order (a page boundary that moved with registry order would
  // silently skip rows between two requests).
  rows.sort((left, right) => (fleetSortKey(left) < fleetSortKey(right) ? -1 : 1));
  return { rows, unreadableTenants: unreadable.sort() };
}

/**
 * The cross-tenant ordering key.
 *
 * The separator is the `"\0"` ESCAPE, never a literal NUL byte — a source file
 * containing one is classified as binary by `grep` and by `git diff`, so it
 * silently drops out of audits and out of pull-request diffs
 * (`apps/gateway/test/source-nul-bytes.test.ts` is the gate, and this line was
 * its third catch). It has to be NUL rather than a space or a colon because
 * every component is tenant-controllable: with a printable separator,
 * `("a b", "c")` and `("a", "b c")` produce the same key, and two distinct rows
 * that compare equal make the page boundary depend on which tenant answered
 * first.
 */
function fleetSortKey(row: FleetAssetRow): string {
  return [row.tenant_id, row.asset_type, row.name, row.version, row.variant, row.id].join("\0");
}

/**
 * The tenants a fan-out will visit, refused when it would be too wide.
 *
 * `provisionedTenants()` is the registry, so this is every tenant the
 * deployment has onboarded — including ones with no assets, which cost a round
 * trip each. Hence the cap.
 */
export async function fleetTenantIds(router: TenantDatabaseRouter): Promise<readonly string[]> {
  const tenants = await router.provisionedTenants();
  if (tenants.length > FLEET_FANOUT_MAX_TENANTS) {
    throw new HttpError(
      400,
      "asset_fleet_fanout_too_wide",
      `this deployment has ${tenants.length} provisioned tenants, more than the ${FLEET_FANOUT_MAX_TENANTS} a single fleet read fans out to; narrow the request with ?tenant_id=`,
    );
  }
  return [...tenants].sort();
}

// ---------------------------------------------------------------------------
// The review write
// ---------------------------------------------------------------------------

/** What the operator decided about a withheld version. */
export type AssetReviewDecision = "release" | "reject";

/** The visibility a decision moves the row to. */
export function reviewTargetVisibility(decision: AssetReviewDecision): AssetVisibility {
  // `reject` HARDENS rather than deletes: a rejected `pending_scan` row becomes
  // `quarantined`, which is the state that says a human looked. Leaving it
  // `pending_scan` would make it indistinguishable from "not yet screened" and
  // it would be re-queued forever.
  return decision === "release" ? "visible" : "quarantined";
}

/** The row a review acts on, as read before the decision is recorded. */
export interface ReviewableAsset {
  readonly row: FleetAssetRow;
}

export type AssetReviewOutcome =
  | { readonly kind: "applied"; readonly to: AssetVisibility }
  /** Someone moved the row between the read and the write. */
  | { readonly kind: "conflict" };

/**
 * Apply a decision to exactly the state the operator reviewed.
 *
 * The guard is `AND visibility = <from>`, not `AND visibility IN (withheld)`,
 * and that is the whole point: a compare-and-set on the reviewed state means a
 * concurrent screener verdict (or a second operator) cannot have its decision
 * silently overwritten by this one. An empty `RETURNING` set is the refusal —
 * same shape every guarded write in `apps/gateway/src/assets/d1.ts` uses, for
 * the same reason (D1 is SQLite: no `SELECT … FOR UPDATE`, and a Worker cannot
 * hold a transaction across an `await`, so the invariant has to live INSIDE the
 * writing statement).
 *
 * `visibility` is also the ONLY column touched. A review does not delete the
 * row and does not touch the bytes — a takedown is a different verb with a
 * different blast radius, and conflating the two would make "reject" a
 * destructive default.
 */
export async function applyAssetReview(
  db: D1Database,
  tenantId: string,
  assetId: string,
  from: AssetVisibility,
  to: AssetVisibility,
  nowUnix: number,
): Promise<AssetReviewOutcome> {
  const result = await db
    .prepare(
      `UPDATE ${STORED_ASSET_TABLE}
          SET visibility = ?, updated_at_unix = ?
        WHERE id = ? AND tenant_id = ? AND visibility = ?
        RETURNING id`,
    )
    .bind(to, nowUnix, assetId, tenantId, from)
    .all<{ id: string }>();
  return (result.results ?? []).length === 1 ? { kind: "applied", to } : { kind: "conflict" };
}

/** One asset row, resolved for a review. `null` when the tenant has no such id. */
export async function readAssetForReview(
  router: TenantDatabaseRouter,
  tenantId: string,
  assetId: string,
): Promise<{ readonly db: D1Database; readonly row: FleetAssetRow } | null> {
  let db: D1Database | null;
  try {
    db = await databaseFor(router, tenantId);
  } catch (error) {
    if (error instanceof UnroutableTenantError) throw unroutableTenantHttpError(error);
    throw error;
  }
  if (db === null) return null;
  const row = await db
    .prepare(
      `SELECT ${FLEET_ASSET_COLUMNS} FROM ${STORED_ASSET_TABLE} WHERE id = ? AND tenant_id = ?`,
    )
    .bind(assetId, tenantId)
    .first<StoredAssetRow>();
  return row === null ? null : { db, row: fleetAssetRow(row, "quarantined_asset") };
}

// ---------------------------------------------------------------------------
// The force-delete  (#743, done-when bullet 3)
// ---------------------------------------------------------------------------

/** `asset_channels` — the mutable pointers a delete can strand (#367). */
export const ASSET_CHANNEL_TABLE = "asset_channels";
/** `asset_bundle_files` — the per-file object index a bundle owns (#736). */
export const ASSET_BUNDLE_FILE_TABLE = "asset_bundle_files";

/**
 * What still points at a version, and whether deleting THIS row would strand it.
 *
 * The two fields answer two different operator questions and collapsing them
 * would lose the one that matters. `channels` is "what is serving these bytes
 * right now" — a `static_site` bundle reaches the public internet through a
 * CHANNEL (`/sites/{slug}` binds a slug to a channel, #737, and a verified
 * custom domain resolves to a site, #738), so a non-empty list means a live
 * surface is involved. `siblingSurvives` is whether another non-yanked variant
 * of the same logical version remains after the delete, in which case those
 * channels keep resolving and nothing goes dark.
 *
 * The pair is exactly the predicate `apps/gateway`'s `ASSET_VARIANT_DELETE_SQL`
 * puts INSIDE its DELETE ("another live variant survives OR no channel points
 * here"), computed here as two reads because this surface has to REPORT what it
 * found before it acts: an operator must be told which channels a force-delete
 * is about to take down, and a guard hidden inside a statement can only refuse,
 * never explain.
 */
export interface AssetVersionReferences {
  /** Channel names pointing at this logical version, sorted. */
  readonly channels: readonly string[];
  /** Another non-yanked variant of the same version survives this delete. */
  readonly siblingSurvives: boolean;
}

/** Read {@link AssetVersionReferences} for one row. */
export async function assetVersionReferences(
  db: D1Database,
  tenantId: string,
  row: FleetAssetRow,
): Promise<AssetVersionReferences> {
  const channels = await db
    .prepare(
      `SELECT channel FROM ${ASSET_CHANNEL_TABLE}
        WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ?
        ORDER BY channel ASC`,
    )
    .bind(tenantId, row.asset_type, row.name, row.version)
    .all<{ channel: string }>();
  const sibling = await db
    .prepare(
      `SELECT id FROM ${STORED_ASSET_TABLE}
        WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ?
          AND id <> ? AND yanked = 0
        LIMIT 1`,
    )
    .bind(tenantId, row.asset_type, row.name, row.version, row.id)
    .first<{ id: string }>();
  return {
    channels: (channels.results ?? []).map((entry) => entry.channel),
    siblingSurvives: sibling !== null,
  };
}

/** Deleting this row would leave at least one channel pointing at nothing. */
export function wouldStrandChannel(references: AssetVersionReferences): boolean {
  return references.channels.length > 0 && !references.siblingSurvives;
}

export type AssetVersionDeletion =
  | {
      readonly kind: "deleted";
      /** R2 keys this delete orphaned: the archive plus every bundle file. */
      readonly objectKeys: readonly string[];
      /** Channel rows this delete REMOVED, sorted. Empty unless it stranded. */
      readonly detachedChannels: readonly string[];
    }
  /** The row moved between the read and the delete — same shape as a review. */
  | { readonly kind: "conflict" };

/**
 * Delete ONE asset version row, its bundle-file index, and (when asked) the
 * channels it would otherwise strand.
 *
 * ## The order, and what a crash in the middle leaves
 *
 * `stored_assets` goes FIRST, alone, guarded on the exact state that was read.
 * Everything else follows. D1 is SQLite and a Worker cannot hold a transaction
 * across an `await`, so the ORDER is the contract, exactly as it is for the
 * review:
 *
 * | order | a crash in between leaves |
 * |---|---|
 * | version row, then the rest (this one) | an artifact that resolves nowhere, plus reclaimable leftovers — the takedown TOOK EFFECT |
 * | the rest, then the version row | a live version whose files were deleted underneath it: a 500 on the serve path instead of a clean 404 |
 *
 * The object keys are RETURNED rather than deleted here: the bucket handle is
 * the caller's ({@link ../ports.js#AssetObjectReclaimer}, a delete-only port)
 * and the bytes must not go before the rows that name them commit. An orphaned
 * R2 object is reclaimable; bytes deleted under a live row are not.
 *
 * ## The guard
 *
 * `AND visibility = ? AND updated_at_unix = ?` is a compare-and-set on the
 * state the operator was shown — the same discipline as
 * {@link applyAssetReview}, and for the same reason: a screener verdict or a
 * second operator that landed between the read and this write must make the
 * delete FAIL rather than silently destroy something nobody looked at.
 */
export async function deleteAssetVersion(
  db: D1Database,
  tenantId: string,
  row: FleetAssetRow,
  options: { readonly detachChannels: boolean },
): Promise<AssetVersionDeletion> {
  const deleted = await db
    .prepare(
      `DELETE FROM ${STORED_ASSET_TABLE}
        WHERE id = ? AND tenant_id = ? AND visibility = ? AND updated_at_unix = ?
        RETURNING storage_uri`,
    )
    .bind(row.id, tenantId, row.visibility, row.updated_at_unix)
    .all<{ storage_uri: string | null }>();
  const removed = deleted.results ?? [];
  if (removed.length !== 1) return { kind: "conflict" };

  const files = await db
    .prepare(
      `DELETE FROM ${ASSET_BUNDLE_FILE_TABLE}
        WHERE asset_id = ? AND tenant_id = ?
        RETURNING storage_uri`,
    )
    .bind(row.id, tenantId)
    .all<{ storage_uri: string | null }>();

  let detached: readonly string[] = [];
  if (options.detachChannels) {
    const channels = await db
      .prepare(
        `DELETE FROM ${ASSET_CHANNEL_TABLE}
          WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ?
          RETURNING channel`,
      )
      .bind(tenantId, row.asset_type, row.name, row.version)
      .all<{ channel: string }>();
    detached = (channels.results ?? []).map((entry) => entry.channel).sort();
  }

  const objectKeys = [
    ...removed.map((entry) => entry.storage_uri),
    ...(files.results ?? []).map((entry) => entry.storage_uri),
  ].filter((key): key is string => typeof key === "string" && key !== "");
  return { kind: "deleted", objectKeys, detachedChannels: detached };
}
