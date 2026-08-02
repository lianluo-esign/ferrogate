/**
 * Contract group `admin_asset` (3 operations) — the asset FLEET surface (#743).
 *
 * ```
 *   GET   /admin/v1/assets                        fleet inventory
 *   GET   /admin/v1/assets/quarantine             the review queue
 *   POST  /admin/v1/assets/quarantine/{asset_id}  release / reject, with a reason
 * ```
 *
 * Once #736 gave a static site a versioned multi-file bundle, #737 served it at
 * `/sites/*` and #738 pointed customer domains at it, "what a tenant has
 * published" became a product surface with an abuse profile — and there was no
 * operator view of it at all. A version the #366 screener withholds
 * (`pending_scan` / `quarantined`) sat in the tenant database, correctly
 * excluded from every read path by `AssetService.#resolveArtifact`, with nobody
 * able to look at it and nobody able to release it.
 *
 * Five decisions are the substance of this module. Each is a security property,
 * not a style choice.
 *
 * ## 0. Reading is one authority; DECIDING is another
 *
 * The review verb has its own fence ({@link authorizeFleetWrite}) and does not
 * borrow the read's ({@link authorizeFleetRead}). The read's tenant branch
 * admits a tenant credential over that tenant's own rows — correct for a read,
 * and an ESCALATION for a decision, because `visibility` is the #366 screener's
 * verdict on that tenant's own content. Authorising the write with the read's
 * fence let any tenant-scoped `admin.write` key move its own `quarantined`
 * version to `visible`: the reviewed party overturning the review, and the
 * exact promotion `apps/gateway/src/assets/d1.ts` refuses on the data plane by
 * guarding its CAS with `AND visibility = 'pending_scan'`.
 *
 * So: a tenant may SEE that its version is withheld (that read is what tells it
 * to fix the artifact) and there is NO credential a tenant can hold that moves
 * one. Release and reject are operator verbs.
 *
 * ## 1. Seeing another tenant's assets is a DISTINCT grant
 *
 * {@link ASSET_FLEET_SCOPE} — `admin.assets.fleet` — must be held EXACTLY. Not
 * `hasScope`: the wildcard does not satisfy it, and neither does being a
 * declared platform operator. That asymmetry is the whole point. Every operator
 * key this repo mints is `["*"]` (`src/adapters.ts`: "an operator-authored key
 * with NO scopes listed has always meant all access"), so if the cross-tenant
 * fleet view were reachable through `hasScope` it would be reachable by every
 * credential that can already read the admin API — i.e. it would be a SIDE
 * EFFECT of the admin scope rather than a decision somebody made. A surface
 * that lists what every tenant is hosting is the most dangerous read in this
 * repo; the deployment has to say the word.
 *
 * The consequence is deliberate and is not a bug: on a deployment that has not
 * added the scope, `GET /admin/v1/assets` answers **403 for a platform
 * operator** and 200 for a tenant reading its own assets. The refusal names the
 * scope so the next action is to mint it rather than to guess.
 *
 * A platform operator has no tenant of its own, so EVERY read it makes here is
 * cross-tenant — which is why the grant is required even when it names a single
 * tenant with `?tenant_id=`. A tenant credential is confined to its own tenant
 * and the grant cannot widen it: naming another tenant is a 403, never a
 * silently-coerced 200 over its own rows (a caller told "200" over a filtered
 * result set cannot tell it was denied).
 *
 * ## 2. Metadata is not content
 *
 * The inventory answers rows and never bytes, never a signed URL, and never
 * `storage_uri` — the R2 object key (`src/store/asset_fleet.ts` omits it from
 * the SELECT list, which is where the decision is visible in a diff). Reading
 * an inventory and reading an artifact are different permissions with different
 * blast radii; an endpoint that returned or linked to bytes would be the larger
 * one wearing the smaller one's name. The digest (`content_hash`) IS returned:
 * it identifies bytes an investigator already holds rather than telling anyone
 * where to fetch them.
 *
 * ## 3. A release is recorded BEFORE it takes effect
 *
 * An unattributed quarantine release is worse than no surface at all, so the
 * decision record — actor, scope, reason, the exact state reviewed — is written
 * (and hash-chained into `audit_events` by the store) before the row moves. The
 * two writes are in two different databases and D1 has no transaction spanning
 * them, so the ORDER is the contract:
 *
 * | order | a crash in between leaves |
 * |---|---|
 * | record, then apply (this one) | an attributed decision that did not take effect — visible, retryable, and the asset stays withheld |
 * | apply, then record | a released artifact nobody can attribute — exactly the failure this surface exists to prevent |
 *
 * The record carries `applied` for that reason: it is written `false` and
 * merged to `true` only after the guarded UPDATE returns a row, so "recorded"
 * never silently reads as "done".
 *
 * ## 4. The state moves through the existing enforcement, not around it
 *
 * `release` sets `visibility = 'visible'`, which is the SAME column
 * `#resolveArtifact` filters on — so a released version becomes servable
 * through the one gate every read path already goes through. Nothing here adds
 * a second path that reads around the withholding, and nothing here can serve a
 * withheld artifact.
 *
 * ## What this slice does NOT do, stated so it is not mistaken for parity
 *
 * The issue's third bullet also asks for per-tenant quota read/adjust and a
 * force-delete of a specific version.
 *
 *  - **Quota is already shipped.** `asset_storage_quota_bytes`,
 *    `monthly_egress_bytes_budget` and `download_rpm_limit` are per-scope
 *    columns written by `PUT /admin/v1/quota-policies/tenant/{tenant_id}` and
 *    projected by `src/store/quota_registry.ts`. A second asset-shaped quota
 *    endpoint would be a second source of truth for the same three numbers.
 *  - **Force-delete is deferred, deliberately.** Deleting a version means
 *    deleting the R2 objects AND the `asset_bundle_files` index that names them
 *    (#736), and that reclamation lives in `apps/gateway`'s `AssetService`.
 *    A metadata-only delete from this Worker would answer `deleted: true` and
 *    leave the bytes in the bucket — a takedown that did not take anything
 *    down, which is a worse answer than not offering the verb.
 */
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { AuthContext, CallerScope, StoreRecord } from "../ports.js";
import { adminItem, adminList, adminListPaginated, parseListQuery } from "../responses.js";
import {
  ASSET_VISIBILITIES,
  type AssetReviewDecision,
  type AssetVisibility,
  WITHHELD_VISIBILITIES,
  applyAssetReview,
  fleetTenantIds,
  readAssetForReview,
  readFleetAssets,
  reviewTargetVisibility,
} from "../store/asset_fleet.js";
import {
  type GroupModule,
  type Handler,
  crudGroup,
  depsOf,
  json,
  pathParam,
  readJson,
  scopeOf,
} from "./resource.js";

/**
 * The DISTINCT grant that admits a cross-tenant asset read.
 *
 * It is checked with exact membership (`scopes.includes`), never with
 * `hasScope` — see decision 1 in the module header. The name is namespaced
 * under `admin.` so `isPrivilegedScope` treats it like the other admin scopes
 * (an empty scope set can never imply it).
 */
export const ASSET_FLEET_SCOPE = "admin.assets.fleet";

/** Store collection the review decisions live in. */
export const ASSET_REVIEW_COLLECTION = "asset-reviews";

/** Response `object` for an inventory row and for a queue row. */
const FLEET_OBJECT = "fleet_asset";
const QUARANTINE_OBJECT = "quarantined_asset";

const visibilitySchema = z.enum(ASSET_VISIBILITIES);

export const assetReviewSchema = z.object({
  /**
   * The tenant that owns the version. REQUIRED — the only caller this verb
   * admits is a platform operator, whose credential names no tenant, so there
   * is nothing to default it from (see decision 0 in the module header).
   *
   * A write names the database it acts on rather than searching for it: an
   * id-only fan-out across every tenant database would make one operator
   * mistake into an O(tenants) write path, and the id alone cannot be
   * authorized before the row is found. It stays `optional()` in the SCHEMA so
   * the refusal is the authorization one (`403`) rather than a body-shape
   * `400` that would tell an unauthorized caller which field to add.
   */
  tenant_id: z.string().trim().min(1).optional(),
  decision: z.enum(["release", "reject"]),
  /**
   * WHY. Required, non-empty, and stored on the decision record the audit row
   * names. "Who" is on the audit row; without "why" a release is a fact with no
   * justification, which is the half that makes a trail reviewable.
   */
  reason: z.string().trim().min(1).max(2_000),
});

/**
 * The tenants this caller may READ, or the refusal.
 *
 * ONE function, called by both read operations, so there is no second place to
 * forget the fence. `null` means "fan out over every provisioned tenant".
 *
 * It is deliberately NOT the fence for a write — see
 * {@link authorizeFleetWrite}. Its tenant branch admits a tenant credential
 * over that tenant's own rows, which is right for a read and is an escalation
 * for a decision.
 */
export function authorizeFleetRead(
  scope: CallerScope,
  auth: AuthContext,
  requestedTenantId: string | null,
): { readonly kind: "tenant"; readonly tenantId: string } | { readonly kind: "fleet" } {
  if (scope.kind === "tenant") {
    if (requestedTenantId !== null && requestedTenantId !== scope.tenantId) {
      throw new HttpError(
        403,
        "cross_tenant_asset_read_denied",
        `this credential is scoped to tenant ${scope.tenantId} and may not read assets of tenant ${requestedTenantId}`,
      );
    }
    return { kind: "tenant", tenantId: scope.tenantId };
  }
  // A platform operator owns no tenant, so every read it makes is cross-tenant
  // — including one that names a single tenant. EXACT membership: the wildcard
  // is not this grant.
  if (!auth.scopes.includes(ASSET_FLEET_SCOPE)) {
    throw new HttpError(
      403,
      "asset_fleet_scope_required",
      `reading assets across tenants requires the distinct ${ASSET_FLEET_SCOPE} scope; the admin wildcard does not grant it`,
    );
  }
  if (requestedTenantId !== null) return { kind: "tenant", tenantId: requestedTenantId };
  return { kind: "fleet" };
}

/**
 * The tenant a caller may WRITE a decision for, or the refusal.
 *
 * A SEPARATE function from {@link authorizeFleetRead}, and the separation is
 * the security property rather than a tidiness one. Read authority and write
 * authority are not the same authority:
 *
 *  - **A tenant credential is refused outright.** `visibility` is the #366
 *    screener's verdict on the tenant's OWN content, so letting the owning
 *    tenant move it is letting the reviewed party overturn the review. The
 *    data plane already refuses this — `apps/gateway/src/assets/d1.ts`'s
 *    promotion CAS is guarded `AND visibility = 'pending_scan'` so a tenant
 *    cannot promote its own quarantined version — and an admin surface that
 *    reused the READ fence would hand that same power back through a different
 *    door. A tenant may still SEE that its version is withheld (that is the
 *    read, and it is what tells the tenant to fix the artifact); it may not
 *    decide.
 *  - **A platform operator must hold {@link ASSET_FLEET_SCOPE} exactly**, for
 *    the same reason the read requires it: every write it makes is about
 *    somebody else's tenant.
 *
 * The consequence, stated so it is not mistaken for an oversight: on this
 * surface there is NO credential a tenant can hold that moves a withheld
 * version. Release and takedown are operator verbs, full stop.
 */
export function authorizeFleetWrite(
  scope: CallerScope,
  auth: AuthContext,
  requestedTenantId: string | null,
  verb: FleetWriteVerb,
): { readonly tenantId: string } {
  if (scope.kind === "tenant") {
    throw new HttpError(
      403,
      "asset_fleet_write_operator_only",
      `${verb.action} is an operator decision: this credential is scoped to tenant ${scope.tenantId}, which may read its own withheld versions but may not ${verb.imperative} them`,
    );
  }
  if (!auth.scopes.includes(ASSET_FLEET_SCOPE)) {
    throw new HttpError(
      403,
      "asset_fleet_scope_required",
      `${verb.action} requires the distinct ${ASSET_FLEET_SCOPE} scope; the admin wildcard does not grant it`,
    );
  }
  if (requestedTenantId === null) {
    // A write NAMES the database it acts on rather than searching for it: an
    // id-only fan-out across every tenant database would make one operator
    // mistake into an O(tenants) write path.
    throw new HttpError(
      400,
      verb.missingTenantCode,
      `tenant_id is required: ${verb.action} names the tenant whose asset it acts on`,
    );
  }
  return { tenantId: requestedTenantId };
}

/** How {@link authorizeFleetWrite} words its refusals for one verb. */
interface FleetWriteVerb {
  /** Noun phrase: "releasing or rejecting a withheld version". */
  readonly action: string;
  /** Verb phrase completing "may not …": "release or reject". */
  readonly imperative: string;
  /** The 400 code for a missing tenant — body-shaped or query-shaped. */
  readonly missingTenantCode: "invalid_request_body" | "invalid_request";
}

/** The review verb, as {@link authorizeFleetWrite} describes it. */
const REVIEW_VERB: FleetWriteVerb = {
  action: "reviewing a withheld asset version",
  imperative: "release or reject",
  missingTenantCode: "invalid_request_body",
};

/** `?visibility=` → the validated set, or the 400. */
function requestedVisibilities(
  raw: string | null,
  allowed: readonly AssetVisibility[],
): readonly AssetVisibility[] | undefined {
  if (raw === null) return undefined;
  const parsed = visibilitySchema.safeParse(raw);
  if (!parsed.success || !allowed.includes(parsed.data)) {
    throw new HttpError(
      400,
      "invalid_request",
      `visibility must be one of ${allowed.join("|")} (got ${JSON.stringify(raw)})`,
    );
  }
  return [parsed.data];
}

/** The shared read, parameterised by which visibilities the surface admits. */
function fleetListHandler(options: {
  readonly object: string;
  readonly allowed: readonly AssetVisibility[];
}): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const auth = c.get("auth") as AuthContext;
    const url = new URL(c.req.url);
    const query = parseListQuery(url, deps.listDefaultLimit, deps.listMaxLimit);
    const requestedTenant = url.searchParams.get("tenant_id");
    const target = authorizeFleetRead(
      scopeOf(c),
      auth,
      requestedTenant === null || requestedTenant.trim() === "" ? null : requestedTenant.trim(),
    );

    const explicit = requestedVisibilities(url.searchParams.get("visibility"), options.allowed);
    const tenantIds =
      target.kind === "tenant" ? [target.tenantId] : await fleetTenantIds(deps.tenantDatabases);

    const page = await readFleetAssets(
      deps.tenantDatabases,
      tenantIds,
      {
        assetType: url.searchParams.get("asset_type") ?? undefined,
        name: url.searchParams.get("name") ?? undefined,
        // No `?visibility=` on the queue still means "the withheld ones" —
        // `options.allowed` is the surface's own floor, never widened by the
        // absence of a filter.
        visibilities: explicit ?? options.allowed,
      },
      options.object,
      // A single-tenant request IS about that tenant, so an unreachable
      // database is its 503. A fan-out reports the gap instead of failing the
      // whole fleet — see `store/asset_fleet.ts`.
      { failOnUnreachable: target.kind === "tenant" },
    );

    const window = page.rows.slice(query.offset, query.offset + query.limit);
    const envelope = query.paginate
      ? adminListPaginated(window, page.rows.length, query.offset, query.limit)
      : adminList(page.rows);
    return json(c, 200, {
      ...envelope,
      // ALWAYS present, empty array included: an absent field would be
      // indistinguishable from "nothing was missed", and a partial inventory
      // read as complete is how an abuse response misses the abuse.
      unreadable_tenants: page.unreadableTenants,
    });
  };
}

/** `POST /admin/v1/assets/quarantine/{asset_id}` — the audited decision. */
const reviewHandler: Handler = async (c) => {
  const deps = depsOf(c);
  const scope = scopeOf(c);
  const auth = c.get("auth") as AuthContext;
  const assetId = pathParam(c, "asset_id");
  const body = await readJson(c, assetReviewSchema);

  // The WRITE fence, not the read one — see `authorizeFleetWrite`.
  const { tenantId } = authorizeFleetWrite(scope, auth, body.tenant_id ?? null, REVIEW_VERB);

  const resolved = await readAssetForReview(deps.tenantDatabases, tenantId, assetId);
  // Absent, or in a tenant this caller cannot see: the SAME 404 either way. A
  // 403 here would confirm the id exists somewhere on the platform.
  if (resolved === null) {
    throw new HttpError(404, "not_found", `asset ${assetId} not found for tenant ${tenantId}`);
  }
  const from = resolved.row.visibility;
  if (!WITHHELD_VISIBILITIES.includes(from)) {
    // The queue is what this surface reviews. Taking a LIVE version down is a
    // different verb with a different blast radius (and, done here, would be a
    // takedown wearing a review's audit shape).
    throw new HttpError(
      409,
      "asset_not_withheld",
      `asset ${assetId} is ${from} and is not in the quarantine queue; this surface reviews withheld versions only`,
    );
  }

  const decision = body.decision as AssetReviewDecision;
  const to = reviewTargetVisibility(decision);
  const now = Math.floor(Date.now() / 1000);

  // (1) RECORD FIRST — see decision 3 in the module header. `store.create`
  // appends the hash-chained `audit_events` row; because the record carries the
  // OWNING tenant, that row lands on the tenant's chain, so the tenant can see
  // that its asset was released and by whom.
  const record: StoreRecord = {
    id: `arv_${crypto.randomUUID()}`,
    tenant_id: tenantId,
    asset_id: assetId,
    asset_type: resolved.row.asset_type,
    name: resolved.row.name,
    version: resolved.row.version,
    variant: resolved.row.variant,
    decision,
    reason: body.reason,
    from_visibility: from,
    to_visibility: to,
    applied: false,
    actor_scope: scope.kind,
    actor_key_id: auth.subject,
    actor_tenant_id: scope.kind === "tenant" ? scope.tenantId : null,
    decided_at_unix: now,
  };
  const stored = await deps.store.create(ASSET_REVIEW_COLLECTION, scope, record);

  // (2) APPLY, guarded on exactly the state that was reviewed.
  const outcome = await applyAssetReview(resolved.db, tenantId, assetId, from, to, now);
  if (outcome.kind === "conflict") {
    // The decision stands in the trail, marked as not applied. Answering 200
    // would tell the operator a release happened that did not.
    await deps.store.merge(ASSET_REVIEW_COLLECTION, scope, String(stored.id), {
      applied: false,
      outcome: "conflict",
    });
    throw new HttpError(
      409,
      "asset_review_conflict",
      `asset ${assetId} left ${from} while it was being reviewed; re-read the queue and decide again`,
    );
  }

  const applied = await deps.store.merge(ASSET_REVIEW_COLLECTION, scope, String(stored.id), {
    applied: true,
    outcome: "applied",
  });
  return json(c, 200, adminItem("asset_review", applied ?? { ...stored, applied: true }));
};

export const adminAssetRoutes: GroupModule = crudGroup("admin_asset", [], {
  listFleetAssets: fleetListHandler({ object: FLEET_OBJECT, allowed: ASSET_VISIBILITIES }),
  listQuarantinedAssets: fleetListHandler({
    object: QUARANTINE_OBJECT,
    allowed: WITHHELD_VISIBILITIES,
  }),
  reviewQuarantinedAsset: reviewHandler,
});
