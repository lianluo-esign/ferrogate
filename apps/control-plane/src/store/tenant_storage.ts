/**
 * Provisioning a tenant's STORAGE at the moment the tenant is created (#820).
 *
 * ## What was missing
 *
 * `tenant_databases` is the fleet roster — `provisionedTenants()` reads it, and
 * `store/asset_fleet.ts` fans out over that list — and a Durable Object
 * namespace cannot be enumerated in production, so it is the ONLY roster there
 * is. Nothing in production wrote it. Every `registry.upsert(` in the tree was a
 * test. So a tenant created through the admin API or through console signup was
 * invisible to every fleet view, and had an empty model catalog. (This sentence
 * used to end "which is `400 model_not_found` on its first inference request".
 * It is not: nothing in `apps/<app>/src` reads the tenant catalog tables yet, and
 * the gateway resolves models from `GATEWAY_MODELS` / `GATEWAY_PROVIDERS`. The
 * roster half was the real defect; see `@ferrogate/storage`\'s
 * `tenant-model-catalog.ts` for what the seed is actually for.)
 *
 * ## Every creation entry point, and how each one reaches this
 *
 * There are four, and the one that gets forgotten is the second:
 *
 *  1. `POST /admin/v1/tenant-accounts` — the generic `createHandler`, through
 *     the `provision` hook on the collection spec (`routes/resource.ts`).
 *  2. `POST /v1/admin/register`, console self-service (`session/routes.ts`). It
 *     bypasses `crudGroup` entirely and writes the `tenant-accounts` DOCUMENT
 *     directly, so no spec hook of any kind runs for it. It calls this module —
 *     and `projectTenantAccount` — explicitly. Before this slice a
 *     self-registered tenant had no `tenants` row either, so the gateway's
 *     lifecycle read and its plan join both missed.
 *  3. `PUT /admin/v1/tenant-accounts/{id}/plan` — an override that does not run
 *     the spec hooks, so it calls this explicitly too. It cannot CREATE a
 *     tenant (the merge 404s on a missing one), but it is the route that
 *     retroactively materialises a self-registered tenant's typed row, so it is
 *     a repair point and repairing storage there is free.
 *  4. `PUT` / `PATCH /admin/v1/tenant-accounts/{id}` — `replaceHandler` /
 *     `mergeHandler`, also through the spec hook. Neither can create; both are
 *     repair points for a tenant whose provisioning failed.
 *
 * ## Why a failure here does NOT fail the request
 *
 * Recording the roster row and seeding the object span the control database and
 * a Durable Object, and there is no cross-store transaction on this platform. So
 * the requirement cannot be "atomic" — it has to be "a half-provisioned tenant
 * is DETECTABLE and resumable", which is what `provisionTenantStorage` delivers:
 * it writes `pending` before touching anything and `failed` with the refusal's
 * own message if a step throws, so the state an operator finds names the cause,
 * and `listUnfinished()` is the worklist.
 *
 * Given that, re-raising here would turn a recoverable storage fault into a
 * failed tenant CREATION — and the tenant document is already committed by the
 * time this runs, so the caller would get a 500 for a tenant that exists. The
 * caller's retry is the same PUT/PATCH that repairs it anyway. So the outcome is
 * recorded and swallowed, and the honest cost is stated here: nothing surfaces
 * the failure to the operator SYNCHRONOUSLY. The roster row is where it surfaces,
 * and wiring a sweep of `listUnfinished()` into a scheduled trigger is the
 * follow-up this comment exists to name rather than to imply is already done.
 *
 * A tenant with no `tenants` row is a different case and it is refused hard,
 * inside `provisionTenantStorage`, BEFORE any object is addressed: an object is
 * created by being addressed, a namespace cannot be enumerated to find the junk
 * ones, and every one of them bills for storage forever.
 */
import {
  type TenantJurisdiction,
  type TenantModelCatalogSeedGraph,
  locationHintFromCloudflareSignal,
  placementSignalFromRequest,
  provisionTenantStorage,
  tenantJurisdictionForResidencyRegions,
} from "@ferrogate/storage";
import type { ControlPlaneDeps } from "../ports.js";
import { PlatformModelCatalogStore } from "./platform-model-catalog.js";

interface ResidencyPolicyRow {
  readonly residency_regions_json: string | null;
}

function residencyRegionsFromColumn(value: string | null): string[] {
  if (value === null || value.trim() === "") return [];
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed)
      ? parsed.filter((entry): entry is string => typeof entry === "string")
      : [];
  } catch {
    return [];
  }
}

/** Read the jurisdiction implied by the policy already committed for a tenant. */
export async function tenantJurisdictionFromPolicy(
  controlDatabase: D1Database,
  tenantId: string,
): Promise<TenantJurisdiction | undefined> {
  try {
    const row = await controlDatabase
      .prepare(
        "SELECT residency_regions_json FROM quota_policies " +
          "WHERE scope_type = 'tenant' AND scope_id = ?",
      )
      .bind(tenantId)
      .first<ResidencyPolicyRow>();
    return tenantJurisdictionForResidencyRegions(
      residencyRegionsFromColumn(row?.residency_regions_json ?? null),
    );
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    if (/no such (table|column):/i.test(detail)) return undefined;
    throw error;
  }
}

/**
 * Read the managed platform catalog for the provisioning seed, degrading ANY
 * read fault to the card fallback (#891).
 *
 * `exportForSeed` already treats an ABSENT catalog — the `d1_compat` migration
 * window where the Worker is new and migration `0025`'s tables are not applied
 * yet — as an empty graph. This widens that tolerance to EVERY read fault: the
 * same "new Worker, old DB" window can also raise `no such column` when a future
 * migration adds a column the new `PROVIDER_SELECT` references, and a platform
 * catalog read fault must never fail tenant onboarding, which did not depend on
 * it at all before this slice. Returning `undefined` makes `provisionTenantStorage`
 * seed the compiled-in card and STILL run — writing its roster row and reporting
 * its own outcome — instead of the caller's outer catch swallowing the throw and
 * returning `false` before provisioning was ever attempted.
 */
async function exportPlatformCatalogSeed(
  controlDatabase: D1Database,
): Promise<TenantModelCatalogSeedGraph | undefined> {
  try {
    return await new PlatformModelCatalogStore({ db: controlDatabase }).exportForSeed();
  } catch {
    return undefined;
  }
}

/**
 * Provision (or resume) one tenant's storage, best-effort.
 *
 * Returns `true` when the tenant's storage is confirmed ready. `false` means the
 * attempt was recorded as unfinished on `tenant_databases` — never that it was
 * skipped silently, except in the one posture where there is nothing to skip:
 * `controlDatabase === null`, i.e. `CONTROL_PLANE_STORE = "memory"` or no `DB`
 * binding, where there is no roster table to write and no durable store behind
 * the document either.
 */
export async function provisionTenantStorageFor(
  deps: ControlPlaneDeps,
  tenantId: string,
  request?: Request,
): Promise<boolean> {
  if (deps.controlDatabase === null) return false;
  const controlDatabase = deps.controlDatabase;
  try {
    // Prefer the request's native `cf`, but fall back to the `x-ferrogate-cf-*` headers a trusted BFF
    // forwards: a Worker→Worker service-binding hop strips `cf`, so a relayed registration would
    // otherwise present no signal and fall to the US-West (`wnam`) default. `origin` tags the source
    // on the roster row so an operator can tell an edge-header placement from a native `cf` one.
    const { signal, origin } = placementSignalFromRequest(request);
    const placement = locationHintFromCloudflareSignal(signal);
    const locationHintSource =
      origin === "edge-header" ? `edge-header;${placement.source}` : placement.source;
    const jurisdiction = await tenantJurisdictionFromPolicy(controlDatabase, tenantId);
    // The MANAGED platform catalog (#891) is the seed source when this
    // deployment has adopted it. It is read over the CONTROL_DATA facade (the
    // Zero-D1 seam #879) and passed DOWN to `provisionTenantStorage` as plain
    // data, so `@ferrogate/storage` never names a `platform_*` table. The read is
    // a LAZY loader: `provisionTenantStorage` only invokes it when a seed will
    // actually run, so an already-seeded tenant (every PUT/PATCH repair point)
    // never pays for the export, and a failed read degrades to the card rather
    // than failing onboarding — see `exportPlatformCatalogSeed`.
    const outcome = await provisionTenantStorage(
      deps.tenantStorage ?? deps.tenantDatabases,
      tenantId,
      {
        locationHint: placement.locationHint,
        locationHintSource,
        locationHintRecordedAtUnix: Math.floor(Date.now() / 1000),
        ...(jurisdiction === undefined ? {} : { jurisdiction }),
        catalogGraphLoader: () => exportPlatformCatalogSeed(controlDatabase),
      },
    );
    return outcome.status === "ready";
  } catch {
    // `provisionTenantStorage` has already written `failed` and the refusal's
    // own message onto the roster row by the time it throws — except for the one
    // refusal that happens BEFORE any row is written, `not_found`, which means
    // this tenant has no `tenants` row at all. That one is a wiring fault in THIS
    // app (the projection that writes the typed row did not run) rather than a
    // storage fault, and its fix is a code change rather than a resume; it leaves
    // no roster row precisely so that an unregistered id never gets an object.
    //
    // Either way there is nothing to record here, only a decision not to fail the
    // request. See the module docblock for why that decision, and what it costs.
    return false;
  }
}
