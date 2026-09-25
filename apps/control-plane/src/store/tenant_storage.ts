/**
 * Provision tenant storage from account creation and account repair hooks.
 * Provisioning verifies the tenant schema and records resumable roster state;
 * platform configuration stays in CONTROL_DATA / PLATFORM_CONFIG KV.
 * Failures are recorded on the roster without undoing the committed account.
 */
import {
  LOCATION_HINT_HEADER,
  coerceTenantLocationHint,
  locationHintFromCloudflareSignal,
  placementSignalFromRequest,
  provisionTenantStorage,
} from "@ferrogate/storage";
import type { ControlPlaneDeps } from "../ports.js";

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
    // otherwise present no signal and fall to the Tokyo (`apac-ne`) default. `origin` tags the source
    // on the roster row so an operator can tell an edge-header placement from a native `cf` one.
    const { signal, origin } = placementSignalFromRequest(request);
    const placement = locationHintFromCloudflareSignal(signal);
    const requestedHint = coerceTenantLocationHint(
      request?.headers?.get(LOCATION_HINT_HEADER) ?? undefined,
    );
    // Explicit tenant-console choice wins. Otherwise a real geo signal homes
    // the object near the user. Only a request with NO signal falls back to
    // the operator default (Tokyo `apac-ne` for this fleet).
    let locationHint = placement.locationHint;
    let locationHintSource =
      origin === "edge-header" ? `edge-header;${placement.source}` : placement.source;
    if (requestedHint !== undefined) {
      locationHint = requestedHint;
      locationHintSource = `tenant-console;${requestedHint}`;
    } else if (origin === "none" && deps.defaultTenantLocationHint !== undefined) {
      locationHint = deps.defaultTenantLocationHint;
      locationHintSource = `operator-default;${deps.defaultTenantLocationHint}`;
    }
    // Track A hard-cut: the tenant-residency jurisdiction was formerly derived
    // from a `quota_policies` row in the shared CONTROL mirror. That mirror is
    // being retired (no tenant data mirrored in the control object), and at FIRST
    // provisioning the tenant's own object does not exist yet to read residency
    // from, so placement no longer consults it — the geo/console/operator-default
    // location hint above is the sole placement signal. A residency-driven
    // jurisdiction, once its authoritative home is the tenant object, is a
    // re-placement concern outside this create-time path.
    const outcome = await provisionTenantStorage(
      deps.tenantStorage ?? deps.tenantDatabases,
      tenantId,
      {
        locationHint,
        locationHintSource,
        locationHintRecordedAtUnix: Math.floor(Date.now() / 1000),
      },
    );
    // One structured line per provisioning attempt. The module docblock notes
    // that a tenant's provisioning outcome does not surface SYNCHRONOUSLY beyond
    // the roster row; this is the observability projection of it. It also makes
    // the placement DECISION auditable from `wrangler tail` / Workers Logs — the
    // location hint a tenant's Durable Object was FIRST addressed with is
    // permanent, so recording which signal chose it (native `cf`, a forwarded
    // edge header, or the operator default) is the difference between an audited
    // placement and one inferred after the fact.
    console.log(
      JSON.stringify({
        event: "tenant_storage_provision",
        tenantId,
        status: outcome.status,
        locationHint,
        locationHintSource,
        placementOrigin: origin,
      }),
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
