/**
 * `GET|HEAD /sites/{site}/{path}` — the static-site serve mode (issue #737).
 *
 * ## It rides the asset pull; it is not a faster copy of it
 *
 * Every byte this module returns leaves through `AssetService.pullAsset`, the
 * same method `GET /v1/assets/{type}/{name}/{version}` calls, entered through
 * the same `#resolveArtifact`. That is the constraint #736 wrote into the
 * bundle index's schema note and it is the whole design here: a second
 * resolution path is how a YANKED site stays servable, how a `quarantined`
 * version becomes readable, and how a tenant fence acquires a second place to
 * be wrong. What this module owns is the part a static host has to decide and
 * an artifact registry does not — which file a URL names, what a miss answers,
 * and how long the answer may be cached.
 *
 * The one thing it must do BEFORE pulling is find out which files exist, so it
 * can tell "serve this" from "redirect to the directory URL" from "fall back to
 * `404.html`". `AssetService.siteFileProbe` does that against the same resolved
 * version without reading or billing a byte — `pullAsset` charges the whole
 * object to the egress budget before it reads anything, so probing with it
 * would bill a tenant for bytes nobody was ever sent.
 *
 * ## Metering, quota and rate limiting — the answer, stated
 *
 * `/sites/*` IS metered and IS egress-quota'd, including for anonymous readers,
 * and the bill goes to the tenant that owns the bundle. `pullAsset` runs
 * `#egressDenial` before the read and `#recordEgress` after it, so a site read
 * spends the same `monthlyEgressBytesBudget` and trips the same
 * `downloadRpmLimit` window as a `GET /v1/assets/**` pull, and writes the same
 * `asset.pull` audit row. An unmetered public serve path on top of tenant-billed
 * R2 storage would be a hole, and #736's decision to count the ARCHIVE in
 * `size_bytes` — storage is what the tenant uploaded, once — is exactly why
 * egress has to be counted separately here: the expansion is served over and
 * over, and nothing in the storage number sees that.
 *
 * The two counters an ANONYMOUS reader is measured against are the OWNER's,
 * resolved from the owner's quota chain rather than from a credential, because
 * there is no credential. The per-request `rateLimit()` middleware is a
 * different mechanism and does not apply: it keys on an api-key id
 * (`subjectFor` returns `null` without one), so an anonymous site read is
 * bounded by the byte budget and the download-RPM window, not by RPM-per-key.
 * A per-IP limiter for anonymous site traffic belongs in front of this (the
 * Cloudflare edge already has one) and is deliberately not invented here.
 */
import type { Context } from "hono";
import { depsFromEnv } from "../adapters.js";
import { bundleFileContentType } from "../assets/bundle.js";
import type { AssetEgressQuota } from "../assets/egress.js";
import { buildAssetService } from "../assets/handlers.js";
import type { AssetCaller } from "../assets/ports.js";
import type { AssetService, AssetServiceDeps } from "../assets/service.js";
import { authenticateBearer, extractApiKey } from "../middleware/auth.js";
import { HttpError } from "../middleware/errors.js";
import type { GatewayDeps, GatewayEnv } from "../ports.js";
import {
  type QuotaBindings,
  quotaPolicySourceFromEnv,
  resolveQuotaWindows,
} from "../ratelimit/index.js";
import { GatewayRouter, type RouteModule } from "../routes/index.js";
import { planSitePath } from "./paths.js";
import { SITE_VARY, siteCacheControl } from "./policy.js";
import {
  SITE_ASSET_TYPE,
  type SiteBinding,
  type SiteBindings,
  siteAccessFor,
  siteBindingsFromEnv,
  siteTenantForCredential,
} from "./registry.js";

/** The contract operation this module mounts. */
export const SITE_OPERATION_ID = "serveSite";

type SiteEnv = {
  Bindings: GatewayEnv["Bindings"] & SiteBindings;
  Variables: GatewayEnv["Variables"];
};

/**
 * The scope a PRIVATE site requires.
 *
 * `assets.read` and not a scope of its own: a site is a `static_site` asset,
 * and a credential that may pull the bundle by identity through
 * `/v1/assets/static_site/{name}/{version}` can already read every byte this
 * route serves. Minting `sites.read` would let a key be refused here and
 * succeed there, which is not a boundary — it is a second lock on the same door.
 */
export const SITE_READ_SCOPE = "assets.read";

/**
 * One refusal for every "no", so a probe cannot distinguish an unknown site
 * from a private one from a withheld, quarantined or yanked version from a
 * missing file inside a real site.
 *
 * The issue asks for the distinction between "a missing path inside a real
 * site" and "an unknown site", and it is made — but only for a caller who is
 * ENTITLED to know it. A reader who may see the site gets
 * `site_file_not_found` (and, when the site ships one, its own `404.html`); a
 * reader who may not gets `site_not_found` and learns nothing about whether
 * the slug, the version or the file was the part that did not exist.
 */
function siteNotFound(slug: string): never {
  throw new HttpError(404, "site_not_found", `no site is served at /sites/${slug}`);
}

/** Ports for the auth ladder — a factory, because bindings are per request. */
export type SiteDepsResolver = GatewayDeps | ((env: GatewayEnv["Bindings"]) => GatewayDeps);

export interface SiteRouteModuleOptions {
  /** A pre-built asset service. Wins over `deps`/`depsFromEnv`. */
  readonly service?: AssetService | undefined;
  /** Ports for a service built here. */
  readonly deps?: Partial<AssetServiceDeps> | undefined;
  /** Ports resolved from the request's Worker bindings, merged over `deps`. */
  readonly depsFromEnv?: ((env: Record<string, unknown>) => Partial<AssetServiceDeps>) | undefined;
  /** The gateway ports the bearer ladder runs against. */
  readonly gatewayDeps?: SiteDepsResolver | undefined;
  /** Site bindings, for tests that do not want to serialise a var. */
  readonly bindings?: ReadonlyMap<string, SiteBinding> | undefined;
}

/**
 * The egress budget an anonymous read is measured against: the OWNER's.
 *
 * `subjectFor` cannot be used — it reads the request's `AuthContext`, and there
 * is none. The chain is the owning tenant with no key, which is exactly what
 * `EffectiveQuota`'s merge does for a tenant-scoped policy, and the counter key
 * `egress:tenant:{id}` it produces is the same one an authenticated read of the
 * same site charges. Anonymous traffic therefore cannot be used to drain a
 * budget the tenant thought applied only to its keys, nor does it get a fresh
 * budget of its own.
 */
async function ownerEgressQuota(
  c: Context<SiteEnv>,
  tenantId: string,
  apiKeyId: string,
): Promise<AssetEgressQuota> {
  if (tenantId === "") return {};
  const resolution = await resolveQuotaWindows(
    quotaPolicySourceFromEnv(c.env as unknown as QuotaBindings),
    { apiKeyId, chain: { tenantId, keyId: apiKeyId }, requestLimitPerMinute: undefined },
  );
  return resolution.ok ? resolution.quota : {};
}

/** Render an `AssetPullResult` that has already succeeded. */
function bytesResponse(
  status: number,
  bytes: Uint8Array | null,
  headers: Readonly<Record<string, string>>,
): Response {
  const body: BodyInit | null =
    bytes === null
      ? null
      : (bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer);
  return new Response(body, { status, headers: { ...headers } });
}

export function siteRouteModule(options: SiteRouteModuleOptions = {}): RouteModule {
  const fixed =
    options.service ?? (options.depsFromEnv === undefined ? buildAssetService(options.deps) : null);
  const byEnv = new WeakMap<object, AssetService>();
  const serviceFor = (c: Context<SiteEnv>): AssetService => {
    if (fixed !== null) return fixed;
    const env = (c.env ?? {}) as Record<string, unknown>;
    const cached = byEnv.get(env);
    if (cached !== undefined) return cached;
    const built = buildAssetService({ ...options.deps, ...options.depsFromEnv?.(env) });
    byEnv.set(env, built);
    return built;
  };
  const portsFor = (c: Context<SiteEnv>): GatewayDeps => {
    const resolver = options.gatewayDeps ?? depsFromEnv;
    return typeof resolver === "function"
      ? resolver(c.env as unknown as GatewayEnv["Bindings"])
      : resolver;
  };

  async function handleSite(c: Context<SiteEnv>): Promise<Response> {
    const service = serviceFor(c);
    const canonical = c.get("canonicalPath") ?? c.req.path;
    const rest = canonical.slice("/sites/".length);
    const queryAt = c.req.url.indexOf("?");
    const search = queryAt === -1 ? "" : c.req.url.slice(queryAt);

    const plan = planSitePath(rest, search);
    if (plan.kind === "invalid") {
      throw new HttpError(400, "site_path_invalid", `not a servable site path: ${plan.reason}`);
    }
    if (plan.kind === "redirect") {
      return new Response(null, {
        status: 308,
        headers: { location: plan.location, "cache-control": "public, max-age=0", vary: SITE_VARY },
      });
    }

    const bindings = options.bindings ?? siteBindingsFromEnv(c.env);
    const binding = bindings.get(plan.slug);
    const access = siteAccessFor(binding, extractApiKey(c.req.raw.headers) !== null);

    let tenantId: string;
    let scopes: readonly string[] = [];
    let apiKeyId = "";
    let projectId: string | undefined;
    if (access.kind === "authenticate") {
      // The SAME ladder the contract middleware runs — key resolution, scope,
      // tenancy lifecycle, RBAC — not a second copy of it. `serveSite` is
      // `anonymous` in the contract because a site's credential requirement is
      // per-site DATA that `auth.kind` cannot express; this line is what makes
      // that a deferral rather than an exemption.
      const operation = c.get("operation") ?? GatewayRouter.operationOrThrow(SITE_OPERATION_ID);
      const auth = await authenticateBearer(
        portsFor(c),
        c.req.raw.headers,
        SITE_READ_SCOPE,
        operation,
      );
      const resolved = siteTenantForCredential(access.binding, auth.tenancy.tenantId ?? "");
      if (resolved === null) siteNotFound(plan.slug);
      tenantId = resolved;
      scopes = [...auth.scopes];
      apiKeyId = auth.subject ?? "";
      projectId = auth.tenancy.projectId ?? undefined;
    } else {
      tenantId = access.tenantId;
      scopes = [SITE_READ_SCOPE];
    }

    const publicSite = binding?.anonymous === true;
    const caller: AssetCaller = {
      tenantId,
      ...(projectId !== undefined ? { projectId } : {}),
      scopes,
      // A site READ never needs the hosting entitlement — that grant governs
      // publishing. `pullAsset` does not consult it; this is stated so nobody
      // "fixes" it into a fail-open later.
      assetHostingEnabled: false,
      apiKeyId,
      effectiveQuota: await ownerEgressQuota(c, tenantId, apiKeyId),
    };
    const ref = {
      assetType: SITE_ASSET_TYPE,
      name: binding?.assetName ?? plan.slug,
      // A CHANNEL, always. `/sites/*` never takes a version from the URL, so a
      // yanked bundle is unresolvable here even though an exact pin still
      // serves one through `/v1/assets/**`.
      reference: binding?.channel ?? "latest",
    };

    const candidates =
      plan.directoryProbe === null ? [plan.file] : [plan.file, plan.directoryProbe.file];
    const probe = await service.siteFileProbe(caller, ref, candidates);
    // A resolution refusal — no such asset, nothing visible, no variant — is
    // reported as the site not existing. Quarantined, withheld and yanked are
    // already absent from `#resolveArtifact`, so they arrive here as exactly
    // the same 404 an unknown slug produces.
    if (!probe.ok) siteNotFound(plan.slug);

    let file = probe.body.path;
    if (file !== null && plan.directoryProbe !== null && file === plan.directoryProbe.file) {
      // The URL named a directory that has an index document. One document,
      // one URL: it lives at the directory URL, so the request moves there
      // instead of the bytes being served under two names.
      return new Response(null, {
        status: 308,
        headers: {
          location: plan.directoryProbe.location,
          "cache-control": "public, max-age=0",
          vary: SITE_VARY,
        },
      });
    }

    let status = 200;
    let fallback = false;
    if (file === null) {
      // A miss inside a real site. SPA rewrite first when the site opted in —
      // it is the site saying "every path is my entry document" — then the
      // site's own 404 document, then the JSON envelope. No directory listing
      // is ever produced, under any of the three.
      const spaFallback = binding?.spa === true ? ["index.html"] : [];
      const notFoundDocument =
        binding === undefined || binding.notFoundDocument === "" ? [] : [binding.notFoundDocument];
      const documents = binding === undefined ? ["404.html"] : [...spaFallback, ...notFoundDocument];
      const second =
        documents.length === 0
          ? null
          : await service.siteFileProbe(caller, ref, documents);
      if (second !== null && second.ok && second.body.path !== null) {
        file = second.body.path;
        fallback = true;
        // The SPA entry document IS the answer (200); a 404 document describes
        // an answer that does not exist (404). Serving `404.html` with a 200 is
        // the classic soft-404 that makes a search engine index every typo.
        status = binding?.spa === true && file === "index.html" ? 200 : 404;
      } else {
        throw new HttpError(
          404,
          "site_file_not_found",
          `/sites/${plan.slug} has no file at ${plan.file}`,
        );
      }
    }

    const contentType = bundleFileContentType(file) ?? "application/octet-stream";
    const result = await service.pullAsset(
      caller,
      ref,
      {
        bundlePath: file,
        headers: c.req.raw.headers,
        method: c.req.method,
        cacheControl: siteCacheControl({ path: file, contentType, publicSite, fallback }),
      },
      { requestId: c.get("requestId") ?? "" },
    );
    if (!result.ok) {
      // Anything the pull refuses AFTER the probe found the file is a real
      // condition of this deployment (no bucket, egress budget exhausted,
      // integrity failure) and is reported as itself — except a 404, which can
      // only mean the version moved underneath us and must not disclose more
      // than the uniform refusal does.
      if (result.status === 404) siteNotFound(plan.slug);
      throw new HttpError(result.status, result.code, result.message);
    }

    // `304` and `416` keep their own status; a fallback document overrides the
    // pull's 200 with the status the URL deserves.
    const finalStatus = result.status === 200 ? status : result.status;
    return bytesResponse(finalStatus, result.bytes, {
      ...result.headers,
      vary: SITE_VARY,
      "x-ferrogate-site-path": file,
    });
  }

  return {
    operationIds: [SITE_OPERATION_ID],
    register(router: GatewayRouter): void {
      router.register(SITE_OPERATION_ID, async (c) => {
        const context = c as unknown as Context<SiteEnv>;
        try {
          return await handleSite(context);
        } finally {
          // The pull-side audit row (`asset.pull`) is buffered by the durable
          // sink and committed once per request — including on the refusals,
          // which are the rows an operator most wants.
          await serviceFor(context).flushAudit();
        }
      });
    },
  };
}
