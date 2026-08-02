/**
 * Which sites exist under `/sites/{slug}`, and which of them may be read
 * without a credential (issue #737).
 *
 * ## Access is explicit, and private is the default
 *
 * A `static_site` bundle is a tenant asset like any other, so the baseline is
 * the baseline every other asset read has: `Authorization: Bearer` with the
 * `assets.read` scope, resolved inside the CREDENTIAL's tenant. Nothing here is
 * required for that; a tenant can serve its own site to its own keys with no
 * configuration at all.
 *
 * Anonymous serving is the exception and it is opt-in, per site AND per
 * channel, because "publish a site" and "publish a site to the entire internet"
 * are different decisions and only the operator gets to make the second one.
 *
 * ## Why operator config rather than a self-service table
 *
 * `/sites/{slug}` is a GLOBAL path namespace over a per-tenant asset namespace:
 * two tenants may each own a `static_site` called `docs`, and an anonymous
 * request carries nothing that says which one it means. Something has to bind
 * the slug to a tenant, and the binding is what makes anonymous resolution
 * possible at all — it is not merely a flag.
 *
 * A self-service table would make that binding a race between tenants for a
 * global name, which is a land-grab and a phishing surface (`/sites/acme-login`
 * is worth taking). So the binding is `GATEWAY_SITES`, an operator var, exactly
 * like `GATEWAY_SKILL_PACKAGES`, `GATEWAY_PROMPT_TEMPLATES`,
 * `GATEWAY_AGENT_UPSTREAMS` and `ASSET_ENTITLEMENTS` before it. A tenant-facing
 * claim flow with domain verification already has a home — the
 * `/admin/v1/site-domains` family and its DNS-TXT challenge — and that is where
 * a self-service slug belongs when it is built.
 *
 * ## The shadowing rule, stated out loud
 *
 * A slug that HAS a binding resolves to that binding's tenant for everybody. A
 * slug that has none resolves inside the caller's own tenant and requires a
 * credential. So an operator who binds `docs` takes the name `/sites/docs` away
 * from every other tenant's private `docs`. That is inherent to a global path
 * namespace and it is one rule rather than a precedence table nobody can
 * predict; `test/sites/access.test.ts` pins it.
 */

/** One operator-bound site. */
export interface SiteBinding {
  /** URL slug: the first path segment under `/sites/`. */
  readonly slug: string;
  /** The tenant that owns the bundle AND is billed for its egress. */
  readonly tenantId: string;
  /** `static_site` asset name inside that tenant. Defaults to the slug. */
  readonly assetName: string;
  /**
   * The channel this slug serves. Defaults to `latest`.
   *
   * A CHANNEL and never a version: the serve mode resolves through the same
   * registry as every other read, and a channel is the only reference that
   * excludes a yanked version by construction (an exact pin deliberately still
   * serves one, with a warning — which is right for a pinned CLI download and
   * wrong for a website nobody pinned).
   */
  readonly channel: string;
  /**
   * Whether an anonymous reader may be served. Default `false`.
   *
   * Per binding, and a binding names exactly one channel, so this is the
   * per-site, per-channel opt-in: publishing to `staging` does not expose it
   * because the binding that is public names `stable`.
   */
  readonly anonymous: boolean;
  /**
   * Serve the site's `index.html` (status 200) for a path that matches no file
   * — the single-page-application rewrite. Default `false`, because turning it
   * on means the site can never answer 404 for anything.
   */
  readonly spa: boolean;
  /**
   * Document served (with status 404) when a path matches no file. Default
   * `404.html`; empty string disables it and the JSON error envelope is used.
   */
  readonly notFoundDocument: string;
}

/** The default a slug with no binding resolves under. */
export const DEFAULT_SITE_CHANNEL = "latest";
export const DEFAULT_SITE_NOT_FOUND_DOCUMENT = "404.html";

/** The `static_site` asset family — the only family `/sites/*` will serve. */
export const SITE_ASSET_TYPE = "static_site";

/** Worker bindings this module reads. */
export interface SiteBindings {
  /**
   * JSON map: slug → `{ tenant_id, asset_name?, channel?, anonymous?, spa?,
   * not_found_document? }`.
   *
   * Absent or malformed ⇒ NO bindings, i.e. every site is private and
   * tenant-scoped. A parse failure must never be read as "everything is
   * public", so it is read as "nothing is bound" — the same polarity
   * `configuredEntitlementsFromEnv` uses for `ASSET_ENTITLEMENTS`.
   */
  readonly GATEWAY_SITES?: string | undefined;
}

function stringField(row: Record<string, unknown>, key: string): string | undefined {
  const value = row[key];
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

function bindingFrom(slug: string, raw: unknown): SiteBinding | null {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const tenantId = stringField(row, "tenant_id");
  // A binding with no tenant binds nothing: it could only resolve to the empty
  // tenant id, which matches no row. Dropping it is what keeps a typo from
  // silently producing a site that answers 404 to its owner and to nobody else.
  if (tenantId === undefined) return null;
  return {
    slug,
    tenantId,
    assetName: stringField(row, "asset_name") ?? slug,
    channel: stringField(row, "channel") ?? DEFAULT_SITE_CHANNEL,
    anonymous: row["anonymous"] === true,
    spa: row["spa"] === true,
    notFoundDocument:
      typeof row["not_found_document"] === "string"
        ? (row["not_found_document"] as string).trim()
        : DEFAULT_SITE_NOT_FOUND_DOCUMENT,
  };
}

/** Parse `GATEWAY_SITES`. Never throws; a bad document binds nothing. */
export function siteBindingsFromEnv(env: SiteBindings): ReadonlyMap<string, SiteBinding> {
  const bindings = new Map<string, SiteBinding>();
  const raw = env.GATEWAY_SITES;
  if (typeof raw !== "string" || raw.trim() === "") return bindings;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return bindings;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return bindings;
  for (const [slug, value] of Object.entries(parsed as Record<string, unknown>)) {
    const binding = bindingFrom(slug, value);
    if (binding !== null) bindings.set(slug, binding);
  }
  return bindings;
}

/** Who a request is served as. */
export type SiteAccess =
  /** No credential needed; serve as the binding's tenant. */
  | { readonly kind: "anonymous"; readonly tenantId: string; readonly binding: SiteBinding }
  /**
   * Authenticate first. `binding` is the operator's entry when the slug has
   * one; `null` means the site is resolved inside the caller's own tenant.
   */
  | { readonly kind: "authenticate"; readonly binding: SiteBinding | null };

/**
 * Decide how to serve `slug`, given whether the request presented a credential.
 *
 * A credential that IS presented is always authenticated, even for a public
 * site: silently ignoring a presented token would serve a caller whose token is
 * expired or revoked as if it were fine, and the caller would have no way to
 * tell. It only affects who pays and what the site resolves to when the slug is
 * unbound.
 */
export function siteAccessFor(
  binding: SiteBinding | undefined,
  credentialPresented: boolean,
): SiteAccess {
  if (binding !== undefined && binding.anonymous && !credentialPresented) {
    return { kind: "anonymous", tenantId: binding.tenantId, binding };
  }
  return { kind: "authenticate", binding: binding ?? null };
}

/**
 * The tenant an AUTHENTICATED caller is served under, or `null` when the answer
 * is "this site is not yours".
 *
 * The fence: a bound, non-anonymous site belongs to exactly one tenant and a
 * credential from any other tenant gets `null` — indistinguishable from the
 * slug not existing. A bound, ANONYMOUS site is public, so any authenticated
 * caller reads it as the owner's, which is also who is billed for the bytes.
 */
export function siteTenantForCredential(
  binding: SiteBinding | null,
  callerTenantId: string,
): string | null {
  if (binding === null) return callerTenantId === "" ? null : callerTenantId;
  if (binding.anonymous) return binding.tenantId;
  return binding.tenantId === callerTenantId ? binding.tenantId : null;
}
