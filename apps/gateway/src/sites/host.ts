/**
 * The custom-domain entry point: a request that arrived on a VERIFIED hostname
 * is served from that tenant's site bundle (issue #738).
 *
 * ## Where it is mounted, and why there
 *
 * `createGatewayApp` mounts this after the request id, the metrics counter, the
 * envelope boundary and the pre-auth network gate — and BEFORE `contractAuth`
 * and every route. Both halves of that position are load-bearing:
 *
 *  - **After the network gate**, because an IP the operator refused must be
 *    refused on every authority, and because the gate's counters must see site
 *    traffic like any other traffic.
 *  - **Before the routes**, because on a custom domain the AUTHORITY belongs to
 *    the tenant, so `/healthz`, `/version`, `/metrics` and `/v1/**` are paths
 *    inside the tenant's document tree and not this gateway's API. Mounting
 *    below the routes would let the gateway's own surface shadow files the
 *    tenant published, and — worse — would let an INACTIVE domain still answer
 *    on those paths, so the refusal below would not actually be about the
 *    authority.
 *
 * ## It routes; it does not resolve
 *
 * All this middleware does is turn an authority into a `(tenant, slug)` pair
 * and call {@link SiteServer.serve} — the same object, the same method and the
 * same arguments the `/sites/{slug}/{path}` route calls. There is no second
 * lookup keyed on the `Host` header, and that is the point: a site YANKED on
 * its slug is yanked on its custom domain, a `quarantined` or `pending_scan`
 * version is withheld from both, the egress is billed to the same tenant on the
 * same counter, and the same `asset.pull` audit row is written. See
 * `./serve.ts`'s header.
 *
 * ## TLS, SNI, and what this repository cannot prove
 *
 * A Worker only ever sees a request on `docs.acme.com` if Cloudflare terminated
 * TLS for that hostname and routed it here, which is DEPLOY-TIME configuration:
 * either a Workers Custom Domain on a zone in the account, or a Cloudflare for
 * SaaS custom hostname with its own certificate (`/zones/{zone}/custom_hostnames`).
 * Neither can be exercised offline — `workerd` under vitest has no TLS
 * terminator, no zone and no certificate authority — so nothing in this tree
 * tests them, and no test here should be read as evidence that they work. What
 * IS tested is everything downstream of the `Host` header, which is the part
 * this repository owns: the ownership proof, the fence, the refusals and the
 * serve path. The provisioning half is tracked separately; see the PR for #738.
 */
import type { Context, MiddlewareHandler } from "hono";
import { assetDepsFromEnv } from "../assets/handlers.js";
import { HttpError } from "../middleware/errors.js";
import type { GatewayEnv } from "../ports.js";
import {
  D1SiteDomainDirectory,
  type SiteDomainDatabase,
  type SiteDomainDirectory,
  normalizeSiteHostname,
} from "./domains.js";
import { type SiteEnv, SiteServer, type SiteServerOptions } from "./serve.js";

/**
 * The status a CLAIMED-but-not-serving authority answers with, on every path.
 *
 * **421 Misdirected Request**, RFC 9110 §15.5.20: *"the request was directed at
 * a server that is not able to produce a response for the combination of scheme
 * and authority"*. That is precisely, and only, what has happened — somebody
 * pointed `docs.acme.com` at this gateway and this gateway will not answer for
 * that authority, because the ownership proof is missing, expired or revoked.
 *
 * Every alternative says something false. `404` claims a resource does not
 * exist, when the truth is about the authority rather than the path, and it
 * would be indistinguishable from a real missing file inside a real site.
 * `403` blames the caller's credential for a decision about DNS. `503` promises
 * the capability comes back on its own; it comes back when the tenant publishes
 * a TXT record and re-verifies, which is not an outage recovering.
 *
 * Falling THROUGH — routing the request as if it had arrived on the API host —
 * is the one behaviour that is worse than any status, and it is the reason this
 * refusal exists at all: it would make "verified" and "not verified"
 * indistinguishable to whoever pointed the DNS, which is exactly the state in
 * which a domain-takeover primitive goes unnoticed.
 */
export const SITE_DOMAIN_INACTIVE_STATUS = 421;

/** The machine-readable code of that refusal. */
export const SITE_DOMAIN_INACTIVE_CODE = "site_domain_not_active";

/**
 * ONE message for every non-serving state.
 *
 * `pending_verification`, `expired`, a proof held by another tenant and a
 * hostname bound to no site all produce this string. The reason is disclosure:
 * the states differ in what they say about a tenant this caller may have
 * nothing to do with, and an unauthenticated prober would otherwise learn
 * whether a competitor had started a claim on a domain. The distinction is kept
 * where it belongs — the `SiteDomainDecision.reason` an operator reads in the
 * logs.
 */
export function siteDomainInactiveMessage(hostname: string): string {
  return [
    `${hostname} is not served here: this gateway holds no live ownership proof`,
    "binding that hostname to a published site. Complete the DNS-TXT challenge at",
    "POST /admin/v1/site-domains/{hostname}/verify, or remove the DNS record that",
    "points it here.",
  ].join(" ");
}

/** Worker bindings this middleware reads. */
export interface SiteDomainBindings {
  /**
   * The CONTROL database holding `site_domains` + `site_domain_verifications`.
   *
   * UNBOUND is inert: with no control database there are no custom domains, and
   * every request routes exactly as it did before #738. That is the safe
   * polarity — the failure mode of a missing binding is "no site is served on a
   * custom hostname", never "every hostname serves a site".
   */
  readonly CONTROL_DB?: unknown;
}

export interface SiteDomainRoutingOptions extends SiteServerOptions {
  /**
   * The directory, or a factory over the request's bindings. Defaults to
   * {@link D1SiteDomainDirectory} on `env.CONTROL_DB`, memoized per env object
   * so one isolate holds one cache.
   */
  readonly directory?:
    | SiteDomainDirectory
    | ((env: Record<string, unknown>) => SiteDomainDirectory | null)
    | undefined;
  /** Injectable clock, in whole seconds. Defaults to the wall clock. */
  readonly now?: (() => number) | undefined;
}

/** `env.CONTROL_DB`, when it really is a D1-shaped binding. */
function controlDatabase(env: Record<string, unknown>): SiteDomainDatabase | null {
  const candidate = (env as SiteDomainBindings).CONTROL_DB;
  if (candidate === null || typeof candidate !== "object") return null;
  return typeof (candidate as SiteDomainDatabase).prepare === "function"
    ? (candidate as SiteDomainDatabase)
    : null;
}

/**
 * Route verified custom hostnames to their site; leave every other authority
 * alone.
 *
 * Inert in three independent ways, so mounting it can never change the
 * behaviour of a deployment that has no custom domains: no `CONTROL_DB` ⇒ pass
 * through; no `site_domains` row for the authority ⇒ pass through; an
 * unreadable directory (missing table, D1 outage) ⇒ pass through. Only a row
 * that exists causes anything to happen, and only a row with a LIVE proof
 * causes anything to be served.
 */
export function siteDomainRouting(
  options: SiteDomainRoutingOptions = {},
): MiddlewareHandler<GatewayEnv> {
  const server = new SiteServer(options);
  const byEnv = new WeakMap<object, SiteDomainDirectory | null>();
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));

  const directoryFor = (env: Record<string, unknown>): SiteDomainDirectory | null => {
    const configured = options.directory;
    if (configured !== undefined) {
      return typeof configured === "function" ? configured(env) : configured;
    }
    const cached = byEnv.get(env);
    if (cached !== undefined) return cached;
    const db = controlDatabase(env);
    const built = db === null ? null : new D1SiteDomainDirectory(db);
    byEnv.set(env, built);
    return built;
  };

  return async (c, next) => {
    const env = (c.env ?? {}) as Record<string, unknown>;
    const directory = directoryFor(env);
    if (directory === null) return next();
    // The URL's host and not the raw `Host` header: Hono builds `c.req.url`
    // from the request the runtime accepted, so a duplicated or malformed
    // header has already been rejected or collapsed by the time it is here.
    const hostname = normalizeSiteHostname(new URL(c.req.url).host);
    if (hostname === "") return next();

    const decision = await directory.resolve(hostname, now());
    if (decision.kind === "unbound") return next();
    if (decision.kind === "inactive") {
      throw new HttpError(
        SITE_DOMAIN_INACTIVE_STATUS,
        SITE_DOMAIN_INACTIVE_CODE,
        siteDomainInactiveMessage(decision.hostname),
      );
    }

    const context = c as unknown as Context<SiteEnv>;
    try {
      return await server.serve(context, { kind: "domain", route: decision.route });
    } finally {
      await server.flushAudit(context);
    }
  };
}

/**
 * The production wiring: the same `env.ASSETS` bucket and tenant D1 bundle
 * index `assetRouteModule` and `siteRouteModule` use, so a custom domain, a
 * slug and a `/v1/assets/**` pull cannot resolve differently.
 */
export function defaultSiteDomainRouting(): MiddlewareHandler<GatewayEnv> {
  return siteDomainRouting({ depsFromEnv: assetDepsFromEnv });
}
