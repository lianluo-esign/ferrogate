/**
 * Hostname → site binding, gated on a LIVE DNS ownership proof (issue #738).
 *
 * ## What this module decides, and what it deliberately does not
 *
 * It answers exactly one question — *"is the authority this request arrived on
 * a custom domain that some tenant has PROVEN it controls, and if so, which
 * tenant and which site?"* — and then hands the answer to
 * `../sites/serve.ts`, which is the same code `/sites/{slug}/{path}` runs. It
 * resolves no version, reads no object, consults no channel and bills nothing.
 *
 * That split is the whole point. #737's constraint is that there is ONE
 * artifact resolution path (`AssetService.#resolveArtifact`), so channels,
 * semver, variants, yank and the withholding of `pending_scan`/`quarantined`
 * rows are literally the same code for every reader. A hostname lookup that
 * also resolved the bundle would be a second path, and the first thing it would
 * get wrong is the thing that is easiest to get wrong: a site YANKED on its slug
 * would keep serving on its custom domain. Here the hostname only ever produces
 * a `(tenant, slug)` pair; everything downstream is unchanged.
 *
 * ## Why the proof cannot be spoofed
 *
 * The proof is the #488 DNS-TXT challenge (`apps/control-plane/src/site_domain_txt.ts`):
 * the tenant publishes `_ferrogate-challenge.<hostname>` = a SHA-256 digest over
 * the length-prefixed `(domain-tag, tenant_id, hostname, token)` tuple, where
 * `token` is 128 random bits this platform minted and never published. Standing
 * in front of the published record proves nothing to another tenant: its own
 * challenge row holds a DIFFERENT token, so the value it must publish is a
 * different digest, and the token is not recoverable from the digest. Publishing
 * the record therefore requires control of the zone's authoritative DNS, which
 * is the thing "owning a domain" means.
 *
 * Two further properties come from the schema rather than from the digest, and
 * both are load-bearing here:
 *
 *  - `site_domains.hostname` is a PRIMARY KEY, so **one hostname has at most one
 *    owner**. Two tenants racing for `example.com` are resolved by the database:
 *    the first `INSERT` wins and the second is told
 *    `SITE_DOMAIN_CLAIM_CONFLICT_MESSAGE`. There is no precedence rule to get
 *    wrong and no way for the loser to be silently ignored.
 *  - `site_domain_verifications` is keyed `(tenant_id, hostname)`, so several
 *    tenants may hold a PENDING challenge for one hostname — a squatter's
 *    unproven claim cannot block the tenant that really owns the domain — while
 *    only the tenant that also holds the `site_domains` row can serve.
 *
 * {@link SITE_DOMAIN_ROUTE_SQL} joins the two on **both** columns for exactly
 * that reason; see the note on it.
 *
 * ## What an inactive hostname does
 *
 * It is REFUSED, uniformly, for every path on that authority — never served
 * from a fallback and never quietly routed as if it were the gateway's own API
 * host. Falling back would mean the difference between "verified" and "not
 * verified" was invisible to the person who pointed the DNS, which is precisely
 * how a domain-takeover primitive stays undetected. See
 * `./host.ts::SITE_DOMAIN_INACTIVE_STATUS` for the status and its reasoning.
 */
import {
  type SiteDomainVerificationState,
  type StoredSiteDomainVerification,
  effectiveSiteDomainVerificationState,
  siteDomainVerificationStateFromString,
  siteDomainVerificationStateServes,
} from "@ferrogate/storage";
import {
  DEFAULT_SITE_CHANNEL,
  DEFAULT_SITE_NOT_FOUND_DOCUMENT,
  type SiteBinding,
} from "./registry.js";

/** A hostname that resolved to one tenant's site. */
export interface SiteDomainRoute {
  /** The normalized authority the request arrived on. */
  readonly hostname: string;
  /** The tenant that PROVED it controls {@link hostname}. */
  readonly tenantId: string;
  /** `site_domains.site` — the site slug, i.e. what follows `/sites/`. */
  readonly slug: string;
}

/**
 * Why a bound hostname is not serving. Carried for the AUDIT/log line only —
 * the refusal itself is uniform, so a prober cannot tell these apart.
 */
export type SiteDomainInactiveReason =
  /** A `site_domains` row with no `site_domain_verifications` row for its owner. */
  | "unproven"
  /** There is a proof row, and its effective state does not serve. */
  | SiteDomainVerificationState;

/** What the directory says about one inbound authority. */
export type SiteDomainDecision =
  /** Not a custom site domain at all — the request routes normally. */
  | { readonly kind: "unbound" }
  /** Claimed, but not serving. The request is REFUSED, not routed. */
  | { readonly kind: "inactive"; readonly hostname: string; readonly reason: SiteDomainInactiveReason }
  /** Serve this tenant's site. */
  | { readonly kind: "route"; readonly route: SiteDomainRoute };

/** One `site_domains` row plus the proof row belonging to ITS OWNER, if any. */
export interface SiteDomainRecord {
  readonly hostname: string;
  readonly tenantId: string;
  readonly site: string;
  /** `null` when the owner has never completed (or even started) a challenge. */
  readonly verification: {
    readonly state: SiteDomainVerificationState;
    readonly tokenExpiresAtUnix: number;
    readonly verificationExpiresAtUnix: number | undefined;
  } | null;
}

/** The seam the request path resolves an authority through. */
export interface SiteDomainDirectory {
  /** `null` hostname or an unknown one must answer `{ kind: "unbound" }`. */
  resolve(hostname: string, nowUnix: number): Promise<SiteDomainDecision>;
}

/**
 * The gate, as a PURE function, so the mutation proof has one line to attack
 * and the expiry rules are assertable without a database.
 *
 * Expiry is applied HERE, at read time, from `nowUnix` — never from a sweeper
 * and never from a cached verdict. `effectiveSiteDomainVerificationState` is
 * `@ferrogate/storage`'s own, not a second copy: an unredeemed challenge past
 * its 7-day TTL and a completed verification past its 90-day deadline both
 * resolve to `expired`, and `siteDomainVerificationStateServes` admits only
 * `verified` and the explicit `grandfathered` migration state.
 */
export function decideSiteDomain(
  record: SiteDomainRecord | null,
  nowUnix: number,
): SiteDomainDecision {
  if (record === null) return { kind: "unbound" };
  if (record.verification === null) {
    return { kind: "inactive", hostname: record.hostname, reason: "unproven" };
  }
  // Only the three fields below are read by `effectiveSiteDomainVerificationState`;
  // the rest of `StoredSiteDomainVerification` is evidence the SERVE path has no
  // business seeing (the challenge token above all), so it is neither selected
  // nor carried. The placeholders exist to satisfy the shared type, and no
  // branch of that function reads them.
  const verification: StoredSiteDomainVerification = {
    tenantId: record.tenantId,
    hostname: record.hostname,
    site: record.site,
    state: record.verification.state,
    challengeToken: "",
    issuedAtUnix: 0,
    tokenExpiresAtUnix: record.verification.tokenExpiresAtUnix,
    verificationExpiresAtUnix: record.verification.verificationExpiresAtUnix,
    attemptCount: 0,
    updatedAtUnix: 0,
  };
  const state = effectiveSiteDomainVerificationState(verification, nowUnix);
  if (!siteDomainVerificationStateServes(state)) {
    return { kind: "inactive", hostname: record.hostname, reason: state };
  }
  if (record.site.trim() === "") {
    // A proven hostname bound to no site names nothing to serve. Refusing is
    // the only honest answer: routing it to the empty slug would resolve inside
    // the caller's own tenant, which is how a verified hostname would come to
    // serve somebody else's bundle.
    return { kind: "inactive", hostname: record.hostname, reason: "unproven" };
  }
  return {
    kind: "route",
    route: { hostname: record.hostname, tenantId: record.tenantId, slug: record.site.trim() },
  };
}

/**
 * The authority as a lookup key: lowercased, port removed, trailing root dot
 * removed. Empty string for anything that cannot be a hostname.
 *
 * Normalization matters because the key is a security boundary. DNS names are
 * case-insensitive and `example.com.` is the same name as `example.com`, so a
 * `Host: EXAMPLE.COM.:8443` that failed to match its own `site_domains` row
 * would silently fall through to the API host — the fallback this module exists
 * to refuse.
 *
 * An IPv6 literal (`[::1]`) keeps its brackets and simply never matches a row;
 * it is not rewritten, because a bracketed literal is not a DNS name and must
 * not be able to alias one.
 */
export function normalizeSiteHostname(raw: string | null | undefined): string {
  if (typeof raw !== "string") return "";
  let host = raw.trim().toLowerCase();
  if (host === "") return "";
  if (host.startsWith("[")) {
    const close = host.indexOf("]");
    if (close === -1) return "";
    host = host.slice(0, close + 1);
  } else {
    const colon = host.indexOf(":");
    if (colon !== -1) host = host.slice(0, colon);
  }
  while (host.endsWith(".")) host = host.slice(0, -1);
  // An ALLOWLIST, not a denylist. A `/`, a space, an `@` or a raw CR/LF in a
  // Host header is a smuggling attempt rather than a hostname, and enumerating
  // the characters that are LEGAL in a DNS label — letters, digits, `-`, the
  // `.` that separates labels, and `_` because underscore labels exist in the
  // wild — is the only form of that check which cannot be widened by a
  // character nobody thought of. An IDN needs nothing extra: it reaches us
  // already punycoded as `xn--…`.
  if (host === "" || !/^[a-z0-9._-]+$/.test(host)) return "";
  return host;
}

/** What a verified hostname resolves to inside the site registry. */
export type SiteDomainBindingResolution =
  /** Serve this binding. Its `tenantId` is the tenant that PROVED the hostname. */
  | { readonly kind: "bound"; readonly binding: SiteBinding }
  /**
   * The operator has bound this slug to a DIFFERENT tenant. The request is
   * refused; see {@link siteDomainBinding}.
   */
  | { readonly kind: "tenant_mismatch"; readonly boundTenantId: string };

/**
 * THE FENCE — the same class of guard as `assertKeyBelongsToTenant`
 * (`apps/gateway/src/assets/keys.ts:194`), and the reason a hostname can never
 * resolve to another tenant's bundle.
 *
 * A custom domain contributes exactly one thing to resolution: a slug, plus the
 * identity of the tenant that proved it controls the hostname. Everything else
 * — the asset name, the CHANNEL, whether anonymous reads are allowed, the SPA
 * rewrite, the 404 document — is #737's `GATEWAY_SITES` binding, unchanged, so
 * a custom domain cannot become a way to read a site under settings the
 * operator never granted it.
 *
 * Three cases, and the middle one is the whole point:
 *
 *  1. **No operator binding for the slug.** A binding is SYNTHESIZED, pinned to
 *     the domain's own tenant. Pinning it is not a convenience: without it the
 *     slug would be "unbound", and #737's rule for an unbound slug is that it
 *     resolves inside the CALLER's tenant — so tenant B's credential would read
 *     tenant B's `docs` bundle on a hostname only tenant A ever proved. The
 *     synthesized binding is PRIVATE (`anonymous: false`), because a DNS proof
 *     is a claim about a hostname and not the operator's decision to publish a
 *     site to the entire internet; that decision stays exactly where #737 put
 *     it, and a verified domain therefore answers `401` until the operator opts
 *     the site in. Deliberate, and the alternative is a second, weaker path to
 *     anonymous serving.
 *  2. **An operator binding owned by a DIFFERENT tenant.** REFUSED. Not
 *     "prefer the domain", not "prefer the operator", not "fall back to the
 *     synthesized binding" — refused, because the two configurations disagree
 *     about who owns a name and every way of picking a winner silently serves
 *     one tenant's bytes on the other's authority. The refusal is the uniform
 *     `site_not_found`, so it discloses nothing about the other tenant either.
 *  3. **An operator binding owned by the SAME tenant.** Used as-is; this is how
 *     a custom domain gets a channel other than `latest`, an anonymous opt-in,
 *     or an SPA rewrite.
 */
export function siteDomainBinding(
  route: SiteDomainRoute,
  bindings: ReadonlyMap<string, SiteBinding>,
): SiteDomainBindingResolution {
  const configured = bindings.get(route.slug);
  if (configured === undefined) {
    return {
      kind: "bound",
      binding: {
        slug: route.slug,
        tenantId: route.tenantId,
        assetName: route.slug,
        channel: DEFAULT_SITE_CHANNEL,
        anonymous: false,
        spa: false,
        notFoundDocument: DEFAULT_SITE_NOT_FOUND_DOCUMENT,
      },
    };
  }
  if (configured.tenantId !== route.tenantId) {
    return { kind: "tenant_mismatch", boundTenantId: configured.tenantId };
  }
  return { kind: "bound", binding: configured };
}

/**
 * The joined read, exported so the mutation proof can assert the PREDICATE is
 * in the SQL the directory actually runs.
 *
 * `ON v.hostname = d.hostname AND v.tenant_id = d.tenant_id` is the fence, and
 * the second conjunct is the one that matters. `site_domain_verifications` is
 * keyed `(tenant_id, hostname)` precisely so that several tenants may hold a
 * challenge for one hostname; joining on hostname ALONE would let tenant B's
 * completed proof satisfy tenant A's binding, i.e. A would serve on a domain
 * only B ever proved it controls. `test/sites/domains.test.ts` drives exactly
 * that fixture and mutation-pins this line.
 *
 * `LEFT JOIN` and not an inner join, so a bound-but-unproven hostname arrives
 * here as a row with a NULL state and is REFUSED, rather than as no row at all
 * — which would be indistinguishable from an unclaimed hostname and would
 * therefore fall through to the gateway's own API routing.
 */
export const SITE_DOMAIN_ROUTE_SQL =
  "SELECT d.hostname AS hostname, d.tenant_id AS tenant_id, d.site AS site, " +
  "v.state AS state, v.token_expires_at_unix AS token_expires_at_unix, " +
  "v.verification_expires_at_unix AS verification_expires_at_unix " +
  "FROM site_domains d " +
  "LEFT JOIN site_domain_verifications v " +
  "  ON v.hostname = d.hostname AND v.tenant_id = d.tenant_id " +
  "WHERE d.hostname = ?";

/**
 * How long one isolate may reuse a `site_domains` READ.
 *
 * This is the "bounded, stated time" the issue asks for, and it bounds exactly
 * one thing: a change to the ROWS — an unbind, a re-bind, a fresh verification.
 * It does NOT bound expiry, because {@link decideSiteDomain} recomputes the
 * effective state from `nowUnix` on every request against the cached DEADLINES,
 * so a verification that lapses mid-window stops serving on the very next
 * request rather than at the end of the window.
 *
 * 60s is chosen against the alternative of no cache at all: without one, every
 * request to every authority — including the API host, which is almost all of
 * them — pays a control-database round trip before it is routed. With one, an
 * operator who unbinds a hostname is told the effect is visible within a minute
 * per isolate, which is a promise that can be kept.
 */
export const SITE_DOMAIN_CACHE_TTL_SECONDS = 60;

interface CacheEntry {
  readonly record: SiteDomainRecord | null;
  readonly expiresAtUnix: number;
}

/** The minimum a D1 handle must offer; keeps the tests free of a full mock. */
export interface SiteDomainDatabase {
  prepare(query: string): {
    bind(...values: unknown[]): { first<T>(): Promise<T | null> };
  };
}

interface SiteDomainRouteRow {
  hostname: string;
  tenant_id: string;
  site: string;
  state: string | null;
  token_expires_at_unix: number | null;
  verification_expires_at_unix: number | null;
}

/**
 * The control-database directory.
 *
 * ## Failure is `unbound`, on purpose
 *
 * A query that throws — the table is missing, the binding is wrong, D1 is down
 * — is reported as "this is not a site domain". That is the SAFE direction and
 * not the convenient one: it can never cause a hostname to be SERVED, only to
 * stop being served, and the alternative (fail closed for every authority)
 * would take the entire API down with the site feature. The failure is not
 * cached, so the next request retries.
 */
export class D1SiteDomainDirectory implements SiteDomainDirectory {
  readonly #db: SiteDomainDatabase;
  readonly #ttlSeconds: number;
  readonly #cache = new Map<string, CacheEntry>();

  constructor(db: SiteDomainDatabase, ttlSeconds: number = SITE_DOMAIN_CACHE_TTL_SECONDS) {
    this.#db = db;
    this.#ttlSeconds = ttlSeconds;
  }

  async resolve(hostname: string, nowUnix: number): Promise<SiteDomainDecision> {
    const key = normalizeSiteHostname(hostname);
    if (key === "") return { kind: "unbound" };
    const cached = this.#cache.get(key);
    if (cached !== undefined && cached.expiresAtUnix > nowUnix) {
      return decideSiteDomain(cached.record, nowUnix);
    }
    let record: SiteDomainRecord | null;
    try {
      record = await this.#read(key);
    } catch {
      // See the class docblock: an unreadable directory means "no custom
      // domains", never "every hostname is a custom domain".
      return { kind: "unbound" };
    }
    this.#cache.set(key, { record, expiresAtUnix: nowUnix + this.#ttlSeconds });
    return decideSiteDomain(record, nowUnix);
  }

  async #read(hostname: string): Promise<SiteDomainRecord | null> {
    const row = await this.#db
      .prepare(SITE_DOMAIN_ROUTE_SQL)
      .bind(hostname)
      .first<SiteDomainRouteRow>();
    if (row === null) return null;
    const state =
      typeof row.state === "string" ? siteDomainVerificationStateFromString(row.state) : undefined;
    return {
      hostname: row.hostname,
      tenantId: row.tenant_id,
      site: row.site,
      // An UNPARSEABLE state is not a servable one. A poisoned or
      // partially-migrated row must never be able to authorize a hostname.
      verification:
        state === undefined
          ? null
          : {
              state,
              tokenExpiresAtUnix: Number(row.token_expires_at_unix ?? 0),
              verificationExpiresAtUnix:
                row.verification_expires_at_unix === null
                  ? undefined
                  : Number(row.verification_expires_at_unix),
            },
    };
  }
}
