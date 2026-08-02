/**
 * The CERTIFICATE half of a custom domain (#738) — the seam
 * `GET /admin/v1/site-domains/{hostname}` reports `certificate_status` through.
 *
 * ## Why a binding cannot answer this, and why it is not a boolean
 *
 * `apps/gateway` serves a verified custom domain through the same `SiteServer`
 * the slug route uses — but a Worker only ever SEES a request for
 * `docs.acme.com` if Cloudflare terminated TLS for that hostname and routed it
 * there. That is a Cloudflare-for-SaaS **custom hostname** on the
 * fallback-origin zone, and it lives in an account-management API no Worker
 * binding exposes. Until this seam existed, an operator who completed the #488
 * DNS proof in FerroGate still had to go configure Cloudflare by hand, and
 * nothing in the product could tell them whether the certificate had issued:
 * the first request on the domain failed, and the admin API could not explain
 * why.
 *
 * A boolean would erase exactly the distinction that matters. Five of the
 * states below are "the domain does not work yet" and **each of them has a
 * different next action** — publish a DCV record, wait, fix a CNAME, restart
 * validation, contact support. Collapsing them into `ready: false` would send
 * an operator to the wrong one four times out of five.
 *
 * ## The certificate is INDEPENDENT of the ownership proof
 *
 * The #488 challenge proves that a tenant controls a hostname *to FerroGate*.
 * Cloudflare's DCV proves control *to a certificate authority*. Neither implies
 * the other, and the gateway gates serving on the FerroGate proof ALONE:
 *
 *  - proof + no certificate → the request never arrives (TLS fails at the edge);
 *  - certificate + no proof → the request arrives and is refused `421`.
 *
 * So nothing here may ever feed a serving decision. This module is
 * OPERATOR INFORMATION, and that is why a deterministic backend is safe here in
 * a way {@link SiteDomainTxtResolver}'s never could be — a wrong certificate
 * state misleads a human, it does not authorise a request.
 *
 * ## Read-through, and what that costs
 *
 * {@link CloudflareForSaasCertificates} calls Cloudflare on every admin GET
 * rather than caching a status on the row. A cached status is wrong exactly
 * when it matters — an operator refreshes the page BECAUSE the state is
 * changing — and there is no event to invalidate it on. The cost is one
 * outbound call per admin read of ONE binding, against Cloudflare's ~1,200
 * req / 5 min budget; the LIST operation deliberately does not do it, because N
 * bindings would be N calls.
 *
 * The default backend makes no call at all, so no deployment acquires outbound
 * traffic by upgrading.
 */
import {
  CloudflareClient,
  type CustomHostname,
  CustomHostnamesClient,
  EnvTokenResolver,
  customHostnameCertificateState,
} from "@ferrogate/cloudflare";

/**
 * What an operator is told, and what they do about it.
 *
 * The first three are this module's own; the rest are
 * `customHostnameCertificateState`'s fold of Cloudflare's `(status,
 * ssl.status)` pair, re-exported as one flat enum so a client switches once.
 *
 * | value | meaning | operator action |
 * |---|---|---|
 * | `unconfigured` | this deployment has no certificate backend bound | FerroGate cannot tell you; configure one, or read the Cloudflare dashboard |
 * | `not_provisioned` | no custom-hostname row exists for this hostname | provision it — **the domain cannot serve** |
 * | `unavailable` | the backend could not be reached or could not answer | retry; the state is UNKNOWN and is deliberately not folded either way |
 * | `pending_validation` | Cloudflare is waiting for its DCV record | give the tenant `validation_records` to publish |
 * | `provisioning` | validation passed, issuance/deployment in flight | wait |
 * | `issued_not_routing` | certificate live, hostname not routing here | fix the tenant's CNAME — TLS is not the problem |
 * | `active` | issued AND routing | none; the domain serves |
 * | `timed_out` | Cloudflare stopped retrying validation | fix DNS, restart validation |
 * | `expired` | the certificate lapsed | re-validate |
 * | `blocked` | Cloudflare refused the hostname | it collides elsewhere on Cloudflare; support |
 * | `inactive` | deleted / deleting / deactivating | re-provision |
 * | `unknown` | a Cloudflare status this code does not classify | read `ssl_status` / `hostname_status` |
 */
export type SiteDomainCertificateStatus =
  | "unconfigured"
  | "not_provisioned"
  | "unavailable"
  | "pending_validation"
  | "provisioning"
  | "issued_not_routing"
  | "active"
  | "timed_out"
  | "expired"
  | "blocked"
  | "inactive"
  | "unknown";

/** A record the tenant must publish for Cloudflare's own validation. */
export interface SiteDomainCertificateRecord {
  readonly name: string;
  readonly type: string;
  readonly value: string;
}

/** One certificate reading, as the admin GET serialises it. */
export interface SiteDomainCertificate {
  readonly status: SiteDomainCertificateStatus;
  /** Which backend answered — named in the response so a reading is traceable. */
  readonly backend: string;
  /** Cloudflare's raw hostname activation status, when there is one. */
  readonly hostnameStatus?: string;
  /** Cloudflare's raw `ssl.status`, when there is one. */
  readonly sslStatus?: string;
  /** Validation errors, or the reason a lookup was `unavailable`. */
  readonly detail?: string;
  readonly validationRecords?: readonly SiteDomainCertificateRecord[];
}

/** The certificate lookup seam. */
export interface SiteDomainCertificatePort {
  /** Stable identifier surfaced in the admin response. */
  readonly backendName: string;
  certificateFor(hostname: string): Promise<SiteDomainCertificate>;
}

/**
 * The DEFAULT: no certificate backend is bound, so nothing is known.
 *
 * `unconfigured` is deliberately its own value and not `not_provisioned`. "We
 * did not look" and "we looked and there is nothing there" send an operator to
 * different places, and a deployment that provisions its custom hostnames out
 * of band (or through Workers Custom Domains, whose per-hostname certificate
 * state lives behind a DIFFERENT API this module does not read — see
 * `packages/cloudflare/src/custom-hostnames.ts`) is in the first state
 * permanently and correctly.
 */
export class UnconfiguredSiteDomainCertificates implements SiteDomainCertificatePort {
  readonly backendName = "unconfigured";

  async certificateFor(): Promise<SiteDomainCertificate> {
    return {
      status: "unconfigured",
      backend: this.backendName,
      detail:
        "no site-domain certificate backend is configured on this deployment; set " +
        "SITE_DOMAIN_CERTIFICATES to read certificate state from Cloudflare",
    };
  }
}

/**
 * The real one: Cloudflare for SaaS custom hostnames on the fallback-origin
 * zone, read through `@ferrogate/cloudflare`'s `CustomHostnamesClient`.
 *
 * A lookup FAILURE is `unavailable`, never `not_provisioned` — see
 * {@link readCertificate}, which is where that rule now lives for BOTH backends.
 * Folding a 5xx or an expired token into "no certificate exists" would tell an
 * operator to re-provision a hostname that is already live — the same
 * fail-visible rule `site_domain_txt.ts` applies to a DNS resolver that cannot
 * answer, and for the same reason.
 */
export class CloudflareForSaasCertificates implements SiteDomainCertificatePort {
  readonly backendName = "cloudflare_for_saas";

  constructor(private readonly hostnames: CustomHostnamesClient) {}

  certificateFor(hostname: string): Promise<SiteDomainCertificate> {
    return readCertificate(
      this.backendName,
      () => this.hostnames.findCustomHostname(hostname),
      `no Cloudflare custom hostname exists for ${hostname} on the configured zone`,
    );
  }
}

/**
 * The DETERMINISTIC backend — the role `StaticAnswersTxtResolver` plays for DNS.
 *
 * Reads a JSON map of `hostname → custom_hostnames row` (Cloudflare's own
 * result shape) and runs it through the SAME fold the live backend uses, so the
 * mapping from a real Cloudflare payload to an operator-facing state is
 * exercisable in a tree that can never reach the Cloudflare API.
 *
 * Unlike the TXT resolver's static backend this one cannot be a bypass of
 * anything: no certificate state gates serving (see the module docblock), so
 * the worst a wrong entry can do is mislead the operator who wrote it.
 *
 * An unparseable document is `unavailable` for every hostname, not
 * `not_provisioned` — a typo in operator configuration must not read as "your
 * certificate does not exist".
 */
export class StaticSiteDomainCertificates implements SiteDomainCertificatePort {
  readonly backendName = "static";
  readonly #rows: ReadonlyMap<string, CustomHostname> | null;
  readonly #parseError: string | null;

  constructor(document: string | undefined) {
    const parsed = parseRows(document);
    this.#rows = parsed.rows;
    this.#parseError = parsed.error;
  }

  certificateFor(hostname: string): Promise<SiteDomainCertificate> {
    return readCertificate(
      this.backendName,
      async () => {
        // A document this backend could not parse is a lookup that cannot
        // ANSWER, not one that answered "nothing here" — so it is raised, and
        // {@link readCertificate} applies the one rule that turns that into
        // `unavailable`. Returning `null` here would silently reclassify an
        // operator's typo as "your certificate does not exist".
        if (this.#rows === null) {
          throw new Error(`SITE_DOMAIN_CERTIFICATE_RECORDS could not be read: ${this.#parseError}`);
        }
        return this.#rows.get(hostname) ?? null;
      },
      `no certificate record is configured for ${hostname}`,
    );
  }
}

/**
 * The three "not-a-yes" answers, decided ONCE for every backend.
 *
 * This used to be written out separately in each backend, and the copies were
 * the risk: `unavailable` vs `not_provisioned` is the distinction the module
 * docblock argues is load-bearing ("we could not look" sends an operator to
 * retry, "we looked and there is nothing there" sends them to provision), and
 * two spellings of a rule that subtle is how the two answers drift apart —
 * exactly the way that pins the states on whichever backend the tests happen to
 * construct rather than on the one that answers in production.
 *
 *  - the lookup THREW → `unavailable`, carrying the failure's own message. The
 *    state is UNKNOWN and is deliberately not folded either way.
 *  - the lookup returned `null` → `not_provisioned`, with the backend's own
 *    sentence about where it looked.
 *  - a row → `@ferrogate/cloudflare`'s fold, which is the only thing that may
 *    ever answer `active`.
 */
async function readCertificate(
  backend: string,
  lookup: () => Promise<CustomHostname | null>,
  absentDetail: string,
): Promise<SiteDomainCertificate> {
  let row: CustomHostname | null;
  try {
    row = await lookup();
  } catch (error) {
    return {
      status: "unavailable",
      backend,
      detail: error instanceof Error ? error.message : String(error),
    };
  }
  // Deliberately OUTSIDE the try: the fold is this module's own code, and a bug
  // in it must surface as a 500 rather than be reported to an operator as a
  // Cloudflare outage.
  if (row === null) {
    return { status: "not_provisioned", backend, detail: absentDetail };
  }
  return fromCustomHostname(row, backend);
}

function parseRows(document: string | undefined): {
  rows: ReadonlyMap<string, CustomHostname> | null;
  error: string | null;
} {
  if (document === undefined || document.trim() === "") {
    return { rows: new Map(), error: null };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(document) as unknown;
  } catch (error) {
    return { rows: null, error: error instanceof Error ? error.message : String(error) };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { rows: null, error: "expected a JSON object keyed by hostname" };
  }
  const rows = new Map<string, CustomHostname>();
  for (const [hostname, row] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof row === "object" && row !== null && !Array.isArray(row)) {
      rows.set(hostname, row as CustomHostname);
    }
  }
  return { rows, error: null };
}

/** One Cloudflare row → one admin reading, through the package's own fold. */
function fromCustomHostname(row: CustomHostname, backend: string): SiteDomainCertificate {
  const folded = customHostnameCertificateState(row);
  return {
    status: folded.state,
    backend,
    ...(folded.hostnameStatus === undefined ? {} : { hostnameStatus: folded.hostnameStatus }),
    ...(folded.sslStatus === undefined ? {} : { sslStatus: folded.sslStatus }),
    ...(folded.detail === undefined ? {} : { detail: folded.detail }),
    ...(folded.validationRecords === undefined
      ? {}
      : { validationRecords: folded.validationRecords }),
  };
}

/** The env this seam reads. Kept narrow so the drift gate can see every name. */
export interface SiteDomainCertificateBindings {
  readonly SITE_DOMAIN_CERTIFICATES?: string;
  readonly SITE_DOMAIN_CERTIFICATE_RECORDS?: string;
  readonly SITE_DOMAIN_CF_ZONE_ID?: string;
  readonly SITE_DOMAIN_CF_ACCOUNT_ID?: string;
  readonly SITE_DOMAIN_CF_API_TOKEN?: string;
}

/**
 * Pick the certificate backend.
 *
 * Same polarity as `resolveTxtResolver`: the DEFAULT is the one that knows
 * nothing. Reading certificate state is an explicit act because it spends an
 * outbound API call and a Cloudflare token, and a deployment that has neither
 * must not start making calls because it upgraded.
 *
 * `cloudflare_for_saas` with an incomplete configuration falls back to
 * {@link UnconfiguredSiteDomainCertificates} rather than constructing a client
 * that will fail every call: a missing zone id is an operator mistake, and
 * `unconfigured` names it, where a stream of `unavailable`s would look like a
 * Cloudflare outage.
 */
export function resolveSiteDomainCertificates(
  env: SiteDomainCertificateBindings,
): SiteDomainCertificatePort {
  switch (env.SITE_DOMAIN_CERTIFICATES?.trim().toLowerCase()) {
    case "cloudflare_for_saas": {
      const zoneId = env.SITE_DOMAIN_CF_ZONE_ID?.trim() ?? "";
      const accountId = env.SITE_DOMAIN_CF_ACCOUNT_ID?.trim() ?? "";
      const token = env.SITE_DOMAIN_CF_API_TOKEN?.trim() ?? "";
      if (zoneId === "" || accountId === "" || token === "") {
        return new UnconfiguredSiteDomainCertificates();
      }
      return new CloudflareForSaasCertificates(
        new CustomHostnamesClient(
          new CloudflareClient({
            // The token arrives as a Worker SECRET binding, so it is already
            // plaintext here and is passed inline. `EnvTokenResolver` treats a
            // reference with no scheme as exactly that; the `env://` form is for
            // the CLI and the deploy scripts, which have no bindings.
            config: { accountId, tokenReference: token },
            resolver: new EnvTokenResolver({}),
          }),
          zoneId,
        ),
      );
    }
    case "static":
      return new StaticSiteDomainCertificates(env.SITE_DOMAIN_CERTIFICATE_RECORDS);
    default:
      return new UnconfiguredSiteDomainCertificates();
  }
}
