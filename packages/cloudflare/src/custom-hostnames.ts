/**
 * Cloudflare for SaaS **CUSTOM HOSTNAMES** — slice **S6**, the provisioning half
 * of #738.
 *
 * ## Why this product and not Workers Custom Domains
 *
 * Both mechanisms end with Cloudflare terminating TLS for `docs.acme.com` and
 * routing it to a Worker, and they are not interchangeable:
 *
 * | | Workers Custom Domains | Cloudflare for SaaS custom hostnames |
 * |---|---|---|
 * | where the hostname lives | a zone **in our account** | the **tenant's own** zone |
 * | who controls the DNS | we do | the tenant does, with a CNAME to our fallback origin |
 * | certificate | the zone's, managed | one **per hostname**, with its own DCV |
 * | per-hostname status | none — a zone-level cert says nothing about one name | `status` + `ssl.status` on a row keyed by hostname |
 * | scale | one route per Worker per zone | a hostname TABLE on one zone |
 *
 * FerroGate is multi-tenant and a tenant keeps its own DNS: `acme.com` is not,
 * and must not become, a zone in our account. Workers Custom Domains would
 * require every customer to hand us their zone, and — the part that decides it
 * for this issue — a zone-level certificate exposes **no per-hostname state**,
 * so `GET /admin/v1/site-domains/{hostname}` would have nothing to report.
 * Custom hostnames are the product built for exactly this shape, and the row
 * they create is the thing the issue's certificate bullet is asking for.
 *
 * **What it costs, stated plainly.** Cloudflare for SaaS is a paid entitlement
 * billed per active custom hostname; it needs a dedicated fallback-origin zone
 * in our account with a DNS record the tenant's CNAME can target, and the
 * Worker's routes must cover that origin. None of that is programmable from
 * here — see "deploy-time" below.
 *
 * ## This is a capability with ONE call site
 *
 * `apps/control-plane`'s `GET /admin/v1/site-domains/{hostname}` reads through
 * it to report a certificate state. Nothing on the data plane may consume it:
 * `apps/gateway` decides whether to serve from the typed `site_domains` /
 * `site_domain_verifications` rows, never from a certificate, and putting an
 * outbound Cloudflare call on the request path would be a availability
 * dependency on the API for every page view.
 *
 * ## The three load-bearing behaviours
 *
 * 1. **A `1406` duplicate is RECONCILED, not absorbed.** `r2.ts` maps an
 *    already-exists create onto success because an R2 bucket name is unique per
 *    ACCOUNT, so the duplicate is provably ours. A custom hostname is unique
 *    across **all of Cloudflare**, so `1406` means either "this zone already has
 *    it" (idempotent, fine) or "another account holds it" (no certificate will
 *    ever issue for us). {@link CustomHostnamesClient.ensureCustomHostname}
 *    therefore looks the hostname up in OUR zone and only reports a provision
 *    when it is there. Absorbing it the way R2 does would tell an operator their
 *    certificate is on the way when the name is held by somebody else.
 * 2. **`?hostname=` is a PARTIAL match and is re-checked.** Cloudflare's filter
 *    is a contains, not an equality, so the first row of a filtered page can be
 *    a different hostname entirely. Reporting its certificate state as this
 *    binding's would attribute somebody else's certificate to this tenant.
 * 3. **The status fold never guesses `active`.** An `ssl.status` this module
 *    does not classify folds to `unknown`, carrying the raw pair for triage.
 *    `active` is asserted only when the certificate is issued AND the hostname
 *    is routing — see {@link customHostnameCertificateState}.
 *
 * ## What is deploy-time and cannot be exercised here
 *
 * Everything upstream of the API call: the Cloudflare for SaaS entitlement, the
 * fallback-origin zone and its DNS record, the Worker route that covers it, the
 * tenant's CNAME, TLS termination and SNI. `workerd` under vitest has no TLS
 * terminator, no zone and no certificate authority, so no test in this package
 * is evidence that any of them work. What the tests DO hold is the request
 * shapes, the pagination walk, the duplicate reconcile and the fold.
 *
 * ## Wiring line
 *
 * From the control plane (never the request path):
 *
 * ```ts
 * const provision = await new CustomHostnamesClient(cf, zoneId)
 *   .ensureCustomHostname(hostname, { customMetadata: { tenant_id: tenant } });
 * ```
 */
import type { CloudflareClient } from "./client.js";
import { CloudflareError } from "./errors.js";

/**
 * `1406` — "Duplicate custom hostname found.", answered under HTTP 409.
 *
 * Deliberately a set of ONE. A bare 409 with any other code (or none) is a real
 * error and must surface: unlike R2's already-exists pair, this code does not
 * establish that the resource is ours, only that the NAME is taken somewhere on
 * Cloudflare. See behaviour (1) in the module docblock.
 */
export const CUSTOM_HOSTNAME_DUPLICATE_CODES: readonly number[] = [1406];

/**
 * Rows per page of the hostname list. Cloudflare defaults `per_page` to 20 on
 * this endpoint and caps it at 50; asking for the cap minimises calls against
 * the ~1,200 req / 5 min global limit. Page-NUMBERED, like D1's list and unlike
 * R2's cursor dialect.
 */
const CUSTOM_HOSTNAMES_PER_PAGE = 50;

/** The DCV method Cloudflare validates the certificate with. */
export type CustomHostnameValidationMethod = "http" | "txt" | "email";

/**
 * `txt` by default. `http` needs the hostname to already resolve to Cloudflare,
 * which on a first provision it does not; `email` needs a human to click a link.
 * A TXT record is the same kind of artefact the #488 ownership challenge already
 * asks the tenant for, so the operator instruction is one shape, twice.
 */
const DEFAULT_VALIDATION_METHOD: CustomHostnameValidationMethod = "txt";

/** Cloudflare's widest-compatibility chain. */
const DEFAULT_BUNDLE_METHOD = "ubiquitous";

/** TLS 1.0/1.1 are deprecated; 1.2 is the floor a new certificate should carry. */
const DEFAULT_MIN_TLS_VERSION = "1.2";

const ZONE_CUSTOM_HOSTNAMES_PATH = "custom_hostnames";

/** What {@link CustomHostnamesClient.createCustomHostname} sends. */
export interface CustomHostnameRequest {
  /** The exact hostname to certify. No wildcard — see {@link assertCustomHostname}. */
  readonly hostname: string;
  /** Defaults to `txt`. */
  readonly validationMethod?: CustomHostnameValidationMethod;
  /** `1.0`/`1.1`/`1.2`/`1.3`. Defaults to `1.2`. */
  readonly minTlsVersion?: string;
  /** `ubiquitous`/`optimal`/`force`. Defaults to `ubiquitous`. */
  readonly bundleMethod?: string;
  /** Opaque operator metadata Cloudflare echoes back on reads. */
  readonly customMetadata?: Readonly<Record<string, string>>;
}

/**
 * A `custom_hostnames` row. Every field is optional because Cloudflare's schema
 * makes them so, and because a partially-populated row must decode rather than
 * throw — an undecodable row would take the admin GET down over a field this
 * module does not use.
 */
export interface CustomHostname {
  readonly id?: string;
  readonly hostname?: string;
  readonly status?: string;
  readonly ssl?: {
    readonly id?: string;
    readonly type?: string;
    readonly method?: string;
    readonly status?: string;
    readonly validation_records?: readonly {
      readonly txt_name?: string;
      readonly txt_value?: string;
      readonly http_url?: string;
      readonly http_body?: string;
      readonly emails?: readonly string[];
    }[];
    readonly validation_errors?: readonly { readonly message?: string }[];
    readonly certificate_authority?: string;
    readonly expires_on?: string;
  };
  readonly ownership_verification?: {
    readonly type?: string;
    readonly name?: string;
    readonly value?: string;
  };
  readonly verification_errors?: readonly string[];
  readonly custom_metadata?: Readonly<Record<string, string>>;
  readonly created_at?: string;
}

/** A record the tenant must publish for Cloudflare's own DCV to complete. */
export interface CustomHostnameValidationRecord {
  readonly name: string;
  readonly type: string;
  readonly value: string;
}

/**
 * The operator-facing certificate state.
 *
 * Every value names a DIFFERENT next action, which is the whole reason this is
 * not a boolean:
 *
 * | state | what is true | what the operator does |
 * |---|---|---|
 * | `active` | certificate issued AND the hostname routes here | nothing — the domain serves |
 * | `pending_validation` | Cloudflare is waiting on the DCV record | give the tenant `validationRecords` to publish; **requests fail TLS until then** |
 * | `provisioning` | validation passed, issuance/deployment in flight | wait (minutes) |
 * | `issued_not_routing` | the certificate is live, the hostname is not | fix the tenant's CNAME to the fallback origin — TLS is NOT the problem |
 * | `timed_out` | Cloudflare gave up after its backoff schedule | fix DNS, then PATCH the row to restart validation |
 * | `expired` | the certificate lapsed | re-validate |
 * | `blocked` | Cloudflare refused the hostname | it collides with a zone elsewhere on Cloudflare; support |
 * | `inactive` | deleted / deleting / deactivating | re-provision |
 * | `unknown` | a pair this module does not classify | read the raw `hostnameStatus`/`sslStatus` |
 *
 * `unknown` is deliberately not a synonym for "broken" and never for "fine": it
 * is the answer for a Cloudflare status this code has not been taught, and
 * folding it either way would be a guess presented as a fact.
 */
export type CustomHostnameCertificateState =
  | "active"
  | "pending_validation"
  | "provisioning"
  | "issued_not_routing"
  | "timed_out"
  | "expired"
  | "blocked"
  | "inactive"
  | "unknown";

/** {@link customHostnameCertificateState}'s answer. */
export interface CustomHostnameCertificate {
  readonly state: CustomHostnameCertificateState;
  /** Cloudflare's raw hostname activation status, for triage. */
  readonly hostnameStatus?: string;
  /** Cloudflare's raw `ssl.status`, for triage. */
  readonly sslStatus?: string;
  /** Validation errors / verification errors, joined. */
  readonly detail?: string;
  /** What the tenant must publish, when the state is `pending_validation`. */
  readonly validationRecords?: readonly CustomHostnameValidationRecord[];
}

/** The outcome of {@link CustomHostnamesClient.ensureCustomHostname}. */
export interface CustomHostnameProvision {
  readonly hostname: string;
  /** The Cloudflare row id, for a later PATCH/DELETE. */
  readonly id: string;
  /** `true` when THIS call created the row; `false` when it already existed. */
  readonly created: boolean;
  readonly certificate: CustomHostnameCertificate;
}

/** `ssl.status` values that mean Cloudflare is working and nobody must act. */
const SSL_PROVISIONING = new Set([
  "initializing",
  "pending_issuance",
  "pending_deployment",
  "staging_deployment",
  "staging_active",
  "pending_cleanup",
]);

/** `ssl.status` values where Cloudflare stopped trying. */
const SSL_TIMED_OUT = new Set([
  "initializing_timed_out",
  "validation_timed_out",
  "issuance_timed_out",
  "deployment_timed_out",
  "deletion_timed_out",
]);

const SSL_EXPIRED = new Set(["expired", "pending_expiration"]);

const SSL_INACTIVE = new Set(["deleted", "pending_deletion", "deactivating", "inactive"]);

/** Hostname statuses that route traffic here. */
const HOSTNAME_ROUTING = new Set(["active", "active_redeploying"]);

/** Hostname statuses that do not route yet but are not a refusal. */
const HOSTNAME_NOT_ROUTING = new Set([
  "pending",
  "pending_provisioned",
  "pending_migration",
  "moved",
]);

const HOSTNAME_BLOCKED = new Set(["blocked", "pending_blocked"]);

const HOSTNAME_GONE = new Set(["deleted", "pending_deletion"]);

/**
 * Fold a `custom_hostnames` row into one operator-facing state.
 *
 * The certificate is read FIRST because it is the harder gate: a request cannot
 * complete TLS without it, whatever the hostname status says. Only once the
 * certificate is `active` does the hostname status decide between `active` and
 * `issued_not_routing` — the distinction a boolean erases, and the one an
 * operator is usually staring at, because "the certificate is fine, your CNAME
 * is not" and "wait for the certificate" have nothing in common as instructions.
 *
 * `backup_issued` and `holding_deployment` fold to `unknown` rather than to
 * anything cheerier: both describe a NEW certificate held back from deployment,
 * and say nothing about the one currently serving. Calling either `active`
 * would assert something the response does not contain.
 */
export function customHostnameCertificateState(record: CustomHostname): CustomHostnameCertificate {
  const hostnameStatus = typeof record.status === "string" ? record.status : undefined;
  const sslStatus = typeof record.ssl?.status === "string" ? record.ssl.status : undefined;
  const base = {
    ...(hostnameStatus === undefined ? {} : { hostnameStatus }),
    ...(sslStatus === undefined ? {} : { sslStatus }),
    ...(detailOf(record) === undefined ? {} : { detail: detailOf(record) as string }),
  };
  const validationRecords = validationRecordsOf(record);
  const withRecords = validationRecords.length === 0 ? base : { ...base, validationRecords };

  const state = ((): CustomHostnameCertificateState => {
    if (sslStatus === undefined) return "unknown";
    if (sslStatus === "pending_validation") return "pending_validation";
    if (SSL_PROVISIONING.has(sslStatus)) return "provisioning";
    if (SSL_TIMED_OUT.has(sslStatus)) return "timed_out";
    if (SSL_EXPIRED.has(sslStatus)) return "expired";
    if (SSL_INACTIVE.has(sslStatus)) return "inactive";
    if (sslStatus !== "active") return "unknown";
    // The certificate is live. Now — and only now — does routing decide.
    if (hostnameStatus === undefined) return "unknown";
    if (HOSTNAME_BLOCKED.has(hostnameStatus)) return "blocked";
    if (HOSTNAME_GONE.has(hostnameStatus)) return "inactive";
    if (HOSTNAME_ROUTING.has(hostnameStatus)) return "active";
    if (HOSTNAME_NOT_ROUTING.has(hostnameStatus)) return "issued_not_routing";
    return "unknown";
  })();

  return { state, ...withRecords };
}

function detailOf(record: CustomHostname): string | undefined {
  const parts = [
    ...(record.ssl?.validation_errors ?? []).map((entry) => entry.message ?? ""),
    ...(record.verification_errors ?? []),
  ].filter((message) => message !== "");
  return parts.length === 0 ? undefined : parts.join("; ");
}

function validationRecordsOf(record: CustomHostname): readonly CustomHostnameValidationRecord[] {
  const out: CustomHostnameValidationRecord[] = [];
  for (const entry of record.ssl?.validation_records ?? []) {
    if (entry.txt_name !== undefined && entry.txt_value !== undefined) {
      out.push({ name: entry.txt_name, type: "txt", value: entry.txt_value });
    } else if (entry.http_url !== undefined && entry.http_body !== undefined) {
      out.push({ name: entry.http_url, type: "http", value: entry.http_body });
    }
  }
  const ownership = record.ownership_verification;
  if (ownership?.name !== undefined && ownership.value !== undefined) {
    out.push({ name: ownership.name, type: ownership.type ?? "txt", value: ownership.value });
  }
  return out;
}

/** The zone-scoped custom-hostname surface over the shared client. */
export class CustomHostnamesClient {
  /**
   * `zoneId` is the FALLBACK-ORIGIN zone in our account — the one every tenant
   * CNAMEs at — never the tenant's zone. It is a constructor argument rather
   * than a `{zone_id}` template on {@link CloudflareClient} because the shared
   * client is account-scoped and only templates `{account_id}`; a zone is a
   * per-call-site decision.
   */
  constructor(
    private readonly client: CloudflareClient,
    private readonly zoneId: string,
  ) {}

  /**
   * Create a custom hostname and start Cloudflare's DCV.
   *
   * Retry is opted IN. A hostname is globally unique, so a re-issued create
   * after a 5xx cannot mint a SECOND certificate — it either succeeds or reports
   * the duplicate, which {@link ensureCustomHostname} then reconciles. That is
   * the same argument `d1.ts` makes and the one `r2-token.ts` cannot make.
   */
  async createCustomHostname(request: CustomHostnameRequest): Promise<CustomHostname> {
    assertCustomHostname(request.hostname);
    const body: Record<string, unknown> = {
      hostname: request.hostname,
      ssl: {
        method: request.validationMethod ?? DEFAULT_VALIDATION_METHOD,
        // Cloudflare accepts only `dv` here and says so in the schema. Spelled
        // out rather than omitted so the request is self-describing.
        type: "dv",
        bundle_method: request.bundleMethod ?? DEFAULT_BUNDLE_METHOD,
        settings: { min_tls_version: request.minTlsVersion ?? DEFAULT_MIN_TLS_VERSION },
      },
    };
    if (request.customMetadata !== undefined) body.custom_metadata = request.customMetadata;
    return this.client.requestJson<CustomHostname>("POST", this.#collectionPath(), {
      body,
      idempotent: true,
    });
  }

  /**
   * List **all** custom hostnames on the zone, walking pages beyond the first.
   *
   * Terminates once a page returns fewer rows than `per_page`, exactly like
   * D1's page-numbered list. Without the walk, "absent" would mean "not on
   * page 1" — which on a SaaS zone with thousands of hostnames is almost
   * always.
   */
  async listCustomHostnames(hostnameFilter?: string): Promise<CustomHostname[]> {
    if (hostnameFilter !== undefined) assertCustomHostname(hostnameFilter);
    const rows: CustomHostname[] = [];
    let page = 1;
    for (;;) {
      const filter = hostnameFilter === undefined ? "" : `&hostname=${hostnameFilter}`;
      const batch = await this.client.getJson<CustomHostname[]>(
        `${this.#collectionPath()}?per_page=${CUSTOM_HOSTNAMES_PER_PAGE}&page=${page}${filter}`,
      );
      rows.push(...batch);
      if (batch.length < CUSTOM_HOSTNAMES_PER_PAGE) return rows;
      page += 1;
    }
  }

  /**
   * The row for EXACTLY this hostname, or `null`.
   *
   * The server-side `?hostname=` filter is a CONTAINS match, so the equality
   * re-check below is the load-bearing line: without it a query for
   * `docs.acme.com` can be answered by `docs.acme.com.attacker.test`, and this
   * binding would be reported with a certificate state belonging to somebody
   * else's hostname.
   */
  async findCustomHostname(hostname: string): Promise<CustomHostname | null> {
    assertCustomHostname(hostname);
    const rows = await this.listCustomHostnames(hostname);
    return rows.find((row) => row.hostname === hostname) ?? null;
  }

  /** Delete a custom hostname row **and its certificate**, by Cloudflare id. */
  async deleteCustomHostname(id: string): Promise<void> {
    await this.client.requestAck("DELETE", this.#itemPath(id), { idempotent: true });
  }

  /**
   * Create-if-absent, and report the certificate state either way.
   *
   * Safe to call on every bind/verify. The duplicate path is the interesting
   * one: see behaviour (1) in the module docblock for why a `1406` is
   * reconciled against our own zone rather than absorbed into success.
   */
  async ensureCustomHostname(
    hostname: string,
    options: Omit<CustomHostnameRequest, "hostname"> = {},
  ): Promise<CustomHostnameProvision> {
    assertCustomHostname(hostname);
    let row: CustomHostname;
    let created: boolean;
    try {
      row = await this.createCustomHostname({ hostname, ...options });
      created = true;
    } catch (error) {
      if (!isDuplicateHostname(error)) throw error;
      const existing = await this.findCustomHostname(hostname);
      if (existing === null) {
        throw CloudflareError.config(
          `custom hostname ${JSON.stringify(hostname)} is already registered on Cloudflare but ` +
            `is not on zone ${JSON.stringify(this.zoneId)}: it is held by another Cloudflare ` +
            "account or zone, and no certificate can be issued for it here until that record is " +
            "released",
        );
      }
      row = existing;
      created = false;
    }
    return {
      hostname,
      id: row.id ?? "",
      created,
      certificate: customHostnameCertificateState(row),
    };
  }

  #collectionPath(): string {
    return `zones/${assertZoneId(this.zoneId)}/${ZONE_CUSTOM_HOSTNAMES_PATH}`;
  }

  #itemPath(id: string): string {
    if (id === "" || !/^[a-zA-Z0-9-]+$/.test(id)) {
      throw CloudflareError.config(
        `invalid custom hostname id ${JSON.stringify(id)}: expected a Cloudflare uuid`,
      );
    }
    return `${this.#collectionPath()}/${id}`;
  }
}

/**
 * Whether a create failure is Cloudflare's duplicate-hostname answer.
 *
 * Code-specific, not status-specific, for the reason `r2.ts` argues: a bare 409
 * (a hostname mid-deletion, a zone-level conflict) is a real error. The
 * difference from R2 is what happens NEXT — this predicate only says "the name
 * is taken somewhere", never "it is ours".
 */
function isDuplicateHostname(error: unknown): boolean {
  return (
    error instanceof CloudflareError &&
    error.kind === "api" &&
    error.errors.some((entry) => CUSTOM_HOSTNAME_DUPLICATE_CODES.includes(entry.code))
  );
}

/**
 * Reject a zone id that could escape the path segment. Cloudflare zone ids are
 * 32 hex characters; the check is the looser "path-safe" one the sibling
 * modules use, because rejecting a well-formed id Cloudflare later widens would
 * be a worse failure than a caller bug surfaced one call later.
 */
function assertZoneId(zoneId: string): string {
  if (zoneId === "" || !/^[a-zA-Z0-9]+$/.test(zoneId)) {
    throw CloudflareError.config(
      `invalid Cloudflare zone id ${JSON.stringify(zoneId)}: expected a hexadecimal zone id`,
    );
  }
  return zoneId;
}

/**
 * Reject anything that is not a plain, fully-qualified, lowercase DNS name.
 *
 * Three of these are more than hygiene:
 *
 *  - **no wildcard.** `*.acme.com` would obtain a certificate covering names for
 *    which no #488 ownership proof exists, so the platform would hold TLS for
 *    hostnames nobody proved control of. Cloudflare supports wildcard custom
 *    hostnames; FerroGate deliberately does not use them.
 *  - **no `:` `/` `?` `#` or whitespace.** The hostname is spliced into a query
 *    string by {@link CustomHostnamesClient.listCustomHostnames}; a charset this
 *    narrow is what makes that splice safe without an encoder.
 *  - **lowercase only.** DNS names are case-insensitive but Cloudflare's row is
 *    stored lowercase, and the exact-equality re-check in
 *    {@link CustomHostnamesClient.findCustomHostname} compares strings. A
 *    mixed-case argument would silently never match. Normalising it here would
 *    hide a caller that is not normalising its own storage key.
 */
function assertCustomHostname(hostname: string): void {
  const legal =
    hostname.length > 0 &&
    hostname.length <= 255 &&
    /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(hostname);
  if (!legal) {
    throw CloudflareError.config(
      `invalid custom hostname ${JSON.stringify(hostname)}: expected a lowercase, fully ` +
        "qualified DNS name with no wildcard, scheme, port or path",
    );
  }
}
