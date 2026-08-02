/**
 * R2 **bucket provisioning** — slice **S1**.
 *
 * Ported from `crates/ferrogate-cloudflare/src/r2.rs`. No Worker binding can
 * create an R2 bucket: provisioning is an account-MANAGEMENT operation, so this
 * does not collapse into `env.ASSETS` the way the object data plane does.
 *
 * ## Mount status — read before wiring
 *
 * The deployed TS asset path does NOT use bucket-per-tenant. `apps/gateway/src/
 * assets` uses ONE bucket and isolates tenants by key prefix, enforced in
 * application code (`assertKeyBelongsToTenant`). The Rust production path had
 * the same posture. So this module is a **capability with no call site yet**,
 * and it must stay that way until a bucket-per-tenant decision is actually
 * taken — porting it was in scope; mounting it speculatively is not, and R2 is
 * not even enabled on the live account today.
 *
 * The wiring line, when that decision is taken, is in a control-plane tenant
 * ONBOARDING handler (never the request path):
 *
 * ```ts
 * const provision = await new R2Client(cf).ensureTenantBucket(tenantId);
 * ```
 *
 * ## The three load-bearing behaviours
 *
 * 1. **{@link r2BucketNameForTenant} must be injective.** The bucket IS the
 *    per-tenant asset boundary: two tenants that derive one name read and
 *    overwrite each other's objects, and slice S2 would then scope a
 *    "per-tenant" credential to a SHARED bucket. R2 names cannot carry a raw
 *    tenant id (`[a-z0-9-]`, 3–63 chars), so any direct embedding must fold
 *    characters and truncate — and folding plus truncation are exactly the two
 *    ways to lose injectivity. An earlier derivation lost it both ways.
 * 2. **Idempotent create is narrowed to two documented codes**, not "any 409".
 * 3. **The list walks the cursor.** Without it "absent" means "not on page 1".
 *
 * ## No legacy-name compatibility surface
 *
 * There is deliberately NO helper computing a pre-injective name and NO
 * dual-read fallback. A fallback would resolve two tenants that folded to one
 * legacy name back onto that one shared bucket — reintroducing exactly the
 * cross-tenant read/write the derivation fixed. Nothing has ever been
 * provisioned under a tenant-derived name by either tree, so there is nothing
 * to migrate; `docs/rewrite/cf-crate-assessment.md` §5.1 records what a
 * migration would owe if a legacy bucket is ever found (in particular: the REST
 * surface is control plane only and cannot move a single object).
 */
import type { CloudflareClient } from "./client.js";
import { nextCursor } from "./envelope.js";
import { CloudflareError } from "./errors.js";

const R2_BUCKETS_PATH = "accounts/{account_id}/r2/buckets";

/**
 * Rows per page of the bucket list. Cloudflare defaults `per_page` to 20 and
 * caps it at 1,000; asking for the cap minimises the request count against the
 * ~1,200 req / 5 min global limit. If the server clamps it, correctness is
 * unaffected — the cursor is followed either way.
 */
const R2_BUCKETS_PER_PAGE = 1000;

/** R2's hard bucket-name bounds (Cloudflare R2 docs, "Create new buckets"). */
export const R2_BUCKET_NAME_MAX_LEN = 63;
/** See {@link R2_BUCKET_NAME_MAX_LEN}. */
export const R2_BUCKET_NAME_MIN_LEN = 3;

/** Readable leading tag; also what guarantees the name starts with a letter. */
const R2_TENANT_BUCKET_PREFIX = "ferrogate-";

/**
 * Domain-separation tag mixed into the hashed tenant identity. Bumping the `v1`
 * suffix renames every tenant's bucket — that is a **migration**, never a
 * refactor.
 */
const R2_TENANT_BUCKET_DIGEST_DOMAIN = "ferrogate.r2.bucket.v1";

/** 32 hex chars = 128 bits, a ~2^64 birthday bound. ALL of the collision
 * resistance lives here — not in the readable slug. */
const R2_TENANT_BUCKET_DIGEST_HEX_LEN = 32;

/** Sized so `prefix(10) + slug(20) + '-'(1) + digest(32) === 63`, R2's exact max. */
const R2_TENANT_BUCKET_SLUG_MAX_LEN = 20;

/**
 * "The bucket you asked to create already exists and is owned by this account"
 * — the idempotent-create success case, and the ONLY failure absorbed into a
 * success.
 *
 * `10004` is the account REST API's duplicate-create code; `10073` is the
 * S3-compatible `BucketConflict` sibling. The HTTP status alone is NOT
 * sufficient in either direction: Cloudflare also answers the duplicate create
 * with `success:false` + `10004` under **HTTP 200**, and a BARE 409 (a bucket
 * mid-deletion, a jurisdiction conflict, a name held elsewhere) must surface as
 * an error — because `already_exists` is reported to the caller as
 * *provisioned*, and slice S2 then mints a read+write credential against that
 * name.
 */
export const R2_BUCKET_ALREADY_EXISTS_CODES: readonly number[] = [10004, 10073];

/** Request body for `POST /accounts/{account_id}/r2/buckets`. */
export interface R2CreateBucketRequest {
  readonly name: string;
  /** `apac`/`eeur`/`enam`/`weur`/`wnam`/`oc`. Serialized camelCase, per the schema. */
  readonly locationHint?: string;
  /** `Standard`/`InfrequentAccess`. Serialized camelCase, per the schema. */
  readonly storageClass?: string;
}

/** An R2 bucket descriptor. All fields are optional in Cloudflare's schema. */
export interface R2Bucket {
  readonly name?: string;
  readonly creation_date?: string;
  readonly location?: string;
  readonly storage_class?: string;
  readonly jurisdiction?: string;
}

/** Outcome of an idempotent {@link R2Client.createBucket}. */
export type R2BucketCreation =
  | { readonly kind: "created"; readonly bucket: R2Bucket }
  | { readonly kind: "already_exists" };

/** The result of {@link R2Client.ensureTenantBucket}. */
export interface R2BucketProvision {
  /** The derived bucket name that now exists. */
  readonly name: string;
  /** The account R2 S3 endpoint, for wiring an S3-compatible client. */
  readonly s3Endpoint: string;
  /** `true` when THIS call created the bucket; `false` when it already existed. */
  readonly created: boolean;
}

/** The R2 bucket-management surface over the shared client. */
export class R2Client {
  constructor(private readonly client: CloudflareClient) {}

  /**
   * Create an R2 bucket. **Idempotent**: an already-exists response maps to
   * `already_exists` rather than an error, so onboarding can provision
   * unconditionally. Every other failure surfaces typed.
   *
   * Retry is opted IN: the operation is idempotent by construction, so
   * re-issuing it on a 5xx is safe and matches the Rust behaviour.
   */
  async createBucket(request: R2CreateBucketRequest): Promise<R2BucketCreation> {
    const body: Record<string, string> = { name: request.name };
    if (request.locationHint !== undefined) body.locationHint = request.locationHint;
    if (request.storageClass !== undefined) body.storageClass = request.storageClass;
    try {
      const bucket = await this.client.requestJson<R2Bucket>("POST", R2_BUCKETS_PATH, {
        body,
        idempotent: true,
      });
      return { kind: "created", bucket };
    } catch (error) {
      if (isBucketAlreadyExists(error)) return { kind: "already_exists" };
      throw error;
    }
  }

  /**
   * List **all** of the account's R2 buckets, following the cursor beyond the
   * first page.
   *
   * Termination: no/empty cursor, an empty page, **or a cursor the server
   * repeats verbatim** — the last is a server-side no-progress bug that would
   * otherwise spin forever.
   */
  async listBuckets(): Promise<R2Bucket[]> {
    const buckets: R2Bucket[] = [];
    let cursor: string | undefined;
    for (;;) {
      const path =
        cursor === undefined
          ? `${R2_BUCKETS_PATH}?per_page=${R2_BUCKETS_PER_PAGE}`
          : `${R2_BUCKETS_PATH}?per_page=${R2_BUCKETS_PER_PAGE}&cursor=${percentEncodeQueryValue(cursor)}`;
      const { result, resultInfo } = await this.client.getJsonPaged<{ buckets?: R2Bucket[] }>(path);
      const page = result.buckets ?? [];
      buckets.push(...page);

      const next = nextCursor(resultInfo);
      if (next === undefined || page.length === 0 || next === cursor) return buckets;
      cursor = next;
    }
  }

  /**
   * Delete an R2 bucket by name. The bucket must be EMPTY; a non-empty bucket
   * surfaces as a typed `api` error (`BucketNotEmpty`).
   */
  async deleteBucket(name: string): Promise<void> {
    await this.client.requestAck("DELETE", r2BucketPath(name), { idempotent: true });
  }

  /**
   * Ensure a tenant's R2 bucket exists (create-if-absent) and return its name
   * plus the account R2 S3 endpoint. Safe to call on every onboarding attempt.
   *
   * A tenant id that names no identity is rejected BEFORE any request — see
   * {@link validateTenantId}.
   */
  async ensureTenantBucket(tenant: string): Promise<R2BucketProvision> {
    validateTenantId(tenant);
    const name = await r2BucketNameForTenant(tenant);
    const outcome = await this.createBucket({ name });
    return {
      name,
      s3Endpoint: this.client.r2S3Endpoint(),
      created: outcome.kind === "created",
    };
  }
}

/**
 * Whether a create-bucket failure is really the idempotent "already exists and
 * you own it" case.
 *
 * Deliberately status-AGNOSTIC (the code, not the status, is the idempotency
 * signal) but code-SPECIFIC (a bare 409 is a real error). Note this only ever
 * inspects an `api` error: a `401` carrying a stray `10004` has already
 * classified as `unauthorized` and is not rescued here.
 */
function isBucketAlreadyExists(error: unknown): boolean {
  return (
    error instanceof CloudflareError &&
    error.kind === "api" &&
    error.errors.some((entry) => R2_BUCKET_ALREADY_EXISTS_CODES.includes(entry.code))
  );
}

/**
 * Percent-encode a query value, keeping only the RFC 3986 unreserved set.
 * Cloudflare's pagination cursor is opaque and can carry `+`, `/` and `=`;
 * splicing it raw into the query string would corrupt it.
 */
function percentEncodeQueryValue(value: string): string {
  let encoded = "";
  for (const byte of new TextEncoder().encode(value)) {
    const char = String.fromCharCode(byte);
    if (/[A-Za-z0-9\-._~]/.test(char)) encoded += char;
    else encoded += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return encoded;
}

/**
 * Reject a tenant id that cannot name a tenant.
 *
 * {@link r2BucketNameForTenant} is deliberately infallible — it maps ANY string
 * to an R2-legal, injective name, including `""`. That is right for a
 * derivation and wrong for a PROVISIONING entry point: an empty or
 * punctuation-only tenant id is a caller bug, and silently minting real storage
 * (plus, via S2, a real credential) for it hides that bug behind a success.
 *
 * The rule is narrow on purpose — this package is a transport client and does
 * not own tenant-id policy, so it requires only that the id carry a real
 * identity. Callers needing a stricter charset gate it upstream.
 */
function validateTenantId(tenant: string): void {
  if (!/[a-zA-Z0-9]/.test(tenant)) {
    throw CloudflareError.config(
      `invalid tenant id ${JSON.stringify(tenant)} for R2 provisioning: expected at least one ` +
        "ASCII alphanumeric character",
    );
  }
}

/**
 * Derive a deterministic, R2-valid, **collision-safe** bucket name for a tenant.
 *
 * Shape: `ferrogate-{slug}-{digest}` — the `{slug}-` part is dropped entirely
 * when the tenant id carries no alphanumerics at all.
 *
 * The tenant identity is canonicalised **length-prefixed** as
 * `"{domain}:{len}:{tenant}"`, so the encoding stays unambiguous if a second
 * component (jurisdiction, realm, …) is ever appended. `{digest}` is the
 * lowercase-hex SHA-256 of that, truncated to 128 bits; `{slug}` is a lossy,
 * purely COSMETIC rendering so an operator can eyeball which bucket belongs to
 * whom. Two tenants may share a slug; they cannot share a digest.
 *
 * Async because `crypto.subtle` is the platform's hash — the Rust equivalent
 * was synchronous, and that is the only shape difference.
 */
export async function r2BucketNameForTenant(tenant: string): Promise<string> {
  const slug = tenantBucketSlug(tenant);
  const digest = await tenantBucketDigest(tenant);
  return slug === ""
    ? `${R2_TENANT_BUCKET_PREFIX}${digest}`
    : `${R2_TENANT_BUCKET_PREFIX}${slug}-${digest}`;
}

async function tenantBucketDigest(tenant: string): Promise<string> {
  const canonical = `${R2_TENANT_BUCKET_DIGEST_DOMAIN}:${tenant.length}:${tenant}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  const hex = Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  return hex.slice(0, R2_TENANT_BUCKET_DIGEST_HEX_LEN);
}

/**
 * Cosmetic, deliberately lossy: runs of `[a-z0-9]` (lowercased) joined by a
 * single `-`, capped, never leading/trailing `-` or containing `--`. Carries NO
 * isolation guarantee — collisions here are fine and expected.
 *
 * NOTE the length cap is applied DURING the walk (as in Rust), so the cap
 * counts characters admitted, not characters consumed.
 */
function tenantBucketSlug(tenant: string): string {
  let slug = "";
  for (const char of tenant) {
    if (slug.length === R2_TENANT_BUCKET_SLUG_MAX_LEN) break;
    if (/[a-zA-Z0-9]/.test(char)) slug += char.toLowerCase();
    else if (slug !== "" && !slug.endsWith("-")) slug += "-";
  }
  return slug.replace(/-+$/, "");
}

/**
 * Build the `r2/buckets/{name}` path, rejecting names that could escape the
 * path segment. R2 names are lowercase alphanumeric + hyphens; anything else is
 * a caller bug surfaced before any request is sent.
 */
function r2BucketPath(name: string): string {
  if (name === "" || !/^[a-z0-9-]+$/.test(name)) {
    throw CloudflareError.config(
      `invalid R2 bucket name ${JSON.stringify(name)}: expected lowercase alphanumeric and hyphens`,
    );
  }
  return `accounts/{account_id}/r2/buckets/${name}`;
}
