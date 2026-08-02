/**
 * Minting **bucket-scoped R2 S3 credentials** — slice **S2**.
 *
 * Ported from `crates/ferrogate-cloudflare/src/r2_token.rs`.
 *
 * ## Which Cloudflare API (verified, not guessed)
 *
 * R2 has **no** "create R2 token" REST endpoint. The R2 dashboard's "Manage R2
 * API Tokens" is a UI over Cloudflare's generic **account-owned API tokens**
 * API, restricted with R2 permission groups plus a bucket resource scope:
 *
 *  - `POST   /accounts/{account_id}/tokens` — mint;
 *  - `DELETE /accounts/{account_id}/tokens/{token_id}` — revoke.
 *
 * Account-owned (**not** `POST /user/tokens`) is deliberate: the token is a
 * durable service principal owned by the FerroGate account and survives the
 * creating user.
 *
 * The S3 credential is then DERIVED: `accessKeyId` is the token's `id`, and
 * `secretAccessKey` is `hex(sha256(token.value))` over the plaintext Cloudflare
 * returns **exactly once**, at creation.
 *
 * ## Why this exists (the security argument), and why it is not mounted yet
 *
 * Today `apps/gateway`'s asset presigner signs EVERY tenant's URL with one
 * deployment-wide key pair. A presigned URL is itself scoped to one object by
 * SigV4, so the URLs are safe; the exposure is the CREDENTIAL — if that secret
 * leaks, the blast radius is every tenant's objects. A per-tenant minted
 * credential narrows that to one bucket = one tenant.
 *
 * The Rust production path had the SAME posture, so this is not a port
 * regression — it is an unbuilt defense-in-depth layer on both sides. It stays
 * unmounted until the bucket-per-tenant decision in `r2.ts` is taken and R2 is
 * enabled on the account. The wiring line, at that point, is in a control-plane
 * ONBOARDING handler:
 *
 * ```ts
 * const { bucket, token } = await new R2TokenClient(cf).ensureTenantCredentials(tenantId);
 * // then write `token.secretAccessKey` STRAIGHT into Cloudflare Secrets Store —
 * // never into D1. The Rust deferred that last step too.
 * ```
 *
 * ## Not idempotent, by construction
 *
 * Cloudflare returns the secret `value` once and never lets it be read back, so
 * create-if-absent is impossible. {@link R2TokenClient.ensureTenantCredentials}
 * keeps the BUCKET idempotent and mints a fresh token each call; the caller owns
 * storing it. For the same reason the mint is **never retried** — a retried
 * `POST` creates a second credential whose secret is lost forever.
 */
import type { CloudflareClient } from "./client.js";
import { CloudflareError } from "./errors.js";
import { type R2BucketProvision, R2Client } from "./r2.js";

const ACCOUNT_TOKENS_PATH = "accounts/{account_id}/tokens";

/** Buckets outside a data-localization jurisdiction use `default`. */
export const R2_DEFAULT_JURISDICTION = "default";

/**
 * **Workers R2 Storage Bucket Item Read** — read + list objects within the
 * scoped bucket. Published in the R2 *authentication* docs' Access-Policy
 * example.
 */
export const R2_BUCKET_ITEM_READ_PERMISSION_GROUP_ID = "6a018a9f2fc74eb6b293b0c548f38b39";

/**
 * **Workers R2 Storage Bucket Item Write** — read + write + list within the
 * scoped bucket.
 *
 * Published **only** in Cloudflare's R2 *Data Catalog* documentation. The R2
 * authentication docs carry the Read id alone, so they are NOT a source for
 * this one — which makes this the single most expensive constant in the crate
 * to rediscover.
 */
export const R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID = "2efd5506f9c8494dacb1fa10a3e7d5b6";

/** The access level a scoped token grants over its single bucket. */
export type R2TokenAccess = "read-only" | "read-write";

/** The permission-group id an access level attaches. */
export function permissionGroupIdFor(access: R2TokenAccess): string {
  return access === "read-only"
    ? R2_BUCKET_ITEM_READ_PERMISSION_GROUP_ID
    : R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID;
}

/** The Cloudflare dashboard name of the attached permission group. */
export function permissionGroupNameFor(access: R2TokenAccess): string {
  return access === "read-only"
    ? "Workers R2 Storage Bucket Item Read"
    : "Workers R2 Storage Bucket Item Write";
}

/** A request to mint an R2 API token scoped to exactly one bucket. */
export interface R2ScopedTokenRequest {
  /** Human-readable name recorded on the Cloudflare side. NOT the credential. */
  readonly tokenName: string;
  /** The single bucket the token may access. */
  readonly bucket: string;
  /** The bucket's jurisdiction segment. See {@link R2_DEFAULT_JURISDICTION}. */
  readonly jurisdiction: string;
  readonly access: R2TokenAccess;
}

/**
 * A minted, bucket-scoped R2 credential.
 *
 * `toString`/`toJSON` are overridden so the secret cannot reach a log line, an
 * error chain or a test failure by accident — mirroring the hand-written
 * `Debug` impls the Rust grew for the same reason. The field itself stays
 * readable for the caller that must persist it into Secrets Store.
 */
export class R2ScopedToken {
  constructor(
    /** The Cloudflare token id, for later revocation. Equals `accessKeyId`. */
    readonly tokenId: string,
    /** The S3 **Access Key ID**: the Cloudflare token `id`. */
    readonly accessKeyId: string,
    /** The S3 **Secret Access Key**: `hex(sha256(token.value))`. */
    readonly secretAccessKey: string,
  ) {}

  toString(): string {
    return `R2ScopedToken { tokenId: ${this.tokenId}, accessKeyId: ${this.accessKeyId}, secretAccessKey: <redacted> }`;
  }

  toJSON(): Record<string, string> {
    return {
      tokenId: this.tokenId,
      accessKeyId: this.accessKeyId,
      secretAccessKey: "<redacted>",
    };
  }
}

/** The result of {@link R2TokenClient.ensureTenantCredentials}. */
export interface R2CredentialProvision {
  readonly bucket: R2BucketProvision;
  readonly token: R2ScopedToken;
}

/** The `result` of a create-token response. `value` arrives exactly once. */
interface CreateTokenResult {
  readonly id?: string;
  readonly value?: string;
}

/** Build `com.cloudflare.edge.r2.bucket.{account_id}_{jurisdiction}_{bucket}`. */
export function r2BucketResourceScope(
  accountId: string,
  jurisdiction: string,
  bucket: string,
): string {
  return `com.cloudflare.edge.r2.bucket.${accountId}_${jurisdiction}_${bucket}`;
}

/** The scoped-R2-credential surface over the shared client. */
export class R2TokenClient {
  readonly #r2: R2Client;

  constructor(private readonly client: CloudflareClient) {
    this.#r2 = new R2Client(client);
  }

  /**
   * Mint an API token restricted to a single bucket and return the derived S3
   * credential plus the token id.
   *
   * **Never retried** — see the module docblock. A 5xx here fails the call and
   * the caller mints again explicitly, which is recoverable; a silent second
   * mint is not.
   */
  async createScopedToken(request: R2ScopedTokenRequest): Promise<R2ScopedToken> {
    validateBucketName(request.bucket);
    validateJurisdiction(request.jurisdiction);
    if (request.tokenName.trim() === "") {
      throw CloudflareError.config("R2 scoped-token request requires a non-empty token name");
    }

    const result = await this.client.requestJson<CreateTokenResult>("POST", ACCOUNT_TOKENS_PATH, {
      idempotent: false,
      body: {
        name: request.tokenName,
        policies: [
          {
            effect: "allow",
            resources: {
              [r2BucketResourceScope(
                this.client.accountId,
                request.jurisdiction,
                request.bucket,
              )]: "*",
            },
            permission_groups: [{ id: permissionGroupIdFor(request.access) }],
          },
        ],
      },
    });

    if (typeof result.id !== "string" || result.id === "") {
      throw CloudflareError.decode("Cloudflare create-token response omitted the token id");
    }
    if (typeof result.value !== "string" || result.value === "") {
      throw CloudflareError.decode(
        "Cloudflare create-token response omitted the token value (required to derive the R2 " +
          "secret access key)",
      );
    }

    return new R2ScopedToken(result.id, result.id, await sha256Hex(result.value));
  }

  /** Revoke (delete) a previously minted token by its id. */
  async revokeToken(tokenId: string): Promise<void> {
    await this.client.requestAck("DELETE", accountTokenPath(tokenId), { idempotent: true });
  }

  /**
   * Ensure a tenant's bucket exists **and** mint a read+write credential scoped
   * to just that bucket. The bucket step is idempotent; the token step is not.
   */
  async ensureTenantCredentials(tenant: string): Promise<R2CredentialProvision> {
    const bucket = await this.#r2.ensureTenantBucket(tenant);
    const token = await this.createScopedToken({
      tokenName: `ferrogate-r2-${bucket.name}`,
      bucket: bucket.name,
      jurisdiction: R2_DEFAULT_JURISDICTION,
      access: "read-write",
    });
    return { bucket, token };
  }
}

/** Lowercase-hex SHA-256 — R2's secret-access-key derivation. */
async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Reject a bucket name that could break out of the `_`-delimited resource-scope
 * id (or escape a path). Note `_` itself is rejected: smuggling one in would
 * make the account/jurisdiction/bucket split ambiguous.
 */
function validateBucketName(bucket: string): void {
  if (bucket === "" || !/^[a-z0-9-]+$/.test(bucket)) {
    throw CloudflareError.config(
      `invalid R2 bucket name ${JSON.stringify(bucket)}: expected lowercase alphanumeric and hyphens`,
    );
  }
}

/** Reject a jurisdiction that is not a bare lowercase-alpha token. */
function validateJurisdiction(jurisdiction: string): void {
  if (jurisdiction === "" || !/^[a-z]+$/.test(jurisdiction)) {
    throw CloudflareError.config(
      `invalid R2 jurisdiction ${JSON.stringify(jurisdiction)}: expected a lowercase-alpha token ` +
        'like "default" or "eu"',
    );
  }
}

/** Build the revocation path, rejecting a token id that could escape it. */
function accountTokenPath(tokenId: string): string {
  if (tokenId === "" || !/^[a-zA-Z0-9]+$/.test(tokenId)) {
    throw CloudflareError.config(
      `invalid Cloudflare token id ${JSON.stringify(tokenId)}: expected an alphanumeric id`,
    );
  }
  return `accounts/{account_id}/tokens/${tokenId}`;
}
