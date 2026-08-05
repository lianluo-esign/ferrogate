/**
 * `@ferrogate/cloudflare` — the Cloudflare account-MANAGEMENT REST surface.
 *
 * This package is the TS home of the Rust crate `ferrogate-cloudflare`, the
 * 21st crate, which had **no row in `PORT-PLAN.md`** and was therefore never
 * assigned to any porting wave. `docs/rewrite/cf-crate-assessment.md` carries
 * the full per-slice verdict and the Cloudflare-verified constants; this is the
 * implementation of the slices that verdict marked STILL NEEDED.
 *
 * ## What lives here, and why a binding cannot replace it
 *
 * A Worker binding addresses a resource that ALREADY EXISTS. Creating one, and
 * minting a credential for one, are account-management operations that no
 * binding exposes — and the CLI and deploy scripts run outside a Worker, where
 * there are no bindings at all.
 *
 * | Slice | Module | Why it survived the move to Workers |
 * |---|---|---|
 * | S1 | `r2.ts` | no binding creates an R2 bucket |
 * | S2 | `r2-token.ts` | no binding mints a bucket-scoped S3 credential |
 * | S3 | `client.ts` `preflight` + `scopes.ts` | operability: NAME the missing permission group |
 * | S4 | `retry.ts` + `errors.ts` + `envelope.ts` | the shared retry/backoff + typed taxonomy the tree had two partial copies of |
 * | S5 | retired | Tenant data is now created by Durable Object addressing; no account-management client is needed |
 * | S6 | `custom-hostnames.ts` | no binding terminates TLS for a TENANT's hostname (#738) |
 *
 * ## What is deliberately ABSENT (do not "port it back")
 *
 * The D1 `/query` endpoint and the `d1-proxy` client
 * (native `batch()` behind a `[[services]]` binding), the Workers-AI /
 * AI-Gateway REST hops (`env.AI`), agent memory/schedule/container REST hops
 * (Durable Objects), and the `cf://` token resolver (inside a Worker a secret
 * IS a binding). Deleting a REST hop in favour of a binding is the POINT of the
 * rewrite, not a gap.
 *
 * ## Mount status
 *
 * `retry.ts` provides the shared account-management retry primitive.
 * `custom-hostnames.ts` (S6) has ONE control-plane consumer,
 * `GET /admin/v1/site-domains/{hostname}` (#738).
 * S1/S2/S5 are provisioning capabilities whose control-plane call sites are not
 * built yet; each module's docblock states the exact wiring line and the gate
 * that must open first. Nothing here may acquire a request-path consumer except
 * the retry/error primitives.
 */
export {
  AUTHENTICATION_CODES,
  CloudflareError,
  MISSING_SCOPE_CODES,
  type CloudflareApiErrorEntry,
  type CloudflareErrorKind,
} from "./errors.js";

export {
  decodeEnvelope,
  intoAck,
  intoResult,
  intoResultWithInfo,
  nextCursor,
  type CloudflareEnvelope,
  type CloudflareMessage,
  type CloudflareResultInfo,
} from "./envelope.js";

export {
  DEFAULT_RETRY_POLICY,
  RETRYABLE_STATUSES,
  backoffDelayMs,
  executeWithRetry,
  isRetryableStatus,
  systemClock,
  type Clock,
  type RetryOptions,
  type RetryPolicy,
  type RetryResult,
  type RetryableOutcome,
} from "./retry.js";

export {
  REQUIRED_TOKEN_PERMISSION_GROUPS,
  requiredGroupNames,
  type TokenPermissionGroup,
} from "./scopes.js";

export {
  CloudflareClient,
  DEFAULT_AI_GATEWAY_BASE_URL,
  DEFAULT_API_BASE_URL,
  EnvTokenResolver,
  FetchHttpTransport,
  r2S3Endpoint,
  type CloudflareClientOptions,
  type CloudflareConfig,
  type FetchLike,
  type HttpMethod,
  type HttpRequest,
  type HttpResponse,
  type HttpTransport,
  type RequestOptions,
  type TokenResolver,
} from "./client.js";

export {
  R2Client,
  R2_BUCKET_ALREADY_EXISTS_CODES,
  R2_BUCKET_NAME_MAX_LEN,
  R2_BUCKET_NAME_MIN_LEN,
  r2BucketNameForTenant,
  type R2Bucket,
  type R2BucketCreation,
  type R2BucketProvision,
  type R2CreateBucketRequest,
} from "./r2.js";

export {
  R2ScopedToken,
  R2TokenClient,
  R2_BUCKET_ITEM_READ_PERMISSION_GROUP_ID,
  R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID,
  R2_DEFAULT_JURISDICTION,
  permissionGroupIdFor,
  permissionGroupNameFor,
  r2BucketResourceScope,
  type R2CredentialProvision,
  type R2ScopedTokenRequest,
  type R2TokenAccess,
} from "./r2-token.js";

export {
  CUSTOM_HOSTNAME_DUPLICATE_CODES,
  CustomHostnamesClient,
  customHostnameCertificateState,
  type CustomHostname,
  type CustomHostnameCertificate,
  type CustomHostnameCertificateState,
  type CustomHostnameProvision,
  type CustomHostnameRequest,
  type CustomHostnameValidationMethod,
  type CustomHostnameValidationRecord,
} from "./custom-hostnames.js";
