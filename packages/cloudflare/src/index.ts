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
 * | S1/S2 | retired by #744 | the asset path uses one shared R2 bucket and tenant key prefixes |
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
 * S1/S2 per-tenant provisioning was retired by #744. S5 is a separate
 * provisioning capability whose control-plane call site is not built yet.
 * Nothing here may acquire a request-path consumer except the retry/error
 * primitives.
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
