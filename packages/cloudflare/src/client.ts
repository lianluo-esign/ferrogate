/**
 * The shared Cloudflare `client/v4` account-MANAGEMENT client.
 *
 * Ported from `crates/ferrogate-cloudflare/src/{client,config,resolver}.rs`.
 * Bearer auth, `{account_id}` templating, envelope decoding, typed error
 * mapping and the deterministic retry loop, written ONCE — this package exists
 * because the tree had grown two independent partial copies of exactly this.
 *
 * ## What COLLAPSED in the move to Workers (do not port it back)
 *
 * The Rust crate carried a `TokenResolver` seam with an `env://` / `cf://`
 * scheme, a `ReqwestTransport`, a `TokioClock`, and `HttpTransport`/`Clock`
 * traits. Inside a Worker a secret **is** a binding and `fetch` is ambient, so:
 * the transport seam collapses to an injectable {@link FetchLike}; the clock to
 * `scheduler.wait`; and the resolver to reading `env`. {@link EnvTokenResolver}
 * survives only because this package also runs OUTSIDE a Worker — in `apps/cli`
 * and in deploy scripts, which have no bindings and must read a variable.
 *
 * ## Deliberate divergence: retry is opt-in for non-GET
 *
 * The Rust loop retried every method on a 5xx. Here `idempotent` defaults to
 * `method === "GET"` and every non-GET caller states its own answer, because a
 * retried `POST /accounts/{id}/tokens` mints a second credential whose secret is
 * lost forever. See `docs/rewrite/cf-crate-assessment.md` §S4.
 *
 * ## Credentials
 *
 * No credential is ever hard-coded here. The client takes a token *reference*
 * and a resolver; the secret arrives from `env` / Secrets Store at the call
 * site. {@link HttpRequest} carries the resolved bearer, so it must never be
 * logged — this module never stringifies one.
 */
import {
  type CloudflareResultInfo,
  decodeEnvelope,
  intoAck,
  intoResult,
  intoResultWithInfo,
} from "./envelope.js";
import { CloudflareError } from "./errors.js";
import {
  type Clock,
  type RetryPolicy,
  executeWithRetry,
  systemClock,
} from "./retry.js";
import { requiredGroupNames } from "./scopes.js";

/** The default `client/v4` origin. */
export const DEFAULT_API_BASE_URL = "https://api.cloudflare.com/client/v4";
/** The AI Gateway origin (a request-shaping base, not a REST client base). */
export const DEFAULT_AI_GATEWAY_BASE_URL = "https://gateway.ai.cloudflare.com";

/** The account's R2 S3-compatible data-plane endpoint. */
export function r2S3Endpoint(accountId: string): string {
  return `https://${accountId}.r2.cloudflarestorage.com`;
}

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

/**
 * A transport-level request. `bearerToken` is the ALREADY-RESOLVED secret;
 * never log this object.
 */
export interface HttpRequest {
  readonly method: HttpMethod;
  readonly url: string;
  readonly bearerToken: string;
  readonly body?: string;
  readonly contentType?: string;
}

/**
 * A transport-level response. A non-2xx status is NOT an error at this layer —
 * the client maps it to a typed {@link CloudflareError} after inspecting the
 * envelope. `body` can carry a plaintext credential (the one-time token value
 * from a mint), so it must never be logged either.
 */
export interface HttpResponse {
  readonly status: number;
  readonly retryAfterMs?: number;
  readonly body: string;
}

/** The HTTP execution seam; tests inject a scripted transport. */
export interface HttpTransport {
  execute(request: HttpRequest): Promise<HttpResponse>;
}

/** Minimal `fetch` shape, so a caller can inject one without a network. */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * Production transport over ambient `fetch`.
 *
 * `Retry-After` is parsed as delta-SECONDS only. The HTTP-date form is
 * deliberately not honoured — Cloudflare emits delta-seconds for its API rate
 * limit — and an unparseable value yields `undefined` so the caller falls back
 * to the exponential schedule rather than sleeping for a garbage duration.
 */
export class FetchHttpTransport implements HttpTransport {
  readonly #fetch: FetchLike;

  constructor(fetchImpl?: FetchLike) {
    this.#fetch = fetchImpl ?? ((input, init) => fetch(input, init));
  }

  async execute(request: HttpRequest): Promise<HttpResponse> {
    const headers: Record<string, string> = {
      authorization: `Bearer ${request.bearerToken}`,
      accept: "application/json",
    };
    if (request.body !== undefined) {
      headers["content-type"] = request.contentType ?? "application/json";
    }
    let response: Response;
    try {
      response = await this.#fetch(request.url, {
        method: request.method,
        headers,
        ...(request.body === undefined ? {} : { body: request.body }),
      });
    } catch (error) {
      throw CloudflareError.transport(
        error instanceof Error ? error.message : String(error),
        error,
      );
    }
    let body: string;
    try {
      body = await response.text();
    } catch (error) {
      throw CloudflareError.transport(
        `failed to read response body: ${error instanceof Error ? error.message : String(error)}`,
        error,
      );
    }
    const retryAfterMs = parseRetryAfterMs(response.headers.get("retry-after"));
    return retryAfterMs === undefined
      ? { status: response.status, body }
      : { status: response.status, body, retryAfterMs };
  }
}

function parseRetryAfterMs(header: string | null): number | undefined {
  if (header === null) return undefined;
  const seconds = Number.parseInt(header.trim(), 10);
  if (!Number.isFinite(seconds) || seconds < 0 || String(seconds) !== header.trim()) {
    return undefined;
  }
  return seconds * 1_000;
}

/** Materialises a live token from a token *reference*. */
export interface TokenResolver {
  resolve(reference: string): Promise<string>;
}

/**
 * Resolves `env://VAR` references from an environment map; a reference with no
 * scheme is treated as an inline plaintext token.
 *
 * `cf://` is deliberately UNSUPPORTED here, exactly as in Rust, for three
 * reasons that all still hold: the Secrets Store client depends on this client
 * (a cycle), the Secrets Store manage-plane API is write-only, and bootstrapping
 * would be circular (you need a token to read the token). Inside a Worker a
 * `cf://` secret arrives as a binding, so `env` already answers.
 */
export class EnvTokenResolver implements TokenResolver {
  constructor(private readonly env: Readonly<Record<string, string | undefined>> = {}) {}

  async resolve(reference: string): Promise<string> {
    if (reference === "") {
      throw CloudflareError.tokenResolution("token reference is empty");
    }
    if (reference.startsWith("cf://")) {
      throw CloudflareError.tokenResolution(
        `the cf:// secret backend is not resolvable from this package (${reference}); inside a ` +
          "Worker a Secrets Store secret is a binding — read it from env and pass it inline",
      );
    }
    if (!reference.startsWith("env://")) return reference;
    const name = reference.slice("env://".length);
    const value = this.env[name];
    if (value === undefined || value === "") {
      throw CloudflareError.tokenResolution(
        `environment variable ${name} referenced by ${reference} is unset or empty`,
      );
    }
    return value;
  }
}

/** Account id, token reference(s) and base URL for the shared client. */
export interface CloudflareConfig {
  readonly accountId: string;
  /** `env://VAR`, or an inline plaintext token. NEVER a literal in source. */
  readonly tokenReference: string;
  /** Optional per-tenant token overrides, keyed by tenant id. */
  readonly tenantTokenReferences?: Readonly<Record<string, string>>;
  /** Defaults to {@link DEFAULT_API_BASE_URL}. */
  readonly apiBaseUrl?: string;
  /**
   * Overrides the per-account R2 S3 host. Defaults to
   * `https://<account_id>.r2.cloudflarestorage.com`; a jurisdictional (`eu`,
   * `fedramp`) bucket, or a local S3 stand-in, needs an explicit one.
   */
  readonly r2S3Endpoint?: string;
}

/** Per-call knobs. */
export interface RequestOptions {
  /** Selects a per-tenant token override when one is configured. */
  readonly tenant?: string;
  /**
   * Whether this call may be re-issued on a 429/5xx. Defaults to
   * `method === "GET"`. A non-GET caller MUST state its own answer; see the
   * module docblock.
   */
  readonly idempotent?: boolean;
  /** A JSON-serialisable body. Mutually exclusive with `rawBody`. */
  readonly body?: unknown;
  /** A pre-encoded body (multipart, …). Requires `contentType`. */
  readonly rawBody?: string;
  readonly contentType?: string;
  /** Authenticate with this token verbatim instead of the configured one. */
  readonly bearerOverride?: string;
}

export interface CloudflareClientOptions {
  readonly config: CloudflareConfig;
  readonly resolver: TokenResolver;
  readonly transport?: HttpTransport;
  readonly clock?: Clock;
  readonly retry?: RetryPolicy;
}

/** The shared Cloudflare account-management client. */
export class CloudflareClient {
  readonly #config: CloudflareConfig;
  readonly #resolver: TokenResolver;
  readonly #transport: HttpTransport;
  readonly #clock: Clock;
  readonly #retry: RetryPolicy | undefined;

  constructor(options: CloudflareClientOptions) {
    this.#config = options.config;
    this.#resolver = options.resolver;
    this.#transport = options.transport ?? new FetchHttpTransport();
    this.#clock = options.clock ?? systemClock;
    this.#retry = options.retry;
  }

  get accountId(): string {
    return this.#config.accountId;
  }

  get config(): CloudflareConfig {
    return this.#config;
  }

  /** The account's R2 S3-compatible data-plane endpoint, or the override. */
  r2S3Endpoint(): string {
    return this.#config.r2S3Endpoint ?? r2S3Endpoint(this.#config.accountId);
  }

  /** Issue a request and decode its `result` into `T`. */
  async requestJson<T>(
    method: HttpMethod,
    path: string,
    options: RequestOptions = {},
  ): Promise<T> {
    const { status, retryAfterMs, body } = await this.#send(method, path, options);
    return intoResult<T>(decodeEnvelope<T>(body, describe(method, path)), status, retryAfterMs);
  }

  /** Convenience GET returning a decoded `result`. */
  async getJson<T>(path: string, options: RequestOptions = {}): Promise<T> {
    return this.requestJson<T>("GET", path, options);
  }

  /**
   * GET returning the decoded `result` **plus** the `result_info` pagination
   * metadata. {@link getJson} discards it, which leaves a caller of a paginated
   * endpoint unable to tell a complete answer from page 1 of many.
   */
  async getJsonPaged<T>(
    path: string,
    options: RequestOptions = {},
  ): Promise<{ readonly result: T; readonly resultInfo: CloudflareResultInfo | undefined }> {
    const { status, retryAfterMs, body } = await this.#send("GET", path, options);
    return intoResultWithInfo<T>(
      decodeEnvelope<T>(body, describe("GET", path)),
      status,
      retryAfterMs,
    );
  }

  /** Issue a request whose success carries no meaningful `result`. */
  async requestAck(
    method: HttpMethod,
    path: string,
    options: RequestOptions = {},
  ): Promise<void> {
    const { status, retryAfterMs, body } = await this.#send(method, path, options);
    intoAck(decodeEnvelope<unknown>(body, describe(method, path)), status, retryAfterMs);
  }

  /**
   * Slice **S3** — the operability check.
   *
   * A cheap `GET /accounts/{account_id}` that verifies the token is valid AND
   * scoped for the account. A token that authenticates but lacks a permission
   * group surfaces as `missing_scope`, whose message NAMES the groups to grant
   * — which is the whole point: without it an operator learns only that some
   * call failed, at first use, in production.
   *
   * This has no request-path consumer and must not acquire one.
   */
  async preflight(options: RequestOptions = {}): Promise<void> {
    const { status, retryAfterMs, body } = await this.#send(
      "GET",
      "accounts/{account_id}",
      options,
    );
    intoAck(decodeEnvelope<unknown>(body, "preflight"), status, retryAfterMs);
  }

  async #send(
    method: HttpMethod,
    path: string,
    options: RequestOptions,
  ): Promise<HttpResponse> {
    if (this.#config.accountId === "") {
      throw CloudflareError.config("account id is empty; refusing to build a Cloudflare URL");
    }
    const bearerToken =
      options.bearerOverride ??
      (await this.#resolver.resolve(this.#tokenReference(options.tenant)));

    if (options.body !== undefined && options.rawBody !== undefined) {
      throw CloudflareError.config("a request may carry `body` or `rawBody`, not both");
    }
    const body =
      options.rawBody ?? (options.body === undefined ? undefined : JSON.stringify(options.body));

    const request: HttpRequest = {
      method,
      url: this.#buildUrl(path),
      bearerToken,
      ...(body === undefined ? {} : { body }),
      ...(body === undefined
        ? {}
        : { contentType: options.contentType ?? "application/json" }),
    };

    const { outcome, attempts } = await executeWithRetry(
      // Rust's `HttpTransport` contract RESTRICTED `execute` to returning
      // `Err(CloudflareError::Transport)`, and the retry loop leaned on that.
      // TypeScript cannot enforce it, so the contract is restored here rather
      // than trusted: an injected transport that throws a bare `TypeError`
      // would otherwise escape the loop unretried and reach the caller
      // unclassified.
      async () => {
        try {
          return await this.#transport.execute(request);
        } catch (error) {
          if (error instanceof CloudflareError) throw error;
          throw CloudflareError.transport(
            error instanceof Error ? error.message : String(error),
            error,
          );
        }
      },
      {
        ...(this.#retry === undefined ? {} : { policy: this.#retry }),
        clock: this.#clock,
        enabled: options.idempotent ?? method === "GET",
        isRetryableError: (error) => error instanceof CloudflareError && error.retryable,
        wrapExhaustedError: (count, error) =>
          error instanceof CloudflareError
            ? CloudflareError.exhaustedRetries(count, error)
            : error,
      },
    );

    // An exhausted 429 short-circuits with the real attempt count rather than
    // being decoded — the body of a rate-limit response says nothing useful.
    if (outcome.status === 429) {
      throw CloudflareError.rateLimited(outcome.retryAfterMs, attempts);
    }
    return outcome;
  }

  #tokenReference(tenant: string | undefined): string {
    if (tenant === undefined) return this.#config.tokenReference;
    return this.#config.tenantTokenReferences?.[tenant] ?? this.#config.tokenReference;
  }

  #buildUrl(path: string): string {
    const templated = path.replaceAll("{account_id}", this.#config.accountId);
    const base = this.#config.apiBaseUrl ?? DEFAULT_API_BASE_URL;
    return `${base.replace(/\/+$/, "")}/${templated.replace(/^\/+/, "")}`;
  }
}

function describe(method: HttpMethod, path: string): string {
  return `${method} ${path}`;
}

/** Re-exported so a consumer can name the scope table without a second import. */
export { requiredGroupNames };
