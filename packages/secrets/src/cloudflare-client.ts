/**
 * Minimal Cloudflare `client/v4` REST client with an injectable transport seam.
 *
 * PORT-TODO(4.6/4.7): the Rust crate depends on the shared
 * `ferrogate_cloudflare::CloudflareClient` (issue #405 — auth, retries,
 * envelope decode + error mapping written once). That sibling crate maps to a
 * future `@ferrogate/cloudflare` TS package which has NOT been ported yet
 * (wave 2 orders `secrets` alongside it). To keep this package self-contained
 * and behaviourally faithful, this file re-implements the slice of the client
 * that the Secrets Store backend actually uses — envelope decode, the
 * `{account_id}` path template, the `env://`-referenced bearer token, and the
 * `HttpTransport` seam the tests script — and should be REPLACED by an import
 * from `@ferrogate/cloudflare` once that package exists. Retry/backoff and
 * pagination are not reproduced here (the manage plane needs neither).
 */
import { z } from "zod";

/** HTTP verbs the client issues. */
export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

/** A prepared request handed to the {@link HttpTransport}. */
export interface HttpRequest {
  readonly method: HttpMethod;
  readonly url: string;
  readonly headers: Record<string, string>;
  readonly body?: Uint8Array;
}

/** A transport response (already read into a string body). */
export interface HttpResponse {
  readonly status: number;
  readonly body: string;
  readonly retryAfterMs?: number;
}

/** The HTTP execution seam; tests inject a scripted in-memory transport. */
export interface HttpTransport {
  execute(request: HttpRequest): Promise<HttpResponse>;
}

/** Error raised by the Cloudflare client (envelope failure or transport). */
export class CloudflareError extends Error {
  override readonly name = "CloudflareError";
}

/** Materializes a live token from a token *reference* (`env://VAR` or inline). */
export interface TokenResolver {
  resolve(reference: string): Promise<string>;
}

/**
 * Resolves `env://VAR` token references from an environment map; a non-`env://`
 * reference is treated as an inline plaintext token (test convenience,
 * mirroring the Rust `EnvTokenResolver`).
 */
export class EnvTokenResolver implements TokenResolver {
  private readonly env: Record<string, string | undefined>;
  constructor(env: Record<string, string | undefined> = {}) {
    this.env = env;
  }
  resolve(reference: string): Promise<string> {
    if (reference.startsWith("env://")) {
      const name = reference.slice("env://".length);
      const value = this.env[name];
      if (value === undefined || value.trim() === "") {
        throw new CloudflareError(
          `token reference ${reference} resolved to an empty value`,
        );
      }
      return Promise.resolve(value);
    }
    return Promise.resolve(reference);
  }
}

/** Default public Cloudflare API base. */
export const DEFAULT_API_BASE_URL = "https://api.cloudflare.com/client/v4";

/**
 * Client configuration. `apiTokenRef` is a token **reference** (never a token
 * value) — the reference lands in config, the live token is materialized per
 * request by the {@link TokenResolver} at the `Authorization` header only.
 */
export class CloudflareConfig {
  readonly accountId: string;
  readonly apiTokenRef: string;
  apiBaseUrl: string;

  constructor(accountId: string, apiTokenRef: string, apiBaseUrl?: string) {
    this.accountId = accountId;
    this.apiTokenRef = apiTokenRef;
    this.apiBaseUrl = apiBaseUrl ?? DEFAULT_API_BASE_URL;
  }
}

/** Cloudflare success/error envelope: `{ success, errors, messages, result }`. */
const envelopeSchema = z.object({
  success: z.boolean(),
  errors: z
    .array(z.object({ code: z.number().optional(), message: z.string() }))
    .optional()
    .default([]),
  messages: z.array(z.unknown()).optional().default([]),
  result: z.unknown().optional(),
});

/**
 * The shared Cloudflare API client (minimal slice). Substitutes `{account_id}`
 * in every path, unwraps the standard envelope, and maps a `success:false`
 * body — or a non-2xx transport response — to a {@link CloudflareError}.
 */
export class CloudflareClient {
  private readonly cfg: CloudflareConfig;
  private readonly tokens: TokenResolver;
  private readonly transport: HttpTransport;

  constructor(
    config: CloudflareConfig,
    tokens: TokenResolver,
    transport: HttpTransport,
  ) {
    this.cfg = config;
    this.tokens = tokens;
    this.transport = transport;
  }

  accountId(): string {
    return this.cfg.accountId;
  }
  config(): CloudflareConfig {
    return this.cfg;
  }

  private buildUrl(path: string): string {
    const resolved = path.replace("{account_id}", this.cfg.accountId);
    const base = this.cfg.apiBaseUrl.replace(/\/+$/, "");
    return `${base}/${resolved}`;
  }

  private async send(
    method: HttpMethod,
    path: string,
    body?: Uint8Array,
  ): Promise<unknown> {
    const token = await this.tokens.resolve(this.cfg.apiTokenRef);
    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const response = await this.transport.execute({
      method,
      url: this.buildUrl(path),
      headers,
      ...(body !== undefined ? { body } : {}),
    });

    let parsed: z.infer<typeof envelopeSchema>;
    try {
      parsed = envelopeSchema.parse(JSON.parse(response.body));
    } catch (cause) {
      if (response.status < 200 || response.status >= 300) {
        throw new CloudflareError(
          `Cloudflare API returned HTTP ${response.status}: ${response.body}`,
        );
      }
      throw new CloudflareError(
        `invalid Cloudflare API envelope: ${String(cause)}`,
      );
    }
    if (!parsed.success) {
      const detail = parsed.errors
        .map((e) => (e.code !== undefined ? `${e.code}: ${e.message}` : e.message))
        .join("; ");
      throw new CloudflareError(
        `Cloudflare API request failed: ${detail || `HTTP ${response.status}`}`,
      );
    }
    return parsed.result;
  }

  /** `GET` an envelope and validate `result` with `schema`. */
  async getJson<S extends z.ZodTypeAny>(
    path: string,
    schema: S,
  ): Promise<z.infer<S>> {
    return schema.parse(await this.send("GET", path));
  }

  /** Issue `method` with an optional JSON body; validate `result`. */
  async requestJson<S extends z.ZodTypeAny>(
    method: HttpMethod,
    path: string,
    schema: S,
    body?: Uint8Array,
  ): Promise<z.infer<S>> {
    return schema.parse(await this.send(method, path, body));
  }
}
