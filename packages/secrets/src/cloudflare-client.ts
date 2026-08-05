/**
 * Minimal Cloudflare `client/v4` REST client with an injectable transport seam.
 *
 * PORT-TODO(P: 4.6/4.7) — PACKAGE RELOCATION, NOT A PLATFORM LIMIT, NOT CLOSED.
 *
 * The Rust crate depends on the shared `ferrogate_cloudflare::CloudflareClient`
 * (issue #405 — auth, retries, envelope decode + error mapping written once).
 *
 * **UPDATE (wave 17): `@ferrogate/cloudflare` NOW EXISTS.** The whole crate is
 * ported — `errors.ts` (the typed taxonomy incl. the `10013`/`10058` traps),
 * `envelope.ts`, `retry.ts`, `scopes.ts` + `preflight()`, `r2.ts`,
 * `r2-token.ts`, and `custom-hostnames.ts` — with the account-management
 * slices covered by package tests. See
 * `docs/rewrite/cf-crate-assessment.md` §0.0. **Do NOT write a third partial
 * client anywhere; import that package.**
 *
 * This file is nonetheless left as-is, and the marker stays OPEN, for a reason
 * that is about THIS package rather than the missing one: collapsing it into a
 * re-export is a behaviour-affecting refactor of the Secrets Store manage
 * plane, and it must be done by a task that owns `packages/secrets` and can
 * re-prove its suite. Note it must NOT pick up the shared retry when it does —
 * see the deliberate omission two paragraphs down.
 *
 * So this file keeps a self-contained re-implementation of exactly the slice
 * the Secrets Store backend uses — envelope decode, the `{account_id}` path
 * template, the `env://`-referenced bearer token, and the `HttpTransport` seam
 * the tests script. Retry/backoff and pagination are deliberately NOT
 * reproduced: the manage plane needs neither, and a half-implemented retry is a
 * duplicated-write hazard on a write-only API.
 *
 * FOR THIS PACKAGE this is a nothing-lost deferral: the surface below is
 * complete and tested for every call the backend makes. When
 * `@ferrogate/cloudflare` lands, this file becomes a re-export and the marker
 * is deleted.
 *
 * ## TREE-WIDE, HOWEVER, IT IS NOT NOTHING-LOST — recorded here because this is
 * ## the only marker in the repo that names `ferrogate-cloudflare` at all
 *
 * That earlier "nothing-lost" claim was scoped to this file and read as though
 * it covered the crate. It does not. A census of the TS tree
 * (`grep -rn 'api.cloudflare.com' packages/ apps/`) found TWO independent
 * envelope-decoding partial clients and no shared one:
 *   - this file (Secrets Store manage plane),
 * (`@ferrogate/providers`' Cloudflare surface was once counted as a second; it
 * is a request-SHAPING layer that rewrites a URL and injects `cf-aig-*`
 * headers, and never decodes the envelope, so it is not a REST client.)
 *
 * **As of wave 17 there IS a shared one** — `@ferrogate/cloudflare`. This file
 * still carries its own envelope decoder pending the scoped package refactor.
 *
 * MOST of the Rust crate is CORRECTLY absent, and it is worth writing down why
 * so nobody "ports" it back: `ferrogate-cloudflare` exists because the Rust
 * gateway ran OUTSIDE Cloudflare and had to reach every product over REST. This
 * port runs INSIDE it, so the tenant data plane uses native Durable Objects
 * (with native D1 bindings retained only for compatibility), the Workers AI and
 * AI Gateway calls use their bindings, and
 * the agent memory/schedule/container REST hops by Durable Objects. Deleting a
 * REST hop in favour of a binding is the POINT of the rewrite, not a gap.
 *
 * What is genuinely UNPORTED — no TS equivalent anywhere, and no other marker
 * tracking it — is the slice a Worker still cannot do with a binding, because
 * these are account-management operations rather than data-plane ones:
 *   - `r2.rs` — per-tenant R2 bucket provisioning (`r2_bucket_name_for_tenant`,
 *     create-bucket, the already-exists reconciliation codes);
 *   - `r2_token.rs` — minting SCOPED, temporary R2 S3 credentials (the
 *     read/write permission-group ids, jurisdiction), i.e. how a tenant gets
 *     credentials narrower than the account token;
 *   - `scopes.rs` + `CloudflareClient::preflight` — the required
 *     token-permission-group list and the cheap GET that tells an operator
 *     WHICH permission group is missing instead of failing at first use;
 *   - the shared retry/backoff honoring Cloudflare's global ~1,200 req / 5 min
 *     API limit, and the typed `AUTHENTICATION_CODES` / `MISSING_SCOPE_CODES`
 *     error taxonomy, which all three clients above currently approximate.
 *
 * **All five of those are now ported** into `packages/cloudflare` (wave 17),
 * so the list above is history, not a TODO. What REMAINS open, and why:
 *
 *   - S4 (retry + taxonomy) is genuinely closed for account-management clients.
 *     THIS file still carries its own envelope decoder;
 *     collapsing it is a `packages/secrets` refactor, not a port gap.
 *   - S1/S2/S3/S5 are ported but have NO CALL SITE. That is deliberate: the R2
 *     legs must land WITH their control-plane onboarding call site or not at
 *     all, and that call site is gated on a bucket-per-tenant decision plus R2
 *     being enabled on the account. Wiring them speculatively would add exactly
 *     the implemented-tested-never-mounted dead code this port keeps getting
 *     bitten by.
 *
 * Per-slice verdict, the wiring lines, and the Cloudflare-verified constants
 * that must be transcribed BEFORE `crates/**` is deleted (permission-group ids,
 * the R2 resource-scope format, the secret-key derivation, the already-exists /
 * missing-scope / auth code sets, the bucket-name derivation, the retry
 * schedule): `docs/rewrite/cf-crate-assessment.md`.
 */
import { z } from "zod";

import { type EnvLike, readEnvSecret } from "./env.js";

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
 *
 * Reads through `readEnvSecret`, so `CLOUDFLARE_API_TOKEN` may itself be bound
 * as a `[[secrets_store_secrets]]` secret — the account-scoped manage-plane
 * token is exactly the credential an operator would keep there.
 */
export class EnvTokenResolver implements TokenResolver {
  private readonly env: EnvLike;
  constructor(env: EnvLike = {}) {
    this.env = env;
  }
  async resolve(reference: string): Promise<string> {
    if (reference.startsWith("env://")) {
      const name = reference.slice("env://".length);
      const value = await readEnvSecret(name, this.env);
      if (value === undefined) {
        throw new CloudflareError(
          `token reference ${reference} resolved to an empty value`,
        );
      }
      return value;
    }
    return reference;
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
