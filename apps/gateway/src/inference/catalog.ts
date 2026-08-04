/**
 * The config-driven provider table + logical→physical model registry.
 *
 * This is the port of the two Rust config tables that make the registry
 * indirection real (`config/ferrogate.example.toml`):
 *
 * ```toml
 * [[providers]]                       # -> ferrogate_providers::ProviderConfig
 * name = "anthropic"
 * kind = "anthropic"
 * base_url = "https://api.anthropic.com/v1"
 * api_key_env = "ANTHROPIC_API_KEY"   # names the variable, never the value
 *
 * [[models]]                          # -> ferrogate_providers::ModelRegistryEntry
 * name = "best-reasoning"             #    the LOGICAL name a client asks for
 * provider = "anthropic"              #    joined to [[providers]].name
 * provider_model = "claude-3-5-sonnet-latest"   # ModelRoute.provider_model
 * capabilities = ["chat", "streaming", "tools"]
 * ```
 *
 * On Workers the two tables are JSON vars and `api_key_env` becomes
 * `api_key_var`, naming a Worker SECRET binding rather than a process
 * environment variable. Everything else is the same join: a client's `model`
 * string is a key into `[[models]]`, and `provider_model` — NOT the client
 * string — is what reaches the upstream. That indirection is the whole point of
 * the registry: logical names are stable tenant-facing contracts, and the
 * physical model behind one can be re-pointed without a client change.
 *
 * ## Fail-closed parsing
 *
 * Rust validates this configuration at process start and REFUSES TO BOOT on a
 * duplicate model name, an unknown provider reference, or an unknown adapter
 * family (`ModelRegistryError::{EmptyModelName,DuplicateModel}`,
 * `ferrogate-config` validation). A Worker cannot refuse to boot per request,
 * so the equivalent here is that an invalid table yields the EMPTY catalog:
 * every model answers `400 model_not_found` and nothing is dispatched anywhere.
 * A misconfiguration can therefore never *widen* what is reachable — the same
 * rule `parseJsonVar` follows for the auth tables in `src/adapters.ts`.
 */
import { BYOK_ALIAS_PATTERN } from "@ferrogate/secrets";
import { z } from "zod";
import {
  type ProviderSecretResolution,
  providerSecretRefusal,
  resolveProviderSecret,
} from "../keys/index.js";
import { canonicalProviderKind, defaultAuthScheme } from "./adapters.js";
import type { OpenRouterRoute } from "./adapters.js";
import { InMemoryModelResolver, emptyModelResolver } from "./defaults.js";
import type {
  AwsRouteCredentials,
  CloudflareAiGatewayRoute,
  GcpRouteCredentials,
  InferenceBindings,
  ModelCapability,
  ModelResolver,
  PhysicalRoute,
} from "./ports.js";
import { ROUTING_STRATEGIES } from "./strategy.js";

// ---------------------------------------------------------------------------
// Wire schemas
// ---------------------------------------------------------------------------

/** `ferrogate_providers::ModelCapability`, as written in configuration. */
const capabilitySchema = z.enum([
  "chat",
  "streaming",
  "vision",
  "images",
  "embeddings",
  "rerank",
  "transcription",
  "speech",
  "tools",
  "structured_output",
]);

/**
 * The account-level `[cloudflare]` block (issue #672), carried in the
 * `GATEWAY_CLOUDFLARE` var.
 *
 * Field names and defaults are `packages/config`'s `cloudflareConfigSchema`
 * (`schema/entities.ts:524`) verbatim, which is itself the port of the Rust
 * `[cloudflare]` section — an operator's TOML and a Worker var should not
 * disagree about what the account block is called. Only the three keys AI
 * Gateway routing reads are accepted: `api_token`, `tenant_tokens` and
 * `r2_s3_endpoint` belong to the manage-plane clients, not to this seam, and a
 * table that accepted them here would imply this Worker uses them.
 *
 * `.strict()` for the same reason every other table in this file is: a
 * misspelled `account_ id` must fail loudly, not route to `/v1//gw/...`.
 */
export const cloudflareAccountRecordSchema = z
  .object({
    /** `[cloudflare].account_id` — required for any routed provider. */
    account_id: z.string().trim().min(1),
    /** `[cloudflare].ai_gateway_base_url` — the compat (passthrough) host. */
    ai_gateway_base_url: z.string().trim().url().optional(),
    /** `[cloudflare].api_base_url` — the unified REST host. */
    api_base_url: z.string().trim().url().optional(),
  })
  .strict();

export type CloudflareAccountRecord = z.infer<typeof cloudflareAccountRecordSchema>;

/** Cloudflare's own public hosts — `cloudflareConfigSchema`'s defaults. */
const DEFAULT_AI_GATEWAY_BASE_URL = "https://gateway.ai.cloudflare.com";
const DEFAULT_CLOUDFLARE_API_BASE_URL = "https://api.cloudflare.com/client/v4";

/**
 * `[[providers]].cloudflare_ai_gateway` — `ProviderCloudflareAiGatewayConfig`
 * (`packages/config/src/schema/entities.ts:38`), with `aig_token_secret_ref`
 * spelled `aig_token_var` for the same reason `api_key_env` became
 * `api_key_var`: a Worker names a SECRET BINDING (or an `env://` / `cf://`
 * reference) where a process names an environment variable. The value never
 * appears in the table.
 */
const providerCloudflareAiGatewaySchema = z
  .object({
    /** The AI Gateway's name inside the account. */
    gateway_id: z.string().trim().min(1),
    /** `CloudflareAiGatewayMode`, lower-case as in the TOML enum. */
    mode: z.enum(["compat", "unified"]).optional(),
    /**
     * Cloudflare's provider slug. Only `openai` and `anthropic` have a default
     * derivable from the family; every other family MUST name one, and the
     * adapter fails the request closed if it does not (`cloudflare.ts`
     * `resolveSlug`). That check is deliberately left where Cloudflare's slug
     * vocabulary is known rather than duplicated into a second table here.
     */
    provider_slug: z.string().trim().min(1).optional(),
    /** Binding/reference holding the `cf-aig-authorization` bearer. */
    aig_token_var: z.string().trim().min(1).optional(),
  })
  .strict();

/**
 * One `[[providers]]` row.
 *
 * `.strict()` mirrors the Rust config loader's `deny_unknown_fields`: a
 * misspelled `base_urls` must fail the table loudly rather than silently leave
 * the provider pointing nowhere.
 */
export const providerRecordSchema = z
  .object({
    /** `ProviderConfig.name` — joined to `[[models]].provider`. */
    name: z.string().trim().min(1),
    /** `ProviderConfig.kind`; must be a known adapter family or alias. */
    kind: z.string().trim().min(1),
    /** `ProviderConfig.base_url`; adapters append their endpoint path. */
    base_url: z.string().trim().url(),
    /**
     * Where the provider's credential comes from: a Worker SECRET binding NAME
     * (`OPENAI_API_KEY`, the legacy form), or a secret REFERENCE resolved
     * through `@ferrogate/secrets` — `env://NAME` or `cf://<store>/<name>`.
     * Never the value. See `src/keys/provider-secrets.ts`.
     */
    api_key_var: z.string().trim().min(1).optional(),
    /**
     * `byok_alias` (issue #682) — the DEFAULT per-tenant credential alias for
     * this provider. An alias, never a credential, and never a tenant: the
     * tenant is the authenticated caller's, so one provider row serves every
     * tenant with that tenant's own negotiated key.
     *
     * NOT resolved here. Catalog construction is synchronous and per-env, while
     * a BYOK lookup is a per-request, per-tenant D1 read — resolving it at this
     * seam would bake ONE tenant's credential into an isolate-wide catalog,
     * which is the cross-tenant leak this feature exists to prevent. The alias
     * is carried onto the route and `src/inference/byok.ts` resolves it per
     * request.
     */
    byok_alias: z.string().trim().regex(BYOK_ALIAS_PATTERN).optional(),
    /** Credential scheme override; defaults to the family's Rust hard-coding. */
    auth_scheme: z.enum(["bearer", "x-api-key"]).optional(),
    /** `ProviderConfig.openrouter_http_referer` — OpenRouter attribution only. */
    openrouter_http_referer: z.string().trim().min(1).optional(),
    /** `ProviderConfig.openrouter_x_title` — OpenRouter attribution only. */
    openrouter_x_title: z.string().trim().min(1).optional(),
    /**
     * `Provider.region` (issue #173) — the provider's declared physical region.
     * Rust makes ONE field do three jobs and this port does the same: it is the
     * data-residency region, the AWS region a `bedrock` provider signs for, and
     * the GCP location a `vertex` provider addresses. `Provider::region`'s doc
     * comment states that reuse explicitly ("rather than adding a duplicate
     * field"), so a second `aws_region` here would be an invention.
     */
    region: z.string().trim().min(1).optional(),
    /**
     * Issue #681 — does the operator ASSERT a zero-data-retention agreement over
     * this provider ACCOUNT?
     *
     * `.optional()` with no default, deliberately and load-bearingly: an absent
     * value stays `undefined`, which `residency/policy.ts` reads as
     * **unverified** and refuses under a ZDR policy. A `.default(false)` here
     * would be indistinguishable from an operator explicitly stating "this
     * account retains", and a `.default(true)` would make every existing
     * `GATEWAY_MODELS` table satisfy a ZDR policy the moment one is switched on.
     *
     * It sits on the PROVIDER because a ZDR agreement is a commercial fact about
     * an account, not about one model id; a model leg may still narrow it (see
     * `routeFieldsSchema.zero_data_retention`) for the case where one model on
     * an otherwise-covered account is excluded from the agreement.
     */
    zero_data_retention: z.boolean().optional(),
    /**
     * `Provider.aws_access_key_id` (issue #172) — NOT a secret, which is why
     * Rust keeps it in plain config and so does this table.
     */
    aws_access_key_id: z.string().trim().min(1).optional(),
    /**
     * Rust `Provider.aws_secret_access_key_env`, renamed `_var` because a
     * Worker resolves a SECRET BINDING where a process resolves an environment
     * variable. Same split as `api_key_var`: the NAME is here, the value never.
     */
    aws_secret_access_key_var: z.string().trim().min(1).optional(),
    /**
     * Rust `Provider.aws_session_token_env`. Present only for temporary/STS
     * credentials; omit it for a long-lived IAM user access key.
     */
    aws_session_token_var: z.string().trim().min(1).optional(),
    /** `Provider.gcp_project_id` (issue #172) — not a secret, like the AWS key id. */
    gcp_project_id: z.string().trim().min(1).optional(),
    /**
     * Rust `Provider.gcp_access_token_env`: the binding holding a PRE-MINTED
     * OAuth2 access token (scope `cloud-platform`). FerroGate never mints or
     * refreshes it — see `GcpRouteCredentials` in `./ports.ts`.
     */
    gcp_access_token_var: z.string().trim().min(1).optional(),
    /**
     * `Provider.cloudflare_ai_gateway` (issue #406, mounted by #672). Present ⇒
     * every request this provider serves is re-addressed onto the account's AI
     * Gateway. Requires the account block (`GATEWAY_CLOUDFLARE`), exactly as
     * the Rust validator requires a top-level `[cloudflare]` section —
     * `validateCloudflareAiGatewayProviders` in `packages/config`.
     */
    cloudflare_ai_gateway: providerCloudflareAiGatewaySchema.optional(),
  })
  .strict();

/**
 * The fields a FALLBACK / CANARY / SHADOW route carries — i.e. everything on a
 * `ModelRoute` except the logical name and the tenancy, which belong to the
 * owning `ModelRegistryEntry` and are inherited.
 *
 * `routing_strategy` and the two prices closed F6 and live on the model row /
 * every leg respectively — see {@link modelRecordSchema} and `strategy.ts`.
 *
 * PORT-TODO(P: `src/cache/config.ts` `aiCacheEnabled`, F11 residue): the ONE
 * `ModelRegistryEntry` field still unrepresentable here is `cache_enabled`, the
 * per-model leg of `AppState::ai_cache_enabled`'s four-level opt-out (global,
 * profile, model, api-key). It is NOT missing behavior: the response cache
 * landed in `src/middleware/response-cache.ts` and `aiCacheEnabled` already
 * takes a `logicalModel` and consults the model leg — it just reads that leg out
 * of the cache policy var rather than out of `[[models]]`, so an operator
 * disables caching for one model in the cache policy instead of on the model
 * row. Adding the key here would put a second, competing source of truth on the
 * same switch. Whether to fold the two is a decision for `src/cache/`, which
 * owns the policy shape and is not this slice's directory; until then the switch
 * exists and works, in the other file.
 */
const routeFieldsSchema = {
  /** `ModelRoute.provider` — must name a row in the provider table. */
  provider: z.string().trim().min(1),
  /** `ModelRoute.provider_model` — the id put on the wire. */
  provider_model: z.string().trim().min(1),
  capabilities: z.array(capabilitySchema).optional(),
  /** `ModelRoute.region` (issue #173). */
  region: z.string().trim().min(1).optional(),
  /**
   * Issue #681 — a per-leg override of the provider's ZDR assertion.
   *
   * The leg wins when it states anything, INCLUDING `false`: the narrowing case
   * ("this account is covered, except for this preview model") is the whole
   * reason the override exists, and `leg ?? provider` would make a `false` leg
   * on a `true` provider read as covered. `?? undefined` is not usable either —
   * see `zeroDataRetentionOf` in the builder below.
   */
  zero_data_retention: z.boolean().optional(),
  /** `ModelRoute.context_window` — the eligibility gate's declared ceiling. */
  context_window: z.number().int().positive().optional(),
  /** `ModelRoute.priority` — ASCENDING; `0` is tried first. */
  priority: z.number().int().min(0).optional(),
  /** `ModelRoute.weight` — DESCENDING within a priority group. */
  weight: z.number().int().min(0).optional(),
  /**
   * `ModelRoute.input_price_per_1m` — USD per 1M prompt tokens, scoring
   * `routing_strategy = "lowest_cost"` / `"balanced"` (`strategy.ts`).
   *
   * `nonnegative`, not `positive`: a genuinely free route prices at 0 and must
   * be expressible, and `route_estimated_cost` is happy with it. Absent means
   * UNPRICED, which is not the same as free — see `routeEstimatedUnitCost`.
   */
  input_price_per_1m: z.number().nonnegative().optional(),
  /** `ModelRoute.output_price_per_1m` — USD per 1M completion tokens. */
  output_price_per_1m: z.number().nonnegative().optional(),
  /**
   * `ModelRoute.cached_input_price_per_1m` — USD per 1M CACHE-READ prompt
   * tokens (issue #667). Absent ⇒ cache reads settle at `input_price_per_1m`.
   *
   * Settlement-only: `metering/route-price.ts` reads these three, and routing
   * does not, because whether a prompt hits the cache is not known when the
   * route is chosen.
   */
  cached_input_price_per_1m: z.number().nonnegative().optional(),
  /** `ModelRoute.cache_write_price_per_1m` — USD per 1M CACHE-WRITE prompt tokens. */
  cache_write_price_per_1m: z.number().nonnegative().optional(),
  /** `ModelRoute.reasoning_price_per_1m` — USD per 1M reasoning tokens. */
  reasoning_price_per_1m: z.number().nonnegative().optional(),
  /**
   * `ModelRoute.audio_second_price_per_1m` — USD per 1M SECONDS of transcribed
   * audio (issue #703). Whisper's $0.006/minute is `100`.
   *
   * "Per 1M" of a unit nobody quotes in millions is deliberate: every other rate
   * on this row is per 1M and `metering/route-price.ts` divides all of them by
   * one constant. A per-minute or per-1k rate would put two denominators in one
   * settlement function, which is one typo away from a bill that is off by 60x.
   * Settlement-only, like the three above: a duration is a property of a request
   * that has already happened.
   */
  audio_second_price_per_1m: z.number().nonnegative().optional(),
  /**
   * `ModelRoute.audio_character_price_per_1m` — USD per 1M CHARACTERS of
   * synthesized text (issue #703). This one every TTS vendor already quotes per
   * 1M: OpenAI's `tts-1` is `15`.
   */
  audio_character_price_per_1m: z.number().nonnegative().optional(),
} as const;

/** One `[[models]].fallbacks` entry — a `ModelRoute` with no rollout split. */
const fallbackRouteSchema = z.object({ ...routeFieldsSchema }).strict();

/**
 * `CanaryRoute` (`state_rollout.rs:47`) — a route plus the sticky percentage of
 * callers diverted onto it.
 *
 * `percent` is required: a canary route with no percentage is an operator
 * mistake that would otherwise read as "0%", i.e. a canary configured, passing
 * validation, and reached by nobody. That is precisely the failure mode
 * `packages/routing`'s marker describes, so it fails the table instead.
 */
const canaryRouteSchema = z
  .object({ ...routeFieldsSchema, percent: z.number().int().min(0).max(100) })
  .strict();

/**
 * `ShadowRoute` (`server/shadow.rs:69,78`) — a MIRROR. Never served to a
 * client; sampled by `shadowSampled` and capped by `max_requests`.
 */
const shadowRouteSchema = z
  .object({
    ...routeFieldsSchema,
    sample_percent: z.number().int().min(0).max(100),
    /** `shadow.max_requests`; `0` (and absence) is uncapped. */
    max_requests: z.number().int().min(0).optional(),
  })
  .strict();

/**
 * One `[[models]]` row — a `ModelRegistryEntry`: the primary `ModelRoute`, its
 * `fallbacks`, and the optional canary/shadow splits.
 *
 * `fallbacks` is what makes the failover ladder REACHABLE. A dispatch loop that
 * can walk N candidates while the config vocabulary can only express one is the
 * dead-code shape this wave exists to remove, so the two land together.
 */
export const modelRecordSchema = z
  .object({
    /** `ModelRegistryEntry.name` — the LOGICAL model a client asks for. */
    name: z.string().trim().min(1),
    ...routeFieldsSchema,
    /** `ModelRegistryEntry.enabled`; defaults to `true` as in Rust. */
    enabled: z.boolean().optional(),
    /**
     * `ModelRegistryEntry.routing_strategy` — the order `strategy.ts` walks the
     * eligible candidates in. Absent is `RoutingStrategy::default()`, i.e.
     * `"priority"`, so every catalog written before this field existed keeps its
     * exact ordering.
     *
     * It belongs to the ENTRY, not to a route, which is why it sits here and not
     * in `routeFieldsSchema`: a fallback cannot have its own strategy in Rust
     * either. `buildModelCatalog` copies it onto every flattened leg so the
     * handler can read it off whichever leg survived eligibility.
     */
    routing_strategy: z.enum(ROUTING_STRATEGIES).optional(),
    /** `ModelRegistryEntry.fallbacks` — the candidate list `chat.rs:259` walks. */
    fallbacks: z.array(fallbackRouteSchema).optional(),
    /** `ModelRegistryEntry.canary` — the rollout split. */
    canary: canaryRouteSchema.optional(),
    /** `ModelRegistryEntry.shadow` — the mirror. */
    shadow: shadowRouteSchema.optional(),
    /** Owning tenant of a private model; absent = globally visible. */
    tenant_id: z.string().trim().min(1).optional(),
    /** Owning project; absent = tenant-wide. */
    project_id: z.string().trim().min(1).optional(),
    /** `owned_by` in `GET /v1/models`; Rust echoes the provider name. */
    owned_by: z.string().trim().min(1).optional(),
  })
  .strict();

export type ProviderRecord = z.infer<typeof providerRecordSchema>;
export type ModelRecord = z.infer<typeof modelRecordSchema>;

/** The route half of a `[[models]]` row, shared by the primary and every leg. */
type RouteLeg = z.infer<typeof fallbackRouteSchema>;

/** The rollout discriminators a canary/shadow leg carries onto its route. */
interface RouteRollout {
  readonly canaryPercent?: number;
  readonly shadowPercent?: number;
  readonly shadowMaxRequests?: number;
}

/**
 * Drop `undefined`-valued keys so a leg can be spread OVER its Rust defaults.
 *
 * Zod omits an absent `.optional()` key rather than setting it to `undefined`,
 * so `{ ...defaults, ...leg }` would already behave — but only as long as that
 * stays true of every schema and every hand-built `ModelRecord` a test passes to
 * `buildModelCatalog` directly. An explicit `priority: undefined` silently
 * erasing the Rust default is exactly the kind of quiet regression the
 * primary-before-fallback ordering must not depend on.
 */
function definedRouting<T extends object>(leg: T): T {
  return Object.fromEntries(
    Object.entries(leg).filter(([, value]) => value !== undefined),
  ) as T;
}

/** Either the flattened routes, or the reason the whole table was refused. */
export type ModelCatalogResult =
  | { readonly ok: true; readonly routes: readonly PhysicalRoute[] }
  | { readonly ok: false; readonly reason: string };

/** Parsed catalog inputs shared by env-only and tenant-D1 loading. */
export interface ModelCatalogInputs {
  readonly providers: readonly ProviderRecord[];
  readonly models: readonly ModelRecord[];
  readonly cloudflare?: CloudflareAccountRecord;
}

export type ModelCatalogInputsResult =
  | { readonly ok: true; readonly inputs: ModelCatalogInputs }
  | { readonly ok: false; readonly reason: string };

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

function parseTable<T extends z.ZodTypeAny>(
  raw: string | undefined,
  schema: T,
  label: string,
): { ok: true; rows: z.infer<T>[] } | { ok: false; reason: string } {
  if (raw === undefined || raw.trim() === "") {
    return { ok: true, rows: [] };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return { ok: false, reason: `${label} is not valid JSON: ${detail}` };
  }
  const result = z.array(schema).safeParse(parsed);
  if (!result.success) {
    const detail = result.error.issues
      .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
      .join("; ");
    return { ok: false, reason: `${label} is invalid: ${detail}` };
  }
  return { ok: true, rows: result.data as z.infer<T>[] };
}

/**
 * Resolve a credential the provider table NAMED, through `@ferrogate/secrets`.
 *
 * `reference` is the operator's own text: a bare Worker binding name (the
 * legacy form, unchanged), or an `env://` / `cf://` / `vault://` secret
 * reference. See `src/keys/provider-secrets.ts` for the resolution table, the
 * fail-closed rule, and the two PORT-TODO limits that remain.
 *
 * Fails CLOSED — an unresolvable reference refuses the WHOLE catalog at every
 * call site below, so a provider can never dispatch with an empty credential.
 */
function boundSecret(
  secrets: Readonly<Record<string, unknown>>,
  reference: string,
): ProviderSecretResolution {
  return resolveProviderSecret(secrets, reference);
}

/** The composite credentials a `bedrock` / `vertex` provider dispatches with. */
interface ProviderCredentials {
  readonly aws?: AwsRouteCredentials | undefined;
  readonly gcp?: GcpRouteCredentials | undefined;
}

/**
 * Port of the Rust config validator's Bedrock/Vertex blocks
 * (`ferrogate-config::validate_providers`) plus `aws_provider_credentials` /
 * `gcp_provider_credentials` (`state.rs`), which are two halves of one rule:
 * neither family has a bearer-token auth mode, so a missing piece of the
 * credential must be caught before any traffic rather than producing an
 * unsigned request.
 *
 * Two deliberate deviations, both STRICTER than Rust and neither able to widen
 * anything:
 *
 *  1. Rust bails at CONFIG LOAD for a missing field but merely leaves
 *     `aws_credentials: None` when the named ENV VAR is unset (the adapter then
 *     refuses at request time). A Worker cannot refuse to boot, so both cases
 *     land in the same place here: an unbound named binding refuses the whole
 *     catalog, exactly as `api_key_var` already does, and every model answers
 *     `400 model_not_found`.
 *  2. The check runs over the PROVIDER table, not over the providers a model
 *     happens to reference, because the Rust validator does too — a misconfigured
 *     provider row is refused whether or not a model points at it.
 *
 * The `index` in the message is the provider's position in the table, matching
 * the Rust `field providers[{index}].<field>` wording so an operator can grep
 * either tree's diagnostic.
 */
function providerCredentials(
  provider: ProviderRecord,
  index: number,
  secrets: Readonly<Record<string, unknown>>,
): { ok: true; credentials: ProviderCredentials } | { ok: false; reason: string } {
  const canonical = canonicalProviderKind(provider.kind);

  if (canonical === "bedrock") {
    if (provider.aws_access_key_id === undefined) {
      return {
        ok: false,
        reason: `field providers[${index}].aws_access_key_id: required when kind = bedrock`,
      };
    }
    if (provider.aws_secret_access_key_var === undefined) {
      return {
        ok: false,
        reason: `field providers[${index}].aws_secret_access_key_var: required when kind = bedrock`,
      };
    }
    if (provider.region === undefined) {
      return {
        ok: false,
        reason: `field providers[${index}].region: required when kind = bedrock (this is the AWS region, e.g. us-east-1)`,
      };
    }
    const secretAccessKey = boundSecret(secrets, provider.aws_secret_access_key_var);
    if (!secretAccessKey.ok) {
      return {
        ok: false,
        reason: providerSecretRefusal(
          provider.name,
          "aws_secret_access_key_var",
          provider.aws_secret_access_key_var,
          secretAccessKey,
        ),
      };
    }
    let sessionToken: string | undefined;
    if (provider.aws_session_token_var !== undefined) {
      const resolved = boundSecret(secrets, provider.aws_session_token_var);
      if (!resolved.ok) {
        return {
          ok: false,
          reason: providerSecretRefusal(
            provider.name,
            "aws_session_token_var",
            provider.aws_session_token_var,
            resolved,
          ),
        };
      }
      sessionToken = resolved.value;
    }
    return {
      ok: true,
      credentials: {
        aws: {
          accessKeyId: provider.aws_access_key_id,
          secretAccessKey: secretAccessKey.value,
          ...(sessionToken === undefined ? {} : { sessionToken }),
          region: provider.region,
        },
      },
    };
  }

  if (canonical === "vertex") {
    if (provider.gcp_project_id === undefined) {
      return {
        ok: false,
        reason: `field providers[${index}].gcp_project_id: required when kind = vertex`,
      };
    }
    if (provider.gcp_access_token_var === undefined) {
      return {
        ok: false,
        reason: `field providers[${index}].gcp_access_token_var: required when kind = vertex`,
      };
    }
    if (provider.region === undefined) {
      return {
        ok: false,
        reason: `field providers[${index}].region: required when kind = vertex (this is the GCP location, e.g. us-central1)`,
      };
    }
    const accessToken = boundSecret(secrets, provider.gcp_access_token_var);
    if (!accessToken.ok) {
      return {
        ok: false,
        reason: providerSecretRefusal(
          provider.name,
          "gcp_access_token_var",
          provider.gcp_access_token_var,
          accessToken,
        ),
      };
    }
    return {
      ok: true,
      credentials: {
        gcp: {
          accessToken: accessToken.value,
          projectId: provider.gcp_project_id,
          location: provider.region,
        },
      },
    };
  }

  // Every other family authenticates with the single `api_key` string. Rust
  // resolves `aws_credentials`/`gcp_credentials` for them too (the resolver is
  // not kind-gated), but no non-Bedrock/Vertex adapter reads either field, so
  // carrying them would be dead weight on the route.
  return { ok: true, credentials: {} };
}

/**
 * Port of `validate_cloudflare_ai_gateway_providers` (issue #406) —
 * `packages/config/src/validate/sections.ts:801` — plus the resolution the Rust
 * `state_routing.rs::cloudflare_ai_gateway_routing` does when it assembles the
 * routing from the provider block and the account section.
 *
 * Both halves are fail-closed at TABLE time rather than at request time,
 * matching how `api_key_var` and the Bedrock/Vertex credentials are already
 * treated here: a routed provider whose account block or gateway token is
 * missing refuses the WHOLE catalog. The alternative — dropping the routing and
 * dialling the vendor directly — is precisely the silent detachment this issue
 * exists to end, and it would be invisible to an operator who believes their
 * traffic is being cached, rate-limited and logged by the AI Gateway.
 */
function cloudflareAiGatewayRouting(
  provider: ProviderRecord,
  index: number,
  secrets: Readonly<Record<string, unknown>>,
  cloudflare: CloudflareAccountRecord | undefined,
): { ok: true; routing?: CloudflareAiGatewayRoute } | { ok: false; reason: string } {
  const block = provider.cloudflare_ai_gateway;
  if (block === undefined) {
    return { ok: true };
  }
  const at = (field: string) => `field providers[${index}].cloudflare_ai_gateway${field}`;

  if (cloudflare === undefined) {
    return {
      ok: false,
      reason: `${at("")}: requires the account-level GATEWAY_CLOUDFLARE block (issue #672) for the account id and base URLs`,
    };
  }

  // `workers-ai` never leaves the isolate: `inference/workers-ai.ts` recognizes
  // the prepared REST path and serves it through the `env.AI` binding instead of
  // `fetch`. Rewriting that URL onto the AI Gateway would silently take the
  // request OFF the binding and onto the network — a request that then needs an
  // account API token this Worker does not carry. Cloudflare's own answer for
  // this pairing is the binding's `gateway` option, which is a different change
  // in a different file, so the pairing is refused loudly instead of half-done.
  if (canonicalProviderKind(provider.kind) === "workers-ai") {
    return {
      ok: false,
      reason: `${at("")}: not supported for kind = workers-ai — Workers AI is served through the AI binding, which reaches the AI Gateway via its own gateway option rather than by URL routing`,
    };
  }

  let aigToken: string | undefined;
  if (block.aig_token_var !== undefined) {
    const resolved = boundSecret(secrets, block.aig_token_var);
    if (!resolved.ok) {
      return {
        ok: false,
        reason: providerSecretRefusal(
          provider.name,
          "cloudflare_ai_gateway.aig_token_var",
          block.aig_token_var,
          resolved,
        ),
      };
    }
    aigToken = resolved.value;
  }

  return {
    ok: true,
    routing: {
      accountId: cloudflare.account_id,
      gatewayId: block.gateway_id,
      gatewayBaseUrl: cloudflare.ai_gateway_base_url ?? DEFAULT_AI_GATEWAY_BASE_URL,
      apiBaseUrl: cloudflare.api_base_url ?? DEFAULT_CLOUDFLARE_API_BASE_URL,
      // The package spells the mode in the Rust enum's PascalCase; the table
      // spells it as the TOML does. Absent is `DEFAULT_CLOUDFLARE_AI_GATEWAY_MODE`.
      mode: block.mode === "unified" ? "Unified" : "Compat",
      ...(block.provider_slug === undefined ? {} : { providerSlug: block.provider_slug }),
      ...(aigToken === undefined ? {} : { aigToken }),
    },
  };
}

/**
 * Join the two tables into the flattened {@link PhysicalRoute}s the dispatch
 * seam carries, resolving each provider's credential out of `secrets`.
 *
 * `secrets` is the Worker `env`; a provider's `api_key_var` is resolved against
 * it through `@ferrogate/secrets` ({@link boundSecret}), so the credential value
 * never appears in either table and an operator may write either a bare binding
 * name or an `env://` / `cf://` reference. A provider whose credential does not
 * resolve is a MISCONFIGURATION, not an anonymous provider: it refuses the whole
 * catalog, because silently dispatching an unauthenticated request to a paid
 * upstream is the failure mode this check exists to prevent. The same rule
 * covers the composite `bedrock`/`vertex` credentials — see
 * {@link providerCredentials}.
 */
export function buildModelCatalog(
  providers: readonly ProviderRecord[],
  models: readonly ModelRecord[],
  secrets: Readonly<Record<string, unknown>> = {},
  cloudflare?: CloudflareAccountRecord,
): ModelCatalogResult {
  const byName = new Map<string, ProviderRecord>();
  const credentialsByName = new Map<string, ProviderCredentials>();
  const routingByName = new Map<string, CloudflareAiGatewayRoute>();
  for (const [index, provider] of providers.entries()) {
    if (byName.has(provider.name)) {
      return { ok: false, reason: `duplicate provider ${provider.name}` };
    }
    if (canonicalProviderKind(provider.kind) === null) {
      return {
        ok: false,
        reason: `provider ${provider.name} has unsupported kind ${provider.kind}`,
      };
    }
    const credentials = providerCredentials(provider, index, secrets);
    if (!credentials.ok) {
      return { ok: false, reason: credentials.reason };
    }
    const routing = cloudflareAiGatewayRouting(provider, index, secrets, cloudflare);
    if (!routing.ok) {
      return { ok: false, reason: routing.reason };
    }
    byName.set(provider.name, provider);
    credentialsByName.set(provider.name, credentials.credentials);
    if (routing.routing !== undefined) {
      routingByName.set(provider.name, routing.routing);
    }
  }

  // `OpenRouterRoute` is `PhysicalRoute` plus the two optional OpenRouter
  // attribution fields, which `ports.ts` has no home for yet (see
  // `OpenRouterProviderExtras`). Every other consumer sees a plain
  // `PhysicalRoute`.
  const routes: OpenRouterRoute[] = [];
  const seen = new Set<string>();
  for (const model of models) {
    // `ModelRegistryError::DuplicateModel` — Rust refuses the registry outright.
    if (seen.has(model.name)) {
      return { ok: false, reason: `duplicate model ${model.name}` };
    }
    seen.add(model.name);

    // The primary route, then `fallbacks`, then the canary and shadow splits.
    // ALL of them flatten into one table keyed by `logicalModel`: the ladder
    // reads it through `ModelResolver.candidates`, `GET /v1/models` dedupes it
    // (`InMemoryModelResolver.catalog`), and the rollout rows carry the two
    // discriminators (`canaryPercent` / `shadowPercent`) that
    // `candidates.ts` splits them back out on.
    //
    // `priority` / `weight` defaults are Rust's and they are NOT the same on
    // both sides of this list (`state.rs::model_registry_entry`):
    //
    //   - the PRIMARY is `ModelRoute::new` ⇒ `priority = 0, weight = 1`;
    //   - a FALLBACK is `priority.unwrap_or(100), weight.unwrap_or(1)`.
    //
    // The 0-vs-100 split is what pins the primary ahead of every undeclared
    // fallback. Defaulting both to 0 would put them in ONE priority group, where
    // the order then falls to weight and finally to the provider NAME — so a
    // fallback whose provider sorts alphabetically before the primary's would be
    // dispatched first, on a config that declares no ordering at all. The weight
    // default of 1 rather than 0 matters for the same reason
    // (`weighted_start_index` reads `weight.max(1)`, so a group of 0-weight
    // routes would rotate as if uniformly weighted anyway — but the DESCENDING
    // weight tiebreak would see a declared `weight = 0` as beating an undeclared
    // one, which is backwards).
    const primaryDefaults = { priority: 0, weight: 1 } as const;
    const fallbackDefaults = { priority: 100, weight: 1 } as const;
    const legs: readonly (RouteLeg & { readonly rollout?: RouteRollout })[] = [
      { ...primaryDefaults, ...definedRouting(model) },
      ...(model.fallbacks ?? []).map((fallback) => ({
        ...fallbackDefaults,
        ...definedRouting(fallback),
      })),
      ...(model.canary === undefined
        ? []
        : [
            {
              ...fallbackDefaults,
              ...definedRouting(model.canary),
              rollout: { canaryPercent: model.canary.percent },
            },
          ]),
      ...(model.shadow === undefined
        ? []
        : [
            {
              ...fallbackDefaults,
              ...definedRouting(model.shadow),
              rollout: {
                shadowPercent: model.shadow.sample_percent,
                shadowMaxRequests: model.shadow.max_requests ?? 0,
              },
            },
          ]),
    ];

    for (const leg of legs) {
      const provider = byName.get(leg.provider);
      if (provider === undefined) {
        return {
          ok: false,
          reason: `model ${model.name} names unknown provider ${leg.provider}`,
        };
      }

      let apiKey: string | undefined;
      if (provider.api_key_var !== undefined) {
        const resolved = boundSecret(secrets, provider.api_key_var);
        if (!resolved.ok) {
          return {
            ok: false,
            reason: providerSecretRefusal(
              provider.name,
              "api_key_var",
              provider.api_key_var,
              resolved,
            ),
          };
        }
        apiKey = resolved.value;
      }

      const credentials = credentialsByName.get(provider.name) ?? {};

      // `ModelRoute.region` IS the provider's declared region in Rust (the
      // registry copies `Provider.region` onto every route it builds), so the
      // provider row is the source. A model-level `region` still wins, which is
      // additive: it can only make a route MORE specific than the provider's.
      const region = leg.region ?? provider.region;
      // The leg wins whenever it STATES something, so an explicit `false` on a
      // leg narrows a `true` provider. `??` would be wrong for exactly that
      // case, which is the one this override exists for.
      const zeroDataRetention =
        leg.zero_data_retention !== undefined
          ? leg.zero_data_retention
          : provider.zero_data_retention;

      routes.push({
        logicalModel: model.name,
        provider: provider.name,
        providerModel: leg.provider_model,
        providerKind: provider.kind,
        baseUrl: provider.base_url,
        ...(apiKey !== undefined ? { apiKey } : {}),
        // The ALIAS only. `src/inference/byok.ts` turns it into a credential
        // per request, inside the caller's tenant scope.
        ...(provider.byok_alias === undefined ? {} : { byokAlias: provider.byok_alias }),
        ...(credentials.aws === undefined ? {} : { awsCredentials: credentials.aws }),
        ...(credentials.gcp === undefined ? {} : { gcpCredentials: credentials.gcp }),
        // Every leg of a routed provider is routed: the AI Gateway is a property
        // of the PROVIDER connection, so a fallback/canary/shadow leg that
        // reached the same provider unrouted would quietly bypass the gateway.
        ...(routingByName.has(provider.name)
          ? { cloudflareAiGateway: routingByName.get(provider.name) }
          : {}),
        authScheme: provider.auth_scheme ?? defaultAuthScheme(provider.kind),
        ownedBy: model.owned_by ?? provider.name,
        ...(leg.capabilities !== undefined
          ? { capabilities: leg.capabilities as readonly ModelCapability[] }
          : {}),
        ...(region !== undefined ? { region } : {}),
        // ABSENT, never `undefined`: `residency/policy.ts` distinguishes "the
        // operator said no" from "nobody said", and an own property holding
        // `undefined` would be indistinguishable from the missing one only by
        // accident of how it is read.
        ...(zeroDataRetention !== undefined ? { zeroDataRetention } : {}),
        ...(leg.context_window !== undefined ? { contextWindow: leg.context_window } : {}),
        ...(leg.priority !== undefined ? { priority: leg.priority } : {}),
        ...(leg.weight !== undefined ? { weight: leg.weight } : {}),
        ...(leg.input_price_per_1m !== undefined
          ? { inputPricePer1m: leg.input_price_per_1m }
          : {}),
        ...(leg.output_price_per_1m !== undefined
          ? { outputPricePer1m: leg.output_price_per_1m }
          : {}),
        // #667. Absent keys, never `undefined` values: `route-price.ts`
        // distinguishes "this route states no cached rate" (fall back to the
        // fresh input rate) from "priced at zero".
        ...(leg.cached_input_price_per_1m !== undefined
          ? { cachedInputPricePer1m: leg.cached_input_price_per_1m }
          : {}),
        ...(leg.cache_write_price_per_1m !== undefined
          ? { cacheWritePricePer1m: leg.cache_write_price_per_1m }
          : {}),
        ...(leg.reasoning_price_per_1m !== undefined
          ? { reasoningPricePer1m: leg.reasoning_price_per_1m }
          : {}),
        // #703. Same absent-key rule: `route-price.ts` refuses to settle an
        // audio call the route states no audio rate for, and a `undefined`
        // VALUE would be indistinguishable from a rate of zero once spread.
        ...(leg.audio_second_price_per_1m !== undefined
          ? { audioSecondPricePer1m: leg.audio_second_price_per_1m }
          : {}),
        ...(leg.audio_character_price_per_1m !== undefined
          ? { audioCharacterPricePer1m: leg.audio_character_price_per_1m }
          : {}),
        // `routing_strategy` belongs to the registry ENTRY, so it is copied from
        // `model` onto EVERY leg — never read off `leg`, which for a fallback
        // cannot carry one (`fallbackRouteSchema` is `.strict()`).
        ...(model.routing_strategy !== undefined
          ? { routingStrategy: model.routing_strategy }
          : {}),
        ...(leg.rollout ?? {}),
        // `ModelRegistryEntry.enabled` governs the WHOLE entry, fallbacks
        // included: Rust disables the registry entry, not a single route, so a
        // disabled model must not be reachable through one of its fallbacks.
        enabled: model.enabled ?? true,
        ...(model.tenant_id !== undefined ? { tenantId: model.tenant_id } : {}),
        ...(model.project_id !== undefined ? { projectId: model.project_id } : {}),
        ...(provider.openrouter_http_referer !== undefined
          ? { openrouterHttpReferer: provider.openrouter_http_referer }
          : {}),
        ...(provider.openrouter_x_title !== undefined
          ? { openrouterXTitle: provider.openrouter_x_title }
          : {}),
      });
    }
  }

  return { ok: true, routes };
}

/**
 * Parse the account-level `[cloudflare]` block out of `GATEWAY_CLOUDFLARE`.
 *
 * Absent or blank is the OFF posture and is not an error — it is what every
 * deployment that does not use AI Gateway routing looks like. It only becomes
 * an error once a provider row asks to be routed, which is where
 * {@link cloudflareAiGatewayRouting} refuses.
 */
function cloudflareAccountFromEnv(
  raw: string | undefined,
): { ok: true; cloudflare?: CloudflareAccountRecord } | { ok: false; reason: string } {
  if (raw === undefined || raw.trim() === "") {
    return { ok: true };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return { ok: false, reason: `GATEWAY_CLOUDFLARE is not valid JSON: ${detail}` };
  }
  const result = cloudflareAccountRecordSchema.safeParse(parsed);
  if (!result.success) {
    const detail = result.error.issues
      .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
      .join("; ");
    return { ok: false, reason: `GATEWAY_CLOUDFLARE is invalid: ${detail}` };
  }
  return { ok: true, cloudflare: result.data };
}

/**
 * `GATEWAY_PROVIDERS` + `GATEWAY_MODELS` + `GATEWAY_CLOUDFLARE` →
 * {@link ModelCatalogResult}.
 */
export function modelCatalogFromEnv(env: InferenceBindings): ModelCatalogResult {
  const inputs = modelCatalogInputsFromEnv(env);
  if (!inputs.ok) {
    return inputs;
  }
  return buildModelCatalog(
    inputs.inputs.providers,
    inputs.inputs.models,
    env,
    inputs.inputs.cloudflare,
  );
}

/** Parse the env tables without flattening them into physical routes. */
export function modelCatalogInputsFromEnv(
  env: InferenceBindings,
): ModelCatalogInputsResult {
  const providers = parseTable(
    typeof env.GATEWAY_PROVIDERS === "string" ? env.GATEWAY_PROVIDERS : undefined,
    providerRecordSchema,
    "GATEWAY_PROVIDERS",
  );
  if (!providers.ok) {
    return { ok: false, reason: providers.reason };
  }
  const models = parseTable(
    typeof env.GATEWAY_MODELS === "string" ? env.GATEWAY_MODELS : undefined,
    modelRecordSchema,
    "GATEWAY_MODELS",
  );
  if (!models.ok) {
    return { ok: false, reason: models.reason };
  }
  const cloudflare = cloudflareAccountFromEnv(
    typeof env.GATEWAY_CLOUDFLARE === "string" ? env.GATEWAY_CLOUDFLARE : undefined,
  );
  if (!cloudflare.ok) {
    return { ok: false, reason: cloudflare.reason };
  }
  return {
    ok: true,
    inputs: {
      providers: providers.rows,
      models: models.rows,
      ...(cloudflare.cloudflare === undefined ? {} : { cloudflare: cloudflare.cloudflare }),
    },
  };
}

/**
 * The {@link ModelResolverFactory} the composition root injects.
 *
 * An invalid table logs its reason once (never the credential — only binding
 * NAMES appear in a reason string) and resolves to the empty registry.
 */
export function modelsFromEnv(env: InferenceBindings): ModelResolver {
  const catalog = modelCatalogFromEnv(env);
  if (!catalog.ok) {
    console.warn(`[ferrogate] model catalog disabled: ${catalog.reason}`);
    return emptyModelResolver;
  }
  return new InMemoryModelResolver(catalog.routes);
}
