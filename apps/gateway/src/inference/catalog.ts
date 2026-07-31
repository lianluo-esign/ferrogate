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
import { z } from "zod";
import { canonicalProviderKind, defaultAuthScheme } from "./adapters.js";
import type { OpenRouterRoute } from "./adapters.js";
import { InMemoryModelResolver, emptyModelResolver } from "./defaults.js";
import type {
  InferenceBindings,
  ModelCapability,
  ModelResolver,
  PhysicalRoute,
} from "./ports.js";

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
  "tools",
  "structured_output",
]);

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
    /** Name of the Worker SECRET binding holding the credential. */
    api_key_var: z.string().trim().min(1).optional(),
    /** Credential scheme override; defaults to the family's Rust hard-coding. */
    auth_scheme: z.enum(["bearer", "x-api-key"]).optional(),
    /** `ProviderConfig.openrouter_http_referer` — OpenRouter attribution only. */
    openrouter_http_referer: z.string().trim().min(1).optional(),
    /** `ProviderConfig.openrouter_x_title` — OpenRouter attribution only. */
    openrouter_x_title: z.string().trim().min(1).optional(),
  })
  .strict();

/** One `[[models]]` row (the primary `ModelRoute` of a `ModelRegistryEntry`). */
export const modelRecordSchema = z
  .object({
    /** `ModelRegistryEntry.name` — the LOGICAL model a client asks for. */
    name: z.string().trim().min(1),
    /** `ModelRoute.provider` — must name a row in the provider table. */
    provider: z.string().trim().min(1),
    /** `ModelRoute.provider_model` — the id put on the wire. */
    provider_model: z.string().trim().min(1),
    capabilities: z.array(capabilitySchema).optional(),
    /** `ModelRegistryEntry.enabled`; defaults to `true` as in Rust. */
    enabled: z.boolean().optional(),
    /** `ModelRoute.region` (issue #173). */
    region: z.string().trim().min(1).optional(),
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

/** Either the flattened routes, or the reason the whole table was refused. */
export type ModelCatalogResult =
  | { readonly ok: true; readonly routes: readonly PhysicalRoute[] }
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
 * Join the two tables into the flattened {@link PhysicalRoute}s the dispatch
 * seam carries, resolving each provider's credential out of `secrets`.
 *
 * `secrets` is the Worker `env`; a provider's `api_key_var` is looked up there
 * so the credential value never appears in either table. A provider that names
 * a binding that is absent (or not a non-empty string) is a MISCONFIGURATION,
 * not an anonymous provider: it refuses the whole catalog, because silently
 * dispatching an unauthenticated request to a paid upstream is the failure mode
 * this check exists to prevent.
 */
export function buildModelCatalog(
  providers: readonly ProviderRecord[],
  models: readonly ModelRecord[],
  secrets: Readonly<Record<string, unknown>> = {},
): ModelCatalogResult {
  const byName = new Map<string, ProviderRecord>();
  for (const provider of providers) {
    if (byName.has(provider.name)) {
      return { ok: false, reason: `duplicate provider ${provider.name}` };
    }
    if (canonicalProviderKind(provider.kind) === null) {
      return {
        ok: false,
        reason: `provider ${provider.name} has unsupported kind ${provider.kind}`,
      };
    }
    byName.set(provider.name, provider);
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

    const provider = byName.get(model.provider);
    if (provider === undefined) {
      return {
        ok: false,
        reason: `model ${model.name} names unknown provider ${model.provider}`,
      };
    }

    let apiKey: string | undefined;
    if (provider.api_key_var !== undefined) {
      const value = secrets[provider.api_key_var];
      if (typeof value !== "string" || value.trim() === "") {
        return {
          ok: false,
          reason: `provider ${provider.name} names api_key_var ${provider.api_key_var}, which is not bound`,
        };
      }
      apiKey = value;
    }

    routes.push({
      logicalModel: model.name,
      provider: provider.name,
      providerModel: model.provider_model,
      providerKind: provider.kind,
      baseUrl: provider.base_url,
      ...(apiKey !== undefined ? { apiKey } : {}),
      authScheme: provider.auth_scheme ?? defaultAuthScheme(provider.kind),
      ownedBy: model.owned_by ?? provider.name,
      ...(model.capabilities !== undefined
        ? { capabilities: model.capabilities as readonly ModelCapability[] }
        : {}),
      ...(model.region !== undefined ? { region: model.region } : {}),
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

  return { ok: true, routes };
}

/** `GATEWAY_PROVIDERS` + `GATEWAY_MODELS` → {@link ModelCatalogResult}. */
export function modelCatalogFromEnv(env: InferenceBindings): ModelCatalogResult {
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
  return buildModelCatalog(providers.rows, models.rows, env);
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
