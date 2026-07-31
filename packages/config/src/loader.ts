/**
 * Port of `ferrogate-config`'s `loader.rs` + `config/loader.rs` (inventory §5.5):
 * config-load precedence, the `[control_api]`/`[admin_api]` alias migration, and
 * the Caddyfile intermediate -> `Config` bridge.
 *
 * PORT-TODO(inventory §5.8) — PLATFORM LIMIT, NOT CLOSED (plus one scope note).
 *
 * PLATFORM LIMIT: workerd has NO FILESYSTEM. `Config::from_file` /
 * `from_toml_file` / `from_yaml_file` and `resolve_paths_relative_to` (which
 * rebases cert/key/ACME paths against the config file's directory) have no
 * expressible form — there is no path, no cwd, and no `std::fs`. Config on this
 * platform is sourced from wrangler vars, KV, D1 or a bundled asset, so the
 * entry point is `loadConfigFromObject(rawObject)` over an ALREADY-DECODED
 * object. `resolve_paths_relative_to` is additionally moot: it only ever
 * rebased manual-TLS/ACME paths, which are N/A behind Cloudflare's TLS
 * termination (see `schema/sections.ts`).
 *
 * SCOPE NOTE, NOT A PLATFORM LIMIT: `from_toml_str`/`from_yaml_str` decode a
 * STRING, which a Worker can perfectly well do — they are absent only because
 * this package carries no TOML/YAML parser dependency. Whoever adds one should
 * decode to an object and hand it to `loadConfigFromObject`; do NOT re-derive
 * the alias migration or validation, which are the parts that carry semantics.
 * The Caddyfile bridge does not need a dependency and IS ported
 * (`fromCaddyfileStr`). Pinned by `platform-limits.test.ts` > "loader".
 */
import { parseCaddyfile } from "./caddyfile/parser.js";
import type { GatewayConfig } from "./caddyfile/types.js";
import type { EnvSource } from "./secrets.js";
import { parseConfig, type Config } from "./schema/config.js";
import { validateConfig, type ValidateOptions } from "./validate.js";

/** Whether a path's filename is exactly `Caddyfile` (case-insensitive). */
export function isCaddyfilePath(path: string): boolean {
  const name = path.split(/[\\/]/).pop() ?? path;
  return name.toLowerCase() === "caddyfile";
}

/** The outcome of resolving the control-plane API alias. */
export interface AliasMigration {
  /** The raw config object with `control_api`/`admin_api` resolved into `admin_api`. */
  config: Record<string, unknown>;
  /** Migration notices (the deprecated-alias warning), for the caller to surface. */
  warnings: string[];
}

/**
 * `Config::migrate_control_plane_aliases` (issue #359): resolve the effective
 * control-plane API config from the canonical `[control_api]` section or the
 * deprecated `[admin_api]` alias. Both present is a hard error; alias-only
 * warns; neither leaves the defaults. Runs BEFORE schema validation (a Worker
 * has no serde `skip_deserializing`), so it operates on the raw object.
 */
export function migrateControlPlaneAliases(raw: Record<string, unknown>): AliasMigration {
  const config = { ...raw };
  const controlApi = config.control_api;
  const adminAlias = config.admin_api;
  const warnings: string[] = [];

  const hasControl = controlApi !== undefined && controlApi !== null;
  const hasAlias = adminAlias !== undefined && adminAlias !== null;

  if (hasControl && hasAlias) {
    throw new Error(
      "conflicting control-plane API configuration: both the canonical [control_api] section and " +
        "the deprecated [admin_api] alias are set. They map to the same FerroGate Control Plane " +
        "API service, so keep only one -- prefer [control_api] and remove [admin_api].",
    );
  }
  if (hasControl) {
    config.admin_api = controlApi;
  } else if (hasAlias) {
    warnings.push(
      "the [admin_api] config section is a deprecated alias; rename it to [control_api] (FerroGate " +
        "Control Plane API). The [admin_api] alias still works during the migration window and maps " +
        "1:1 onto [control_api].",
    );
    // admin_api already holds the alias value (the effective section).
  }
  delete config.control_api;
  return { config, warnings };
}

/**
 * Load a config from an already-parsed object (TOML/YAML/JSON decoded by the
 * caller): migrate the control-plane alias, validate the structural shape via
 * the Zod schema, then run the cross-field `validate()` gate.
 */
export function loadConfigFromObject(
  raw: Record<string, unknown>,
  options: ValidateOptions = {},
): { config: Config; warnings: string[] } {
  const migrated = migrateControlPlaneAliases(raw);
  const config = parseConfig(migrated.config);
  validateConfig(config, options);
  return { config, warnings: migrated.warnings };
}

/**
 * `Config::from_gateway_config`: map the Caddyfile intermediate model into a
 * raw runtime config object (every unspecified section left to its schema
 * default). Returns a plain object ready for {@link loadConfigFromObject}.
 */
export function fromGatewayConfig(gateway: GatewayConfig): Record<string, unknown> {
  let tls: Record<string, unknown> | undefined;
  if (gateway.tls !== null) {
    tls = { enabled: true, cert_path: gateway.tls.cert_path, key_path: gateway.tls.key_path, http2: false };
  } else if (gateway.tls_acme !== null) {
    const acme = gateway.tls_acme;
    const acmeOut: Record<string, unknown> = {
      enabled: true,
      domains: acme.domains,
      email: acme.email,
      dns_provider: acme.dns_provider,
      dns_config: acme.dns_config,
      dns_hook_set: acme.dns_hook_set,
      dns_hook_cleanup: acme.dns_hook_cleanup,
      terms_agreed: true,
    };
    if (acme.directory_url !== null) acmeOut.directory_url = acme.directory_url;
    if (acme.challenge !== null) acmeOut.challenge = acme.challenge;
    if (acme.http_challenge_listen !== null) acmeOut.http_challenge_listen = acme.http_challenge_listen;
    if (acme.storage_dir !== null) acmeOut.storage_dir = acme.storage_dir;
    if (acme.renewal_window_secs !== null) acmeOut.renewal_window_secs = acme.renewal_window_secs;
    if (acme.renewal_check_interval_secs !== null)
      acmeOut.renewal_check_interval_secs = acme.renewal_check_interval_secs;
    if (acme.renewal_retry_interval_secs !== null)
      acmeOut.renewal_retry_interval_secs = acme.renewal_retry_interval_secs;
    if (acme.auto_graceful_reload !== null) acmeOut.auto_graceful_reload = acme.auto_graceful_reload;
    tls = { enabled: true, cert_path: null, key_path: null, http2: false, acme: acmeOut };
  }

  const parsePrice = (value: string | null): number | null => {
    if (value === null) return null;
    const parsed = Number.parseFloat(value);
    return Number.isNaN(parsed) ? null : parsed;
  };

  return {
    listen: gateway.listen,
    admin: { listen: gateway.admin, cors_allowed_origin: null },
    ...(tls !== undefined ? { tls } : {}),
    providers: gateway.providers.map((provider) => ({
      name: provider.name,
      kind: provider.kind,
      base_url: provider.base_url,
      api_key_env: provider.api_key_env,
      openrouter_http_referer: provider.openrouter_http_referer,
      openrouter_x_title: provider.openrouter_x_title,
      enabled: true,
    })),
    models: gateway.models.map((model) => ({
      name: model.name,
      provider: model.provider,
      provider_model: model.provider_model,
      routing_strategy: "priority",
      capabilities: model.capabilities,
      context_window: model.context_window,
      input_price_per_1m: parsePrice(model.input_price_per_1m),
      output_price_per_1m: parsePrice(model.output_price_per_1m),
      enabled: true,
    })),
    api_keys: gateway.api_keys.map((key) => ({
      id: key.id,
      name: key.name,
      key_env: key.key_env,
      key: key.key,
      key_hash: key.key_hash,
      enabled: true,
      scopes: key.scopes,
      allowed_models: key.allowed_models,
      denied_models: key.denied_models,
      allowed_providers: key.allowed_providers,
      denied_providers: key.denied_providers,
      // #540: carry the DECLARED tenancy across; a Caddyfile that says neither
      // lands on null/null and is refused by validate().
      organization_id: key.organization_id,
      platform_operator: key.platform_operator,
    })),
    upstreams: gateway.upstreams.map((upstream) => ({
      name: upstream.name,
      url: upstream.url,
      urls: upstream.urls,
      enabled: true,
    })),
    routes: gateway.routes
      .filter((route) => route.upstream !== null)
      .map((route) => ({
        name: route.name,
        upstream: route.upstream,
        hosts: route.hosts,
        path_prefixes: route.path_prefixes,
        strip_prefix: route.strip_prefix,
        request_headers: route.request_headers,
        response_headers: route.response_headers,
        enabled: true,
      })),
    // #542: a Caddyfile CAN say "this gateway is open" via `auth off`.
    auth: { disabled: gateway.auth_disabled },
  };
}

/** `Config::from_caddyfile_str`: parse a Caddyfile string then load it. */
export function fromCaddyfileStr(
  raw: string,
  file: string,
  options: ValidateOptions & { env?: EnvSource } = {},
): { config: Config; warnings: string[] } {
  const gateway = parseCaddyfile(raw, file, options.env);
  return loadConfigFromObject(fromGatewayConfig(gateway), options);
}
