/**
 * Port of `ferrogate-config`'s `types.rs`: the Caddyfile-compatible
 * intermediate configuration model (`GatewayConfig` and friends, inventory
 * §5.2). This crate owns parse-time shape only; the runtime truth is `Config`
 * after normalization.
 *
 * `GatewayModel.capabilities` is `Vec<ferrogate_providers::ModelCapability>` in
 * Rust; the enum is inlined in `../schema/enums.ts` (the `@ferrogate/providers`
 * package lands in wave 2), and this schema uses it so an unknown slug is
 * rejected at parse time exactly as `FromStr` rejects it in Rust.
 */
import { z } from "zod";
import { modelCapabilitySchema } from "../schema/enums.js";

export const gatewayTlsConfigSchema = z.object({
  cert_path: z.string(),
  key_path: z.string(),
});
export type GatewayTlsConfig = z.infer<typeof gatewayTlsConfigSchema>;

export const gatewayTlsAcmeConfigSchema = z.object({
  domains: z.array(z.string()).default([]),
  email: z.string().nullable().default(null),
  directory_url: z.string().nullable().default(null),
  challenge: z.string().nullable().default(null),
  http_challenge_listen: z.string().nullable().default(null),
  storage_dir: z.string().nullable().default(null),
  dns_provider: z.string().nullable().default(null),
  dns_config: z.record(z.string(), z.string()).default({}),
  dns_hook_set: z.string().nullable().default(null),
  dns_hook_cleanup: z.string().nullable().default(null),
  renewal_window_secs: z.number().int().nullable().default(null),
  renewal_check_interval_secs: z.number().int().nullable().default(null),
  renewal_retry_interval_secs: z.number().int().nullable().default(null),
  auto_graceful_reload: z.boolean().nullable().default(null),
});
export type GatewayTlsAcmeConfig = z.infer<typeof gatewayTlsAcmeConfigSchema>;

export const gatewayUpstreamSchema = z.object({
  name: z.string(),
  url: z.string(),
  urls: z.array(z.string()).default([]),
});
export type GatewayUpstream = z.infer<typeof gatewayUpstreamSchema>;

export const gatewayHeaderSchema = z.object({ name: z.string(), value: z.string() });
export type GatewayHeader = z.infer<typeof gatewayHeaderSchema>;

export const staticResponseSchema = z.object({
  body: z.string(),
  status: z.number().int(),
});
export type StaticResponse = z.infer<typeof staticResponseSchema>;

export const gatewayRouteSchema = z.object({
  name: z.string(),
  upstream: z.string().nullable().default(null),
  hosts: z.array(z.string()).default([]),
  path_prefixes: z.array(z.string()).default([]),
  strip_prefix: z.string().nullable().default(null),
  request_headers: z.array(gatewayHeaderSchema).default([]),
  response_headers: z.array(gatewayHeaderSchema).default([]),
  static_response: staticResponseSchema.nullable().default(null),
});
export type GatewayRoute = z.infer<typeof gatewayRouteSchema>;

export const gatewayProviderSchema = z.object({
  name: z.string(),
  kind: z.string(),
  base_url: z.string(),
  api_key_env: z.string().nullable().default(null),
  openrouter_http_referer: z.string().nullable().default(null),
  openrouter_x_title: z.string().nullable().default(null),
});
export type GatewayProvider = z.infer<typeof gatewayProviderSchema>;

export const gatewayModelSchema = z.object({
  name: z.string(),
  provider: z.string(),
  provider_model: z.string(),
  capabilities: z.array(modelCapabilitySchema).default([]),
  context_window: z.number().int().nullable().default(null),
  input_price_per_1m: z.string().nullable().default(null),
  output_price_per_1m: z.string().nullable().default(null),
});
export type GatewayModel = z.infer<typeof gatewayModelSchema>;

export const gatewayApiKeySchema = z.object({
  id: z.string(),
  name: z.string(),
  key_env: z.string().nullable().default(null),
  key: z.string().nullable().default(null),
  key_hash: z.string().nullable().default(null),
  scopes: z.array(z.string()).default([]),
  allowed_models: z.array(z.string()).default([]),
  denied_models: z.array(z.string()).default([]),
  allowed_providers: z.array(z.string()).default([]),
  denied_providers: z.array(z.string()).default([]),
  monthly_token_budget: z.number().int().nullable().default(null),
  request_limit_per_minute: z.number().int().nullable().default(null),
  organization_id: z.string().nullable().default(null),
  platform_operator: z.boolean().nullable().default(null),
});
export type GatewayApiKey = z.infer<typeof gatewayApiKeySchema>;

export const gatewayLogSchema = z.object({ route: z.string().nullable().default(null) });
export type GatewayLog = z.infer<typeof gatewayLogSchema>;

export const gatewayConfigSchema = z.object({
  listen: z.string(),
  admin: z.string().nullable().default(null),
  tls: gatewayTlsConfigSchema.nullable().default(null),
  tls_acme: gatewayTlsAcmeConfigSchema.nullable().default(null),
  upstreams: z.array(gatewayUpstreamSchema).default([]),
  routes: z.array(gatewayRouteSchema).default([]),
  providers: z.array(gatewayProviderSchema).default([]),
  models: z.array(gatewayModelSchema).default([]),
  api_keys: z.array(gatewayApiKeySchema).default([]),
  logs: z.array(gatewayLogSchema).default([]),
  /** `auth off` in the global options block (#542): the gateway requires no credential. */
  auth_disabled: z.boolean().default(false),
});
export type GatewayConfig = z.infer<typeof gatewayConfigSchema>;

/** A fresh default `GatewayConfig` (Rust `GatewayConfig::default()` with `listen` set by the parser). */
export function defaultGatewayConfig(): GatewayConfig {
  return {
    listen: "127.0.0.1:8080",
    admin: null,
    tls: null,
    tls_acme: null,
    upstreams: [],
    routes: [],
    providers: [],
    models: [],
    api_keys: [],
    logs: [],
    auth_disabled: false,
  };
}

/** A fresh default `GatewayRoute` (used by the parser's `..default()` spreads). */
export function defaultGatewayRoute(): GatewayRoute {
  return {
    name: "",
    upstream: null,
    hosts: [],
    path_prefixes: [],
    strip_prefix: null,
    request_headers: [],
    response_headers: [],
    static_response: null,
  };
}
