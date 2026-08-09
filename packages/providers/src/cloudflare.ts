/**
 * Cloudflare AI Gateway upstream routing (issue #406) — port of `cloudflare.rs`.
 *
 * A pure request-shaping layer: after an adapter builds a
 * {@link ProviderHttpRequest}, {@link applyCloudflareAiGatewayRouting} rewrites
 * the outbound URL onto a tenant's Cloudflare AI Gateway and injects the
 * `cf-aig-*` headers, preserving the body and the per-request BYOK auth header.
 */

import { asStr, getField } from "./json.js";
import type { Json } from "./json.js";
import { AdapterError, SecretValue } from "./types.js";
import type { ProviderAdapterFamily, ProviderHeader, ProviderHttpRequest } from "./types.js";

/** Which Cloudflare AI Gateway surface a provider routes through. */
export type CloudflareAiGatewayMode = "Compat" | "Unified";
export const DEFAULT_CLOUDFLARE_AI_GATEWAY_MODE: CloudflareAiGatewayMode = "Compat";

/** The logical upstream surface being dispatched. */
export type CloudflareAiGatewaySurface =
  | "ChatCompletions"
  | "Responses"
  | "Messages"
  | "Embeddings";

/** Per-provider Cloudflare AI Gateway routing parameters. */
export interface CloudflareAiGatewayRouting {
  accountId: string;
  gatewayId: string;
  gatewayBaseUrl: string;
  apiBaseUrl: string;
  /** AI Gateway token for an authenticated gateway (`cf-aig-authorization`). */
  aigToken?: SecretValue;
  mode: CloudflareAiGatewayMode;
  /** Explicit Cloudflare provider slug; derived from family when absent. */
  providerSlug?: string;
}

/** Default Cloudflare provider slug for a family, or `undefined`. */
function defaultSlugForFamily(family: ProviderAdapterFamily): string | undefined {
  switch (family) {
    case "OpenAiCompatible":
      return "openai";
    case "Anthropic":
      return "anthropic";
    default:
      return undefined;
  }
}

/** Provider-native path suffix appended after the compat `.../{provider}` segment. */
function compatNativeSuffix(
  family: ProviderAdapterFamily,
  surface: CloudflareAiGatewaySurface,
): string {
  if (family === "Anthropic" && surface === "Messages") return "/v1/messages";
  switch (surface) {
    case "ChatCompletions":
      return "/chat/completions";
    case "Responses":
      return "/responses";
    case "Embeddings":
      return "/embeddings";
    case "Messages":
      return "/v1/messages";
  }
}

/** The `/ai/v1/{...}` suffix for the unified REST surface. */
function unifiedSurfacePath(surface: CloudflareAiGatewaySurface): string {
  switch (surface) {
    case "ChatCompletions":
      return "chat/completions";
    case "Responses":
      return "responses";
    case "Messages":
      return "messages";
    case "Embeddings":
      return "embeddings";
  }
}

/** Resolve the provider slug: explicit override, else family default (fail-closed). */
function resolveSlug(routing: CloudflareAiGatewayRouting, family: ProviderAdapterFamily): string {
  const explicit = routing.providerSlug?.trim();
  if (explicit) return explicit;
  const fallback = defaultSlugForFamily(family);
  if (fallback === undefined) {
    throw AdapterError.invalidRequest(
      `cloudflare ai gateway routing requires an explicit provider_slug for family ${family}`,
    );
  }
  return fallback;
}

function nonEmpty(value: string, label: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    throw AdapterError.invalidRequest(
      `${label} must not be empty for cloudflare ai gateway routing`,
    );
  }
  return trimmed;
}

const trimEndSlashes = (value: string): string => value.replace(/\/+$/, "");

/** Prefix body `model` with `author/` (unified mode) unless already namespaced. */
function rewriteModelToAuthorForm(body: Json, author: string): void {
  const model = asStr(getField(body, "model"));
  if (model === undefined) return;
  if (model.includes("/")) return;
  (body as Record<string, Json>).model = `${author}/${model}`;
}

/** Insert a header, replacing any case-insensitive same-named header. */
function upsertHeader(headers: ProviderHeader[], name: string, value: string): void {
  const lowered = name.toLowerCase();
  for (let i = headers.length - 1; i >= 0; i--) {
    if (headers[i]!.name.toLowerCase() === lowered) headers.splice(i, 1);
  }
  headers.push({ name, value: new SecretValue(value) });
}

/**
 * Rewrite `request` in place to route through a Cloudflare AI Gateway.
 * Preserves the body and the per-request BYOK auth header; unified mode also
 * rewrites `model` to `author/model` form.
 */
export function applyCloudflareAiGatewayRouting(
  routing: CloudflareAiGatewayRouting,
  family: ProviderAdapterFamily,
  surface: CloudflareAiGatewaySurface,
  request: ProviderHttpRequest,
): void {
  const accountId = nonEmpty(routing.accountId, "cloudflare account_id");
  const gatewayId = nonEmpty(routing.gatewayId, "cloudflare gateway_id");
  const slug = resolveSlug(routing, family);

  if (routing.mode === "Compat") {
    const base = nonEmpty(routing.gatewayBaseUrl, "cloudflare ai_gateway_base_url");
    const suffix = compatNativeSuffix(family, surface);
    request.endpoint = `${trimEndSlashes(base)}/v1/${accountId}/${gatewayId}/${slug}${suffix}`;
  } else {
    const base = nonEmpty(routing.apiBaseUrl, "cloudflare api_base_url");
    request.endpoint = `${trimEndSlashes(base)}/accounts/${accountId}/ai/v1/${unifiedSurfacePath(surface)}`;
    rewriteModelToAuthorForm(request.body, slug);
    upsertHeader(request.headers, "cf-aig-gateway-id", gatewayId);
  }

  const token = routing.aigToken?.exposeSecret().trim();
  if (token) {
    upsertHeader(request.headers, "cf-aig-authorization", `Bearer ${token}`);
  }
}
