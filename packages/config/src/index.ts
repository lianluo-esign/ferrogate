/**
 * `@ferrogate/config` — gateway configuration loading + validation.
 *
 * Replaces the Rust crate `ferrogate-config`. On Cloudflare, configuration is
 * sourced from Workers vars/secrets and the control-plane store rather than a
 * Caddyfile on disk.
 */
import { z } from "zod";
import type { Scope } from "@ferrogate/core";
import { errorEnvelopeSchema } from "@ferrogate/schemas";

/** Validated gateway configuration document. */
export const gatewayConfigSchema = z.object({
  version: z.string().default("v1"),
  upstreams: z.array(z.string()).default([]),
  defaultModel: z.string().optional(),
});
export type GatewayConfig = z.infer<typeof gatewayConfigSchema>;

/** A configuration bound to a tenancy scope. */
export interface ScopedConfig {
  scope: Scope;
  config: GatewayConfig;
}

/** Pluggable source of configuration (env, D1, KV, remote control plane). */
export interface ConfigSource {
  load(): Promise<GatewayConfig>;
}

/** Error envelope reused for config validation failures. */
export const configErrorSchema = errorEnvelopeSchema;
