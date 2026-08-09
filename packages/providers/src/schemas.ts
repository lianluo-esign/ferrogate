/**
 * Zod wire schemas for the provider-adapter data shapes (inventory §3.3).
 *
 * These validate the plain-JSON wire forms crossing the gateway boundary. The
 * in-memory {@link ../types} carry `SecretValue`-wrapped secrets; these schemas
 * describe the pre-wrap wire form (secrets as raw strings) that config/ingress
 * decode before constructing the typed structs.
 */

import { jsonValueSchema } from "@ferrogate/core";
import { z } from "zod";

/** `RoutingStrategy` (snake_case on the wire). */
export const routingStrategySchema = z.enum([
  "priority",
  "lowest_cost",
  "lowest_latency",
  "balanced",
]);

/** `ModelCapability` (snake_case on the wire). */
export const modelCapabilitySchema = z.enum([
  "chat",
  "streaming",
  "vision",
  "images",
  "embeddings",
  "tools",
  "structured_output",
]);

/** Provider families + aliases the registry accepts. */
export const providerAdapterFamilySchema = z.enum([
  "openai-compatible",
  "anthropic",
  "gemini",
  "grok",
  "openrouter",
  "azure-openai",
  "bedrock",
  "vertex",
  "workers-ai",
]);

export const providerUsageSchema = z.object({
  promptTokens: z.number().int().nonnegative().optional(),
  completionTokens: z.number().int().nonnegative().optional(),
  totalTokens: z.number().int().nonnegative().optional(),
});
export type ProviderUsageWire = z.infer<typeof providerUsageSchema>;

export const providerCatalogModelSchema = z.object({
  id: z.string(),
  ownedBy: z.string().optional(),
  created: z.number().int().nonnegative().optional(),
  contextWindow: z.number().int().nonnegative().optional(),
  capabilities: z.array(z.string()),
});
export type ProviderCatalogModelWire = z.infer<typeof providerCatalogModelSchema>;

export const providerErrorResponseSchema = z.object({
  status: z.number().int(),
  body: jsonValueSchema,
});

export const chatCompletionPlanSchema = z.object({
  logicalModel: z.string(),
  providerModel: z.string(),
  stream: z.boolean(),
  body: jsonValueSchema,
});

export const responsesPlanSchema = chatCompletionPlanSchema;

export const embeddingsPlanSchema = z.object({
  logicalModel: z.string(),
  providerModel: z.string(),
  body: jsonValueSchema,
});

export const imagesPlanSchema = embeddingsPlanSchema;

/** Wire form of a prepared request (header values are raw strings here). */
export const providerHttpRequestWireSchema = z.object({
  provider: z.string(),
  endpoint: z.string(),
  body: jsonValueSchema,
  stream: z.boolean(),
  headers: z.array(z.object({ name: z.string(), value: z.string() })),
});

/** Wire form of `ProviderConfig` — secrets are raw strings before wrapping. */
export const providerConfigWireSchema = z.object({
  name: z.string(),
  kind: z.string(),
  baseUrl: z.string(),
  apiKey: z.string().optional(),
  openrouterHttpReferer: z.string().optional(),
  openrouterXTitle: z.string().optional(),
  awsCredentials: z
    .object({
      accessKeyId: z.string(),
      secretAccessKey: z.string(),
      sessionToken: z.string().optional(),
      region: z.string(),
    })
    .optional(),
  gcpCredentials: z
    .object({
      accessToken: z.string(),
      projectId: z.string(),
      location: z.string(),
    })
    .optional(),
});
export type ProviderConfigWire = z.infer<typeof providerConfigWireSchema>;

/** A single model registry entry (logical → physical) in its wire form. */
export const modelSchema = z.object({
  id: z.string(),
  provider: z.string(),
  contextWindow: z.number().int().positive().optional(),
});
export type Model = z.infer<typeof modelSchema>;
