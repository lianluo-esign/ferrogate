/**
 * `@ferrogate/providers` — model registry and provider adapters.
 *
 * Replaces the Rust crate `ferrogate-providers`. Upstream calls flow through
 * `fetch()` and Cloudflare AI Gateway rather than a native HTTP client.
 */
import { z } from "zod";
import type { ToolRef } from "@ferrogate/core";

/** A single model entry in the registry. */
export const modelSchema = z.object({
  id: z.string(),
  provider: z.string(),
  contextWindow: z.number().int().positive().optional(),
});
export type Model = z.infer<typeof modelSchema>;

/** Adapter that maps a canonical request onto one upstream provider's API. */
export interface ProviderAdapter {
  readonly name: string;
  supports(modelId: string): boolean;
  tools(): readonly ToolRef[];
}

/** Lookup surface over the configured models. */
export interface ModelRegistry {
  get(modelId: string): Model | undefined;
  list(): readonly Model[];
}
