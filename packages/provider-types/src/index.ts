/** Stable business-facing provider families shared by Polaris, Vega and FerroGate. */
export const PROVIDER_TYPE_IDS = [
  "openai",
  "anthropic",
  "gemini",
  "minimax",
  "deepseek",
  "grok",
] as const;

export type ProviderTypeId = (typeof PROVIDER_TYPE_IDS)[number];

export const DEFAULT_PROVIDER_TYPE_ID: ProviderTypeId = "openai";

const PROVIDER_TYPE_ID_SET: ReadonlySet<string> = new Set(PROVIDER_TYPE_IDS);

export function isProviderTypeId(value: unknown): value is ProviderTypeId {
  return typeof value === "string" && PROVIDER_TYPE_ID_SET.has(value);
}

/**
 * Compatibility fallback for records created before `provider_type_id` existed.
 * OpenAI-compatible vendors are ambiguous, so their historical default is OpenAI;
 * every new provider must persist the explicit business type selected in Polaris.
 */
export function inferProviderTypeIdFromKind(kind: unknown): ProviderTypeId | null {
  if (typeof kind !== "string") return null;
  switch (kind.trim().toLowerCase()) {
    case "anthropic":
    case "claude":
      return "anthropic";
    case "gemini":
    case "google":
    case "google-gemini":
    case "google_gemini":
    case "vertex":
    case "vertex-ai":
      return "gemini";
    case "grok":
    case "xai":
      return "grok";
    case "deepseek":
      return "deepseek";
    case "minimax":
      return "minimax";
    case "openai":
    case "openai-compatible":
    case "openrouter":
    case "azure":
    case "azure-openai":
      return "openai";
    default:
      return null;
  }
}
