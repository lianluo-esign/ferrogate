/**
 * Recover a token count from a buffered success body that carried NO usage
 * object (#976 Phase B1).
 *
 * The extractors in `./usage.ts` return `undefined` when a provider omits usage
 * — a native Anthropic response with the field dropped, an OAuth/subscription
 * upstream that never reports it, a family whose envelope this gateway has not
 * yet learned. Before this module such a call was metered at $0. Here the
 * gateway counts the tokens itself, over the same text it forwarded and
 * received, using the local BPE tokenizer (`./tokenizer.ts`).
 *
 * ## Scope and honesty
 *
 * This is the LAST resort, invoked only when the dialect-correct extractor found
 * nothing on a VALID 2xx body — the caller keeps `recordUsage(..., undefined)`
 * on error and invalid-body branches, so a garbage response is never dressed up
 * as a measured one. The count is an approximation: it reads the visible prompt
 * and completion TEXT, not tool-call arguments or structured outputs, so a
 * response that is all tool calls under-counts its completion side. That is a
 * documented under-bill on a narrow subset, and still strictly better than the
 * $0 it replaces. The result is tagged `local_tokenizer` (not `provider_usage`)
 * precisely so a report can tell a recovered count from a measured one.
 *
 * ## Prompt vs completion dialect
 *
 * The two halves are read from DIFFERENT bytes. The prompt harvester
 * ({@link promptTextFrom}) is dialect-agnostic — it mirrors
 * `estimate.ts::promptCharacterCount`, walking the request body and collecting
 * every string leaf except the non-prompt knobs — because a request in any
 * ingress shape (OpenAI `messages`, Responses `input`, Gemini `contents`) is
 * just prompt text under structural keys. The completion harvester
 * ({@link completionTextFrom}) IS dialect-specific: a response body carries ids,
 * roles and finish reasons a generic walk would wrongly bill, so each family's
 * generated-text location is read explicitly.
 */
import { countTokens } from "./tokenizer.js";
import type { ProviderUsage, UsageDialect } from "./usage.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function get(value: unknown, key: string): unknown {
  return isRecord(value) ? value[key] : undefined;
}

function asArray(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

function pushText(out: string[], value: unknown): void {
  if (typeof value === "string" && value.length > 0) out.push(value);
}

/**
 * Request KNOBS that are not prompt text, skipped so a long `user` id, a `seed`,
 * or the Anthropic content-block `type` discriminator cannot inflate the count.
 *
 * This is the union of `estimate.ts::isNonPromptRequestField` and the `type` key
 * `messages.rs::prompt_character_count` drops — the two traversals the pre-
 * dispatch estimate uses, merged so ONE harvester serves every ingress shape.
 */
const NON_PROMPT_KEYS: ReadonlySet<string> = new Set([
  "model",
  "stream",
  "max_tokens",
  "max_completion_tokens",
  "temperature",
  "top_p",
  "n",
  "presence_penalty",
  "frequency_penalty",
  "seed",
  "user",
  "type",
]);

function collectPromptText(value: unknown, key: string | undefined, out: string[]): void {
  if (key !== undefined && NON_PROMPT_KEYS.has(key)) return;
  if (typeof value === "string") {
    pushText(out, value);
    return;
  }
  const items = asArray(value);
  if (items !== undefined) {
    for (const item of items) collectPromptText(item, undefined, out);
    return;
  }
  if (isRecord(value)) {
    for (const [childKey, child] of Object.entries(value)) {
      collectPromptText(child, childKey, out);
    }
  }
}

/** The prompt text of a request in any ingress dialect, joined for counting. */
export function promptTextFrom(requestBody: unknown): string {
  const out: string[] = [];
  collectPromptText(requestBody, undefined, out);
  return out.join("\n");
}

/** OpenAI `content`: a bare string, or an array of `{ text }` content parts. */
function collectContentParts(content: unknown, out: string[]): void {
  if (typeof content === "string") {
    pushText(out, content);
    return;
  }
  for (const part of asArray(content) ?? []) {
    if (typeof part === "string") pushText(out, part);
    else pushText(out, get(part, "text"));
  }
}

/** Generated text out of a buffered response, by the dialect the body is in. */
export function completionTextFrom(dialect: UsageDialect, body: unknown): string {
  const out: string[] = [];
  switch (dialect) {
    case "openai": {
      // Chat Completions: `choices[].message.content`.
      for (const choice of asArray(get(body, "choices")) ?? []) {
        collectContentParts(get(get(choice, "message"), "content"), out);
      }
      // Responses: `output[].content[].text`.
      for (const item of asArray(get(body, "output")) ?? []) {
        collectContentParts(get(item, "content"), out);
      }
      break;
    }
    case "anthropic": {
      for (const block of asArray(get(body, "content")) ?? []) {
        pushText(out, get(block, "text"));
      }
      break;
    }
    case "gemini": {
      for (const candidate of asArray(get(body, "candidates")) ?? []) {
        for (const part of asArray(get(get(candidate, "content"), "parts")) ?? []) {
          pushText(out, get(part, "text"));
        }
      }
      break;
    }
    case "bedrock": {
      const content = get(get(get(body, "output"), "message"), "content");
      for (const block of asArray(content) ?? []) {
        pushText(out, get(block, "text"));
      }
      break;
    }
  }
  return out.join("\n");
}

/**
 * The recovered usage for a buffered call whose body carried no usage object, or
 * `undefined` when neither side yielded any text to count (an empty-bodied
 * success — nothing to bill, and inventing a floor here would mislabel it).
 *
 * `completionDialect` is the dialect of the RESPONSE bytes (the upstream's
 * native shape on the buffered path), which is not always the ingress dialect —
 * a `/v1/messages` request served by an OpenAI upstream returns OpenAI-shaped
 * bytes. `requestBody` is whatever body the estimate for this surface was taken
 * over (the translated OpenAI body for `/v1/messages`, the native body
 * otherwise), so the prompt count tracks the same text the reservation did.
 */
export function localFallbackUsage(
  requestBody: unknown,
  responseBody: unknown,
  completionDialect: UsageDialect,
  model: string,
): ProviderUsage | undefined {
  const promptText = promptTextFrom(requestBody);
  const completionText = completionTextFrom(completionDialect, responseBody);
  const promptTokens = promptText.length > 0 ? countTokens(promptText, model) : 0;
  const completionTokens = completionText.length > 0 ? countTokens(completionText, model) : 0;
  if (promptTokens === 0 && completionTokens === 0) {
    return undefined;
  }
  return {
    promptTokens,
    completionTokens,
    totalTokens: promptTokens + completionTokens,
  };
}
