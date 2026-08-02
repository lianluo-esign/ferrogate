/**
 * The PRE-DISPATCH token estimate — `chat.rs::estimate_chat_completion_usage`,
 * `messages.rs::estimate_messages_usage`,
 * `embeddings.rs::estimate_embeddings_usage`, `images.rs::estimate_images_usage`.
 *
 * ## Why the gateway estimates at all
 *
 * Three Rust gates run BEFORE a byte goes upstream and all three are charged
 * with this number: the tokens-per-minute window
 * (`try_consume_api_key_tokens_per_minute`), the monthly token budget, and the
 * prepaid-wallet reservation. Settlement afterwards uses the provider's
 * reported usage, which stays authoritative — the estimate only sizes the
 * reservation. Without it the TPM window has nothing to charge and the gate is
 * inert, which is exactly the state this module was written to end (see the
 * `TokenGovernor` port in `./ports.ts`).
 *
 * Each surface estimates differently, and the differences are load-bearing:
 *
 * | surface        | prompt side                              | completion side |
 * |----------------|------------------------------------------|-----------------|
 * | chat/responses | whole body, minus the non-prompt fields  | `max_completion_tokens` ?? `max_tokens` ?? 512, times `n` |
 * | messages       | `messages` only, minus `type` keys        | `max_tokens` ?? 512 (no `n`) |
 * | embeddings     | `input` only, pre-tokenized ids count 1   | 0 |
 * | images         | 0                                         | `n` (default 1, clamped to 100) generated images |
 *
 * ## PORT-TODO(P: inventory-request-path §1.6 "Budgets", issue #282): the local
 * BPE count is NOT ported; this is the `chars/4` leg only.
 *
 * NOT a platform limit — `js-tiktoken` / `gpt-tokenizer` run fine in workerd,
 * and the Rust vocabularies (`cl100k_base`, `o200k_base`) are embedded rather
 * than fetched, so nothing about Workers forbids it. What is missing is the
 * DEPENDENCY, and precisely that: re-verified for this pass —
 * `grep -c "tiktoken\|gpt-tokenizer" bun.lock` is **0** and no tokenizer is
 * vendored anywhere in the workspace, so there is nothing already paid for that
 * this slice declined to use. Closing it is a `bun install` plus a ~2 MB
 * Worker-script-size decision on `apps/gateway`'s dependency list. Neither is
 * available to a porting slice: adding a dependency changes the lockfile every
 * concurrent workspace shares, and the script-size budget is an operator's call.
 * It is therefore held OPEN deliberately rather than closed by vendoring a
 * vocabulary table into the repo.
 *
 * The approximation implemented instead is the Rust tree's OWN documented
 * fallback — `crate::tokenizer::count_tokens` returns `None` for every model
 * without a bundled vocabulary and `estimate_prompt_tokens` then uses
 * `(chars + 3) / 4`. So this is the exact code path Rust takes today for every
 * opaque tenant alias; it is only the `gpt-4o`/`gpt-4`/`claude` family names
 * that would take the sharper BPE leg.
 *
 * The direction of the error is stated deliberately: for natural-language
 * prompts `chars/4` is an UPPER bound on the BPE count (the Rust test
 * `known_model_prompt_estimate_uses_the_local_tokenizer` asserts exactly that
 * inequality), so the port OVER-reserves. A TPM window therefore refuses at or
 * before the point Rust would, never after — the approximation fails closed.
 * `test/inference/estimate.test.ts` pins that inequality so a future BPE leg
 * cannot be landed in a direction that loosens the gate.
 *
 * Everything else on these four functions is 1:1, including the parts that look
 * like details and are not: the `chars().count()` Unicode-scalar count (JS
 * `String.length` counts UTF-16 code units and would DOUBLE every astral
 * character), the non-prompt field filter, `as_u64`'s rejection of negative and
 * fractional numbers, and the `n > 0` filter.
 */

import { DEFAULT_IMAGE_COUNT, MAX_ESTIMATED_IMAGE_COUNT } from "./schemas.js";

/** Rust `chat.rs`/`messages.rs` `DEFAULT_COMPLETION_TOKEN_RESERVATION`. */
export const DEFAULT_COMPLETION_TOKEN_RESERVATION = 512;

/**
 * `BillingTokenUsage` as the pre-dispatch gates consume it.
 *
 * `totalTokens` is what is charged; the split is kept because the wallet
 * reservation prices the two dimensions at different rates.
 */
export interface EstimatedUsage {
  readonly promptTokens: number;
  readonly completionTokens: number;
  readonly totalTokens: number;
}

function usage(promptTokens: number, completionTokens: number): EstimatedUsage {
  return {
    promptTokens,
    completionTokens,
    totalTokens: promptTokens + completionTokens,
  };
}

/**
 * `serde_json::Value::as_u64` — `undefined` for anything that is not a
 * non-negative integer that fits a `u64`.
 *
 * This is not defensive padding. `as_u64` is why `{"max_tokens": -1}` and
 * `{"max_tokens": 1.5}` fall through to the 512 default in Rust instead of
 * producing a negative or fractional reservation, and why `{"n": -3}` cannot
 * make a multiplication shrink the estimate.
 */
function asU64(value: unknown): number | undefined {
  if (typeof value !== "number") return undefined;
  if (!Number.isInteger(value) || value < 0) return undefined;
  return value;
}

function get(value: unknown, key: string): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  return (value as Record<string, unknown>)[key];
}

function asArray(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Rust `text.chars().count()` — Unicode SCALAR VALUES, not UTF-16 code units.
 *
 * `"😀".length` is 2 in JS and 1 in Rust. Using `.length` would inflate every
 * emoji/CJK-astral prompt's estimate by up to 2x and make the port charge a TPM
 * window differently from the Rust it replaces.
 */
function charCount(text: string): number {
  let count = 0;
  for (const _ of text) count += 1;
  return count;
}

/** `(chars + 3) / 4` with Rust's integer (flooring) division. */
function charsToTokens(chars: number): number {
  return Math.floor((chars + 3) / 4);
}

// ---------------------------------------------------------------------------
// chat.completions + responses
// ---------------------------------------------------------------------------

/**
 * `chat.rs::is_non_prompt_request_field` — request KNOBS that are not prompt
 * text, excluded so a long `user` id or a big `seed` cannot inflate the
 * estimate, and (more importantly) so the estimate tracks the prompt.
 */
export function isNonPromptRequestField(key: string): boolean {
  switch (key) {
    case "model":
    case "stream":
    case "max_tokens":
    case "max_completion_tokens":
    case "temperature":
    case "top_p":
    case "n":
    case "presence_penalty":
    case "frequency_penalty":
    case "seed":
    case "user":
      return true;
    default:
      return false;
  }
}

/** `chat.rs::prompt_character_count`. */
function promptCharacterCount(value: unknown, key: string | undefined): number {
  if (key !== undefined && isNonPromptRequestField(key)) return 0;
  if (typeof value === "string") return charCount(value);
  const items = asArray(value);
  if (items !== undefined) {
    let sum = 0;
    for (const item of items) sum += promptCharacterCount(item, undefined);
    return sum;
  }
  if (isPlainObject(value)) {
    let sum = 0;
    for (const [childKey, child] of Object.entries(value)) {
      sum += promptCharacterCount(child, childKey);
    }
    return sum;
  }
  return 0;
}

/** `chat.rs::message_overhead_tokens` — 4 tokens per message (ChatML framing). */
function messageOverheadTokens(body: unknown): number {
  const messages = asArray(get(body, "messages"));
  return messages === undefined ? 0 : messages.length * 4;
}

/** `chat.rs::requested_completion_tokens`. `max_completion_tokens` wins. */
function requestedCompletionTokens(body: unknown): number | undefined {
  const preferred = asU64(get(body, "max_completion_tokens"));
  return preferred ?? asU64(get(body, "max_tokens"));
}

/** `chat.rs::requested_choice_count` — `n`, ignoring 0 and anything not a `u64`. */
function requestedChoiceCount(body: unknown): number {
  const n = asU64(get(body, "n"));
  return n !== undefined && n > 0 ? n : 1;
}

/**
 * `chat.rs::estimate_chat_completion_usage`, serving both
 * `/v1/chat/completions` and `/v1/responses` exactly as the Rust does (both go
 * through `build_chat_completion_request_plan`).
 *
 * `model` is accepted and unused: it is the tokenizer-selection argument, and
 * keeping it in the signature means landing the BPE leg is a change to this
 * function's body and to nothing else. See the module PORT-TODO.
 */
export function estimateChatCompletionUsage(body: unknown, _model: string): EstimatedUsage {
  const promptTokens =
    charsToTokens(promptCharacterCount(body, undefined)) + messageOverheadTokens(body);
  const completionTokens =
    (requestedCompletionTokens(body) ?? DEFAULT_COMPLETION_TOKEN_RESERVATION) *
    requestedChoiceCount(body);
  return usage(promptTokens, completionTokens);
}

// ---------------------------------------------------------------------------
// messages
// ---------------------------------------------------------------------------

/**
 * `messages.rs::prompt_character_count` — a DIFFERENT traversal from the chat
 * one: it walks only the `messages` value it is handed, and its object filter
 * drops exactly one key, `type` (the Anthropic content-block discriminator
 * `"text"`/`"image"`/`"tool_use"`, which is structure, not prompt).
 */
function messagesCharacterCount(value: unknown): number {
  if (typeof value === "string") return charCount(value);
  const items = asArray(value);
  if (items !== undefined) {
    let sum = 0;
    for (const item of items) sum += messagesCharacterCount(item);
    return sum;
  }
  if (isPlainObject(value)) {
    let sum = 0;
    for (const [key, child] of Object.entries(value)) {
      if (key === "type") continue;
      sum += messagesCharacterCount(child);
    }
    return sum;
  }
  return 0;
}

/**
 * `messages.rs::estimate_messages_usage`.
 *
 * Charged against the TRANSLATED OpenAI-shaped body, not the Anthropic one the
 * client sent — `handle_messages` estimates after `to_chat_completions`, so the
 * system prompt Anthropic carries top-level is already folded into
 * `messages[0]` and therefore counted. Estimating the untranslated body would
 * silently drop the system prompt from the reservation.
 *
 * No `n` multiplier: the Anthropic Messages API has no `n`.
 */
export function estimateMessagesUsage(chatBody: unknown, _model: string): EstimatedUsage {
  const messages = get(chatBody, "messages");
  const overhead = messageOverheadTokens(chatBody);
  const promptTokens = charsToTokens(messagesCharacterCount(messages)) + overhead;
  const completionTokens =
    asU64(get(chatBody, "max_tokens")) ?? DEFAULT_COMPLETION_TOKEN_RESERVATION;
  return usage(promptTokens, completionTokens);
}

/**
 * The number `POST /v1/messages/count_tokens` answers with (issue #671).
 *
 * It is deliberately a one-line projection of {@link estimateMessagesUsage}
 * rather than its own traversal. The endpoint's entire value proposition is
 * that the count a client pre-flights with is the count the gateway will
 * reserve against that client's TPM window, monthly token budget and prepaid
 * wallet when the identical body is actually sent — so the two numbers must be
 * produced by ONE piece of arithmetic. A second estimator here, however
 * faithful on the day it was written, is a number that can drift away from the
 * bill, and a count that silently disagrees with the bill is worse than no
 * endpoint: it converts "I could not pre-estimate" into "I pre-estimated
 * wrongly and believed it".
 *
 * The argument is the TRANSLATED, OpenAI-shaped body for the same reason
 * `handleMessages` estimates over the translated body: `to_chat_completions`
 * folds Anthropic's top-level `system` prompt into `messages[0]`, so counting
 * the untranslated request would under-report every request that carries one.
 *
 * Only the PROMPT half is returned. `estimateMessagesUsage`'s completion half
 * is a RESERVATION against `max_tokens` (or the 512 default), i.e. an output
 * budget the caller chose, not an input measurement — Anthropic's
 * `count_tokens` reports `input_tokens` and nothing else, and folding an output
 * reservation into it would answer a question nobody asked. The relationship
 * between the two is pinned by `test/inference/count-tokens.test.ts`:
 * `reservation === input_tokens + completion reservation`.
 *
 * Sharpening the estimate (the BPE leg described in this module's PORT-TODO)
 * therefore lands in `estimateMessagesUsage` and moves both numbers together,
 * which is the property this indirection exists to guarantee.
 */
export function countMessagesInputTokens(chatBody: unknown, model: string): number {
  return estimateMessagesUsage(chatBody, model).promptTokens;
}

// ---------------------------------------------------------------------------
// embeddings
// ---------------------------------------------------------------------------

/**
 * `embeddings.rs::embeddings_element_tokens`.
 *
 * The JSON-number arm is the security-relevant one (issue #207): OpenAI accepts
 * a PRE-TOKENIZED `input` — a flat array of token ids, or an array of such
 * arrays for a batch — and a character-only count scores those at 0, letting a
 * caller drive unlimited real embedding tokens past the TPM, token-budget and
 * wallet gates. Each id is already exactly one token.
 */
function embeddingsElementTokens(element: unknown): number {
  if (typeof element === "string") {
    return charsToTokens(charCount(element));
  }
  if (typeof element === "number") {
    return 1;
  }
  const items = asArray(element);
  if (items !== undefined) {
    let sum = 0;
    for (const item of items) sum += embeddingsElementTokens(item);
    return sum;
  }
  return 0;
}

/**
 * `embeddings.rs::estimate_embeddings_usage` + `estimate_embeddings_input_tokens`.
 *
 * The floor is deliberate and asymmetric: a PRESENT, non-empty `input` is
 * floored to 1 token so a tiny or odd input still engages the gates, while an
 * explicitly empty string/array stays 0 and reserves nothing.
 */
export function estimateEmbeddingsUsage(body: unknown, _model: string): EstimatedUsage {
  const input = get(body, "input");
  const counted =
    typeof input === "string" || Array.isArray(input) ? embeddingsElementTokens(input) : 0;
  let promptTokens = counted;
  if (typeof input === "string" && input.length > 0) {
    promptTokens = Math.max(counted, 1);
  } else if (Array.isArray(input) && input.length > 0) {
    promptTokens = Math.max(counted, 1);
  }
  return usage(promptTokens, 0);
}

// ---------------------------------------------------------------------------
// images
// ---------------------------------------------------------------------------

/**
 * `images.rs::requested_image_count`.
 *
 * `DEFAULT_IMAGE_COUNT` / `MAX_ESTIMATED_IMAGE_COUNT` are imported from
 * `./schemas.ts` rather than re-declared: two copies of a clamp is exactly how a
 * cap silently stops matching the schema that admits the field.
 */
export function requestedImageCount(body: unknown): number {
  const n = asU64(get(body, "n"));
  const requested = n !== undefined && n > 0 ? n : DEFAULT_IMAGE_COUNT;
  return Math.min(requested, MAX_ESTIMATED_IMAGE_COUNT);
}

/**
 * `images.rs::estimate_images_usage` (issue #275).
 *
 * The unit is GENERATED IMAGES, carried on the completion dimension so the
 * same gates engage against the same non-token quantity the ledger settles.
 * The clamp is what stops a hostile `"n": 100000000` from pre-charging a
 * caller's whole window (and, in the wallet's case, their whole balance) on a
 * request the provider would have refused anyway.
 */
export function estimateImagesUsage(body: unknown): EstimatedUsage {
  const images = requestedImageCount(body);
  return usage(0, images);
}
