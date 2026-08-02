/**
 * Canonical prompt-caching directive + per-family translation (issue #690).
 *
 * ## Why this module exists
 *
 * `cache_control` is an Anthropic-shaped marker. It survived to an Anthropic
 * upstream only because the message list is copied through; every other family
 * has a different mechanism and rebuilds the body, so the marker fell on the
 * floor. The result was that cache economics differed per ROUTE with no way for
 * the caller to reason about them: the same request could be served with a 90%
 * prefix discount on one leg of a failover and at full price on the next, and a
 * caller who needed the prompt NOT cached had no way to say so at all.
 *
 * This is the money-side twin of {@link ./structured.ts}'s output-contract
 * drift (#674), so it follows that module's shape exactly: parse ONE canonical
 * intent, re-emit it in each family's dialect, and REFUSE what a family cannot
 * express rather than serve it under different rules.
 *
 * | family                | mechanism                                          |
 * |-----------------------|----------------------------------------------------|
 * | Anthropic (Messages)  | `cache_control: {type:"ephemeral", ttl?}` breakpoint |
 * | Bedrock (Converse)    | a `{"cachePoint":{"type":"default"}}` block          |
 * | OpenAI-compatible     | automatic caching — nothing to send                 |
 * | Gemini / Vertex       | implicit caching — nothing to send                  |
 * | Workers AI            | no prompt cache at all                              |
 *
 * ## The three modes, and why they are only three
 *
 * `auto` is a HINT: "use whatever prefix caching you have." Every family can
 * satisfy it — the two with breakpoints get one, the two that cache implicitly
 * already do it, and a family with no cache satisfies it vacuously because
 * nothing was promised. It never refuses, so it never costs a route.
 *
 * `explicit` is a CONTRACT: "cache the static prefix, for this long." Only the
 * breakpoint families can promise that, and only Anthropic can promise a
 * lifetime other than the default, so everything else refuses.
 *
 * `off` is also a contract, in the other direction: "do not write this prompt
 * into a provider prompt cache." It is a retention/isolation requirement, not a
 * cost knob, which is why a family whose caching cannot be disabled must refuse
 * rather than answer 200 while doing the opposite. On the families that CAN
 * honour it, honouring it means stripping any native marker the caller left in
 * the body — otherwise the directive would be a comment rather than a control.
 *
 * ## Relationship to the accounting side (#667)
 *
 * This module is the directive going OUT. The hit/miss split coming BACK is
 * already normalized at capture time by #667 (`cachedInputTokens` /
 * `cacheWriteTokens` on `ProviderUsage`), which is the precondition for
 * normalizing a mechanism at all: emitting a cache breakpoint whose tokens
 * nobody counts would HIDE the cost instead of exposing it. The 1.25x write
 * premium a breakpoint incurs is visible as `cache_write_tokens` for exactly
 * that reason.
 */
import { AdapterError } from "./types.js";
import { asObject, asStr, getField, isArray, isObject } from "./json.js";
import type { Json, JsonObject } from "./json.js";

/** The body member a caller sets to state a caching intent. */
export const PROMPT_CACHE_MEMBER = "prompt_cache";

/** Cache lifetimes the canonical form can express — Anthropic's two TTLs. */
export type PromptCacheTtl = "5m" | "1h";

/** The provider-neutral caching intent a request stated. */
export type CanonicalPromptCache =
  /** Best effort: use whatever prefix caching the family offers. Never refused. */
  | { readonly kind: "auto" }
  /** A promise: a cache breakpoint at the static prefix, with this lifetime. */
  | { readonly kind: "explicit"; readonly ttl: PromptCacheTtl }
  /** A promise: this prompt is not written into a provider prompt cache. */
  | { readonly kind: "off" };

/**
 * Read (and do NOT remove) the directive from a chat/responses body.
 *
 * Removal is {@link stripPromptCacheDirective}'s job and happens in the adapter
 * that copies the caller's body through, because `prompt_cache` is FerroGate's
 * own member: OpenAI rejects unknown top-level fields, so leaving it on a
 * passthrough body would turn a caching hint into a 400.
 */
export function promptCacheFromBody(body: Json | undefined): CanonicalPromptCache | undefined {
  const value = getField(body, PROMPT_CACHE_MEMBER);
  if (value === undefined || value === null) return undefined;
  const object = asObject(value);
  if (!object) {
    throw AdapterError.invalidRequest(`\`${PROMPT_CACHE_MEMBER}\` must be a JSON object`);
  }
  const mode = asStr(object["mode"]);
  if (mode === undefined) {
    throw AdapterError.invalidRequest(
      `\`${PROMPT_CACHE_MEMBER}\` must carry a string \`mode\` ("auto", "explicit" or "off")`,
    );
  }
  const ttl = readTtl(object["ttl"]);
  switch (mode) {
    case "auto":
    case "off":
      // A lifetime is only meaningful for the mode that promises one. Accepting
      // it silently on the other two would let a caller believe it had asked
      // for a 1h cache when it had asked for nothing of the kind.
      if (ttl !== undefined) {
        throw AdapterError.invalidRequest(
          `\`${PROMPT_CACHE_MEMBER}.ttl\` is only meaningful with \`mode: "explicit"\``,
        );
      }
      return mode === "auto" ? { kind: "auto" } : { kind: "off" };
    case "explicit":
      return { kind: "explicit", ttl: ttl ?? "5m" };
    default:
      throw AdapterError.invalidRequest(
        `\`${PROMPT_CACHE_MEMBER}.mode\` must be "auto", "explicit" or "off" (got "${mode}")`,
      );
  }
}

function readTtl(value: Json | undefined): PromptCacheTtl | undefined {
  if (value === undefined || value === null) return undefined;
  const ttl = asStr(value);
  if (ttl !== "5m" && ttl !== "1h") {
    throw AdapterError.invalidRequest(
      `\`${PROMPT_CACHE_MEMBER}.ttl\` must be "5m" or "1h" (got ${JSON.stringify(value)})`,
    );
  }
  return ttl;
}

/** Remove the FerroGate-only member so it never reaches a provider. */
export function stripPromptCacheDirective(body: JsonObject): void {
  delete body[PROMPT_CACHE_MEMBER];
}

// ---------------------------------------------------------------------------
// Anthropic — `cache_control` breakpoints
// ---------------------------------------------------------------------------

const ANTHROPIC_CACHE_MEMBER = "cache_control";

/**
 * Apply the directive to an Anthropic `/v1/messages` body, in place.
 *
 * Anthropic caches by PREFIX, rendered `tools` → `system` → `messages`, so a
 * single breakpoint at the end of `system` covers the tools and the system
 * prompt while leaving the volatile turn outside the cached span. That is the
 * one placement that is right for the general case: marking the tools instead
 * would end the prefix before the system prompt, and marking the last message
 * would write the whole conversation into the cache on every turn.
 *
 * When there is no static prefix at all — no system, no tools — the fallback is
 * the last content block of the last message. That is the documented
 * incremental-caching pattern for multi-turn conversations: this turn pays a
 * write and the next turn reads it. The write is NOT free (1.25x), which is
 * exactly why #667's `cache_write_tokens` had to land first.
 *
 * A caller that placed its own `cache_control` markers has already made these
 * decisions; the directive then validates but does not add a second breakpoint,
 * because Anthropic allows only four and the caller's placement is the more
 * informed one.
 */
export function applyPromptCacheToAnthropic(
  body: JsonObject,
  directive: CanonicalPromptCache,
  _providerKind: string,
): void {
  if (directive.kind === "off") {
    stripCacheControl(body);
    return;
  }
  if (bodyHasCacheControl(body)) return;

  const marker: JsonObject =
    directive.kind === "explicit" && directive.ttl === "1h"
      ? { type: "ephemeral", ttl: "1h" }
      : { type: "ephemeral" };

  if (markLastAnthropicSystemBlock(body, marker)) return;
  // An OpenAI-shaped body carries the system prompt as a leading `system`-ROLE
  // message rather than as a top-level field, and that is the shape the
  // `/v1/chat/completions` and `/v1/messages` ingresses hand this adapter. The
  // boundary is the same one; only the spelling differs.
  if (markLastAnthropicSystemMessage(body, marker)) return;
  if (markLastAnthropicTool(body, marker)) return;
  markLastAnthropicMessageBlock(body, marker);
}

/** `system` as a string is promoted to a one-element block array to carry it. */
function markLastAnthropicSystemBlock(body: JsonObject, marker: JsonObject): boolean {
  const system = body["system"];
  if (typeof system === "string") {
    if (system.length === 0) return false;
    body["system"] = [{ type: "text", text: system, [ANTHROPIC_CACHE_MEMBER]: marker }];
    return true;
  }
  if (isArray(system) && system.length > 0) {
    const last = system[system.length - 1];
    if (!isObject(last)) return false;
    last[ANTHROPIC_CACHE_MEMBER] = marker;
    return true;
  }
  return false;
}

function markLastAnthropicSystemMessage(body: JsonObject, marker: JsonObject): boolean {
  const messages = body["messages"];
  if (!isArray(messages)) return false;
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index];
    if (!isObject(message) || asStr(message["role"]) !== "system") continue;
    // Never the LAST message: a body whose final turn is the system prompt has
    // no volatile suffix, so a breakpoint there would cache the whole request
    // and read back nothing.
    if (index === messages.length - 1) return false;
    return markLastContentBlock(message, marker);
  }
  return false;
}

function markLastAnthropicTool(body: JsonObject, marker: JsonObject): boolean {
  const tools = body["tools"];
  if (!isArray(tools) || tools.length === 0) return false;
  const last = tools[tools.length - 1];
  if (!isObject(last)) return false;
  last[ANTHROPIC_CACHE_MEMBER] = marker;
  return true;
}

function markLastAnthropicMessageBlock(body: JsonObject, marker: JsonObject): void {
  const messages = body["messages"];
  if (!isArray(messages) || messages.length === 0) return;
  const last = messages[messages.length - 1];
  if (isObject(last)) markLastContentBlock(last, marker);
}

/** Mark a message's final content block, promoting a string body to a block. */
function markLastContentBlock(message: JsonObject, marker: JsonObject): boolean {
  const content = message["content"];
  if (typeof content === "string") {
    message["content"] = [{ type: "text", text: content, [ANTHROPIC_CACHE_MEMBER]: marker }];
    return true;
  }
  if (isArray(content) && content.length > 0) {
    const block = content[content.length - 1];
    if (isObject(block)) {
      block[ANTHROPIC_CACHE_MEMBER] = marker;
      return true;
    }
  }
  return false;
}

/** True when the caller already placed at least one breakpoint of its own. */
function bodyHasCacheControl(value: Json | undefined): boolean {
  if (isArray(value)) return value.some(bodyHasCacheControl);
  if (!isObject(value)) return false;
  if (value[ANTHROPIC_CACHE_MEMBER] !== undefined) return true;
  return Object.values(value).some(bodyHasCacheControl);
}

/** Recursively remove every `cache_control` marker — what `off` MEANS. */
function stripCacheControl(value: Json | undefined): void {
  if (isArray(value)) {
    for (const entry of value) stripCacheControl(entry);
    return;
  }
  if (!isObject(value)) return;
  delete value[ANTHROPIC_CACHE_MEMBER];
  for (const entry of Object.values(value)) stripCacheControl(entry);
}

// ---------------------------------------------------------------------------
// Bedrock Converse — `cachePoint`
// ---------------------------------------------------------------------------

const BEDROCK_CACHE_MEMBER = "cachePoint";

/**
 * Apply the directive to a Bedrock `Converse` body, in place.
 *
 * Converse expresses the same prefix boundary as a `cachePoint` BLOCK appended
 * to `system` / a message's `content` / `toolConfig.tools`, rather than as a
 * member of the preceding block. What it does NOT express is a lifetime: the
 * checkpoint lives for Bedrock's own (~5 minute) window and there is no dial,
 * so a 1h contract is refused here instead of being served as 5m.
 *
 * Anthropic-on-Bedrock is the most common failover partner for a direct
 * Anthropic route, so leaving this family out would have preserved the defect
 * for exactly the pair that most needs it fixed.
 */
export function applyPromptCacheToBedrockConverse(
  body: JsonObject,
  directive: CanonicalPromptCache,
  providerKind: string,
): void {
  if (directive.kind === "off") {
    // Converse only caches where a cachePoint says to, so "do not cache" is
    // honoured by emitting none — and by removing any the body already carries.
    stripCachePoints(body);
    return;
  }
  if (directive.kind === "explicit" && directive.ttl === "1h") {
    throw AdapterError.unsupportedCapability(
      'prompt caching (Bedrock Converse cachePoint has no selectable lifetime; send ttl "5m")',
      providerKind,
    );
  }
  const point: JsonObject = { [BEDROCK_CACHE_MEMBER]: { type: "default" } };
  if (appendBedrockCachePoint(body["system"], point)) return;
  if (appendBedrockCachePoint(getField(body["toolConfig"], "tools"), point)) return;
  const messages = body["messages"];
  if (!isArray(messages) || messages.length === 0) return;
  const last = messages[messages.length - 1];
  if (isObject(last)) appendBedrockCachePoint(last["content"], point);
}

function appendBedrockCachePoint(target: Json | undefined, point: JsonObject): boolean {
  if (!isArray(target) || target.length === 0) return false;
  if (target.some((entry) => getField(entry, BEDROCK_CACHE_MEMBER) !== undefined)) return true;
  target.push({ ...point });
  return true;
}

function stripCachePoints(value: Json | undefined): void {
  if (isArray(value)) {
    for (let index = value.length - 1; index >= 0; index -= 1) {
      const entry = value[index];
      if (isObject(entry) && entry[BEDROCK_CACHE_MEMBER] !== undefined) {
        value.splice(index, 1);
        continue;
      }
      stripCachePoints(entry);
    }
    return;
  }
  if (!isObject(value)) return;
  for (const entry of Object.values(value)) stripCachePoints(entry);
}

// ---------------------------------------------------------------------------
// The families whose caching is automatic
// ---------------------------------------------------------------------------

/**
 * OpenAI-compatible, Gemini/Vertex, and Workers AI: nothing is emitted, and the
 * question is only which intents may be accepted in silence.
 *
 *  - `auto` is satisfied by construction wherever caching is automatic, and
 *    satisfied vacuously where there is no cache. Never refused.
 *  - `explicit` is refused by the automatic families: they choose the prefix
 *    and the lifetime themselves, so promising a caller's breakpoint would be a
 *    promise nobody kept. `cachesNothing` families refuse it too — there is no
 *    cache at all.
 *  - `off` is refused wherever caching is automatic and cannot be disabled per
 *    request, and ACCEPTED where there is no prompt cache to begin with.
 *
 * The refusal removes the route from the ladder for this request (the #674
 * mechanism), so a caller with a mixed-family logical model is served by a
 * route that can honour the contract rather than one that cannot.
 */
export function applyPromptCacheToAutomaticFamily(
  directive: CanonicalPromptCache,
  providerKind: string,
  options: { readonly cachesNothing?: boolean } = {},
): void {
  if (directive.kind === "auto") return;
  const cachesNothing = options.cachesNothing === true;
  if (directive.kind === "off") {
    if (cachesNothing) return;
    throw AdapterError.unsupportedCapability(
      "prompt caching (this family caches prompts automatically and cannot be told not to; send mode \"auto\")",
      providerKind,
    );
  }
  throw AdapterError.unsupportedCapability(
    cachesNothing
      ? 'prompt caching (this family has no prompt cache; send mode "auto")'
      : 'prompt caching (this family chooses its own cache prefix and lifetime; send mode "auto")',
    providerKind,
  );
}

/**
 * Read the directive off a request body and adjudicate it for a family with no
 * per-request mechanism. The body is NOT modified: Gemini, Vertex and Workers
 * AI rebuild the upstream body field-by-field, so there is nothing to strip.
 * The passthrough family (OpenAI-compatible) calls
 * {@link stripPromptCacheDirective} itself, on the body it is about to send.
 */
export function assertPromptCacheForAutomaticFamily(
  body: Json | undefined,
  providerKind: string,
  options: { readonly cachesNothing?: boolean } = {},
): void {
  const directive = promptCacheFromBody(body);
  if (directive !== undefined) {
    applyPromptCacheToAutomaticFamily(directive, providerKind, options);
  }
}
