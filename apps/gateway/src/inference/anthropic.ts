/**
 * Anthropic Messages ⇄ OpenAI chat-completions translation.
 *
 * Clean-room port of `ferrogate-providers/src/anthropic_messages.rs` (issue
 * #272). Pure JSON⇄JSON: no I/O, no governance, no state — the Rust module made
 * the same promise so it stayed unit-testable in isolation, and this one keeps
 * it.
 *
 * Why it exists at all: `/v1/messages` is a Claude-protocol-native ingress, but
 * FerroGate routes it through the SAME governed chokepoint the OpenAI ingress
 * uses so every adapter family is reachable as an upstream. The request is
 * translated into an OpenAI chat body on the way in, and the provider's
 * chat-completion is translated back into an Anthropic Message on the way out.
 * An Anthropic upstream round-trips: the adapter converts the OpenAI body back
 * to Anthropic shape, and `chatCompletionToMessage` detects an already-Anthropic
 * response and passes it through untouched.
 *
 * This is the default implementation of the `AnthropicTranslator` port; it moves
 * to `@ferrogate/providers` when that package is ported.
 */
import { AdapterError, PROMPT_CACHE_MEMBER } from "@ferrogate/providers";

import type { AnthropicTranslator, TranslationResult } from "./ports.js";

type Json = Record<string, unknown>;

function asRecord(value: unknown): Json | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Json)
    : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asArray(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

function asUint(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function get(value: unknown, key: string): unknown {
  return asRecord(value)?.[key];
}

/**
 * Rust `Value::to_string()` on a non-string value — compact JSON, no spaces.
 * `JSON.stringify` produces the same text for every JSON value serde_json can
 * hold, which is what the `stringify_arguments` / `tool_result_to_text`
 * fallbacks rely on.
 */
function valueToString(value: unknown): string {
  return JSON.stringify(value) ?? "null";
}

// ---------------------------------------------------------------------------
// Request direction — `to_chat_completions`
// ---------------------------------------------------------------------------

/**
 * The Anthropic members this translation RE-SPELLS; everything else is carried
 * across untouched (issue #725).
 *
 * The list used to run the other way round — a `SCALAR_PASSTHROUGH` allowlist of
 * `model` / `max_tokens` / `temperature` / `top_p` / `stream`, which #690 had
 * already been forced to widen once for `prompt_cache`. An allowlist loses the
 * NEXT member by default and only stops losing it when a human notices, and
 * `/v1/messages` is a live protocol Anthropic keeps adding to (`top_k`,
 * `thinking`, `service_tier`, `container`, `mcp_servers`, …). So the default is
 * inverted: a member with an OpenAI spelling is translated below, a member
 * FerroGate owns is handled below, and ANY OTHER member rides along. It then
 * either survives back to an Anthropic upstream unchanged — which is the whole
 * point — or draws a 400 from a non-Anthropic upstream that names it. Neither
 * outcome is the silent 200 this issue is about.
 *
 * `system` is in the list because Rust folds the Anthropic top-level system
 * prompt into `messages[0]` as a `system`-role turn, and that is the shape the
 * OpenAI-side estimator, guardrails and adapters all expect. It is lifted back
 * to the top-level parameter on the way out (see {@link chatCompletionsToMessages}).
 */
const ANTHROPIC_RESPELLED = new Set<string>([
  "system",
  "messages",
  "stop_sequences",
  "tools",
  "tool_choice",
  "metadata",
  PROMPT_CACHE_MEMBER,
]);

/**
 * `anthropic_system_to_text` — Anthropic carries the system prompt as a
 * top-level field (a string, or an array of text blocks joined with `\n`).
 * Returns `undefined` for an empty result so no empty system turn is emitted.
 */
function systemToText(system: unknown): string | undefined {
  const text = asString(system);
  if (text !== undefined) {
    return text.length > 0 ? text : undefined;
  }
  const blocks = asArray(system);
  if (blocks !== undefined) {
    const joined = blocks
      .map((block) => asString(get(block, "text")))
      .filter((value): value is string => value !== undefined)
      .join("\n");
    return joined.length > 0 ? joined : undefined;
  }
  return undefined;
}

/**
 * `collapse_content` — a lone text block collapses to a plain string (the shape
 * most upstreams prefer); anything richer stays an OpenAI content-part array.
 * An empty part list becomes `null`, matching `Value::Null`.
 */
function collapseContent(parts: readonly Json[]): unknown {
  if (parts.length === 0) {
    return null;
  }
  const [single] = parts;
  if (parts.length === 1 && single !== undefined && single.type === "text") {
    return single.text ?? "";
  }
  return [...parts];
}

/** `anthropic_image_to_data_url`. */
function imageBlockToUrl(block: unknown): string | undefined {
  const source = get(block, "source");
  if (source === undefined) {
    return undefined;
  }
  switch (asString(get(source, "type"))) {
    case "base64": {
      const mediaType = asString(get(source, "media_type")) ?? "image/png";
      const data = asString(get(source, "data"));
      return data === undefined ? undefined : `data:${mediaType};base64,${data}`;
    }
    case "url":
      return asString(get(source, "url"));
    default:
      return undefined;
  }
}

/** `tool_result_to_text`. */
function toolResultToText(content: unknown): string {
  if (content === undefined) {
    return "";
  }
  const text = asString(content);
  if (text !== undefined) {
    return text;
  }
  const blocks = asArray(content);
  if (blocks !== undefined) {
    return blocks.map((block) => asString(get(block, "text")) ?? valueToString(block)).join("\n");
  }
  return valueToString(content);
}

/** `stringify_arguments` — OpenAI wants `function.arguments` as a JSON string. */
function stringifyArguments(input: unknown): string {
  if (input === undefined) {
    return "{}";
  }
  return asString(input) ?? valueToString(input);
}

/** `parse_arguments` — and back again; an unparseable string degrades to `{}`. */
export function parseArguments(argumentsValue: unknown): unknown {
  if (argumentsValue === undefined) {
    return {};
  }
  const text = asString(argumentsValue);
  if (text === undefined) {
    return argumentsValue;
  }
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

/** `anthropic_tool_to_openai`. */
function toolToOpenAi(tool: unknown): Json {
  const record = asRecord(tool);
  if (record !== undefined && isNativeTool(record)) {
    return record;
  }
  const fn: Json = { name: get(tool, "name") ?? null };
  const description = get(tool, "description");
  if (description !== undefined) {
    fn.description = description;
  }
  fn.parameters = get(tool, "input_schema") ?? { type: "object" };
  return { type: "function", function: fn };
}

/** Preserve typed Anthropic server tools while translating client functions. */
function isNativeTool(record: Json): boolean {
  return (
    asString(record.type) !== undefined &&
    record.type !== "function" &&
    record.function === undefined
  );
}

/** `anthropic_tool_choice_to_openai`. */
function toolChoiceToOpenAi(choice: unknown): unknown {
  const keyword = asString(choice);
  if (keyword !== undefined) {
    switch (keyword) {
      case "auto":
        return "auto";
      case "none":
        return "none";
      case "any":
        return "required";
      default:
        return choice;
    }
  }

  const record = asRecord(choice);
  if (record === undefined) {
    return choice;
  }
  switch (asString(record.type)) {
    case "auto":
      return "auto";
    case "none":
      return "none";
    case "any":
      return "required";
    case "tool": {
      const name = asString(record.name);
      return name === undefined ? record : { type: "function", function: { name } };
    }
    default:
      return record;
  }
}

/** `anthropic_message_to_chat` — appends 0..n OpenAI messages for one turn. */
function messageToChat(message: unknown, out: Json[]): void {
  const role = asString(get(message, "role")) ?? "user";
  const content = get(message, "content") ?? null;

  const text = asString(content);
  if (text !== undefined) {
    out.push({ role, content: text });
    return;
  }

  const blocks = asArray(content);
  if (blocks === undefined) {
    // Null / absent content -> empty assistant/user turn.
    out.push({ role, content: "" });
    return;
  }

  const contentParts: Json[] = [];
  const toolCalls: Json[] = [];
  const toolMessages: Json[] = [];

  for (const block of blocks) {
    switch (asString(get(block, "type"))) {
      case "text":
        contentParts.push({ type: "text", text: asString(get(block, "text")) ?? "" });
        break;
      case "image": {
        const url = imageBlockToUrl(block);
        if (url !== undefined) {
          contentParts.push({ type: "image_url", image_url: { url } });
        }
        break;
      }
      case "tool_use":
        toolCalls.push({
          id: asString(get(block, "id")) ?? "",
          type: "function",
          function: {
            name: asString(get(block, "name")) ?? "",
            arguments: stringifyArguments(get(block, "input")),
          },
        });
        break;
      case "tool_result":
        toolMessages.push({
          role: "tool",
          tool_call_id: asString(get(block, "tool_use_id")) ?? "",
          content: toolResultToText(get(block, "content")),
        });
        break;
      default:
        break;
    }
  }

  // OpenAI requires tool result messages to appear before the next user text in
  // the same logical turn.
  out.push(...toolMessages);

  if (toolCalls.length > 0) {
    out.push({
      role: "assistant",
      content: collapseContent(contentParts),
      tool_calls: toolCalls,
    });
  } else if (contentParts.length > 0) {
    out.push({ role, content: collapseContent(contentParts) });
  }
}

/**
 * `to_chat_completions`. Text content is preserved verbatim so request-stage
 * guardrails see identical text under either ingress protocol.
 */
export function toChatCompletions(body: Json): TranslationResult {
  if (asRecord(body) === undefined) {
    return {
      ok: false,
      error: {
        kind: "invalid_request",
        message: "Anthropic messages request body must be a JSON object",
      },
    };
  }

  const out: Json = {};
  for (const [key, value] of Object.entries(body)) {
    if (!ANTHROPIC_RESPELLED.has(key)) {
      out[key] = value;
    }
  }
  if ("stop_sequences" in body) {
    out.stop = body.stop_sequences;
  }
  // Anthropic's `metadata` is exactly `{user_id}` — the end-user identifier for
  // abuse monitoring — while `metadata` on the OpenAI side of this gateway is
  // FerroGate's own billing attribution. Carrying the object across by name
  // would file a caller's end user as a cost centre, so the ONE member it
  // defines takes OpenAI's name for the same thing and the adapter spells it
  // back (issue #725).
  const userId = asString(get(body.metadata, "user_id"));
  if (userId !== undefined) {
    out.user = userId;
  }

  const messages: Json[] = [];
  const system = systemToText(body.system);
  if (system !== undefined) {
    messages.push({ role: "system", content: system });
  }
  for (const message of asArray(body.messages) ?? []) {
    messageToChat(message, messages);
  }
  out.messages = messages;

  const tools = asArray(body.tools);
  if (tools !== undefined) {
    const converted = tools.map(toolToOpenAi);
    if (converted.length > 0) {
      out.tools = converted;
    }
  }
  if ("tool_choice" in body) {
    const choice = body.tool_choice;
    const converted = toolChoiceToOpenAi(choice);
    if (converted !== undefined) {
      out.tool_choice = converted;
    }
    if (get(choice, "disable_parallel_tool_use") === true) {
      out.parallel_tool_calls = false;
    }
  }

  const promptCache = body[PROMPT_CACHE_MEMBER] ?? promptCacheFromCacheControl(body);
  if (promptCache !== undefined) {
    out[PROMPT_CACHE_MEMBER] = promptCache;
  }

  return { ok: true, body: out };
}

/**
 * Why `prompt_cache` is read here and not left to the native marker alone
 * (issue #690).
 *
 * `/v1/messages` reaches the SAME governed chokepoint every other ingress
 * does, and can be backed by any family on the ladder. A directive this
 * translation dropped was a directive the route quietly declined to honour
 * while answering 200 — and `off` is a retention/isolation control, not a cost
 * knob, so a 200 there means the prompt WAS written into a provider cache the
 * caller told the gateway to keep it out of. #674's rule is that what a family
 * cannot express is REFUSED, and a directive the route never reads cannot be
 * refused. Carrying it forward is what puts `/v1/messages` under that rule.
 *
 * The member is deliberately not in {@link SCALAR_PASSTHROUGH}: it is an
 * object, and it is FerroGate's own rather than a member of either protocol.
 * It is passed through UNVALIDATED because `@ferrogate/providers`'
 * `promptCacheFromBody` is the one canonical parser, and a second validation
 * here is a second thing to drift.
 *
 * A STATED directive beats an INFERRED one: a caller that both left native
 * `cache_control` markers and wrote `prompt_cache` has said two things, and the
 * one it wrote out is the deliberate one. That ordering matters most for
 * `{"mode":"off"}`, where reading the markers instead would cache a prompt the
 * caller had just asked not to be cached.
 */

/**
 * A native `cache_control` marker, read as the canonical caching directive
 * (issue #690).
 *
 * Every rebuild above — `systemToText`, `messageToChat`, `toolToOpenAi` —
 * constructs fresh blocks, so the caller's markers were DROPPED here and an
 * Anthropic-native client lost its whole prefix discount on FerroGate's own
 * `/v1/messages` ingress: the request the caller wrote was cached, the request
 * FerroGate sent was not. Carrying the intent forward as `prompt_cache` fixes
 * that and, because the directive is provider-neutral, keeps it alive across a
 * failover to a family with a different mechanism — which is the whole point of
 * the issue.
 *
 * The marker's PLACEMENT is not carried, only its intent: the OpenAI grammar
 * has nowhere to put it, and the re-emitted breakpoint lands at the canonical
 * static-prefix boundary. That is a change for a caller that had marked
 * something else — and still strictly better than the erasure it replaces.
 */
function promptCacheFromCacheControl(body: Json): Json | undefined {
  const marker = findCacheControl(body);
  if (marker === undefined) return undefined;
  const ttl = asString(get(marker, "ttl"));
  return { mode: "explicit", ...(ttl === "1h" ? { ttl } : {}) };
}

function findCacheControl(value: unknown): unknown {
  if (Array.isArray(value)) {
    for (const entry of value) {
      const found = findCacheControl(entry);
      if (found !== undefined) return found;
    }
    return undefined;
  }
  const record = asRecord(value);
  if (record === undefined) return undefined;
  if (record.cache_control !== undefined) return record.cache_control;
  for (const entry of Object.values(record)) {
    const found = findCacheControl(entry);
    if (found !== undefined) return found;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Upstream direction — OpenAI chat-completions → Anthropic Messages (issue #725)
// ---------------------------------------------------------------------------

/**
 * The whole chat body, translated into a native Messages body.
 *
 * ## What was wrong
 *
 * The Anthropic adapter used to REBUILD its upstream body from a five-member
 * allowlist — `model`, `messages`, `max_tokens`, `stream`, and `system` only if
 * the OpenAI-shaped body already had one. `tools`, `tool_choice`, `temperature`,
 * `stop`, `top_p`, `user` and everything else the caller sent were dropped on
 * the floor, and the request still answered 200. That is the worst shape a
 * gateway defect can take: a caller that sends `tools` gets a well-formed
 * completion in which the model simply never calls a tool, nothing errors, and
 * the caller debugs its own prompt. #690 established that what a family cannot
 * express is REFUSED rather than silently degraded; every member above is one
 * Anthropic CAN express, which makes dropping it strictly worse than the case
 * that rule was written for.
 *
 * ## Why a translation and not a wider allowlist
 *
 * #690 had already widened that allowlist once, for `prompt_cache`. An allowlist
 * is a list that loses the next member by default, so this replaces it with a
 * total classification of the body:
 *
 * | class          | rule                                                        |
 * |----------------|-------------------------------------------------------------|
 * | adapter-owned  | `model` / `stream` / `messages` / `max_tokens` — the adapter decides |
 * | re-spelled     | translated into Anthropic's name below                      |
 * | gateway-owned  | FerroGate's own members and OpenAI transport knobs; stripped |
 * | inexpressible  | REFUSED by {@link assertAnthropicCanExpress}, never dropped  |
 * | anything else  | forwarded verbatim                                          |
 *
 * The last row is the mechanism claim. A member no one has classified is either
 * Anthropic's own (`top_k`, `thinking`, `service_tier`, `container`, …) and
 * works, or it is not and the upstream answers 400 naming it. Neither outcome is
 * the silent 200 this issue is about, and neither needs a human to notice a new
 * field first.
 *
 * The result is a plain object whose subtrees may still alias the CALLER's body,
 * so the adapter deep-copies it with `ownBody` before the `prompt_cache` and
 * structured-output helpers decorate it — otherwise a breakpoint written here
 * would change what the next candidate on the failover ladder sends.
 *
 * @throws AdapterError `UnsupportedCapability` for a member Anthropic cannot express.
 */
export function chatCompletionsToMessages(
  body: Json,
  options: { readonly model: string; readonly stream: boolean; readonly providerKind: string },
): Json {
  assertAnthropicCanExpress(body, options.providerKind);

  // The remainder goes down FIRST so that every classified member below
  // overwrites it: a forwarded value can never shadow a translated one.
  const out: Json = {};
  for (const [key, value] of Object.entries(body)) {
    if (!CHAT_CLASSIFIED.has(key) && value !== null && value !== undefined) {
      out[key] = value;
    }
  }

  const { messages, system } = chatMessagesToAnthropic(body.messages, body.system);
  out.model = options.model;
  out.messages = messages;
  if (system !== undefined) {
    out.system = system;
  }
  // Anthropic REQUIRES `max_tokens`, hence the default the Rust adapter also
  // applied. `max_completion_tokens` is OpenAI's newer spelling of the same cap.
  out.max_tokens = body.max_tokens ?? body.max_completion_tokens ?? 1024;
  out.stream = options.stream;

  const stop = anthropicStopSequences(body);
  if (stop !== undefined) {
    out.stop_sequences = stop;
  }
  const tools = toolsToAnthropic(body.tools);
  if (tools !== undefined) {
    out.tools = tools;
  }
  const toolChoice = toolChoiceToAnthropic(body.tool_choice, body.parallel_tool_calls);
  if (toolChoice !== undefined) {
    out.tool_choice = toolChoice;
  }
  const user = asString(body.user);
  if (user !== undefined) {
    out.metadata = { user_id: user };
  }
  return out;
}

/**
 * Members that must NOT ride along on the remainder, and why.
 *
 * Three groups, deliberately in one set: the adapter's own decisions, the
 * members re-spelled by hand above, and the members that are FerroGate's or the
 * OpenAI transport's rather than either protocol's. `metadata` is in the last
 * group because on the OpenAI side of this gateway it is FerroGate's billing
 * attribution (`requestMetadataSchema`) — forwarding it would both leak a cost
 * centre to Anthropic and 400 there, since Anthropic's `metadata` accepts only
 * `user_id`, which arrives as `user` instead.
 */
const CHAT_CLASSIFIED = new Set<string>([
  // adapter-owned
  "model",
  "stream",
  "messages",
  "max_tokens",
  "max_completion_tokens",
  // re-spelled
  "system",
  "stop",
  "stop_sequences",
  "tools",
  "tool_choice",
  "parallel_tool_calls",
  "user",
  // inexpressible: no-op values are stripped rather than forwarded
  "n",
  "frequency_penalty",
  "presence_penalty",
  "logit_bias",
  "logprobs",
  "top_logprobs",
  "seed",
  "reasoning_effort",
  // gateway- / transport-owned
  PROMPT_CACHE_MEMBER,
  "metadata",
  "stream_options",
  "store",
  // `response_format` has no Anthropic member at all; it becomes a forced tool
  // call through `applyStructuredOutputToAnthropic` (issue #674), so leaving it
  // on the wire would be a duplicate of a requirement already expressed.
  "response_format",
]);

/**
 * What Anthropic cannot express, refused rather than dropped (issue #690's rule).
 *
 * Every member here changes the answer the caller expects. Sending the request
 * without it and returning 200 is the silent degrade this whole file is about;
 * refusing takes THIS candidate off the failover ladder, so a deployment that
 * also lists an OpenAI route under the same logical model is served there
 * instead of being quietly answered under different sampling rules.
 *
 * The refusal is local rather than "forward it and let Anthropic 400" — which
 * the remainder rule would otherwise do — because these are OPENAI members with
 * a known meaning: the gateway can say which member and why without spending an
 * upstream round trip, and only a locally-refused candidate can fail over.
 *
 * `noop` is what keeps this from breaking working traffic. SDKs send `n: 1`,
 * zero penalties and `logprobs: false` by default; those ask for nothing, so
 * refusing them would be a point made at the caller's expense. `null` and
 * `undefined` are no-ops everywhere, which is how the official clients spell
 * "not set".
 */
const ANTHROPIC_INEXPRESSIBLE: ReadonlyArray<{
  readonly member: string;
  readonly why: string;
  readonly noop: (value: unknown) => boolean;
}> = [
  {
    member: "n",
    why: "the Messages API returns exactly one completion",
    noop: (value) => value === 1,
  },
  {
    member: "frequency_penalty",
    why: "Anthropic has no frequency penalty",
    noop: (value) => value === 0,
  },
  {
    member: "presence_penalty",
    why: "Anthropic has no presence penalty",
    noop: (value) => value === 0,
  },
  {
    member: "logit_bias",
    why: "Anthropic cannot bias individual tokens",
    noop: (value) => Object.keys(asRecord(value) ?? {}).length === 0,
  },
  {
    member: "logprobs",
    why: "the Messages API does not return token log probabilities",
    noop: (value) => value === false,
  },
  {
    member: "top_logprobs",
    why: "the Messages API does not return token log probabilities",
    noop: () => false,
  },
  {
    member: "seed",
    why: "Anthropic offers no deterministic sampling seed",
    noop: () => false,
  },
  {
    member: "reasoning_effort",
    why: "Anthropic budgets extended thinking in TOKENS, not effort levels, and inventing a budget would answer a different question",
    noop: () => false,
  },
];

function assertAnthropicCanExpress(body: Json, providerKind: string): void {
  for (const { member, why, noop } of ANTHROPIC_INEXPRESSIBLE) {
    const value = body[member];
    if (value === undefined || value === null || noop(value)) {
      continue;
    }
    throw AdapterError.unsupportedCapability(`\`${member}\` (${why})`, providerKind);
  }
}

/** `stop` (string or array) and Anthropic's own spelling both land here. */
function anthropicStopSequences(body: Json): unknown {
  const value = body.stop_sequences ?? body.stop;
  if (value === undefined || value === null) {
    return undefined;
  }
  const single = asString(value);
  return single === undefined ? value : [single];
}

/**
 * OpenAI's `{type:"function",function:{…}}` tool grammar → Anthropic's.
 *
 * A tool that already carries `input_schema` is Anthropic's own and is left
 * alone — that is how a server tool (`{"type":"web_search_20250305",…}`) or any
 * future native tool type reaches the upstream instead of being mangled into a
 * function definition it is not.
 */
function toolsToAnthropic(tools: unknown): unknown[] | undefined {
  const list = asArray(tools);
  if (list === undefined || list.length === 0) {
    return undefined;
  }
  return list.map(toolToAnthropic);
}

function toolToAnthropic(tool: unknown): unknown {
  const record = asRecord(tool);
  if (record === undefined || record.input_schema !== undefined || isNativeTool(record)) {
    return tool;
  }
  // Chat nests the definition under `function`; `/v1/responses` flattens it.
  const fn = asRecord(record.function) ?? record;
  const name = asString(fn.name);
  if (name === undefined) {
    return tool;
  }
  const out: Json = { name };
  const description = fn.description;
  if (description !== undefined) {
    out.description = description;
  }
  out.input_schema = fn.parameters ?? { type: "object" };
  const cacheControl = record.cache_control ?? fn.cache_control;
  if (cacheControl !== undefined) {
    out.cache_control = cacheControl;
  }
  return out;
}

/**
 * OpenAI's `tool_choice` → Anthropic's, including the one member that has no
 * `tool_choice` spelling at all.
 *
 * `parallel_tool_calls: false` is OpenAI's top-level switch and Anthropic's
 * `tool_choice.disable_parallel_tool_use`, so it has to be folded in HERE or a
 * caller that sent it without any `tool_choice` would lose it. `true` is
 * Anthropic's default and asks for nothing, so it is not emitted.
 */
function toolChoiceToAnthropic(choice: unknown, parallelToolCalls: unknown): unknown {
  const translated = toolChoiceGrammar(choice);
  if (parallelToolCalls !== false) {
    return translated;
  }
  const base = asRecord(translated) ?? { type: "auto" };
  return { ...base, disable_parallel_tool_use: true };
}

function toolChoiceGrammar(choice: unknown): unknown {
  if (choice === undefined || choice === null) {
    return undefined;
  }
  const keyword = asString(choice);
  if (keyword !== undefined) {
    switch (keyword) {
      case "auto":
        return { type: "auto" };
      case "none":
        return { type: "none" };
      case "required":
        return { type: "any" };
      default:
        return choice;
    }
  }
  const record = asRecord(choice);
  if (record === undefined) {
    return choice;
  }
  if (asString(record.type) === "function") {
    const name = asString(record.name ?? get(record.function, "name"));
    return name === undefined ? record : { type: "tool", name };
  }
  // Already Anthropic's grammar (`auto` / `any` / `none` / `tool`), or a member
  // this tree has no name for. Forwarded, per the remainder rule.
  return record;
}

/**
 * The inverse of {@link messageToChat}: OpenAI turns → Anthropic turns, with the
 * system prompt lifted back out.
 *
 * Three shapes have to be undone, and all three matter for an agent loop:
 *
 *  - a `system`-role turn is not a turn at all on this API, which accepts only
 *    `user` and `assistant` — it is the top-level `system` parameter, and a body
 *    carrying the role is one the real upstream rejects outright;
 *  - an assistant `tool_calls` array is a `tool_use` content block;
 *  - a `tool`-role result is a `tool_result` block inside a USER turn, and
 *    consecutive results belong to one turn because that is how Anthropic pairs
 *    them with the assistant turn that requested them.
 */
function chatMessagesToAnthropic(
  messages: unknown,
  existingSystem: unknown,
): { messages: Json[]; system: unknown } {
  const systemBlocks: Json[] = [];
  appendSystemBlocks(existingSystem, systemBlocks);

  const out: Json[] = [];
  let pendingToolResults: Json[] = [];
  const flushToolResults = (): void => {
    if (pendingToolResults.length > 0) {
      out.push({ role: "user", content: pendingToolResults });
      pendingToolResults = [];
    }
  };

  for (const message of asArray(messages) ?? []) {
    const role = asString(get(message, "role")) ?? "user";
    if (role === "system" || role === "developer") {
      appendSystemBlocks(get(message, "content"), systemBlocks);
      continue;
    }
    if (role === "tool" || role === "function") {
      const block: Json = {
        type: "tool_result",
        tool_use_id: asString(get(message, "tool_call_id")) ?? "",
        content: get(message, "content") ?? "",
      };
      pendingToolResults.push(block);
      continue;
    }
    flushToolResults();
    out.push(chatTurnToAnthropic(role, message));
  }
  flushToolResults();

  return { messages: out, system: anthropicSystem(systemBlocks) };
}

function chatTurnToAnthropic(role: string, message: unknown): Json {
  const content = get(message, "content");
  const toolCalls = asArray(get(message, "tool_calls"));

  const text = asString(content);
  if (text !== undefined && toolCalls === undefined) {
    // A plain string stays a plain string: it is the shape Anthropic documents
    // for a single-text turn, and re-wrapping it would change nothing but the
    // bytes a caching prefix hashes over.
    return { role, content: text };
  }

  const blocks: Json[] = [];
  if (text !== undefined) {
    if (text.length > 0) {
      blocks.push({ type: "text", text });
    }
  } else {
    for (const part of asArray(content) ?? []) {
      blocks.push(contentPartToAnthropic(part));
    }
  }
  for (const call of toolCalls ?? []) {
    const fn = get(call, "function");
    blocks.push({
      type: "tool_use",
      id: asString(get(call, "id")) ?? "",
      name: asString(get(fn, "name")) ?? "",
      input: parseArguments(get(fn, "arguments")),
    });
  }
  // Anthropic rejects an empty content array; an empty turn is an empty string,
  // which is what the OpenAI body meant by `content: null` with no tool calls.
  return blocks.length === 0 ? { role, content: "" } : { role, content: blocks };
}

/**
 * `image_url` is the ONE content part whose spelling differs. Everything else —
 * `text`, and any part type this tree has no name for — is forwarded verbatim,
 * which is also what preserves a caller's own `cache_control` marker on a block.
 */
function contentPartToAnthropic(part: unknown): Json {
  const record = asRecord(part);
  if (record === undefined || asString(record.type) !== "image_url") {
    return (record ?? { type: "text", text: valueToString(part) }) as Json;
  }
  const url = asString(get(record.image_url, "url"));
  if (url === undefined) {
    return record;
  }
  const source = dataUrlToSource(url) ?? { type: "url", url };
  const out: Json = { type: "image", source };
  if (record.cache_control !== undefined) {
    out.cache_control = record.cache_control;
  }
  return out;
}

/** `data:image/png;base64,…` → Anthropic's base64 image source. */
function dataUrlToSource(url: string): Json | undefined {
  const match = /^data:([^;,]+);base64,(.*)$/s.exec(url);
  if (match === null) {
    return undefined;
  }
  return { type: "base64", media_type: match[1] as string, data: match[2] as string };
}

/** A system prompt arrives as a string, as content parts, or as several turns. */
function appendSystemBlocks(content: unknown, out: Json[]): void {
  if (content === undefined || content === null) {
    return;
  }
  const text = asString(content);
  if (text !== undefined) {
    if (text.length > 0) {
      out.push({ type: "text", text });
    }
    return;
  }
  for (const part of asArray(content) ?? []) {
    const record = asRecord(part);
    if (record !== undefined) {
      out.push(record);
    }
  }
}

/**
 * One plain text block collapses back to a string — the form Anthropic's own
 * examples use and the one a caller sent in the first place. Anything richer (a
 * `cache_control` marker, several turns) needs the block array to survive.
 */
function anthropicSystem(blocks: readonly Json[]): unknown {
  if (blocks.length === 0) {
    return undefined;
  }
  const [single] = blocks;
  if (
    blocks.length === 1 &&
    single !== undefined &&
    single.type === "text" &&
    Object.keys(single).length === 2 &&
    typeof single.text === "string"
  ) {
    return single.text;
  }
  return [...blocks];
}

// ---------------------------------------------------------------------------
// Response direction — `chat_completion_to_message`
// ---------------------------------------------------------------------------

/** `is_anthropic_message` — an already-native response is passed straight back. */
export function isAnthropicMessage(value: unknown): boolean {
  return asString(get(value, "type")) === "message" && asArray(get(value, "content")) !== undefined;
}

/** `finish_reason_to_stop_reason`. */
export function finishReasonToStopReason(
  finishReason: string | undefined,
  sawToolUse: boolean,
): string {
  if (sawToolUse) {
    return "tool_use";
  }
  switch (finishReason) {
    case "length":
      return "max_tokens";
    case "tool_calls":
      return "tool_use";
    case "stop":
      return "end_turn";
    default:
      return "end_turn";
  }
}

/** `chat_completion_to_message`. */
export function chatCompletionToMessage(chat: unknown, fallbackModel: string): unknown {
  if (isAnthropicMessage(chat)) {
    return chat;
  }

  const rawId = asString(get(chat, "id"));
  const id = rawId === undefined ? "msg_ferrogate" : rawId.replaceAll("chatcmpl", "msg");
  const model = asString(get(chat, "model")) ?? fallbackModel;

  const choice = asArray(get(chat, "choices"))?.[0];
  const message = choice === undefined ? undefined : get(choice, "message");
  const finishReason = choice === undefined ? undefined : asString(get(choice, "finish_reason"));

  const content: Json[] = [];
  const text = asString(get(message, "content"));
  if (text !== undefined && text.length > 0) {
    content.push({ type: "text", text });
  }

  let sawToolUse = false;
  for (const toolCall of asArray(get(message, "tool_calls")) ?? []) {
    sawToolUse = true;
    const fn = get(toolCall, "function");
    content.push({
      type: "tool_use",
      id: asString(get(toolCall, "id")) ?? "",
      name: asString(get(fn, "name")) ?? "",
      input: parseArguments(get(fn, "arguments")),
    });
  }

  const usage = get(chat, "usage");
  const outputTokens = asUint(get(usage, "completion_tokens")) ?? 0;

  return {
    id,
    type: "message",
    role: "assistant",
    model,
    content,
    stop_reason: finishReasonToStopReason(finishReason, sawToolUse),
    stop_sequence: null,
    usage: { ...anthropicUsageCounters(usage), output_tokens: outputTokens },
  };
}

/**
 * `prompt_tokens` → the Anthropic input counters, with the cache split kept
 * (issue #690).
 *
 * The two vocabularies disagree about what the headline number MEANS: OpenAI's
 * `prompt_tokens` INCLUDES `prompt_tokens_details.cached_tokens`, while
 * Anthropic's `input_tokens` EXCLUDES `cache_read_input_tokens`. So the fresh
 * count is the difference, and reporting the unreduced 9012 alongside a 9000
 * cache read would make an Anthropic-native client double-count the prompt —
 * which is why this is a subtraction and not merely an extra field.
 *
 * A response with no cached tokens reported emits exactly the two counters it
 * always did: an absent counter stays absent rather than becoming a zero, the
 * same rule #667 applies on the metering side.
 */
function anthropicUsageCounters(usage: unknown): Record<string, number> {
  const promptTokens = asUint(get(usage, "prompt_tokens")) ?? 0;
  const details = get(usage, "prompt_tokens_details") ?? get(usage, "input_tokens_details");
  const cached = asUint(get(details, "cached_tokens"));
  if (cached === undefined) {
    return { input_tokens: promptTokens };
  }
  return {
    input_tokens: Math.max(promptTokens - cached, 0),
    cache_read_input_tokens: cached,
  };
}

/** Default {@link AnthropicTranslator} wired into `defaults.ts`. */
export const defaultAnthropicTranslator: AnthropicTranslator = {
  toChatCompletions,
  chatCompletionToMessage,
};
