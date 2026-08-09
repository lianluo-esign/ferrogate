/**
 * Canonical `/v1/responses` request model — port of `canonical.rs`.
 *
 * Parses an OpenAI Responses-API body into a provider-neutral
 * {@link CanonicalAiRequest}, then re-emits it in each family's wire shape
 * (`intoAnthropicBody`, `intoGeminiBody`). The chat-shaped emitters
 * (`intoChatBodyWith*`) are the Rust `#[cfg(test)]` helpers, retained for unit
 * coverage of the canonicalization.
 */

import {
  applyPromptCacheToAnthropic,
  applyPromptCacheToAutomaticFamily,
  promptCacheFromBody,
  stripPromptCacheDirective,
} from "./caching.js";
import type { CanonicalPromptCache } from "./caching.js";
import type { Json, JsonObject } from "./json.js";
import {
  asArray,
  asObject,
  asStr,
  getField,
  isArray,
  isObject,
  ownBody,
  parseJson,
} from "./json.js";
import {
  applyStructuredOutputToAnthropic,
  applyStructuredOutputToGemini,
  structuredOutputFromResponsesBody,
} from "./structured.js";
import type { CanonicalStructuredOutput } from "./structured.js";
import { AdapterError } from "./types.js";

type CanonicalToolChoice =
  | { type: "Auto" }
  | { type: "None" }
  | { type: "Required" }
  | { type: "Tool"; name: string };

interface CanonicalToolDefinition {
  name: string;
  description?: string;
  inputSchema: Json;
}

interface CanonicalToolCall {
  id: string;
  name: string;
  arguments: Json;
}

type CanonicalContent =
  | { kind: "Text"; text: string }
  | { kind: "TextBlocks"; blocks: CanonicalContentBlock[] }
  | { kind: "ToolCalls"; toolCalls: CanonicalToolCall[] };

type CanonicalContentBlock =
  | { kind: "Text"; text: string }
  | { kind: "ImageUrl"; url: string }
  | { kind: "ImageBase64"; dataUrl: string };

interface CanonicalMessage {
  role: string;
  content: CanonicalContent;
}

const userMessage = (content: CanonicalContent): CanonicalMessage => ({ role: "user", content });

export class CanonicalAiRequest {
  private constructor(
    private readonly sourceBody: JsonObject,
    private readonly messages: CanonicalMessage[],
    private readonly tools: CanonicalToolDefinition[],
    private readonly toolChoice: CanonicalToolChoice | undefined,
    private readonly instructions: Json | undefined,
    private readonly maxOutputTokens: Json | undefined,
    /** `text.format` — the Responses spelling of `response_format` (#674). */
    private readonly structuredOutput: CanonicalStructuredOutput | undefined,
    /** `prompt_cache` — the provider-neutral caching directive (#690). */
    private readonly promptCache: CanonicalPromptCache | undefined,
  ) {}

  static fromResponsesBody(body: Json): CanonicalAiRequest {
    const object = ensureObjectBody(body);
    return new CanonicalAiRequest(
      object,
      responsesInputToMessages(getField(object, "input")),
      responsesToolsToCanonical(getField(object, "tools")),
      responsesToolChoiceToCanonical(getField(object, "tool_choice")),
      getField(object, "instructions"),
      getField(object, "max_output_tokens"),
      structuredOutputFromResponsesBody(object),
      promptCacheFromBody(object),
    );
  }

  /** Rust `#[cfg(test)]` helper: chat body carrying `system` as a field. */
  intoChatBodyWithSystemField(): Json {
    const body: JsonObject = { ...this.sourceBody };
    body.messages = canonicalMessagesToJson(this.messages);
    if (this.tools.length > 0) body.tools = canonicalToolsToJson(this.tools);
    if (this.toolChoice) body.tool_choice = canonicalToolChoiceToJson(this.toolChoice);
    if (this.instructions !== undefined) body.system = this.instructions;
    if (this.maxOutputTokens !== undefined) body.max_tokens = this.maxOutputTokens;
    return body;
  }

  /** Rust `#[cfg(test)]` helper: chat body carrying `system` as first message. */
  intoChatBodyWithSystemMessage(): Json {
    const body: JsonObject = { ...this.sourceBody };
    const messages = canonicalMessagesToJson(this.messages);
    if (this.tools.length > 0) body.tools = canonicalToolsToJson(this.tools);
    if (this.toolChoice) body.tool_choice = canonicalToolChoiceToJson(this.toolChoice);
    if (this.instructions !== undefined) {
      (messages as Json[]).unshift({ role: "system", content: this.instructions });
    }
    body.messages = messages;
    if (this.maxOutputTokens !== undefined) body.max_tokens = this.maxOutputTokens;
    return body;
  }

  intoAnthropicBody(): Json {
    // A SHALLOW spread of `sourceBody` still shares every subtree it did not
    // overwrite — `instructions` becomes `system` by reference — so the
    // breakpoint placed below would land in the caller's object and reach every
    // other candidate on the ladder. `ownBody` is the boundary that stops it,
    // and the type the `apply*` helpers demand (issue #690).
    const body = ownBody({ ...this.sourceBody });
    body.messages = canonicalMessagesToAnthropicJson(this.messages);
    if (this.tools.length > 0) body.tools = canonicalToolsToAnthropicJson(this.tools);
    if (this.toolChoice) body.tool_choice = canonicalToolChoiceToAnthropicJson(this.toolChoice);
    if (this.instructions !== undefined) body.system = this.instructions;
    if (this.maxOutputTokens !== undefined) body.max_tokens = this.maxOutputTokens;
    // Coerced into a forced tool call (or refused) AFTER the caller's own tools
    // and tool_choice are in place, so a collision between the two is visible
    // rather than silently overwritten (issue #674).
    if (this.structuredOutput !== undefined) {
      applyStructuredOutputToAnthropic(body, this.structuredOutput, "anthropic");
    }
    // The caching directive is FerroGate's own member: it is stripped from the
    // copied source body and re-emitted as `cache_control` breakpoints (#690).
    stripPromptCacheDirective(body);
    if (this.promptCache !== undefined) {
      applyPromptCacheToAnthropic(body, this.promptCache, "anthropic");
    }
    return body;
  }

  intoGeminiBody(): Json {
    const body = ownBody({ ...this.sourceBody });
    body.contents = canonicalMessagesToGeminiJson(this.messages);
    if (this.instructions !== undefined) {
      body.systemInstruction = canonicalInstructionToGeminiJson(this.instructions);
    }
    if (this.tools.length > 0) body.tools = canonicalToolsToGeminiJson(this.tools);
    if (this.toolChoice) body.toolConfig = canonicalToolChoiceToGeminiJson(this.toolChoice);
    const generationConfig: JsonObject = {};
    if (this.maxOutputTokens !== undefined) {
      generationConfig.maxOutputTokens = this.maxOutputTokens;
    }
    if (this.structuredOutput !== undefined) {
      applyStructuredOutputToGemini(generationConfig, this.structuredOutput, "gemini");
    }
    if (Object.keys(generationConfig).length > 0) body.generationConfig = generationConfig;
    // Gemini caches implicitly and has no per-request breakpoint, so the
    // directive is adjudicated (auto accepted, explicit/off refused) and never
    // reaches the wire (#690).
    stripPromptCacheDirective(body);
    if (this.promptCache !== undefined) {
      applyPromptCacheToAutomaticFamily(this.promptCache, "gemini");
    }
    return body;
  }
}

function ensureObjectBody(body: Json): JsonObject {
  const object = asObject(body);
  if (!object) {
    throw AdapterError.invalidRequest("responses request body must be a JSON object");
  }
  return object;
}

const hasMessageRole = (value: Json): boolean => asStr(getField(value, "role")) !== undefined;

function responsesInputToMessages(input: Json | undefined): CanonicalMessage[] {
  if (typeof input === "string") return [userMessage({ kind: "Text", text: input })];
  if (isArray(input)) {
    if (input.some(hasMessageRole)) {
      if (input.some((value) => !hasMessageRole(value))) throw contentNotSupportedError();
      return input.map(responsesMessageToCanonicalMessage);
    }
    return [userMessage(responsesContentToCanonical(input))];
  }
  if (input === null || input === undefined) return [];
  return [userMessage(responsesContentToCanonical(input))];
}

function responsesMessageToCanonicalMessage(value: Json): CanonicalMessage {
  const role = asStr(getField(value, "role")) ?? "user";
  const toolCalls = getField(value, "tool_calls");
  let content: CanonicalContent;
  if (toolCalls !== undefined) {
    if (!toolCallsIsEmpty(toolCalls) && !contentIsEmpty(getField(value, "content"))) {
      throw contentNotSupportedError();
    }
    content = { kind: "ToolCalls", toolCalls: responsesToolCallsToCanonical(toolCalls) };
  } else {
    content = responsesContentToCanonical(getField(value, "content") ?? null);
  }
  return { role, content };
}

function responsesContentToCanonical(value: Json): CanonicalContent {
  if (typeof value === "string") return { kind: "Text", text: value };
  if (isArray(value)) {
    const blocks: CanonicalContentBlock[] = [];
    const toolCalls: CanonicalToolCall[] = [];
    for (const item of value) {
      const parsed = responsesContentItemToCanonical(item);
      if (parsed.type === "Block") blocks.push(parsed.block);
      else toolCalls.push(parsed.toolCall);
    }
    if (toolCalls.length > 0) {
      if (blocks.length > 0) throw contentNotSupportedError();
      return { kind: "ToolCalls", toolCalls };
    }
    return { kind: "TextBlocks", blocks };
  }
  if (isObject(value)) {
    const parsed = responsesContentItemToCanonical(value);
    if (parsed.type === "Block") return { kind: "TextBlocks", blocks: [parsed.block] };
    return { kind: "ToolCalls", toolCalls: [parsed.toolCall] };
  }
  if (value === null) return { kind: "Text", text: "" };
  throw contentNotSupportedError();
}

type ResponsesContentItem =
  | { type: "Block"; block: CanonicalContentBlock }
  | { type: "ToolCall"; toolCall: CanonicalToolCall };

function responsesContentItemToCanonical(value: Json): ResponsesContentItem {
  if (typeof value === "string") return { type: "Block", block: { kind: "Text", text: value } };
  const object = asObject(value);
  if (object) {
    const blockType = asStr(object.type);
    if (blockType === "input_text" || blockType === "output_text" || blockType === "text") {
      return { type: "Block", block: { kind: "Text", text: asStr(object.text) ?? "" } };
    }
    if (blockType === "input_image" || blockType === "image_url" || blockType === "image") {
      const image = extractImageReference(object);
      if (image === undefined) throw contentNotSupportedError();
      if (image.startsWith("data:")) {
        return { type: "Block", block: { kind: "ImageBase64", dataUrl: image } };
      }
      return { type: "Block", block: { kind: "ImageUrl", url: image } };
    }
    if (blockType === "tool_call" || blockType === "function_call" || blockType === "tool_use") {
      return { type: "ToolCall", toolCall: responsesToolCallToCanonical(value) };
    }
    throw contentNotSupportedError();
  }
  throw contentNotSupportedError();
}

function responsesToolCallsToCanonical(value: Json): CanonicalToolCall[] {
  if (isArray(value)) return value.map(responsesToolCallToCanonical);
  if (isObject(value)) return [responsesToolCallToCanonical(value)];
  if (value === null) return [];
  throw contentNotSupportedError();
}

function responsesToolCallToCanonical(value: Json): CanonicalToolCall {
  const fn = getField(value, "function");
  const id = asStr(getField(value, "id") ?? getField(value, "call_id"));
  if (id === undefined) throw contentNotSupportedError();
  const name = asStr(getField(fn, "name") ?? getField(value, "name"));
  if (name === undefined) throw contentNotSupportedError();
  const argsRaw =
    getField(fn, "arguments") ??
    getField(value, "arguments") ??
    getField(value, "input") ??
    getField(value, "args") ??
    null;
  return { id, name, arguments: parseJsonStringOrClone(argsRaw) };
}

function contentIsEmpty(value: Json | undefined): boolean {
  if (value === undefined || value === null) return true;
  if (typeof value === "string") return value.length === 0;
  if (isArray(value)) return value.length === 0;
  if (isObject(value)) return Object.keys(value).length === 0;
  return false;
}

const toolCallsIsEmpty = (value: Json): boolean =>
  value === null || (isArray(value) && value.length === 0);

function extractImageReference(object: JsonObject): string | undefined {
  const source = object.source;
  const candidate =
    object.image_url ?? object.url ?? getField(source, "url") ?? getField(source, "data");
  if (typeof candidate === "string") return candidate;
  if (isObject(candidate)) {
    const nested = asStr(candidate.url ?? candidate.data);
    if (nested !== undefined) return nested;
  }
  const direct = asStr(object.image_url);
  return direct;
}

const contentNotSupportedError = (): AdapterError =>
  AdapterError.invalidRequest(
    "Responses adapter supports text, image, and tool-call input content only",
  );

// --- chat-shaped emitters (Rust #[cfg(test)]) ------------------------------

const canonicalMessagesToJson = (messages: CanonicalMessage[]): Json =>
  messages.map(canonicalMessageToJson);

function canonicalMessageToJson(message: CanonicalMessage): Json {
  if (message.content.kind === "ToolCalls") {
    return {
      role: message.role,
      content: null,
      tool_calls: canonicalToolCallsToJson(message.content.toolCalls),
    };
  }
  return { role: message.role, content: canonicalContentToJson(message.content) };
}

function canonicalContentToJson(content: CanonicalContent): Json {
  switch (content.kind) {
    case "Text":
      return content.text;
    case "TextBlocks":
      return content.blocks.map(canonicalContentBlockToJson);
    case "ToolCalls":
      return null;
  }
}

function canonicalContentBlockToJson(block: CanonicalContentBlock): Json {
  switch (block.kind) {
    case "Text":
      return { type: "text", text: block.text };
    case "ImageUrl":
      return { type: "image_url", image_url: { url: block.url } };
    case "ImageBase64":
      return { type: "image_url", image_url: { url: block.dataUrl } };
  }
}

function canonicalToolCallsToJson(toolCalls: CanonicalToolCall[]): Json {
  return toolCalls.map((toolCall) => ({
    id: toolCall.id,
    type: "function",
    function: {
      name: toolCall.name,
      arguments: toolArgumentsToString(toolCall.arguments),
    },
  }));
}

function canonicalToolsToJson(tools: CanonicalToolDefinition[]): Json {
  return tools.map((tool) => {
    const fn: JsonObject = { name: tool.name, parameters: tool.inputSchema };
    if (tool.description !== undefined) fn.description = tool.description;
    return { type: "function", function: fn };
  });
}

function canonicalToolChoiceToJson(choice: CanonicalToolChoice): Json {
  switch (choice.type) {
    case "Auto":
      return "auto";
    case "None":
      return "none";
    case "Required":
      return "required";
    case "Tool":
      return { type: "function", function: { name: choice.name } };
  }
}

// --- Anthropic emitters ----------------------------------------------------

const canonicalMessagesToAnthropicJson = (messages: CanonicalMessage[]): Json =>
  messages.map((message) => ({
    role: message.role,
    content: canonicalContentToAnthropicJson(message.content),
  }));

function canonicalContentToAnthropicJson(content: CanonicalContent): Json {
  switch (content.kind) {
    case "Text":
      return content.text;
    case "TextBlocks":
      return content.blocks.map(canonicalContentBlockToAnthropicJson);
    case "ToolCalls":
      return content.toolCalls.map((toolCall) => ({
        type: "tool_use",
        id: toolCall.id,
        name: toolCall.name,
        input: toolCall.arguments,
      }));
  }
}

function canonicalContentBlockToAnthropicJson(block: CanonicalContentBlock): Json {
  switch (block.kind) {
    case "Text":
      return { type: "text", text: block.text };
    case "ImageUrl":
      return { type: "image", source: { type: "url", url: block.url } };
    case "ImageBase64": {
      const decoded = decodeDataUrl(block.dataUrl) ?? ["image/png", block.dataUrl];
      return {
        type: "image",
        source: { type: "base64", media_type: decoded[0], data: decoded[1] },
      };
    }
  }
}

function canonicalToolsToAnthropicJson(tools: CanonicalToolDefinition[]): Json {
  return tools.map((tool) => {
    const value: JsonObject = { name: tool.name, input_schema: tool.inputSchema };
    if (tool.description !== undefined) value.description = tool.description;
    return value;
  });
}

function canonicalToolChoiceToAnthropicJson(choice: CanonicalToolChoice): Json {
  switch (choice.type) {
    case "Auto":
      return { type: "auto" };
    case "None":
      return { type: "none" };
    case "Required":
      return { type: "any" };
    case "Tool":
      return { type: "tool", name: choice.name };
  }
}

// --- Gemini emitters -------------------------------------------------------

const canonicalMessagesToGeminiJson = (messages: CanonicalMessage[]): Json =>
  messages
    .filter((message) => message.role !== "system")
    .map((message) => ({
      role: canonicalRoleToGeminiRole(message.role),
      parts: canonicalContentToGeminiParts(message.content),
    }));

function canonicalContentToGeminiParts(content: CanonicalContent): Json {
  switch (content.kind) {
    case "Text":
      return [{ text: content.text }];
    case "TextBlocks":
      return content.blocks.map(canonicalContentBlockToGeminiPart);
    case "ToolCalls":
      return content.toolCalls.map((toolCall) => ({
        functionCall: { name: toolCall.name, args: toolCall.arguments, id: toolCall.id },
      }));
  }
}

function canonicalContentBlockToGeminiPart(block: CanonicalContentBlock): Json {
  switch (block.kind) {
    case "Text":
      return { text: block.text };
    case "ImageUrl":
      return { fileData: { fileUri: block.url } };
    case "ImageBase64": {
      const decoded = decodeDataUrl(block.dataUrl) ?? ["image/png", block.dataUrl];
      return { inlineData: { mimeType: decoded[0], data: decoded[1] } };
    }
  }
}

function canonicalInstructionToGeminiJson(instructions: Json): Json {
  return { role: "system", parts: canonicalInstructionParts(instructions) };
}

function canonicalInstructionParts(instructions: Json): Json {
  if (typeof instructions === "string") return [{ text: instructions }];
  if (isArray(instructions)) {
    const parts: Json[] = [];
    for (const block of instructions) {
      if (typeof block === "string") parts.push({ text: block });
      else if (isObject(block) && asStr(block.type) === "text") {
        parts.push({ text: asStr(block.text) ?? "" });
      }
    }
    return parts;
  }
  return [];
}

function canonicalToolsToGeminiJson(tools: CanonicalToolDefinition[]): Json {
  return [
    {
      functionDeclarations: tools.map((tool) => {
        const value: JsonObject = { name: tool.name, parameters: tool.inputSchema };
        if (tool.description !== undefined) value.description = tool.description;
        return value;
      }),
    },
  ];
}

function canonicalToolChoiceToGeminiJson(choice: CanonicalToolChoice): Json {
  switch (choice.type) {
    case "Auto":
      return { functionCallingConfig: { mode: "AUTO" } };
    case "None":
      return { functionCallingConfig: { mode: "NONE" } };
    case "Required":
      return { functionCallingConfig: { mode: "ANY" } };
    case "Tool":
      return {
        functionCallingConfig: { mode: "ANY", allowedFunctionNames: [choice.name] },
      };
  }
}

function canonicalRoleToGeminiRole(role: string): string {
  switch (role) {
    case "assistant":
    case "model":
      return "model";
    default:
      return "user";
  }
}

function decodeDataUrl(value: string): [string, string] | undefined {
  if (!value.startsWith("data:")) return undefined;
  const rest = value.slice("data:".length);
  const comma = rest.indexOf(",");
  if (comma < 0) return undefined;
  const meta = rest.slice(0, comma);
  const data = rest.slice(comma + 1);
  const mediaType = meta.split(";")[0] || "image/png";
  return [mediaType, data];
}

// --- tool definitions / choice parsing -------------------------------------

function responsesToolsToCanonical(value: Json | undefined): CanonicalToolDefinition[] {
  if (isArray(value)) return value.map(responsesToolDefinitionToCanonical);
  if (value === null || value === undefined) return [];
  throw contentNotSupportedError();
}

function responsesToolDefinitionToCanonical(value: Json): CanonicalToolDefinition {
  const object = asObject(value);
  if (!object) throw contentNotSupportedError();
  const fn = asObject(object.function);
  const nameRaw = asStr(object.name ?? getField(fn, "name"));
  const name = nameRaw !== undefined && nameRaw.trim().length > 0 ? nameRaw : undefined;
  if (name === undefined) throw contentNotSupportedError();
  const description = asStr(object.description ?? getField(fn, "description"));
  const inputSchema = object.input_schema ?? object.parameters ?? getField(fn, "parameters");
  if (inputSchema === undefined) throw contentNotSupportedError();
  return { name, description, inputSchema };
}

function responsesToolChoiceToCanonical(value: Json | undefined): CanonicalToolChoice | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value === "string") {
    switch (value) {
      case "auto":
        return { type: "Auto" };
      case "none":
        return { type: "None" };
      case "required":
      case "any":
        return { type: "Required" };
      default:
        throw contentNotSupportedError();
    }
  }
  const object = asObject(value);
  if (object) {
    const kind = asStr(object.type);
    switch (kind) {
      case "auto":
        return { type: "Auto" };
      case "none":
        return { type: "None" };
      case "required":
      case "any":
        return { type: "Required" };
      case "function":
      case "tool": {
        const nameRaw = asStr(object.name ?? getField(asObject(object.function), "name"));
        const name = nameRaw !== undefined && nameRaw.trim().length > 0 ? nameRaw : undefined;
        if (name === undefined) throw contentNotSupportedError();
        return { type: "Tool", name };
      }
      default:
        throw contentNotSupportedError();
    }
  }
  throw contentNotSupportedError();
}

function parseJsonStringOrClone(value: Json): Json {
  if (typeof value === "string") {
    const parsed = parseJson(value);
    if (parsed !== undefined) return parsed;
  }
  return value;
}

const toolArgumentsToString = (value: Json): string =>
  typeof value === "string" ? value : JSON.stringify(value);
