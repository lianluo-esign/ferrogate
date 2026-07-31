/**
 * Protocol-normalized guardrail content envelopes — port of
 * `ferrogate-guardrails::envelope`.
 *
 * Walks provider request/response JSON (Chat Completions, Responses,
 * Embeddings, Images) into typed {@link ContentSegment}s, accumulates SSE
 * streams, and — the security-critical half — validates and applies constrained
 * text {@link ContentPatch}es back onto the request document.
 *
 * All offsets are UTF-8 byte offsets (see `./bytes`), matching the Rust
 * segment/patch contract exactly. Patch application is deliberately narrow:
 * only exact text-bearing paths are mutable; JSON/metadata/tool-schema/tool-args
 * are immutable because byte replacement inside serialized JSON could rewrite a
 * credential, allowlist, or routing field.
 */
import { z } from "zod";
import { byteLen, byteSlice, isCharBoundary } from "./bytes.js";
import { sha256, toHex } from "./hash.js";
import { DetectorError, type ContentPatch } from "./contract.js";

export const guardrailProtocolSchema = z.enum([
  "chat_completions",
  "responses",
  "embeddings",
  "images",
  "managed_action",
  "a2a",
]);
export type GuardrailProtocol = z.infer<typeof guardrailProtocolSchema>;

export const contentSourceSchema = z.enum([
  "system",
  "developer",
  "user",
  "assistant",
  "tool_schema",
  "tool_arguments",
  "tool_result",
  "metadata",
  "text_attachment",
  "unknown",
]);
export type ContentSource = z.infer<typeof contentSourceSchema>;

export const ALL_CONTENT_SOURCES: readonly ContentSource[] = [
  "system",
  "developer",
  "user",
  "assistant",
  "tool_schema",
  "tool_arguments",
  "tool_result",
  "metadata",
  "text_attachment",
  "unknown",
];

export function allContentSources(): ContentSource[] {
  return [...ALL_CONTENT_SOURCES];
}

export const segmentContentTypeSchema = z.enum(["text", "json", "text_attachment"]);
export type SegmentContentType = z.infer<typeof segmentContentTypeSchema>;

export const contentSegmentSchema = z.object({
  segment_id: z.string(),
  source: contentSourceSchema,
  protocol_location: z.string(),
  content_type: segmentContentTypeSchema,
  text: z.string(),
  fingerprint: z.string(),
});
export type ContentSegment = z.infer<typeof contentSegmentSchema>;

import { detectorStageSchema, type DetectorStage } from "./contract.js";

export const guardrailEnvelopeSchema = z.object({
  protocol: guardrailProtocolSchema,
  stage: detectorStageSchema,
  segments: z.array(contentSegmentSchema),
});
export type GuardrailEnvelope = z.infer<typeof guardrailEnvelopeSchema>;

/** `sha256:<hex>` fingerprint of `text` (content identity, not keyed evidence). */
export function contentFingerprint(text: string): string {
  return fingerprint(text);
}

function fingerprint(text: string): string {
  return `sha256:${toHex(sha256(new TextEncoder().encode(text)))}`;
}

function newSegment(
  segmentId: string,
  source: ContentSource,
  protocolLocation: string,
  contentType: SegmentContentType,
  text: string,
): ContentSegment {
  return {
    segment_id: segmentId,
    source,
    protocol_location: protocolLocation,
    content_type: contentType,
    text,
    fingerprint: fingerprint(text),
  };
}

function protocolName(protocol: GuardrailProtocol): string {
  switch (protocol) {
    case "chat_completions":
      return "chat";
    case "responses":
      return "responses";
    case "embeddings":
      return "embeddings";
    case "images":
      return "images";
    case "managed_action":
      return "managed_action";
    case "a2a":
      return "a2a";
  }
}

function sourceForRole(role: string): ContentSource {
  switch (role) {
    case "system":
      return "system";
    case "developer":
      return "developer";
    case "user":
      return "user";
    case "assistant":
      return "assistant";
    case "tool":
    case "function":
      return "tool_result";
    default:
      return "unknown";
  }
}

/** Single-segment text envelope (Rust `GuardrailEnvelope::from_text`). */
export function envelopeFromText(
  protocol: GuardrailProtocol,
  stage: DetectorStage,
  source: ContentSource,
  protocolLocation: string,
  text: string,
): GuardrailEnvelope {
  return {
    protocol,
    stage,
    segments: [newSegment(`${protocolName(protocol)}:0`, source, protocolLocation, "text", text)],
  };
}

/** Single-segment managed-action envelope (issue #200). */
export function envelopeManagedAction(
  stage: DetectorStage,
  protocolLocation: string,
  text: string,
): GuardrailEnvelope {
  const source: ContentSource = stage === "request" ? "tool_arguments" : "tool_result";
  return envelopeFromText("managed_action", stage, source, protocolLocation, text);
}

/** Join all segment texts with `"\n"` (Rust `flattened_text`). */
export function flattenedText(envelope: GuardrailEnvelope): string {
  return envelope.segments.map((s) => s.text).join("\n");
}

/** Sum of UTF-8 byte lengths across segments (Rust `total_text_bytes`). */
export function totalTextBytes(envelope: GuardrailEnvelope): number {
  return envelope.segments.reduce((acc, s) => acc + byteLen(s.text), 0);
}

// --- Envelope builder -------------------------------------------------------

class EnvelopeBuilder {
  protocol: GuardrailProtocol;
  stage: DetectorStage;
  segments: ContentSegment[] = [];

  constructor(protocol: GuardrailProtocol, stage: DetectorStage) {
    this.protocol = protocol;
    this.stage = stage;
  }

  get isEmpty(): boolean {
    return this.segments.length === 0;
  }

  push(source: ContentSource, location: string, contentType: SegmentContentType, text: string): void {
    if (text.length === 0) {
      return;
    }
    const index = this.segments.length;
    this.segments.push(
      newSegment(`${protocolName(this.protocol)}:${index}`, source, location, contentType, text),
    );
  }

  finish(): GuardrailEnvelope {
    return { protocol: this.protocol, stage: this.stage, segments: this.segments };
  }
}

function asArray(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function get(value: unknown, key: string): unknown {
  const obj = asObject(value);
  return obj ? obj[key] : undefined;
}

/** Walk a provider request body into an envelope for the given protocol. */
export function normalizeRequest(protocol: GuardrailProtocol, body: unknown): GuardrailEnvelope {
  const builder = new EnvelopeBuilder(protocol, "request");
  switch (protocol) {
    case "chat_completions":
      extractChatRequest(body, builder);
      break;
    case "responses":
      extractResponsesRequest(body, builder);
      break;
    case "embeddings":
      extractEmbeddingsRequest(body, builder);
      break;
    case "images":
      extractImagesRequest(body, builder);
      break;
    case "managed_action":
    case "a2a":
      break;
  }
  return builder.finish();
}

/**
 * Walk a provider response into an envelope. `body` is the raw response bytes;
 * `streaming` selects SSE frame accumulation. Embeddings/Images/ManagedAction/
 * A2A are never response-normalized (they have no model-generated text output).
 */
export function normalizeResponse(
  protocol: GuardrailProtocol,
  body: Uint8Array,
  streaming: boolean,
): GuardrailEnvelope {
  const builder = new EnvelopeBuilder(protocol, "response");
  if (
    protocol === "embeddings" ||
    protocol === "images" ||
    protocol === "managed_action" ||
    protocol === "a2a"
  ) {
    return builder.finish();
  }
  if (streaming) {
    extractSse(protocol, body, builder);
  } else {
    let value: unknown;
    try {
      value = JSON.parse(new TextDecoder().decode(body));
    } catch {
      value = undefined;
    }
    if (value !== undefined) {
      if (protocol === "chat_completions") {
        extractChatResponse(value, builder);
      } else if (protocol === "responses") {
        extractResponsesResponse(value, builder);
      }
    }
  }
  if (builder.isEmpty && body.length > 0) {
    builder.push("assistant", "response.raw", "text", new TextDecoder().decode(body));
  }
  return builder.finish();
}

function extractChatRequest(body: unknown, builder: EnvelopeBuilder): void {
  const messages = asArray(get(body, "messages"));
  if (messages) {
    messages.forEach((message, messageIndex) => {
      const role = asString(get(message, "role")) ?? "unknown";
      const source = sourceForRole(role);
      extractContent(get(message, "content"), source, `messages[${messageIndex}].content`, builder);
      extractToolCalls(get(message, "tool_calls"), `messages[${messageIndex}].tool_calls`, builder);
    });
  }
  extractTools(get(body, "tools"), "tools", builder);
  extractMetadata(get(body, "metadata"), builder);
}

function extractResponsesRequest(body: unknown, builder: EnvelopeBuilder): void {
  const instructions = asString(get(body, "instructions"));
  if (instructions !== undefined) {
    builder.push("developer", "instructions", "text", instructions);
  }
  const input = get(body, "input");
  if (typeof input === "string") {
    builder.push("user", "input", "text", input);
  } else if (Array.isArray(input)) {
    input.forEach((item, index) => extractResponsesItem(item, `input[${index}]`, builder));
  }
  extractTools(get(body, "tools"), "tools", builder);
  extractMetadata(get(body, "metadata"), builder);
}

function extractEmbeddingsRequest(body: unknown, builder: EnvelopeBuilder): void {
  const input = get(body, "input");
  if (typeof input === "string") {
    builder.push("user", "input", "text", input);
  } else if (Array.isArray(input)) {
    input.forEach((item, index) => {
      const text = asString(item);
      if (text !== undefined) {
        builder.push("user", `input[${index}]`, "text", text);
      }
    });
  }
  extractMetadata(get(body, "metadata"), builder);
}

function extractImagesRequest(body: unknown, builder: EnvelopeBuilder): void {
  const prompt = asString(get(body, "prompt"));
  if (prompt !== undefined) {
    builder.push("user", "prompt", "text", prompt);
  }
  extractMetadata(get(body, "metadata"), builder);
}

function extractChatResponse(body: unknown, builder: EnvelopeBuilder): void {
  const choices = asArray(get(body, "choices"));
  if (!choices) {
    return;
  }
  choices.forEach((choice, choiceIndex) => {
    const message = get(choice, "message") ?? get(choice, "delta");
    const role = asString(get(message, "role"));
    const source: ContentSource = role ? sourceForRole(role) : "assistant";
    extractContent(
      get(message, "content"),
      source,
      `choices[${choiceIndex}].message.content`,
      builder,
    );
    extractToolCalls(
      get(message, "tool_calls"),
      `choices[${choiceIndex}].message.tool_calls`,
      builder,
    );
  });
}

function extractResponsesResponse(body: unknown, builder: EnvelopeBuilder): void {
  const output = asArray(get(body, "output"));
  if (output) {
    output.forEach((item, index) => extractResponsesItem(item, `output[${index}]`, builder));
    return;
  }
  const outputText = asString(get(body, "output_text"));
  if (outputText !== undefined) {
    builder.push("assistant", "output_text", "text", outputText);
  }
}

function extractResponsesItem(item: unknown, location: string, builder: EnvelopeBuilder): void {
  const itemType = asString(get(item, "type")) ?? "message";
  if (itemType === "function_call") {
    const args = asString(get(item, "arguments"));
    if (args !== undefined) {
      builder.push("tool_arguments", `${location}.arguments`, "json", args);
    }
  } else if (itemType === "function_call_output") {
    extractContent(get(item, "output"), "tool_result", `${location}.output`, builder);
  } else {
    const role = asString(get(item, "role"));
    const source: ContentSource = role ? sourceForRole(role) : "user";
    extractContent(get(item, "content"), source, `${location}.content`, builder);
  }
}

function extractContent(
  content: unknown,
  source: ContentSource,
  location: string,
  builder: EnvelopeBuilder,
): void {
  if (typeof content === "string") {
    builder.push(source, location, "text", content);
    return;
  }
  if (Array.isArray(content)) {
    content.forEach((part, partIndex) => {
      const partType = asString(get(part, "type")) ?? "text";
      const partLocation = `${location}[${partIndex}]`;
      if (partType === "text" || partType === "input_text" || partType === "output_text") {
        const text = asString(get(part, "text"));
        if (text !== undefined) {
          builder.push(source, `${partLocation}.text`, "text", text);
        }
      } else if (partType === "input_file" || partType === "file") {
        const mediaType = asString(get(part, "media_type")) ?? "";
        if (mediaType.startsWith("text/")) {
          const textField = asString(get(part, "text"));
          if (textField !== undefined) {
            builder.push("text_attachment", `${partLocation}.text`, "text_attachment", textField);
          } else {
            const fileData = asString(get(part, "file_data"));
            if (fileData !== undefined) {
              builder.push(
                "text_attachment",
                `${partLocation}.file_data`,
                "text_attachment",
                fileData,
              );
            }
          }
        }
      }
    });
    return;
  }
  if (source === "tool_result" && content !== undefined && content !== null) {
    builder.push(source, location, "json", JSON.stringify(content));
  }
}

function extractToolCalls(calls: unknown, location: string, builder: EnvelopeBuilder): void {
  const arr = asArray(calls);
  if (!arr) {
    return;
  }
  arr.forEach((call, index) => {
    const args = asString(get(get(call, "function"), "arguments"));
    if (args !== undefined) {
      builder.push(
        "tool_arguments",
        `${location}[${index}].function.arguments`,
        "json",
        args,
      );
    }
  });
}

function extractTools(tools: unknown, location: string, builder: EnvelopeBuilder): void {
  const arr = asArray(tools);
  if (!arr) {
    return;
  }
  arr.forEach((tool, index) => {
    builder.push("tool_schema", `${location}[${index}]`, "json", JSON.stringify(tool));
  });
}

function extractMetadata(metadata: unknown, builder: EnvelopeBuilder): void {
  if (metadata === undefined || metadata === null) {
    return;
  }
  builder.push("metadata", "metadata", "json", JSON.stringify(metadata));
}

// --- SSE accumulation -------------------------------------------------------

function extractSse(protocol: GuardrailProtocol, body: Uint8Array, builder: EnvelopeBuilder): void {
  const normalized = new TextDecoder().decode(body).replace(/\r\n/g, "\n");
  // BTreeMap<(source, location)> → sort key preserves deterministic segment order.
  const accumulated = new Map<string, { source: ContentSource; location: string; text: string }>();
  const keyOf = (source: ContentSource, location: string) => `${source} ${location}`;
  const append = (source: ContentSource, location: string, text: string) => {
    const key = keyOf(source, location);
    const existing = accumulated.get(key);
    if (existing) {
      existing.text += text;
    } else {
      accumulated.set(key, { source, location, text });
    }
  };

  for (const frame of normalized.split("\n\n")) {
    let event: string | undefined;
    const dataLines: string[] = [];
    for (const line of frame.split("\n")) {
      if (line.startsWith("event:")) {
        event = line.slice("event:".length).trim();
      } else if (line.startsWith("data:")) {
        dataLines.push(line.slice("data:".length).replace(/^\s+/, ""));
      }
    }
    const data = dataLines.join("\n");
    if (data.length === 0 || data === "[DONE]") {
      continue;
    }
    let value: unknown;
    try {
      value = JSON.parse(data);
    } catch {
      continue;
    }
    if (protocol === "chat_completions") {
      accumulateChatSse(value, append);
    } else if (protocol === "responses") {
      accumulateResponsesSse(event, value, append);
    }
  }

  const ordered = [...accumulated.values()].sort((a, b) =>
    keyOf(a.source, a.location) < keyOf(b.source, b.location) ? -1 : 1,
  );
  for (const entry of ordered) {
    const contentType: SegmentContentType = entry.source === "tool_arguments" ? "json" : "text";
    builder.push(entry.source, entry.location, contentType, entry.text);
  }
}

type AppendFn = (source: ContentSource, location: string, text: string) => void;

function accumulateChatSse(value: unknown, append: AppendFn): void {
  const choices = asArray(get(value, "choices"));
  if (!choices) {
    return;
  }
  choices.forEach((choice, choiceIndex) => {
    const delta = get(choice, "delta");
    if (delta === undefined) {
      return;
    }
    const content = asString(get(delta, "content"));
    if (content !== undefined) {
      append("assistant", `choices[${choiceIndex}].delta.content`, content);
    }
    const calls = asArray(get(delta, "tool_calls"));
    if (calls) {
      calls.forEach((call, callOffset) => {
        const idx = get(call, "index");
        const callIndex = typeof idx === "number" ? idx : callOffset;
        const args = asString(get(get(call, "function"), "arguments"));
        if (args !== undefined) {
          append(
            "tool_arguments",
            `choices[${choiceIndex}].delta.tool_calls[${callIndex}].function.arguments`,
            args,
          );
        }
      });
    }
  });
}

function accumulateResponsesSse(event: string | undefined, value: unknown, append: AppendFn): void {
  const eventType = asString(get(value, "type")) ?? event;
  if (eventType === "response.output_text.delta") {
    const delta = asString(get(value, "delta"));
    if (delta !== undefined) {
      const output = numberOr(get(value, "output_index"), 0);
      const content = numberOr(get(value, "content_index"), 0);
      append("assistant", `output[${output}].content[${content}].text`, delta);
    }
  } else if (eventType === "response.function_call_arguments.delta") {
    const delta = asString(get(value, "delta"));
    if (delta !== undefined) {
      const index = numberOr(get(value, "index"), 0);
      append("tool_arguments", `output[${index}].arguments`, delta);
    }
  }
}

function numberOr(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

// --- Patch validation + application (security-critical) ---------------------

function patchError(message: string): DetectorError {
  return DetectorError.new("invalid_patch", message);
}

/**
 * Validate patches against the detector-visible segments only: known segment,
 * matching protocol path, matching fingerprint (else `stale_patch`), a valid
 * non-overlapping UTF-8-boundary byte range.
 */
export function validateContentPatchesForSegments(
  segments: ContentSegment[],
  patches: ContentPatch[],
): void {
  const ordered = [...patches].sort((a, b) => {
    if (a.segment_id !== b.segment_id) {
      return a.segment_id < b.segment_id ? -1 : 1;
    }
    if (a.byte_start !== b.byte_start) {
      return a.byte_start - b.byte_start;
    }
    return a.byte_end - b.byte_end;
  });
  let previous: { id: string; end: number } | undefined;
  for (const patch of ordered) {
    const segment = segments.find((s) => s.segment_id === patch.segment_id);
    if (!segment) {
      throw patchError("guardrail patch references an unknown segment");
    }
    if (patch.protocol_location !== segment.protocol_location) {
      throw patchError("guardrail patch protocol path does not match its segment");
    }
    if (patch.expected_fingerprint !== segment.fingerprint) {
      throw DetectorError.new("stale_patch", "guardrail patch fingerprint is stale");
    }
    if (
      patch.byte_start > patch.byte_end ||
      patch.byte_end > byteLen(segment.text) ||
      !isCharBoundary(segment.text, patch.byte_start) ||
      !isCharBoundary(segment.text, patch.byte_end) ||
      (previous !== undefined && previous.id === patch.segment_id && patch.byte_start < previous.end)
    ) {
      throw patchError("guardrail patch has an invalid, non-UTF-8, or overlapping range");
    }
    previous = { id: patch.segment_id, end: patch.byte_end };
  }
}

/**
 * Patch target's source must be declared AND a mutable text source
 * (System/Developer/User/Assistant/ToolResult/TextAttachment) with a text
 * content-type; JSON/metadata/tool-schema/tool-args are immutable
 * (`protected_path`).
 */
export function validateContentPatchPermissions(
  envelope: GuardrailEnvelope,
  declaredSources: ContentSource[],
  patches: ContentPatch[],
): void {
  validateContentPatchesForSegments(envelope.segments, patches);
  for (const patch of patches) {
    const segment = envelope.segments.find((s) => s.segment_id === patch.segment_id);
    if (!segment) {
      throw patchError("guardrail patch references an unknown segment");
    }
    if (
      !declaredSources.includes(segment.source) ||
      !isMutableSource(segment.source) ||
      !(segment.content_type === "text" || segment.content_type === "text_attachment")
    ) {
      throw DetectorError.new("protected_path", "guardrail patch targets a protected content path");
    }
  }
}

function isMutableSource(source: ContentSource): boolean {
  return (
    source === "system" ||
    source === "developer" ||
    source === "user" ||
    source === "assistant" ||
    source === "tool_result" ||
    source === "text_attachment"
  );
}

/**
 * Apply patches to exact text-bearing protocol paths in `document`. Re-checks
 * the fingerprint against the LIVE document text (else `stale_patch`) and
 * replaces byte ranges right-to-left. Returns a new document; the input is not
 * mutated.
 */
export function applyContentPatchesToDocument(
  document: unknown,
  envelope: GuardrailEnvelope,
  declaredSources: ContentSource[],
  patches: ContentPatch[],
): unknown {
  validateContentPatchesForSegments(envelope.segments, patches);
  validateContentPatchPermissions(envelope, declaredSources, patches);
  const output = structuredCloneJson(document);

  const grouped = new Map<string, ContentPatch[]>();
  for (const patch of patches) {
    const segment = envelope.segments.find((s) => s.segment_id === patch.segment_id);
    if (!segment) {
      throw patchError("guardrail patch references an unknown segment");
    }
    const list = grouped.get(segment.protocol_location) ?? [];
    list.push(patch);
    grouped.set(segment.protocol_location, list);
  }

  const paths = [...grouped.keys()].sort();
  for (const path of paths) {
    const pathPatches = grouped.get(path) as ContentPatch[];
    const target = valueAtProtocolPath(output, path);
    if (target === undefined) {
      throw DetectorError.new("stale_patch", "guardrail patch protocol path no longer exists");
    }
    const text = target.get();
    if (typeof text !== "string") {
      throw DetectorError.new("protected_path", "guardrail patch target is not an exact text field");
    }
    const first = pathPatches[0];
    if (first !== undefined && contentFingerprint(text) !== first.expected_fingerprint) {
      throw DetectorError.new(
        "stale_patch",
        "guardrail patch target changed after detector evaluation",
      );
    }
    const sorted = [...pathPatches].sort((a, b) =>
      a.byte_start !== b.byte_start ? a.byte_start - b.byte_start : a.byte_end - b.byte_end,
    );
    let replaced = text;
    for (let i = sorted.length - 1; i >= 0; i--) {
      const patch = sorted[i] as ContentPatch;
      replaced =
        byteSlice(replaced, 0, patch.byte_start) +
        patch.replacement +
        byteSlice(replaced, patch.byte_end, byteLen(replaced));
    }
    target.set(replaced);
  }
  return output;
}

function structuredCloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

interface PathCursor {
  get(): unknown;
  set(value: string): void;
}

/** Dotted/indexed protocol-path lens (`messages[0].content`). */
function valueAtProtocolPath(document: unknown, path: string): PathCursor | undefined {
  const tokens = parseProtocolPath(path);
  if (!tokens) {
    return undefined;
  }
  let parent: unknown = undefined;
  let parentKey: string | number | undefined;
  let current: unknown = document;
  for (const token of tokens) {
    if (token.kind === "field") {
      const obj = asObject(current);
      if (!obj || !(token.value in obj)) {
        return undefined;
      }
      parent = obj;
      parentKey = token.value;
      current = obj[token.value];
    } else {
      if (!Array.isArray(current) || token.value >= current.length) {
        return undefined;
      }
      parent = current;
      parentKey = token.value;
      current = current[token.value];
    }
  }
  if (parent === undefined || parentKey === undefined) {
    return undefined;
  }
  return {
    get: () => current,
    set: (value: string) => {
      (parent as Record<string | number, unknown>)[parentKey as string | number] = value;
    },
  };
}

type PathToken = { kind: "field"; value: string } | { kind: "index"; value: number };

/** Parse `messages[0].content`; rejects `..`, leading `.`, trailing `.`. */
export function parseProtocolPath(path: string): PathToken[] | undefined {
  if (path.length === 0 || path.startsWith(".") || path.includes("..")) {
    return undefined;
  }
  const tokens: PathToken[] = [];
  let i = 0;
  while (i < path.length) {
    const start = i;
    while (i < path.length && path[i] !== "." && path[i] !== "[") {
      i++;
    }
    if (i > start) {
      tokens.push({ kind: "field", value: path.slice(start, i) });
    }
    while (i < path.length && path[i] === "[") {
      i++;
      const numberStart = i;
      while (i < path.length && path[i]! >= "0" && path[i]! <= "9") {
        i++;
      }
      if (numberStart === i || path[i] !== "]") {
        return undefined;
      }
      tokens.push({ kind: "index", value: Number.parseInt(path.slice(numberStart, i), 10) });
      i++;
    }
    if (i < path.length) {
      if (path[i] !== ".") {
        return undefined;
      }
      i++;
      if (i === path.length) {
        return undefined;
      }
    }
  }
  return tokens.length > 0 ? tokens : undefined;
}
