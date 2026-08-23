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
import { type ContentPatch, DetectorError } from "./contract.js";
import { sha256, toHex } from "./hash.js";

export const guardrailProtocolSchema = z.enum([
  "chat_completions",
  "responses",
  "embeddings",
  "rerank",
  "images",
  // Issue #703. `audio_speech` and NOT a shared `audio` protocol: the two halves
  // of the audio surface are not symmetric. A speech request carries the TEXT a
  // caller wants spoken, which is ordinary user content and fully screenable; a
  // transcription request carries opaque audio bytes, which nothing in this tree
  // can read. One protocol covering both would extract the readable half and
  // silently claim the other, which is what an EMPTY envelope always is — a
  // screening that passes on nothing while producing an evidence row that says
  // it ran. There is deliberately no `audio_transcription` member for that
  // reason; see `GUARDRAIL_OPERATIONS` in `apps/gateway/src/guardrails/middleware.ts`.
  "audio_speech",
  // Issue #703, the OTHER half — and it is a RESPONSE-stage protocol, which is
  // what makes it a different member rather than a second spelling of
  // `audio_speech`.
  //
  // A transcription REQUEST is opaque audio and stays unscreenable; that has not
  // changed and `normalizeRequest` below extracts nothing for this protocol on
  // purpose. What IS screenable is the answer. A transcript is text, and it is
  // ATTACKER-CONTROLLED text: anyone who can hand the tenant an audio file
  // chooses every word of it, and it flows straight back to a caller who will
  // usually put it in the next prompt. That is the same trust boundary a
  // retrieved document crosses, so the segments are `text_attachment` and never
  // `assistant` — the transcript is not something a model of ours composed, it
  // is content that arrived from outside and was merely re-encoded.
  "audio_transcription",
  "managed_action",
  "a2a",
  // Issue #740. A HOSTED ASSET — a published `mcp_manifest`, `config_file`,
  // `skill_bundle` or a text file inside a `static_site` bundle.
  //
  // Its own member, and not `chat_completions` with a `text_attachment`
  // segment, for the reason `rerank` is its own member: `normalizeRequest`
  // extracts nothing from an asset for any existing protocol, so binding a
  // policy to one of them would produce an EMPTY envelope — a screening that
  // passes on nothing while writing an evidence row that says it ran. The
  // asset screener builds its envelope directly with `envelopeFromText`,
  // exactly as `apps/agent-runtime` does for `a2a`, so both extraction arms
  // below are deliberately empty rather than absent.
  "asset",
  // Gemini-native ingress (`POST /v1beta/models/{model}:generateContent`).
  //
  // Its own member and NOT `chat_completions`, for the reason `rerank` and
  // `asset` are: the chat extractor walks `messages[].content`, and a Gemini
  // body carries `contents[].parts[].text` with `systemInstruction` beside it,
  // so binding this surface to `chat_completions` would produce an EMPTY
  // envelope — a screening that passes on nothing while writing an evidence row
  // that says it ran. Both a REQUEST-stage (the caller's `contents` on their way
  // to a provider) and a RESPONSE-stage (`candidates[].content.parts[].text`,
  // the model's answer) are screenable, so unlike `audio_speech`/
  // `audio_transcription` this one member covers both directions. See
  // `GUARDRAIL_OPERATIONS` in `apps/gateway/src/guardrails/middleware.ts`.
  "gemini",
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

import { type DetectorStage, detectorStageSchema } from "./contract.js";

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
    case "rerank":
      return "rerank";
    case "audio_speech":
      return "audio_speech";
    case "audio_transcription":
      return "audio_transcription";
    case "images":
      return "images";
    case "managed_action":
      return "managed_action";
    case "a2a":
      return "a2a";
    case "asset":
      return "asset";
    case "gemini":
      return "gemini";
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

  push(
    source: ContentSource,
    location: string,
    contentType: SegmentContentType,
    text: string,
  ): void {
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
    case "rerank":
      extractRerankRequest(body, builder);
      break;
    case "audio_speech":
      extractAudioSpeechRequest(body, builder);
      break;
    case "images":
      extractImagesRequest(body, builder);
      break;
    case "gemini":
      extractGeminiRequest(body, builder);
      break;
    // A transcription request is `multipart/form-data` wrapping opaque audio.
    // Extracting the `model`/`language`/`prompt` fields beside it would produce
    // a "screened" request whose envelope contains none of the content the
    // request actually carries — the empty-envelope lie, one field short. The
    // gateway therefore never evaluates the request stage for this protocol
    // (`OperationBinding.screensRequest`) and this arm is the seam that makes
    // that structural rather than a convention.
    case "audio_transcription":
    case "managed_action":
    case "a2a":
    // Issue #740. Same seam as `a2a`: the asset screener owns the envelope
    // (there is no request BODY to walk — the content is an object in R2), so
    // this arm must extract nothing rather than fall through to a generic walk
    // that would find a JSON manifest and label it as a chat document.
    case "asset":
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
    protocol === "rerank" ||
    // Issue #703. A speech response is AUDIO BYTES. There is no text to walk
    // and no detector in this tree reads a waveform, so the response stage is
    // an empty envelope by construction — stated here rather than left to a
    // JSON parse that would have failed on the bytes anyway.
    protocol === "audio_speech" ||
    protocol === "images" ||
    protocol === "managed_action" ||
    protocol === "a2a" ||
    // Issue #740. An asset has no RESPONSE document: it is screened once, at
    // publish, and the read path enforces that decision by withholding the row
    // rather than by screening the bytes again. Falling through would hit the
    // `response.raw` arm below and label a published binary `assistant`.
    protocol === "asset"
  ) {
    return builder.finish();
  }
  // Issue #703. Handled ahead of the generic arms and returned from directly,
  // because BOTH of the generic behaviours below are wrong for a transcript:
  // the JSON walk would find no chat/responses shape, and the `response.raw`
  // fallback would then label the whole document `assistant` — asserting that a
  // model of ours composed text that in fact arrived from whoever supplied the
  // audio. Provenance is the discriminator every injection rule scores on
  // (`injection.ts::sourceTrust`), so getting it wrong here would silently
  // downgrade an attack in a retrieved recording to the trust level of our own
  // completion.
  if (protocol === "audio_transcription") {
    extractAudioTranscriptionResponse(body, builder);
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
      } else if (protocol === "gemini") {
        extractGeminiResponse(value, builder);
      }
    }
  }
  if (builder.isEmpty && body.length > 0) {
    builder.push("assistant", "response.raw", "text", new TextDecoder().decode(body));
  }
  return builder.finish();
}

/**
 * The transcript, out of whatever shape the caller's `response_format` asked
 * for (issue #703).
 *
 * `handleAudioUpload` answers three different bodies off one upstream result,
 * and an attacker picks which one by setting a form field — so all three have to
 * reach the screener or the control is bypassable by a one-word change to the
 * request:
 *
 *  - `json` (the default) ⇒ `{"text": ...}`;
 *  - `verbose_json` ⇒ the same plus `segments[].text`, each of which is walked
 *    on its own, because a phrase split across a segment boundary is still a
 *    phrase and because a redaction patch has to name the exact field it edits;
 *  - `text` (and `srt`/`vtt`) ⇒ the bare transcript, no JSON around it.
 *
 * The last case is why the fallback is keyed on "did this parse as a JSON
 * OBJECT", not on "did the walk find anything". A bare transcript that happens
 * to be a JSON scalar (`42`, `"yes"`, `null` — all things a one-word recording
 * produces) parses fine and would otherwise be dropped on the floor as an
 * unrecognized document. Conversely a document that IS an object but carries no
 * text is left EMPTY rather than being fed to the detectors as raw JSON: an
 * envelope whose only content is `{"text":""}`'s punctuation would be a
 * screening that ran on scaffolding, which is the empty-envelope lie wearing a
 * segment.
 */
function extractAudioTranscriptionResponse(body: Uint8Array, builder: EnvelopeBuilder): void {
  if (body.length === 0) {
    return;
  }
  const decoded = new TextDecoder().decode(body);
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded);
  } catch {
    parsed = undefined;
  }
  const document = asObject(parsed);
  if (document === undefined) {
    builder.push("text_attachment", "response.raw", "text_attachment", decoded);
    return;
  }
  const text = asString(document.text);
  if (text !== undefined) {
    builder.push("text_attachment", "response.text", "text_attachment", text);
  }
  const segments = asArray(document.segments);
  if (segments !== undefined) {
    segments.forEach((segment, index) => {
      const segmentText = asString(get(segment, "text"));
      if (segmentText !== undefined) {
        builder.push(
          "text_attachment",
          `response.segments[${index}].text`,
          "text_attachment",
          segmentText,
        );
      }
    });
  }
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

/**
 * `POST /v1/rerank` (issue #676) — the QUERY and every DOCUMENT.
 *
 * Both halves are user content on its way to a provider, so both are screened.
 * The documents especially: a RAG pipeline reranks chunks it just pulled out of
 * a corpus, which is precisely where a secret or a customer record nobody meant
 * to send to a vendor comes from. A policy that redacts a card number out of a
 * chat prompt and lets the same number through inside a document being ranked
 * has not been enforced — it has been routed around.
 *
 * The `{ text }` document spelling the ingress also admits is read here too. The
 * path strings (`documents[i]`) name the CALLER's index on purpose: a patch is
 * applied by path, so a redaction has to land in the document the caller sent
 * rather than in the flattened array the adapter builds later.
 */
function extractRerankRequest(body: unknown, builder: EnvelopeBuilder): void {
  const query = asString(get(body, "query"));
  if (query !== undefined) {
    builder.push("user", "query", "text", query);
  }
  const documents = asArray(get(body, "documents"));
  documents?.forEach((document, index) => {
    const plain = asString(document);
    if (plain !== undefined) {
      builder.push("user", `documents[${index}]`, "text", plain);
      return;
    }
    // The `{ text }` spelling. The path descends to `.text` rather than stopping
    // at the element, because `applyContentPatchesToDocument` refuses to write a
    // path whose value is not a string — so a path of `documents[i]` would make
    // every redaction on an object-shaped document a `protected_path` error
    // instead of a redaction.
    const wrapped = asString(get(document, "text"));
    if (wrapped !== undefined) {
      builder.push("user", `documents[${index}].text`, "text", wrapped);
    }
  });
  extractMetadata(get(body, "metadata"), builder);
}

/**
 * `POST /v1/audio/speech` (issue #703) — the text a caller asked to be spoken.
 *
 * This is the one genuinely screenable half of the audio surface, and it is
 * worth screening for a reason specific to it: synthesis turns text into an
 * artefact that leaves the text channel entirely. A secret spoken into an MP3 is
 * past every downstream text control a tenant owns — a DLP scan of chat
 * transcripts, a log scrubber, a redaction policy on `/v1/chat/completions` —
 * because none of them reads audio. The last point at which the string is still
 * a string is right here.
 *
 * `voice` and `response_format` are NOT pushed. They are enum-shaped provider
 * knobs, not content, and a redaction patch landing on `voice` would rewrite a
 * routing field rather than withhold anything — the exact class this module's
 * header calls out as the reason patching is deliberately narrow.
 */
function extractAudioSpeechRequest(body: unknown, builder: EnvelopeBuilder): void {
  const input = asString(get(body, "input"));
  if (input !== undefined) {
    builder.push("user", "input", "text", input);
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

/**
 * The Gemini `ContentSource` for a `contents[].role` (Gemini-native ingress).
 *
 * Gemini names exactly two turn roles — `user` and `model` — plus the implicit
 * "no role" of a single-turn request, which the API treats as `user`. A
 * `functionResponse` part is tool output regardless of the turn it rides in and
 * is classified at the part level (below), so it never reaches here.
 */
function geminiSource(role: string | undefined): ContentSource {
  switch (role) {
    case "model":
      return "assistant";
    case "user":
      return "user";
    default:
      // A `contents` entry with no role is a single-turn user prompt.
      return "user";
  }
}

/**
 * Walk a Gemini `parts[]` array — the shape shared by `contents[]` (request),
 * `systemInstruction` (request) and `candidates[].content` (response).
 *
 *  - `text` is ordinary content, classed by the enclosing turn's `source`.
 *  - `functionCall.args` is MODEL-authored tool input; it is an OBJECT on this
 *    protocol (unlike OpenAI's stringified `arguments`), so it is serialized for
 *    the detector to read. A redaction patch targeting it would be refused by
 *    `applyContentPatchesToDocument` (the path resolves to an object, not a
 *    string) — the same honest failure `rerank`'s object documents take, and the
 *    reason detection is stringified while rewriting stays a no-op here.
 *  - `functionResponse.response` is TOOL output — content that arrived from
 *    outside the model — so it is `tool_result` and screened as the injection
 *    surface it is.
 *  - `inlineData` / `fileData` are binary or references with nothing a text
 *    detector can read, and are deliberately skipped.
 */
function extractGeminiParts(
  parts: unknown,
  source: ContentSource,
  location: string,
  builder: EnvelopeBuilder,
): void {
  const arr = asArray(parts);
  if (!arr) {
    return;
  }
  arr.forEach((part, index) => {
    const partLocation = `${location}.parts[${index}]`;
    const text = asString(get(part, "text"));
    if (text !== undefined) {
      builder.push(source, `${partLocation}.text`, "text", text);
      return;
    }
    const functionCall = get(part, "functionCall");
    if (functionCall !== undefined) {
      const args = get(functionCall, "args");
      if (args !== undefined) {
        builder.push(
          "tool_arguments",
          `${partLocation}.functionCall.args`,
          "json",
          JSON.stringify(args),
        );
      }
      return;
    }
    const functionResponse = get(part, "functionResponse");
    if (functionResponse !== undefined) {
      const response = get(functionResponse, "response");
      if (response !== undefined) {
        builder.push(
          "tool_result",
          `${partLocation}.functionResponse.response`,
          "json",
          JSON.stringify(response),
        );
      }
    }
  });
}

/**
 * `POST /v1beta/models/{model}:generateContent` request — the caller's
 * `contents` and `systemInstruction` on their way to a provider (Gemini-native
 * ingress). `systemInstruction` is accepted under both its camelCase REST
 * spelling and the snake_case one, since the gateway forwards whichever the
 * client sent byte-for-byte.
 */
function extractGeminiRequest(body: unknown, builder: EnvelopeBuilder): void {
  const systemInstruction = get(body, "systemInstruction") ?? get(body, "system_instruction");
  extractGeminiParts(get(systemInstruction, "parts"), "system", "systemInstruction", builder);
  const contents = asArray(get(body, "contents"));
  contents?.forEach((content, index) => {
    const source = geminiSource(asString(get(content, "role")));
    extractGeminiParts(get(content, "parts"), source, `contents[${index}]`, builder);
  });
}

/**
 * `generateContent` buffered response — `candidates[].content.parts[].text` and
 * any `functionCall` arguments the model produced.
 */
function extractGeminiResponse(body: unknown, builder: EnvelopeBuilder): void {
  const candidates = asArray(get(body, "candidates"));
  if (!candidates) {
    return;
  }
  candidates.forEach((candidate, index) => {
    const content = get(candidate, "content");
    const role = asString(get(content, "role"));
    const source: ContentSource = role ? geminiSource(role) : "assistant";
    extractGeminiParts(get(content, "parts"), source, `candidates[${index}].content`, builder);
  });
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
      builder.push("tool_arguments", `${location}[${index}].function.arguments`, "json", args);
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
  const keyOf = (source: ContentSource, location: string) => `${source}\u0000${location}`;
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
    } else if (protocol === "gemini") {
      accumulateGeminiSse(value, append);
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

/**
 * `streamGenerateContent?alt=sse` — each frame is a partial
 * `GenerateContentResponse`, and a candidate's text arrives split across frames
 * exactly as `choices[].delta.content` does on chat. Accumulation is keyed on
 * `candidates[i].content.parts[j].text`, so the concatenation reassembles the
 * answer for a marker that straddles a frame boundary.
 */
function accumulateGeminiSse(value: unknown, append: AppendFn): void {
  const candidates = asArray(get(value, "candidates"));
  if (!candidates) {
    return;
  }
  candidates.forEach((candidate, candidateIndex) => {
    const parts = asArray(get(get(candidate, "content"), "parts"));
    if (!parts) {
      return;
    }
    parts.forEach((part, partIndex) => {
      const base = `candidates[${candidateIndex}].content.parts[${partIndex}]`;
      const text = asString(get(part, "text"));
      if (text !== undefined) {
        append("assistant", `${base}.text`, text);
      }
      const args = get(get(part, "functionCall"), "args");
      if (args !== undefined) {
        append("tool_arguments", `${base}.functionCall.args`, JSON.stringify(args));
      }
    });
  });
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
      (previous !== undefined &&
        previous.id === patch.segment_id &&
        patch.byte_start < previous.end)
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
      throw DetectorError.new(
        "protected_path",
        "guardrail patch target is not an exact text field",
      );
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
      while (i < path.length) {
        const character = path[i];
        if (character === undefined || character < "0" || character > "9") break;
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
