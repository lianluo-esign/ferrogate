/**
 * Zod request/response schemas for the fourteen inference operations.
 *
 * Clean-room port of the Rust ingress extractors:
 *  - `ChatCompletionRequest`   (`server/chat.rs`, shared by `/v1/chat/completions`
 *                               and `/v1/responses` — see `AiEndpoint`)
 *  - `AnthropicMessagesRequest`(`server/messages.rs`)
 *  - `EmbeddingsRequest`       (`server/embeddings.rs`)
 *  - `ImagesRequest`           (`server/images.rs`)
 *  - `OpenAiModelList`/`OpenAiModel` (`server/responses.rs`, `/v1/models`)
 *
 * ## Faithfulness notes (read before tightening anything here)
 *
 * The Rust extractors are deliberately *thin*: `inventory-request-path.md` §1.4
 * records that "chat/messages/embeddings/images request bodies are largely
 * passed through as `serde_json::Value` and translated by the provider adapters,
 * not strongly typed here". None of the structs carry `deny_unknown_fields`, so
 * every unknown key survives to the upstream — which is why every schema below
 * is `.passthrough()`. Dropping unknown keys would silently strip caller
 * parameters (`temperature`, `tools`, `response_format`, …) and is a real
 * regression, not a cleanup.
 *
 * Two places where this port validates *more* than the Rust tree did:
 *
 *  1. `messages` on `/v1/chat/completions` is checked to be an array of objects.
 *     Rust only extracted `model`/`stream`/`metadata` and let the provider
 *     reject a malformed `messages`. `docs/rewrite/TESTING.md` makes the edge
 *     400 an explicit invariant of the TS port ("Zod: non-array messages → 400"),
 *     and `/v1/messages` already had exactly this check in Rust
 *     (`build_messages_request_plan`). The element schema stays open (`role` is
 *     a free string, `content` may be a string, an array of parts, or null) so
 *     no legitimate OpenAI payload is rejected.
 *     // PORT-TODO(P: inventory-request-path §1.4) — **KEPT AS A STANDING
 *     // CONSTRAINT, NOT A GAP.** Nothing is unported behind this marker: this
 *     // schema is STRICTER than the Rust extractor, deliberately, because
 *     // `docs/rewrite/TESTING.md` makes the edge 400 an invariant of the port.
 *     // The marker tracks the RISK that strictness carries — the Rust tree
 *     // could not reject a legitimate payload here and this one can. If a
 *     // provider ever needs a message shape this schema refuses, widen the
 *     // element schema; NEVER narrow the `.passthrough()`, which is what keeps
 *     // `temperature`/`tools`/`response_format` reaching the upstream. It is
 *     // closed the day the strictness is either removed or proven against
 *     // every adapter family's accepted message shapes.
 *
 *  2. Nothing else. `max_tokens` stays optional on `/v1/messages` even though
 *     Anthropic requires it, because the Rust `AnthropicAdapter` defaults it to
 *     1024 when absent (`anthropic.rs::prepare_chat_completions`).
 *
 * Validation failures are rendered by the caller as the Rust error envelope:
 * `invalid_json` (400) when the body is not JSON at all, `invalid_request`
 * (400) when the body is JSON but the shape is wrong. See `errors.ts`.
 */
import { z } from "zod";

// ---------------------------------------------------------------------------
// Request metadata (issue #171) — `ferrogate_billing::validate_request_metadata`
// ---------------------------------------------------------------------------

/** Rust `ferrogate_billing::MAX_METADATA_ENTRIES`. */
export const MAX_METADATA_ENTRIES = 8;
/** Rust `ferrogate_billing::MAX_METADATA_KEY_LEN` (bytes, not chars). */
export const MAX_METADATA_KEY_LEN = 64;
/** Rust `ferrogate_billing::MAX_METADATA_VALUE_LEN` (bytes, not chars). */
export const MAX_METADATA_VALUE_LEN = 256;

/**
 * `Option<BTreeMap<String, String>>` — a flat string→string map. The *bounds*
 * are intentionally NOT expressed in Zod: Rust reports a bound violation with
 * the distinct code `invalid_request_metadata`, whereas a type violation is
 * `invalid_request`. Keeping the two apart requires two checks; see
 * {@link validateRequestMetadata}.
 */
export const requestMetadataSchema = z.record(z.string(), z.string());
export type RequestMetadata = z.infer<typeof requestMetadataSchema>;

const utf8 = new TextEncoder();

/**
 * Port of `ferrogate_billing::validate_request_metadata`. Returns the
 * human-readable reason of the FIRST violation, or `null` when the map is
 * within bounds. Messages are byte-identical to the Rust `format!` strings so
 * client-side assertions carry over.
 *
 * Rust iterates a `BTreeMap`, i.e. in sorted key order; `Object.keys` is
 * insertion-ordered, so the keys are sorted here to keep "first violation
 * reported" deterministic and identical.
 */
export function validateRequestMetadata(metadata: RequestMetadata | undefined): string | null {
  if (metadata === undefined) {
    return null;
  }
  const keys = Object.keys(metadata).sort();
  if (keys.length > MAX_METADATA_ENTRIES) {
    return `metadata supports at most ${MAX_METADATA_ENTRIES} entries, got ${keys.length}`;
  }
  for (const key of keys) {
    const value = metadata[key] ?? "";
    if (key.length === 0) {
      return "metadata keys must not be empty";
    }
    if (utf8.encode(key).byteLength > MAX_METADATA_KEY_LEN) {
      return `metadata key ${JSON.stringify(key)} exceeds the ${MAX_METADATA_KEY_LEN}-byte limit`;
    }
    if (utf8.encode(value).byteLength > MAX_METADATA_VALUE_LEN) {
      return `metadata value for key ${JSON.stringify(key)} exceeds the ${MAX_METADATA_VALUE_LEN}-byte limit`;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Shared fragments
// ---------------------------------------------------------------------------

/**
 * `model: String` — required and non-empty. Rust's `serde` requires the field
 * to be present and a string; an empty string would fall through to
 * `resolve_model` and fail there with `model_not_found`, so emptiness is left
 * to the resolver rather than rejected here.
 */
const modelField = z.string({
  required_error: "missing field `model`",
  invalid_type_error: "invalid type: expected a string for field `model`",
});

/** `#[serde(default)] stream: bool` — absent means `false`, never `null`. */
const streamField = z.boolean().default(false);

/**
 * An OpenAI chat message. Deliberately open: `role` is a free-form string (the
 * Rust tree never enumerated roles, and OpenAI keeps adding them — `developer`
 * arrived after this code was written), `content` accepts the three shapes the
 * API actually sends, and unknown members pass through.
 */
export const chatMessageSchema = z
  .object({
    role: z.string(),
    content: z.union([z.string(), z.array(z.unknown()), z.null()]).optional(),
    name: z.string().optional(),
    tool_calls: z.array(z.unknown()).optional(),
    tool_call_id: z.string().optional(),
  })
  .passthrough();
export type ChatMessage = z.infer<typeof chatMessageSchema>;

// ---------------------------------------------------------------------------
// POST /v1/chat/completions — operation `createChatCompletion`
// ---------------------------------------------------------------------------

export const chatCompletionRequestSchema = z
  .object({
    model: modelField,
    messages: z
      .array(chatMessageSchema, {
        required_error: 'chat completion request must include a "messages" array',
        invalid_type_error: 'chat completion request must include a "messages" array',
      })
      .min(1, 'chat completion request must include a non-empty "messages" array'),
    stream: streamField,
    metadata: requestMetadataSchema.optional(),
  })
  .passthrough();
export type ChatCompletionRequest = z.infer<typeof chatCompletionRequestSchema>;

// ---------------------------------------------------------------------------
// POST /v1/responses — operation `createResponse`
// ---------------------------------------------------------------------------

/**
 * The Responses API carries `input` (string | array of items) instead of
 * `messages`, and the whole body is optional beyond `model` — a caller may send
 * only `model` + `previous_response_id`. Rust deserialized this endpoint into
 * the SAME `ChatCompletionRequest` extractor (`AiEndpoint::Responses`), so only
 * `model`/`stream`/`metadata` were ever enforced. That is reproduced exactly.
 */
export const responsesRequestSchema = z
  .object({
    model: modelField,
    input: z.union([z.string(), z.array(z.unknown())]).optional(),
    stream: streamField,
    metadata: requestMetadataSchema.optional(),
  })
  .passthrough();
export type ResponsesRequest = z.infer<typeof responsesRequestSchema>;

// ---------------------------------------------------------------------------
// POST /v1/messages — operation `createMessage` (Anthropic-native ingress)
// ---------------------------------------------------------------------------

/** One Anthropic content block; `type` drives the translation, rest is open. */
export const anthropicContentBlockSchema = z.object({ type: z.string().optional() }).passthrough();

/** One Anthropic turn. `content` is a string or an array of content blocks. */
export const anthropicMessageSchema = z
  .object({
    role: z.string().optional(),
    content: z.union([z.string(), z.array(anthropicContentBlockSchema), z.null()]).optional(),
  })
  .passthrough();

/**
 * `AnthropicMessagesRequest` plus the explicit `messages`-is-an-array check the
 * Rust handler performed immediately after deserializing
 * (`build_messages_request_plan`). The rejection message is byte-identical.
 */
export const anthropicMessagesRequestSchema = z
  .object({
    model: modelField,
    messages: z
      .array(anthropicMessageSchema, {
        required_error: 'Anthropic messages request must include a "messages" array',
        invalid_type_error: 'Anthropic messages request must include a "messages" array',
      })
      .min(1, 'Anthropic messages request must include a non-empty "messages" array'),
    stream: streamField,
    max_tokens: z.number().optional(),
    system: z.union([z.string(), z.array(anthropicContentBlockSchema), z.null()]).optional(),
    stop_sequences: z.array(z.string()).optional(),
    temperature: z.number().optional(),
    top_p: z.number().optional(),
    tools: z.array(z.unknown()).optional(),
    tool_choice: z.unknown().optional(),
    metadata: z.unknown().optional(),
  })
  .passthrough();
export type AnthropicMessagesRequest = z.infer<typeof anthropicMessagesRequestSchema>;

// ---------------------------------------------------------------------------
// POST /v1/messages/count_tokens — operation `countMessageTokens` (issue #671)
// ---------------------------------------------------------------------------

/**
 * The count-tokens request is the Messages request, and the SAME schema object
 * is reused rather than a parallel copy of it.
 *
 * That is the point: the endpoint promises "this is what /v1/messages would
 * charge you for this body". A separate schema that admitted a body
 * `/v1/messages` rejects (or rejected one it admits) would make the promise
 * untestable for exactly the requests where the two disagree. Anthropic's own
 * `count_tokens` takes the Messages body too, minus the `max_tokens`
 * requirement — and `max_tokens` is already optional on this schema because
 * Rust left it optional, so nothing has to be relaxed.
 *
 * `stream` is accepted-and-ignored rather than rejected: the schema passes
 * unknown members through, a counting request produces no stream, and refusing
 * a member the sibling endpoint accepts would make "send the same body to
 * either" false.
 */
export const anthropicCountTokensRequestSchema = anthropicMessagesRequestSchema;
export type AnthropicCountTokensRequest = z.infer<typeof anthropicCountTokensRequestSchema>;

/**
 * `MessageTokensCount` — Anthropic's `count_tokens` response, verbatim.
 *
 * One member. It is declared as a schema (rather than an inline object literal
 * in the handler) so the wire shape has a named, exported source of truth that
 * the OpenAPI document's `input_tokens`-only response schema can be read
 * against.
 */
export const anthropicTokenCountSchema = z.object({
  input_tokens: z.number().int().nonnegative(),
});
export type AnthropicTokenCount = z.infer<typeof anthropicTokenCountSchema>;

// ---------------------------------------------------------------------------
// POST /v1/embeddings — operation `createEmbedding`
// ---------------------------------------------------------------------------

/**
 * `input` must be a string or an array. Rust checked this on the raw
 * `serde_json::Value` *after* the extractor and produced this exact message
 * under code `invalid_request`; `z.custom` reproduces both.
 */
const embeddingsInputField = z.custom<string | unknown[]>(
  (value) => typeof value === "string" || Array.isArray(value),
  { message: 'embeddings request must include a string or array "input" field' },
);

export const embeddingsRequestSchema = z
  .object({
    model: modelField,
    input: embeddingsInputField,
    metadata: requestMetadataSchema.optional(),
  })
  .passthrough();
export type EmbeddingsRequest = z.infer<typeof embeddingsRequestSchema>;

// ---------------------------------------------------------------------------
// POST /v1/rerank — operation `createRerank` (issue #676)
// ---------------------------------------------------------------------------

/**
 * The ingress grammar, and why it is Cohere's rather than an invention.
 *
 * OpenAI has no rerank endpoint, so there is no OpenAI dialect to be compatible
 * with and no Rust ancestor to port. Every other vendor that ships one — Cohere,
 * Jina, Voyage, and the unified APIs that aggregate them — spells it
 * `{ model, query, documents, top_n }`, so that is what a client's existing
 * code already sends. Inventing a fourth spelling would mean every caller
 * writes a FerroGate-specific branch, which is the opposite of the reason this
 * operation exists.
 *
 * A document is a string OR `{ text }`: Cohere v1 accepted objects, v2 accepts
 * strings, and clients in the wild send both. They are normalized to text once,
 * at the adapter boundary ({@link rerankDocumentTexts} in `@ferrogate/providers`),
 * so nothing downstream carries two shapes.
 */
const rerankDocumentField = z.union([z.string(), z.object({ text: z.string() }).passthrough()]);

/**
 * `documents` must be a NON-EMPTY array.
 *
 * Empty is rejected rather than answered with an empty result list: a reranking
 * request with nothing to rank is a caller bug, and admitting it would spend an
 * upstream call (and a TPM reservation) to return `[]`.
 */
export const rerankRequestSchema = z
  .object({
    model: modelField,
    query: z.string().min(1, 'rerank request must include a non-empty "query" field'),
    documents: z
      .array(rerankDocumentField)
      .min(1, 'rerank request must include a non-empty "documents" array'),
    /** How many ranked results to return. Cohere's spelling; `top_k` upstream. */
    top_n: z.number().int().positive().optional(),
    /** Echo the ranked document text back, for a client that did not keep it. */
    return_documents: z.boolean().optional(),
    metadata: requestMetadataSchema.optional(),
  })
  .passthrough();
export type RerankRequest = z.infer<typeof rerankRequestSchema>;

// ---------------------------------------------------------------------------
// The audio surface — `createTranscription` / `createTranslation` /
// `createSpeech` (issue #703)
// ---------------------------------------------------------------------------

/**
 * `POST /v1/audio/{transcriptions,translations}` — the MULTIPART upload, after
 * the form has been parsed.
 *
 * ## Why this validates a normalized object rather than the `FormData`
 *
 * Every other operation on this surface hands Zod a JSON document, and the
 * error envelope, the metadata bounds check, the model gate and the estimator
 * all read `Record<string, unknown>`. Reshaping the form into that shape ONCE,
 * at the reader (`readAudioUpload` in `./handlers.ts`), means the twelve stages
 * downstream are untouched by the fact that this ingress happens to be
 * multipart — which is the whole point of #676's "structural twin" rule.
 *
 * `file` carries the decoded bytes plus the two things a provider needs to
 * label them. It is `unknown` to Zod on purpose: a `Uint8Array` is not a shape
 * Zod can usefully describe, and re-validating bytes it never parsed would be
 * theatre. What IS checked is that the part existed and was non-empty, which is
 * the caller error that actually happens.
 */
export const audioUploadRequestSchema = z
  .object({
    model: modelField,
    file: z.custom<AudioUploadFile>(
      (value) =>
        typeof value === "object" &&
        value !== null &&
        (value as AudioUploadFile).bytes instanceof Uint8Array &&
        (value as AudioUploadFile).bytes.byteLength > 0,
      { message: 'audio request must include a non-empty "file" part' },
    ),
    /** ISO-639-1 hint. Improves accuracy; never required. */
    language: z.string().optional(),
    /** A text hint that biases the decoder — OpenAI's `prompt` field. */
    prompt: z.string().optional(),
    response_format: z.enum(["json", "text", "verbose_json", "srt", "vtt"]).optional(),
    temperature: z.number().min(0).max(1).optional(),
    metadata: requestMetadataSchema.optional(),
  })
  .passthrough();
export type AudioUploadRequest = z.infer<typeof audioUploadRequestSchema>;

/**
 * The BY-REFERENCE spelling of the same request (issue #703): no `file` part,
 * a `file_ref` naming a recording the caller already published to R2 through
 * `/v1/assets/presign/upload/**`.
 *
 * A SECOND schema rather than a `file`-or-`file_ref` union on the first one,
 * for the error message. A union reports "no branch matched" and lists both
 * failures, so a caller who simply forgot the `file` part would be told about a
 * `file_ref` field they have never heard of. Two schemas, selected on which
 * field is present, means each caller error is reported in the vocabulary of
 * the request they actually sent.
 *
 * `file_ref` is validated here only as a non-empty string;
 * `parseAudioObjectReference` owns its grammar, because the grammar is the
 * asset coordinate's and belongs beside the resolver that uses it.
 */
export const audioReferenceRequestSchema = z
  .object({
    model: modelField,
    file_ref: z.string().min(1, 'audio request must include a non-empty "file_ref"'),
    language: z.string().optional(),
    prompt: z.string().optional(),
    response_format: z.enum(["json", "text", "verbose_json", "srt", "vtt"]).optional(),
    temperature: z.number().min(0).max(1).optional(),
    metadata: requestMetadataSchema.optional(),
  })
  .passthrough();

/**
 * The audio-upload ceiling, in bytes — the DEFAULT for
 * `InferenceLimits.audioUploadMaxBytes` (issue #703).
 *
 * 25 MiB, chosen for three reasons that agree:
 *
 *  1. it is OpenAI's own documented limit on `/v1/audio/transcriptions`, so a
 *     client that already works against OpenAI works here unchanged, and a
 *     client that would be refused there is refused here with the same shape of
 *     answer rather than after a wasted upstream round trip;
 *  2. it is roughly two hours of 24 kbit/s voice, which covers the workloads
 *     this surface exists for (meetings, calls, voice memos);
 *  3. it fits comfortably inside a Worker's memory bound even counting the
 *     base64 expansion the Workers AI leg applies (25 MiB → ~34 MiB), with room
 *     for the response and the isolate itself.
 *
 * It lives HERE, beside the schema, rather than in `handlers.ts`, because
 * `defaults.ts` needs it for `DEFAULT_INFERENCE_LIMITS` and `handlers.ts`
 * imports `defaults.ts` — the constant in the handler would be an import cycle.
 * The same reason `DEFAULT_IMAGE_COUNT` lives in this file rather than in the
 * estimator that clamps against it.
 */
export const MAX_AUDIO_UPLOAD_BYTES = 25 * 1024 * 1024;

/**
 * The BY-REFERENCE ceiling — the DEFAULT for
 * `InferenceLimits.audioReferenceMaxBytes` (issue #703).
 *
 * 40 MiB, and it is a different number from {@link MAX_AUDIO_UPLOAD_BYTES}
 * because it answers a different question. The inline ceiling bounds an
 * UNTRUSTED STREAM whose length the gateway cannot know until it has read it;
 * this one bounds an object whose exact size R2 already reported, so the risk
 * it manages is not ingest at all — it is how much of a 128 MiB isolate one
 * request may hold.
 *
 * The arithmetic, stated so it can be argued with:
 *
 *  - the OpenAI-compatible passthrough builds a `FormData` over the bytes, so
 *    peak residency is ~1x the object;
 *  - the Workers AI leg base64-encodes them (`workers_ai.ts`), so peak is the
 *    object PLUS its 4/3 encoding — 40 MiB → ~93 MiB. That is the binding
 *    constraint, and it is what picked 40 rather than 64.
 *
 * What that buys: ~2.8 hours of 32 kbit/s voice, ~1.4 hours at 64 kbit/s. The
 * 90-minute meeting recording this path exists for fits at any bitrate a voice
 * codec actually uses, and it fits WITHOUT the caller having to push it through
 * this Worker in one shot.
 *
 * What it does NOT claim: this is not unbounded, and pretending otherwise would
 * be the more comfortable lie. The bound exists because the by-reference read
 * still MATERIALIZES the object. Removing it means streaming `R2ObjectBody.body`
 * straight into a provider's multipart request body — genuinely possible, and
 * genuinely nicer here than on the inline path because an R2 object can be
 * re-opened per failover attempt where a consumed request stream cannot — but it
 * is a change to the dispatcher's body contract, not to this constant, and it is
 * not done. An operator whose isolate budget allows more raises
 * `audioReferenceMaxBytes`; the default is the one that is safe on the leg that
 * expands.
 */
export const MAX_AUDIO_REFERENCE_BYTES = 40 * 1024 * 1024;

/** One decoded upload part: the bytes plus how to label them upstream. */
export interface AudioUploadFile {
  readonly bytes: Uint8Array;
  readonly filename: string;
  readonly contentType: string;
}

/**
 * `POST /v1/audio/speech` — OpenAI's text-to-speech body.
 *
 * `input` is `min(1)` for the same reason `rerank.documents` is `min(1)`:
 * synthesizing nothing is a caller bug, and admitting it would spend an upstream
 * call and a TPM reservation to return an empty audio file.
 *
 * `voice` is OPTIONAL, which is a deviation from OpenAI (it requires one). The
 * reason is that the deployments this surface actually serves first are Workers
 * AI models whose voice selection is a `lang` code, and rejecting a request for
 * omitting a field the served provider does not have would make the OpenAI
 * dialect a liability rather than a compatibility layer. A caller targeting
 * OpenAI still sends it and it is forwarded verbatim.
 */
export const speechRequestSchema = z
  .object({
    model: modelField,
    input: z.string().min(1, 'speech request must include a non-empty "input" field'),
    voice: z.string().optional(),
    response_format: z.enum(["mp3", "opus", "aac", "flac", "wav", "pcm"]).optional(),
    speed: z.number().min(0.25).max(4).optional(),
    /** Workers AI's MeloTTS spelling of voice selection. */
    language: z.string().optional(),
    metadata: requestMetadataSchema.optional(),
  })
  .passthrough();
export type SpeechRequest = z.infer<typeof speechRequestSchema>;

// ---------------------------------------------------------------------------
// POST /v1/images/generations — operation `createImage`
// ---------------------------------------------------------------------------

/** `prompt` must be a present, non-blank string (Rust used `trim().is_empty()`). */
const imagePromptField = z.custom<string>(
  (value) => typeof value === "string" && value.trim().length > 0,
  {
    message: 'image generation request must include a non-empty string "prompt" field',
  },
);

/** Rust `images.rs::DEFAULT_IMAGE_COUNT` — `n` when the caller omits it. */
export const DEFAULT_IMAGE_COUNT = 1;
/** Rust `images.rs::MAX_ESTIMATED_IMAGE_COUNT` — cap on the pre-charge estimate. */
export const MAX_ESTIMATED_IMAGE_COUNT = 100;

export const imagesRequestSchema = z
  .object({
    model: modelField,
    prompt: imagePromptField,
    n: z.number().optional(),
    size: z.string().optional(),
    metadata: requestMetadataSchema.optional(),
  })
  .passthrough();
export type ImagesRequest = z.infer<typeof imagesRequestSchema>;

// ---------------------------------------------------------------------------
// GET /v1/models — operation `listModels`
// GET /v1/models/{model} — operation `getModel`
// ---------------------------------------------------------------------------

/** The closed capability vocabulary, as `catalog.ts` parses it out of config. */
const modelCapabilitySchema = z.enum([
  "chat",
  "streaming",
  "vision",
  "images",
  "embeddings",
  "rerank",
  "transcription",
  "speech",
  "tools",
  "structured_output",
]);

/** Input/output media a model supports — DERIVED, see `./model-metadata.ts`. */
const modelModalitiesSchema = z.object({
  input: z.array(z.enum(["text", "image", "embedding", "score", "audio"])),
  output: z.array(z.enum(["text", "image", "embedding", "score", "audio"])),
});

/**
 * One price direction across every leg. Equal legs emit a scalar; differing
 * legs emit their range. `null` is UNPRICED and is NOT the same as `0`, which
 * is a genuinely free route — see `./model-metadata.ts` for the mixed case.
 */
const modelPriceSchema = z.union([
  z.number(),
  z.null(),
  z.object({ min: z.number().nullable(), max: z.number().nullable() }),
]);

const modelPricingSchema = z.object({
  currency: z.literal("USD"),
  unit: z.literal("per_1m_tokens"),
  input: modelPriceSchema,
  output: modelPriceSchema,
});

/**
 * `OpenAiModel` (`responses.rs`), plus the discovery metadata issue #670 added.
 *
 * `created` is hard-coded 0 in the Rust tree. The first four fields are the
 * OpenAI object unchanged; the rest are ADDITIVE, so an OpenAI-shaped SDK keeps
 * parsing this body while an integrator can finally see what a model does and
 * what it costs without reading operator config. The derivation — including
 * which leg of a multi-route model answers — lives in `./model-metadata.ts`.
 */
export const openAiModelSchema = z.object({
  id: z.string(),
  object: z.literal("model"),
  created: z.number().int(),
  owned_by: z.string(),
  capabilities: z.array(modelCapabilitySchema),
  context_window: z.number().int().positive().nullable(),
  modalities: modelModalitiesSchema,
  pricing: modelPricingSchema,
});
export type OpenAiModel = z.infer<typeof openAiModelSchema>;

/** `OpenAiModelList` (`responses.rs`). */
export const openAiModelListSchema = z.object({
  object: z.literal("list"),
  data: z.array(openAiModelSchema),
});
export type OpenAiModelList = z.infer<typeof openAiModelListSchema>;

// ---------------------------------------------------------------------------
// Anthropic-dialect model objects — `GET /v1/models` on the Anthropic ingress
// ---------------------------------------------------------------------------

/**
 * `AnthropicModel` — the Anthropic SDK's `ModelInfo` shape.
 *
 * The Anthropic SDK's `ModelInfo` has seven fields: `id`, `type: "model"`,
 * `display_name`, `created_at`, `capabilities`, `max_input_tokens`,
 * `max_tokens`. Two of these are emitted as `null` because FerroGate does not
 * track the Anthropic capability model or per-model `max_tokens` limits:
 *
 *  - `capabilities` → `null` (FerroGate's own capability model is
 *    `ModelCapability[]`, not the Anthropic `ModelCapabilities` shape);
 *  - `max_tokens` → `null` (not tracked per model).
 *
 * The SDK's `ModelInfo` has no pricing field. FerroGate's price scalar/range is
 * therefore intentionally absent here rather than added as a dialect extension.
 *
 * `max_input_tokens` maps to `descriptor.context_window` (the same concept).
 *
 * `display_name` is the model id (FerroGate's own choice — the upstream model
 * descriptors carry no human-readable label, so the id is used verbatim).
 * `created_at` is an ISO-8601 string. This is served on the Anthropic ingress
 * (requests carrying `anthropic-version`), while the OpenAI ingress keeps the
 * OpenAI dialect (`{id, object:"model", created, owned_by}`).
 */
export const anthropicModelSchema = z.object({
  id: z.string(),
  type: z.literal("model"),
  display_name: z.string(),
  created_at: z.string(),
  capabilities: z.null(),
  max_input_tokens: z.number().nullable(),
  max_tokens: z.null(),
});
export type AnthropicModel = z.infer<typeof anthropicModelSchema>;

/**
 * `AnthropicModelList` — the `data` field consumed by the Anthropic SDK's
 * `Page`. The SDK's full response also declares `has_more`, `first_id`, and
 * `last_id`; FerroGate omits them because its model catalog is not paginated.
 * The SDK defaults those absent fields to `false`, `null`, and `null`, so
 * `hasNextPage()` correctly returns `false`.
 */
export const anthropicModelListSchema = z.object({
  data: z.array(anthropicModelSchema),
});
export type AnthropicModelList = z.infer<typeof anthropicModelListSchema>;

// ---------------------------------------------------------------------------
// Provider usage (response side)
// ---------------------------------------------------------------------------

/**
 * `ferrogate_providers::ProviderUsage`. Every member is `Option<u64>`; a
 * provider that reports only `total_tokens` is normal. Non-integer or negative
 * counts are dropped rather than metered (mirrors `Value::as_u64`).
 */
export const providerUsageSchema = z.object({
  prompt_tokens: z.number().int().nonnegative().optional(),
  completion_tokens: z.number().int().nonnegative().optional(),
  total_tokens: z.number().int().nonnegative().optional(),
});
export type ProviderUsageWire = z.infer<typeof providerUsageSchema>;

/**
 * Format a `ZodError` into the single-line message the Rust `format!("{}: {error}")`
 * produced from `serde_json`. serde reports one error (it fails fast); Zod
 * collects all of them, so they are joined in issue order — strictly more
 * information, same shape.
 */
export function formatZodError(error: z.ZodError): string {
  return error.issues
    .map((issue) => {
      const path = issue.path.join(".");
      return path.length > 0 ? `${path}: ${issue.message}` : issue.message;
    })
    .join("; ");
}
