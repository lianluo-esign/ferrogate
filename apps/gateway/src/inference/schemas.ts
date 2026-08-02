/**
 * Zod request/response schemas for the six inference operations.
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
    messages: z.array(chatMessageSchema, {
      required_error: 'chat completion request must include a "messages" array',
      invalid_type_error: 'chat completion request must include a "messages" array',
    }),
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
export const anthropicContentBlockSchema = z
  .object({ type: z.string().optional() })
  .passthrough();

/** One Anthropic turn. `content` is a string or an array of content blocks. */
export const anthropicMessageSchema = z
  .object({
    role: z.string().optional(),
    content: z
      .union([z.string(), z.array(anthropicContentBlockSchema), z.null()])
      .optional(),
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
    messages: z.array(anthropicMessageSchema, {
      required_error: 'Anthropic messages request must include a "messages" array',
      invalid_type_error: 'Anthropic messages request must include a "messages" array',
    }),
    stream: streamField,
    max_tokens: z.number().optional(),
    system: z
      .union([z.string(), z.array(anthropicContentBlockSchema), z.null()])
      .optional(),
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
  "tools",
  "structured_output",
]);

/** Input/output media a model supports — DERIVED, see `./model-metadata.ts`. */
const modelModalitiesSchema = z.object({
  input: z.array(z.enum(["text", "image", "embedding"])),
  output: z.array(z.enum(["text", "image", "embedding"])),
});

/**
 * Per-1M-token prices. `null` is UNPRICED and is NOT the same as `0`, which is
 * a genuinely free route — see `./model-metadata.ts` for why both states exist.
 */
const modelPricingSchema = z.object({
  currency: z.literal("USD"),
  unit: z.literal("per_1m_tokens"),
  input: z.number().nullable(),
  output: z.number().nullable(),
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
