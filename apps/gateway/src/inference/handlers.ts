/**
 * Hono handlers for the twelve inference operations owned by `apps/gateway`.
 *
 * | contract operation      | method + path              | scope              | Rust handler |
 * |-------------------------|----------------------------|--------------------|--------------|
 * | `listModels`            | GET  /v1/models            | `models.read`      | `local.rs::handle_models` |
 * | `getModel`              | GET  /v1/models/{model}    | `models.read`      | issue #670 (no Rust twin) |
 * | `createChatCompletion`  | POST /v1/chat/completions  | `chat.completions` | `chat.rs::handle_chat_completions` |
 * | `createResponse`        | POST /v1/responses         | `responses.create` | `chat.rs::handle_responses` |
 * | `createMessage`         | POST /v1/messages          | `messages.create`  | `messages.rs::handle_messages` |
 * | `countMessageTokens`    | POST /v1/messages/count_tokens | `messages.create` | *(none — new in TS, issue #671)* |
 * | `createEmbedding`       | POST /v1/embeddings        | `embeddings.create`| `embeddings.rs::handle_embeddings` |
 * | `createRerank`          | POST /v1/rerank            | `embeddings.create`| *(none — new in TS, issue #676)* |
 * | `createImage`           | POST /v1/images/generations| `images.generate`  | `images.rs::handle_images` |
 *
 * `createRerank` (issue #676) is the second row with no Rust counterpart and the
 * only one with no OpenAI counterpart either: OpenAI ships no rerank endpoint,
 * so every RAG pipeline that needs one wires a second vendor around the gateway
 * and that spend leaves FerroGate's view. It reuses `embeddings.create` — see
 * {@link handleRerank} for why a seventh data-plane scope was rejected.
 *
 * `countMessageTokens` is the OTHER row with no Rust counterpart: the Rust tree
 * never exposed the estimator it already computed on every dispatch, so a
 * client could not size a context window or pre-estimate spend without paying
 * for a completion (issue #671). It reuses the estimator rather than adding a
 * second one — see {@link handleCountMessageTokens}.
 *
 * The Rust pipeline for every POST is the same six steps, and the ORDER is
 * load-bearing (`chat.rs:158`: "authenticate before reading the body, so an
 * unauthenticated oversized request is still `missing_api_key` and not
 * `payload_too_large`"):
 *
 *   1. authenticate + scope check   → owned by the contract-driven middleware
 *   2. read the body under the cap  → `payload_too_large` (413)
 *   3. parse JSON                   → `invalid_json` (400)
 *   4. extract/validate the shape   → `invalid_request` (400)
 *   5. metadata bounds              → `invalid_request_metadata` (400)
 *   6. model gate + resolve         → `model_not_allowed` (403) /
 *                                     `model_disabled` | `model_not_found` (400)
 *   7. adapter → dispatch           → `provider_dispatch_error` (502)
 *
 * Step 1 is NOT implemented here on purpose — ROUTE-MAP invariant 1 requires one
 * table-driven middleware for all 271 operations, and duplicating a per-route
 * guard is exactly what that invariant forbids. Everything from step 2 down is
 * this module's, and is implemented below.
 */
import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import type { Context, MiddlewareHandler } from "hono";
import type { z } from "zod";
import {
  applyCanary,
  eligibleCandidates,
  routeRequirements,
  routingRejectionFor,
  servableCandidates,
} from "./candidates.js";
import type { ModelEndpointKind } from "./candidates.js";
import { byokScopedModels } from "./byok.js";
import { resolveCandidates, resolveDeps } from "./defaults.js";
import { dispatchWithFailover } from "./reliability.js";
import type { AttemptCandidate } from "./reliability.js";
import {
  ProviderBodyTooLargeError,
  ProviderEndpointError,
  dispatchDeadline,
  parseProviderEndpoint,
  providerTransportMessage,
  readBoundedProviderBody,
  readBoundedProviderBytes,
  readBoundedStream,
} from "./dispatch.js";
import {
  envelopeForThrown,
  errorResponse,
  gatewayHeaders,
  jsonResponse,
  rawUpstreamResponse,
  reject,
  relayedRateLimitHeaders,
} from "./errors.js";
import type { InferenceRejection, UpstreamRelay } from "./errors.js";
import {
  countMessagesInputTokens,
  estimateChatCompletionUsage,
  estimateEmbeddingsUsage,
  estimateImagesUsage,
  estimateMessagesUsage,
  estimateRerankUsage,
  estimateAudioUploadUsage,
  estimateSpeechUsage,
  TOKENS_PER_AUDIO_SECOND,
} from "./estimate.js";
import type { EstimatedUsage } from "./estimate.js";
import { effectiveResidencyPolicy } from "../residency/policy.js";
import {
  genAiOperationForRouteLabel,
  observeGenAiInvocation,
} from "../telemetry/genai.js";
import { inferenceRequestScope, noInferenceLog, unmeteredTokenGovernor } from "./identity.js";
import type { InferenceLogFacts, TokenAdmissionHandle, TokenGovernor } from "./identity.js";
import { describeModel } from "./model-metadata.js";
import type { ModelDescriptor } from "./model-metadata.js";
import { expandPromptReference } from "./prompt-reference.js";
import { shadowMirrorFor, spawnShadowMirror } from "./shadow.js";
import type { ShadowMirror } from "./shadow.js";
import { enforceWorkflowGate, narrowByWorkflowProviders } from "./workflow.js";
import type { WorkflowGateOutcome } from "./workflow.js";
import type { WorkflowProviderConstraint } from "@ferrogate/policy";
import {
  adapterErrorMessage,
  callerCanUseModel,
  callerCanUseProvider,
  scopeCanSeeModel,
} from "./ports.js";
import type {
  Caller,
  InferenceBindings,
  InferenceDeps,
  InferenceOperation,
  PhysicalRoute,
  ResolvedInferenceDeps,
  StreamDialect,
  UpstreamRequest,
  Usage,
} from "./ports.js";
import {
  anthropicCountTokensRequestSchema,
  anthropicMessagesRequestSchema,
  audioUploadRequestSchema,
  chatCompletionRequestSchema,
  embeddingsRequestSchema,
  formatZodError,
  imagesRequestSchema,
  MAX_AUDIO_UPLOAD_BYTES,
  rerankRequestSchema,
  responsesRequestSchema,
  speechRequestSchema,
  validateRequestMetadata,
} from "./schemas.js";
import type {
  AnthropicTokenCount,
  AudioUploadFile,
  OpenAiModelList,
  RequestMetadata,
} from "./schemas.js";
import { DEFAULT_ROUTING_STRATEGY, orderCandidatesByStrategy } from "./strategy.js";
import { sseUsageTap, usageFromResponseBody, usageProviderKindFor } from "./usage.js";
import type { ProviderUsage, UsageDialect } from "./usage.js";

/** Hono variable map: the request id and caller resolved once per request. */
export interface InferenceEnv {
  Bindings: InferenceBindings;
  Variables: {
    requestId: string;
    inferenceCaller: Caller;
    /** The already-parsed JSON body (see {@link readInferenceBody}). */
    inferenceBody: unknown;
    /**
     * Ports for THIS request. Identical to the injected set except for a
     * `models` dependency supplied as a factory, which needs the Worker `env`
     * that only exists per request (see {@link envScopedDeps}).
     */
    inferenceDeps: ResolvedInferenceDeps;
    /**
     * The INBOUND request's abort signal, captured before
     * {@link readInferenceBody} replaces `c.req.raw` (the replacement Request
     * carries a fresh, never-aborted signal, so reading it at dispatch time
     * would silently disable client-disconnect propagation).
     */
    inferenceClientSignal: AbortSignal | undefined;
    /**
     * Rust step 5, the tokens-per-minute window, bound to the OUTER request
     * (see `./identity.ts`). Inert when the inner router is driven directly.
     */
    inferenceTokens: TokenGovernor;
    /**
     * #664 — where this app reports the facts a REQUEST LOG needs, bound to the
     * OUTER request (see `./identity.ts`). Inert when the inner router is
     * driven directly, exactly like {@link inferenceTokens}.
     */
    inferenceLog: (facts: InferenceLogFacts) => void;
    /**
     * #678 — attribution tags the OUTER gate supplied from the virtual key for
     * required tags the caller did not state. Merged UNDER the caller's own
     * `metadata` by {@link attributedMetadata}. Empty when nothing was
     * defaulted, which is the normal case.
     */
    inferenceAttributionDefaults: Readonly<Record<string, string>>;

    /**
     * replaces `c.req.raw`.
     *
     * #669. The GenAI observation seam (`src/telemetry/genai.ts`) is a
     * `WeakMap` keyed on the request the OUTER gateway layers hold, and after
     * the body reader has run `c.req.raw` is a DIFFERENT, re-presented object —
     * so writing the observation against `c.req.raw` from a handler files it
     * under a key nothing outside this router can look up, and the telemetry
     * middleware finds nothing. That is not hypothetical: it is exactly what
     * the first cut of #669 did, and every `gen_ai.*` assertion stayed red with
     * the whole chain otherwise wired.
     *
     * `inferenceClientSignal` above exists for the same reason (the replacement
     * Request carries a fresh signal); this is the same hazard, one field over.
     */
    inferenceOriginRequest: Request;
  };
}

type InferenceContext = Context<InferenceEnv>;

/** Rust route labels (`AiEndpoint::route`, `MESSAGES_ROUTE`, …) used in metering. */
const ROUTE_LABELS = {
  "chat.completions": "openai.chat.completions",
  responses: "openai.responses",
  messages: "anthropic.messages",
  embeddings: "openai.embeddings",
  // No vendor prefix, deliberately (issue #676): the other five labels name the
  // INGRESS dialect they port (`openai.*`, `anthropic.*`), and reranking has no
  // OpenAI or Anthropic surface to be a dialect of. `openai.rerank` would name a
  // vendor endpoint that does not exist, and dashboards key off this string.
  rerank: "rerank",
  // Vendor-prefixed, unlike `rerank` one line up, and the asymmetry is correct:
  // these three ARE the OpenAI dialect — `/v1/audio/transcriptions` is a real
  // OpenAI endpoint this surface ports, where reranking has no OpenAI endpoint
  // to be a dialect of. Dashboards key off these strings, so they name what the
  // request actually is.
  "audio.transcriptions": "openai.audio.transcriptions",
  "audio.translations": "openai.audio.translations",
  "audio.speech": "openai.audio.speech",
  images: "openai.images.generations",
  models: "openai.models",
} as const;

// ---------------------------------------------------------------------------
// Step 2 + 3 — bounded body read and JSON parse
// ---------------------------------------------------------------------------

/**
 * Reads the body under `limits.inference_body_max_bytes` and parses it as JSON.
 *
 * Two behaviors this middleware exists to preserve, both of which
 * `@hono/zod-validator` alone would lose:
 *
 *  - **`payload_too_large` (413)** — `read_request_body(session, max)` aborts
 *    once the cap is exceeded. Hono has no equivalent, so the cap is enforced
 *    here, BEFORE the body is parsed, so a hostile 100 MB body is never
 *    materialized as a JS string beyond the cap.
 *  - **`invalid_json` (400) distinct from `invalid_request` (400)** — Rust
 *    reports a body that is not JSON at all under a different code than a body
 *    that is JSON of the wrong shape. Hono's own validator raises an
 *    `HTTPException` with the plain-text message "Malformed JSON in request
 *    body", which is neither the right code nor the right envelope.
 *
 * It also normalizes the `Content-Type` gate. `hono/validator` skips JSON
 * validation entirely (yielding `{}`) when the request carries no JSON
 * content-type, which would turn a perfectly valid Rust-accepted request into a
 * spurious `invalid_request`. Rust parsed the bytes regardless of content-type,
 * so when the body IS valid JSON the request is rewritten with an
 * `application/json` content-type before the validator runs.
 */
function readInferenceBody(): MiddlewareHandler<InferenceEnv> {
  return async (c, next) => {
    const requestId = c.get("requestId");
    const max = c.get("inferenceDeps").limits.inferenceBodyMaxBytes;

    const declared = c.req.header("content-length");
    if (declared !== undefined) {
      const length = Number.parseInt(declared, 10);
      if (Number.isFinite(length) && length > max) {
        return errorResponse(tooLarge(max), requestId);
      }
    }

    const raw = new Uint8Array(await c.req.arrayBuffer());
    // A chunked / Content-Length-lying client is caught here, exactly as the
    // Rust reader re-checked after the read.
    if (raw.byteLength > max) {
      return errorResponse(tooLarge(max), requestId);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(
        new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(raw),
      );
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      return errorResponse(
        reject(400, "invalid_json", `invalid JSON body: ${detail}`),
        requestId,
      );
    }

    c.set("inferenceBody", parsed);
    // Re-present the (already consumed) body to the validator with a
    // content-type it will accept. `c.req.raw` is a mutable field on
    // `HonoRequest`; nothing has read the body cache at this point.
    c.req.raw = new Request(c.req.raw.url, {
      method: c.req.raw.method,
      headers: withJsonContentType(c.req.raw.headers),
      body: raw,
    });
    c.req.bodyCache.json = parsed;

    await next();
    return;
  };
}

/** Thrown by {@link readAudioUpload} when the ceiling is crossed mid-stream. */
class AudioUploadTooLargeError extends Error {}

/**
 * The MULTIPART ingress for `POST /v1/audio/{transcriptions,translations}`
 * (issue #703) — the one operation family whose body is not JSON.
 *
 * ## The ceiling, and why it is enforced by ABORTING rather than by measuring
 *
 * A Worker has a hard memory bound, so an unbounded upload is a denial of
 * service on ourselves — not on a provider, not on a tenant, on this isolate.
 * There are two shapes to refuse and they need two different mechanisms:
 *
 *  1. an honestly-declared oversized body. `Content-Length` alone decides it, so
 *     the refusal costs ZERO bytes read. That is the cheap, common case (an SDK
 *     uploading a two-hour recording) and it must not be answered by reading
 *     two hours of audio first.
 *  2. a chunked upload with NO `Content-Length`, or one that lies. This is the
 *     hostile shape, and the only correct answer is to stop pulling from the
 *     stream the moment the cap is crossed — which is exactly what
 *     `readBoundedStream` does, `reader.cancel()` and all. `request.formData()`
 *     and `request.arrayBuffer()` both buffer the WHOLE body and then let you
 *     measure it, so neither can be used here at any cap: by the time they
 *     return, the damage they were supposed to prevent has already happened.
 *
 * The cap is `limits.audioUploadMaxBytes` — a separate, much larger number than
 * `inferenceBodyMaxBytes` for the reason stated on that field.
 *
 * ## Why the form is re-parsed out of the bytes we already hold
 *
 * `new Response(bytes, { headers }).formData()` is a pure, in-memory parse of a
 * buffer whose size this middleware has already bounded, so the multipart
 * decode cannot exceed the ceiling either. Going through `c.req.formData()`
 * would have handed the parse the UNBOUNDED stream instead.
 *
 * ## Why it produces a plain object
 *
 * Everything downstream — the metadata bounds check, the model gate, the
 * estimator, the guardrail envelope, the adapters — reads
 * `Record<string, unknown>`. Normalizing here, once, is what lets the audio
 * handlers be structural twins of `handleEmbeddings` instead of a parallel path
 * that would have to re-implement each of those stages for a `FormData`.
 */
function readAudioUpload(): MiddlewareHandler<InferenceEnv> {
  return async (c, next) => {
    const requestId = c.get("requestId");
    const max = c.get("inferenceDeps").limits.audioUploadMaxBytes;

    const declared = c.req.header("content-length");
    if (declared !== undefined) {
      const length = Number.parseInt(declared, 10);
      if (Number.isFinite(length) && length > max) {
        return errorResponse(audioTooLarge(max), requestId);
      }
    }

    const stream = c.req.raw.body;
    let raw: Uint8Array;
    try {
      raw =
        stream === null
          ? new Uint8Array(0)
          : await readBoundedStream(stream, max, () => new AudioUploadTooLargeError());
    } catch (error) {
      if (error instanceof AudioUploadTooLargeError) {
        return errorResponse(audioTooLarge(max), requestId);
      }
      return errorResponse(
        reject(400, "invalid_request", "could not read the audio upload body"),
        requestId,
      );
    }

    const contentType = c.req.header("content-type") ?? "";
    let form: FormData;
    try {
      form = await new Response(raw as unknown as BodyInit, {
        headers: { "content-type": contentType },
      }).formData();
    } catch {
      // A distinct code from `invalid_request`, mirroring the `invalid_json`
      // vs `invalid_request` split the JSON reader draws one function up: "your
      // bytes are not a multipart body at all" and "your multipart body is
      // missing a field" are different mistakes with different fixes.
      return errorResponse(
        reject(
          400,
          "invalid_multipart",
          "request body is not a readable multipart/form-data document",
        ),
        requestId,
      );
    }

    const body: Record<string, unknown> = {};
    for (const [name, value] of form.entries()) {
      if (typeof value === "string") {
        body[name] = name === "temperature" ? numberOrString(value) : value;
        continue;
      }
      const file = value as File;
      body[name] = {
        bytes: new Uint8Array(await file.arrayBuffer()),
        filename: file.name === "" ? "audio" : file.name,
        contentType: file.type === "" ? "application/octet-stream" : file.type,
      } satisfies AudioUploadFile;
    }

    const parsed = audioUploadRequestSchema.safeParse(body);
    if (!parsed.success) {
      return errorResponse(
        reject(400, "invalid_request", `invalid audio request: ${formatZodError(parsed.error)}`),
        requestId,
      );
    }
    c.set("inferenceBody", body);

    await next();
    return;
  };
}

/**
 * A multipart field is always a string on the wire, but `temperature` is a
 * NUMBER in the ingress schema and in every provider's grammar. Converted here
 * rather than in the schema so the schema stays one shape for both ingresses.
 * A non-numeric value is left as the string it was, so the schema reports the
 * type error rather than this function silently producing `NaN`.
 */
function numberOrString(value: string): number | string {
  const parsed = Number(value);
  return value.trim() !== "" && Number.isFinite(parsed) ? parsed : value;
}

function audioTooLarge(maxBytes: number): InferenceRejection {
  return reject(
    413,
    "payload_too_large",
    `audio upload exceeds maximum size of ${maxBytes} bytes`,
  );
}

function tooLarge(maxBytes: number): InferenceRejection {
  return reject(
    413,
    "payload_too_large",
    `request body exceeds maximum size of ${maxBytes} bytes`,
  );
}

function withJsonContentType(headers: Headers): Headers {
  const next = new Headers(headers);
  next.set("content-type", "application/json");
  return next;
}

// ---------------------------------------------------------------------------
// Step 4 — Zod validation rendered as the Rust envelope
// ---------------------------------------------------------------------------

/**
 * `zValidator` with a hook that replaces the library's default
 * `{ success: false, error: … }` 400 body with the FerroGate error envelope.
 *
 * `label` reproduces `AiEndpoint::invalid_request_label` and its siblings, e.g.
 * `"invalid chat completion request"`, so the message reads exactly as the Rust
 * `format!("{label}: {error}")` did.
 */
function validateBody<S extends z.ZodTypeAny>(
  schema: S,
  label: string,
): MiddlewareHandler<InferenceEnv> {
  return zValidator("json", schema, (result, c) => {
    if (!result.success) {
      // `c` is typed against an empty Env inside the hook, so the variable map
      // is re-asserted here; the middleware above always set `requestId`.
      const requestId = (c as unknown as InferenceContext).get("requestId");
      return errorResponse(
        reject(400, "invalid_request", `${label}: ${formatZodError(result.error)}`),
        requestId,
      );
    }
    return undefined;
  }) as unknown as MiddlewareHandler<InferenceEnv>;
}

/** Nothing was defaulted — hoisted so the common path allocates nothing. */
const NO_ATTRIBUTION_DEFAULTS: Readonly<Record<string, string>> = Object.freeze({});

/**
 * The request's EFFECTIVE attribution tags: what the caller stated, over what
 * the outer gate defaulted from the virtual key (#678).
 *
 * ## Why the merge happens here and not in the gate
 *
 * The gate (`src/attribution/middleware.ts`) runs before this app and reads the
 * body from a `Request.clone()`; it deliberately does not REWRITE the body,
 * because rewriting would mean materializing and re-presenting the caller's
 * bytes and would put the `payload_too_large` / `invalid_json` boundary behind a
 * re-serialization. So the gate carries only what it ADDED, and the merge lands
 * at the exact point the metadata becomes `Usage.metadata` — i.e. at the one
 * value that reaches `billing_events.event_json -> metadata`, which is the
 * column #677's chargeback query filters on. A default that stopped short of
 * this line would satisfy the gate and still leave the charge unattributed.
 *
 * ## The direction of the spread is load-bearing
 *
 * Defaults FIRST, caller SECOND: a tag the caller stated always wins. The gate
 * only ever defaults keys the caller left unstated, so the two can collide only
 * if the request changed between the gate's read and this one — impossible for
 * one request, and the safe resolution either way.
 */
function attributedMetadata(
  c: InferenceContext,
  request: Record<string, unknown>,
): RequestMetadata | undefined {
  const stated = request["metadata"] as RequestMetadata | undefined;
  const defaults = c.get("inferenceAttributionDefaults");
  if (defaults === undefined || Object.keys(defaults).length === 0) return stated;
  return { ...defaults, ...(stated ?? {}) };
}

// ---------------------------------------------------------------------------
// Steps 5 + 6 — metadata bounds, model gate, model resolution
// ---------------------------------------------------------------------------

/**
 * The ORDERED candidate ladder for one request, each with its upstream request
 * already prepared.
 *
 * Rust's `routing.eligible_routes` (`chat.rs:243`) — the list the `'routes:`
 * loop walks. It is a LIST rather than a single route because that signature is
 * what the circuit breaker, the failover ladder and the eligibility gate all
 * hang off; see the class docs on `ModelResolver` in `./ports.ts`.
 */
interface PlannedRequest {
  readonly candidates: readonly AttemptCandidate[];
  /**
   * The MIRROR selected for this request (`server/shadow.rs::shadow_decision`),
   * or `undefined` when no shadow is configured, the caller is not sampled, or
   * the caller has no sticky identity.
   *
   * It rides on the plan rather than being recomputed at dispatch because the
   * mirror is chosen from the FULL candidate list — `servableCandidates` has
   * already stripped it out of `candidates` by then, which is exactly the
   * property that keeps a mirror off the ladder.
   */
  readonly shadow?: ShadowMirror | undefined;
}

/** `ModelEndpointKind` for the eligibility gate. */
function endpointKindFor(operation: InferenceOperation): ModelEndpointKind {
  switch (operation) {
    case "embeddings":
      return "embeddings";
    case "rerank":
      return "rerank";
    case "audio.transcriptions":
    case "audio.translations":
      // One capability serves both: they are the same Whisper-class model with
      // one flag flipped. See `ModelEndpointKind` in `./candidates.ts`.
      return "transcription";
    case "audio.speech":
      return "speech";
    case "images":
      return "images";
    case "responses":
      return "responses";
    default:
      // `model_catalog` never reaches the gate (it is not a dispatched
      // inference request); `/v1/messages` plans as `chat.completions` because
      // it dispatches a translated chat request, which is what Rust does too.
      return "chat.completions";
  }
}

/**
 * Runs steps 5 and 6 and builds the upstream request for every eligible
 * candidate route. Returns a rejection instead of throwing so the caller keeps
 * the Rust status/code pairs verbatim.
 *
 * `estimated` is the pre-dispatch token estimate, threaded in for the two Rust
 * arguments that read it: `request_input_token_upper_bound` (the prompt half,
 * feeding the context-window leg of the eligibility gate) and `estimated_usage`
 * (the whole thing, feeding `route_estimated_cost` under
 * `routing_strategy = "lowest_cost"`). It is a pure computation, so hoisting it
 * above the TPM admission — which still runs AFTER planning, for the reason
 * documented on {@link admitTokens} — changes nothing about when the caller is
 * charged. Absent (the `/v1/images` surface, whose estimate is a count of
 * generated images and prices nothing on the prompt side) leaves the
 * context-window leg unarmed and falls `lowest_cost` back to the unit cost,
 * which is `route_estimated_cost`'s own `None` arm.
 */
function planUpstream(
  deps: ResolvedInferenceDeps,
  caller: Caller,
  operation: InferenceOperation,
  logicalModel: string,
  metadata: RequestMetadata | undefined,
  stream: boolean,
  body: Record<string, unknown>,
  estimated?: EstimatedUsage,
  workflowConstraint: WorkflowProviderConstraint | null = null,
): PlannedRequest | InferenceRejection {
  const inputTokenUpperBound = estimated?.promptTokens ?? 0;
  const metadataReason = validateRequestMetadata(metadata);
  if (metadataReason !== null) {
    return reject(400, "invalid_request_metadata", metadataReason);
  }

  // `AuthContext::can_use_model` — 403, and deliberately BEFORE resolution so a
  // denied key cannot probe which model names exist.
  if (!callerCanUseModel(caller, logicalModel)) {
    return reject(
      403,
      "model_not_allowed",
      `API key is not allowed to use model ${logicalModel}`,
    );
  }

  // Re-checked against the tree, not against the audit: F10 and F11 have SINCE
  // LANDED and this marker no longer describes them.
  //
  //  - **Gateway config profiles (F10).** `src/middleware/response-cache.ts:88`
  //    exports `GATEWAY_CONFIG_HEADER = "x-ferrogate-config"`, reads it off the
  //    request and passes the id into `aiCacheEnabled`. Note that Rust's
  //    `GatewayConfigUse` (`state.rs:3325`) carries EXACTLY ONE override —
  //    `cache_enabled` — so "overrides per-request cache and routing behavior"
  //    overstated it: there is no routing leg to port.
  //  - **Exact-match response cache (F11).** `src/middleware/response-cache.ts`
  //    + `src/cache/{config,key,store,fingerprint,metrics}.ts`, mounted by
  //    `createGatewayApp` immediately before the routes, with the four-level
  //    `ai_cache_enabled` opt-out and the #233 guardrail-fingerprint rotation.
  //
  // PORT-TODO(P: `state_routing.rs:262` `GatewayConfigResolveError`, `src/cache/`):
  // two residues, neither of them in this directory, both stated precisely so
  // the next owner does not re-derive them from `crates/`.
  //
  //  1. **The typed profile-resolution errors.** Rust's
  //     `resolve_gateway_config_profile` returns `NotFound(id)` / `Disabled` /
  //     `NotAllowed` and REFUSES the request; the TS reader treats an unknown or
  //     forbidden `x-ferrogate-config` as "no profile", so a client that
  //     misspells a profile id silently gets the default posture instead of an
  //     error. Fail-open on a caching hint rather than on a policy, so it is a
  //     fidelity gap and not a hole — but it is a real one. The change is in
  //     `src/cache/config.ts` (which owns the profile table) plus one rejection
  //     arm here.
  //  2. **The SEMANTIC cache.** `semantic_cache.rs` (feature-hashed local
  //     embeddings + a cosine threshold) has no TS counterpart, and
  //     `@ferrogate/observability` still renders
  //     `ferrogate_ai_cache_requests_total{status="semantic_hit"}` — a series
  //     with no producer, which reads 0 forever and looks like a cold cache
  //     rather than an absent one. NOT a platform limit: Vectorize + Workers AI
  //     map onto it cleanly. It belongs beside the exact-match cache in
  //     `src/cache/`, not in the dispatch path here.
  //
  // `AppState::candidate_model_routes` — every ENABLED route for the model,
  // primary then fallbacks, priority→weight ordered.
  const resolved = resolveCandidates(deps.models, logicalModel);
  if (resolved.length === 0) {
    const known = deps.models
      .catalog()
      .find((candidate) => candidate.logicalModel === logicalModel);
    return known === undefined
      ? reject(400, "model_not_found", `unknown model ${logicalModel}`)
      : reject(400, "model_disabled", `model ${logicalModel} is disabled`);
  }

  // A tenant must not be able to invoke another tenant's private model even
  // when it guessed the logical name (`can_tenant_use_model`). The listing
  // filter and the invocation gate MUST agree — that was issue #515. Tenancy
  // lives on the registry ENTRY, so every candidate carries the same answer;
  // checking the primary is checking all of them.
  if (!scopeCanSeeModel(caller.scope, caller.projectId, resolved[0] as PhysicalRoute)) {
    return reject(400, "model_not_found", `unknown model ${logicalModel}`);
  }

  // Issue #681 — the TENANT residency policy the outer gate resolved, combined
  // with the per-CREDENTIAL `region_allowlist` the Rust port already carried.
  // Both must hold, so the region lists intersect; see
  // `residency/policy.ts::effectiveResidencyPolicy`.
  const residencyPolicy = effectiveResidencyPolicy(
    caller.residency ?? null,
    caller.regionAllowlist,
  );

  // `server/shadow.rs::shadow_decision` (sampling half) — chosen from the FULL
  // list, because the very next line removes the mirror from it. It is given the
  // residency policy DIRECTLY: the mirror is not a candidate, so
  // `eligibleCandidates` below never sees it, and before #681 that made the
  // mirror the one leg that could put a governed prompt in an unexamined region.
  const shadow = shadowMirrorFor(
    resolved,
    caller,
    operation,
    logicalModel,
    body,
    residencyPolicy,
  );

  // `AppState::canary_route` — promote the canary for the sticky subset of
  // callers it selects, drop it for everyone else — and then strip the SHADOW
  // route, which is a mirror and must never be servable to a client.
  const rolled = servableCandidates(applyCanary(resolved, caller));

  // `model_routing.rs` — eligibility runs BEFORE anything reads price or
  // health, "so an incompatible route is never allowed to reach dispatch".
  const requirements = routeRequirements(
    endpointKindFor(operation),
    body,
    stream,
    inputTokenUpperBound,
  );
  const decision = eligibleCandidates(rolled, requirements, residencyPolicy);
  if (decision.eligible.length === 0) {
    const rejection = routingRejectionFor(logicalModel, decision.exclusions, residencyPolicy);
    return reject(rejection.status, rejection.code, rejection.message);
  }

  // `chat.rs::apply_workflow_provider_constraint`, at the Rust position: the
  // node's provider pin is intersected with the ELIGIBLE routes — after
  // eligibility, before strategy ordering — so a node pinned to `anthropic-eu`
  // cannot be served by `anthropic-us` even when both are healthy and eligible.
  // `403 workflow_provider_not_allowed` when nothing survives, which is the
  // thirteenth refusal and the only one that cannot be decided before routing.
  const narrowed = narrowByWorkflowProviders(
    workflowConstraint,
    logicalModel,
    decision.eligible,
  );
  if (!narrowed.ok) return narrowed.rejection;

  // `candidate_model_routes`'s `match model.routing_strategy` — applied to the
  // SURVIVORS, after eligibility and before the first socket, which is the whole
  // point of the Rust ordering ("an incompatible cheap/healthy route therefore
  // cannot influence ordering"). The strategy is a property of the registry
  // ENTRY, so every leg carries the same value and the first survivor is as good
  // a place to read it as any; absent ⇒ `"priority"`, the pre-strategy order.
  const ordered = orderCandidatesByStrategy(
    narrowed.routes,
    (narrowed.routes[0] as PhysicalRoute).routingStrategy ?? DEFAULT_ROUTING_STRATEGY,
    { estimatedUsage: estimated, metrics: deps.routingMetrics },
  );

  const candidates: AttemptCandidate[] = [];
  let firstFailure: InferenceRejection | null = null;
  for (const route of ordered) {
    const adapter = deps.adapters.adapterFor(route.providerKind);
    if (adapter === null) {
      firstFailure ??= reject(
        502,
        "provider_adapter_error",
        `unsupported provider kind ${route.providerKind.trim().toLowerCase()}`,
      );
      continue;
    }

    const built = adapter.buildUpstreamRequest({
      operation,
      route,
      logicalModel,
      providerModel: route.providerModel,
      stream,
      body,
    });
    if (!built.ok) {
      // `UnsupportedCapability` is the fail-closed capability error from issue
      // #275 (e.g. images on an Anthropic route) and is a client-side 400;
      // an unknown kind is a server-side misconfiguration, 502.
      const status = built.error.kind === "unsupported_capability" ? 400 : 502;
      const code =
        built.error.kind === "unsupported_capability"
          ? "model_capability_unsupported"
          : built.error.kind === "invalid_request"
            ? "invalid_request"
            : "provider_adapter_error";
      firstFailure ??= reject(
        built.error.kind === "invalid_request" ? 400 : status,
        code,
        adapterErrorMessage(built.error),
      );
      continue;
    }

    candidates.push({ route, upstream: built.request });
  }

  // A candidate whose adapter refuses the request is dropped, not fatal — the
  // ladder falls through to one that can serve it. Only when NOTHING can be
  // prepared does the first refusal become the answer, which is exactly the
  // single-route behavior this path had before the ladder existed.
  if (candidates.length === 0) {
    return (
      firstFailure ??
      reject(502, "provider_adapter_error", `no provider adapter for model ${logicalModel}`)
    );
  }

  return { candidates, ...(shadow === null ? {} : { shadow }) };
}

/**
 * The `'routes:` loop, at the four dispatch sites.
 *
 * Everything about the ladder lives in `reliability.ts`; this function is the
 * seam that hands it the gateway-policy half of dispatch — endpoint-scheme
 * validation and the `limits.dispatchTimeoutMs` deadline, which stay in
 * {@link dispatchUpstream} so that every dispatcher, including one a test
 * injects, is held to them.
 *
 * It is also THE ONE PLACE the shadow mirror is fired (`spawn_shadow_mirror`).
 * All four dispatching handlers funnel through here, so the mirror cannot be
 * forgotten on one surface the way four separate call sites would eventually
 * allow — and firing it here rather than in the handlers puts it immediately
 * BEFORE the primary `await`, i.e. concurrently with the client's own dispatch
 * and never in front of it.
 */
async function dispatchCandidates(
  c: InferenceContext,
  deps: ResolvedInferenceDeps,
  planned: PlannedRequest,
): Promise<
  | {
      readonly route: PhysicalRoute;
      readonly response: Response;
      /**
       * Rust `ProviderAttempt.index` (#135) — the ZERO-BASED index of the
       * attempt that produced this response. `FailoverOutcome.attempts` counts
       * attempts MADE (so a first-try success is 1), and the served attempt is
       * always the last one made, hence `- 1`. Threaded onto {@link Usage} so
       * `metering/event.ts` can partition `ledgerEntryId` on it: without it two
       * attempts of one request derive one ledger id and the second is absorbed
       * by `ON CONFLICT DO NOTHING` as a silent under-bill.
       */
      readonly attemptIndex: number;
      /**
       * #726 — true when the candidate that answered is NOT the caller's
       * first-choice route.
       *
       * Deliberately derived from `FailoverOutcome.candidateIndex`, not from
       * {@link attemptIndex}: a same-provider RETRY re-dials the route the
       * caller asked for, so its rate-limit numbers are still theirs, while a
       * move to candidate 1 (whether the ladder walked there or the breaker
       * skipped candidate 0) reports a window the caller neither selected nor
       * is guaranteed to be routed to again. `errors.ts::relayedRateLimitHeaders`
       * argues what is done with it.
       */
      readonly failedOver: boolean;
    }
  | InferenceRejection
> {
  const signal = clientSignal(c);
  if (planned.shadow !== undefined) {
    // Fire-and-forget. `spawnShadowMirror` returns synchronously, hands the
    // work to `ctx.waitUntil`, and swallows every failure — see `shadow.ts`
    // for the five mechanisms that keep a mirror off the client's response.
    spawnShadowMirror(deps, planned.shadow, executionCtxOf(c));
  }
  // `auth.can_use_provider` — the credential's PROVIDER allowlist. Read from the
  // per-request caller (the same value `planUpstream` gates the model on) rather
  // than captured in `deps`, because `deps` is built once per router and the
  // allowlist is per credential. Passing a `deps`-level predicate here would
  // make the gate answer for whichever key happened to warm the isolate.
  const caller = c.get("inferenceCaller");
  const outcome = await dispatchWithFailover({
    candidates: planned.candidates,
    circuit: deps.circuit,
    settings: deps.reliability,
    providerAllowed: (provider) => callerCanUseProvider(caller, provider),
    // `ProviderRoutingMetrics::record_request_log` — recorded HERE rather than
    // inside `dispatchWithFailover` because the ladder is a pure decision
    // procedure over an injected `attempt`, and because the classification is
    // Rust's request-LOG rule, not the ladder's retry rule: a request counts as
    // failed on `status_code >= 400 || error_code.is_some()`, so a provider
    // answering 400 to a malformed body still counts against its observed
    // failure rate even though the circuit breaker (which guards on
    // `retryable_status`) deliberately ignores it. Latency is added only on the
    // success arm, so a provider that fails fast never looks fast.
    attempt: async (candidate) => {
      const startedAt = Date.now();
      const result = await dispatchUpstream(deps, candidate.upstream, signal);
      const provider = candidate.route.provider;
      if (isRejection(result) || !result.ok) {
        deps.routingMetrics.recordFailure(provider);
      } else {
        deps.routingMetrics.recordSuccess(provider, Date.now() - startedAt);
      }
      return result;
    },
    isRejection: (value): value is InferenceRejection => isRejection(value),
  });
  if (!outcome.ok) {
    return outcome.rejection;
  }
  return {
    route: outcome.candidate.route,
    response: outcome.response,
    attemptIndex: Math.max(0, outcome.attempts - 1),
    failedOver: outcome.candidateIndex > 0,
  };
}

// ---------------------------------------------------------------------------
// Step 7 — dispatch
// ---------------------------------------------------------------------------

/**
 * `dispatch_provider_request` transport failures → 502 `provider_dispatch_error`.
 *
 * `signal` is the INBOUND request's signal, forwarded to the provider fetch so a
 * client that hangs up stops the upstream generating (and billing) tokens
 * nobody will read. In Rust this was implicit — dropping the `reqwest::Response`
 * closed the provider connection — and `src/streaming/abort.ts` documents why
 * Workers has to wire it explicitly.
 *
 * Two of `dispatch.rs`'s guards run HERE rather than inside the injected
 * `UpstreamDispatcher`, and that placement is deliberate. `UpstreamDispatcher`
 * is the platform seam (`fetch` today, an AI-Gateway binding later); the
 * endpoint scheme check and the `limits.dispatchTimeoutMs` deadline are
 * *gateway policy*, so putting them here means every dispatcher — including one
 * a test injects — is held to them, and `limits` stays the single source of
 * truth instead of a value baked into whichever dispatcher was wired.
 */
async function dispatchUpstream(
  deps: ResolvedInferenceDeps,
  upstream: UpstreamRequest,
  signal?: AbortSignal,
): Promise<Response | InferenceRejection> {
  try {
    // `build_provider_request` parses the endpoint BEFORE opening a socket, so
    // a `file:`/`ws:` `base_url` is refused with its own message rather than
    // whatever the runtime says about an unsupported scheme.
    parseProviderEndpoint(upstream.endpoint);
  } catch (error) {
    const detail = error instanceof ProviderEndpointError ? error.message : String(error);
    return reject(502, "provider_dispatch_error", `provider dispatch failed: ${detail}`);
  }

  const deadline = dispatchDeadline(deps.limits.dispatchTimeoutMs, signal);
  try {
    return await deps.dispatcher.dispatch(upstream, deadline.signal);
  } catch (error) {
    return reject(
      502,
      "provider_dispatch_error",
      `provider dispatch failed: ${providerTransportMessage(
        upstream.stream,
        error,
        deadline.expired(),
      )}`,
    );
  }
}

/**
 * `read_bounded_response_body` at the four buffered call sites.
 *
 * The cap lives on the NON-streaming path only, exactly as in Rust:
 * `dispatch_provider_streaming_request` takes no `max_body_bytes` because a
 * stream is relayed frame-by-frame and never accumulated.
 *
 * A refusal is the same 502 `provider_dispatch_error` a transport failure gets,
 * because in Rust it is the same `bail!` out of the same `dispatch_provider_*`
 * function and every AI surface renders that as
 * `format!("provider dispatch failed: {error}")`. Note the ORDER: the cap is
 * enforced before the status is inspected, so an oversized provider ERROR body
 * is refused too rather than being relayed.
 */
async function readUpstreamBody(
  deps: ResolvedInferenceDeps,
  response: Response,
): Promise<string | InferenceRejection> {
  try {
    return await readBoundedProviderBody(response, deps.limits.providerResponseMaxBytes);
  } catch (error) {
    const detail =
      error instanceof ProviderBodyTooLargeError
        ? error.message
        : `failed to read provider response body: ${
            error instanceof Error ? error.message : String(error)
          }`;
    return reject(502, "provider_dispatch_error", `provider dispatch failed: ${detail}`);
  }
}

/**
 * The inbound request's abort signal, when the runtime exposes one.
 *
 * `Request.signal` is present in workerd and in `undici`, but a hand-built
 * `Request` in a unit test may not carry one, so this never throws.
 */
function inboundSignal(request: Request): AbortSignal | undefined {
  try {
    return request.signal ?? undefined;
  } catch {
    return undefined;
  }
}

/** The captured inbound signal for this request (see {@link InferenceEnv}). */
function clientSignal(c: InferenceContext): AbortSignal | undefined {
  return c.get("inferenceClientSignal");
}

/**
 * `c.executionCtx`, or `undefined` when the context was built without one.
 *
 * Reading it THROWS under `app.request(...)` in a unit test, so this is the
 * only safe way to reach `waitUntil` from a handler. `route-module.ts` has the
 * identical guard for the same reason; the two cannot share one because the
 * outer and inner apps have different `Env` types.
 */
function executionCtxOf(
  c: InferenceContext,
): { waitUntil(work: Promise<unknown>): void } | undefined {
  try {
    return c.executionCtx;
  } catch {
    return undefined;
  }
}

function isRejection(value: unknown): value is InferenceRejection {
  return (
    typeof value === "object" &&
    value !== null &&
    "status" in value &&
    "code" in value &&
    "message" in value
  );
}

// ---------------------------------------------------------------------------
// Step 5 (Rust numbering) — tokens per minute, charged with the estimate
// ---------------------------------------------------------------------------

/**
 * `try_consume_api_key_tokens_per_minute`, at the Rust call site.
 *
 * Placement is copied exactly and both halves of it matter:
 *
 *  - AFTER `planUpstream`, because Rust checks TPM inside the provider-attempt
 *    loop, i.e. once the model gate and route resolution have already answered.
 *    A caller sending an unknown model gets `model_not_found` and is NOT
 *    charged a minute's worth of tokens for it.
 *  - BEFORE `dispatchUpstream`, because the entire point is to refuse without
 *    paying a provider. Charging after dispatch would bill the tokens it was
 *    meant to prevent.
 *
 * Rust also checks it ONCE per logical request (`tpm_checked`), not once per
 * fallback route candidate; there is a single dispatch per request here, so
 * one call site per handler is the same thing.
 */
async function admitTokens(
  c: InferenceContext,
  estimated: EstimatedUsage,
): Promise<TokenAdmissionHandle | InferenceRejection | null> {
  return await c.get("inferenceTokens").admit(estimated.totalTokens);
}

/**
 * Reconcile the admission against the response's REAL usage.
 *
 * Opt-in: Rust never settles a TPM window, so with the default
 * `RateLimitOptions` this is a no-op and the port is byte-identical.
 *
 * It is never allowed to fail a response, so the rejection is swallowed — same
 * contract as {@link recordUsage}. Callers on the BUFFERED path `await` it,
 * because they still hold the response and a settlement that lands after the
 * next request has already been admitted has settled nothing. The two STREAMING
 * call sites cannot: they run inside the usage tap's `flush`, where there is no
 * response left to hold, so there it is {@link settleTokensDetached}.
 */
async function settleTokens(
  c: InferenceContext,
  admission: TokenAdmissionHandle | null,
  actualTokens: number | undefined,
): Promise<void> {
  if (admission === null || actualTokens === undefined) {
    return;
  }
  try {
    await c.get("inferenceTokens").settle(admission, actualTokens);
  } catch {
    // A settlement failure must not fail an already-produced response.
  }
}

/** {@link settleTokens} for the streaming tap, which cannot await. */
function settleTokensDetached(
  c: InferenceContext,
  admission: TokenAdmissionHandle | null,
  actualTokens: number | undefined,
): void {
  void settleTokens(c, admission, actualTokens);
}

/** The admission handle, or `null` for "nothing to settle". */
function admissionHandle(
  admitted: TokenAdmissionHandle | InferenceRejection | null,
): TokenAdmissionHandle | null {
  return admitted === null || isRejection(admitted) ? null : admitted;
}

// ---------------------------------------------------------------------------
// Steps 31-32 (Rust numbering) — the workflow GRAPH gate
// ---------------------------------------------------------------------------

/**
 * `chat.rs::decide_ai_workflow_admission`, at the Rust call site.
 *
 * Placement, and why each half of it is the reference's:
 *
 *  - BEFORE `planUpstream`, because a step that is not a legal move in the
 *    graph must be refused whatever the routing table says, and because the
 *    PROVIDER constraint it returns has to be in hand before candidates are
 *    narrowed. Rust runs the same ladder while building the request plan.
 *  - BEFORE `admitTokens`, so a refused step never spends a minute's tokens on
 *    a call it was never allowed to make.
 *
 * A request that declares no workflow header at all is `ungated` after one
 * header read and no I/O, so this costs an ordinary inference request nothing.
 */
async function admitWorkflowStep(
  c: InferenceContext,
  deps: ResolvedInferenceDeps,
  caller: Caller,
  logicalModel: string,
  estimated: EstimatedUsage | undefined,
): Promise<WorkflowGateOutcome | InferenceRejection> {
  const outcome = await enforceWorkflowGate(deps.workflows, deps.workflowHistory, {
    headers: c.req.raw.headers,
    requestId: c.get("requestId"),
    caller,
    logicalModel,
    estimatedTotalTokens: estimated?.totalTokens ?? 0,
    nowUnixSeconds: deps.nowUnixSeconds(),
  });
  if (outcome.kind === "refused") return outcome.rejection;
  if (outcome.kind === "admitted") {
    // Written at ADMISSION, with `succeeded: false`: the model-call counter and
    // the run's start time must include a step that was allowed even if the
    // provider then failed, or a caller could exhaust `max_model_calls`'
    // worth of provider attempts by ensuring each one errors. The edge gate
    // reads only SUCCEEDED rows, so a failed step still does not advance the
    // graph.
    await deps.workflowHistory.recordStep({
      ...outcome.step,
      requestId: c.get("requestId"),
      occurredAtUnix: deps.nowUnixSeconds(),
      totalTokens: estimated?.totalTokens ?? 0,
      succeeded: false,
    });
  }
  return outcome;
}

/**
 * Settle an admitted workflow step: mark it succeeded and replace the
 * pre-dispatch estimate with the provider's real usage.
 *
 * Rust derives `workflow_token_usage` from SETTLED metering events, so leaving
 * the estimate in the ledger would gate the token budget on a number no
 * provider ever produced. Never allowed to fail a response — the call has
 * already happened and the caller is entitled to it.
 */
function settleWorkflowStep(
  c: InferenceContext,
  deps: ResolvedInferenceDeps,
  gate: WorkflowGateOutcome,
  succeeded: boolean,
  actualTokens: number | undefined,
): void {
  if (gate.kind !== "admitted") return;
  void (async (): Promise<void> => {
    try {
      await deps.workflowHistory.recordStep({
        ...gate.step,
        requestId: c.get("requestId"),
        occurredAtUnix: deps.nowUnixSeconds(),
        totalTokens: actualTokens ?? 0,
        succeeded,
      });
    } catch {
      // Same contract as `recordUsage`.
    }
  })();
}

/** The provider constraint an admitted step carries, if any. */
function workflowConstraintOf(gate: WorkflowGateOutcome): WorkflowProviderConstraint | null {
  return gate.kind === "admitted" ? gate.constraint : null;
}

/**
 * The SERVED route's own prices, in the shape `Usage` carries them (#663).
 *
 * `dispatchCandidates` can fail over, so the route that ANSWERED is not
 * necessarily the route that was planned — and the two can be priced
 * differently. Reading them off `servedRoute` at each meter site is therefore
 * not a convenience: billing the planned route's price for a fallback provider's
 * response would be a confidently wrong number.
 *
 * Absent keys, never `undefined` values, because `Usage` is spread into the
 * billing event and `metering/route-price.ts` distinguishes "unpriced" from
 * "priced at zero".
 */
function routePricing(route: PhysicalRoute): {
  inputPricePer1m?: number;
  outputPricePer1m?: number;
  cachedInputPricePer1m?: number;
  cacheWritePricePer1m?: number;
  reasoningPricePer1m?: number;
} {
  return {
    ...(route.inputPricePer1m !== undefined ? { inputPricePer1m: route.inputPricePer1m } : {}),
    ...(route.outputPricePer1m !== undefined ? { outputPricePer1m: route.outputPricePer1m } : {}),
    // #667 — the cached/reasoning rates travel with the other two, for the same
    // reason: a failover means the route that ANSWERED is not the route that
    // was planned, and the two can be priced differently.
    ...(route.cachedInputPricePer1m !== undefined
      ? { cachedInputPricePer1m: route.cachedInputPricePer1m }
      : {}),
    ...(route.cacheWritePricePer1m !== undefined
      ? { cacheWritePricePer1m: route.cacheWritePricePer1m }
      : {}),
    ...(route.reasoningPricePer1m !== undefined
      ? { reasoningPricePer1m: route.reasoningPricePer1m }
      : {}),
    // #703 — the two audio rates ride along for the same reason as the other
    // five. They are absent on every non-audio route, and `Usage` distinguishes
    // "unpriced" from "priced at zero", so carrying them costs nothing and
    // omitting them would leave the audio surface unsettleable on a failover.
    ...(route.audioSecondPricePer1m !== undefined
      ? { audioSecondPricePer1m: route.audioSecondPricePer1m }
      : {}),
    ...(route.audioCharacterPricePer1m !== undefined
      ? { audioCharacterPricePer1m: route.audioCharacterPricePer1m }
      : {}),
  };
}

/**
 * Publish the ROUTING half of this request's GenAI observation (#669) — what
 * model, on which provider, under which operation.
 *
 * Called the moment `meterBase` exists, which is BEFORE the response is built,
 * because that is the only ordering under which a STREAMED request gets a model
 * on its span at all: {@link recordUsage} does not run for an SSE body until
 * the usage frame arrives, which is after the telemetry emission. See
 * `src/telemetry/genai.ts` for the merge rule that lets the two halves land
 * separately.
 *
 * `providerKind` travels separately from `meterBase` because `Usage` does not
 * carry one — it records the CONFIGURED provider name (`ProviderConfig.name`,
 * an operator's label like `probe` or `openai-eu`), and `gen_ai.provider.name`
 * needs the adapter FAMILY. Publishing the configured name would put a
 * deployment-private string where every backend expects `openai`.
 */
function observeInvocation(
  request: Request,
  base: Omit<Usage, "promptTokens" | "completionTokens" | "totalTokens">,
  providerKind: string,
): void {
  const operationName = genAiOperationForRouteLabel(base.route);
  if (operationName === undefined) return;
  observeGenAiInvocation(request, {
    operationName,
    providerKind,
    requestModel: base.logicalModel,
    responseModel: base.providerModel,
  });
}
/**
 * Record a metering event AND the request log's share of the same facts; never
 * allowed to fail the response.
 *
 * ## Why the request-log contribution belongs exactly here
 *
 * This is the single chokepoint every dispatched request passes through, on
 * every ending it can have: the buffered success path, the upstream-ERROR path
 * (which calls it with no usage — a 502 is still a decision, and an audit trail
 * that omitted provider failures would omit the interesting half), and the SSE
 * tap's `flush()`/`cancel()`. It is also the only place that holds `base`,
 * which already carries the route label, the provider, BOTH model names and
 * the dispatch attempt index — i.e. everything about this request that only
 * this app knows.
 *
 * The alternative — assembling the same facts in the outer middleware — cannot
 * work: `inner.fetch` opens a fresh context, so none of this is visible there.
 * See `./identity.ts::InferenceRequestScope.log`.
 *
 * The two sinks are reported to independently and both are wrapped, because a
 * metering failure must not cost the evidence row and an evidence failure must
 * certainly not cost the charge.
 */
function recordUsage(
  c: InferenceContext,
  deps: ResolvedInferenceDeps,
  base: Omit<
    Usage,
    | "promptTokens"
    | "completionTokens"
    | "totalTokens"
    | "cachedInputTokens"
    | "cacheWriteTokens"
    | "reasoningTokens"
  >,
  providerKind: string,
  usage: ProviderUsage | undefined,
): void {
  // #669 — the TOKEN half of the observation, from the same provider usage
  // frame the charge is built from, so a span and its charge can never disagree
  // about how many tokens were used. Kept OUTSIDE the try/catch below on
  // purpose: that catch exists to stop a failing metering SINK from failing the
  // response, and swallowing a telemetry bug under it would hide it.
  observeInvocation(c.get("inferenceOriginRequest"), base, providerKind);
  if (usage !== undefined) {
    observeGenAiInvocation(c.get("inferenceOriginRequest"), {
      ...(usage.promptTokens === undefined ? {} : { inputTokens: usage.promptTokens }),
      ...(usage.completionTokens === undefined ? {} : { outputTokens: usage.completionTokens }),
    });
  }
  try {
    deps.usage.record({
      ...base,
      ...(usage?.promptTokens !== undefined ? { promptTokens: usage.promptTokens } : {}),
      ...(usage?.completionTokens !== undefined
        ? { completionTokens: usage.completionTokens }
        : {}),
      ...(usage?.totalTokens !== undefined ? { totalTokens: usage.totalTokens } : {}),
      // #667. Absent stays absent all the way to the billing event, where the
      // wire schema defaults it to 0 — so "the provider reported no cached
      // tokens" and "this response predates the counter" settle identically,
      // and neither can be mistaken for an observed zero mid-stream.
      ...(usage?.cachedInputTokens !== undefined
        ? { cachedInputTokens: usage.cachedInputTokens }
        : {}),
      ...(usage?.cacheWriteTokens !== undefined
        ? { cacheWriteTokens: usage.cacheWriteTokens }
        : {}),
      ...(usage?.reasoningTokens !== undefined
        ? { reasoningTokens: usage.reasoningTokens }
        : {}),
    });
  } catch {
    // `InMemoryBillingEventSink` surfaced a poisoned-lock error to the LOG, not
    // to the caller. Same contract here.
  }
  try {
    c.get("inferenceLog")({
      route: base.route,
      provider: base.provider,
      logicalModel: base.logicalModel,
      providerModel: base.providerModel,
      streamed: base.stream,
      providerAttemptIndex: base.providerAttemptIndex,
      promptTokens: usage?.promptTokens,
      completionTokens: usage?.completionTokens,
      totalTokens: usage?.totalTokens,
    });
  } catch {
    // Same contract: evidence is best-effort at the seam, never a 500.
  }
}

/**
 * Headers a streamed response carries in addition to the gateway ones.
 *
 * The relay (#726) matters MORE here than on the buffered paths, not less: a
 * stream's headers are flushed before the first token, so they are the only
 * pacing signal a streaming client will ever get for this request.
 */
function streamingHeaders(
  contentType: string,
  requestId: string,
  upstream?: UpstreamRelay,
): Record<string, string> {
  return {
    "content-type": contentType,
    // The Rust writer emitted a chunked SSE response with no caching; Workers
    // sets transfer-encoding itself, so only the cache directives are explicit.
    "cache-control": "no-cache",
    ...relayedRateLimitHeaders(upstream),
    "x-request-id": requestId,
    "x-trace-id": requestId,
    "x-ferrogate-runtime": "workers",
  };
}

/**
 * Relay a streamed provider response.
 *
 * The upstream `ReadableStream` is piped straight to the client — no buffering,
 * so first-token latency is the provider's. A normalizer (when the ingress and
 * upstream dialects differ) and the usage tap are composed as
 * `TransformStream`s in front of it, which is precisely the CF port strategy
 * called out in `inventory-request-path.md` §1.5.
 */
function streamResponse(
  deps: ResolvedInferenceDeps,
  upstreamResponse: Response,
  dialect: StreamDialect,
  usageDialect: UsageDialect,
  route: PhysicalRoute,
  requestId: string,
  onUsage: (usage: ProviderUsage | undefined) => void,
  upstream?: UpstreamRelay,
): Response {
  const contentType = upstreamResponse.headers.get("content-type") ?? "text/event-stream";
  const body = upstreamResponse.body;
  if (body === null) {
    return new Response(null, {
      status: upstreamResponse.status,
      headers: streamingHeaders(contentType, requestId, upstream),
    });
  }

  const normalizer = deps.normalizers.normalizerFor({
    dialect,
    providerKind: route.providerKind,
    logicalModel: route.logicalModel,
    requestId,
    contentType,
  });
  const normalized = normalizer === null ? body : body.pipeThrough(normalizer);
  // The usage tap sits AFTER the normalizer, so it always reads the dialect the
  // client is actually served — that ordering is the fix for the metering
  // bypass documented at `chat.rs:1012`.
  const tapped = normalized.pipeThrough(sseUsageTap(usageDialect, onUsage));

  // A normalized stream is always `text/event-stream`, whatever the upstream
  // labelled itself (the Rust writer hard-codes it on the normalized branches).
  const outgoingContentType = normalizer === null ? contentType : "text/event-stream";
  return new Response(tapped, {
    status: upstreamResponse.status,
    headers: streamingHeaders(outgoingContentType, requestId, upstream),
  });
}

/** True when the upstream actually returned a stream we should relay as one. */
function isStreamingUpstream(response: Response): boolean {
  const contentType = response.headers.get("content-type") ?? "";
  return response.ok && contentType.toLowerCase().includes("text/event-stream");
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/**
 * Build the inference router.
 *
 * Mounted by the app shell (`apps/gateway/src/index.ts`) with
 * `app.route("/", createInferenceRouter(deps))`; every path below is absolute so
 * the mount point is `/`.
 */
export function createInferenceRouter(deps: InferenceDeps = {}): Hono<InferenceEnv> {
  const depsFor = envScopedDeps(deps);
  const app = new Hono<InferenceEnv>();

  // THE ENVELOPE GUARANTEE (issue #733).
  //
  // This app is not mounted with `app.route()`; `route-module.ts` DELEGATES
  // into it with `inner.fetch(c.req.raw, …)`, which starts a fresh Hono
  // dispatch with its own error handling. Without this line Hono's DEFAULT
  // handler answered — `console.error(err)` plus
  // `new Response('Internal Server Error', { status: 500 })` — so an unhandled
  // throw left here as a `text/plain` 500 with no `code`, no `type` and no
  // `request_id`, and the OUTER app's `gatewayErrorHandler` never saw a throw
  // at all: it had already been turned into an ordinary Response. That is the
  // single status on which a caller most needs to tell "retry me" from "I am
  // broken", and it was the one status whose body was not the envelope.
  //
  // The request id is the INNER one (`fg-<16 hex>`, minted by the middleware
  // below), because that is the id this surface puts in `x-request-id` and
  // therefore the only id a caller can quote. When the throw happened BEFORE
  // that middleware could set it — a port that fails while it is being
  // RESOLVED, which is what a `models` factory does when its config is broken —
  // the inbound header is honoured and a UUID is the last resort, so a 500 is
  // never answered with a null correlation id.
  //
  // This does NOT make `middleware/errors.ts`'s `envelopeBoundary` redundant:
  // Hono only routes an `Error` here (`compose` rethrows anything else), so a
  // thrown literal still leaves this app and is caught one layer out.
  app.onError((error, c) =>
    envelopeForThrown(
      error,
      c.get("requestId") ?? c.req.header("x-request-id") ?? crypto.randomUUID(),
    ),
  );

  // Ports, request identity and caller, once per request (Rust middleware
  // step 1). The ports come first because the body reader below reads the
  // request-size cap off them.
  app.use("*", async (c, next) => {
    const resolved = depsFor(c.env);
    // Read BEFORE `readInferenceBody()` swaps `c.req.raw` for a re-presented
    // Request — the scope is keyed by the object `route-module.ts` published.
    const scope = inferenceRequestScope(c.req.raw);
    c.set("inferenceDeps", resolved);
    c.set("inferenceClientSignal", inboundSignal(c.req.raw));
    // Same "before the body reader swaps it" rule as the signal above — see
    // the field's doc on `InferenceEnv`.
    c.set("inferenceOriginRequest", c.req.raw);
    c.set("requestId", c.req.header("x-request-id") ?? resolved.requestIds.next());
    // The AUTHENTICATED caller when the module is mounted on the gateway app;
    // the injected resolver otherwise (an inner-app unit test, or a deployment
    // where the guard has not run). Never both — an authenticated request must
    // not be re-described by a default that grants platform-operator scope.
    const caller = scope?.caller ?? resolved.caller(c.req.raw);
    c.set("inferenceCaller", caller);
    c.set("inferenceTokens", scope?.tokens ?? unmeteredTokenGovernor);
    c.set("inferenceLog", scope?.log ?? noInferenceLog);
    c.set("inferenceAttributionDefaults", scope?.attributionDefaults ?? NO_ATTRIBUTION_DEFAULTS);

    // Per-tenant BYOK (issue #682) — substitute the CALLING TENANT's own
    // provider credential for the platform one before anything is planned.
    //
    // Here, and not in `planUpstream`, for two structural reasons: the
    // credential must be in place before `adapter.buildUpstreamRequest` bakes it
    // into the `Authorization` header, and `planUpstream` is synchronous while
    // the lookup is a D1 read. Doing it once in the shared middleware also means
    // every dispatching surface is covered by construction — a new one cannot
    // forget it, which is the same argument `dispatchCandidates` makes for
    // firing the shadow mirror from one place.
    //
    // Returning the rejection here rather than degrading to the platform
    // credential is the fail-closed half: a tenant that asked to be billed on
    // its own agreement must never be silently served on FerroGate's key.
    const models = await byokScopedModels(resolved.models, resolved.byok, caller, c.req.raw);
    if (isRejection(models)) {
      return errorResponse(models, c.get("requestId"));
    }
    if (models !== resolved.models) {
      c.set("inferenceDeps", { ...resolved, models });
    }

    await next();
    return;
  });

  const body = readInferenceBody();
  // Prompt-by-reference (#694). Between the body read and Zod, because the
  // expansion is what PRODUCES the `model` and `messages` Zod is about to
  // require — after validation it would always be too late. Mounted only on the
  // two OpenAI-dialect operations: `prompt_templates.target` is
  // `chat_completions | responses`, so those are the two bodies a rendered
  // template is shaped for. Anthropic `/v1/messages`, embeddings and images
  // pass it through untouched and refuse the unknown member on their own
  // schema, which is the honest answer for a body the renderer cannot produce.
  const promptReference = expandPromptReference();

  // -- GET /v1/models --------------------------------------------------------
  app.get("/v1/models", (c) => handleModels(c, c.get("inferenceDeps")));

  // -- GET /v1/models/{model} ------------------------------------------------
  // Registered AFTER the collection route; Hono matches in registration order
  // for equal specificity, and these two cannot collide anyway (different
  // segment counts). The path is the contract's `honoPath` — `route-module.ts`
  // asserts that at construction, so a contract move cannot leave this a 404.
  app.get("/v1/models/:model", (c) => handleModel(c, c.get("inferenceDeps")));

  // -- POST /v1/chat/completions --------------------------------------------
  app.post(
    "/v1/chat/completions",
    body,
    promptReference,
    validateBody(chatCompletionRequestSchema, "invalid chat completion request"),
    (c) => handleOpenAiInference(c, c.get("inferenceDeps"), "chat.completions"),
  );

  // -- POST /v1/responses ----------------------------------------------------
  app.post(
    "/v1/responses",
    body,
    promptReference,
    validateBody(responsesRequestSchema, "invalid responses request"),
    (c) => handleOpenAiInference(c, c.get("inferenceDeps"), "responses"),
  );

  // -- POST /v1/messages -----------------------------------------------------
  app.post(
    "/v1/messages",
    body,
    validateBody(anthropicMessagesRequestSchema, "invalid Anthropic messages request"),
    (c) => handleMessages(c, c.get("inferenceDeps")),
  );

  // -- POST /v1/messages/count_tokens ---------------------------------------
  // Registered AFTER `/v1/messages`; Hono matches both statically, so neither
  // shadows the other and the order is documentary only (it keeps the two
  // Anthropic-native surfaces adjacent).
  app.post(
    "/v1/messages/count_tokens",
    body,
    validateBody(anthropicCountTokensRequestSchema, "invalid Anthropic count_tokens request"),
    (c) => handleCountMessageTokens(c, c.get("inferenceDeps")),
  );

  // -- POST /v1/embeddings ---------------------------------------------------
  app.post(
    "/v1/embeddings",
    body,
    validateBody(embeddingsRequestSchema, "invalid embeddings request"),
    (c) => handleEmbeddings(c, c.get("inferenceDeps")),
  );

  // -- POST /v1/rerank -------------------------------------------------------
  app.post(
    "/v1/rerank",
    body,
    validateBody(rerankRequestSchema, "invalid rerank request"),
    (c) => handleRerank(c, c.get("inferenceDeps")),
  );

  // -- POST /v1/audio/transcriptions ----------------------------------------
  //
  // `audioUpload` REPLACES `body` + `validateBody` rather than wrapping them:
  // this ingress is multipart, so the JSON reader would answer `invalid_json`
  // on a perfectly valid upload. The reader does its own Zod pass on the
  // normalized object, which is why no `validateBody` follows it.
  const audioUpload = readAudioUpload();
  app.post("/v1/audio/transcriptions", audioUpload, (c) =>
    handleAudioUpload(c, c.get("inferenceDeps"), "audio.transcriptions"),
  );

  // -- POST /v1/audio/translations ------------------------------------------
  app.post("/v1/audio/translations", audioUpload, (c) =>
    handleAudioUpload(c, c.get("inferenceDeps"), "audio.translations"),
  );

  // -- POST /v1/audio/speech -------------------------------------------------
  // JSON in, BYTES out. The request half is an ordinary body read.
  app.post(
    "/v1/audio/speech",
    body,
    validateBody(speechRequestSchema, "invalid speech request"),
    (c) => handleSpeech(c, c.get("inferenceDeps")),
  );

  // -- POST /v1/images/generations ------------------------------------------
  app.post(
    "/v1/images/generations",
    body,
    validateBody(imagesRequestSchema, "invalid image generation request"),
    (c) => handleImages(c, c.get("inferenceDeps")),
  );

  return app;
}

/**
 * Resolve the injected ports against a Worker `env`, memoized per env object.
 *
 * Only a `models` dependency given as a {@link ModelResolverFactory} actually
 * depends on `env`; everything else is env-free, so this is a cache lookup on
 * the hot path rather than a per-request rebuild. Memoizing matters: the model
 * registry is long-lived state (`route-module.ts` explains why the inner app is
 * built once), and rebuilding it per request would throw away the isolate's
 * warm catalog. `env` is immutable for the life of a Worker version, so an
 * entry can never go stale.
 */
function envScopedDeps(deps: InferenceDeps): (env: unknown) => ResolvedInferenceDeps {
  const byEnv = new WeakMap<object, ResolvedInferenceDeps>();
  let envless: ResolvedInferenceDeps | undefined;
  return (env: unknown): ResolvedInferenceDeps => {
    // `app.request(path, init)` in a unit test passes no bindings at all.
    if (typeof env !== "object" || env === null) {
      envless ??= resolveDeps(deps);
      return envless;
    }
    const cached = byEnv.get(env);
    if (cached !== undefined) {
      return cached;
    }
    const built = resolveDeps(deps, env as InferenceBindings);
    byEnv.set(env, built);
    return built;
  };
}

// ---------------------------------------------------------------------------
// GET /v1/models — `local.rs::handle_models`
// GET /v1/models/{model} — `getModel` (issue #670)
// ---------------------------------------------------------------------------

/**
 * The catalog rows THIS caller may discover — one row per logical model.
 *
 * Three filters, and each one is a gate that already exists on the invocation
 * path. Discovery that disagrees with invocation is an ORACLE, which is the
 * lesson of issue #515: the listing leaked other tenants' private logical names
 * and their provider mapping while invocation was blocked downstream, so a
 * tenant could enumerate what it could not call.
 *
 *  1. `enabled` — Rust's `ModelRegistryEntry.enabled`.
 *  2. `scopeCanSeeModel` — the tenant/project visibility filter (issue #515),
 *     matching `planUpstream`'s own check.
 *  3. `callerCanUseModel` — the credential's `allowed_models` / denylist, i.e.
 *     `AuthContext::can_use_model`, the predicate behind the 403
 *     `model_not_allowed` on invocation. It was MISSING here (issue #670): a key
 *     scoped to one model still listed the whole catalog, so the allowlist was
 *     enforced on the call and not on the discovery of what to call.
 */
function discoverableModels(
  deps: ResolvedInferenceDeps,
  caller: Caller,
): readonly PhysicalRoute[] {
  return deps.models
    .catalog()
    .filter((route) => route.enabled)
    .filter((route) => scopeCanSeeModel(caller.scope, caller.projectId, route))
    .filter((route) => callerCanUseModel(caller, route.logicalModel));
}

/** `describeModel` over the model's full candidate ladder — see `model-metadata.ts`. */
function describeCatalogEntry(
  deps: ResolvedInferenceDeps,
  entry: PhysicalRoute,
): ModelDescriptor {
  return describeModel(entry, resolveCandidates(deps.models, entry.logicalModel));
}

function handleModels(c: InferenceContext, deps: ResolvedInferenceDeps): Response {
  const requestId = c.get("requestId");
  const caller = c.get("inferenceCaller");

  const data = discoverableModels(deps, caller).map((entry) =>
    describeCatalogEntry(deps, entry),
  );

  const listing: OpenAiModelList = { object: "list", data };
  return jsonResponse(listing, requestId);
}

/**
 * `GET /v1/models/{model}` — the single-model read.
 *
 * ## Why 404, when invocation answers 400 `model_not_found`
 *
 * They are different questions. On `POST /v1/chat/completions` the ROUTE exists
 * and the caller's BODY names something unusable, which is a bad request — that
 * is Rust's 400 and it is unchanged. Here the model name is the resource
 * identity in the URL, and a resource that is not there is 404; every
 * OpenAI-compatible client already expects 404 from `GET /v1/models/{id}`.
 *
 * ## Why every refusal is the SAME 404
 *
 * Unknown, disabled, another tenant's, and outside this key's `allowed_models`
 * all answer `404 model_not_found` with one message. Distinguishing them would
 * turn this operation into an existence oracle for exactly the names the
 * filters above exist to hide — "403 not allowed" on a model tells you the model
 * is real, which is the leak issue #515 closed on the listing. The invocation
 * path keeps its finer taxonomy (`model_disabled` vs `model_not_found`, and the
 * 403 `model_not_allowed`) because a caller there already knows the name.
 */
function handleModel(c: InferenceContext, deps: ResolvedInferenceDeps): Response {
  const requestId = c.get("requestId");
  const caller = c.get("inferenceCaller");
  const requested = c.req.param("model");

  const entry = discoverableModels(deps, caller).find(
    (route) => route.logicalModel === requested,
  );
  if (entry === undefined) {
    return errorResponse(
      reject(404, "model_not_found", `unknown model ${requested}`),
      requestId,
    );
  }
  return jsonResponse(describeCatalogEntry(deps, entry), requestId);
}

// ---------------------------------------------------------------------------
// POST /v1/chat/completions and POST /v1/responses — `chat.rs::handle_ai_request`
// ---------------------------------------------------------------------------

async function handleOpenAiInference(
  c: InferenceContext,
  deps: ResolvedInferenceDeps,
  operation: "chat.completions" | "responses",
): Promise<Response> {
  const requestId = c.get("requestId");
  const caller = c.get("inferenceCaller");
  const request = c.get("inferenceBody") as Record<string, unknown>;
  const logicalModel = String(request["model"]);
  const stream = request["stream"] === true;
  const metadata = attributedMetadata(c, request);

  // Rust `estimate_chat_completion_usage` — `/v1/responses` shares it, because
  // both surfaces go through `build_chat_completion_request_plan`.
  const estimated = estimateChatCompletionUsage(request, logicalModel);

  const gate = await admitWorkflowStep(c, deps, caller, logicalModel, estimated);
  if (isRejection(gate)) {
    return errorResponse(gate, requestId);
  }

  const planned = planUpstream(
    deps,
    caller,
    operation,
    logicalModel,
    metadata,
    stream,
    request,
    estimated,
    workflowConstraintOf(gate),
  );
  if (isRejection(planned)) {
    return errorResponse(planned, requestId);
  }

  const admitted = await admitTokens(c, estimated);
  if (isRejection(admitted)) {
    return errorResponse(admitted, requestId);
  }
  const admission = admissionHandle(admitted);

  const dispatched = await dispatchCandidates(c, deps, planned);
  if (isRejection(dispatched)) {
    return errorResponse(dispatched, requestId);
  }
  const { route: servedRoute, response: upstreamResponse, attemptIndex, failedOver } = dispatched;
  // #726 — the pacing headers of the response that ACTUALLY answered, plus
  // whether the ladder moved the caller to get it. Built once here so every
  // exit below (relayed body, translated body, stream) carries the same
  // decision instead of five call sites re-deriving it.
  const relay: UpstreamRelay = { headers: upstreamResponse.headers, failedOver };

  const routeLabel = ROUTE_LABELS[operation];
  const usageDialect = usageProviderKindFor(operation, servedRoute.providerKind);
  const meterBase = {
    requestId,
    route: routeLabel,
    logicalModel,
    provider: servedRoute.provider,
    providerModel: servedRoute.providerModel,
    stream,
    status: upstreamResponse.status,
    ...(metadata !== undefined ? { metadata } : {}),
    ...(servedRoute.tenantId !== undefined ? { tenantId: servedRoute.tenantId } : {}),
    providerAttemptIndex: attemptIndex,
    ...routePricing(servedRoute),
  } satisfies Omit<Usage, "promptTokens" | "completionTokens" | "totalTokens">;
  // #669 — publish the routing half NOW, before the streaming branch returns a
  // response whose usage frame has not arrived yet. `recordUsage` publishes it
  // again (harmlessly — the merge is idempotent) for the buffered paths.
  observeInvocation(c.get("inferenceOriginRequest"), meterBase, servedRoute.providerKind);

  if (stream && isStreamingUpstream(upstreamResponse)) {
    const dialect: StreamDialect =
      operation === "responses" ? "openai.responses" : "openai.chat";
    return streamResponse(
      deps,
      upstreamResponse,
      dialect,
      usageDialect,
      servedRoute,
      requestId,
      (usage) => {
        recordUsage(c, deps, meterBase, servedRoute.providerKind, usage);
        settleTokensDetached(c, admission, usage?.totalTokens);
        settleWorkflowStep(c, deps, gate, true, usage?.totalTokens);
      },
      relay,
    );
  }

  const text = await readUpstreamBody(deps, upstreamResponse);
  if (isRejection(text)) {
    return errorResponse(text, requestId);
  }
  if (!upstreamResponse.ok) {
    recordUsage(c, deps, meterBase, servedRoute.providerKind, undefined);
    // An upstream ERROR settles the step as un-succeeded: it still counted
    // against `max_model_calls` (it was admitted), but it must not advance the
    // graph's edge gate.
    settleWorkflowStep(c, deps, gate, false, undefined);
    return rawUpstreamResponse(
      upstreamResponse.status,
      upstreamResponse.headers.get("content-type") ?? "application/json",
      text,
      requestId,
      relay,
    );
  }

  const parsed = safeJson(text);
  const usage = usageFromResponseBody(usageDialect, parsed);
  recordUsage(c, deps, meterBase, servedRoute.providerKind, usage);
  await settleTokens(c, admission, usage?.totalTokens);
  settleWorkflowStep(c, deps, gate, true, usage?.totalTokens);
  return rawUpstreamResponse(
    upstreamResponse.status,
    upstreamResponse.headers.get("content-type") ?? "application/json",
    text,
    requestId,
    relay,
  );
}

// ---------------------------------------------------------------------------
// POST /v1/messages — `messages.rs::handle_messages`
// ---------------------------------------------------------------------------

/**
 * The Anthropic-native ingress. It reuses the chat-completions plan/dispatch
 * path by translating the body in, and translates the provider's response back
 * out — so `/v1/messages` inherits every adapter family and the SAME governed
 * chokepoint, which is exactly why the Rust tree did it this way (issue #272).
 */
async function handleMessages(
  c: InferenceContext,
  deps: ResolvedInferenceDeps,
): Promise<Response> {
  const requestId = c.get("requestId");
  const caller = c.get("inferenceCaller");
  const request = c.get("inferenceBody") as Record<string, unknown>;
  const logicalModel = String(request["model"]);
  const stream = request["stream"] === true;

  const translated = deps.translator.toChatCompletions(request);
  if (!translated.ok) {
    return errorResponse(
      reject(
        400,
        "invalid_request",
        `could not translate Anthropic messages request: ${adapterErrorMessage(translated.error)}`,
      ),
      requestId,
    );
  }

  // Rust `estimate_messages_usage` reads the TRANSLATED body, not the Anthropic
  // one the client sent: `to_chat_completions` has already folded the top-level
  // `system` prompt into `messages[0]`, so estimating the original would drop
  // the system prompt out of the reservation entirely.
  const estimated = estimateMessagesUsage(translated.body, logicalModel);

  const gate = await admitWorkflowStep(c, deps, caller, logicalModel, estimated);
  if (isRejection(gate)) {
    return errorResponse(gate, requestId);
  }

  const planned = planUpstream(
    deps,
    caller,
    "chat.completions",
    logicalModel,
    undefined,
    stream,
    translated.body,
    estimated,
    workflowConstraintOf(gate),
  );
  if (isRejection(planned)) {
    return errorResponse(planned, requestId);
  }

  const admitted = await admitTokens(c, estimated);
  if (isRejection(admitted)) {
    return errorResponse(admitted, requestId);
  }
  const admission = admissionHandle(admitted);

  const dispatched = await dispatchCandidates(c, deps, planned);
  if (isRejection(dispatched)) {
    return errorResponse(dispatched, requestId);
  }
  const { route: servedRoute, response: upstreamResponse, attemptIndex, failedOver } = dispatched;
  // #726 — the pacing headers of the response that ACTUALLY answered, plus
  // whether the ladder moved the caller to get it. Built once here so every
  // exit below (relayed body, translated body, stream) carries the same
  // decision instead of five call sites re-deriving it.
  const relay: UpstreamRelay = { headers: upstreamResponse.headers, failedOver };

  const usageDialect = usageProviderKindFor("messages", servedRoute.providerKind);
  const meterBase = {
    requestId,
    route: ROUTE_LABELS.messages,
    logicalModel,
    provider: servedRoute.provider,
    providerModel: servedRoute.providerModel,
    stream,
    status: upstreamResponse.status,
    ...(servedRoute.tenantId !== undefined ? { tenantId: servedRoute.tenantId } : {}),
    providerAttemptIndex: attemptIndex,
    ...routePricing(servedRoute),
  } satisfies Omit<Usage, "promptTokens" | "completionTokens" | "totalTokens">;
  // #669 — see the same call in `handleChatCompletionsLike`: the streaming
  // branch below returns before any usage frame exists.
  observeInvocation(c.get("inferenceOriginRequest"), meterBase, servedRoute.providerKind);

  if (stream && isStreamingUpstream(upstreamResponse)) {
    // A non-Anthropic upstream is run through `MessagesStreamNormalizer`
    // (`openAiToAnthropicStream`): OpenAI chat SSE → Anthropic `message_start` /
    // `content_block_start|delta|stop` / `message_delta` / `message_stop`, with
    // tool-call accumulation. An Anthropic upstream passes through untouched.
    // Either way the CLIENT is served Anthropic frames, so the usage tap — which
    // runs after the normalizer — always uses the Anthropic extractor.
    return streamResponse(
      deps,
      upstreamResponse,
      "anthropic.messages",
      usageDialect,
      servedRoute,
      requestId,
      (usage) => {
        recordUsage(c, deps, meterBase, servedRoute.providerKind, usage);
        settleTokensDetached(c, admission, usage?.totalTokens);
        settleWorkflowStep(c, deps, gate, true, usage?.totalTokens);
      },
      relay,
    );
  }

  const text = await readUpstreamBody(deps, upstreamResponse);
  if (isRejection(text)) {
    return errorResponse(text, requestId);
  }
  if (!upstreamResponse.ok) {
    recordUsage(c, deps, meterBase, servedRoute.providerKind, undefined);
    // An upstream ERROR settles the step as un-succeeded: it still counted
    // against `max_model_calls` (it was admitted), but it must not advance the
    // graph's edge gate.
    settleWorkflowStep(c, deps, gate, false, undefined);
    return rawUpstreamResponse(
      upstreamResponse.status,
      upstreamResponse.headers.get("content-type") ?? "application/json",
      text,
      requestId,
      relay,
    );
  }

  const parsed = safeJson(text);
  const usage = usageFromResponseBody(usageDialect, parsed);
  recordUsage(c, deps, meterBase, servedRoute.providerKind, usage);
  await settleTokens(c, admission, usage?.totalTokens);
  settleWorkflowStep(c, deps, gate, true, usage?.totalTokens);
  // An Anthropic upstream answered natively → passed through unchanged; an
  // OpenAI-family upstream is reshaped so a Claude client sees a native Message
  // either way.
  const message = deps.translator.chatCompletionToMessage(parsed, logicalModel);
  return jsonResponse(message, requestId, upstreamResponse.status, relay);
}

// ---------------------------------------------------------------------------
// POST /v1/messages/count_tokens — `countMessageTokens` (issue #671)
// ---------------------------------------------------------------------------

/**
 * The Anthropic-native token-count pre-flight.
 *
 * A client cannot size a context window or pre-estimate spend without sending
 * the request and paying for it. This answers the same question the gateway
 * already asks itself before every `/v1/messages` dispatch, and answers it with
 * the SAME arithmetic (`countMessagesInputTokens` is a projection of
 * `estimateMessagesUsage`, see `./estimate.ts`) so the number a caller budgets
 * against is the number that will be reserved against their TPM window, their
 * monthly token budget and their prepaid wallet.
 *
 * ## Which parts of the `/v1/messages` ladder this runs, and which it does not
 *
 * Kept, because they decide what the ANSWER even means or who may ask:
 *
 *  - auth + scope. Registered as a contract operation (`countMessageTokens`,
 *    bearer, `messages.create`), so the ONE table-driven guard in
 *    `middleware/auth.ts` covers it and the request-rate/quota middleware the
 *    app mounts for every operation covers it too. A free, unauthenticated
 *    counting oracle is an abuse surface with no owner, so this is not
 *    negotiable and it is asserted directly by `test/inference/count-tokens.test.ts`.
 *  - the MODEL gate — `can_use_model` (403), then resolution (400
 *    `model_not_found` / `model_disabled`), then the tenant visibility check
 *    (400 `model_not_found`). Without it the endpoint becomes exactly the
 *    enumeration oracle issue #515 closed: a probe that reveals which logical
 *    model names exist and which tenants own the private ones.
 *
 * Deliberately NOT run, each for a stated reason:
 *
 *  - **the rest of `planUpstream`** — eligibility, canary/shadow, strategy
 *    ordering, adapter preparation. Beyond being pure waste for a request that
 *    dispatches nothing, the context-window leg of the eligibility gate would
 *    REFUSE a body larger than the model's window — i.e. refuse to tell the
 *    caller the number precisely when they most need it, which inverts the
 *    endpoint's purpose. It also builds an upstream request carrying provider
 *    credentials, which no counting request should ever materialize.
 *  - **the TPM admission** (`admitTokens`). The window meters tokens spent at a
 *    provider and this request spends none; charging it would bill a caller for
 *    asking what something would cost. The per-request rate limit above still
 *    bounds the surface.
 *  - **the workflow graph gate + metering.** Both record a MODEL CALL, and
 *    counting is not one. A step written here would consume `max_model_calls`
 *    and put a row in the ledger for a call that never happened.
 *  - **guardrail screening.** See `guardrails/middleware.ts`: the prompt is
 *    never inferred over, so a denial would block a size estimate on grounds
 *    that apply to dispatch, and an evidence row would record a screening of
 *    content that never reached a provider.
 *  - **the operator drain gate.** Draining refuses new AI requests so a node
 *    can be retired; a count consumes no capacity and produces no spend, so
 *    refusing it would turn a decided "stop spending" into "stop answering".
 */
function handleCountMessageTokens(
  c: InferenceContext,
  deps: ResolvedInferenceDeps,
): Response {
  const requestId = c.get("requestId");
  const caller = c.get("inferenceCaller");
  const request = c.get("inferenceBody") as Record<string, unknown>;
  const logicalModel = String(request["model"]);

  const gate = countTokensModelGate(deps, caller, logicalModel);
  if (gate !== null) {
    return errorResponse(gate, requestId);
  }

  // Translate first, exactly as `handleMessages` does: `to_chat_completions`
  // folds Anthropic's top-level `system` prompt into `messages[0]`, and the
  // estimator reads `messages`. Counting the untranslated body would silently
  // report a smaller number than the one that is later reserved, for every
  // request that carries a system prompt.
  const translated = deps.translator.toChatCompletions(request);
  if (!translated.ok) {
    return errorResponse(
      reject(
        400,
        "invalid_request",
        `could not translate Anthropic messages request: ${adapterErrorMessage(translated.error)}`,
      ),
      requestId,
    );
  }

  const count: AnthropicTokenCount = {
    input_tokens: countMessagesInputTokens(translated.body, logicalModel),
  };
  return jsonResponse(count, requestId);
}

/**
 * The model half of `planUpstream`, and only that half.
 *
 * Extracted rather than inlined so the three refusals stay recognisably the
 * same three refusals `/v1/messages` produces — same order, same codes, same
 * messages. Returns `null` when the caller may count against this model.
 */
function countTokensModelGate(
  deps: ResolvedInferenceDeps,
  caller: Caller,
  logicalModel: string,
): InferenceRejection | null {
  // BEFORE resolution, so a denied key cannot probe which model names exist.
  if (!callerCanUseModel(caller, logicalModel)) {
    return reject(
      403,
      "model_not_allowed",
      `API key is not allowed to use model ${logicalModel}`,
    );
  }

  const resolved = resolveCandidates(deps.models, logicalModel);
  if (resolved.length === 0) {
    const known = deps.models
      .catalog()
      .find((candidate) => candidate.logicalModel === logicalModel);
    return known === undefined
      ? reject(400, "model_not_found", `unknown model ${logicalModel}`)
      : reject(400, "model_disabled", `model ${logicalModel} is disabled`);
  }

  // Tenancy lives on the registry ENTRY, so every candidate carries the same
  // answer and checking the primary checks all of them (issue #515).
  if (!scopeCanSeeModel(caller.scope, caller.projectId, resolved[0] as PhysicalRoute)) {
    return reject(400, "model_not_found", `unknown model ${logicalModel}`);
  }

  return null;
}

// ---------------------------------------------------------------------------
// POST /v1/embeddings — `embeddings.rs::handle_embeddings`
// ---------------------------------------------------------------------------

async function handleEmbeddings(
  c: InferenceContext,
  deps: ResolvedInferenceDeps,
): Promise<Response> {
  const requestId = c.get("requestId");
  const caller = c.get("inferenceCaller");
  const request = c.get("inferenceBody") as Record<string, unknown>;
  const logicalModel = String(request["model"]);
  const metadata = attributedMetadata(c, request);

  // Rust `estimate_embeddings_usage` — the arm that scores a PRE-TOKENIZED
  // `input` (a flat array of token ids) at one token each is the one that
  // matters: a character-only count reads those as 0 and lets a caller drive
  // unlimited embedding tokens straight past this gate (issue #207).
  const estimated = estimateEmbeddingsUsage(request, logicalModel);

  const gate = await admitWorkflowStep(c, deps, caller, logicalModel, estimated);
  if (isRejection(gate)) {
    return errorResponse(gate, requestId);
  }

  const planned = planUpstream(
    deps,
    caller,
    "embeddings",
    logicalModel,
    metadata,
    false,
    request,
    estimated,
    workflowConstraintOf(gate),
  );
  if (isRejection(planned)) {
    return errorResponse(planned, requestId);
  }

  const admitted = await admitTokens(c, estimated);
  if (isRejection(admitted)) {
    return errorResponse(admitted, requestId);
  }
  const admission = admissionHandle(admitted);

  const dispatched = await dispatchCandidates(c, deps, planned);
  if (isRejection(dispatched)) {
    return errorResponse(dispatched, requestId);
  }
  const { route: servedRoute, response: upstreamResponse, attemptIndex, failedOver } = dispatched;
  // #726 — the pacing headers of the response that ACTUALLY answered, plus
  // whether the ladder moved the caller to get it. Built once here so every
  // exit below (relayed body, translated body, stream) carries the same
  // decision instead of five call sites re-deriving it.
  const relay: UpstreamRelay = { headers: upstreamResponse.headers, failedOver };

  const text = await readUpstreamBody(deps, upstreamResponse);
  if (isRejection(text)) {
    return errorResponse(text, requestId);
  }
  const meterBase = {
    requestId,
    route: ROUTE_LABELS.embeddings,
    logicalModel,
    provider: servedRoute.provider,
    providerModel: servedRoute.providerModel,
    stream: false,
    status: upstreamResponse.status,
    ...(metadata !== undefined ? { metadata } : {}),
    ...(servedRoute.tenantId !== undefined ? { tenantId: servedRoute.tenantId } : {}),
    providerAttemptIndex: attemptIndex,
    ...routePricing(servedRoute),
  } satisfies Omit<Usage, "promptTokens" | "completionTokens" | "totalTokens">;

  if (!upstreamResponse.ok) {
    recordUsage(c, deps, meterBase, servedRoute.providerKind, undefined);
    // An upstream ERROR settles the step as un-succeeded: it still counted
    // against `max_model_calls` (it was admitted), but it must not advance the
    // graph's edge gate.
    settleWorkflowStep(c, deps, gate, false, undefined);
    return rawUpstreamResponse(
      upstreamResponse.status,
      upstreamResponse.headers.get("content-type") ?? "application/json",
      text,
      requestId,
      relay,
    );
  }

  const parsed = safeJson(text);
  const usage = usageFromResponseBody("openai", parsed);
  recordUsage(c, deps, meterBase, servedRoute.providerKind, usage);
  await settleTokens(c, admission, usage?.totalTokens);
  settleWorkflowStep(c, deps, gate, true, usage?.totalTokens);

  // `translate_embeddings_response`: `undefined` means "pass the upstream body
  // through byte-for-byte" — correct for the OpenAI-compatible family, whose
  // `/embeddings` response already IS the canonical shape (issue #274).
  const adapter = deps.adapters.adapterFor(servedRoute.providerKind);
  const translated = adapter?.translateEmbeddingsResponse?.(parsed, logicalModel);
  if (translated !== undefined) {
    return jsonResponse(translated, requestId, upstreamResponse.status, relay);
  }
  return rawUpstreamResponse(
    upstreamResponse.status,
    upstreamResponse.headers.get("content-type") ?? "application/json",
    text,
    requestId,
    relay,
  );
}

// ---------------------------------------------------------------------------
// POST /v1/rerank — `createRerank` (issue #676; no Rust ancestor)
// ---------------------------------------------------------------------------

/**
 * Reranking, served through the same seven-step pipeline as every other `/v1`
 * operation.
 *
 * ## Why this is a copy of `handleEmbeddings` and not a new shape
 *
 * That similarity is the point. The issue's complaint is a GOVERNANCE hole —
 * teams wire a second vendor for reranking and that spend leaves the gateway's
 * view — so the fix is worth nothing unless reranking passes through the same
 * gates as everything else. Every line below is one of those gates: the workflow
 * admission, the model/tenancy/eligibility ladder in `planUpstream`, the TPM
 * reservation, the failover ladder, and `recordUsage`. A bespoke path would have
 * closed the hole on paper and left the controls off.
 *
 * ## The scope is `embeddings.create`, not a seventh scope
 *
 * The house precedent is `countMessageTokens` reusing `messages.create` and
 * `getModel` reusing `models.read`: a new operation inside an existing family
 * takes that family's scope. Reranking is the second half of the retrieval
 * pipeline whose first half is embedding, so every key already provisioned for
 * RAG can reach it. A seventh scope would have forced a re-mint of every such
 * key — including the console's membership-tier virtual keys and the
 * development key — to buy a distinction nobody asked for. It stays a
 * REVERSIBLE decision: adding `rerank.create` later is a contract edit plus one
 * entry in `keys/scopes.ts`, and it fails closed for old keys, which is the safe
 * direction.
 *
 * ## Metering when the provider reports no tokens
 *
 * Workers AI's rerankers report no usage at all. The usage row is still written
 * — route, provider, physical model, tenant, status, attempt index and the
 * route's price book — so the call is IN VIEW, which is what the issue is about;
 * only the token counters are absent. They are left absent rather than
 * back-filled from the estimate, for the reason `handleImages` states one
 * function down: a number the provider did not report must not be recorded as if
 * it had been. The consequence is deliberate and it is the fail-closed one — the
 * TPM reservation is never settled DOWN (`settleTokens` is a no-op on
 * `undefined`), so the caller is charged the estimate for the minute rather than
 * zero.
 */
async function handleRerank(
  c: InferenceContext,
  deps: ResolvedInferenceDeps,
): Promise<Response> {
  const requestId = c.get("requestId");
  const caller = c.get("inferenceCaller");
  const request = c.get("inferenceBody") as Record<string, unknown>;
  const logicalModel = String(request["model"]);
  const metadata = request["metadata"] as RequestMetadata | undefined;

  const estimated = estimateRerankUsage(request);

  const gate = await admitWorkflowStep(c, deps, caller, logicalModel, estimated);
  if (isRejection(gate)) {
    return errorResponse(gate, requestId);
  }

  const planned = planUpstream(
    deps,
    caller,
    "rerank",
    logicalModel,
    metadata,
    false,
    request,
    estimated,
    workflowConstraintOf(gate),
  );
  if (isRejection(planned)) {
    return errorResponse(planned, requestId);
  }

  const admitted = await admitTokens(c, estimated);
  if (isRejection(admitted)) {
    return errorResponse(admitted, requestId);
  }
  const admission = admissionHandle(admitted);

  const dispatched = await dispatchCandidates(c, deps, planned);
  if (isRejection(dispatched)) {
    return errorResponse(dispatched, requestId);
  }
  const { route: servedRoute, response: upstreamResponse, attemptIndex, failedOver } = dispatched;
  // #726 — the pacing headers of the response that ACTUALLY answered, plus
  // whether the ladder moved the caller to get it. Built once here so every
  // exit below (relayed body, translated body, stream) carries the same
  // decision instead of five call sites re-deriving it.
  const relay: UpstreamRelay = { headers: upstreamResponse.headers, failedOver };

  const text = await readUpstreamBody(deps, upstreamResponse);
  if (isRejection(text)) {
    return errorResponse(text, requestId);
  }
  const meterBase = {
    requestId,
    route: ROUTE_LABELS.rerank,
    logicalModel,
    provider: servedRoute.provider,
    providerModel: servedRoute.providerModel,
    stream: false,
    status: upstreamResponse.status,
    ...(metadata !== undefined ? { metadata } : {}),
    ...(servedRoute.tenantId !== undefined ? { tenantId: servedRoute.tenantId } : {}),
    providerAttemptIndex: attemptIndex,
    ...routePricing(servedRoute),
  } satisfies Omit<Usage, "promptTokens" | "completionTokens" | "totalTokens">;

  if (!upstreamResponse.ok) {
    recordUsage(c, deps, meterBase, servedRoute.providerKind, undefined);
    settleWorkflowStep(c, deps, gate, false, undefined);
    return rawUpstreamResponse(
      upstreamResponse.status,
      upstreamResponse.headers.get("content-type") ?? "application/json",
      text,
      requestId,
      relay,
    );
  }

  const parsed = safeJson(text);
  // Scraped rather than assumed absent. Workers AI's rerankers report nothing,
  // so this reads `undefined` today — but a rerank leg on a family that DOES
  // report has to be metered on what it reported, and the `openai` dialect is
  // the right reader for it: every vendor that ships rerank (Cohere, Jina,
  // Voyage) reports OpenAI-NAMED counters, which is the same reason
  // `handleEmbeddings` pins this argument to `"openai"` rather than deriving it.
  const usage = usageFromResponseBody("openai", parsed);
  recordUsage(c, deps, meterBase, servedRoute.providerKind, usage);
  await settleTokens(c, admission, usage?.totalTokens);
  settleWorkflowStep(c, deps, gate, true, usage?.totalTokens ?? estimated.totalTokens);

  const adapter = deps.adapters.adapterFor(servedRoute.providerKind);
  const translated = adapter?.translateRerankResponse?.(parsed, logicalModel, request);
  if (translated !== undefined) {
    return jsonResponse(translated, requestId, upstreamResponse.status, relay);
  }
  // No translation leg: pass the upstream body through byte-for-byte, the same
  // `Ok(None)` arm `/v1/embeddings` takes for the OpenAI-compatible family.
  // Reachable only for a family whose `prepareRerank` succeeded, so it is the
  // right answer for a future vendor that already speaks the canonical shape.
  return rawUpstreamResponse(
    upstreamResponse.status,
    upstreamResponse.headers.get("content-type") ?? "application/json",
    text,
    requestId,
    relay,
  );
}

// ---------------------------------------------------------------------------
// The audio surface (issue #703; no Rust ancestor)
// ---------------------------------------------------------------------------

/**
 * `POST /v1/audio/{transcriptions,translations}` — speech to text, through the
 * same pipeline as every other `/v1` operation.
 *
 * ## Why this is another copy of `handleEmbeddings`
 *
 * Same reason `handleRerank` is, and the issue says so outright: voice
 * applications "route around" the gateway, so a whole workload class loses
 * governance and cost tracking. A fix that served audio on a bespoke path would
 * close the hole on paper and leave the controls off. Every line below is one of
 * those controls — workflow admission, the model/tenancy/eligibility ladder in
 * `planUpstream`, the TPM reservation, the failover ladder, `recordUsage`, and
 * (through `routes/index.ts`) the drain gate.
 *
 * ## The estimate/settle gap, and how it is closed
 *
 * Transcription is billed on SECONDS OF AUDIO and that number does not exist
 * until the provider answers — this handler holds a compressed blob, not a
 * decoded waveform. So:
 *
 *  - BEFORE dispatch, `estimateAudioUploadUsage` reserves an upper bound derived
 *    from the byte count at a deliberately low assumed bitrate. Over-reserving
 *    holds the caller's own window briefly; under-reserving would let them past
 *    the gate, so the bound leans the safe way.
 *  - AFTER, the provider's reported duration settles both the TPM reservation
 *    (converted at `TOKENS_PER_AUDIO_SECOND`, because the window is denominated
 *    in tokens) and the billing row (`Usage.audioSeconds`, in seconds, because
 *    the invoice is denominated in seconds).
 *  - when the provider reports NO duration, `audioSeconds` is left ABSENT and
 *    the reservation is left UNSETTLED. Both are the fail-closed direction and
 *    both are the same call `handleRerank` and `handleImages` make: a number the
 *    provider did not report must not be recorded as if it had been, and
 *    settling a reservation DOWN on a number nobody measured would refund a
 *    caller for work that happened.
 *
 * ## `response_format`
 *
 * The caller's `response_format: "text"` is honoured HERE rather than forwarded,
 * because the Workers AI run surface has no such knob and the OpenAI
 * passthrough's answer has to be re-shaped anyway. Everything else — `json`,
 * `verbose_json` — is the JSON document, which is what the translated body
 * already is.
 */
async function handleAudioUpload(
  c: InferenceContext,
  deps: ResolvedInferenceDeps,
  operation: "audio.transcriptions" | "audio.translations",
): Promise<Response> {
  const requestId = c.get("requestId");
  const caller = c.get("inferenceCaller");
  const request = c.get("inferenceBody") as Record<string, unknown>;
  const logicalModel = String(request["model"]);
  const metadata = attributedMetadata(c, request);

  const estimated = estimateAudioUploadUsage(request);

  const gate = await admitWorkflowStep(c, deps, caller, logicalModel, estimated);
  if (isRejection(gate)) {
    return errorResponse(gate, requestId);
  }

  const planned = planUpstream(
    deps,
    caller,
    operation,
    logicalModel,
    metadata,
    false,
    request,
    estimated,
    workflowConstraintOf(gate),
  );
  if (isRejection(planned)) {
    return errorResponse(planned, requestId);
  }

  const admitted = await admitTokens(c, estimated);
  if (isRejection(admitted)) {
    return errorResponse(admitted, requestId);
  }
  const admission = admissionHandle(admitted);

  const dispatched = await dispatchCandidates(c, deps, planned);
  if (isRejection(dispatched)) {
    return errorResponse(dispatched, requestId);
  }
  const { route: servedRoute, response: upstreamResponse, attemptIndex, failedOver } = dispatched;
  const relay: UpstreamRelay = { headers: upstreamResponse.headers, failedOver };

  const text = await readUpstreamBody(deps, upstreamResponse);
  if (isRejection(text)) {
    return errorResponse(text, requestId);
  }
  const meterBase = {
    requestId,
    route: ROUTE_LABELS[operation],
    logicalModel,
    provider: servedRoute.provider,
    providerModel: servedRoute.providerModel,
    stream: false,
    status: upstreamResponse.status,
    ...(metadata !== undefined ? { metadata } : {}),
    ...(servedRoute.tenantId !== undefined ? { tenantId: servedRoute.tenantId } : {}),
    providerAttemptIndex: attemptIndex,
    ...routePricing(servedRoute),
  } satisfies Omit<Usage, "promptTokens" | "completionTokens" | "totalTokens">;

  if (!upstreamResponse.ok) {
    recordUsage(c, deps, meterBase, servedRoute.providerKind, undefined);
    settleWorkflowStep(c, deps, gate, false, undefined);
    return rawUpstreamResponse(
      upstreamResponse.status,
      upstreamResponse.headers.get("content-type") ?? "application/json",
      text,
      requestId,
      relay,
    );
  }

  const parsed = safeJson(text);
  const adapter = deps.adapters.adapterFor(servedRoute.providerKind);
  // `undefined` means "this family already speaks the ingress dialect", which is
  // the OpenAI passthrough's answer — its `/v1/audio/transcriptions` response IS
  // `{ text, ... }`. Workers AI translates.
  const translated = adapter?.translateTranscriptionResponse?.(parsed, logicalModel) ?? parsed;
  const seconds = audioDurationOf(translated);

  recordUsage(
    c,
    deps,
    {
      ...meterBase,
      // Absent when the provider reported nothing. See the header.
      ...(seconds !== undefined ? { audioSeconds: seconds } : {}),
    },
    servedRoute.providerKind,
    // No `ProviderUsage`: this operation produces no tokens, and a fabricated
    // zero would be metered as a real reading. Same call `handleImages` makes.
    undefined,
  );
  await settleTokens(
    c,
    admission,
    seconds === undefined ? undefined : Math.ceil(seconds * TOKENS_PER_AUDIO_SECOND),
  );
  settleWorkflowStep(c, deps, gate, true, estimated.totalTokens);

  // ---- `response_format`, applied HERE and not forwarded -------------------
  //
  // It is an INGRESS concern on this surface: the Workers AI run surface has no
  // such knob, and the OpenAI passthrough's body has to be re-shaped anyway.
  // Applying it after metering is what lets `duration` be read for billing on
  // every request while still being ABSENT from the default `json` answer, which
  // is what OpenAI documents. Shaping first would have made the meter's input
  // depend on what the client asked to see.
  const format = request["response_format"];
  if (format === "text") {
    const transcript = (translated as { text?: unknown } | undefined)?.text;
    return rawUpstreamResponse(
      upstreamResponse.status,
      "text/plain; charset=utf-8",
      typeof transcript === "string" ? transcript : "",
      requestId,
      relay,
    );
  }
  if (format === "verbose_json") {
    return jsonResponse(translated, requestId, upstreamResponse.status, relay);
  }
  // The default. OpenAI's `json` is `{ "text": ... }` and NOTHING else — a
  // client switching on `Object.keys` (or a strict SDK model) would break on a
  // richer body, so the extra fields are withheld unless asked for.
  const transcript = (translated as { text?: unknown } | undefined)?.text;
  return jsonResponse(
    { text: typeof transcript === "string" ? transcript : "" },
    requestId,
    upstreamResponse.status,
    relay,
  );
}

/** The billable duration, in seconds, off a translated transcription body. */
function audioDurationOf(body: unknown): number | undefined {
  const duration = (body as { duration?: unknown } | undefined)?.duration;
  return typeof duration === "number" && Number.isFinite(duration) && duration > 0
    ? duration
    : undefined;
}

/**
 * `POST /v1/audio/speech` — text to speech. JSON in, AUDIO BYTES out.
 *
 * ## The one place this handler is NOT a copy of `handleEmbeddings`
 *
 * The response. Every other operation on this surface answers a JSON document,
 * and `readUpstreamBody` decodes the provider's bytes as UTF-8 to produce one.
 * Doing that to an MP3 replaces every byte above 0x7f with U+FFFD — the caller
 * gets a 200, the right content type, the right length in characters, and a file
 * no audio player can open. So this leg reads BYTES
 * ({@link readBoundedProviderBytes}, the same bounded read one decode-step
 * lower) and relays them untouched.
 *
 * ## Errors are still the envelope (issue #733)
 *
 * The binary passthrough applies to SUCCESS only. A non-2xx upstream is decoded
 * as text and handed to `rawUpstreamResponse`, which relays a well-formed
 * provider error verbatim and wraps an unreadable one in the FerroGate envelope.
 * That line is what keeps an SDK's error handling working: a caller must never
 * have to distinguish "these bytes are audio" from "these bytes are a CDN's
 * HTML 502" by sniffing them.
 *
 * ## Metering
 *
 * Speech is billed on CHARACTERS OF INPUT, which — unlike a transcription's
 * duration — is fully known before dispatch. So there is no estimate/settle gap
 * on this leg at all: the count recorded is the count reserved against, and it
 * is recorded only on success, because a failed synthesis synthesized nothing.
 */
async function handleSpeech(
  c: InferenceContext,
  deps: ResolvedInferenceDeps,
): Promise<Response> {
  const requestId = c.get("requestId");
  const caller = c.get("inferenceCaller");
  const request = c.get("inferenceBody") as Record<string, unknown>;
  const logicalModel = String(request["model"]);
  const metadata = attributedMetadata(c, request);

  const estimated = estimateSpeechUsage(request);

  const gate = await admitWorkflowStep(c, deps, caller, logicalModel, estimated);
  if (isRejection(gate)) {
    return errorResponse(gate, requestId);
  }

  const planned = planUpstream(
    deps,
    caller,
    "audio.speech",
    logicalModel,
    metadata,
    false,
    request,
    estimated,
    workflowConstraintOf(gate),
  );
  if (isRejection(planned)) {
    return errorResponse(planned, requestId);
  }

  const admitted = await admitTokens(c, estimated);
  if (isRejection(admitted)) {
    return errorResponse(admitted, requestId);
  }
  const admission = admissionHandle(admitted);

  const dispatched = await dispatchCandidates(c, deps, planned);
  if (isRejection(dispatched)) {
    return errorResponse(dispatched, requestId);
  }
  const { route: servedRoute, response: upstreamResponse, attemptIndex, failedOver } = dispatched;
  const relay: UpstreamRelay = { headers: upstreamResponse.headers, failedOver };

  let bytes: Uint8Array;
  try {
    bytes = await readBoundedProviderBytes(upstreamResponse, deps.limits.providerResponseMaxBytes);
  } catch (error) {
    const detail =
      error instanceof ProviderBodyTooLargeError
        ? error.message
        : `failed to read provider response body: ${
            error instanceof Error ? error.message : String(error)
          }`;
    return errorResponse(
      reject(502, "provider_dispatch_error", `provider dispatch failed: ${detail}`),
      requestId,
    );
  }

  const upstreamContentType =
    upstreamResponse.headers.get("content-type") ?? "application/octet-stream";
  const meterBase = {
    requestId,
    route: ROUTE_LABELS["audio.speech"],
    logicalModel,
    provider: servedRoute.provider,
    providerModel: servedRoute.providerModel,
    stream: false,
    status: upstreamResponse.status,
    ...(metadata !== undefined ? { metadata } : {}),
    ...(servedRoute.tenantId !== undefined ? { tenantId: servedRoute.tenantId } : {}),
    providerAttemptIndex: attemptIndex,
    ...routePricing(servedRoute),
  } satisfies Omit<Usage, "promptTokens" | "completionTokens" | "totalTokens">;

  if (!upstreamResponse.ok) {
    recordUsage(c, deps, meterBase, servedRoute.providerKind, undefined);
    settleWorkflowStep(c, deps, gate, false, undefined);
    // Decoded as text on the ERROR path only. A provider error body is JSON or
    // an HTML page; either way it is text, and `rawUpstreamResponse` is what
    // decides between relaying it verbatim and wrapping it (#733).
    return rawUpstreamResponse(
      upstreamResponse.status,
      upstreamContentType,
      new TextDecoder().decode(bytes),
      requestId,
      relay,
    );
  }

  const adapter = deps.adapters.adapterFor(servedRoute.providerKind);
  const audio = adapter?.translateSpeechResponse?.(bytes, upstreamContentType);
  const payload = audio ?? { bytes, contentType: upstreamContentType };

  const characters = typeof request["input"] === "string" ? (request["input"] as string).length : 0;
  recordUsage(
    c,
    deps,
    { ...meterBase, audioCharacters: characters },
    servedRoute.providerKind,
    undefined,
  );
  // Settled at exactly what was reserved: the quantity was never in doubt.
  await settleTokens(c, admission, estimated.totalTokens);
  settleWorkflowStep(c, deps, gate, true, estimated.totalTokens);

  return audioResponse(payload.bytes, payload.contentType, requestId, relay);
}

/**
 * A binary 2xx, with the gateway's own headers and the pacing relay.
 *
 * Deliberately NOT `rawUpstreamResponse`: that function takes a `string`, and
 * its #733 wrap-check parses the body as JSON to decide whether to envelope it.
 * Both are correct for a text body and both are wrong for an MP3 — the decode
 * corrupts it, and the JSON check would be asking whether a waveform happens to
 * parse. The status is fixed at 2xx by construction here, so the wrap-check has
 * nothing to decide anyway: it only ever applies to `status >= 400`.
 */
function audioResponse(
  bytes: Uint8Array,
  contentType: string,
  requestId: string,
  upstream?: UpstreamRelay,
): Response {
  return new Response(bytes as BodyInit, {
    status: 200,
    headers: {
      "content-type": contentType,
      ...gatewayHeaders(requestId),
      ...relayedRateLimitHeaders(upstream),
    },
  });
}

// ---------------------------------------------------------------------------
// POST /v1/images/generations — `images.rs::handle_images`
// ---------------------------------------------------------------------------

async function handleImages(
  c: InferenceContext,
  deps: ResolvedInferenceDeps,
): Promise<Response> {
  const requestId = c.get("requestId");
  const caller = c.get("inferenceCaller");
  const request = c.get("inferenceBody") as Record<string, unknown>;
  const logicalModel = String(request["model"]);
  const metadata = attributedMetadata(c, request);

  // Rust `estimate_images_usage` (issue #275): the pre-charge unit is GENERATED
  // IMAGES on the completion dimension, and `n` is clamped to
  // `MAX_ESTIMATED_IMAGE_COUNT` so a hostile `"n": 1e9` cannot pre-charge the
  // caller's entire window on a request the provider would refuse anyway.
  //
  // Computed BEFORE planning (it is pure, and the charge below is unmoved) so
  // that `lowest_cost` can price this surface too. Its prompt side is 0, which
  // leaves the context-window eligibility leg exactly as unarmed as it was.
  const estimated = estimateImagesUsage(request);

  const gate = await admitWorkflowStep(c, deps, caller, logicalModel, estimated);
  if (isRejection(gate)) {
    return errorResponse(gate, requestId);
  }

  const planned = planUpstream(
    deps,
    caller,
    "images",
    logicalModel,
    metadata,
    false,
    request,
    estimated,
    workflowConstraintOf(gate),
  );
  if (isRejection(planned)) {
    return errorResponse(planned, requestId);
  }

  const admitted = await admitTokens(c, estimated);
  if (isRejection(admitted)) {
    return errorResponse(admitted, requestId);
  }
  const admission = admissionHandle(admitted);

  const dispatched = await dispatchCandidates(c, deps, planned);
  if (isRejection(dispatched)) {
    return errorResponse(dispatched, requestId);
  }
  const { route: servedRoute, response: upstreamResponse, attemptIndex, failedOver } = dispatched;
  // #726 — the pacing headers of the response that ACTUALLY answered, plus
  // whether the ladder moved the caller to get it. Built once here so every
  // exit below (relayed body, translated body, stream) carries the same
  // decision instead of five call sites re-deriving it.
  const relay: UpstreamRelay = { headers: upstreamResponse.headers, failedOver };

  const text = await readUpstreamBody(deps, upstreamResponse);
  if (isRejection(text)) {
    return errorResponse(text, requestId);
  }
  const parsed = upstreamResponse.ok ? safeJson(text) : undefined;
  // Images settle on the number of images the provider actually returned — the
  // AUTHORITATIVE count is always taken from the response, never from the
  // caller's `n` (which is only used to pre-size the reservation, capped at
  // `MAX_ESTIMATED_IMAGE_COUNT`, so a hostile `n` cannot force an unbounded
  // pre-charge).
  const imageCount = Array.isArray((parsed as { data?: unknown } | undefined)?.data)
    ? ((parsed as { data: unknown[] }).data.length)
    : undefined;

  recordUsage(
    c,
    deps,
    {
      requestId,
      route: ROUTE_LABELS.images,
      logicalModel,
      provider: servedRoute.provider,
      providerModel: servedRoute.providerModel,
      stream: false,
      status: upstreamResponse.status,
      ...(imageCount !== undefined ? { imageCount } : {}),
      ...(metadata !== undefined ? { metadata } : {}),
      ...(servedRoute.tenantId !== undefined ? { tenantId: servedRoute.tenantId } : {}),
      providerAttemptIndex: attemptIndex,
      ...routePricing(servedRoute),
    },
    servedRoute.providerKind,
    // `/v1/images` settles on IMAGES, not tokens, so there is no
    // `ProviderUsage` here and the span carries `gen_ai.request.model` /
    // `gen_ai.operation.name` with no `gen_ai.usage.*`. That is correct: the
    // convention has no image-count attribute, and a fabricated zero token
    // count would be worse than none.
    undefined,
  );

  // `image_settlement_usage`: the AUTHORITATIVE count is the response's `data`
  // length, falling back to the pre-dispatch estimate when the body carries no
  // countable envelope — never the caller's `n`.
  await settleTokens(c, admission, imageCount);
  // `/v1/images` has no token usage at all — it settles on images — so the
  // workflow step keeps the pre-dispatch estimate rather than inventing a token
  // count from an image count. The step's SUCCESS is what the edge gate reads,
  // and that is recorded truthfully.
  settleWorkflowStep(c, deps, gate, upstreamResponse.ok, estimated.totalTokens);

  return rawUpstreamResponse(
    upstreamResponse.status,
    upstreamResponse.headers.get("content-type") ?? "application/json",
    text,
    requestId,
    relay,
  );
}

// ---------------------------------------------------------------------------

/** Parse a provider body, tolerating a non-JSON one (Rust used `.ok()` here). */
function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
