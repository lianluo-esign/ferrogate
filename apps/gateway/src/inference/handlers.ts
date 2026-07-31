/**
 * Hono handlers for the six inference operations owned by `apps/gateway`.
 *
 * | contract operation      | method + path              | scope              | Rust handler |
 * |-------------------------|----------------------------|--------------------|--------------|
 * | `listModels`            | GET  /v1/models            | `models.read`      | `local.rs::handle_models` |
 * | `createChatCompletion`  | POST /v1/chat/completions  | `chat.completions` | `chat.rs::handle_chat_completions` |
 * | `createResponse`        | POST /v1/responses         | `responses.create` | `chat.rs::handle_responses` |
 * | `createMessage`         | POST /v1/messages          | `messages.create`  | `messages.rs::handle_messages` |
 * | `createEmbedding`       | POST /v1/embeddings        | `embeddings.create`| `embeddings.rs::handle_embeddings` |
 * | `createImage`           | POST /v1/images/generations| `images.generate`  | `images.rs::handle_images` |
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
 * table-driven middleware for all 251 operations, and duplicating a per-route
 * guard is exactly what that invariant forbids. Everything from step 2 down is
 * this module's, and is implemented below.
 */
import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import type { Context, MiddlewareHandler } from "hono";
import type { z } from "zod";
import { resolveDeps } from "./defaults.js";
import {
  ProviderBodyTooLargeError,
  ProviderEndpointError,
  dispatchDeadline,
  parseProviderEndpoint,
  providerTransportMessage,
  readBoundedProviderBody,
} from "./dispatch.js";
import { errorResponse, jsonResponse, rawUpstreamResponse, reject } from "./errors.js";
import type { InferenceRejection } from "./errors.js";
import {
  adapterErrorMessage,
  callerCanUseModel,
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
  anthropicMessagesRequestSchema,
  chatCompletionRequestSchema,
  embeddingsRequestSchema,
  formatZodError,
  imagesRequestSchema,
  responsesRequestSchema,
  validateRequestMetadata,
} from "./schemas.js";
import type { OpenAiModelList, RequestMetadata } from "./schemas.js";
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
  };
}

type InferenceContext = Context<InferenceEnv>;

/** Rust route labels (`AiEndpoint::route`, `MESSAGES_ROUTE`, …) used in metering. */
const ROUTE_LABELS = {
  "chat.completions": "openai.chat.completions",
  responses: "openai.responses",
  messages: "anthropic.messages",
  embeddings: "openai.embeddings",
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

// ---------------------------------------------------------------------------
// Steps 5 + 6 — metadata bounds, model gate, model resolution
// ---------------------------------------------------------------------------

interface PlannedRequest {
  readonly route: PhysicalRoute;
  readonly upstream: UpstreamRequest;
}

/**
 * Runs steps 5 and 6 and builds the upstream request. Returns a rejection
 * instead of throwing so the caller keeps the Rust status/code pairs verbatim.
 */
function planUpstream(
  deps: ResolvedInferenceDeps,
  caller: Caller,
  operation: InferenceOperation,
  logicalModel: string,
  metadata: RequestMetadata | undefined,
  stream: boolean,
  body: Record<string, unknown>,
): PlannedRequest | InferenceRejection {
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

  const route = deps.models.resolve(logicalModel);
  if (route === null) {
    const known = deps.models
      .catalog()
      .find((candidate) => candidate.logicalModel === logicalModel);
    return known === undefined
      ? reject(400, "model_not_found", `unknown model ${logicalModel}`)
      : reject(400, "model_disabled", `model ${logicalModel} is disabled`);
  }

  // A tenant must not be able to invoke another tenant's private model even
  // when it guessed the logical name (`can_tenant_use_model`). The listing
  // filter and the invocation gate MUST agree — that was issue #515.
  if (!scopeCanSeeModel(caller.scope, caller.projectId, route)) {
    return reject(400, "model_not_found", `unknown model ${logicalModel}`);
  }

  const adapter = deps.adapters.adapterFor(route.providerKind);
  if (adapter === null) {
    return reject(
      502,
      "provider_adapter_error",
      `unsupported provider kind ${route.providerKind.trim().toLowerCase()}`,
    );
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
    return reject(
      built.error.kind === "invalid_request" ? 400 : status,
      code,
      adapterErrorMessage(built.error),
    );
  }

  return { route, upstream: built.request };
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

function isRejection(value: unknown): value is InferenceRejection {
  return (
    typeof value === "object" &&
    value !== null &&
    "status" in value &&
    "code" in value &&
    "message" in value
  );
}

/** Record a metering event; never allowed to fail the response. */
function recordUsage(
  deps: ResolvedInferenceDeps,
  base: Omit<Usage, "promptTokens" | "completionTokens" | "totalTokens">,
  usage: ProviderUsage | undefined,
): void {
  try {
    deps.usage.record({
      ...base,
      ...(usage?.promptTokens !== undefined ? { promptTokens: usage.promptTokens } : {}),
      ...(usage?.completionTokens !== undefined
        ? { completionTokens: usage.completionTokens }
        : {}),
      ...(usage?.totalTokens !== undefined ? { totalTokens: usage.totalTokens } : {}),
    });
  } catch {
    // `InMemoryBillingEventSink` surfaced a poisoned-lock error to the LOG, not
    // to the caller. Same contract here.
  }
}

/** Headers a streamed response carries in addition to the gateway ones. */
function streamingHeaders(contentType: string, requestId: string): Record<string, string> {
  return {
    "content-type": contentType,
    // The Rust writer emitted a chunked SSE response with no caching; Workers
    // sets transfer-encoding itself, so only the cache directives are explicit.
    "cache-control": "no-cache",
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
): Response {
  const contentType = upstreamResponse.headers.get("content-type") ?? "text/event-stream";
  const body = upstreamResponse.body;
  if (body === null) {
    return new Response(null, {
      status: upstreamResponse.status,
      headers: streamingHeaders(contentType, requestId),
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
    headers: streamingHeaders(outgoingContentType, requestId),
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

  // Ports, request identity and caller, once per request (Rust middleware
  // step 1). The ports come first because the body reader below reads the
  // request-size cap off them.
  app.use("*", async (c, next) => {
    const resolved = depsFor(c.env);
    c.set("inferenceDeps", resolved);
    c.set("inferenceClientSignal", inboundSignal(c.req.raw));
    c.set("requestId", c.req.header("x-request-id") ?? resolved.requestIds.next());
    c.set("inferenceCaller", resolved.caller(c.req.raw));
    await next();
  });

  const body = readInferenceBody();

  // -- GET /v1/models --------------------------------------------------------
  app.get("/v1/models", (c) => handleModels(c, c.get("inferenceDeps")));

  // -- POST /v1/chat/completions --------------------------------------------
  app.post(
    "/v1/chat/completions",
    body,
    validateBody(chatCompletionRequestSchema, "invalid chat completion request"),
    (c) => handleOpenAiInference(c, c.get("inferenceDeps"), "chat.completions"),
  );

  // -- POST /v1/responses ----------------------------------------------------
  app.post(
    "/v1/responses",
    body,
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

  // -- POST /v1/embeddings ---------------------------------------------------
  app.post(
    "/v1/embeddings",
    body,
    validateBody(embeddingsRequestSchema, "invalid embeddings request"),
    (c) => handleEmbeddings(c, c.get("inferenceDeps")),
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
// ---------------------------------------------------------------------------

function handleModels(c: InferenceContext, deps: ResolvedInferenceDeps): Response {
  const requestId = c.get("requestId");
  const caller = c.get("inferenceCaller");

  // A platform-operator key sees every ENABLED model; a tenant-scoped key sees
  // only the models visible to its tenant/project, matching the invocation gate
  // in `planUpstream`. Without this the listing leaked other tenants' private
  // logical names and their upstream provider mapping (issue #515), even though
  // invocation was blocked downstream.
  const data = deps.models
    .catalog()
    .filter((route) => route.enabled)
    .filter((route) => scopeCanSeeModel(caller.scope, caller.projectId, route))
    .map((route) => ({
      id: route.logicalModel,
      object: "model" as const,
      // Hard-coded 0 in the Rust tree; the config carries no creation time.
      created: 0,
      owned_by: route.ownedBy ?? route.provider,
    }));

  const listing: OpenAiModelList = { object: "list", data };
  return jsonResponse(listing, requestId);
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
  const metadata = request["metadata"] as RequestMetadata | undefined;

  const planned = planUpstream(
    deps,
    caller,
    operation,
    logicalModel,
    metadata,
    stream,
    request,
  );
  if (isRejection(planned)) {
    return errorResponse(planned, requestId);
  }

  const upstreamResponse = await dispatchUpstream(deps, planned.upstream, clientSignal(c));
  if (isRejection(upstreamResponse)) {
    return errorResponse(upstreamResponse, requestId);
  }

  const routeLabel = ROUTE_LABELS[operation];
  const usageDialect = usageProviderKindFor(operation, planned.route.providerKind);
  const meterBase = {
    requestId,
    route: routeLabel,
    logicalModel,
    provider: planned.route.provider,
    providerModel: planned.route.providerModel,
    stream,
    status: upstreamResponse.status,
    ...(metadata !== undefined ? { metadata } : {}),
    ...(planned.route.tenantId !== undefined ? { tenantId: planned.route.tenantId } : {}),
  } satisfies Omit<Usage, "promptTokens" | "completionTokens" | "totalTokens">;

  if (stream && isStreamingUpstream(upstreamResponse)) {
    const dialect: StreamDialect =
      operation === "responses" ? "openai.responses" : "openai.chat";
    return streamResponse(
      deps,
      upstreamResponse,
      dialect,
      usageDialect,
      planned.route,
      requestId,
      (usage) => recordUsage(deps, meterBase, usage),
    );
  }

  const text = await readUpstreamBody(deps, upstreamResponse);
  if (isRejection(text)) {
    return errorResponse(text, requestId);
  }
  if (!upstreamResponse.ok) {
    recordUsage(deps, meterBase, undefined);
    return rawUpstreamResponse(
      upstreamResponse.status,
      upstreamResponse.headers.get("content-type") ?? "application/json",
      text,
      requestId,
    );
  }

  const parsed = safeJson(text);
  recordUsage(deps, meterBase, usageFromResponseBody(usageDialect, parsed));
  return rawUpstreamResponse(
    upstreamResponse.status,
    upstreamResponse.headers.get("content-type") ?? "application/json",
    text,
    requestId,
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

  const planned = planUpstream(
    deps,
    caller,
    "chat.completions",
    logicalModel,
    undefined,
    stream,
    translated.body,
  );
  if (isRejection(planned)) {
    return errorResponse(planned, requestId);
  }

  const upstreamResponse = await dispatchUpstream(deps, planned.upstream, clientSignal(c));
  if (isRejection(upstreamResponse)) {
    return errorResponse(upstreamResponse, requestId);
  }

  const usageDialect = usageProviderKindFor("messages", planned.route.providerKind);
  const meterBase = {
    requestId,
    route: ROUTE_LABELS.messages,
    logicalModel,
    provider: planned.route.provider,
    providerModel: planned.route.providerModel,
    stream,
    status: upstreamResponse.status,
    ...(planned.route.tenantId !== undefined ? { tenantId: planned.route.tenantId } : {}),
  } satisfies Omit<Usage, "promptTokens" | "completionTokens" | "totalTokens">;

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
      planned.route,
      requestId,
      (usage) => recordUsage(deps, meterBase, usage),
    );
  }

  const text = await readUpstreamBody(deps, upstreamResponse);
  if (isRejection(text)) {
    return errorResponse(text, requestId);
  }
  if (!upstreamResponse.ok) {
    recordUsage(deps, meterBase, undefined);
    return rawUpstreamResponse(
      upstreamResponse.status,
      upstreamResponse.headers.get("content-type") ?? "application/json",
      text,
      requestId,
    );
  }

  const parsed = safeJson(text);
  recordUsage(deps, meterBase, usageFromResponseBody(usageDialect, parsed));
  // An Anthropic upstream answered natively → passed through unchanged; an
  // OpenAI-family upstream is reshaped so a Claude client sees a native Message
  // either way.
  const message = deps.translator.chatCompletionToMessage(parsed, logicalModel);
  return jsonResponse(message, requestId, upstreamResponse.status);
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
  const metadata = request["metadata"] as RequestMetadata | undefined;

  const planned = planUpstream(
    deps,
    caller,
    "embeddings",
    logicalModel,
    metadata,
    false,
    request,
  );
  if (isRejection(planned)) {
    return errorResponse(planned, requestId);
  }

  const upstreamResponse = await dispatchUpstream(deps, planned.upstream, clientSignal(c));
  if (isRejection(upstreamResponse)) {
    return errorResponse(upstreamResponse, requestId);
  }

  const text = await readUpstreamBody(deps, upstreamResponse);
  if (isRejection(text)) {
    return errorResponse(text, requestId);
  }
  const meterBase = {
    requestId,
    route: ROUTE_LABELS.embeddings,
    logicalModel,
    provider: planned.route.provider,
    providerModel: planned.route.providerModel,
    stream: false,
    status: upstreamResponse.status,
    ...(metadata !== undefined ? { metadata } : {}),
    ...(planned.route.tenantId !== undefined ? { tenantId: planned.route.tenantId } : {}),
  } satisfies Omit<Usage, "promptTokens" | "completionTokens" | "totalTokens">;

  if (!upstreamResponse.ok) {
    recordUsage(deps, meterBase, undefined);
    return rawUpstreamResponse(
      upstreamResponse.status,
      upstreamResponse.headers.get("content-type") ?? "application/json",
      text,
      requestId,
    );
  }

  const parsed = safeJson(text);
  recordUsage(deps, meterBase, usageFromResponseBody("openai", parsed));

  // `translate_embeddings_response`: `undefined` means "pass the upstream body
  // through byte-for-byte" — correct for the OpenAI-compatible family, whose
  // `/embeddings` response already IS the canonical shape (issue #274).
  const adapter = deps.adapters.adapterFor(planned.route.providerKind);
  const translated = adapter?.translateEmbeddingsResponse?.(parsed, logicalModel);
  if (translated !== undefined) {
    return jsonResponse(translated, requestId, upstreamResponse.status);
  }
  return rawUpstreamResponse(
    upstreamResponse.status,
    upstreamResponse.headers.get("content-type") ?? "application/json",
    text,
    requestId,
  );
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
  const metadata = request["metadata"] as RequestMetadata | undefined;

  const planned = planUpstream(deps, caller, "images", logicalModel, metadata, false, request);
  if (isRejection(planned)) {
    return errorResponse(planned, requestId);
  }

  const upstreamResponse = await dispatchUpstream(deps, planned.upstream, clientSignal(c));
  if (isRejection(upstreamResponse)) {
    return errorResponse(upstreamResponse, requestId);
  }

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
    deps,
    {
      requestId,
      route: ROUTE_LABELS.images,
      logicalModel,
      provider: planned.route.provider,
      providerModel: planned.route.providerModel,
      stream: false,
      status: upstreamResponse.status,
      ...(imageCount !== undefined ? { imageCount } : {}),
      ...(metadata !== undefined ? { metadata } : {}),
      ...(planned.route.tenantId !== undefined ? { tenantId: planned.route.tenantId } : {}),
    },
    undefined,
  );

  return rawUpstreamResponse(
    upstreamResponse.status,
    upstreamResponse.headers.get("content-type") ?? "application/json",
    text,
    requestId,
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
