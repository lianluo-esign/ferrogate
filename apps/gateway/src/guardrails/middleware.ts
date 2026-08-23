import { type GuardrailProtocol, normalizeRequest, normalizeResponse } from "@ferrogate/guardrails";
/**
 * The guardrail MIDDLEWARE seam — one Hono middleware that installs both the
 * input (request-stage) and output (response-stage) screening the Rust
 * inference handlers performed inline.
 *
 * ## Wiring (the integrate step owns `src/index.ts` / `src/routes/index.ts`)
 *
 * ```ts
 * // apps/gateway/src/routes/index.ts, inside createGatewayApp, IMMEDIATELY
 * // after the contract auth guard and BEFORE any route module is mounted:
 * import { guardrails, guardrailDepsFromEnv } from "../guardrails/index.js";
 *
 * app.use("*", contractAuth(options.deps ?? depsFromEnv));
 * app.use("*", guardrails(options.guardrails ?? guardrailDepsFromEnv));   // <-- ADD
 * ```
 *
 * Order is load-bearing and matches `server/chat.rs`:
 *
 * 1. `contractAuth` — authenticate BEFORE reading the body, so an
 *    unauthenticated oversized request is `missing_api_key`, not
 *    `payload_too_large` (`chat.rs:158`). This middleware reads the body, so it
 *    MUST sit after the guard.
 * 2. `guardrails` — request-stage screening. It reads the body from a
 *    `Request.clone()` and never touches Hono's body cache, so
 *    `readInferenceBody`'s own bounded read + `payload_too_large` + `invalid_json`
 *    behavior downstream is completely unaffected.
 * 3. the route modules — validation, model gate, dispatch.
 *
 * In the Rust the guardrail ran AFTER model resolution, because the policy scope
 * selector can key on `provider`. A middleware runs before resolution, so the
 * provider is supplied through {@link GuardrailMiddlewareOptions.providerForModel}
 * — pass `(model, env) => modelsFromEnv(env).resolve(model)?.provider` at the
 * composition root and provider-scoped policies keep working verbatim. With no
 * resolver the selector simply sees no provider, which (per `scopeMatches`) means
 * a provider-scoped policy does not match — fail-open on SELECTION, so state it
 * explicitly at the composition root rather than leaving it implicit.
 *
 * ## What it enforces
 *
 * - **Request stage** — ANY match (deny OR redact) refuses the request with
 *   403 and the FerroGate error envelope. That is not a simplification: every
 *   Rust model-content handler does exactly this
 *   (`chat.rs:409-417`, `messages.rs:390-399`, `embeddings.rs:307-338`,
 *   `images.rs`), branching on `effect` only on the RESPONSE stage. A
 *   request-stage `redact` therefore blocks; it never silently rewrites the
 *   caller's prompt and forwards it.
 * - **Response stage, non-streaming** — `deny` → 403 envelope; `redact` →
 *   `redactText` over the response document.
 * - **Response stage, streaming** — see `stream.ts`. `reject_streaming` is
 *   refused before dispatch by the engine itself; `buffer_and_enforce` becomes
 *   incremental per-frame screening; `shadow_after_complete` passes through and
 *   evaluates once at the end (`not_enforced`).
 */
import type { Context, MiddlewareHandler, Next } from "hono";
import { GATEWAY_CONFIG_HEADER } from "../middleware/response-cache.js";
import { contributeRequestLogFacts, requestLogFactsFor } from "../requestlog/facts.js";
import type { GuardrailVerdict } from "../requestlog/record.js";
import { publishConversationReplayScreener } from "./conversation-replay.js";
import { GuardrailEngine, evidenceLocation, evidenceTarget, redactText } from "./engine.js";
import type {
  GuardrailAuditSink,
  GuardrailEngineDeps,
  GuardrailEvaluationContext,
  GuardrailEvidenceSink,
  GuardrailMatch,
  GuardrailTenant,
} from "./ports.js";
import { type StreamDialect, screenSseBody } from "./stream.js";

/** The inference operations guardrails apply to, and how each normalizes. */
interface OperationBinding {
  readonly protocol: GuardrailProtocol;
  readonly dialect: StreamDialect;
  /**
   * Whether the REQUEST stage runs (issue #703).
   *
   * `true` for every operation that sends a JSON body, and for those nothing
   * about the middleware changed. It is `false` for three, for two different
   * reasons that both come down to "there is no text here to hand a detector":
   *
   *  - `createTranscription` / `createTranslation` send `multipart/form-data`
   *    wrapping opaque audio (#703);
   *  - `getResponse` is a GET and has no body at all (#689).
   *
   * In both cases the request stage does not run AT ALL, and — the part that
   * matters — NO `allowed` verdict is recorded for it. That distinction is the
   * whole reason this is a flag rather than an empty envelope evaluated for
   * form's sake: an empty envelope would pass every check, write an evidence
   * row, and report a control that read nothing.
   */
  readonly screensRequest: boolean;
  /**
   * Whether the RESPONSE stage runs. Defined for chat/responses
   * (model-generated text), since #703 for the two audio uploads (an
   * attacker-supplied transcript), and since #689 for `getResponse` (a turn a
   * DIFFERENT credential's policy approved). See `normalizeResponse`.
   */
  readonly screensResponse: boolean;
}

/**
 * `AiEndpoint::guardrail_protocol` (`server/chat.rs:106-111`) plus the two
 * request-only surfaces. `/v1/messages` normalizes as `chat_completions`
 * because the Rust ran the guardrail over the TRANSLATED chat body
 * (`server/messages.rs:1635`).
 */
export const GUARDRAIL_OPERATIONS: Readonly<Record<string, OperationBinding>> = {
  createChatCompletion: {
    protocol: "chat_completions",
    dialect: "openai.chat",
    screensRequest: true,
    screensResponse: true,
  },
  createResponse: {
    protocol: "responses",
    dialect: "openai.responses",
    screensRequest: true,
    screensResponse: true,
  },
  createMessage: {
    protocol: "chat_completions",
    dialect: "anthropic.messages",
    screensRequest: true,
    screensResponse: true,
  },
  // Embeddings/Rerank/Images are REQUEST-only: `normalize_response` returns an
  // empty envelope for them (`envelope.ts`), matching the Rust.
  createEmbedding: {
    protocol: "embeddings",
    dialect: "openai.chat",
    screensRequest: true,
    screensResponse: false,
  },
  // Issue #676. Its own protocol, not `embeddings`: the embeddings extractor
  // walks `input`, and a rerank body carries `query` + `documents`, so binding
  // it there would produce an EMPTY envelope — screening that is green, costs an
  // evidence row, and enforces nothing. That is the exact shape of hole this
  // table is supposed to make impossible.
  createRerank: {
    protocol: "rerank",
    dialect: "openai.chat",
    screensRequest: true,
    screensResponse: false,
  },
  // ---- the audio surface (issue #703) --------------------------------------
  //
  // Three operations, two protocols, and the asymmetry between them IS the
  // entry. "Audio is opaque, so audio cannot be guarded" is only half true, and
  // shipping the half would have left the more dangerous direction open.
  //
  // `createSpeech` — REQUEST-screened. Its body is JSON carrying the `input`
  // text a caller wants spoken, which is ordinary user content and the last
  // point at which it is still a string: once synthesized it is past every text
  // control a tenant owns (a DLP scan of transcripts, a log scrubber, a
  // redaction policy on `/v1/chat/completions`; none of them reads audio).
  // `screensResponse` is false because the answer is MP3 bytes — decoding those
  // as UTF-8 to hand a detector would produce mojibake and an evidence row
  // about nothing.
  //
  // `createTranscription` / `createTranslation` — RESPONSE-screened, and NOT
  // request-screened. Both halves are deliberate:
  //
  //  - the INPUT is opaque and stays that way. Their bodies are
  //    `multipart/form-data` wrapping audio; `readJsonBodyBounded` below returns
  //    `undefined` for a non-JSON body, no detector in this tree reads a
  //    waveform, and `normalizeRequest("audio_transcription", …)` extracts
  //    nothing on purpose. `screensRequest: false` says exactly that, and the
  //    middleware records NO verdict for a stage it did not run — which is the
  //    difference between an absence an auditor can see and a no-op that looks
  //    like a control.
  //
  //  - the OUTPUT is not opaque, and it is the direction the attack travels. A
  //    transcript is text chosen by whoever supplied the recording — anyone who
  //    can email your customer an audio file — returned to a caller who will
  //    usually put it straight into the next prompt. That is the same class
  //    issue #688 closes for tool results and retrieved documents, and a
  //    transcript is a textbook instance of it. So the answer goes through the
  //    ordinary response stage, over the `audio_transcription` protocol, with
  //    the same evidence shape and the same deny/redact effects as every other
  //    text egress on this table. `envelope.ts` walks the three shapes
  //    `response_format` can produce, because otherwise the bypass would be one
  //    form field long.
  createSpeech: {
    protocol: "audio_speech",
    dialect: "openai.chat",
    screensRequest: true,
    screensResponse: false,
  },
  createTranscription: {
    protocol: "audio_transcription",
    dialect: "openai.chat",
    screensRequest: false,
    screensResponse: true,
  },
  createTranslation: {
    protocol: "audio_transcription",
    dialect: "openai.chat",
    screensRequest: false,
    screensResponse: true,
  },
  createImage: {
    protocol: "images",
    dialect: "openai.chat",
    screensRequest: true,
    screensResponse: false,
  },
  // ---- Gemini-native ingress -----------------------------------------------
  //
  // `POST /v1beta/models/{model}:{generateContent|streamGenerateContent}`. It
  // is the first binding that screens BOTH stages over a single protocol member
  // (chat/responses/messages do too, but each is its own translated shape),
  // because both directions carry screenable text: the request's `contents[].
  // parts[].text` and `systemInstruction` on their way to a provider, and the
  // answer's `candidates[].content.parts[].text`. That symmetry is the whole
  // reason `gemini` is one protocol and not the split the audio surface needed.
  //
  // A cross-protocol fallback cannot reach here: the handler refuses a
  // Gemini-native request that would dispatch to a non-Gemini supplier with
  // `502 provider_protocol_mismatch` rather than translating, so the bytes this
  // screener sees are always the Gemini shape its extractor walks. Binding it to
  // `chat_completions` would have produced an empty envelope — the exact no-op
  // this table forbids — since the chat extractor reads `messages`, not
  // `contents`.
  geminiGenerateContent: {
    protocol: "gemini",
    dialect: "gemini",
    screensRequest: true,
    screensResponse: true,
  },
  // ---- the stored conversation READ (issue #689) ---------------------------
  //
  // `GET /v1/responses/{id}`, RESPONSE-screened, and it is here because the
  // exception that kept it off this table turned out to be false.
  //
  // The write-side fix (`inference/conversation-commit.ts`) makes a stored turn
  // byte-for-byte the turn the response stage handed the WRITER. The argument
  // built on it was that the read therefore needs no screening: the bytes were
  // approved, and the caller already holds them. The first clause is true. The
  // second is not, because the two fences are different widths:
  //
  //   - conversation state is fenced on `(tenantId, projectId)`
  //     (`inference/conversation.ts::conversationOwner`);
  //   - policy scope is fenced per KEY — `api_key_ids` is the NARROWEST
  //     administrative selector `packages/guardrails/src/policy.ts` ranks, and
  //     it is selected from `auth.subject`.
  //
  // So one project's two credentials share one conversation store while sitting
  // under different policies, and a turn written by an UNGOVERNED key is served
  // to a GOVERNED one. Measured: a redact policy scoped to key B alone, key A
  // stores a card verbatim (correct — no policy binds A), and key B's GET
  // answered 200 with the card. `test/inference/responses-cross-key-guardrail.
  // test.ts` is that measurement.
  //
  // This is a COMPLEMENT to the write-side fix, not a replacement for it. The
  // cost objection that rules out screening-on-read as a SUBSTITUTE is about the
  // chain replay, which is O(depth) detector work per turn; a `GET` is O(1) —
  // one stored document, one screening pass, on a request that does no
  // inference at all. And the write-side fix stays load-bearing for everything
  // this binding cannot reach: a DENIED turn is still never written, so there is
  // no row at rest for the retention window and none to read back.
  //
  // `screensRequest: false` is not a widening of the #703 exception, it is the
  // only value that works: a GET has NO body, `readJsonBodyBounded` returns
  // `undefined` for `request.body === null`, and the request-stage branch
  // answers that with an early `return next()` — which would skip the response
  // stage entirely and leave this binding inert. An operation with no request
  // body records no request-stage verdict, which is the honest reading.
  //
  // A continuation is distinct from this GET binding. Its chain is assembled
  // inside the inference router, so the request-stage path below publishes the
  // already-resolved engine and selected revision marker through
  // `conversation-replay.ts`; the router calls it at assembly for turns whose
  // screening context differs (#779, #808).
  getResponse: {
    protocol: "responses",
    dialect: "openai.responses",
    screensRequest: false,
    screensResponse: true,
  },
};

export interface GuardrailMiddlewareOptions extends GuardrailEngineDeps {
  /**
   * Resolves the physical provider for a logical model, so provider-scoped
   * policies select correctly. See the wiring note above.
   */
  readonly providerForModel?:
    | ((model: string, env: Record<string, unknown>) => string | undefined)
    | undefined;
  /**
   * Anthropic → OpenAI-chat request translation for `/v1/messages`, so the
   * envelope is built over the same document the Rust screened. Pass
   * `defaultAnthropicTranslator.toChatCompletions` from `inference/index.ts`.
   */
  readonly translateAnthropicRequest?:
    | ((body: Record<string, unknown>) => Record<string, unknown> | undefined)
    | undefined;
  /**
   * Cap on the request bytes this middleware will read for screening. Defaults
   * to the Rust `limits.inference_body_max_bytes` (1 MiB). A body OVER the cap
   * is left entirely alone so the downstream reader answers 413
   * `payload_too_large` — the Rust order (body cap first, guardrail second).
   */
  readonly maxRequestBytes?: number | undefined;
  /**
   * Cap on a NON-streaming response body read for screening. Over the cap the
   * response is passed through and a capture-overflow evidence row is written,
   * mirroring `record_guardrail_stream_capture_overflow`.
   */
  readonly maxResponseBytes?: number | undefined;
}

/**
 * A deps factory resolved per Worker `env`, like `middleware/auth.ts`.
 *
 * It may be ASYNC. The durable policy source (`d1.ts`) reads
 * `guardrail_policy_revisions` / `guardrail_policy_bindings` out of D1, and
 * D1 has no synchronous read — so `guardrails()` awaits the resolver once per
 * `env` and every request in the isolate shares that one snapshot. A REJECTION
 * is not swallowed: it propagates out of the middleware, which is the
 * fail-closed direction (503, no unscreened content forwarded) and the same
 * posture `guardrailPolicySourceFromEnv` already takes for a malformed policy
 * var.
 */
export type GuardrailDepsResolver = (
  env: Record<string, unknown>,
) => GuardrailMiddlewareOptions | Promise<GuardrailMiddlewareOptions>;

/**
 * Publish what screening decided, for the request log (#664).
 *
 * This middleware is the ONLY thing that knows whether a guardrail ran, so
 * without this line the trail's `guardrail_verdict` column would be
 * `not_screened` on every row — a compliance field that is always the same
 * value is a field that answers nothing.
 *
 * It writes to the per-`Request` fact collector rather than to `c.set(...)`
 * because the reader is a different middleware and, for an inference request,
 * the interesting facts arrive from a different Hono app entirely; see
 * `../requestlog/facts.ts` for why the carrier is keyed by the `Request`.
 *
 * `blocked` wins over a later `allowed`: input screening passing and output
 * screening then denying is ONE blocked decision, and the collector's
 * last-write-wins merge would otherwise be order-dependent.
 */
function recordGuardrailVerdict(
  c: Context,
  verdict: GuardrailVerdict,
  match?: GuardrailMatch,
): void {
  if (verdict === "allowed" && requestLogFactsFor(c.req.raw).guardrailVerdict === "blocked") {
    return;
  }
  contributeRequestLogFacts(c.req.raw, {
    guardrailVerdict: verdict,
    ...(match === undefined ? {} : { guardrailPolicyId: match.ruleId }),
  });
}

/**
 * Schedule the durable evidence write, OFF the hot path (#665).
 *
 * The engine's `evidence.append` is synchronous and buffers; this is where the
 * buffer actually reaches D1 or the Queue. It is called from a `finally`, so
 * every exit of the middleware — a 403 block, a pass-through, a thrown error —
 * lands its evidence, and it is called again when a screened SSE body finishes,
 * because a stream's evidence is decided long after the middleware returned.
 *
 * Returns a NO-OP for a sink with no `flush` (the in-memory sink), so the
 * offline/local path is unchanged.
 *
 * `ctx.waitUntil` keeps the invocation alive until the write lands. Hono throws
 * from `executionCtx` when there is none (a plain `app.fetch(request, env)` in
 * a unit test); the write is already in flight by then and settles on its own,
 * so that case is caught and ignored rather than turned into a request failure.
 * A guardrail that returned 500 because its evidence queue was busy would have
 * turned a compliance feature into an outage.
 */
function evidenceFlusher(c: Context, evidence: GuardrailEvidenceSink, env: unknown): () => void {
  if (typeof evidence.flush !== "function") return () => {};
  const flush = evidence.flush.bind(evidence);
  return () => {
    const work = flush({ env });
    try {
      c.executionCtx.waitUntil(work);
    } catch {
      // No ExecutionContext on this invocation — see the docblock.
    }
  };
}

/**
 * Re-run `flush` when a screened SSE body ends.
 *
 * `stream.ts` evaluates once per frame, so the row that records what a stream
 * actually decided is appended AFTER the middleware's own `finally` has already
 * run. Without this the last (and only interesting) evidence for every streamed
 * request would sit in the buffer until some later request happened to flush
 * it — or be lost with the isolate.
 *
 * An identity `transform` with a `flush` hook is the cheapest way to observe
 * end-of-stream: it copies no bytes and adds no buffering, and `flush` fires on
 * normal completion. A cancelled stream (the client hung up) does not reach it,
 * which is correct — the invocation is being torn down and `waitUntil` on a
 * dead context would throw.
 */
function flushWhenStreamEnds(body: ReadableStream, onEnd: () => void): ReadableStream {
  return body.pipeThrough(
    new TransformStream({
      transform(chunk, controller) {
        controller.enqueue(chunk);
      },
      flush() {
        onEnd();
      },
    }),
  );
}

const DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

/** The FerroGate error envelope — byte-identical to `inference/errors.ts`. */
function errorEnvelope(code: string, message: string, requestId: string): string {
  return JSON.stringify({
    error: { message, type: "ferrogate_error", code, request_id: requestId },
  });
}

/** `write_json_error(session, FORBIDDEN, guardrail.code, guardrail.message, request_id)`. */
export function guardrailBlockedResponse(match: GuardrailMatch, requestId: string): Response {
  const body = errorEnvelope(match.code, match.message, requestId);
  return new Response(body, {
    status: 403,
    headers: {
      "content-type": "application/json",
      "content-length": String(new TextEncoder().encode(body).byteLength),
      "x-request-id": requestId,
      "x-trace-id": requestId,
      "x-ferrogate-runtime": "workers",
    },
  });
}

// ---------------------------------------------------------------------------
// The middleware
// ---------------------------------------------------------------------------

export function guardrails(
  deps: GuardrailMiddlewareOptions | GuardrailDepsResolver,
): MiddlewareHandler {
  let cachedEnv: unknown;
  let cachedResolution: Promise<[GuardrailMiddlewareOptions, GuardrailEngine]> | undefined;

  /**
   * One resolution per `env` object, memoized as the PROMISE rather than as its
   * value. Two concurrent first requests would otherwise each start a durable
   * policy load; sharing the promise means one load and one compiled engine,
   * which also keeps a `CustomHttpDetector`'s bulkhead/circuit state shared
   * across the isolate exactly as the Rust's single `Arc<dyn GuardrailDetector>`
   * did. A REJECTED promise is dropped from the cache so the next request
   * retries instead of inheriting a permanent failure.
   */
  const resolve = async (
    env: Record<string, unknown>,
  ): Promise<[GuardrailMiddlewareOptions, GuardrailEngine]> => {
    if (typeof deps !== "function") {
      cachedResolution ??= Promise.resolve<[GuardrailMiddlewareOptions, GuardrailEngine]>([
        deps,
        new GuardrailEngine(deps),
      ]);
      return cachedResolution;
    }
    if (cachedResolution === undefined || cachedEnv !== env) {
      cachedEnv = env;
      const pending = Promise.resolve(deps(env)).then(
        (options): [GuardrailMiddlewareOptions, GuardrailEngine] => [
          options,
          new GuardrailEngine(options),
        ],
      );
      pending.catch(() => {
        if (cachedResolution === pending) {
          cachedResolution = undefined;
          cachedEnv = undefined;
        }
      });
      cachedResolution = pending;
    }
    return cachedResolution;
  };

  // NAMED, not an arrow: `GATEWAY_MIDDLEWARE` is asserted structurally by
  // runtime handler name (`test/metering/wiring.test.ts` for the drain,
  // `test/attribution/enforcement.test.ts` for #678's position between
  // admission and screening), and an anonymous handler is invisible to that
  // gate — which is how a REORDERING, the one defect no behavioural test can
  // see, would slip through.
  return async function guardrailsMiddleware(c: Context, next: Next) {
    const inbound = c.req.raw;
    const operationId = (c.get("operation") as { operationId?: string } | null)?.operationId;
    const binding = operationId === undefined ? undefined : GUARDRAIL_OPERATIONS[operationId];
    if (binding === undefined) {
      return next();
    }

    const env = (c.env ?? {}) as Record<string, unknown>;
    const [options, engine] = await resolve(env);
    // Buffered evidence reaches D1/the Queue here, never on the hot path.
    // `finally` so a 403 block, a pass-through and a thrown error all land it.
    const flushEvidence = evidenceFlusher(c, options.evidence, env);
    const requestId = (c.get("requestId") as string | undefined) ?? "";
    try {
      const tenant = tenantFrom(c);
      const gatewayConfigId = gatewayConfigIdFrom(c);

      let context: GuardrailEvaluationContext;
      let plan: ReturnType<GuardrailEngine["streamingGuardrailPlan"]>;

      if (binding.screensRequest) {
        const body = await readJsonBodyBounded(
          c.req.raw,
          options.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES,
        );
        if (body === undefined) {
          // Not JSON, or over the cap: the downstream reader owns the 400/413. A
          // guardrail cannot screen what it cannot parse, and inventing a verdict
          // here would shadow the correct error code.
          return next();
        }

        const model = typeof body.model === "string" ? body.model : undefined;
        const provider = model !== undefined ? options.providerForModel?.(model, env) : undefined;
        const streaming = body.stream === true;

        const screenedBody =
          operationId === "createMessage" && options.translateAnthropicRequest !== undefined
            ? (options.translateAnthropicRequest(body) ?? body)
            : body;

        context = {
          requestId,
          tenant,
          ...(tenant.apiKeyId !== undefined ? { actorApiKeyId: tenant.apiKeyId } : {}),
          ...(gatewayConfigId !== undefined ? { gatewayConfigId } : {}),
          ...(model !== undefined ? { model } : {}),
          ...(provider !== undefined ? { provider } : {}),
          streaming,
          envelope: normalizeRequest(binding.protocol, screenedBody),
        };

        // ---- INPUT screening -----------------------------------------------
        const requestMatch = await engine.matchGuardrail("request", context);
        if (requestMatch !== null) {
          await auditBlock(options.audit, context, requestMatch, "request");
          recordGuardrailVerdict(c, "blocked", requestMatch);
          // Any match — deny OR redact — refuses. See the module doc.
          return guardrailBlockedResponse(requestMatch, requestId);
        }
        // Screening RAN and passed. The request log distinguishes this from
        // `not_screened` (#664): the early `return next()` paths above — an
        // operation no policy binds, a body that could not be parsed — leave the
        // verdict unset, and recording those as "allowed" would tell an auditor a
        // control ran when none did.
        recordGuardrailVerdict(c, "allowed");

        // A `reject_streaming` policy denies a streaming request before dispatch;
        // `matchGuardrail` above already produced that verdict, so by here the plan
        // only distinguishes enforcement from shadow.
        plan = engine.streamingGuardrailPlan(context);

        publishConversationReplayScreener(inbound, {
          policyRevisionMarker: engine.policyRevisionMarker(context),
          screen: async ({ requestId: replayId, input, response }) => {
            const replayRequestContext: GuardrailEvaluationContext = {
              ...context,
              requestId: replayId,
              streaming: false,
              envelope: normalizeRequest("responses", { input }),
            };
            const requestMatch = await engine.matchGuardrail("request", replayRequestContext);
            if (requestMatch !== null) {
              await auditBlock(
                options.audit,
                replayRequestContext,
                requestMatch,
                "conversation replay",
              );
              recordGuardrailVerdict(c, "blocked", requestMatch);
              return { ok: false, code: requestMatch.code, message: requestMatch.message };
            }

            const replayContext: GuardrailEvaluationContext = {
              ...context,
              requestId: replayId,
              streaming: false,
              envelope: normalizeResponse(
                "responses",
                new TextEncoder().encode(JSON.stringify(response)),
                false,
              ),
            };
            const match = await engine.matchGuardrail("response", replayContext);
            if (match === null) return { ok: true, response };
            if (match.effect === "deny") {
              await auditBlock(options.audit, replayContext, match, "conversation replay");
              recordGuardrailVerdict(c, "blocked", match);
              return { ok: false, code: match.code, message: match.message };
            }

            const redactedText = redactText(match, JSON.stringify(response));
            try {
              const redacted: unknown = JSON.parse(redactedText);
              if (typeof redacted !== "object" || redacted === null || Array.isArray(redacted)) {
                return {
                  ok: false,
                  code: "guardrail_invalid_redaction",
                  message: "guardrail could not redact a stored conversation turn safely",
                };
              }
              await options.audit?.record({
                requestId: replayId,
                tenant: replayContext.tenant,
                action: "guardrail.redact",
                target: evidenceTarget(match),
                outcome: "redacted",
                message: `guardrail ${match.ruleName} redacted conversation replay at ${evidenceLocation(match)}`,
              });
              return { ok: true, response: redacted as Record<string, unknown> };
            } catch {
              return {
                ok: false,
                code: "guardrail_invalid_redaction",
                message: "guardrail could not redact a stored conversation turn safely",
              };
            }
          },
        });

        await next();
      } else {
        // ---- NO input screening (issues #703, #689) -------------------------
        //
        // The two audio uploads and `getResponse`. The audio bodies are
        // `multipart/form-data` wrapping opaque audio and a GET has no body at
        // all, so in neither case is there anything to hand a detector — and the
        // difference between this branch and "evaluate an empty envelope" is the
        // entire reason the branch exists: an empty envelope passes every check,
        // buffers an evidence row, and records `allowed`, which tells an auditor
        // a control read content that no detector ever saw. Nothing is recorded
        // here; the verdict is written after the RESPONSE stage, by whatever the
        // response stage actually decided.
        //
        // The body is not read at all, not even to find `model`. Reading it
        // would either duplicate the bounded multipart parse `readAudioUpload`
        // already performs (a second full copy of the upload, in a 128 MiB
        // isolate) or race it for the same stream. So the model and provider —
        // which policy SCOPE selection keys on — are taken after `next()` from
        // the facts the inference route publishes for the request log (#664),
        // which is the seam that already crosses the inner/outer Hono boundary.
        //
        // For `getResponse` those facts are ABSENT (a stored read dispatches to
        // no provider), so a model- or provider-scoped policy does not select
        // for it — the same fail-open-on-SELECTION the module doc states for a
        // missing `providerForModel`. The scope that matters for the leak this
        // binding closes is `api_key_ids`, which comes off `auth` above and is
        // always present.
        await next();

        const facts = requestLogFactsFor(c.req.raw);
        context = {
          requestId,
          tenant,
          ...(tenant.apiKeyId !== undefined ? { actorApiKeyId: tenant.apiKeyId } : {}),
          ...(facts.logicalModel !== undefined ? { model: facts.logicalModel } : {}),
          ...(facts.provider !== undefined ? { provider: facts.provider } : {}),
          ...(gatewayConfigId !== undefined ? { gatewayConfigId } : {}),
          streaming: false,
          // Empty by construction — `normalizeRequest` extracts nothing from
          // `{}` for `audio_transcription` or for `responses`. It is here only
          // so the response stage has a context to extend, and it is NEVER
          // evaluated.
          envelope: normalizeRequest(binding.protocol, {}),
        };
        plan = engine.streamingGuardrailPlan(context);
      }

      // The inference route REPLACES the request id
      // (`inference/handlers.ts:1190`), and from here on the client's id is the
      // join key: it is what `x-request-id` carries and what `request_logs`
      // records. The request-stage evidence already buffered is re-keyed onto
      // it, and the response-stage evidence below is built with it. Without
      // this, `GET /admin/v1/investigations?request_id=<the id the client was
      // told>` would find the request log and NOT the screening that produced
      // it — i.e. would report that a screened request was never screened.
      // See `GuardrailEvidenceSink.recorrelate`.
      //
      // It is read off the RESPONSE HEADER, not off `c.get("requestId")`,
      // because the inference router runs in a SEPARATE Hono app
      // (`route-module.ts` delegates with `inner.fetch(c.req.raw, …)`) and its
      // `c.set(...)` is invisible out here — the same isolation
      // `requestlog/facts.ts` exists to bridge. The header is what the client
      // was actually told, which is the definition of the join key.
      const settledRequestId =
        c.res?.headers.get("x-request-id") ??
        (c.get("requestId") as string | undefined) ??
        requestId;
      options.evidence.recorrelate?.(requestId, settledRequestId);
      const settledContext: GuardrailEvaluationContext = {
        ...context,
        requestId: settledRequestId,
      };

      // ---- OUTPUT screening ------------------------------------------------
      //
      // For a `screensRequest: false` binding (#703) EVERY early return below
      // leaves the request-log verdict unset, and that is the correct reading:
      // nothing screened this request at either stage, so `not_screened` is
      // exactly what an auditor should see. The `allowed` verdict for those
      // operations is written at one place only — after a response screen that
      // really ran and really passed.
      const response = c.res;
      if (!binding.screensResponse || response === undefined || response.body === null) {
        return;
      }
      if (response.status >= 400) {
        // A provider/gateway error body is not model content; the Rust screened
        // the response only on the success path.
        return;
      }

      const contentType = response.headers.get("content-type") ?? "";
      const isSse = contentType.includes("text/event-stream");

      if (isSse) {
        if (plan === "none") {
          return;
        }
        if (plan === "shadow_after_complete") {
          // Pass through untouched; the engine records `not_enforced` evidence.
          //
          // PORT-TODO(L: inventory-request-path §streaming shadow): a DELIBERATE
          // approximation, and the difference is observable in evidence only.
          // The Rust captured the whole streamed body and evaluated it ONCE at
          // completion. Reproducing that literally would mean buffering an SSE
          // response in a Worker — unbounded memory on a 128 MiB isolate, and the
          // first-token latency this whole port exists to preserve — so
          // `shadow_after_complete` here reuses the INCREMENTAL screener with
          // enforcement suppressed by `effectiveShadow`.
          //
          // What is identical: the bytes the client receives (untouched, in the
          // same order, at the same time) and the enforcement decision (none —
          // shadow never blocks). What differs: the evidence row is decided from
          // the frame that first matched rather than from the assembled document,
          // so a finding that only exists ACROSS a frame boundary is not seen.
          // Evidence is UPSERTED by evaluation id (`evidence.ts`), so a shadow
          // stream still produces exactly ONE row per policy, not one per frame.
          c.res = new Response(
            // A stream's evidence is appended per FRAME, long after this
            // middleware's own `finally` has run — so the flush is re-armed on
            // end-of-body. See {@link flushWhenStreamEnds}.
            flushWhenStreamEnds(
              screenSseBody(response.body, {
                engine,
                context: { ...settledContext, streaming: true },
                dialect: binding.dialect,
                protocol: binding.protocol,
                requestId: settledRequestId,
              }),
              flushEvidence,
            ),
            response,
          );
          return;
        }
        c.res = new Response(
          flushWhenStreamEnds(
            screenSseBody(response.body, {
              engine,
              context: { ...settledContext, streaming: true },
              dialect: binding.dialect,
              protocol: binding.protocol,
              requestId: settledRequestId,
              onOutcome: (outcome) => {
                if (outcome.kind === "blocked") {
                  void auditBlock(options.audit, context, outcome.match, "response.stream");
                  // Mid-stream block. The request log is written when the body
                  // settles (`requestlog/middleware.ts`), so this lands in time.
                  recordGuardrailVerdict(c, "blocked", outcome.match);
                }
              },
            }),
            flushEvidence,
          ),
          response,
        );
        return;
      }

      // Non-streaming response.
      const raw = await readBytesBounded(
        response,
        options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
      );
      if (raw === undefined) {
        await engine.recordStreamCaptureOverflow({ ...settledContext, streaming: false });
        return;
      }
      const responseContext: GuardrailEvaluationContext = {
        ...settledContext,
        streaming: false,
        envelope: normalizeResponse(binding.protocol, raw, false),
      };
      const responseMatch = await engine.matchGuardrail("response", responseContext);
      if (responseMatch === null) {
        // #703. The ONLY place a response-only binding earns `allowed`: a
        // response stage that ran, over an envelope built from real bytes, and
        // decided nothing matched. For a request-screened binding the verdict is
        // already `allowed` from the input stage and this is a no-op.
        recordGuardrailVerdict(c, "allowed");
        c.res = new Response(raw, response);
        return;
      }
      if (responseMatch.effect === "deny") {
        await auditBlock(options.audit, responseContext, responseMatch, "response");
        recordGuardrailVerdict(c, "blocked", responseMatch);
        c.res = guardrailBlockedResponse(responseMatch, settledRequestId);
        return;
      }
      const redacted = redactText(responseMatch, new TextDecoder().decode(raw));
      await options.audit?.record({
        requestId: settledRequestId,
        tenant,
        action: "guardrail.redact",
        target: evidenceTarget(responseMatch),
        outcome: "redacted",
        message: `guardrail ${responseMatch.ruleName} redacted response at ${evidenceLocation(responseMatch)}`,
      });
      c.res = new Response(redacted, response);
    } finally {
      flushEvidence();
    }
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function auditBlock(
  audit: GuardrailAuditSink | undefined,
  context: GuardrailEvaluationContext,
  match: GuardrailMatch,
  where: string,
): Promise<void> {
  await audit?.record({
    requestId: context.requestId,
    ...(context.traceId !== undefined ? { traceId: context.traceId } : {}),
    ...(context.actorApiKeyId !== undefined ? { actorApiKeyId: context.actorApiKeyId } : {}),
    tenant: context.tenant,
    action: "guardrail.deny",
    target: evidenceTarget(match),
    outcome: "blocked",
    message: `guardrail ${match.ruleName} blocked ${where} for model ${context.model ?? "unknown"} at ${evidenceLocation(match)}`,
  });
}

/** `AuthContext` → the guardrail tenancy tuple. */
export function tenantFrom(c: Context): GuardrailTenant {
  const auth = c.get("auth") as
    | {
        subject?: string | null;
        tenancy?: {
          tenantId?: string | null;
          projectId?: string | null;
          workspaceId?: string | null;
          userId?: string | null;
        };
      }
    | null
    | undefined;
  if (auth === null || auth === undefined) {
    return {};
  }
  const tenancy = auth.tenancy ?? {};
  return {
    ...(tenancy.tenantId ? { organizationId: tenancy.tenantId } : {}),
    ...(tenancy.projectId ? { projectId: tenancy.projectId } : {}),
    ...(tenancy.workspaceId ? { workspaceId: tenancy.workspaceId } : {}),
    ...(tenancy.userId ? { userId: tenancy.userId } : {}),
    ...(auth.subject ? { apiKeyId: auth.subject } : {}),
  };
}

/** The authenticated request's gateway profile, when one was selected. */
export function gatewayConfigIdFrom(c: Context): string | undefined {
  const value = c.req.header(GATEWAY_CONFIG_HEADER)?.trim();
  return value === undefined || value === "" ? undefined : value;
}

/**
 * Read the request body for screening WITHOUT consuming it.
 *
 * `Request.clone()` tees the body in workerd, so `c.req.arrayBuffer()`
 * downstream still sees the original bytes and `c.req.bodyCache` is untouched.
 * Returns `undefined` for a non-object body, unparsable JSON, or a body over
 * `max` — in every one of those cases the downstream reader owns the error.
 */
async function readJsonBodyBounded(
  request: Request,
  max: number,
): Promise<Record<string, unknown> | undefined> {
  if (request.body === null) {
    return undefined;
  }
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    const length = Number.parseInt(declared, 10);
    if (Number.isFinite(length) && length > max) {
      return undefined;
    }
  }
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(await request.clone().arrayBuffer());
  } catch {
    return undefined;
  }
  if (bytes.byteLength > max) {
    return undefined;
  }
  try {
    const parsed: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes),
    );
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

/** Buffered response read with a hard cap; `undefined` means "over the cap". */
async function readBytesBounded(response: Response, max: number): Promise<Uint8Array | undefined> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const length = Number.parseInt(declared, 10);
    if (Number.isFinite(length) && length > max) {
      return undefined;
    }
  }
  const bytes = new Uint8Array(await response.clone().arrayBuffer());
  return bytes.byteLength > max ? undefined : bytes;
}
