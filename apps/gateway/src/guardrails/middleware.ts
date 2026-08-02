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
import { contributeRequestLogFacts, requestLogFactsFor } from "../requestlog/facts.js";
import type { GuardrailVerdict } from "../requestlog/record.js";
import { GuardrailEngine, evidenceLocation, evidenceTarget, redactText } from "./engine.js";
import type {
  GuardrailAuditSink,
  GuardrailEngineDeps,
  GuardrailEvaluationContext,
  GuardrailMatch,
  GuardrailTenant,
} from "./ports.js";
import { type StreamDialect, screenSseBody } from "./stream.js";

/** The inference operations guardrails apply to, and how each normalizes. */
interface OperationBinding {
  readonly protocol: GuardrailProtocol;
  readonly dialect: StreamDialect;
  /** Response normalization is only defined for chat/responses (see `normalizeResponse`). */
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
    screensResponse: true,
  },
  createResponse: {
    protocol: "responses",
    dialect: "openai.responses",
    screensResponse: true,
  },
  createMessage: {
    protocol: "chat_completions",
    dialect: "anthropic.messages",
    screensResponse: true,
  },
  // Embeddings/Images are REQUEST-only: `normalize_response` returns an empty
  // envelope for them (`envelope.ts`), matching the Rust.
  createEmbedding: { protocol: "embeddings", dialect: "openai.chat", screensResponse: false },
  createImage: { protocol: "images", dialect: "openai.chat", screensResponse: false },
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

  return async (c: Context, next: Next) => {
    const operationId = (c.get("operation") as { operationId?: string } | null)?.operationId;
    const binding = operationId === undefined ? undefined : GUARDRAIL_OPERATIONS[operationId];
    if (binding === undefined) {
      return next();
    }

    const env = (c.env ?? {}) as Record<string, unknown>;
    const [options, engine] = await resolve(env);
    const requestId = (c.get("requestId") as string | undefined) ?? "";
    const tenant = tenantFrom(c);

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

    const context: GuardrailEvaluationContext = {
      requestId,
      tenant,
      ...(tenant.apiKeyId !== undefined ? { actorApiKeyId: tenant.apiKeyId } : {}),
      ...(model !== undefined ? { model } : {}),
      ...(provider !== undefined ? { provider } : {}),
      streaming,
      envelope: normalizeRequest(binding.protocol, screenedBody),
    };

    // ---- INPUT screening -------------------------------------------------
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
    const plan = engine.streamingGuardrailPlan(context);

    await next();

    // ---- OUTPUT screening ------------------------------------------------
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
          screenSseBody(response.body, {
            engine,
            context: { ...context, streaming: true },
            dialect: binding.dialect,
            protocol: binding.protocol,
            requestId,
          }),
          response,
        );
        return;
      }
      c.res = new Response(
        screenSseBody(response.body, {
          engine,
          context: { ...context, streaming: true },
          dialect: binding.dialect,
          protocol: binding.protocol,
          requestId,
          onOutcome: (outcome) => {
            if (outcome.kind === "blocked") {
              void auditBlock(options.audit, context, outcome.match, "response.stream");
              // Mid-stream block. The request log is written when the body
              // settles (`requestlog/middleware.ts`), so this lands in time.
              recordGuardrailVerdict(c, "blocked", outcome.match);
            }
          },
        }),
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
      await engine.recordStreamCaptureOverflow({ ...context, streaming: false });
      return;
    }
    const responseContext: GuardrailEvaluationContext = {
      ...context,
      streaming: false,
      envelope: normalizeResponse(binding.protocol, raw, false),
    };
    const responseMatch = await engine.matchGuardrail("response", responseContext);
    if (responseMatch === null) {
      c.res = new Response(raw, response);
      return;
    }
    if (responseMatch.effect === "deny") {
      await auditBlock(options.audit, responseContext, responseMatch, "response");
      recordGuardrailVerdict(c, "blocked", responseMatch);
      c.res = guardrailBlockedResponse(responseMatch, requestId);
      return;
    }
    const redacted = redactText(responseMatch, new TextDecoder().decode(raw));
    await options.audit?.record({
      requestId,
      tenant,
      action: "guardrail.redact",
      target: evidenceTarget(responseMatch),
      outcome: "redacted",
      message: `guardrail ${responseMatch.ruleName} redacted response at ${evidenceLocation(responseMatch)}`,
    });
    c.res = new Response(redacted, response);
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
