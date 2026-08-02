/**
 * The GenAI OBSERVATION seam (#669) — how a `gen_ai.*` fact gets from the
 * inference handler to the span builder.
 *
 * ## The problem this exists to solve
 *
 * The two places that emit telemetry — `src/telemetry/middleware.ts` (all 31
 * operations) and `src/inference/route-module.ts` (the six inference ones) —
 * are OUTSIDE the inference handler. Both see only a `Request` and a
 * `Response`, and neither of those carries the model, the provider kind or the
 * token counts:
 *
 *  - the logical model is in the request BODY, which the outer layers must not
 *    re-read (it has already been consumed, and re-buffering it on the request
 *    path is exactly the cost the streaming design avoids);
 *  - the PHYSICAL model and provider kind are decided by routing/failover
 *    inside the handler and appear in no header;
 *  - the token counts come from the provider's usage frame, which for a
 *    buffered response is parsed inside the handler and for an SSE response
 *    arrives after the headers are already on the wire.
 *
 * So the handler has to hand the facts outward. This module is that hand-off,
 * and it deliberately reuses the pattern `src/inference/identity.ts` already
 * established for the same boundary: a `WeakMap` keyed on the INBOUND `Request`
 * object.
 *
 * ## Why keyed on the `Request` object and not on the request id
 *
 * `inferenceRouteModule` calls `inner.fetch(c.req.raw, …)`, so the inner Hono
 * app's `c.req.raw` is the SAME object as the outer one — that identity is what
 * makes `inferenceRequestScope` work today and it is what makes this work. A
 * `Map` keyed on the request-id STRING would be wrong twice over: nothing
 * evicts it, so a long-lived isolate leaks one entry per request forever, and
 * the inner handler mints its own `fg-…` id that the outer middleware does not
 * know, so the two halves would not even meet. A `WeakMap` entry dies with the
 * request that owns it and needs no cleanup path to forget.
 *
 * ## Merge semantics, and why they matter for streaming
 *
 * {@link observeGenAiInvocation} MERGES into whatever is already recorded for
 * the request. That is not convenience — it is the only way a streaming request
 * gets a model at all:
 *
 *  - the handler records the routing facts (operation, provider, both models)
 *    as soon as dispatch resolves, which is BEFORE the response object exists;
 *  - it records the token counts when the provider's usage frame is parsed,
 *    which for a BUFFERED response is still before the handler returns, and for
 *    an SSE response is after the telemetry emission has already happened.
 *
 * The consequence is stated rather than hidden: **a streamed request's span
 * carries the model and provider but no `gen_ai.usage.*`**. Holding the span
 * open until the stream ends would mean holding the emission past the client's
 * last byte, and the metering path already owns the "settle after the stream"
 * job (`src/metering/middleware.ts`) with a durable destination. Emitting a
 * token-less span now is better than emitting a complete one late, and far
 * better than emitting zeros: a `0` would be indistinguishable from an empty
 * completion and would drag every downstream average down.
 */
import {
  GenAiOperationName,
  type GenAiInvocation,
  genAiProviderName,
} from "@ferrogate/observability";

/**
 * The facts a handler contributes. Everything is optional because the two
 * recording points know different halves — see the merge note in the module
 * docs.
 */
export interface GenAiObservation {
  readonly operationName?: string | undefined;
  /** The FerroGate provider KIND (`openai`, `bedrock`, …), not a semconv name. */
  readonly providerKind?: string | undefined;
  readonly requestModel?: string | undefined;
  readonly responseModel?: string | undefined;
  readonly inputTokens?: number | undefined;
  readonly outputTokens?: number | undefined;
}

/** Accumulated observations, one entry per in-flight inbound `Request`. */
const OBSERVED = new WeakMap<Request, GenAiObservation>();

/**
 * `Usage.route` (`openai.chat.completions`, `anthropic.messages`, …) →
 * `gen_ai.operation.name`.
 *
 * Keyed on the ROUTE LABEL rather than on the contract operation id because the
 * label is what `Usage` already carries, so the mapping has one input and no
 * chance of disagreeing with what metering recorded for the same request.
 *
 * An unmapped label yields `undefined` rather than a guess: a span with a
 * fabricated `gen_ai.operation.name` is worse than a span without one, because
 * the spec makes the attribute REQUIRED and a backend will trust it.
 */
export function genAiOperationForRouteLabel(routeLabel: string): string | undefined {
  switch (routeLabel) {
    // `/v1/responses` is an inference call that returns a chat-shaped
    // completion; the spec has no `responses` value, and `chat` is the
    // predefined one that applies.
    case "openai.chat.completions":
    case "openai.responses":
    case "anthropic.messages":
      return GenAiOperationName.Chat;
    case "openai.embeddings":
      return GenAiOperationName.Embeddings;
    case "openai.images.generations":
      return GenAiOperationName.GenerateContent;
    default:
      // `openai.models` (a catalog listing) reaches no model and must not
      // produce a GenAI span; so must any label added later without a decision
      // being made here.
      return undefined;
  }
}

/** Record (and merge) what this request now knows about its GenAI operation. */
export function observeGenAiInvocation(request: Request, observation: GenAiObservation): void {
  const previous = OBSERVED.get(request);
  OBSERVED.set(request, previous === undefined ? observation : merge(previous, observation));
}

/**
 * Later non-`undefined` values win, and an `undefined` never erases a value the
 * earlier observation supplied. That asymmetry is the point: the token-counting
 * call passes no routing facts and must not blank them.
 */
function merge(previous: GenAiObservation, next: GenAiObservation): GenAiObservation {
  return {
    operationName: next.operationName ?? previous.operationName,
    providerKind: next.providerKind ?? previous.providerKind,
    requestModel: next.requestModel ?? previous.requestModel,
    responseModel: next.responseModel ?? previous.responseModel,
    inputTokens: next.inputTokens ?? previous.inputTokens,
    outputTokens: next.outputTokens ?? previous.outputTokens,
  };
}

/**
 * The accumulated observation as a semconv {@link GenAiInvocation}, or
 * `undefined` when this request reached no model.
 *
 * `undefined` is returned unless BOTH an operation name and a request model are
 * known, and that is a deliberate floor rather than defensiveness:
 * `gen_ai.operation.name` and `gen_ai.request.model` are the two attributes
 * every GenAI metric keys on, and a point published with either one empty
 * becomes a permanent empty series in whatever backend receives it.
 *
 * `durationSeconds` and `errorType` are the CALLER's to supply — only the
 * telemetry layer knows the wall-clock bounds and the status the client was
 * finally served.
 */
export function genAiInvocationFor(
  request: Request,
  timing: {
    readonly durationSeconds?: number | undefined;
    readonly errorType?: string | undefined;
  },
): GenAiInvocation | undefined {
  const observed = OBSERVED.get(request);
  if (observed?.operationName === undefined || observed.requestModel === undefined) {
    return undefined;
  }
  return {
    operationName: observed.operationName,
    // An observation with no provider kind cannot happen today (both are
    // recorded together), but mapping `""` would publish an empty provider
    // rather than throwing, and an empty string is a series nobody can read.
    providerName: genAiProviderName(observed.providerKind ?? ""),
    requestModel: observed.requestModel,
    ...(observed.responseModel === undefined ? {} : { responseModel: observed.responseModel }),
    ...(observed.inputTokens === undefined ? {} : { inputTokens: observed.inputTokens }),
    ...(observed.outputTokens === undefined ? {} : { outputTokens: observed.outputTokens }),
    ...(timing.durationSeconds === undefined ? {} : { durationSeconds: timing.durationSeconds }),
    ...(timing.errorType === undefined ? {} : { errorType: timing.errorType }),
  };
}
