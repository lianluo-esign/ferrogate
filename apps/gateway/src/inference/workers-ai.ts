/**
 * The `env.AI` transport for the `workers-ai` provider family (issue #673).
 *
 * `WorkersAiAdapter` (`@ferrogate/providers`) prepares a REAL Workers AI REST
 * request — `POST https://api.cloudflare.com/client/v4/accounts/<id>/ai/run/
 * <model>` with the task-shaped native body. This module is the other half:
 * an {@link UpstreamDispatcher} that recognises that request and serves it
 * through the Worker's `AI` binding instead of opening a socket, then rebuilds
 * the OpenAI-shaped answer the gateway contract owes the client.
 *
 * ## Why the dispatcher, and not the adapter, does the response translation
 *
 * `ProviderAdapter` is pure, synchronous and REQUEST-shaped: it has exactly one
 * response seam (`translateEmbeddingsResponse`) and no seam at all for a chat
 * response or a stream. That is not an oversight in the port — every other
 * family's upstream already answers in an OpenAI-compatible or
 * separately-normalized dialect. Workers AI's run surface does not, so the
 * translation has to happen where the `Response` actually exists, which is the
 * dispatcher. Embeddings are the exception and deliberately go the other way:
 * this module hands the native `{ shape, data }` body straight through and the
 * adapter's existing `translateEmbeddingsResponse` converts it, exactly as it
 * does for Gemini and Vertex.
 *
 * ## Fail-closed when the binding is absent
 *
 * A `workers-ai` route on a Worker with no `[ai]` binding answers a synthesized
 * 503 naming the missing stanza ({@link unboundBindingResponse}). It
 * deliberately does not fall back to the REST endpoint: that would need an API
 * token nobody configured, and silently egressing (and paying for) a request an
 * operator asked to keep on-platform is worse than a loud failure. Same posture
 * `bedrock`/`vertex` take when their credential is missing.
 *
 * ## What is NOT here
 *
 * Workers AI's task-typed surfaces other than text-generation, text-embeddings
 * and reranking — text classification (`{ text }` → `[{ label, score }]`),
 * image generation — have no ingress operation in the gateway contract to carry
 * them, so there is no code for them here. (Reranking left this list with issue
 * #676, which added `POST /v1/rerank`; see {@link runOnBinding}.) The one
 * classification path FerroGate actually uses on-platform today is the
 * Llama-Guard guardrail detector, which is chat-shaped and already mounted
 * (`src/guardrails/config.ts` → `@ferrogate/guardrails`'
 * `workersAiBindingClient`). Adding a `prepareClassification` with no caller
 * would be dead code.
 */
import { WORKERS_AI_RUN_PATH_SEGMENT } from "@ferrogate/providers";
import type { InferenceBindings, UpstreamDispatcher, UpstreamRequest } from "./ports.js";

/**
 * The slice of the native `env.AI` binding this module uses.
 *
 * Declared structurally rather than imported from `@cloudflare/workers-types`,
 * for the same reason `@ferrogate/guardrails`' `WorkersAiBinding` is: the real
 * binding is assignable to it, and a test double can be too. The two
 * declarations are intentionally the same shape — one Worker, one binding.
 */
export interface WorkersAiBinding {
  run(model: string, input: Record<string, unknown>, options?: unknown): Promise<unknown>;
}

/** The binding name in `wrangler.toml`'s `[ai]` stanza. */
export const WORKERS_AI_BINDING = "AI";

/**
 * Is this prepared request one `WorkersAiAdapter` built?
 *
 * Matched on the PATH, not on a provider name or a sentinel scheme: the path is
 * what the adapter and Cloudflare's own API agree on, and
 * `WORKERS_AI_RUN_PATH_SEGMENT` is exported from the adapter module so the two
 * halves cannot drift. `UpstreamRequest` carries no `providerKind` — matching on
 * `request.provider` would match an operator's arbitrary provider NAME, which is
 * not the same thing at all.
 */
export function workersAiModelOf(request: UpstreamRequest): string | null {
  let url: URL;
  try {
    url = new URL(request.endpoint);
  } catch {
    return null;
  }
  const marker = url.pathname.indexOf(WORKERS_AI_RUN_PATH_SEGMENT);
  if (marker < 0) {
    return null;
  }
  const model = url.pathname.slice(marker + WORKERS_AI_RUN_PATH_SEGMENT.length);
  return model.length > 0 ? model : null;
}

/**
 * Wrap `inner` so that Workers AI requests go through `ai` and everything else
 * is dispatched unchanged.
 *
 * Composition rather than replacement matters: a deployment mixes a
 * `workers-ai` route with OpenAI/Anthropic routes in one failover ladder, and
 * the SAME dispatcher instance serves every attempt.
 */
export function workersAiDispatcher(
  ai: WorkersAiBinding | undefined,
  inner: UpstreamDispatcher,
): UpstreamDispatcher {
  return {
    async dispatch(request: UpstreamRequest, signal?: AbortSignal): Promise<Response> {
      const model = workersAiModelOf(request);
      if (model === null) {
        return await inner.dispatch(request, signal);
      }
      if (ai === undefined) {
        return unboundBindingResponse(request.provider);
      }
      return await runOnBinding(ai, model, request, signal);
    },
  };
}

/**
 * Resolve the dispatcher for a Worker `env`, wrapping `inner` (the network
 * egress) with the `AI` binding leg.
 *
 * The `AI` binding only exists per request, so this is a FACTORY the router
 * calls once per `env` object (`resolveDeps` in `./defaults.ts`) — the same
 * shape `circuit`, `shadowBudget` and `workflows` already use. `inner` is a
 * parameter rather than a default import of `fetchDispatcher` so this module
 * has no edge back into `./defaults.ts`; the import graph stays acyclic.
 *
 * With no binding the wrapper is STILL installed: a `workers-ai` route must
 * fail with the explicit "requires the AI binding" message rather than being
 * dispatched to `api.cloudflare.com` with no credential and answering an
 * opaque 400 an operator cannot act on.
 */
export function workersAiDispatcherFromEnv(
  env: InferenceBindings,
  inner: UpstreamDispatcher,
): UpstreamDispatcher {
  const ai = env[WORKERS_AI_BINDING] as WorkersAiBinding | undefined;
  return workersAiDispatcher(
    ai !== undefined && typeof ai.run === "function" ? ai : undefined,
    inner,
  );
}

/**
 * The "no `[ai]` binding" answer: a synthesized 503 in CLOUDFLARE'S OWN error
 * envelope, not a thrown exception.
 *
 * Throwing was the first shape and it loses the message. `dispatchUpstream`
 * catches everything an `UpstreamDispatcher` throws and renders
 * `providerTransportMessage(...)` — deliberately a bare failure CLASS
 * (`provider request failed (transport)`) with no detail, because a transport
 * error can carry the operator's credential-bearing URL. An operator staring at
 * that string has no way to learn that a `wrangler.toml` stanza is missing.
 *
 * Answering with a provider-shaped error instead routes through the adapter's
 * `normalizeErrorResponse`, which is the path every real upstream failure
 * takes, so the message survives to the client verbatim and the status is one
 * the ladder already understands. 503, not 4xx: nothing is wrong with the
 * CALLER's request — this deployment cannot serve it.
 */
function unboundBindingResponse(provider: string): Response {
  return new Response(
    JSON.stringify({
      success: false,
      errors: [
        {
          code: 7000,
          message:
            `workers-ai provider '${provider}' requires the ${WORKERS_AI_BINDING} binding; ` +
            "declare [ai] in wrangler.toml",
        },
      ],
    }),
    { status: 503, headers: { "content-type": "application/json" } },
  );
}

// ---------------------------------------------------------------------------
// Binding call + response translation
// ---------------------------------------------------------------------------

async function runOnBinding(
  ai: WorkersAiBinding,
  model: string,
  request: UpstreamRequest,
  signal?: AbortSignal,
): Promise<Response> {
  const input = (request.body ?? {}) as Record<string, unknown>;
  // The binding has no `signal` parameter. A client that hung up before the
  // call started must not spend tokens, so the deadline is honoured at the one
  // point this code can honour it; once `run` is in flight it runs to
  // completion, which is a platform limit, not a policy choice.
  signal?.throwIfAborted();
  const result = await ai.run(model, input);

  if (isReadableStream(result)) {
    return sseResponse(workersAiSseToOpenAi(result, model));
  }
  if (result instanceof Response) {
    // `returnRawResponse`-style answers are relayed as-is. Nothing in this
    // module asks for one today; relaying beats guessing at its body.
    return result;
  }

  const record = asRecord(result);
  // Embeddings: hand the NATIVE body back and let the adapter's
  // `translateEmbeddingsResponse` shape it, which is the seam that already
  // exists for exactly this and is where the Gemini/Vertex translations live.
  if (record !== undefined && Array.isArray(record["data"])) {
    return jsonResponse(record);
  }
  // Rerank (issue #676): same deal, through `translateRerankResponse`.
  //
  // The discriminator is `response` being an ARRAY. That is not a heuristic
  // reaching for a marker — it is the exact difference between the two run
  // surfaces this branch has to tell apart: a text-generation answer is
  // `{ response: "some text" }` and a reranker answer is
  // `{ response: [{ id, score }] }`. Matching on the request body instead
  // (`"contexts" in input`) would work too, but it would put the decision on
  // the request while the ambiguity is in the RESPONSE, so a family that ever
  // grows a third array-shaped surface breaks in the wrong file.
  //
  // Without this arm the reranker's scores fall into `openAiCompletion` below
  // and are rendered as a chat completion whose `content` is `""` — a 200 with
  // an empty answer, which is the worst possible failure for a governance
  // surface: silent, and metered.
  if (record !== undefined && Array.isArray(record["response"])) {
    return jsonResponse(record);
  }
  return jsonResponse(openAiCompletion(record, model));
}

/** `{ response, tool_calls?, usage? }` → an OpenAI `chat.completion` body. */
function openAiCompletion(
  result: Record<string, unknown> | undefined,
  model: string,
): Record<string, unknown> {
  const content = typeof result?.["response"] === "string" ? (result["response"] as string) : "";
  const toolCalls = Array.isArray(result?.["tool_calls"])
    ? (result?.["tool_calls"] as unknown[])
    : undefined;
  const message: Record<string, unknown> = { role: "assistant", content };
  if (toolCalls !== undefined && toolCalls.length > 0) {
    message["tool_calls"] = toolCalls.map((call, index) => openAiToolCall(call, index));
  }
  return {
    id: `chatcmpl-${model}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        message,
        finish_reason: toolCalls !== undefined && toolCalls.length > 0 ? "tool_calls" : "stop",
      },
    ],
    // Passed through verbatim when present: Workers AI already names the three
    // counters the way OpenAI does, so `usageProviderKindFor`'s default
    // (`"openai"`) extractor meters this family with no new arm. Absent usage
    // stays absent rather than becoming zeros — a fabricated zero would be
    // metered as a real reading of "this cost nothing".
    ...(isRecord(result?.["usage"]) ? { usage: result?.["usage"] } : {}),
  };
}

/**
 * Workers AI's native tool call is `{ name, arguments }` with no id and no
 * `function` wrapper; OpenAI's is `{ id, type, function: { name, arguments } }`
 * with `arguments` as a JSON STRING. Both differences are converted here so a
 * client's OpenAI SDK can read the call.
 */
function openAiToolCall(call: unknown, index: number): Record<string, unknown> {
  const record = asRecord(call) ?? {};
  const args = record["arguments"];
  return {
    id: typeof record["id"] === "string" ? record["id"] : `workers_ai_tool_${index}`,
    type: "function",
    function: {
      name: typeof record["name"] === "string" ? record["name"] : "",
      arguments: typeof args === "string" ? args : JSON.stringify(args ?? {}),
    },
  };
}

/**
 * Workers AI native SSE → OpenAI `chat.completion.chunk` SSE.
 *
 * The native stream is `data: {"response":"tok"}` frames followed by
 * `data: [DONE]`, with the token counts riding on a late frame. The OpenAI
 * stream a client (and this gateway's own meter) expects is
 * `chat.completion.chunk` frames, a final `finish_reason: "stop"` chunk, an
 * `include_usage`-style usage-only chunk, and `[DONE]`.
 *
 * The usage chunk is not cosmetic. `src/inference/usage.ts` scrapes the LAST
 * usage frame off the streamed bytes; with none, a streamed request is metered
 * at the 512-token fallback estimate — the token-budget/TPM/wallet bypass that
 * module's header names. So whatever usage the native stream reported is
 * re-emitted in the shape the scraper reads.
 */
export function workersAiSseToOpenAi(
  upstream: ReadableStream<Uint8Array>,
  model: string,
): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8");
  const id = `chatcmpl-${model}`;
  const created = Math.floor(Date.now() / 1000);
  let pending = "";
  let first = true;
  let usage: Record<string, unknown> | undefined;
  let finished = false;

  const chunk = (delta: Record<string, unknown>, finishReason: string | null): string =>
    `data: ${JSON.stringify({
      id,
      object: "chat.completion.chunk",
      created,
      model,
      choices: [{ index: 0, delta, finish_reason: finishReason }],
    })}\n\n`;

  const finish = (controller: TransformStreamDefaultController<Uint8Array>): void => {
    if (finished) return;
    finished = true;
    controller.enqueue(encoder.encode(chunk({}, "stop")));
    if (usage !== undefined) {
      controller.enqueue(
        encoder.encode(
          `data: ${JSON.stringify({
            id,
            object: "chat.completion.chunk",
            created,
            model,
            choices: [],
            usage,
          })}\n\n`,
        ),
      );
    }
    controller.enqueue(encoder.encode("data: [DONE]\n\n"));
  };

  const handleFrame = (
    frame: string,
    controller: TransformStreamDefaultController<Uint8Array>,
  ): void => {
    const payload = sseData(frame);
    if (payload === undefined) return;
    if (payload === "[DONE]") {
      finish(controller);
      return;
    }
    let value: unknown;
    try {
      value = JSON.parse(payload);
    } catch {
      // A frame this gateway cannot parse is DROPPED, not relayed: relaying it
      // would put a non-OpenAI frame in a stream the client was promised is
      // OpenAI-shaped, and its SDK would throw on it.
      return;
    }
    const record = asRecord(value);
    if (record === undefined) return;
    if (isRecord(record["usage"])) {
      usage = record["usage"] as Record<string, unknown>;
    }
    const text = record["response"];
    if (typeof text !== "string" || text.length === 0) return;
    // The role rides on the FIRST delta only, which is the OpenAI framing.
    const delta = first ? { role: "assistant", content: text } : { content: text };
    first = false;
    controller.enqueue(encoder.encode(chunk(delta, null)));
  };

  const transform = new TransformStream<Uint8Array, Uint8Array>({
    transform(bytes, controller) {
      pending += decoder.decode(bytes, { stream: true });
      for (;;) {
        const boundary = pending.indexOf("\n\n");
        if (boundary < 0) break;
        handleFrame(pending.slice(0, boundary), controller);
        pending = pending.slice(boundary + 2);
      }
    },
    flush(controller) {
      pending += decoder.decode();
      if (pending.trim().length > 0) {
        handleFrame(pending, controller);
      }
      finish(controller);
    },
  });

  return upstream.pipeThrough(transform);
}

/** The `data:` payload of one SSE frame, with the single optional space stripped. */
function sseData(frame: string): string | undefined {
  for (const rawLine of frame.split("\n")) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (!line.startsWith("data:")) continue;
    const data = line.slice("data:".length);
    return data.startsWith(" ") ? data.slice(1) : data;
  }
  return undefined;
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function sseResponse(body: ReadableStream<Uint8Array>): Response {
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
    },
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

function isReadableStream(value: unknown): value is ReadableStream<Uint8Array> {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as ReadableStream).getReader === "function"
  );
}
