/**
 * `requestLogging()` — the one place a request-log row is created.
 *
 * ## Why a middleware, and why it is the AUTHORITATIVE leg
 *
 * The obvious place to write a request log is the inference handler, next to
 * the metering record. That would be wrong, and the wrongness is the point of
 * the whole issue: an inference handler only runs for a request that got as far
 * as an inference handler. A request refused by the rate limiter, blocked by a
 * guardrail, rejected for an unknown model or 401'd at the door would leave no
 * evidence at all — and those are the rows an incident review and an audit are
 * actually looking for.
 *
 * So the row is created HERE, from the outer chain, for every request that
 * reaches this middleware, whatever happened downstream. The facts only an
 * inner slice can know (the physical route, the provider model, the token
 * counts, the guardrail verdict) are merged in from `./facts.ts`, and their
 * absence is recorded as absence rather than filled in.
 *
 * ## Position in `GATEWAY_MIDDLEWARE`
 *
 * After `meteringDrain` and `requestTelemetry`, BEFORE `rateLimit` and
 * `guardrails`. Being ahead of those two is what makes a 429 and a 403 land in
 * the trail: this middleware wraps them, so it sees the response they
 * short-circuit with. Being behind the metering drain is deliberate too —
 * money outranks evidence for outermost position, and nothing is lost by
 * sitting one layer in because `meteringDrain` returns the same `Response`
 * object it received.
 *
 * ## Nothing here is in front of a client byte
 *
 * `next()` is awaited (that is how the status and the latency are known) and
 * NOTHING else is. The record is assembled and written inside `ctx.waitUntil`,
 * after the response object exists. For an SSE response the write is deferred
 * again, until the body has been consumed or the client has hung up, because
 * the token counts arrive from the usage tap near the end of the stream — a row
 * written at header time would record every streamed inference request as
 * having used no tokens. Both endings settle
 * (`../middleware/body-completion.ts`), so a mid-stream disconnect still
 * produces a row.
 *
 * A failure anywhere in here is swallowed: `RequestLogSink.write` never
 * rejects, and the assembly itself is wrapped. A gateway that 500s because its
 * audit log was unavailable has turned a compliance control into an outage.
 */
import type { Context, MiddlewareHandler } from "hono";
import { isEventStream, observeBodyCompletion } from "../middleware/body-completion.js";
import { CACHE_STATUS_HEADER } from "../middleware/response-cache.js";
import type { AuthContext, GatewayEnv } from "../ports.js";
import { requestLogFactsFor } from "./facts.js";
import type { RequestLogRecord } from "./record.js";
import type { RequestLogSink } from "./sink.js";

/** `c.executionCtx` without the throw (`app.request()` creates none). */
function executionContextOf(c: {
  executionCtx: { waitUntil(work: Promise<unknown>): void };
}): { waitUntil(work: Promise<unknown>): void } | undefined {
  try {
    return c.executionCtx;
  } catch {
    return undefined;
  }
}

/**
 * The largest error body this middleware will read to recover an `error_code`.
 *
 * A FerroGate error envelope is a few hundred bytes; a provider's upstream
 * error passed through can be larger but is still bounded by the response the
 * client already received. The cap exists so a pathological upstream cannot
 * make the logging path hold megabytes after the response has been served.
 */
const MAX_ERROR_BODY_BYTES = 64 * 1024;

/**
 * A clone of a refusal body, when reading it is cheap and safe — else
 * `undefined`.
 *
 * Cloning has to happen SYNCHRONOUSLY, while the response is still intact; the
 * clone is then read inside the deferred task. Never for an event stream (there
 * is no bounded body to read and teeing one would double-buffer the whole
 * stream), never for a success (a 200 body is model content, and this is a
 * metadata row, not a body archive), and never past the cap.
 */
function cloneErrorBody(response: Response): Response | undefined {
  if (response.status < 400 || response.body === null) return undefined;
  if (isEventStream(response)) return undefined;
  const declared = response.headers.get("content-length");
  if (declared !== null && Number(declared) > MAX_ERROR_BODY_BYTES) return undefined;
  if (!(response.headers.get("content-type") ?? "").includes("json")) return undefined;
  try {
    return response.clone();
  } catch {
    return undefined;
  }
}

/**
 * `error.code` out of the FerroGate error envelope.
 *
 * This is why the trail can say WHY a request was refused without every
 * refusing slice having to thread a code through the middleware chain. The
 * envelope shape (`{ error: { code, message, type, request_id } }`) is the one
 * `middleware/errors.ts` and `inference/errors.ts` both write, byte for byte,
 * so one reader covers 401/403/404/413/429/5xx and every guardrail block.
 *
 * A body that is not that shape — a provider's own error, relayed verbatim —
 * yields `undefined`, and the row still carries the status code.
 */
async function errorCodeFrom(clone: Response | undefined): Promise<string | undefined> {
  if (clone === undefined) return undefined;
  try {
    const parsed: unknown = await clone.json();
    if (typeof parsed !== "object" || parsed === null) return undefined;
    const error = (parsed as { error?: unknown }).error;
    if (typeof error !== "object" || error === null) return undefined;
    const code = (error as { code?: unknown }).code;
    return typeof code === "string" && code !== "" ? code : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Assemble the durable record.
 *
 * Exported for the test that asserts the assembly directly; the middleware is
 * its only production caller.
 */
export function requestLogRecordFrom(
  c: Context<GatewayEnv>,
  startedAtMs: number,
  errorCode: string | undefined,
): RequestLogRecord {
  const response = c.res;
  const facts = requestLogFactsFor(c.req.raw);
  const auth = c.get("auth") as AuthContext | null | undefined;
  const endedAtMs = Date.now();

  return {
    /**
     * The id the CLIENT was told, read off the RESPONSE — not
     * `c.get("requestId")`. The inference route module mints its own `fg-…` id
     * inside the inner app and puts THAT on `x-request-id`, so a row stamped
     * with the outer UUID could never be joined to the id in a customer's
     * incident report. The same reasoning `telemetry/middleware.ts` gives, and
     * the same id `meteringDrain` files a charge under — which is what makes a
     * request log and its charge joinable at all.
     */
    requestId: response.headers.get("x-request-id") ?? c.get("requestId") ?? "",
    traceId: c.get("traceId") ?? undefined,
    agentRunId: facts.agentRunId,
    // The AUTHENTICATED tenancy, never a client-declared header. A
    // platform-operator credential carries none, and the row records that
    // absence rather than inventing a tenant — which is also what keeps the
    // control plane's strict-equality fence meaningful.
    tenantId: auth?.tenancy.tenantId ?? undefined,
    projectId: auth?.tenancy.projectId ?? undefined,
    workspaceId: auth?.tenancy.workspaceId ?? undefined,
    apiKeyId: auth?.subject ?? undefined,
    operationId: c.get("operation")?.operationId,
    method: c.req.method,
    // The CANONICAL path (`/control/v1/*` folded onto `/admin/v1/*`), so two
    // spellings of one operation do not become two things in the trail.
    path: c.get("canonicalPath") ?? new URL(c.req.url).pathname,
    route: facts.route,
    provider: facts.provider,
    logicalModel: facts.logicalModel,
    providerModel: facts.providerModel,
    statusCode: response.status,
    errorCode,
    cacheStatus: response.headers.get(CACHE_STATUS_HEADER) ?? undefined,
    startedAtUnix: Math.floor(startedAtMs / 1000),
    completedAtUnix: Math.floor(endedAtMs / 1000),
    // Milliseconds, because seconds cannot express a gateway's own latency and
    // `completed - started` on whole seconds is 0 for most requests.
    latencyMs: Math.max(endedAtMs - startedAtMs, 0),
    promptTokens: facts.promptTokens,
    completionTokens: facts.completionTokens,
    totalTokens: facts.totalTokens,
    // NOT `allowed` by default. An operation no guardrail policy binds was
    // never screened, and recording that as "allowed" would tell an auditor a
    // control ran when none did.
    guardrailVerdict: facts.guardrailVerdict ?? "not_screened",
    guardrailPolicyId: facts.guardrailPolicyId,
    streamed: facts.streamed ?? isEventStream(response),
    providerAttemptIndex: facts.providerAttemptIndex,
  };
}

/** Mount the request-log writer. See the module docblock for the position. */
export function requestLogging(sink: RequestLogSink): MiddlewareHandler<GatewayEnv> {
  return async function requestLoggingMiddleware(c, next): Promise<void> {
    const startedAtMs = Date.now();
    await next();

    const ctx = executionContextOf(c);
    // No `ExecutionContext` — a unit test driving `app.request()`. There is no
    // lifetime to keep the write alive, and a floating promise is the honest
    // best effort; `sink.write` never rejects, so it cannot become an unhandled
    // rejection either.
    const defer = (work: Promise<unknown>): void => {
      if (ctx === undefined) void work;
      else ctx.waitUntil(work);
    };

    const errorClone = cloneErrorBody(c.res);
    const persist = async (): Promise<void> => {
      try {
        const record = requestLogRecordFrom(c, startedAtMs, await errorCodeFrom(errorClone));
        await sink.write(record, { env: c.env, ...(ctx === undefined ? {} : { ctx }) });
      } catch {
        // Assembly itself failed. Nothing to record, and nothing that may reach
        // the client — the response has already been served.
      }
    };

    const response = c.res;
    const body = response.body;
    if (body === null || !isEventStream(response)) {
      defer(persist());
      return;
    }

    // Streamed: wait for the body to finish or be abandoned, so the usage tap
    // has contributed its token counts before the row is assembled.
    const observed = observeBodyCompletion(body);
    c.res = new Response(observed.body, response);
    defer(observed.settled.then(persist));
  };
}
