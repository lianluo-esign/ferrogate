/**
 * THE WRITER — a `request_logs` row for every inference request, end to end on
 * real Cloudflare bindings (#664).
 *
 * ## The defect
 *
 * There was no writer. Zero `INSERT INTO request_logs` anywhere in
 * `apps/<app>/src`, on a schema that has had the table since the first control
 * migration, behind an authenticated admin API that answered `200 []` on every
 * deployment. The gateway metered to `billing_events`/`billing_ledger` and
 * emitted telemetry, and persisted no record of what it decided.
 *
 * ## What is real here, and what is not
 *
 * Real: the composed gateway (`createGatewayApp`), the contract router, the
 * auth guard, the whole middleware chain, the inference dispatch path, the
 * `CONTROL_DB` D1 binding `wrangler.toml` declares, the deployed migration, and
 * an `ExecutionContext` created by `cloudflare:test` so `waitUntil` is the real
 * one. The ONLY thing intercepted is the outbound provider `fetch`.
 *
 * Not real: `app.fetch(request, env, ctx)` rather than `SELF`, for the reason
 * `test/metering/durable.test.ts` gives — `SELF` runs `src/worker.ts`, whose
 * model registry is pinned EMPTY by `vitest.config.ts`, so every request would
 * answer `400 model_not_found` and never dispatch. The wiring under test is
 * character-for-character what `src/index.ts` does.
 *
 * ## The rule every case obeys
 *
 * **Nothing here seeds `request_logs`.** Every row an assertion finds was put
 * there by a real HTTP request flowing through the real middleware chain, so a
 * green case cannot be explained by a fixture.
 */
import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import type { RequestIdFactory } from "../../src/inference/index.js";
import {
  consumeRequestLogBatch,
  createRequestLogSink,
  requestLogBindingsFromEnv,
  requestLogging,
} from "../../src/requestlog/index.js";
import type { RequestLogSink } from "../../src/requestlog/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { OPENAI_ROUTE } from "../inference/fixtures.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
  providerSse,
} from "../inference/provider-mock.js";
import {
  RecordingQueue,
  applyControlMigrations,
  controlDb,
  resetRequestLogs,
  storedRequestLogs,
} from "./harness.js";

const BASE = "https://gw.test";
const AUTHED = { authorization: "Bearer fg_log_tenant", "content-type": "application/json" };
const OPERATOR = { authorization: "Bearer fg_root", "content-type": "application/json" };

/**
 * A tenant-scoped native key carrying the INFERENCE scopes, declared here
 * rather than in `vitest.config.ts`.
 *
 * The shared fixture keys are tool/skill scoped, so an inference request made
 * with one answers `403 scope_denied` — a status this suite would happily write
 * a row for, which would make every "the row carries the model" assertion
 * vacuous. Overriding `GATEWAY_NATIVE_API_KEYS` on THIS harness's bindings
 * keeps the change local: no other suite's world moves.
 *
 * It carries a `project_id` on purpose. Project attribution is one of the facts
 * #664's acceptance criteria names, and it is the one that would silently stay
 * NULL if no credential in the suite ever had one.
 */
const LOG_TENANT_KEY = JSON.stringify([
  {
    key: "fg_log_tenant",
    id: "key_log_tenant",
    tenant_id: "tenant_a",
    project_id: "project_logs",
    scopes: ["chat.completions", "messages.create", "models.read"],
  },
]);

function fixedRequestIds(id: string): RequestIdFactory {
  return { next: (): string => id };
}

interface Harness {
  readonly sink: RequestLogSink;
  readonly queue: RecordingQueue;
  call(path: string, init: RequestInit): Promise<Response>;
  settle(): Promise<void>;
}

/**
 * The composition root, on real bindings.
 *
 * `requestLogging(createRequestLogSink(requestLogBindingsFromEnv))` is exactly
 * what `src/index.ts` mounts, and its POSITION in the array matters: ahead of
 * everything that can short-circuit, so a refusal is still logged.
 */
function gateway(options: { requestId?: string; queue?: RecordingQueue } = {}): Harness {
  const queue = options.queue ?? new RecordingQueue();
  const bindings: Record<string, unknown> = {
    ...(env as unknown as Record<string, unknown>),
    TENANT_DATA: env.TENANT_DATA,
    // Only bound when the test asked for the queue arm; otherwise the sink
    // takes the direct-D1 arm, which is the `wrangler dev --local` posture.
    ...(options.queue === undefined ? { REQUEST_LOG: undefined } : { REQUEST_LOG: queue }),
    GATEWAY_NATIVE_API_KEYS: LOG_TENANT_KEY,
  };

  const sink = createRequestLogSink(requestLogBindingsFromEnv);
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver([OPENAI_ROUTE]),
        ...(options.requestId === undefined
          ? {}
          : { requestIds: fixedRequestIds(options.requestId) }),
      }),
    ],
    middleware: [requestLogging(sink)],
  });

  let context: ExecutionContext | undefined;
  return {
    sink,
    queue,
    async call(path, init): Promise<Response> {
      context = createExecutionContext();
      return app.fetch(new Request(`${BASE}${path}`, init), bindings, context);
    },
    async settle(): Promise<void> {
      if (context !== undefined) await waitOnExecutionContext(context);
    },
  };
}

function chatBody(stream = false, model = "gpt-4o-mini"): string {
  return JSON.stringify({
    model,
    messages: [{ role: "user", content: "hi" }],
    ...(stream ? { stream: true } : {}),
  });
}

const BUFFERED_COMPLETION = {
  id: "chatcmpl-1",
  object: "chat.completion",
  model: "gpt-4o-mini",
  choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
  usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
};

const STREAM_FRAMES: readonly string[] = [
  'data: {"id":"c","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"He"},"finish_reason":null}]}',
  'data: {"id":"c","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"llo"},"finish_reason":"stop"}]}',
  'data: {"id":"c","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}',
  "data: [DONE]",
];

let provider: ProviderInterceptor | undefined;

beforeAll(applyControlMigrations);

beforeEach(async () => {
  await resetRequestLogs();
});

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

// ---------------------------------------------------------------------------
// The headline: a row exists, and it carries what an auditor asked for
// ---------------------------------------------------------------------------

describe("a buffered inference request produces one durable row", () => {
  it("records tenant, project, key, both model names, route, provider, status, latency and tokens", async () => {
    // Empty first, so the row below cannot be a leftover.
    expect(await storedRequestLogs()).toHaveLength(0);

    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const h = gateway({ requestId: "fg-buffered-1" });
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    await h.settle();

    const rows = await storedRequestLogs();
    expect(rows).toHaveLength(1);
    const row = rows[0] as NonNullable<(typeof rows)[0]>;

    // The id the CLIENT was told — the join key for an incident report.
    expect(row.request_id).toBe("fg-buffered-1");
    expect(response.headers.get("x-request-id")).toBe(row.request_id);

    // Tenancy + credential: the AUTHENTICATED ones, from `vitest.config.ts`'s
    // `fg_tenant_tools` key.
    expect(row.tenant).toBe("tenant_a");
    expect(row.project).toBe("project_logs");
    expect(row.api_key_id).toBe("key_log_tenant");

    // Model, BOTH names — the caller's logical name and the physical one the
    // provider was actually asked for. A trail with only one cannot answer
    // "which upstream model produced this".
    expect(row.logical_model).toBe("gpt-4o-mini");
    expect(row.provider_model).toBe("gpt-4o-mini-2024-07-18");
    expect(row.provider).toBe("openai-main");
    expect(row.route).toBe("openai.chat.completions");

    // Status, latency, tokens.
    expect(row.status_code).toBe(200);
    expect(row.latency_ms).toBeGreaterThanOrEqual(0);
    expect(row.prompt_tokens).toBe(11);
    expect(row.completion_tokens).toBe(4);
    expect(row.total_tokens).toBe(15);
    expect(row.streamed).toBe(0);

    // The guardrail verdict. NOT `allowed`: no guardrail middleware is mounted
    // in this harness, so nothing screened this request, and saying "allowed"
    // would claim a control ran.
    expect(row.guardrail_verdict).toBe("not_screened");

    // And the document half is the whole record, for the JSONL export.
    const document = JSON.parse(row.request_json) as Record<string, unknown>;
    expect(document["object"]).toBe("request_log");
    expect(document["logical_model"]).toBe("gpt-4o-mini");
    expect(document["total_tokens"]).toBe(15);
  });

  it("stamps started/completed seconds that bracket the request", async () => {
    const before = Math.floor(Date.now() / 1000);
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const h = gateway();
    await h.call("/v1/chat/completions", { method: "POST", headers: AUTHED, body: chatBody() });
    await h.settle();
    const after = Math.floor(Date.now() / 1000);

    const row = (await storedRequestLogs())[0] as { started_at_unix: number; completed_at_unix: number };
    expect(row.started_at_unix).toBeGreaterThanOrEqual(before);
    expect(row.completed_at_unix).toBeLessThanOrEqual(after);
    expect(row.completed_at_unix).toBeGreaterThanOrEqual(row.started_at_unix);
  });
});

// ---------------------------------------------------------------------------
// Streaming — the leg a row written at header time would get wrong
// ---------------------------------------------------------------------------

describe("a STREAMED inference request records the tokens the tap reported", () => {
  it("waits for the body to finish before writing the row", async () => {
    provider = interceptProviderFetch(() => providerSse(STREAM_FRAMES));
    const h = gateway({ requestId: "fg-stream-1" });
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(true),
    });
    expect(response.status).toBe(200);
    // Drain the body as a client would: the usage frame is near the END, so a
    // writer that fired at header time would have recorded no tokens at all.
    await response.text();
    await h.settle();

    const rows = await storedRequestLogs();
    expect(rows).toHaveLength(1);
    const row = rows[0] as NonNullable<(typeof rows)[0]>;
    expect(row.request_id).toBe("fg-stream-1");
    expect(row.streamed).toBe(1);
    expect(row.prompt_tokens).toBe(7);
    expect(row.completion_tokens).toBe(3);
    expect(row.total_tokens).toBe(10);
    expect(row.status_code).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// The rows an inference-handler-shaped writer would have missed entirely
// ---------------------------------------------------------------------------

describe("a REFUSED request is still evidence", () => {
  it("records a request refused before dispatch, with its error code", async () => {
    // No provider interceptor: this must never reach one.
    const h = gateway({ requestId: "fg-refused-1" });
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(false, "no-such-model"),
    });
    expect(response.status).toBe(400);
    await h.settle();

    const rows = await storedRequestLogs();
    expect(rows).toHaveLength(1);
    const row = rows[0] as NonNullable<(typeof rows)[0]>;
    expect(row.status_code).toBe(400);
    // The WHY, recovered from the FerroGate error envelope — the single field
    // that turns "something was refused" into an answer.
    expect(row.error_code).toBe("model_not_found");
    // Nothing was dispatched, so there is no provider and no token count, and
    // the row says so rather than inventing them.
    expect(row.provider).toBeNull();
    expect(row.total_tokens).toBeNull();
  });

  it("records an UPSTREAM provider failure as a decision that happened", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({ error: { message: "upstream is down" } }, 502),
    );
    const h = gateway();
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(),
    });
    expect(response.status).toBeGreaterThanOrEqual(400);
    await h.settle();

    const rows = await storedRequestLogs();
    expect(rows).toHaveLength(1);
    const row = rows[0] as NonNullable<(typeof rows)[0]>;
    // The provider WAS chosen and WAS called: an audit that dropped failed
    // upstream calls would drop the interesting half of every incident.
    expect(row.logical_model).toBe("gpt-4o-mini");
    expect(row.provider).toBe("openai-main");
    expect(row.status_code).toBeGreaterThanOrEqual(400);
  });

  it("records a NON-INFERENCE operation too", async () => {
    const h = gateway();
    const response = await h.call("/v1/models", { headers: OPERATOR });
    expect(response.status).toBe(200);
    await h.settle();

    const rows = await storedRequestLogs();
    expect(rows).toHaveLength(1);
    const row = rows[0] as NonNullable<(typeof rows)[0]>;
    expect(row.status_code).toBe(200);
    // No model was invoked, so no model is recorded.
    expect(row.logical_model).toBeNull();
    expect(JSON.parse(row.request_json)["path"]).toBe("/v1/models");
  });
});

// ---------------------------------------------------------------------------
// The Queue arm, and the consumer that drains it
// ---------------------------------------------------------------------------

describe("the Queue producer/consumer pair", () => {
  it("sends to REQUEST_LOG instead of writing D1 inline when the queue is bound", async () => {
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const queue = new RecordingQueue();
    const h = gateway({ requestId: "fg-queued-1", queue });
    await h.call("/v1/chat/completions", { method: "POST", headers: AUTHED, body: chatBody() });
    await h.settle();

    expect(queue.sent).toHaveLength(1);
    expect(h.sink.stats).toMatchObject({ queued: 1, written: 0, dropped: 0 });
    // The hot path is off the write, so D1 is still empty at this point.
    expect(await storedRequestLogs()).toHaveLength(0);

    // …and the consumer is what lands it.
    const result = await consumeRequestLogBatch(
      { messages: queue.sent.map((body) => ({ body })) },
      env,
    );
    expect(result).toMatchObject({ written: 1, malformed: 0, retried: false });

    const rows = await storedRequestLogs();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      request_id: "fg-queued-1",
      logical_model: "gpt-4o-mini",
      total_tokens: 15,
      status_code: 200,
    });
  });

  /** At-least-once delivery: the second copy must not fail, and must not double. */
  it("is idempotent on redelivery", async () => {
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const queue = new RecordingQueue();
    const h = gateway({ requestId: "fg-redelivered", queue });
    await h.call("/v1/chat/completions", { method: "POST", headers: AUTHED, body: chatBody() });
    await h.settle();

    const messages = queue.sent.map((body) => ({ body }));
    await consumeRequestLogBatch({ messages }, env);
    await consumeRequestLogBatch({ messages }, env);

    const rows = await storedRequestLogs();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.total_tokens).toBe(15);
  });

  /** A permanently-bad message is acked, not retried in front of good evidence. */
  it("drops an undecodable message and still writes the good ones", async () => {
    let acked = 0;
    let retried = false;
    const result = await consumeRequestLogBatch(
      {
        messages: [
          { body: { not: "a request log" }, ack: () => { acked += 1; } },
          {
            body: {
              object: "request_log",
              request_id: "fg-good",
              started_at_unix: 1_700_000_000,
              completed_at_unix: 1_700_000_000,
              status_code: 200,
              latency_ms: 5,
              guardrail_verdict: "allowed",
              streamed: false,
              method: "POST",
              path: "/v1/chat/completions",
            },
          },
        ],
        retryAll: () => {
          retried = true;
        },
      },
      env,
    );
    expect(result).toMatchObject({ written: 1, malformed: 1, retried: false });
    expect(acked).toBe(1);
    expect(retried).toBe(false);
    expect((await storedRequestLogs()).map((row) => row.request_id)).toEqual(["fg-good"]);
  });

  /** A queue outage degrades the batching, never the evidence. */
  it("falls back to the direct D1 write when the queue rejects", async () => {
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const queue = new RecordingQueue();
    queue.fail();
    const h = gateway({ requestId: "fg-queue-down", queue });
    await h.call("/v1/chat/completions", { method: "POST", headers: AUTHED, body: chatBody() });
    await h.settle();

    expect(queue.sent).toHaveLength(0);
    expect(h.sink.stats).toMatchObject({ queued: 0, written: 1, failed: 1 });
    expect((await storedRequestLogs()).map((row) => row.request_id)).toEqual(["fg-queue-down"]);
  });
});

// ---------------------------------------------------------------------------
// A logging failure is never a request failure
// ---------------------------------------------------------------------------

describe("the data plane does not depend on the evidence path", () => {
  it("serves normally and keeps the authoritative object when the projection is absent", async () => {
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const sink = createRequestLogSink(requestLogBindingsFromEnv);
    const { app } = createGatewayApp({
      modules: [inferenceRouteModule({ models: new InMemoryModelResolver([OPENAI_ROUTE]) })],
      middleware: [requestLogging(sink)],
    });
    const ctx = createExecutionContext();
    const response = await app.fetch(
      new Request(`${BASE}/v1/chat/completions`, {
        method: "POST",
        headers: AUTHED,
        body: chatBody(),
      }),
      // Every binding the gateway needs to AUTHENTICATE, and neither evidence
      // binding — the "nowhere to write" deployment.
      {
        ...(env as unknown as Record<string, unknown>),
        GATEWAY_NATIVE_API_KEYS: LOG_TENANT_KEY,
        REQUEST_LOG: undefined,
        CONTROL_DB: undefined,
      },
      ctx,
    );
    expect(response.status).toBe(200);
    await waitOnExecutionContext(ctx);

    // The tenant object is authoritative, so removing the fleet projection
    // must not turn a tenant write into a control-D1 fallback or a drop.
    expect(sink.stats).toMatchObject({ dropped: 0, queued: 0, written: 1 });
    expect(await storedRequestLogs()).toHaveLength(0);
    const requestId = response.headers.get("x-request-id");
    expect(requestId).not.toBeNull();
    const objectRows = await env.TENANT_DATA.get(env.TENANT_DATA.idFromName("tenant_a")).query({
      tenantId: "tenant_a",
      sql: "SELECT request_id, tenant FROM request_logs WHERE request_id = ?",
      params: [requestId],
    });
    expect(objectRows.results).toEqual([{ request_id: requestId, tenant: "tenant_a" }]);
  });

  it("serves the request normally when the D1 write itself fails", async () => {
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const errors: string[] = [];
    const sink = createRequestLogSink({
      queue: () => undefined,
      database: () => ({
        prepare: () => ({
          bind: () => ({
            run: async () => {
              throw new Error("D1_ERROR");
            },
            all: async () => {
              throw new Error("D1_ERROR");
            },
          }),
        }),
        batch: async () => {
          throw new Error("D1_ERROR");
        },
      }),
      diagnostics: { onError: (stage) => errors.push(stage) },
    });
    const { app } = createGatewayApp({
      modules: [inferenceRouteModule({ models: new InMemoryModelResolver([OPENAI_ROUTE]) })],
      middleware: [requestLogging(sink)],
    });
    const ctx = createExecutionContext();
    const response = await app.fetch(
      new Request(`${BASE}/v1/chat/completions`, {
        method: "POST",
        headers: AUTHED,
        body: chatBody(),
      }),
      {
        ...(env as unknown as Record<string, unknown>),
        GATEWAY_NATIVE_API_KEYS: LOG_TENANT_KEY,
      },
      ctx,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ id: "chatcmpl-1" });
    await waitOnExecutionContext(ctx);
    expect(errors).toEqual(["d1"]);
    expect(sink.stats.failed).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// The upsert's merge rule — the property the dependent slices are built on
// ---------------------------------------------------------------------------

describe("a later write MERGES into the row rather than blanking it", () => {
  it("never erases a fact a previous leg established", async () => {
    await applyControlMigrations();
    const db = controlDb();
    const { writeRequestLogs } = await import("../../src/requestlog/index.js");

    await writeRequestLogs(db, [
      {
        requestId: "fg-merge",
        method: "POST",
        path: "/v1/chat/completions",
        statusCode: 200,
        startedAtUnix: 1_700_000_000,
        completedAtUnix: 1_700_000_000,
        latencyMs: 12,
        guardrailVerdict: "allowed",
        streamed: false,
        tenantId: "tenant_a",
        logicalModel: "gpt-4o-mini",
        totalTokens: 15,
      },
    ]);

    // A second leg that knows only the guardrail verdict.
    await writeRequestLogs(db, [
      {
        requestId: "fg-merge",
        method: "POST",
        path: "/v1/chat/completions",
        statusCode: 200,
        startedAtUnix: 1_700_000_000,
        completedAtUnix: 1_700_000_000,
        latencyMs: 12,
        guardrailVerdict: "blocked",
        streamed: false,
      },
    ]);

    const rows = await storedRequestLogs();
    expect(rows).toHaveLength(1);
    // The facts only the FIRST write knew are still there.
    expect(rows[0]).toMatchObject({
      tenant: "tenant_a",
      logical_model: "gpt-4o-mini",
      total_tokens: 15,
    });
  });
});
