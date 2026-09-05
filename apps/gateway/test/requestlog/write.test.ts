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
  requestLogTenantDatabaseFromEnv,
  requestLogging,
  writeTenantRequestLogs,
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
  resetPlatformRequestLogs,
  resetTenantRequestLogs,
  storedPlatformRequestLogs,
  storedTenantRequestLogs,
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
  // 0045 (Track A) DROPPED the control `request_logs` mirror; only the tenant
  // and platform objects remain, so only those are reset here.
  await resetPlatformRequestLogs();
  await resetTenantRequestLogs("tenant_a");
  await resetTenantRequestLogs("tenant_b");
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
    // Empty first, so the row below cannot be a leftover. Track A retired the
    // control projection: a tenant-attributed row is authoritative in its own
    // object, so that is where this suite reads it back.
    expect(await storedTenantRequestLogs("tenant_a")).toHaveLength(0);

    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const h = gateway({ requestId: "fg-buffered-1" });
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    await h.settle();

    const rows = await storedTenantRequestLogs("tenant_a");
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
    expect(document.object).toBe("request_log");
    expect(document.logical_model).toBe("gpt-4o-mini");
    expect(document.total_tokens).toBe(15);
  });

  it("stamps started/completed seconds that bracket the request", async () => {
    const before = Math.floor(Date.now() / 1000);
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const h = gateway();
    await h.call("/v1/chat/completions", { method: "POST", headers: AUTHED, body: chatBody() });
    await h.settle();
    const after = Math.floor(Date.now() / 1000);

    const row = (await storedTenantRequestLogs("tenant_a"))[0] as {
      started_at_unix: number;
      completed_at_unix: number;
    };
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

    const rows = await storedTenantRequestLogs("tenant_a");
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

    const rows = await storedTenantRequestLogs("tenant_a");
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

    const rows = await storedTenantRequestLogs("tenant_a");
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
    // An OPERATOR credential carries no tenant → the row is unattributed and its
    // authoritative home is the PLATFORM_DATA object, not a tenant object.
    const response = await h.call("/v1/models", { headers: OPERATOR });
    expect(response.status).toBe(200);
    await h.settle();

    const rows = await storedPlatformRequestLogs();
    expect(rows).toHaveLength(1);
    const row = rows[0] as NonNullable<(typeof rows)[0]>;
    expect(row.status_code).toBe(200);
    // No model was invoked, so no model is recorded.
    expect(row.logical_model).toBeNull();
    expect(JSON.parse(row.request_json).path).toBe("/v1/models");
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
    // The hot path is off the write, so the tenant object is still empty here.
    expect(await storedTenantRequestLogs("tenant_a")).toHaveLength(0);

    // …and the consumer is what lands it in the tenant's authoritative object.
    const result = await consumeRequestLogBatch(
      { messages: queue.sent.map((body) => ({ body })) },
      env,
    );
    expect(result).toMatchObject({ written: 1, malformed: 0, retried: false });

    const rows = await storedTenantRequestLogs("tenant_a");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      request_id: "fg-queued-1",
      logical_model: "gpt-4o-mini",
      total_tokens: 15,
      status_code: 200,
    });
  });

  // Track A retired the request_logs control projection and the per-leg
  // `projectGuardrailToControl`/`projectRequestLogToControl` gates with it, so the
  // former "only the guardrail leg gated off keeps the request_logs mirror" case
  // no longer has a control mirror to assert against and was deleted.

  /**
   * Track A (request_logs): the tenant object is the sole authoritative home. The
   * consumer reports the row written and it lands in the tenant's own object;
   * there is no control projection mirror to fall back to any more.
   */
  it("lands an attributed row in the tenant object and never the control projection", async () => {
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const queue = new RecordingQueue();
    const h = gateway({ requestId: "fg-g2-reqlog-off", queue });
    await h.call("/v1/chat/completions", { method: "POST", headers: AUTHED, body: chatBody() });
    await h.settle();

    expect(await storedTenantRequestLogs("tenant_a")).toHaveLength(0);

    const result = await consumeRequestLogBatch(
      { messages: queue.sent.map((body) => ({ body })) },
      env,
    );
    // The row is WRITTEN — the tenant object is its authoritative home.
    expect(result).toMatchObject({ written: 1, malformed: 0, retried: false });

    // The control projection mirror is retired: 0045 (Track A) DROPPED the
    // control `request_logs` table entirely, so there is nothing left to assert
    // "received nothing" against — the tenant object below is the sole authority.

    // …but the tenant's authoritative object has the row.
    const objectRows = await env.TENANT_DATA.get(env.TENANT_DATA.idFromName("tenant_a")).query({
      tenantId: "tenant_a",
      sql: "SELECT request_id, tenant FROM request_logs WHERE request_id = ?",
      params: ["fg-g2-reqlog-off"],
    });
    expect(objectRows.results).toEqual([{ request_id: "fg-g2-reqlog-off", tenant: "tenant_a" }]);
  });

  /**
   * Track A (request_logs), unscoped leg: an UNATTRIBUTED row has no tenant
   * object, so its sole authoritative home is PLATFORM_DATA (Zero-D1 Plan B). The
   * consumer must land it there while the control mirror stays empty.
   */
  it("lands an unscoped row in the platform object and never the control projection", async () => {
    expect(await storedPlatformRequestLogs()).toHaveLength(0);
    provider = interceptProviderFetch(() => providerJson(BUFFERED_COMPLETION));
    const queue = new RecordingQueue();
    const h = gateway({ queue });
    // An OPERATOR credential carries no tenant → the row is unattributed.
    const response = await h.call("/v1/models", { headers: OPERATOR });
    expect(response.status).toBe(200);
    await h.settle();
    const requestId = response.headers.get("x-request-id");

    const result = await consumeRequestLogBatch(
      { messages: queue.sent.map((body) => ({ body })) },
      env,
    );
    expect(result).toMatchObject({ malformed: 0, retried: false });

    // Control mirror retired (0045 DROPPED the control `request_logs` table);
    // the platform object is authoritative and populated.
    const platform = await storedPlatformRequestLogs();
    expect(platform).toHaveLength(1);
    expect(platform[0]?.request_id).toBe(requestId);
    expect(platform[0]?.tenant).toBeNull();
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

    const rows = await storedTenantRequestLogs("tenant_a");
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
          {
            body: { not: "a request log" },
            ack: () => {
              acked += 1;
            },
          },
          {
            // A malformed guardrail envelope must not fall through the
            // permissive request-log decoder and become a fabricated log row.
            body: {
              object: "guardrail_evaluation",
              request_id: "fg-not-guardrail",
              started_at_unix: 1_700_000_001,
            },
            ack: () => {
              acked += 1;
            },
          },
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
    expect(result).toMatchObject({ written: 1, malformed: 2, retried: false });
    expect(acked).toBe(2);
    expect(retried).toBe(false);
    // `fg-good` carries no tenant, so its authoritative home is the platform object.
    expect((await storedPlatformRequestLogs()).map((row) => row.request_id)).toEqual(["fg-good"]);
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
    expect((await storedTenantRequestLogs("tenant_a")).map((row) => row.request_id)).toEqual([
      "fg-queue-down",
    ]);
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
        CONTROL_DATA: undefined,
      },
      ctx,
    );
    expect(response.status).toBe(200);
    await waitOnExecutionContext(ctx);

    // The tenant object is authoritative, so removing the fleet projection
    // must not turn a tenant write into a control-D1 fallback or a drop.
    expect(sink.stats).toMatchObject({ dropped: 0, queued: 0, written: 1 });
    // (0045 DROPPED the control `request_logs` mirror; the "no control fallback"
    // pin is retired — the tenant object below is the sole authority.)
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
      // Track A: an attributed row's authoritative home is its tenant object, so
      // the failing double is the tenant-database resolver (no control fallback).
      tenantDatabase: () => ({
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
// The platform dual-write leg (Zero-D1 Plan B, G1)
// ---------------------------------------------------------------------------

describe("unscoped request logs land in the platform object", () => {
  it("lands in the PLATFORM_DATA object, the sole authoritative home", async () => {
    // Empty first, so nothing below can be a leftover. (0045 DROPPED the control
    // `request_logs` mirror, so only the platform object is checked.)
    expect(await storedPlatformRequestLogs()).toHaveLength(0);

    // An OPERATOR credential carries no tenant, so its row is UNATTRIBUTED — the
    // one class of request with no TenantDataObject to be authoritative for it,
    // which is the whole reason the platform object exists. `/v1/models` is a
    // real 200 through the whole middleware chain, so this row is not a fixture.
    const h = gateway();
    const response = await h.call("/v1/models", { headers: OPERATOR });
    expect(response.status, await response.clone().text()).toBe(200);
    await h.settle();
    const requestId = response.headers.get("x-request-id");
    expect(requestId).not.toBeNull();

    // The platform object is the SOLE authoritative home now that Track A retired
    // the control projection: `tenant` NULL, because the whole table IS the
    // platform domain and nothing in it carries an owner.
    const platform = await storedPlatformRequestLogs();
    expect(platform).toHaveLength(1);
    expect(platform[0]?.request_id).toBe(requestId);
    expect(platform[0]?.tenant).toBeNull();

    // Track A: 0045 DROPPED the control `request_logs` mirror; it is never
    // written and no longer exists to assert emptiness against.
  });

  it("counts a platform-object write failure, never a control fallback", async () => {
    expect(await storedPlatformRequestLogs()).toHaveLength(0);

    // No queue, and a platform object that refuses every batch. The platform
    // object is now the SOLE authoritative home for an unscoped row (Track A
    // retired the control mirror), so a failure here is a COUNTED `failed`, not a
    // best-effort blip that a control write papers over.
    const errors: string[] = [];
    const sink = createRequestLogSink({
      ...requestLogBindingsFromEnv,
      platformDatabase: () => ({
        prepare: () => ({
          bind: () => ({ run: async () => ({}), all: async () => ({ results: [] }) }),
        }),
        batch: async () => {
          throw new Error("platform object unavailable");
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
      new Request(`${BASE}/v1/models`, { headers: OPERATOR }),
      {
        ...(env as unknown as Record<string, unknown>),
        GATEWAY_NATIVE_API_KEYS: LOG_TENANT_KEY,
        REQUEST_LOG: undefined,
      },
      ctx,
    );
    // The data plane still serves 200 — a logging failure is never a request
    // failure — but nothing landed anywhere and the failure is counted.
    expect(response.status).toBe(200);
    await waitOnExecutionContext(ctx);

    expect(await storedPlatformRequestLogs()).toHaveLength(0);
    // (0045 DROPPED the control `request_logs` mirror; the "no control fallback"
    // pin is retired.)
    expect(errors).toEqual(["d1"]);
    expect(sink.stats).toMatchObject({ written: 0, failed: 1, dropped: 0 });
  });
});

// ---------------------------------------------------------------------------
// The upsert's merge rule — the property the dependent slices are built on
// ---------------------------------------------------------------------------

describe("a later write MERGES into the row rather than blanking it", () => {
  it("never erases a fact a previous leg established", async () => {
    const db = requestLogTenantDatabaseFromEnv(env, "tenant_a");
    if (db === undefined) throw new Error("TENANT_DATA binding is required");

    await writeTenantRequestLogs(db, [
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
    await writeTenantRequestLogs(db, [
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
        tenantId: "tenant_a",
      },
    ]);

    const rows = await storedTenantRequestLogs("tenant_a");
    expect(rows).toHaveLength(1);
    // The facts only the FIRST write knew are still there.
    expect(rows[0]).toMatchObject({
      tenant: "tenant_a",
      logical_model: "gpt-4o-mini",
      total_tokens: 15,
    });
  });

  it("keeps the same logical request id separate across tenant objects", async () => {
    // Track A: each tenant's rows live in its OWN object, so the same logical
    // request id in two tenants is two rows in two objects — not one shared
    // projection table keyed by a composite projection_key.
    const dbA = requestLogTenantDatabaseFromEnv(env, "tenant_a");
    const dbB = requestLogTenantDatabaseFromEnv(env, "tenant_b");
    if (dbA === undefined || dbB === undefined) {
      throw new Error("TENANT_DATA binding is required");
    }
    const base = {
      requestId: "fg-collision",
      method: "POST",
      path: "/v1/chat/completions",
      statusCode: 200,
      startedAtUnix: 1_700_000_001,
      completedAtUnix: 1_700_000_001,
      latencyMs: 1,
      guardrailVerdict: "allowed" as const,
      streamed: false,
    };
    await writeTenantRequestLogs(dbA, [{ ...base, tenantId: "tenant_a", route: "a" }]);
    await writeTenantRequestLogs(dbB, [{ ...base, tenantId: "tenant_b", route: "b" }]);

    expect((await storedTenantRequestLogs("tenant_a")).map((row) => [row.tenant, row.route])).toEqual(
      [["tenant_a", "a"]],
    );
    expect((await storedTenantRequestLogs("tenant_b")).map((row) => [row.tenant, row.route])).toEqual(
      [["tenant_b", "b"]],
    );
  });

  // Track A retired the control projection and its composite `projection_key`
  // column (tenant objects are id-keyed by `request_id`), so the former
  // "SQLite code-point length for non-BMP projection keys" case no longer has a
  // projection_key to assert against and was deleted.
});

/**
 * Regression (2026-08-07): the consumer's catch used to be a bare `catch {}` —
 * a failing batch (a missing projection table, a tenant object outage) was
 * retried and eventually dead-lettered with NOTHING in the logs to say why.
 * Found during live stability testing: request-log messages were silently
 * dead-lettering and the cause was invisible. The catch now logs before it
 * retries; this pins that the failure is observable and still retried.
 */
describe("a failing consumer batch is logged, not swallowed", () => {
  it("warns with the cause and still arms the retry", async () => {
    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args.map(String).join(" "));
    };
    let retried = false;
    try {
      const throwingObject = {
        prepare: () => ({ bind: () => ({}) }),
        batch: async () => {
          throw new Error("D1_ERROR: no such table: request_logs: SQLITE_ERROR");
        },
      };

      const result = await consumeRequestLogBatch(
        {
          messages: [
            {
              // No tenant → the row's authoritative home is the PLATFORM_DATA
              // object; the failing double is therefore the platform resolver.
              body: {
                object: "request_log",
                request_id: "fg-doomed",
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
        undefined,
        () => throwingObject as never,
      );
      expect(result.retried).toBe(true);
    } finally {
      console.warn = originalWarn;
    }
    expect(retried).toBe(true);
    expect(warnings.some((w) => w.includes("request-log consumer batch failed"))).toBe(true);
    expect(warnings.some((w) => w.includes("no such table"))).toBe(true);
  });
});
