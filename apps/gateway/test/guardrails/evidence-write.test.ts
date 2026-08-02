/**
 * THE WRITER — a durable `guardrail_evaluations` row for every screening
 * decision, end to end on real Cloudflare bindings (#665).
 *
 * ## The defect
 *
 * There was no writer, and there was no table. `InMemoryGuardrailEvidenceSink`
 * held every evaluation in the isolate and the isolate threw them away; zero
 * `INSERT INTO guardrail_evaluations` anywhere in `apps/<app>/src` because
 * `sql/d1-ts/` had no such table to insert into. Meanwhile
 * `GET /admin/v1/guardrail-evaluations` and `GET /admin/v1/investigations`
 * answered — authenticated, RBAC-gated, contract-conformant — that nothing had
 * ever been screened. A blocked request could not be investigated.
 *
 * ## What is real here, and what is not
 *
 * Real: the composed gateway (`createGatewayApp`), the contract router, the
 * auth guard, the REAL guardrail middleware over a REAL `PolicyRevision` and
 * the REAL deterministic secret detector from `@ferrogate/guardrails`, the
 * `CONTROL_DB` D1 binding `wrangler.toml` declares, the deployed migration, and
 * an `ExecutionContext` created by `cloudflare:test` so `waitUntil` is the real
 * one. Nothing about a detector is stubbed to a convenient verdict, and nothing
 * here seeds the evidence tables: every row an assertion finds was put there by
 * an HTTP request flowing through the real middleware chain.
 *
 * ## The two properties this file exists for
 *
 *  1. **The evidence is DURABLE.** A blocked request leaves a row, with its
 *     policy, stage, verdict, action, tenant, detector and confidence.
 *  2. **The excerpt is REDACTED.** A guardrail that blocks a prompt for
 *     carrying a secret and then stores that secret verbatim in an evidence
 *     table an operator can list has MOVED the leak, not stopped it. Every
 *     assertion in "the stored evidence carries no plaintext" below reads the
 *     RAW STORED BYTES and looks for the probe secret in them.
 */
import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  DurableGuardrailEvidenceSink,
  guardrails,
} from "../../src/guardrails/index.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import type { RequestIdFactory } from "../../src/inference/index.js";
import { consumeRequestLogBatch } from "../../src/requestlog/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { OPENAI_ROUTE } from "../inference/fixtures.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
} from "../inference/provider-mock.js";
import {
  RecordingQueue,
  applyControlMigrations,
  resetGuardrailEvidence,
  storedGuardrailChecks,
  storedGuardrailEvaluations,
} from "../requestlog/harness.js";
import {
  EVIDENCE_HMAC_KEY,
  PROBE_SECRET,
  bodyWithProbeSecret,
  cleanBody,
  secretScanPolicy,
  sourceFor,
} from "./fixtures.js";

const BASE = "https://gw.test";

/**
 * A tenant-scoped native key carrying the inference scopes, declared here for
 * the reason `test/requestlog/write.test.ts` gives: the shared fixture keys are
 * tool/skill scoped, so an inference request made with one answers `403
 * scope_denied` before any guardrail runs — and a suite asserting on screening
 * evidence would then be asserting on nothing.
 */
const GUARDRAIL_TENANT_KEY = JSON.stringify([
  {
    key: "fg_guard_tenant",
    id: "key_guard_tenant",
    tenant_id: "tenant_a",
    project_id: "project_guard",
    scopes: ["chat.completions", "messages.create", "models.read"],
  },
]);

const AUTHED = {
  authorization: "Bearer fg_guard_tenant",
  "content-type": "application/json",
};

function fixedRequestIds(id: string): RequestIdFactory {
  return { next: (): string => id };
}

interface Harness {
  readonly evidence: DurableGuardrailEvidenceSink;
  readonly queue: RecordingQueue;
  call(path: string, init: RequestInit): Promise<Response>;
  settle(): Promise<void>;
}

/**
 * The composition root, on real bindings — the same shape `src/index.ts` builds
 * when `CONTROL_DB` is bound.
 */
function gateway(
  options: {
    requestId?: string;
    queue?: RecordingQueue;
    policy?: ReturnType<typeof secretScanPolicy>;
  } = {},
): Harness {
  const queue = options.queue ?? new RecordingQueue();
  const bindings: Record<string, unknown> = {
    ...(env as unknown as Record<string, unknown>),
    // Only bound when the test asked for the queue arm; otherwise the sink
    // takes the direct-D1 arm, which is the `wrangler dev --local` posture.
    ...(options.queue === undefined ? { REQUEST_LOG: undefined } : { REQUEST_LOG: queue }),
    GATEWAY_NATIVE_API_KEYS: GUARDRAIL_TENANT_KEY,
  };

  const evidence = new DurableGuardrailEvidenceSink();
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver([OPENAI_ROUTE]),
        ...(options.requestId === undefined
          ? {}
          : { requestIds: fixedRequestIds(options.requestId) }),
      }),
    ],
    middleware: [
      guardrails({
        policies: sourceFor(options.policy ?? secretScanPolicy()),
        evidence,
        evidenceHmacKey: EVIDENCE_HMAC_KEY,
        providerForModel: () => "openai",
      }),
    ],
  });

  let context: ExecutionContext | undefined;
  return {
    evidence,
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

function chatBody(body: Record<string, unknown>): string {
  return JSON.stringify({ ...body, model: "gpt-4o-mini" });
}

let provider: ProviderInterceptor | undefined;

beforeAll(applyControlMigrations);

beforeEach(async () => {
  await resetGuardrailEvidence();
  provider?.restore();
  provider = undefined;
});

// ---------------------------------------------------------------------------
// The headline: a blocked request leaves a row an operator can investigate
// ---------------------------------------------------------------------------

describe("a BLOCKED request produces durable evidence", () => {
  it("records the policy, stage, verdict, action, tenant and detector", async () => {
    // Empty first, so the row below cannot be a leftover.
    expect(await storedGuardrailEvaluations()).toHaveLength(0);

    const h = gateway({ requestId: "fg-blocked-1" });
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(bodyWithProbeSecret()),
    });
    expect(response.status, await response.clone().text()).toBe(403);
    await h.settle();

    const rows = await storedGuardrailEvaluations();
    expect(rows).toHaveLength(1);
    const row = rows[0] as NonNullable<(typeof rows)[0]>;

    // The join key an incident report carries.
    expect(row.request_id).toBe("fg-blocked-1");
    expect(response.headers.get("x-request-id")).toBe(row.request_id);

    // WHO — the AUTHENTICATED tenant off the credential, never a header.
    expect(row.tenant).toBe("tenant_a");
    expect(row.subject_id).toBe("key_guard_tenant");

    // WHY — the policy, its revision, and what it decided.
    expect(row.policy_id).toBe("secret-scan");
    expect(row.policy_revision).toBe(1);
    expect(row.stage).toBe("request");
    expect(row.mode).toBe("enforce");
    expect(row.verdict).toBe("fail");
    expect(row.action).toBe("block");
    expect(row.enforcement_status).toBe("enforced");
    expect(row.finding_count).toBeGreaterThan(0);

    // The keyed, non-reversible identity of the screened content.
    expect(row.input_fingerprint).toMatch(/^hmac-sha256:[0-9a-f]+$/);

    // WHICH DETECTOR — the child row, with its version and config digest.
    const checks = await storedGuardrailChecks();
    expect(checks).toHaveLength(1);
    const check = checks[0] as NonNullable<(typeof checks)[0]>;
    expect(check.evaluation_id).toBe(row.id);
    expect(check.check_id).toBe("deterministic");
    expect(check.verdict).toBe("fail");
    expect(check.config_digest).toMatch(/^sha256:/);

    // …and the per-finding detail the "Done when" names: category, confidence,
    // and a REDACTED excerpt.
    const document = JSON.parse(check.check_json) as {
      findings?: { category: string; confidence?: number; redacted_excerpt?: string }[];
    };
    const finding = document.findings?.[0];
    expect(finding).toBeDefined();
    expect(finding?.category).toBe("aws_access_key_id");
    expect(finding?.confidence).toBeGreaterThan(0);
    expect(typeof finding?.redacted_excerpt).toBe("string");
  });

  /**
   * An ALLOW is evidence too. A trail that only records refusals cannot answer
   * "was this request screened at all", and `not_screened` and `allowed` are
   * the two answers a compliance review actually cares about telling apart.
   */
  it("records a request the policy PASSED", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-1",
        object: "chat.completion",
        model: "gpt-4o-mini",
        choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
      }),
    );
    const h = gateway({ requestId: "fg-allowed-1" });
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(cleanBody()),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    await h.settle();

    const rows = await storedGuardrailEvaluations();
    expect(rows.map((entry) => entry.verdict)).toContain("pass");
    expect(rows.every((entry) => entry.request_id === "fg-allowed-1")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// THE property: the stored excerpt must not carry the thing that was blocked
// ---------------------------------------------------------------------------

describe("the stored evidence carries no plaintext", () => {
  it("never writes the secret that caused the block into any column", async () => {
    const h = gateway({ requestId: "fg-secret-1" });
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(bodyWithProbeSecret()),
    });
    expect(response.status).toBe(403);
    await h.settle();

    const rows = await storedGuardrailEvaluations();
    const checks = await storedGuardrailChecks();
    expect(rows).toHaveLength(1);
    expect(checks).toHaveLength(1);

    // Every byte of both rows, as stored. Not a projection of them — a
    // projection is exactly where a leak hides.
    const stored = JSON.stringify({ rows, checks });
    expect(stored).not.toContain(PROBE_SECRET);
    // …and not a fragment of it either: the secret's distinctive body would
    // identify the credential just as well as the whole string.
    expect(stored).not.toContain(PROBE_SECRET.slice(4));
    expect(stored).not.toContain("please store");

    // The excerpt is present and is a MASK — it says how wide the match was and
    // what it was, and nothing about what it said.
    const document = JSON.parse((checks[0] as { check_json: string }).check_json) as {
      findings?: { redacted_excerpt?: string }[];
    };
    const excerpt = document.findings?.[0]?.redacted_excerpt ?? "";
    expect(excerpt).toContain("aws_access_key_id");
    expect(excerpt).toMatch(/\*/);
    expect(excerpt).not.toContain(PROBE_SECRET);
  });
});

// ---------------------------------------------------------------------------
// The Queue arm — the same producer/consumer pair #664 built
// ---------------------------------------------------------------------------

describe("the Queue producer/consumer pair carries guardrail evidence too", () => {
  it("sends to REQUEST_LOG instead of writing D1 inline when the queue is bound", async () => {
    const queue = new RecordingQueue();
    const h = gateway({ requestId: "fg-queued-1", queue });
    await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(bodyWithProbeSecret()),
    });
    await h.settle();

    expect(queue.sent.length).toBeGreaterThan(0);
    // The hot path is off the write, so D1 is still empty at this point.
    expect(await storedGuardrailEvaluations()).toHaveLength(0);

    // …and the SAME consumer #664 built is what lands it.
    const result = await consumeRequestLogBatch(
      { messages: queue.sent.map((body) => ({ body })) },
      env,
    );
    expect(result.malformed).toBe(0);
    expect(result.retried).toBe(false);

    const rows = await storedGuardrailEvaluations();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.request_id).toBe("fg-queued-1");
  });

  /** At-least-once delivery: the second copy must not fail, and must not double. */
  it("is idempotent on redelivery", async () => {
    const queue = new RecordingQueue();
    const h = gateway({ requestId: "fg-redelivered", queue });
    await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(bodyWithProbeSecret()),
    });
    await h.settle();

    const messages = queue.sent.map((body) => ({ body }));
    await consumeRequestLogBatch({ messages }, env);
    await consumeRequestLogBatch({ messages }, env);

    expect(await storedGuardrailEvaluations()).toHaveLength(1);
    expect(await storedGuardrailChecks()).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// An evidence failure is never a request failure
// ---------------------------------------------------------------------------

describe("the data plane does not depend on the evidence path", () => {
  it("serves the request normally when the D1 write itself fails", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-1",
        object: "chat.completion",
        model: "gpt-4o-mini",
        choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
      }),
    );
    const stages: string[] = [];
    const evidence = new DurableGuardrailEvidenceSink({
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
      diagnostics: { onError: (stage) => stages.push(stage) },
    });
    const { app } = createGatewayApp({
      modules: [inferenceRouteModule({ models: new InMemoryModelResolver([OPENAI_ROUTE]) })],
      middleware: [
        guardrails({
          policies: sourceFor(secretScanPolicy()),
          evidence,
          evidenceHmacKey: EVIDENCE_HMAC_KEY,
          providerForModel: () => "openai",
        }),
      ],
    });

    const ctx = createExecutionContext();
    const response = await app.fetch(
      new Request(`${BASE}/v1/chat/completions`, {
        method: "POST",
        headers: AUTHED,
        body: chatBody(cleanBody()),
      }),
      {
        ...(env as unknown as Record<string, unknown>),
        GATEWAY_NATIVE_API_KEYS: GUARDRAIL_TENANT_KEY,
      },
      ctx,
    );
    expect(response.status).toBe(200);
    await waitOnExecutionContext(ctx);

    expect(stages).toEqual(["d1"]);
    expect(evidence.stats.failed).toBeGreaterThan(0);
  });

  /**
   * With NO queue and NO control database the sink counts a `dropped` and the
   * request is served. Counted rather than silent: "no rows" and "no writer"
   * are indistinguishable from the admin API, which is the whole defect.
   */
  it("serves the request normally with no evidence binding at all", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-1",
        object: "chat.completion",
        model: "gpt-4o-mini",
        choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
      }),
    );
    const evidence = new DurableGuardrailEvidenceSink();
    const { app } = createGatewayApp({
      modules: [inferenceRouteModule({ models: new InMemoryModelResolver([OPENAI_ROUTE]) })],
      middleware: [
        guardrails({
          policies: sourceFor(secretScanPolicy()),
          evidence,
          evidenceHmacKey: EVIDENCE_HMAC_KEY,
          providerForModel: () => "openai",
        }),
      ],
    });

    const ctx = createExecutionContext();
    const response = await app.fetch(
      new Request(`${BASE}/v1/chat/completions`, {
        method: "POST",
        headers: AUTHED,
        body: chatBody(cleanBody()),
      }),
      {
        ...(env as unknown as Record<string, unknown>),
        GATEWAY_NATIVE_API_KEYS: GUARDRAIL_TENANT_KEY,
        REQUEST_LOG: undefined,
        CONTROL_DB: undefined,
      },
      ctx,
    );
    expect(response.status).toBe(200);
    await waitOnExecutionContext(ctx);
    expect(evidence.stats.dropped).toBeGreaterThan(0);
  });
});
