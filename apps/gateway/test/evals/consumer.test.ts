/**
 * THE JUDGE LEG (#692), against the REAL tenant object and the REAL migration.
 *
 * The rows are read back out of the tenant object's `online_eval_scores` with SQL
 * rather than off a recording double, because the claim being made is "scores land
 * in the owning object" and a fake writer proves only that a function was called.
 * The score is tenant data: it lives in the tenant object and nowhere else — the
 * control projection this suite once dual-wrote was retired and its mirror table
 * DROPped (0043).
 *
 * ## MUTATION LOG
 *
 * | mutation (in `src/`)                                          | red |
 * |----------------------------------------------------------------|-----|
 * | `consumer.ts`: drop the `residencyViolations` gate              | `refuses to judge on a route the tenant's residency policy forbids` |
 * | `consumer.ts`: `retryAll()` on a D1 failure removed             | `hands the delivery back when D1 rejects the write` |
 * | `judge.ts`: clamp an out-of-range score instead of refusing     | `refuses a verdict that broke the scale` |
 * | `d1.ts`: `ON CONFLICT … DO UPDATE` → a bare INSERT              | `a redelivered sample corrects its row instead of doubling the sample` |
 */
import { beforeEach, describe, expect, it } from "vitest";

import {
  type OnlineEvalSample,
  consumeOnlineEvalBatch,
  onlineEvalSampleToWire,
} from "../../src/evals/index.js";
import type { PhysicalRoute } from "../../src/inference/index.js";
import { tenantObjectDb } from "../tenant-object.js";
import { resetOnlineEvalTables, storedTenantScores } from "./harness.js";

/**
 * The production wiring, in one place: a score is tenant data, so the consumer
 * writes it to the owning object and nowhere else. The control `online_eval_scores`
 * projection that this suite once dual-wrote was retired end to end and its
 * mirror table DROPped (0043); there is no `database`/`projectionDatabase`/
 * `projectToControl` seam left to exercise.
 */
const TENANT_DB = (_env: unknown, tenantId: string) => tenantObjectDb(tenantId);

const JUDGE_ROUTE: PhysicalRoute = {
  logicalModel: "judge-model",
  provider: "openai-judge",
  providerModel: "gpt-4o-mini-2024-07-18",
  providerKind: "openai",
  baseUrl: "https://api.openai.example/v1/",
  apiKey: "sk-test-judge",
  enabled: true,
};

/** A judge route in a region an EU-only policy forbids. */
const US_JUDGE_ROUTE: PhysicalRoute = { ...JUDGE_ROUTE, region: "us-east-1" };

const CRITERIA = [
  { id: "answer_relevance", definition: "Does the answer address the question?" },
  { id: "grounded", definition: "Is it supported by the context?" },
];

function sample(overrides: Partial<OnlineEvalSample> = {}): OnlineEvalSample {
  return {
    requestId: "fg-req-1",
    tenantId: "tenant_a",
    projectId: "project_1",
    apiKeyId: "key_1",
    agentRunId: "run_9",
    operationId: "createChatCompletion",
    provider: "openai-main",
    logicalModel: "gpt-4o-mini",
    providerModel: "gpt-4o-mini-2024-07-18",
    samplingKey: "fg-req-1",
    samplingUnit: "request",
    sampleRate: 0.5,
    judgeModel: "judge-model",
    criteria: CRITERIA,
    prompt: "user: what is the capital of France?",
    completion: "Paris.",
    promptTruncated: false,
    completionTruncated: false,
    sampledAtUnix: 1_700_000_000,
    ...overrides,
  };
}

function batchOf(...samples: OnlineEvalSample[]) {
  const acked: number[] = [];
  let retried = false;
  return {
    batch: {
      queue: "online-eval",
      messages: samples.map((one, index) => ({
        body: onlineEvalSampleToWire(one),
        ack: () => acked.push(index),
      })),
      retryAll: () => {
        retried = true;
      },
    },
    acked,
    get retried(): boolean {
      return retried;
    },
  };
}

/** A judge that answers with the given text as a chat completion. */
function judgeAnswering(text: string, status = 200) {
  const requests: { body: unknown; url: string }[] = [];
  return {
    requests,
    dispatcher: {
      async dispatch(request: { endpoint: string; body?: unknown }): Promise<Response> {
        requests.push({
          url: request.endpoint,
          body:
            typeof request.body === "string" ? (JSON.parse(request.body) as unknown) : request.body,
        });
        return new Response(
          JSON.stringify({
            id: "chatcmpl-judge",
            object: "chat.completion",
            choices: [{ index: 0, message: { role: "assistant", content: text } }],
          }),
          { status, headers: { "content-type": "application/json" } },
        );
      },
    },
  };
}

const VERDICT = JSON.stringify({
  scores: [
    { criterion: "answer_relevance", score: 1, reason: "Answers the question directly." },
    { criterion: "grounded", score: 0.5, reason: "No context was supplied." },
  ],
});

beforeEach(async () => {
  await resetOnlineEvalTables();
  const tenant = tenantObjectDb("tenant_a");
  await tenant.batch([
    tenant.prepare("DELETE FROM online_eval_scores"),
    tenant.prepare("DELETE FROM online_eval_regressions"),
  ]);
});

describe("a sampled exchange becomes durable scores", () => {
  it("writes one row per criterion, carrying the axes a cost row joins on", async () => {
    const judge = judgeAnswering(VERDICT);
    const delivery = batchOf(sample());

    const result = await consumeOnlineEvalBatch(
      delivery.batch,
      {},
      {
        routeFor: () => JUDGE_ROUTE,
        dispatcher: () => judge.dispatcher,
        tenantDatabase: TENANT_DB,
        now: () => 1_700_000_500_000,
      },
    );

    expect(result).toMatchObject({ scored: 2, malformed: 0, retried: false });
    const rows = await storedTenantScores("tenant_a");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({
      request_id: "fg-req-1",
      criterion_id: "answer_relevance",
      tenant: "tenant_a",
      project: "project_1",
      api_key_id: "key_1",
      agent_run_id: "run_9",
      logical_model: "gpt-4o-mini",
      provider_model: "gpt-4o-mini-2024-07-18",
      judge_model: "judge-model",
      score: 1,
      rationale: "Answers the question directly.",
      sample_rate: 0.5,
      scored_at_unix: 1_700_000_500,
    });
    expect(rows[1]).toMatchObject({ criterion_id: "grounded", score: 0.5 });

    // The judge was actually asked, at temperature 0, with the exchange in the
    // body. Without this the rows above could come from a judge that was never
    // shown anything.
    expect(judge.requests).toHaveLength(1);
    const asked = judge.requests[0]?.body as Record<string, unknown>;
    expect(asked.temperature).toBe(0);
    expect(JSON.stringify(asked.messages)).toContain("capital of France");
    expect(JSON.stringify(asked.messages)).toContain("Paris.");
  });

  it("a redelivered sample corrects its row instead of doubling the sample", async () => {
    // Queues are at-least-once. A doubled row would silently over-weight
    // whichever requests happened to be redelivered, which is invisible in
    // every aggregate anyone would look at.
    const first = judgeAnswering(VERDICT);
    await consumeOnlineEvalBatch(
      batchOf(sample()).batch,
      {},
      {
        routeFor: () => JUDGE_ROUTE,
        dispatcher: () => first.dispatcher,
        tenantDatabase: TENANT_DB,
      },
    );

    const second = judgeAnswering(
      JSON.stringify({ scores: [{ criterion: "answer_relevance", score: 0.25 }] }),
    );
    await consumeOnlineEvalBatch(
      batchOf(sample()).batch,
      {},
      {
        routeFor: () => JUDGE_ROUTE,
        dispatcher: () => second.dispatcher,
        tenantDatabase: TENANT_DB,
      },
    );

    const rows = await storedTenantScores("tenant_a");
    expect(rows).toHaveLength(2);
    expect(rows.find((row) => row.criterion_id === "answer_relevance")).toMatchObject({
      score: 0.25,
    });
  });
});

describe("the score also reaches the metric store", () => {
  it("emits one Analytics Engine gauge per score, through the telemetry collector", async () => {
    // `apps/telemetry` owns the only `writeDataPoint` binding in the fleet, so
    // a score reaches Analytics Engine the way every other gateway metric does
    // — an OTLP request to the collector. Here the collector is a service-
    // binding double and the assertion is on the BYTES the gateway sends;
    // `apps/telemetry/test/online-eval-scores.test.ts` takes the same envelope
    // the rest of the way and asserts the AE data point it becomes.
    const posted: unknown[] = [];
    const collector = {
      async fetch(request: Request): Promise<Response> {
        posted.push(await request.json());
        return new Response(null, { status: 200 });
      },
    };
    const judge = judgeAnswering(VERDICT);

    const result = await consumeOnlineEvalBatch(
      batchOf(sample()).batch,
      { TELEMETRY_COLLECTOR: collector, TELEMETRY_TOKEN: "collector-token" },
      {
        routeFor: () => JUDGE_ROUTE,
        dispatcher: () => judge.dispatcher,
        tenantDatabase: TENANT_DB,
      },
    );

    expect(result).toMatchObject({ scored: 2 });
    expect(posted).toHaveLength(1);
    const envelope = JSON.stringify(posted[0]);
    expect(envelope).toContain("ferrogate.online_eval.score");
    // The grouping axes travel with the value; without them the series cannot
    // be read per criterion or per model, which is the only way it is useful.
    expect(envelope).toContain("answer_relevance");
    expect(envelope).toContain("judge-model");
    expect(envelope).toContain("gpt-4o-mini");
  });

  it("still stores the score when the collector is unreachable", async () => {
    // The D1 row is the record of what was measured; the metric is a
    // convenience. A metrics outage must not cost a score.
    const judge = judgeAnswering(VERDICT);
    const result = await consumeOnlineEvalBatch(
      batchOf(sample()).batch,
      {
        TELEMETRY_COLLECTOR: {
          async fetch(): Promise<Response> {
            throw new Error("collector down");
          },
        },
        TELEMETRY_TOKEN: "collector-token",
      },
      {
        routeFor: () => JUDGE_ROUTE,
        dispatcher: () => judge.dispatcher,
        tenantDatabase: TENANT_DB,
      },
    );

    expect(result).toMatchObject({ scored: 2, retried: false });
    expect(await storedTenantScores("tenant_a")).toHaveLength(2);
  });
});

describe("residency governs the JUDGE route too", () => {
  it("refuses to judge on a route the tenant's residency policy forbids", async () => {
    const judge = judgeAnswering(VERDICT);
    const result = await consumeOnlineEvalBatch(
      batchOf(sample()).batch,
      {
        GATEWAY_RESIDENCY_POLICIES: JSON.stringify([
          { tenant_id: "tenant_a", residency_regions: ["eu-west-1"] },
        ]),
      },
      {
        routeFor: () => US_JUDGE_ROUTE,
        dispatcher: () => judge.dispatcher,
        tenantDatabase: TENANT_DB,
      },
    );

    expect(result).toMatchObject({ scored: 0, refusedResidency: 1 });
    // The decisive assertion: the prompt never left. A gate that only skipped
    // the WRITE would still have shipped the tenant's content out of region.
    expect(judge.requests).toEqual([]);
    expect(await storedTenantScores("tenant_a")).toEqual([]);
  });

  it("judges on an in-region route for the same tenant", async () => {
    // The negative above is only meaningful beside this: without it, a gate
    // that refused everything would look identical.
    const judge = judgeAnswering(VERDICT);
    const result = await consumeOnlineEvalBatch(
      batchOf(sample()).batch,
      {
        GATEWAY_RESIDENCY_POLICIES: JSON.stringify([
          { tenant_id: "tenant_a", residency_regions: ["eu-west-1"] },
        ]),
      },
      {
        routeFor: () => ({ ...JUDGE_ROUTE, region: "eu-west-1" }),
        dispatcher: () => judge.dispatcher,
        tenantDatabase: TENANT_DB,
      },
    );

    expect(result).toMatchObject({ scored: 2, refusedResidency: 0 });
    expect(judge.requests).toHaveLength(1);
  });
});

describe("a bad judge run costs a sample, never a retry storm", () => {
  it("acks a message that does not decode", async () => {
    const delivery = {
      queue: "online-eval",
      messages: [{ body: { object: "request_log", request_id: "x" }, ack: () => {} }],
      retryAll: () => {
        throw new Error("must not retry a permanently-bad message");
      },
    };
    const result = await consumeOnlineEvalBatch(
      delivery,
      {},
      {
        routeFor: () => JUDGE_ROUTE,
        tenantDatabase: TENANT_DB,
      },
    );
    expect(result).toMatchObject({ malformed: 1, scored: 0, retried: false });
  });

  it("refuses a verdict that broke the scale", async () => {
    // A judge that answered 7 on a 0-1 rubric did not follow it. Clamping to 1
    // would file a fabricated number under the tenant's criterion.
    const judge = judgeAnswering(
      JSON.stringify({ scores: [{ criterion: "answer_relevance", score: 7 }] }),
    );
    const result = await consumeOnlineEvalBatch(
      batchOf(sample()).batch,
      {},
      {
        routeFor: () => JUDGE_ROUTE,
        dispatcher: () => judge.dispatcher,
        tenantDatabase: TENANT_DB,
      },
    );

    expect(result).toMatchObject({ scored: 0, unjudgeable: 1, retried: false });
    expect(await storedTenantScores("tenant_a")).toEqual([]);
  });

  it("does not retry an unreachable judge", async () => {
    const delivery = batchOf(sample());
    const result = await consumeOnlineEvalBatch(
      delivery.batch,
      {},
      {
        routeFor: () => JUDGE_ROUTE,
        dispatcher: () => ({
          async dispatch(): Promise<Response> {
            throw new Error("connection refused");
          },
        }),
        tenantDatabase: TENANT_DB,
      },
    );

    expect(result).toMatchObject({ scored: 0, unjudgeable: 1, retried: false });
  });

  it("hands the delivery back when D1 rejects the write", async () => {
    // The opposite direction, and the reason it differs: the judging has
    // already been paid for, so the ROW is the thing worth retrying.
    const judge = judgeAnswering(VERDICT);
    const delivery = batchOf(sample());
    const result = await consumeOnlineEvalBatch(
      delivery.batch,
      {},
      {
        routeFor: () => JUDGE_ROUTE,
        dispatcher: () => judge.dispatcher,
        tenantDatabase: () => ({
          prepare: () => ({
            bind: () => ({
              run: async () => undefined,
              all: async () => undefined,
              first: async () => null,
            }),
          }),
          batch: async () => {
            throw new Error("D1_ERROR: database is locked");
          },
        }),
      },
    );

    expect(result).toMatchObject({ scored: 0, retried: true });
    expect(delivery.retried).toBe(true);
  });

  it("writes the tenant object as the sole durable destination", async () => {
    // The production contract (#859/#881): a score is tenant data. The owning
    // object is the sole durable destination; nothing is mirrored to control —
    // the mirror table was DROPped (0043), so there is no second copy to write.
    const judge = judgeAnswering(VERDICT);
    const delivery = batchOf(sample());
    const result = await consumeOnlineEvalBatch(
      delivery.batch,
      {},
      {
        routeFor: () => JUDGE_ROUTE,
        dispatcher: () => judge.dispatcher,
        tenantDatabase: TENANT_DB,
        now: () => 1_700_000_500_000,
      },
    );

    expect(result).toMatchObject({ scored: 2, retried: false });
    expect(delivery.retried).toBe(false);
    expect(
      await tenantObjectDb("tenant_a")
        .prepare("SELECT COUNT(*) AS count FROM online_eval_scores")
        .first<{ count: number }>(),
    ).toEqual({ count: 2 });
  });
});
