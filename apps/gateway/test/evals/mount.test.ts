/**
 * THE MOUNTS (#692) — the three seams a slice like this dies at, each driven
 * through the DEPLOYED composition root rather than through a hand-built copy.
 *
 * `test/metering/wiring.test.ts` recorded the lesson this file is built on:
 * deleting `meteringDrain(usage)` from `src/index.ts` left 794 tests green. The
 * three seams here are the equivalents for this slice.
 *
 *  1. `onlineEvaluation(onlineEvals)` is IN `GATEWAY_MIDDLEWARE`;
 *  2. `gatewayQueue` routes an online-evaluation message to the judge consumer
 *     AND still routes a request-log message to the request-log consumer —
 *     both queues now arrive at one entry point;
 *  3. `gatewayScheduled` runs the regression sweep.
 *
 * Seams 2 and 3 use the REAL `env` resolution: the model catalogue comes from
 * `GATEWAY_PROVIDERS`/`GATEWAY_MODELS`, the judge is dialled through the real
 * `dispatcherFromEnv` with only the outbound `fetch` intercepted, and the rows
 * are read back out of the real control D1.
 */
import { env as poolEnv } from "cloudflare:test";
import { controlNamespace } from "../support/control-namespace.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  ONLINE_EVAL_SCORE_PROJECTION_UPSERT_SQL,
  TENANT_ONLINE_EVAL_SCORE_UPSERT_SQL,
  onlineEvalSampleToWire,
  onlineEvalScoreBindings,
  onlineEvalScoreProjectionBindings,
} from "../../src/evals/index.js";
import { GATEWAY_MIDDLEWARE, gatewayQueue, gatewayScheduled } from "../../src/index.js";
import { REQUEST_LOG_OBJECT } from "../../src/requestlog/index.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
} from "../inference/provider-mock.js";
import { controlDb, resetOnlineEvalTables, storedRegressions, storedScores } from "./harness.js";
import { tenantObjectDb } from "../tenant-object.js";

const CRITERIA = [{ id: "grounded", definition: "Is it supported by the context?" }];

const PROVIDERS = [
  {
    name: "openai-judge",
    kind: "openai",
    base_url: "https://judge.test/v1",
    api_key_var: "JUDGE_API_KEY",
  },
];
const MODELS = [{ name: "judge-model", provider: "openai-judge", provider_model: "gpt-4o-mini" }];

function env(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    CONTROL_DB: controlDb(),
    CONTROL_DATA: controlNamespace(),
    TENANT_DATA: (poolEnv as unknown as Record<string, unknown>).TENANT_DATA,
    GATEWAY_PROVIDERS: JSON.stringify(PROVIDERS),
    GATEWAY_MODELS: JSON.stringify(MODELS),
    JUDGE_API_KEY: "sk-judge",
    ...extra,
  };
}

const SAMPLE = {
  requestId: "fg-mounted-1",
  tenantId: "tenant_a",
  samplingKey: "fg-mounted-1",
  samplingUnit: "request" as const,
  sampleRate: 1,
  judgeModel: "judge-model",
  criteria: CRITERIA,
  prompt: "user: is the sky blue?",
  completion: "Yes.",
  promptTruncated: false,
  completionTruncated: false,
  sampledAtUnix: 1_700_000_000,
  logicalModel: "gpt-4o-mini",
};

let provider: ProviderInterceptor | undefined;

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

beforeEach(async () => {
  await resetOnlineEvalTables();
  const tenant = tenantObjectDb("tenant_a");
  await tenant.batch([
    tenant.prepare("DELETE FROM online_eval_scores"),
    tenant.prepare("DELETE FROM online_eval_regressions"),
  ]);
});

describe("seam 1 — the sampler is in the deployed chain", () => {
  it("mounts `onlineEvaluation` in GATEWAY_MIDDLEWARE", () => {
    const names = GATEWAY_MIDDLEWARE.map((handler) => handler.name);
    expect(names).toContain("onlineEvaluationMiddleware");
    // AFTER `residency`, which is what resolves the tenant's ZDR posture for
    // the request. Ahead of it the sampler would have no way to know, and a
    // zero-data-retention tenant's prompt would be captured.
    expect(names.indexOf("onlineEvaluationMiddleware")).toBeGreaterThan(
      names.indexOf("residencyMiddleware"),
    );
  });
});

describe("seam 2 — the queue entry point routes both queues", () => {
  it("judges an online-evaluation message and writes its scores", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-judge",
        object: "chat.completion",
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content: JSON.stringify({
                scores: [{ criterion: "grounded", score: 1, reason: "Plainly true." }],
              }),
            },
          },
        ],
      }),
    );

    await gatewayQueue(
      {
        queue: "ferrogate-online-eval",
        messages: [{ body: onlineEvalSampleToWire(SAMPLE), ack: () => {} }],
      },
      env(),
    );

    const rows = await storedScores();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      request_id: "fg-mounted-1",
      criterion_id: "grounded",
      score: 1,
      judge_model: "judge-model",
    });
    // The judge was dialled through the REAL catalogue + dispatcher: the
    // provider base URL from `GATEWAY_PROVIDERS` is what was called.
    expect(provider.requests[0]?.url).toContain("https://judge.test/v1");
  });

  it("still delivers a request-log message to the request-log consumer", async () => {
    // The regression this holds: routing everything to the new consumer, or
    // letting the permissive request-log decoder eat an evaluation sample,
    // would silently break #664 — and #664's own tests never call `gatewayQueue`
    // with a mixed batch.
    await gatewayQueue(
      {
        queue: "ferrogate-request-logs",
        messages: [
          {
            body: {
              object: REQUEST_LOG_OBJECT,
              request_id: "fg-log-1",
              method: "POST",
              path: "/v1/chat/completions",
              status_code: 200,
              started_at_unix: 1_700_000_000,
              completed_at_unix: 1_700_000_001,
              latency_ms: 12,
              tenant: "tenant_a",
            },
            ack: () => {},
          },
        ],
      },
      env(),
    );

    const logs = await controlDb()
      .prepare("SELECT request_id FROM request_logs WHERE request_id = ?")
      .bind("fg-log-1")
      .all();
    expect(logs.results).toHaveLength(1);
    // …and nothing was mistaken for a sample.
    expect(await storedScores()).toEqual([]);
  });
});

describe("seam 3 — the cron tick sweeps regressions", () => {
  it("records a regression the scheduled handler found", async () => {
    const nowUnix = Math.floor(Date.now() / 1000);
    const db = tenantObjectDb("tenant_a");
    const statement = db.prepare(TENANT_ONLINE_EVAL_SCORE_UPSERT_SQL);
    const seed = async (count: number, score: number, atUnix: number) => {
      const records = Array.from({ length: count }, (_, index) => ({
        requestId: `fg-${atUnix}-${index}`,
        tenantId: "tenant_a",
        criterionId: "grounded",
        score,
        judgeModel: "judge-model",
        logicalModel: "gpt-4o-mini",
        samplingKey: `fg-${atUnix}-${index}`,
        samplingUnit: "request" as const,
        sampleRate: 1,
        promptTruncated: false,
        completionTruncated: false,
        scoredAtUnix: atUnix,
      }));
      await db.batch(records.map((record) => statement.bind(...onlineEvalScoreBindings(record))));
      const projection = controlDb().prepare(ONLINE_EVAL_SCORE_PROJECTION_UPSERT_SQL);
      await controlDb().batch(
        records.map((record) => projection.bind(...onlineEvalScoreProjectionBindings(record))),
      );
    };
    await seed(40, 0.95, nowUnix - 3 * 24 * 60 * 60);
    await seed(40, 0.5, nowUnix - 3600);

    // The tenant's own thresholds, in the DURABLE place: `quota_policies`, read
    // through the same `0009` columns a deployment writes. The sweep skips a
    // tenant whose policy it cannot read, so this row is what makes the
    // detection legitimate rather than defaulted — and putting it in D1 rather
    // than in the var also proves the D1 arm of the source, which is the arm
    // every real deployment takes.
    await controlDb()
      .prepare(
        `INSERT INTO quota_policies (id, scope_type, scope_id, online_eval_enabled,
           online_eval_sample_rate, online_eval_judge_model, online_eval_criteria_json,
           online_eval_regression_drop, online_eval_regression_min_samples)
         VALUES (?, 'tenant', ?, 1, 1.0, 'judge-model', ?, 0.1, 20)
         ON CONFLICT (scope_type, scope_id) DO UPDATE SET online_eval_enabled = 1`,
      )
      .bind("qp_tenant_a", "tenant_a", JSON.stringify(CRITERIA))
      .run();

    await gatewayScheduled({}, env(), { waitUntil: () => {} });

    const rows = await storedRegressions();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ tenant: "tenant_a", criterion_id: "grounded" });
  });
});
