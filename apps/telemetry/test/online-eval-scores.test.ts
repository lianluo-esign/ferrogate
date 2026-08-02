/**
 * "Scores land in Analytics Engine" (#692), proven END TO END through the
 * DEPLOYED collector.
 *
 * The gateway does not hold an Analytics Engine binding — `apps/telemetry` owns
 * the only `writeDataPoint` in the fleet, and `requestlog/index.ts` refuses to
 * add a second aggregate writer because two writers to one dataset is how a
 * series comes to be double-counted. So a judge score reaches Analytics Engine
 * the same way every other gateway metric does: an OTLP/JSON metrics request to
 * this Worker.
 *
 * What this file holds is that the envelope the gateway BUILDS
 * (`buildOtlpGaugeMetricsRequest`, the one new thing #692 added to
 * `@ferrogate/observability`) is one this collector already understands — with
 * NO change to `apps/telemetry` at all. The bytes posted below are the real
 * ones: the request is built by the production builder and its body is posted
 * verbatim.
 *
 * MUTATION: rendering the point as a `sum` instead of a `gauge` in
 * `otlp.ts::gaugeMetricJson` keeps this green (the collector reads both), which
 * is why the assertion below is on the AE BLOBS — blob 4 is the metric kind, and
 * it is what an operator's `AVG(double1)` query groups by. Dropping the
 * `attributes` from the data point turns the criterion assertion red, and that
 * is the one that matters: without it a score is unattributable to the
 * criterion, the judge or the tenant, and every trend query is a mean over
 * everything.
 */
import { buildOtlpGaugeMetricsRequest } from "@ferrogate/observability";
import { describe, expect, it } from "vitest";
import app from "../src/index.js";
import { COLLECTOR_TOKEN, RecordingDataset, envWithSink } from "./fixtures.js";

/** The exact points `apps/gateway/src/evals/metrics.ts` builds for one score. */
const SCORE_POINTS = [
  {
    name: "ferrogate.online_eval.score",
    description: "Judge score for one sampled production request, in [0, 1].",
    value: 0.75,
    timeUnixMs: 1_700_000_000_000,
    attributes: [
      { key: "tenant", value: "tenant_a" },
      { key: "criterion", value: "answer_relevance" },
      { key: "judge_model", value: "judge-model" },
      { key: "sampling_unit", value: "conversation" },
      { key: "logical_model", value: "gpt-4o-mini" },
    ],
  },
];

async function post(dataset: RecordingDataset, body: Uint8Array): Promise<Response> {
  return app.fetch(
    new Request("https://collector.test/v1/metrics", {
      method: "POST",
      headers: {
        authorization: `Bearer ${COLLECTOR_TOKEN}`,
        "content-type": "application/json",
        "x-ferrogate-tenant": "tenant_a",
      },
      body,
    }),
    envWithSink(dataset) as unknown as Record<string, unknown>,
  );
}

describe("a judge score reaches Analytics Engine through the existing collector", () => {
  it("accepts the gauge envelope the gateway builds and writes one data point", async () => {
    const built = buildOtlpGaugeMetricsRequest(
      "https://collector.test",
      "ferrogate-gateway",
      SCORE_POINTS,
    );
    // The builder targets the metrics path — a gauge is still the METRIC
    // signal, not a fourth one the collector would 404.
    expect(built.url).toBe("https://collector.test/v1/metrics");

    const dataset = new RecordingDataset();
    const response = await post(dataset, built.body);

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ accepted: 1, dataPoints: 1, dropped: 0 });

    expect(dataset.points).toHaveLength(1);
    const point = dataset.points[0];
    // The score itself is `double1`, which is what `AVG(double1)` reads.
    expect(point?.doubles).toEqual([0.75]);
    // The tenant is the AE index — one point per tenant, queryable per tenant.
    expect(point?.indexes).toEqual(["tenant_a"]);

    const blobs = point?.blobs ?? [];
    expect(blobs[0]).toBe("metric");
    expect(blobs[1]).toBe("ferrogate.online_eval.score");
    expect(blobs[4]).toBe("gauge");
    // The grouping axes. Without them a score cannot be attributed to a
    // criterion, a judge or a model, and no trend query means anything.
    expect(blobs).toContain("criterion=answer_relevance");
    expect(blobs).toContain("judge_model=judge-model");
    expect(blobs).toContain("logical_model=gpt-4o-mini");
    expect(blobs).toContain("tenant=tenant_a");
  });

  it("writes one point per score in a batch", async () => {
    const built = buildOtlpGaugeMetricsRequest("https://collector.test", "ferrogate-gateway", [
      ...SCORE_POINTS,
      {
        ...SCORE_POINTS[0],
        name: "ferrogate.online_eval.score",
        value: 0.25,
        attributes: [
          { key: "tenant", value: "tenant_a" },
          { key: "criterion", value: "grounded" },
        ],
      },
    ] as never);

    const dataset = new RecordingDataset();
    const response = await post(dataset, built.body);

    expect(await response.json()).toMatchObject({ accepted: 2, dataPoints: 2 });
    expect(dataset.points.map((p) => p.doubles?.[0])).toEqual([0.75, 0.25]);
  });
});
