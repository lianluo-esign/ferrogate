/**
 * Scores → Analytics Engine, through the collector that already owns the
 * binding.
 *
 * ## Why this does NOT hold an Analytics Engine binding of its own
 *
 * `apps/telemetry` owns the only `writeDataPoint` binding in the fleet, and
 * `requestlog/index.ts` refuses to add a second aggregate path for exactly the
 * reason that matters here too: two writers to one dataset is how a series comes
 * to be double-counted, and this dataset is the one an operator would alert
 * from. So a score travels the SAME road every other gateway metric travels — an
 * OTLP/JSON metrics request to the collector, which fans it into Analytics
 * Engine and Workers Logs.
 *
 * The only new thing this needed was a metric whose SERIES IS DATA: the metric
 * name is fixed, but the criterion, the model and the tenant are attributes
 * taken from the row, and `GatewayMetricsSnapshot` is a fixed struct that cannot
 * express that. Hence `buildOtlpGaugeMetricsRequest` in
 * `@ferrogate/observability` and `TelemetryEmitter.emitGauges` — the collector
 * needed no change at all, because its metric ingest was already generic
 * (`apps/telemetry/src/otlp.ts` reads `metric.gauge.dataPoints[]` and files each
 * as one AE point).
 *
 * ## A gauge, not a counter
 *
 * A score is a LEVEL. The AE query that matters is `AVG(double1)` over a window
 * grouped by the attribute blobs, which is precisely a gauge reading; declaring
 * it a monotonic sum (as the gateway's request counters are) would invite a
 * rate() over a 0-1 quality score, which means nothing.
 *
 * ## The attributes ARE the grouping axes, and they are the same ones cost has
 *
 * `tenant`, `criterion`, `judge_model`, `logical_model`, `provider`,
 * `operation`, `sampling_unit`. Together with #677's cost dimensions they let
 * "did quality move WITH cost" be asked of the metric store as well as of D1 —
 * and `criterion` and `judge_model` are present precisely because a mean taken
 * across either of those is a mean across two different instruments
 * (`./policy.ts`).
 */
import type { OtlpGaugePoint } from "@ferrogate/observability";
import { telemetryFromEnv } from "../telemetry/emit.js";
import type { OnlineEvalScoreRecord } from "./record.js";

/** The metric name. Fixed, so a dashboard is not per-tenant. */
export const ONLINE_EVAL_SCORE_METRIC = "ferrogate.online_eval.score";
/** The regression signal, emitted by `./regression.ts` on the cron tick. */
export const ONLINE_EVAL_REGRESSION_METRIC = "ferrogate.online_eval.regression";

function attribute(key: string, value: string | undefined): { key: string; value: string }[] {
  return value === undefined || value === "" ? [] : [{ key, value }];
}

/** One gauge point per scored criterion. */
export function onlineEvalScorePoints(
  records: readonly OnlineEvalScoreRecord[],
): OtlpGaugePoint[] {
  return records.map((record) => ({
    name: ONLINE_EVAL_SCORE_METRIC,
    description: "Judge score for one sampled production request, in [0, 1].",
    value: record.score,
    timeUnixMs: record.scoredAtUnix * 1000,
    attributes: [
      { key: "tenant", value: record.tenantId },
      { key: "criterion", value: record.criterionId },
      { key: "judge_model", value: record.judgeModel },
      { key: "sampling_unit", value: record.samplingUnit },
      ...attribute("logical_model", record.logicalModel),
      ...attribute("provider", record.provider),
      ...attribute("operation", record.operationId),
      ...attribute("project", record.projectId),
    ],
  }));
}

/**
 * Ship the points. NEVER REJECTS — a collector that is down, unconfigured or
 * rejecting must cost nothing beyond the points themselves; the durable D1 row
 * is already written by the time this runs.
 */
export async function publishOnlineEvalScorePoints(
  env: unknown,
  points: readonly OtlpGaugePoint[],
): Promise<void> {
  if (points.length === 0) return;
  try {
    const emitter = telemetryFromEnv(env);
    if (!emitter.enabled) return;
    await emitter.emitGauges(points);
  } catch {
    // See above.
  }
}
