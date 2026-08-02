/**
 * The sampled exchange as it travels to the judge, and the scored row that
 * comes back.
 *
 * ## Why the sample carries the attribution axes rather than a request id alone
 *
 * The interesting question is never "what did this score" — it is "did quality
 * move WITH cost". #677 made per-request cost queryable by tenant, project, key,
 * model, tag and agent run; a score that could only be joined by `request_id`
 * would answer that question only for requests whose cost row still exists, and
 * only through a join that no aggregate query can push down. So the score row
 * denormalises the SAME axes, taken from the same authenticated context the cost
 * row is taken from, and `request_id` remains the exact join key for the
 * per-request drill-down. See `./d1.ts` for the join that answers the question.
 *
 * ## Why the wire is nested where `requestlog/record.ts` is flat
 *
 * The request log's wire is flat because every fact it carries is a scalar. A
 * sample carries the criteria ARRAY (each an id and a definition) and two large
 * text fields, so flattening would mean inventing a key encoding at the producer
 * and parsing it at the consumer — the same reasoning
 * `guardrails/evidence-wire.ts` gives for its own nested shape.
 *
 * The `object` discriminator is checked FIRST by every decoder for the reason
 * that module states: a permissive decoder handed the wrong message produces a
 * plausible, wrong row rather than an error.
 */
import type { OnlineEvalCriterion, OnlineEvalSamplingUnit } from "./policy.js";

/** `object` on the queue wire — the discriminator `gatewayQueue` routes on. */
export const ONLINE_EVAL_SAMPLE_OBJECT = "online_eval_sample";

/** One sampled exchange, queued for judging. */
export interface OnlineEvalSample {
  /** The id the CLIENT was told — the join key to #664's log and #677's cost. */
  readonly requestId: string;
  /** The AUTHENTICATED tenant. A sample with no tenant is never produced. */
  readonly tenantId: string;
  readonly projectId?: string | undefined;
  readonly workspaceId?: string | undefined;
  readonly apiKeyId?: string | undefined;
  readonly agentRunId?: string | undefined;
  readonly operationId?: string | undefined;
  readonly provider?: string | undefined;
  /** The model the CALLER asked for, after resolution — the trend axis. */
  readonly logicalModel?: string | undefined;
  /** The model the PROVIDER served, which is what actually changed on a swap. */
  readonly providerModel?: string | undefined;
  /**
   * #693 — the traffic-split experiment this response belonged to, and the ARM
   * that produced it.
   *
   * This is what makes a canary-vs-control quality comparison possible at all:
   * the comparison is only legitimate between two populations scored by the
   * SAME judge under the SAME criterion, and both of those are already on the
   * score row — the arm is the third grouping key that turns "one tenant's
   * scores" into "this arm's scores against that arm's".
   *
   * Absent for a sample taken outside an experiment, which is almost all of
   * them. Carried on the WIRE rather than joined back from `request_logs` at
   * read time because a score and its arm must not be able to disagree: the
   * request log can be re-written by a later leg, and a score is a measurement
   * of the response that actually existed when the sample was taken.
   */
  readonly experimentId?: string | undefined;
  readonly experimentArm?: string | undefined;
  /** The bucket key, so a conversation's scores can be grouped as one. */
  readonly samplingKey: string;
  readonly samplingUnit: OnlineEvalSamplingUnit;
  readonly sampleRate: number;
  readonly judgeModel: string;
  readonly criteria: readonly OnlineEvalCriterion[];
  readonly prompt: string;
  readonly completion: string;
  readonly promptTruncated: boolean;
  readonly completionTruncated: boolean;
  readonly sampledAtUnix: number;
}

export type OnlineEvalSampleWire = Record<string, unknown>;

/** The queue body. Absent optionals are OMITTED, never nulled. */
export function onlineEvalSampleToWire(sample: OnlineEvalSample): OnlineEvalSampleWire {
  const wire: OnlineEvalSampleWire = {
    object: ONLINE_EVAL_SAMPLE_OBJECT,
    request_id: sample.requestId,
    tenant_id: sample.tenantId,
    sampling_key: sample.samplingKey,
    sampling_unit: sample.samplingUnit,
    sample_rate: sample.sampleRate,
    judge_model: sample.judgeModel,
    criteria: sample.criteria.map((c) => ({ id: c.id, definition: c.definition })),
    prompt: sample.prompt,
    completion: sample.completion,
    prompt_truncated: sample.promptTruncated,
    completion_truncated: sample.completionTruncated,
    sampled_at_unix: sample.sampledAtUnix,
  };
  const optional: Array<[string, string | undefined]> = [
    ["project_id", sample.projectId],
    ["workspace_id", sample.workspaceId],
    ["api_key_id", sample.apiKeyId],
    ["agent_run_id", sample.agentRunId],
    ["operation_id", sample.operationId],
    ["provider", sample.provider],
    ["logical_model", sample.logicalModel],
    ["provider_model", sample.providerModel],
    ["experiment_id", sample.experimentId],
    ["experiment_arm", sample.experimentArm],
  ];
  for (const [key, value] of optional) {
    if (value !== undefined && value !== "") wire[key] = value;
  }
  return wire;
}

function str(wire: OnlineEvalSampleWire, key: string): string | undefined {
  const value = wire[key];
  return typeof value === "string" && value !== "" ? value : undefined;
}

function criteriaFromWire(value: unknown): OnlineEvalCriterion[] | undefined {
  if (!Array.isArray(value) || value.length === 0) return undefined;
  const criteria: OnlineEvalCriterion[] = [];
  for (const entry of value) {
    if (typeof entry !== "object" || entry === null) return undefined;
    const id = (entry as { id?: unknown }).id;
    const definition = (entry as { definition?: unknown }).definition;
    if (typeof id !== "string" || id === "") return undefined;
    if (typeof definition !== "string" || definition === "") return undefined;
    criteria.push({ id, definition });
  }
  return criteria;
}

/**
 * Decode a queue body. TOTAL — `undefined` for anything that is not one of
 * these, which is what lets the consumer ack a permanently-bad message instead
 * of retrying it until it dead-letters in front of good ones.
 */
export function onlineEvalSampleFromWire(body: unknown): OnlineEvalSample | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const wire = body as OnlineEvalSampleWire;
  if (wire["object"] !== ONLINE_EVAL_SAMPLE_OBJECT) return undefined;

  const requestId = str(wire, "request_id");
  const tenantId = str(wire, "tenant_id");
  const samplingKey = str(wire, "sampling_key");
  const judgeModel = str(wire, "judge_model");
  const criteria = criteriaFromWire(wire["criteria"]);
  const prompt = wire["prompt"];
  const completion = wire["completion"];
  if (
    requestId === undefined ||
    tenantId === undefined ||
    samplingKey === undefined ||
    judgeModel === undefined ||
    criteria === undefined ||
    typeof prompt !== "string" ||
    typeof completion !== "string"
  ) {
    return undefined;
  }

  const unit = wire["sampling_unit"];
  const rate = wire["sample_rate"];
  const sampledAt = wire["sampled_at_unix"];
  return {
    requestId,
    tenantId,
    projectId: str(wire, "project_id"),
    workspaceId: str(wire, "workspace_id"),
    apiKeyId: str(wire, "api_key_id"),
    agentRunId: str(wire, "agent_run_id"),
    operationId: str(wire, "operation_id"),
    provider: str(wire, "provider"),
    logicalModel: str(wire, "logical_model"),
    providerModel: str(wire, "provider_model"),
    experimentId: str(wire, "experiment_id"),
    experimentArm: str(wire, "experiment_arm"),
    samplingKey,
    samplingUnit: unit === "conversation" ? "conversation" : "request",
    sampleRate: typeof rate === "number" && Number.isFinite(rate) ? rate : 0,
    judgeModel,
    criteria,
    prompt,
    completion,
    promptTruncated: wire["prompt_truncated"] === true,
    completionTruncated: wire["completion_truncated"] === true,
    sampledAtUnix:
      typeof sampledAt === "number" && Number.isFinite(sampledAt)
        ? Math.floor(sampledAt)
        : Math.floor(Date.now() / 1000),
  };
}

/**
 * One scored criterion, as it lands in `online_eval_scores`.
 *
 * `score` is normalised to [0, 1] by the JUDGE PARSER, never here: a score that
 * arrives outside the range is a judge that did not follow the rubric, and
 * clamping it would file a fabricated number under the tenant's criterion.
 */
export interface OnlineEvalScoreRecord {
  readonly requestId: string;
  readonly tenantId: string;
  readonly criterionId: string;
  readonly score: number;
  /**
   * The judge's own one-line reason, bounded. Stored because a score with no
   * reason is unauditable — the first thing anyone does with a low score is ask
   * why, and the answer is not reconstructible after the fact.
   */
  readonly rationale?: string | undefined;
  readonly judgeModel: string;
  readonly projectId?: string | undefined;
  readonly workspaceId?: string | undefined;
  readonly apiKeyId?: string | undefined;
  readonly agentRunId?: string | undefined;
  readonly operationId?: string | undefined;
  readonly provider?: string | undefined;
  readonly logicalModel?: string | undefined;
  readonly providerModel?: string | undefined;
  /** #693 — see {@link OnlineEvalSample.experimentId}. */
  readonly experimentId?: string | undefined;
  readonly experimentArm?: string | undefined;
  readonly samplingKey: string;
  readonly samplingUnit: OnlineEvalSamplingUnit;
  readonly sampleRate: number;
  readonly promptTruncated: boolean;
  readonly completionTruncated: boolean;
  readonly scoredAtUnix: number;
}
