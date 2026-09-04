/**
 * The CONSUMER — where the judge actually runs, in a Worker invocation that no
 * client is waiting on.
 *
 * ```
 *   queue(batch) ─→ decode ─→ residency gate on the JUDGE route (#681)
 *                          ─→ judge dispatch (chat.completions, temperature 0)
 *                          ─→ parse verdict
 *                          ─→ D1 batch upsert  `online_eval_scores`
 *                          ─→ Analytics Engine gauge, via apps/telemetry
 * ```
 *
 * ## Why the gateway consumes its own queue
 *
 * The same topology and the same reasoning as #664's request-log queue: the
 * only things this work needs are the model catalogue, the provider credentials
 * and the CONTROL database, and this Worker already binds all three. Routing the
 * message to a second Worker would add a deploy unit and a second copy of the
 * provider credentials to run one model call. A Worker consuming a queue it
 * produces is a supported Cloudflare topology — a separate invocation with its
 * own `env`, not a re-entrant call.
 *
 * ## THE RESIDENCY GATE IS HERE, AND IT IS THE SAME FUNCTION ROUTE ELIGIBILITY
 * USES
 *
 * A judge call ships the tenant's prompt to a provider, which is exactly what
 * `inference/candidates.ts` and `inference/shadow.ts` are constrained by. So
 * this leg calls `residencyViolations` — the one function that answers "may this
 * route carry this tenant's prompt" — against the JUDGE route, and drops the
 * sample when it says no. Without it, an EU-only tenant's prompt would leave the
 * region through the evaluation path while the inference path refused, which is
 * precisely the "policy honoured on the primary and forgotten on a secondary"
 * failure #681 was written to close. A ZDR tenant never reaches here at all (the
 * sampler excludes them), and the ZDR arm of the same function is still applied,
 * because a policy can change between sampling and judging.
 *
 * ## The retry rule, stated
 *
 * A judge call costs money, and Queues are at-least-once, so "retry everything"
 * is a way to spend an unbounded amount of it on a bad afternoon.
 *
 *  - a message that does not DECODE is acked and counted — it cannot become
 *    valid on redelivery, and retrying would hold a permanently-bad message in
 *    front of good ones;
 *  - a judge that is unreachable, refuses, or answers off-rubric is acked and
 *    counted. **A lost sample is not a lost fact**: this is a measurement of a
 *    sample, and a slightly smaller sample is a much better outcome than a
 *    retry storm against a provider that is already unhappy;
 *  - only a D1 WRITE failure arms `retryAll()`, because there the judging has
 *    already been paid for and the row is the thing that survives. Redelivery
 *    re-judges (bounded by `max_retries`), and the upsert makes the re-applied
 *    row idempotent rather than a doubled sample.
 */
import { defaultAdapterRegistry } from "../inference/adapters.js";
import { modelsFromEnv } from "../inference/catalog.js";
import { dispatcherFromEnv } from "../inference/defaults.js";
import { readBoundedProviderBody } from "../inference/dispatch.js";
import type { InferenceBindings, PhysicalRoute, UpstreamDispatcher } from "../inference/ports.js";
import { residencyViolations } from "../residency/policy.js";
import { residencyPolicySourceFromEnv } from "../residency/source.js";
import type { ResidencyBindings } from "../residency/source.js";
import { completionTextFrom } from "./content.js";
import {
  type OnlineEvalScoreDatabase,
  onlineEvalDatabaseFrom,
  onlineEvalTenantDatabaseFrom,
  writeTenantOnlineEvalScores,
} from "./d1.js";
import { buildJudgeRequestBody, parseJudgeVerdict } from "./judge.js";
import { refreshOnlineEvalLegQuality } from "./leg-quality.js";
import { onlineEvalScorePoints, publishOnlineEvalScorePoints } from "./metrics.js";
import { type OnlineEvalSample, onlineEvalSampleFromWire } from "./record.js";
import type { OnlineEvalScoreRecord } from "./record.js";

/** The `MessageBatch` slice this consumer uses, structurally. */
export interface OnlineEvalMessageBatch {
  readonly queue?: string;
  readonly messages: readonly { readonly body: unknown; ack?(): void }[];
  retryAll?(options?: unknown): void;
}

/** What one delivery did, for the caller's diagnostics and for the tests. */
export interface OnlineEvalConsumeResult {
  /** Scores written to D1. */
  readonly scored: number;
  /** Messages whose body could not be decoded; acked, never retried. */
  readonly malformed: number;
  /** Samples dropped because the judge route may not carry this tenant's prompt. */
  readonly refusedResidency: number;
  /** Samples the judge could not usefully score; acked, never retried. */
  readonly unjudgeable: number;
  /** True when the batch was handed back for redelivery (a D1 failure). */
  readonly retried: boolean;
}

/** The seams the tests replace. Production resolves every one from `env`. */
export interface OnlineEvalConsumerDeps {
  readonly routeFor?: (env: unknown, model: string) => PhysicalRoute | null;
  readonly dispatcher?: (env: unknown) => UpstreamDispatcher;
  /**
   * Object-authoritative score database, grouped one tenant at a time. This is
   * the ONLY durable destination: a score is tenant data and lives in the owning
   * object, never mirrored into the shared control store (#859/#881 red line).
   * The control projection that once dual-wrote here was retired end to end —
   * production has always run `projectToControl: false`, and control migration
   * 0043 has since DROPped the `online_eval_scores` mirror table, so there is no
   * longer a second copy to write, to drift, or to reconcile.
   */
  readonly tenantDatabase?: (env: unknown, tenantId: string) => OnlineEvalScoreDatabase | undefined;
  readonly now?: () => number;
  /** Judge call timeout. A wedged judge must not hold the consumer open. */
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
}

const DEFAULT_JUDGE_TIMEOUT_MS = 30_000;
const DEFAULT_JUDGE_MAX_BYTES = 256 * 1024;

/** Run the judge for one sample. `undefined` when it produced nothing usable. */
async function judge(
  sample: OnlineEvalSample,
  route: PhysicalRoute,
  dispatcher: UpstreamDispatcher,
  timeoutMs: number,
  maxBytes: number,
): Promise<ReturnType<typeof parseJudgeVerdict> | undefined> {
  const adapter = defaultAdapterRegistry.adapterFor(route.providerKind);
  if (adapter === null) return undefined;
  const built = adapter.buildUpstreamRequest({
    operation: "chat.completions",
    route,
    logicalModel: sample.judgeModel,
    providerModel: route.providerModel,
    stream: false,
    body: buildJudgeRequestBody(sample, route.providerModel),
  });
  if (!built.ok) return undefined;

  // No client abort signal exists here — there is no client. The deadline is
  // what stops a wedged judge from holding the consumer invocation open.
  const response = await dispatcher.dispatch(built.request, AbortSignal.timeout(timeoutMs));
  if (response.status !== 200) {
    await response.body?.cancel();
    return undefined;
  }
  const text = await readBoundedProviderBody(response, maxBytes);
  let parsedBody: unknown;
  try {
    parsedBody = JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
  const answer = completionTextFrom(parsedBody);
  if (answer === undefined) return undefined;
  return parseJudgeVerdict(answer, sample.criteria);
}

/**
 * Apply one queue delivery.
 *
 * NEVER throws: a consumer that throws gets its batch redelivered by the
 * platform anyway, so throwing would only lose the ability to say what happened.
 * Failure is reported by arming `retryAll()` and returning `retried: true`.
 */
export async function consumeOnlineEvalBatch(
  batch: OnlineEvalMessageBatch,
  env: unknown,
  deps: OnlineEvalConsumerDeps = {},
): Promise<OnlineEvalConsumeResult> {
  const routeFor =
    deps.routeFor ??
    ((e: unknown, model: string) => modelsFromEnv(e as InferenceBindings).resolve(model));
  const dispatcherFor =
    deps.dispatcher ?? ((e: unknown) => dispatcherFromEnv(e as InferenceBindings));
  const tenantDatabaseFor = deps.tenantDatabase ?? onlineEvalTenantDatabaseFrom;
  const now = deps.now ?? (() => Date.now());
  const timeoutMs = deps.timeoutMs ?? DEFAULT_JUDGE_TIMEOUT_MS;
  const maxBytes = deps.maxResponseBytes ?? DEFAULT_JUDGE_MAX_BYTES;

  const samples: OnlineEvalSample[] = [];
  let malformed = 0;
  for (const message of batch.messages) {
    const sample = onlineEvalSampleFromWire(message.body);
    if (sample === undefined) {
      malformed += 1;
      message.ack?.();
      continue;
    }
    samples.push(sample);
  }
  if (samples.length === 0) {
    return { scored: 0, malformed, refusedResidency: 0, unjudgeable: 0, retried: false };
  }

  const residencySource = residencyPolicySourceFromEnv(env as ResidencyBindings);
  const dispatcher = dispatcherFor(env);
  const records: OnlineEvalScoreRecord[] = [];
  let refusedResidency = 0;
  let unjudgeable = 0;

  for (const sample of samples) {
    const route = routeFor(env, sample.judgeModel);
    if (route === null) {
      // The judge model is not in this deployment's catalogue. Nothing to
      // retry: a redelivery would resolve the same empty catalogue.
      unjudgeable += 1;
      continue;
    }

    // #681 — may THIS tenant's prompt reach the judge's provider?
    const residency = await residencySource.policyFor(sample.tenantId);
    if (!residency.ok) {
      // The policy could not be read. Fail CLOSED: the prompt is not sent. This
      // is the opposite of the sampler's fail direction only in appearance —
      // both refuse to copy content when the governing policy is unknown.
      refusedResidency += 1;
      continue;
    }
    if (residencyViolations(route, residency.policy).length > 0) {
      refusedResidency += 1;
      continue;
    }

    let verdict: Awaited<ReturnType<typeof judge>>;
    try {
      verdict = await judge(sample, route, dispatcher, timeoutMs, maxBytes);
    } catch {
      // Transport failure, timeout, oversized body. Acked and counted; see the
      // retry rule in the module docs.
      verdict = undefined;
    }
    if (verdict === undefined || !verdict.ok) {
      unjudgeable += 1;
      continue;
    }

    const scoredAtUnix = Math.floor(now() / 1000);
    for (const score of verdict.scores) {
      records.push({
        requestId: sample.requestId,
        tenantId: sample.tenantId,
        criterionId: score.criterionId,
        score: score.score,
        rationale: score.rationale,
        judgeModel: sample.judgeModel,
        projectId: sample.projectId,
        workspaceId: sample.workspaceId,
        apiKeyId: sample.apiKeyId,
        agentRunId: sample.agentRunId,
        operationId: sample.operationId,
        provider: sample.provider,
        logicalModel: sample.logicalModel,
        providerModel: sample.providerModel,
        experimentId: sample.experimentId,
        experimentArm: sample.experimentArm,
        samplingKey: sample.samplingKey,
        samplingUnit: sample.samplingUnit,
        sampleRate: sample.sampleRate,
        promptTruncated: sample.promptTruncated,
        completionTruncated: sample.completionTruncated,
        scoredAtUnix,
      });
    }
  }

  if (records.length === 0) {
    for (const message of batch.messages) message.ack?.();
    return { scored: 0, malformed, refusedResidency, unjudgeable, retried: false };
  }

  // #894 — the tenants whose per-leg quality aggregate this batch invalidated.
  // Collected inside the write loop and recomputed only AFTER the whole batch is
  // durable: the aggregate is a projection of the scores, so recomputing it from
  // a partially written batch would publish a mean over rows that a `retryAll`
  // is about to re-derive.
  const refreshed: string[] = [];
  try {
    // The tenant object is the sole durable destination. A score is tenant data
    // and lives in the owning object, never mirrored into the shared control
    // store (#859/#881 red line); the control projection that once dual-wrote
    // beside this was retired and its table DROPped (0043). Grouped one tenant
    // at a time so each batch reaches exactly one object.
    const byTenant = new Map<string, OnlineEvalScoreRecord[]>();
    for (const record of records) {
      if (record.tenantId.trim() === "") {
        throw new Error("online evaluation score has no tenant authority");
      }
      const group = byTenant.get(record.tenantId) ?? [];
      group.push(record);
      byTenant.set(record.tenantId, group);
    }
    for (const [tenantId, group] of byTenant) {
      const tenantDatabase = tenantDatabaseFor(env, tenantId);
      if (tenantDatabase === undefined) {
        throw new Error(`tenant evaluation database is unavailable for ${tenantId}`);
      }
      await writeTenantOnlineEvalScores(tenantDatabase, group);
      refreshed.push(tenantId);
    }
  } catch {
    batch.retryAll?.();
    return { scored: 0, malformed, refusedResidency, unjudgeable, retried: true };
  }

  // #894 — the rolling per-(provider, provider_model) aggregate the router
  // reads, recomputed OFF the request path. Best-effort by construction: the
  // judge has already been paid for and the scores are already durable, so a
  // failed recompute must not retry the batch (which would re-judge every
  // sample). The next batch, or the cron sweep, recomputes the same window.
  for (const tenantId of refreshed) {
    // `onlineEvalDatabaseFrom` is passed as the `database` arg SOLELY to satisfy
    // the object-first guard inside `refreshOnlineEvalLegQuality`, which keys off
    // that exact identity (`=== onlineEvalDatabaseFrom`) to decide that an absent
    // tenant-object binding is a misconfiguration rather than licence to
    // aggregate a shared control table. The recompute itself reads and writes the
    // tenant object resolved by `tenantDatabaseFor`; nothing is written to
    // control.
    await refreshOnlineEvalLegQuality(
      env,
      tenantId,
      Math.floor(now() / 1000),
      onlineEvalDatabaseFrom,
      tenantDatabaseFor,
    ).catch(() => 0);
  }

  // Analytics Engine, AFTER the durable write and never in front of it: the D1
  // row is the record of what was measured, the metric is the series an
  // operator watches. A metrics outage must not cost a score.
  await publishOnlineEvalScorePoints(env, onlineEvalScorePoints(records));

  for (const message of batch.messages) message.ack?.();
  return { scored: records.length, malformed, refusedResidency, unjudgeable, retried: false };
}
