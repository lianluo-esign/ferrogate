/**
 * THE PASS (#697) — the I/O half: claim the window, read the spend, run
 * `./detector.ts`, maintain the episode ledger, notify, throttle.
 *
 * It holds no judgement about what an anomaly is. Every "should this fire"
 * question is answered in `./detector.ts`, which is pure; every "should this
 * page someone" question is answered here, because it depends on durable state
 * (what fired before, and when it was last delivered).
 *
 * ============================================================================
 * EPISODES, NOT DETECTIONS — the answer to "it has been firing for six hours"
 * ============================================================================
 *
 * The naive ledger records one row per detection and sends one webhook per row.
 * At a one-hour window that is 6 pages for a 6-hour incident; at the five-minute
 * window an impatient operator will configure, it is 72. Nobody reads the 72nd,
 * and nobody reads the next real one either, because the channel is muted by
 * then. **That is the failure this design is shaped around.**
 *
 * So the ledger holds EPISODES. One row per (scope, signal) occurrence, opened
 * by the first window that detects, absorbing every consecutive window that
 * keeps detecting, closed by the first that does not. The partial unique index
 * `idx_spend_anomaly_open` is the arbiter: at most one OPEN episode per
 * (scope, signal), enforced by the database rather than by a read-then-write.
 *
 * A notification is sent when, and only when:
 *
 *  1. the episode OPENS — new information;
 *  2. the severity ESCALATES past everything this episode has been —
 *     "warning -> critical" is new information, and it is the one an operator
 *     wants immediately;
 *  3. `cooldownSecs` has elapsed since the last notification and it is STILL
 *     firing — a heartbeat, not a repeat, so an operator who missed the first
 *     one is told again but a channel is not flooded.
 *
 * Six hours of a stuck loop at the defaults is therefore **2 notifications**
 * (open + one 6-hour heartbeat), not 72. A de-escalation is silent: an episode
 * that was critical and is now merely a warning has not produced news.
 *
 * ============================================================================
 * ONE EVALUATOR PER WINDOW
 * ============================================================================
 *
 * The Cron Trigger ticks every minute and the window is an hour, so 59 of 60
 * ticks have nothing to do. `INSERT OR IGNORE INTO spend_anomaly_runs` on the
 * window start is the claim; a tick that does not win it returns after ONE
 * write. The claim is marked in-flight (`scopes_evaluated = -1`) before any
 * tenant object is touched, and a bounded lease lets a later tick reclaim it
 * if the Worker dies after claiming. A failed pass clears its own claim.
 *
 * That claim is also what makes the cooldown check safe. "Read when we last
 * notified, then decide" is a race in general; behind this claim there is
 * exactly one evaluator per window, so it is not one here. The reasoning does
 * NOT survive being moved to the request path, which is why it is written down
 * rather than left as a comfortable assumption.
 */
import { periodMonthFromUnix } from "@ferrogate/storage";
import { resolveControlDatabase, resolveTenantStorage } from "../adapters.js";
import type { ControlPlaneBindings } from "../ports.js";
import {
  type BurnRateDecision,
  type ForecastDecision,
  SEVERITY_RANK,
  SPEND_ANOMALY_WINDOW_SECS,
  type SpendAnomalySeverity,
  type SpendAnomalySignal,
  type SpendAnomalyTuning,
  evaluateBurnRate,
  evaluateForecast,
} from "./detector.js";
import {
  type SpendAlertDelivery,
  type SpendAnomalyWebhookPayload,
  dispatchSpendAnomalyAlert,
  meaningOf,
  spendAlertDeliveryFrom,
} from "./notify.js";
import { SPEND_ANOMALY_POLICY_COLUMNS, budgetFromRow, tuningFromRow } from "./policy.js";
import {
  readPeriodSpendFleet,
  readSpendBucketsFleet,
  readTenantPoliciesFleet,
} from "./source.js";

export const SPEND_ANOMALY_EPISODE_TABLE = "spend_anomaly_episodes";
export const SPEND_ANOMALY_RUN_TABLE = "spend_anomaly_runs";
export const SPEND_THROTTLE_TABLE = "spend_throttles";

/**
 * The auto-throttle upsert. Extracted so the authoritative control write and the
 * best-effort tenant-object shadow (below) run the IDENTICAL statement — the two
 * `spend_throttles` schemas are byte-identical by construction
 * (`0032_spend_throttles.sql`), so the same bind list is total against both.
 *
 * `ON CONFLICT DO UPDATE` with a `MIN` on the RPM keeps the TIGHTER of two
 * signals firing critical for the same scope; the expiry only moves forward, so
 * a still-firing episode keeps the throttle alive without a second row.
 */
const SPEND_THROTTLE_UPSERT_SQL = `INSERT INTO ${SPEND_THROTTLE_TABLE}
     (scope_type, scope_id, rpm_limit, reason, episode_id, created_at_unix, expires_at_unix)
   VALUES ('tenant', ?, ?, ?, ?, ?, ?)
   ON CONFLICT (scope_type, scope_id) DO UPDATE SET
     rpm_limit = MIN(rpm_limit, excluded.rpm_limit),
     reason = excluded.reason,
     episode_id = excluded.episode_id,
     expires_at_unix = MAX(expires_at_unix, excluded.expires_at_unix)`;
/** A dead isolate must not suppress the same closed window forever. */
export const SPEND_ANOMALY_CLAIM_LEASE_SECS = 15 * 60;

/**
 * Track A G2 (stop-control-write) for `spend_throttles`.
 *
 * DEFAULT (unset/`"control"`): the throttle is authoritative on the shared
 * control object with a best-effort tenant-object shadow — the dual-write the
 * admission readers depend on until `GATEWAY_QUOTA_POLICY_SOURCE` flips. When
 * this reads `"tenant_object"` the auto-throttle writes ONLY the owning tenant's
 * own object and NEVER the shared control mirror, which is the
 * [[no-tenant-data-mirror-in-control-d1]] end state. Any other value reads as
 * the safe default (a config typo must not silently stop the brake). See the
 * `CONTROL_SPEND_THROTTLE_SOURCE` binding docs for the deploy-ordering gate.
 */
function spendThrottleWritesTenantObjectOnly(env: ControlPlaneBindings): boolean {
  return (env.CONTROL_SPEND_THROTTLE_SOURCE ?? "").trim() === "tenant_object";
}

/**
 * What one pass reports back on the tick summary.
 *
 * `skipped` distinguishes the three silences an operator most needs to tell
 * apart, because in the DESTINATION (an alert channel) they look identical:
 * the pass did not run, the pass ran and found nothing, the pass ran and could
 * not deliver.
 */
export interface SpendAnomalyReport {
  readonly evaluated: number;
  readonly opened: number;
  readonly notified: number;
  readonly deliveryFailed: number;
  readonly throttled: number;
  readonly resolved: number;
  readonly skipped?: "unconfigured" | "already_evaluated" | "failed" | undefined;
  readonly windowStartUnix?: number | undefined;
  /** `true` when detection ran but no receiver is configured to deliver to. */
  readonly deliveryUnconfigured?: boolean | undefined;
}

const IDLE: SpendAnomalyReport = {
  evaluated: 0,
  opened: 0,
  notified: 0,
  deliveryFailed: 0,
  throttled: 0,
  resolved: 0,
};

/** UTC calendar-month bounds — the billing period, matching `periodMonthFromUnix`. */
export function monthBoundsUnix(unixSeconds: number): { startUnix: number; endUnix: number } {
  const date = new Date(unixSeconds * 1000);
  const year = date.getUTCFullYear();
  const month = date.getUTCMonth();
  return {
    startUnix: Math.floor(Date.UTC(year, month, 1) / 1000),
    endUnix: Math.floor(Date.UTC(year, month + 1, 1) / 1000),
  };
}

interface EpisodeRow {
  readonly id: string;
  readonly severity: string;
  readonly peak_severity: string;
  readonly windows_seen: number;
  readonly notified_count: number;
  readonly last_notified_unix: number | null;
}

interface EpisodeProjectionRow extends EpisodeRow {
  readonly scope_type: string;
  readonly scope_id: string;
  readonly signal: string;
  readonly window_start_unix: number;
  readonly window_secs: number;
  readonly opened_at_unix: number;
  readonly last_seen_unix: number;
  readonly resolved_at_unix: number | null;
  readonly observed_usd: number;
  readonly baseline_usd: number | null;
  readonly threshold_usd: number | null;
  readonly bound_by: string | null;
  readonly baseline_windows: number | null;
  readonly active_windows: number | null;
  readonly projected_usd: number | null;
  readonly budget_usd: number | null;
  readonly period_month: string | null;
  readonly detail_json: string;
}

const EPISODE_COLUMNS = [
  "id",
  "scope_type",
  "scope_id",
  "signal",
  "severity",
  "peak_severity",
  "window_start_unix",
  "window_secs",
  "opened_at_unix",
  "last_seen_unix",
  "resolved_at_unix",
  "windows_seen",
  "notified_count",
  "last_notified_unix",
  "observed_usd",
  "baseline_usd",
  "threshold_usd",
  "bound_by",
  "baseline_windows",
  "active_windows",
  "projected_usd",
  "budget_usd",
  "period_month",
  "detail_json",
] as const;

/** One scope's evaluation, before anything is written. */
interface ScopeEvaluation {
  readonly scopeId: string;
  readonly tuning: SpendAnomalyTuning;
  readonly burn: BurnRateDecision;
  readonly forecast: ForecastDecision;
  readonly budgetUsd: number | undefined;
  readonly periodSpendUsd: number;
}

/**
 * One detection pass over the most recently CLOSED window.
 *
 * Never rejects: every failure is folded into the report. A `scheduled` handler
 * that throws is RETRIED by the platform, and retrying would re-run the
 * schedule dispatch, the audit anchor and the SIEM pump that share this tick —
 * re-dispatching a customer's agent schedules because a spend query failed is a
 * far worse outcome than a missed detection window.
 */
export async function runSpendAnomalyPass(
  env: ControlPlaneBindings,
  now: number,
  options: { readonly fetchImpl?: typeof fetch | undefined } = {},
): Promise<SpendAnomalyReport> {
  const db = resolveControlDatabase(env);
  if (db === null) return { ...IDLE, skipped: "unconfigured" };
  try {
    return await evaluateWindow(db, env, now, options.fetchImpl);
  } catch (error) {
    console.warn("control-plane: spend anomaly pass failed", error);
    return { ...IDLE, skipped: "failed" };
  }
}

async function evaluateWindow(
  db: D1Database,
  env: ControlPlaneBindings,
  now: number,
  fetchImpl: typeof fetch | undefined,
): Promise<SpendAnomalyReport> {
  // The FLEET window size, and there is only one. It is a constant rather than
  // a per-scope knob because the bucketing is one `GROUP BY` for everybody, the
  // window alignment is one grid for everybody, and `spend_anomaly_runs` claims
  // one window start for everybody — a per-scope width would need all three per
  // distinct width, which is the fan-out this pass exists to avoid.
  // `detector.ts` records what it cost to learn that the alternative (a knob
  // that changed only the forecast divisor) manufactures critical alerts.
  const windowSecs = SPEND_ANOMALY_WINDOW_SECS;
  const windowStartUnix = Math.floor(now / windowSecs) * windowSecs - windowSecs;

  // THE CLAIM. A negative `scopes_evaluated` is an in-flight marker. It is
  // intentionally stored in the existing table so this repair needs no schema
  // change: a completed row remains non-negative, while a dead evaluator can
  // be reclaimed after the lease.
  const claim = await db
    .prepare(
      `INSERT OR IGNORE INTO ${SPEND_ANOMALY_RUN_TABLE}
        (window_start_unix, ran_at_unix, scopes_evaluated)
       VALUES (?, ?, -1)`,
    )
    .bind(windowStartUnix, now)
    .run();
  if ((claim.meta?.changes ?? 0) === 0) {
    const reclaimed = await db
      .prepare(
        `UPDATE ${SPEND_ANOMALY_RUN_TABLE}
            SET ran_at_unix = ?, scopes_evaluated = -1,
                episodes_opened = 0, notifications_sent = 0
          WHERE window_start_unix = ?
            AND scopes_evaluated = -1
            AND ran_at_unix <= ?`,
      )
      .bind(now, windowStartUnix, now - SPEND_ANOMALY_CLAIM_LEASE_SECS)
      .run();
    if ((reclaimed.meta?.changes ?? 0) === 0) {
      return { ...IDLE, skipped: "already_evaluated", windowStartUnix };
    }
  }

  try {
    const period = monthBoundsUnix(windowStartUnix);
    const periodMonth = periodMonthFromUnix(windowStartUnix);
    const windowEnd = windowStartUnix + windowSecs;
    // ONE router for both legs the object cutover moved to per-tenant storage:
    // the spend READ (`billing_events` lives only in each tenant's own object,
    // so the fleet query below fans out) and the episode WRITE (authoritative in
    // — and read back from — the object; the operator fleet view fans out to the
    // objects too, so there is no control-facade mirror to keep in sync).
    const tenantRouter = resolveTenantStorage(env);
    const episodeObjects = new Map<string, D1Database>();
    const episodeObjectFor = async (tenantId: string): Promise<D1Database> => {
      const existing = episodeObjects.get(tenantId);
      if (existing !== undefined) return existing;
      const handle = await tenantRouter.forTenant(tenantId);
      if (handle.source !== "durable_object") {
        throw new Error(
          `spend anomaly episodes require TenantDataObject storage for tenant ${tenantId}; got ${handle.source}`,
        );
      }
      episodeObjects.set(tenantId, handle.db);
      return handle.db;
    };

    // The policies are read FIRST, and the bucket query is then widened to the
    // LONGEST baseline anyone configured. Reading them in parallel and slicing
    // from the shipped default is what made `spend_anomaly_baseline_windows`
    // inert: a scope that asked for 48 windows had only 24 fetched, so the knob
    // could not have worked however the slice was written. `tuningFromRow` bounds
    // the value, so this range is bounded too.
    // The tuning is read from each tenant's OWN object (the `quota_policies`
    // enforcement row moved there with the rest of the tenant-private data), by
    // the SAME fan-out and off the SAME roster as the spend read below — so the
    // scopes align and no tenant's tuning is read from a shared control mirror.
    const policyRows = await readTenantPoliciesFleet(tenantRouter, SPEND_ANOMALY_POLICY_COLUMNS);
    const policies = new Map(policyRows.map((row) => [String(row.scope_id), row]));
    const tunings = new Map<string, SpendAnomalyTuning>();
    let widestBaseline = tuningFromRow(undefined).baselineWindows;
    for (const [scopeId, row] of policies) {
      const tuning = tuningFromRow(row);
      tunings.set(scopeId, tuning);
      widestBaseline = Math.max(widestBaseline, tuning.baselineWindows);
    }
    const baselineFrom = windowStartUnix - widestBaseline * windowSecs;

    const [buckets, periodSpend] = await Promise.all([
      readSpendBucketsFleet(tenantRouter, baselineFrom, windowEnd, windowSecs),
      readPeriodSpendFleet(tenantRouter, period.startUnix, windowEnd),
    ]);

    // Index the buckets by tenant. A tenant appears here iff it produced at least
    // one PRICED request in the lookback — which is also the definition of "has
    // a baseline at all", so the set of scopes to evaluate falls out of the data
    // rather than out of a tenant registry that would include tenants with no
    // traffic and give them an all-zero baseline.
    const observedBucket = Math.floor(windowStartUnix / windowSecs);
    const series = new Map<string, Map<number, number>>();
    for (const row of buckets) {
      const byBucket = series.get(row.tenant) ?? new Map<number, number>();
      byBucket.set(row.bucket, row.cost_usd ?? 0);
      series.set(row.tenant, byBucket);
    }
    const periodByTenant = new Map(periodSpend.map((row) => [row.tenant, row.cost_usd ?? 0]));

    const evaluations: ScopeEvaluation[] = [];
    for (const [scopeId, byBucket] of series) {
      const policy = policies.get(scopeId);
      const tuning = tunings.get(scopeId) ?? tuningFromRow(undefined);
      const budgetUsd = budgetFromRow(policy);
      const observedUsd = byBucket.get(observedBucket) ?? 0;

      // The baseline, oldest first. A bucket with no row is a window in which the
      // tenant spent nothing; it is present as ZERO only from the tenant's FIRST
      // observed bucket onward, because windows before a tenant existed are not
      // observations of that tenant and counting them would let a two-hour-old
      // tenant clear a twelve-window baseline gate with ten fabricated zeroes.
      const firstBucket = Math.min(...byBucket.keys());
      const baseline: number[] = [];
      // `tuning.baselineWindows`, which is the scope's OWN configured width — the
      // audited defect was slicing from the shipped default here, so an operator
      // who set 4 was compared against 24 and the episode reported `24` back at
      // them.
      for (
        let bucket = observedBucket - tuning.baselineWindows;
        bucket < observedBucket;
        bucket += 1
      ) {
        if (bucket < firstBucket) continue;
        baseline.push(byBucket.get(bucket) ?? 0);
      }

      const periodSpendUsd = periodByTenant.get(scopeId) ?? observedUsd;
      const input = {
        scopeType: "tenant" as const,
        scopeId,
        windowStartUnix,
        observedUsd,
        // The width the sum above was taken over — the SAME number written to
        // `spend_anomaly_episodes.window_secs` a few lines below.
        observedWindowSecs: windowSecs,
        baseline,
        periodSpendUsd,
        budgetUsd,
        periodRemainingSecs: Math.max(period.endUnix - windowEnd, 0),
        tuning,
      };
      evaluations.push({
        scopeId,
        tuning,
        burn: evaluateBurnRate(input),
        forecast: evaluateForecast(input),
        budgetUsd,
        periodSpendUsd,
      });
    }

    const delivery = spendAlertDeliveryFrom(env);
    let opened = 0;
    let notified = 0;
    let deliveryFailed = 0;
    let throttled = 0;
    let resolved = 0;

    for (const evaluation of evaluations) {
      for (const signal of ["burn_rate_spike", "forecast_overrun"] as const) {
        const detected =
          signal === "burn_rate_spike"
            ? evaluation.burn.outcome === "detected"
            : evaluation.forecast.outcome === "detected";

        if (!detected) {
          // The episode closes on the first window that does NOT detect. Closing
          // here rather than on a timeout is what makes `windows_seen` mean
          // "consecutive windows this was true for" instead of "windows since it
          // was first true", which are different numbers during a flapping
          // incident and only the first is actionable.
          const episodeDb = await episodeObjectFor(evaluation.scopeId);
          const closed = await closeEpisode(episodeDb, evaluation.scopeId, signal, now);
          if (closed !== null) {
            resolved += 1;
          }
          continue;
        }

        const episodeDb = await episodeObjectFor(evaluation.scopeId);
        const outcome = await upsertEpisode(episodeDb, {
          scopeId: evaluation.scopeId,
          signal,
          windowStartUnix,
          windowSecs,
          now,
          periodMonth,
          evaluation,
        });
        if (outcome.opened) opened += 1;

        // AUTO-THROTTLE, before the notification: an operator reading the alert
        // should already be able to see that the brake was applied, and the
        // payload carries `auto_throttled_rpm` to say so. It fires only on a
        // CRITICAL episode and only when the scope configured an RPM — this is
        // the one leg that changes what the gateway does to live traffic.
        let throttledRpm: number | null = null;
        const rpm = evaluation.tuning.autoThrottleRpm;
        if (rpm !== undefined && outcome.severity === "critical" && outcome.shouldNotify) {
          // `episodeDb` is this tenant's own object (resolved just above for the
          // episode write). G2 (stop-control-write): when routed to the object the
          // throttle is authoritative THERE and the shared control mirror is not
          // written at all; until the flip it stays authoritative on control with
          // the object as a best-effort shadow, so the DO-side row is present when
          // the admission readers cut over. The winning arg is always a WRITABLE
          // db (the episode upsert on `episodeDb` just succeeded).
          const toObjectOnly = spendThrottleWritesTenantObjectOnly(env);
          throttledRpm = await applyThrottle(
            toObjectOnly ? episodeDb : db,
            {
              scopeId: evaluation.scopeId,
              rpm,
              ttlSecs: evaluation.tuning.throttleTtlSecs,
              episodeId: outcome.episodeId,
              signal,
              now,
            },
            toObjectOnly ? undefined : episodeDb,
          );
          if (throttledRpm !== null) throttled += 1;
        }

        if (!outcome.shouldNotify) continue;
        if (delivery === undefined) continue;

        const payload = payloadFor({
          episodeId: outcome.episodeId,
          signal,
          severity: outcome.severity,
          reason: outcome.reason,
          scopeId: evaluation.scopeId,
          windowStartUnix,
          windowSecs,
          windowsSeen: outcome.windowsSeen,
          evaluation,
          periodMonth,
          throttledRpm,
          now,
        });
        try {
          await dispatchSpendAnomalyAlert({
            delivery,
            payload,
            ...(fetchImpl === undefined ? {} : { fetchImpl }),
          });
          await episodeDb
            .prepare(
              `UPDATE ${SPEND_ANOMALY_EPISODE_TABLE}
                SET notified_count = notified_count + 1, last_notified_unix = ?
              WHERE id = ?`,
            )
            .bind(now, outcome.episodeId)
            .run();
          notified += 1;
        } catch (error) {
          // NOT retried and the counter is NOT bumped: an episode whose
          // `notified_count` stays 0 is exactly how an operator finds the alerts
          // their receiver dropped. See `./notify.ts` on why the next window is
          // the retry.
          deliveryFailed += 1;
          console.warn(
            "control-plane: spend anomaly alert delivery failed",
            error instanceof Error ? error.name : "",
          );
        }
      }
    }

    const completed = await db
      .prepare(
        `UPDATE ${SPEND_ANOMALY_RUN_TABLE}
            SET scopes_evaluated = ?, episodes_opened = ?, notifications_sent = ?
          WHERE window_start_unix = ?
            AND ran_at_unix = ?
            AND scopes_evaluated = -1`,
      )
      .bind(evaluations.length, opened, notified, windowStartUnix, now)
      .run();
    if ((completed.meta?.changes ?? 0) === 0) {
      throw new Error(`spend anomaly claim lease lost for ${windowStartUnix}`);
    }

    return {
      evaluated: evaluations.length,
      opened,
      notified,
      deliveryFailed,
      throttled,
      resolved,
      windowStartUnix,
      ...(delivery === undefined ? { deliveryUnconfigured: true } : {}),
    };
  } catch (error) {
    // Do not leave a dead evaluator's marker looking complete. The conditional
    // delete cannot remove a newer evaluator's reclaimed claim.
    try {
      await db
        .prepare(
          `DELETE FROM ${SPEND_ANOMALY_RUN_TABLE}
            WHERE window_start_unix = ? AND ran_at_unix = ? AND scopes_evaluated = -1`,
        )
        .bind(windowStartUnix, now)
        .run();
    } catch (releaseError) {
      console.warn("control-plane: failed to release spend anomaly claim", releaseError);
    }
    throw error;
  }
}

async function readEpisode(db: D1Database, id: string): Promise<EpisodeProjectionRow | null> {
  return await db
    .prepare(
      `SELECT ${EPISODE_COLUMNS.join(", ")}
         FROM ${SPEND_ANOMALY_EPISODE_TABLE}
        WHERE id = ?
        LIMIT 1`,
    )
    .bind(id)
    .first<EpisodeProjectionRow>();
}

interface UpsertOutcome {
  readonly episodeId: string;
  readonly opened: boolean;
  readonly severity: SpendAnomalySeverity;
  readonly windowsSeen: number;
  readonly shouldNotify: boolean;
  readonly reason: "opened" | "escalated" | "still_firing";
}

/**
 * Open the episode, or absorb this window into the open one, and decide whether
 * this window produces a notification.
 *
 * The three notification rules are in one place because they have to be read
 * together: any two of them alone would either flood (open + heartbeat with no
 * escalation suppression) or go quiet exactly when the incident got worse.
 */
async function upsertEpisode(
  db: D1Database,
  input: {
    scopeId: string;
    signal: SpendAnomalySignal;
    windowStartUnix: number;
    windowSecs: number;
    now: number;
    periodMonth: string;
    evaluation: ScopeEvaluation;
  },
): Promise<UpsertOutcome> {
  const { evaluation, signal, scopeId, now } = input;
  const severity = (
    signal === "burn_rate_spike" ? evaluation.burn.severity : evaluation.forecast.severity
  ) as SpendAnomalySeverity;

  const existing = await db
    .prepare(
      `SELECT id, severity, peak_severity, windows_seen, notified_count, last_notified_unix
         FROM ${SPEND_ANOMALY_EPISODE_TABLE}
        WHERE scope_type = 'tenant' AND scope_id = ? AND signal = ? AND resolved_at_unix IS NULL`,
    )
    .bind(scopeId, signal)
    .first<EpisodeRow>();

  const evidence = evidenceOf(evaluation, signal);

  if (existing === null) {
    // Deterministic id: an interrupted pass that re-runs this window derives
    // the same id, so the INSERT conflicts instead of forking a second episode
    // for one incident.
    const episodeId = `tenant:${scopeId}:${signal}:${input.windowStartUnix}`;
    await db
      .prepare(
        `INSERT INTO ${SPEND_ANOMALY_EPISODE_TABLE} (
           id, scope_type, scope_id, signal, severity, peak_severity,
           window_start_unix, window_secs, opened_at_unix, last_seen_unix,
           windows_seen, notified_count, observed_usd, baseline_usd, threshold_usd,
           bound_by, baseline_windows, active_windows, projected_usd, budget_usd,
           period_month, detail_json
         ) VALUES (?, 'tenant', ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO NOTHING`,
      )
      .bind(
        episodeId,
        scopeId,
        signal,
        severity,
        severity,
        input.windowStartUnix,
        input.windowSecs,
        now,
        now,
        evidence.observedUsd,
        evidence.baselineUsd,
        evidence.thresholdUsd,
        evidence.boundBy,
        evidence.baselineWindows,
        evidence.activeWindows,
        evidence.projectedUsd,
        evaluation.budgetUsd ?? null,
        input.periodMonth,
        JSON.stringify(evidence.detail),
      )
      .run();
    return {
      episodeId,
      opened: true,
      severity,
      windowsSeen: 1,
      shouldNotify: true,
      reason: "opened",
    };
  }

  const windowsSeen = existing.windows_seen + 1;
  const peak = existing.peak_severity as SpendAnomalySeverity;
  // ESCALATION is measured against the episode's PEAK, not its previous
  // severity: an episode that went critical, fell back to warning and climbed
  // again has produced no new information the second time, and treating that
  // as an escalation is how a flapping incident pages every window.
  const escalated = SEVERITY_RANK[severity] > SEVERITY_RANK[peak];
  const lastNotified = existing.last_notified_unix;
  const cooldownElapsed =
    lastNotified === null || now - lastNotified >= evaluation.tuning.cooldownSecs;
  const shouldNotify = escalated || cooldownElapsed;

  await db
    .prepare(
      `UPDATE ${SPEND_ANOMALY_EPISODE_TABLE}
          SET severity = ?, peak_severity = ?, last_seen_unix = ?, windows_seen = ?,
              window_start_unix = ?, observed_usd = ?, baseline_usd = ?, threshold_usd = ?,
              bound_by = ?, baseline_windows = ?, active_windows = ?, projected_usd = ?,
              budget_usd = ?, detail_json = ?
        WHERE id = ?`,
    )
    .bind(
      severity,
      SEVERITY_RANK[severity] > SEVERITY_RANK[peak] ? severity : peak,
      now,
      windowsSeen,
      input.windowStartUnix,
      evidence.observedUsd,
      evidence.baselineUsd,
      evidence.thresholdUsd,
      evidence.boundBy,
      evidence.baselineWindows,
      evidence.activeWindows,
      evidence.projectedUsd,
      evaluation.budgetUsd ?? null,
      JSON.stringify(evidence.detail),
      existing.id,
    )
    .run();

  return {
    episodeId: existing.id,
    opened: false,
    severity,
    windowsSeen,
    shouldNotify,
    reason: escalated ? "escalated" : "still_firing",
  };
}

/** Close the open episode for (scope, signal), if there is one. Returns 0 or 1. */
async function closeEpisode(
  db: D1Database,
  scopeId: string,
  signal: SpendAnomalySignal,
  now: number,
): Promise<EpisodeProjectionRow | null> {
  const existing = await db
    .prepare(
      `SELECT ${EPISODE_COLUMNS.join(", ")}
         FROM ${SPEND_ANOMALY_EPISODE_TABLE}
        WHERE scope_type = 'tenant' AND scope_id = ? AND signal = ? AND resolved_at_unix IS NULL
        LIMIT 1`,
    )
    .bind(scopeId, signal)
    .first<EpisodeProjectionRow>();
  if (existing === null) return null;

  const result = await db
    .prepare(
      `UPDATE ${SPEND_ANOMALY_EPISODE_TABLE}
          SET resolved_at_unix = ?
        WHERE scope_type = 'tenant' AND scope_id = ? AND signal = ? AND resolved_at_unix IS NULL`,
    )
    .bind(now, scopeId, signal)
    .run();
  if ((result.meta?.changes ?? 0) === 0) return null;
  return await readEpisode(db, existing.id);
}

/**
 * Write (or extend) the auto-throttle for a scope.
 *
 * `db` is the AUTHORITATIVE target and the caller chooses which object it is
 * (Track A G2, see `spendThrottleWritesTenantObjectOnly`): the shared control
 * object while the admission readers still read it there, or — once flipped —
 * the owning tenant's OWN object, with no `shadow` and so no control mirror at
 * all. When present, `shadow` gets the SAME row on a best-effort basis so the
 * DO-side `spend_throttles` table is already populated when the admission
 * readers are later pointed at it. A shadow outage or a not-yet-provisioned
 * tenant must NEVER fail the authoritative write the gateway enforces, so it is
 * caught and logged, exactly like the quota-policy shadow in
 * `routes/quota_policy.ts`. The scope is always a tenant here (`scope_id` IS the
 * tenant id), so both rows belong wholly to that tenant.
 *
 * Returns the applied RPM (from the authoritative write), or `null` when nothing
 * was written there.
 */
async function applyThrottle(
  db: D1Database,
  input: {
    scopeId: string;
    rpm: number;
    ttlSecs: number;
    episodeId: string;
    signal: SpendAnomalySignal;
    now: number;
  },
  shadow?: D1Database,
): Promise<number | null> {
  const expiresAt = input.now + input.ttlSecs;
  const reason = `spend anomaly ${input.signal} (episode ${input.episodeId})`;
  const binds = [input.scopeId, input.rpm, reason, input.episodeId, input.now, expiresAt] as const;
  const result = await db
    .prepare(SPEND_THROTTLE_UPSERT_SQL)
    .bind(...binds)
    .run();
  if (shadow !== undefined) {
    try {
      await shadow
        .prepare(SPEND_THROTTLE_UPSERT_SQL)
        .bind(...binds)
        .run();
    } catch (error) {
      console.warn("control-plane: spend throttle tenant-object shadow write failed", {
        scopeId: input.scopeId,
        signal: input.signal,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return (result.meta?.changes ?? 0) > 0 ? input.rpm : null;
}

/** The columns a detection writes, per signal. */
function evidenceOf(
  evaluation: ScopeEvaluation,
  signal: SpendAnomalySignal,
): {
  observedUsd: number;
  baselineUsd: number | null;
  thresholdUsd: number | null;
  boundBy: string;
  baselineWindows: number;
  activeWindows: number;
  projectedUsd: number | null;
  detail: Record<string, unknown>;
} {
  const burn = evaluation.burn;
  if (signal === "burn_rate_spike") {
    return {
      observedUsd: burn.observedUsd,
      baselineUsd: burn.baselineUsd,
      thresholdUsd: burn.thresholdUsd,
      boundBy: burn.boundBy,
      baselineWindows: burn.observedWindows,
      activeWindows: burn.activeWindows,
      projectedUsd: null,
      detail: { ratio: burn.ratio, outcome: burn.outcome },
    };
  }
  const forecast = evaluation.forecast;
  return {
    observedUsd: burn.observedUsd,
    baselineUsd: null,
    thresholdUsd: forecast.budgetUsd,
    boundBy: "forecast",
    baselineWindows: burn.observedWindows,
    activeWindows: burn.activeWindows,
    projectedUsd: forecast.projectedUsd,
    detail: {
      period_spend_usd: forecast.periodSpendUsd,
      hours_to_exhaustion: forecast.hoursToExhaustion,
      outcome: forecast.outcome,
    },
  };
}

/** The wire payload for one notification. */
function payloadFor(input: {
  episodeId: string;
  signal: SpendAnomalySignal;
  severity: SpendAnomalySeverity;
  reason: "opened" | "escalated" | "still_firing";
  scopeId: string;
  windowStartUnix: number;
  windowSecs: number;
  windowsSeen: number;
  evaluation: ScopeEvaluation;
  periodMonth: string;
  throttledRpm: number | null;
  now: number;
}): SpendAnomalyWebhookPayload {
  const evidence = evidenceOf(input.evaluation, input.signal);
  return {
    type: "spend_anomaly",
    episode_id: input.episodeId,
    signal: input.signal,
    severity: input.severity,
    reason: input.reason,
    scope_type: "tenant",
    scope_id: input.scopeId,
    window_start_unix: input.windowStartUnix,
    window_secs: input.windowSecs,
    windows_seen: input.windowsSeen,
    observed_usd: evidence.observedUsd,
    baseline_usd: evidence.baselineUsd,
    threshold_usd: evidence.thresholdUsd,
    bound_by: evidence.boundBy,
    projected_usd: evidence.projectedUsd,
    budget_usd: input.evaluation.budgetUsd ?? null,
    period_month: input.periodMonth,
    means: meaningOf(input.signal, input.scopeId, input.windowSecs),
    auto_throttled_rpm: input.throttledRpm,
    fired_at_unix: input.now,
  };
}

export type { SpendAlertDelivery };
