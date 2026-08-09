/**
 * The tuning surface (#697): a `quota_policies` row -> a {@link SpendAnomalyTuning}.
 *
 * ## How an operator tunes this, in one sentence
 *
 * `PUT /admin/v1/quota-policies/tenant/{tenant_id}` with the
 * `spend_anomaly_*` fields — the operation, the RBAC action and the scoped
 * authorization all already exist, because the knobs ride the row that already
 * governs the scope (`sql/d1-ts/control/0010_spend_anomaly.sql` states why).
 *
 * The escalation ladder an operator actually walks when an alert is noisy:
 *
 * | complaint                                   | knob                              |
 * |---------------------------------------------|-----------------------------------|
 * | "it fires on our nightly batch"             | `spend_anomaly_ratio` up (the batch is IN the baseline, so widening `spend_anomaly_baseline_windows` will not help) |
 * | "it fires on trivial amounts"               | `spend_anomaly_min_window_usd` up |
 * | "it compares us against the wrong stretch"  | `spend_anomaly_baseline_windows`, and the two cold-start gates with it |
 * | "it pages too often for one incident"       | `spend_anomaly_cooldown_secs` up  |
 * | "the forecast fires at the start of a month"| `spend_anomaly_forecast_min_pct` up |
 * | "we do not want this tenant watched at all" | `spend_anomaly_enabled = 0`       |
 *
 * `bound_by` on every episode says WHICH bar fired, so the first column of that
 * table is answerable from the row rather than guessed.
 *
 * ## Why a bad value falls back rather than throwing
 *
 * This runs on a cron tick that also dispatches agent schedules, anchors the
 * audit chain and pumps the SIEM export. A tenant with `spend_anomaly_ratio =
 * -1` must not take those down, and it must not be interpreted literally either
 * (a negative ratio makes the bar negative and every window an anomaly — a
 * typo that pages the whole fleet). So every reader below refuses a
 * non-positive or non-finite value and uses the documented default, which can
 * only make the detector QUIETER than the typo would have.
 *
 * The one exception is `enabled`, where the stored `0` is meaningful and is
 * honoured exactly.
 */
import {
  SPEND_ANOMALY_DEFAULTS,
  SPEND_ANOMALY_MAX_BASELINE_WINDOWS,
  type SpendAnomalyTuning,
} from "./detector.js";

/** The `quota_policies` columns this module reads, in one place. */
export const SPEND_ANOMALY_POLICY_COLUMNS = [
  "scope_id",
  "monthly_budget_usd",
  "spend_anomaly_enabled",
  "spend_anomaly_baseline_windows",
  "spend_anomaly_min_baseline_windows",
  "spend_anomaly_min_active_windows",
  "spend_anomaly_min_window_usd",
  "spend_anomaly_ratio",
  "spend_anomaly_critical_ratio",
  "spend_anomaly_cooldown_secs",
  "spend_anomaly_forecast_min_pct",
  "spend_anomaly_auto_throttle_rpm",
  "spend_anomaly_throttle_ttl_secs",
] as const;

/** A positive, finite number, or the default. See the module docblock. */
function positive(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : fallback;
}

/** A positive integer, or the default. */
function positiveInt(value: unknown, fallback: number): number {
  const resolved = positive(value, fallback);
  return Number.isSafeInteger(resolved) ? resolved : fallback;
}

/**
 * A positive integer no larger than `max`, or the default.
 *
 * The ceiling is not squeamishness about big numbers: `./pass.ts` widens the
 * fleet bucket query to the LARGEST baseline any policy asks for, so one
 * tenant's stray `spend_anomaly_baseline_windows = 1e9` would make every pass
 * scan `request_logs` back to the epoch, for everybody. Out of range falls back
 * to the documented default, which is the same direction every other reader
 * here takes.
 */
function boundedInt(value: unknown, fallback: number, max: number): number {
  const resolved = positiveInt(value, fallback);
  return resolved <= max ? resolved : fallback;
}

/**
 * A gate count that MAY legitimately be zero.
 *
 * `min_active_windows = 0` is a real configuration — "watch this tenant even
 * though it is sparse, I accept the noise" — and collapsing it into the default
 * would silently refuse an operator's explicit decision. Negative is still
 * refused, because a negative gate is not a decision.
 */
function nonNegativeInt(value: unknown, fallback: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) return fallback;
  return value;
}

/** SQLite has no boolean; anything but an explicit `0` leaves it watching. */
function enabledFrom(value: unknown): boolean {
  return value !== 0 && value !== false;
}

/** The tuning for one scope, defaults filled in. */
export function tuningFromRow(row: Record<string, unknown> | undefined): SpendAnomalyTuning {
  if (row === undefined) return SPEND_ANOMALY_DEFAULTS;
  const d = SPEND_ANOMALY_DEFAULTS;
  const autoThrottleRpm = row.spend_anomaly_auto_throttle_rpm;
  return {
    enabled: enabledFrom(row.spend_anomaly_enabled),
    baselineWindows: boundedInt(
      row.spend_anomaly_baseline_windows,
      d.baselineWindows,
      SPEND_ANOMALY_MAX_BASELINE_WINDOWS,
    ),
    minBaselineWindows: nonNegativeInt(
      row.spend_anomaly_min_baseline_windows,
      d.minBaselineWindows,
    ),
    minActiveWindows: nonNegativeInt(row.spend_anomaly_min_active_windows, d.minActiveWindows),
    minWindowUsd: positive(row.spend_anomaly_min_window_usd, d.minWindowUsd),
    ratio: positive(row.spend_anomaly_ratio, d.ratio),
    criticalRatio: positive(row.spend_anomaly_critical_ratio, d.criticalRatio),
    cooldownSecs: positiveInt(row.spend_anomaly_cooldown_secs, d.cooldownSecs),
    forecastMinPct: positive(row.spend_anomaly_forecast_min_pct, d.forecastMinPct),
    // Off unless a positive integer is stored — the only leg that changes what
    // the gateway does to live traffic must never be switched on by a typo.
    autoThrottleRpm:
      typeof autoThrottleRpm === "number" &&
      Number.isSafeInteger(autoThrottleRpm) &&
      autoThrottleRpm > 0
        ? autoThrottleRpm
        : undefined,
    throttleTtlSecs: positiveInt(row.spend_anomaly_throttle_ttl_secs, d.throttleTtlSecs),
  };
}

/**
 * `monthly_budget_usd` for the forecast leg, or `undefined`.
 *
 * A non-positive budget is `undefined` rather than `0`: a stored `0` would make
 * every projection an overrun, and "budget of zero" is far more likely to be a
 * placeholder than a policy that no spend at all is permitted (which the
 * admission path's own `monthly_budget_exceeded` already enforces).
 */
export function budgetFromRow(row: Record<string, unknown> | undefined): number | undefined {
  const raw = row?.monthly_budget_usd;
  return typeof raw === "number" && Number.isFinite(raw) && raw > 0 ? raw : undefined;
}
