/**
 * `D1BudgetAlertStore` — the durable twin of `../budget-alerts.ts`
 * (inventory-data-billing §1.4.3 `budget_alert_notifications`, issue #170).
 *
 * ## What this closes, and why an in-memory ledger was worse than none
 *
 * A budget threshold (80% / 90% / 100%) must fire its webhook ONCE per billing
 * period, not on every request after the crossing. `MemoryBudgetAlertStore` is
 * the executable specification of that rule, but it cannot enforce it on this
 * platform for a structural reason: a Worker isolate does not outlive the
 * request, so its map is empty again on the next call. Any alert path built on
 * it would re-fire a tenant's webhook on EVERY request past the threshold.
 *
 * ## The claim is the INSERT, not a read followed by an INSERT
 *
 * ```sql
 * INSERT INTO budget_alert_notifications
 *   (id, scope_type, scope_id, period_month, threshold_pct, notified_at_unix)
 * VALUES (?, ?, ?, ?, ?, ?)
 * ON CONFLICT DO NOTHING
 * RETURNING id
 * ```
 *
 * A returned row means "YOU are the caller who fires"; an empty result means
 * "already sent this period". There is deliberately no `SELECT` in front of it:
 * two Workers crossing the same threshold in the same millisecond would both
 * read "not yet notified" and both fire. Making the write itself the arbiter
 * removes the window entirely — SQLite evaluates the conflict inside the
 * statement's own implicit transaction.
 *
 * `ON CONFLICT DO NOTHING` without a conflict target is deliberate too: the
 * table carries BOTH `id PRIMARY KEY` and `UNIQUE (scope_type, scope_id,
 * period_month, threshold_pct)`, and the id is derived from exactly those four
 * columns ({@link budgetAlertNotificationId}). Naming one target would let a
 * future divergence between the id derivation and the natural key raise a
 * constraint error instead of being absorbed as "already notified", which would
 * turn a duplicate suppression into a 500 on the request path.
 *
 * ## Which database
 *
 * CONTROL, not tenant: `quota_policies` and the thresholds
 * (`alert_threshold_pcts_json`) live there, and an alert is an account-level
 * billing fact. The store therefore takes a plain `D1Database` — the control
 * handle — the same shape {@link ControlMonotonicUpserts} takes.
 *
 * PORT-TODO(P: inventory-data-billing §1.4.3, #170) — CROSS-SCOPE, NOT CLOSABLE
 * HERE. What remains is the COMPARISON: nothing yet measures committed spend
 * against `EffectiveQuota.alertThresholdPcts`
 * (`apps/gateway/src/ratelimit/quota.ts`) to decide that a threshold was
 * crossed, and nothing dispatches the webhook. Both are `apps/gateway` edits.
 * This package now supplies the piece that made those unsafe to write — the
 * once-per-period arbiter.
 */
import type { StoredBudgetAlertNotification } from "../budget-alerts.js";
import { budgetAlertNotificationId } from "../ids.js";
import type { QuotaScopeKind } from "../quota.js";
import { d1Error } from "./rows.js";

/** The idempotent claim. Exported so a test can assert the exact statement. */
export const CLAIM_BUDGET_ALERT_SQL =
  "INSERT INTO budget_alert_notifications " +
  "(id, scope_type, scope_id, period_month, threshold_pct, notified_at_unix) " +
  "VALUES (?, ?, ?, ?, ?, ?) " +
  "ON CONFLICT DO NOTHING " +
  "RETURNING id";

/** One threshold crossing, as the caller describes it. */
export interface BudgetAlertClaim {
  scopeType: QuotaScopeKind;
  scopeId: string;
  periodMonth: string;
  thresholdPct: number;
  notifiedAtUnix: number;
}

/** Durable, race-free budget-alert idempotency against the CONTROL database. */
export class D1BudgetAlertStore {
  constructor(private readonly db: D1Database) {}

  /**
   * Claim the right to fire one `(scope, period, threshold)` notification.
   *
   * `true` = this caller won and MUST send the webhook.
   * `false` = another caller (or an earlier request) already did.
   *
   * The return is a boolean rather than the row because a caller that reads
   * fields off a "you lost" result would be reading someone else's write.
   */
  async claimBudgetAlertNotification(claim: BudgetAlertClaim): Promise<boolean> {
    const id = budgetAlertNotificationId(
      claim.scopeType,
      claim.scopeId,
      claim.periodMonth,
      claim.thresholdPct,
    );
    try {
      const row = await this.db
        .prepare(CLAIM_BUDGET_ALERT_SQL)
        .bind(
          id,
          claim.scopeType,
          claim.scopeId,
          claim.periodMonth,
          claim.thresholdPct,
          claim.notifiedAtUnix,
        )
        .first<{ id: string }>();
      return row !== null && row !== undefined;
    } catch (error) {
      throw d1Error("claim_budget_alert_notification", error);
    }
  }

  /** Whether a `(scope, period, threshold)` has already fired. */
  async budgetAlertAlreadyNotified(id: string): Promise<boolean> {
    try {
      const row = await this.db
        .prepare("SELECT id FROM budget_alert_notifications WHERE id = ?")
        .bind(id)
        .first<{ id: string }>();
      return row !== null && row !== undefined;
    } catch (error) {
      throw d1Error("budget_alert_already_notified", error);
    }
  }

  /**
   * Notifications for one `(scope, period)`, ascending by threshold — the same
   * order {@link MemoryBudgetAlertStore.listBudgetAlertNotifications} returns,
   * so the two backends are interchangeable in an assertion.
   */
  async listBudgetAlertNotifications(
    scopeType: QuotaScopeKind,
    scopeId: string,
    periodMonth: string,
  ): Promise<StoredBudgetAlertNotification[]> {
    try {
      const result = await this.db
        .prepare(
          "SELECT id, scope_type, scope_id, period_month, threshold_pct, notified_at_unix " +
            "FROM budget_alert_notifications " +
            "WHERE scope_type = ? AND scope_id = ? AND period_month = ? " +
            "ORDER BY threshold_pct ASC",
        )
        .bind(scopeType, scopeId, periodMonth)
        .all<{
          id: string;
          scope_type: string;
          scope_id: string;
          period_month: string;
          threshold_pct: number;
          notified_at_unix: number;
        }>();
      return result.results.map((row) => ({
        id: row.id,
        scopeType: row.scope_type as QuotaScopeKind,
        scopeId: row.scope_id,
        periodMonth: row.period_month,
        thresholdPct: row.threshold_pct,
        notifiedAtUnix: row.notified_at_unix,
      }));
    } catch (error) {
      throw d1Error("list_budget_alert_notifications", error);
    }
  }
}
