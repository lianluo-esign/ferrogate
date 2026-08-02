/**
 * Budget-threshold alert idempotency ledger (ports
 * `ferrogate-storage::budget_alerts`, issue #170).
 *
 * Exactly one row per `(scope, period, threshold)` means a threshold fires its
 * webhook once per billing period, not on every request after crossing it. The
 * deterministic id makes "insert if absent" the natural idempotency check.
 *
 * The DURABLE half is now `./d1/budget-alerts-d1.ts`
 * (`D1BudgetAlertStore.claimBudgetAlertNotification`): `INSERT ... ON CONFLICT
 * DO NOTHING RETURNING id` against the control database, where a returned row
 * means "you are the one who fires" and an empty result means "already sent
 * this period". That is the piece a Worker cannot fake — an isolate does not
 * outlive the request, so the class below cannot suppress a duplicate at all
 * and would re-fire a tenant's 80%/90%/100% webhook on EVERY request past the
 * crossing (#170).
 *
 * The class below is NOT deprecated by it: it stays the executable
 * specification of the rule, and `test/d1/budget-alerts-d1.test.ts` asserts the
 * two backends agree on the same observable outcomes.
 *
 * PORT-TODO(P: inventory-data-billing §1.4.3 `budget_alert_notifications`, #170) —
 * CROSS-SCOPE, NOT CLOSABLE HERE. What is still missing is the DECISION and the
 * DELIVERY, both of which live on the request path in `apps/gateway`: nothing
 * compares committed spend against `quota_policies.alert_threshold_pcts_json`
 * (already read into `EffectiveQuota` by `apps/gateway/src/ratelimit/quota.ts`)
 * to conclude a threshold was crossed, and nothing sends the webhook once the
 * claim is won. Consequence while it stands: an operator who configures alert
 * thresholds is never notified. What is no longer true is the dangerous part —
 * whoever writes that path can no longer accidentally ship a duplicate-firing
 * alerter, because the once-per-period arbiter now exists.
 */
import type { QuotaScopeKind } from "./quota.js";

export interface StoredBudgetAlertNotification {
  id: string;
  scopeType: QuotaScopeKind;
  scopeId: string;
  periodMonth: string;
  thresholdPct: number;
  notifiedAtUnix: number;
}

export class MemoryBudgetAlertStore {
  private readonly rows = new Map<string, StoredBudgetAlertNotification>();

  /** Record idempotently: `ON CONFLICT (id) DO NOTHING` semantics. */
  recordBudgetAlertNotification(notification: StoredBudgetAlertNotification): void {
    if (!this.rows.has(notification.id)) {
      this.rows.set(notification.id, { ...notification });
    }
  }

  budgetAlertAlreadyNotified(id: string): boolean {
    return this.rows.has(id);
  }

  /** Notifications for one `(scope, period)`, ascending by threshold. */
  listBudgetAlertNotifications(
    scopeType: QuotaScopeKind,
    scopeId: string,
    periodMonth: string,
  ): StoredBudgetAlertNotification[] {
    const out = [...this.rows.values()]
      .filter(
        (n) =>
          n.scopeType === scopeType && n.scopeId === scopeId && n.periodMonth === periodMonth,
      )
      .map((n) => ({ ...n }));
    out.sort((a, b) => a.thresholdPct - b.thresholdPct);
    return out;
  }
}

// `budgetAlertNotificationId` is exported from `./ids.js`.
