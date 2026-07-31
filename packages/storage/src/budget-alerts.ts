/**
 * Budget-threshold alert idempotency ledger (ports
 * `ferrogate-storage::budget_alerts`, issue #170).
 *
 * Exactly one row per `(scope, period, threshold)` means a threshold fires its
 * webhook once per billing period, not on every request after crossing it. The
 * deterministic id makes "insert if absent" the natural idempotency check.
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
