// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Idempotency ledger for proactive budget-threshold alerting
// (issue #170): exactly one row per (scope, period, tier) means a
// threshold fires its webhook once per billing period, not on every
// subsequent request after crossing it. Split into its own file per the
// "one business entity per file" convention.

use super::{
    postgres_error, PostgresControlPlaneStore, PostgresRow, QuotaScopeKind, Repository,
    RuntimeControlPlaneBackend, RuntimeControlPlaneState, RuntimeStorageRepositories, StorageError,
    StorageOperation,
};

/// One "tenant X was notified it crossed tier Y of its budget for period Z"
/// record (issue #170). The deterministic `id` (see
/// [`budget_alert_notification_id`]) makes "insert if absent" the natural
/// idempotency check -- callers should check [`RuntimeStorageRepositories::
/// budget_alert_already_notified`] before firing a webhook, then record
/// the notification via [`RuntimeStorageRepositories::
/// record_budget_alert_notification`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBudgetAlertNotification {
    pub id: String,
    pub scope_type: QuotaScopeKind,
    pub scope_id: String,
    pub period_month: String,
    pub threshold_pct: u8,
    pub notified_at_unix: i64,
}

/// Deterministic id so recording the same tier twice for the same
/// scope+period is naturally idempotent, mirroring `quota_policy_id`.
pub fn budget_alert_notification_id(
    scope_type: QuotaScopeKind,
    scope_id: &str,
    period_month: &str,
    threshold_pct: u8,
) -> String {
    format!(
        "{}:{scope_id}:{period_month}:{threshold_pct}",
        scope_type.as_str()
    )
}

fn budget_alert_notification_from_row(
    row: &PostgresRow,
) -> Result<StoredBudgetAlertNotification, StorageError> {
    let scope_type_raw = row.get::<_, String>(1);
    let scope_type = QuotaScopeKind::from_str_opt(&scope_type_raw).ok_or_else(|| {
        StorageError::Runtime(format!(
            "unknown budget_alert_notifications.scope_type {scope_type_raw}"
        ))
    })?;
    Ok(StoredBudgetAlertNotification {
        id: row.get::<_, String>(0),
        scope_type,
        scope_id: row.get::<_, String>(2),
        period_month: row.get::<_, String>(3),
        threshold_pct: row.get::<_, i16>(4) as u8,
        notified_at_unix: row.get::<_, i64>(5),
    })
}

impl PostgresControlPlaneStore {
    fn budget_alert_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    pub(super) async fn record_budget_alert_notification(
        &self,
        notification: &StoredBudgetAlertNotification,
    ) -> Result<(), StorageError> {
        let threshold_pct = i16::from(notification.threshold_pct);
        let operation = self.budget_alert_operation("record budget alert notification");
        let client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        client
            .execute(
                "INSERT INTO budget_alert_notifications \
                 (id, scope_type, scope_id, period_month, threshold_pct, notified_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &notification.id,
                    &notification.scope_type.as_str(),
                    &notification.scope_id,
                    &notification.period_month,
                    &threshold_pct,
                    &notification.notified_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    pub(super) async fn budget_alert_already_notified(
        &self,
        id: &str,
    ) -> Result<bool, StorageError> {
        let operation = self.budget_alert_operation("budget alert already notified");
        let client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let row = client
            .query_opt(
                "SELECT id, scope_type, scope_id, period_month, threshold_pct, notified_at_unix \
                 FROM budget_alert_notifications WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        Ok(row.is_some())
    }

    pub(super) async fn list_budget_alert_notifications(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Result<Vec<StoredBudgetAlertNotification>, StorageError> {
        let operation = self.budget_alert_operation("list budget alert notifications");
        let client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let rows = client
            .query(
                "SELECT id, scope_type, scope_id, period_month, threshold_pct, notified_at_unix \
                 FROM budget_alert_notifications \
                 WHERE scope_type = $1 AND scope_id = $2 AND period_month = $3 \
                 ORDER BY threshold_pct ASC",
                &[&scope_type.as_str(), &scope_id, &period_month],
            )
            .await
            .map_err(postgres_error)?;
        rows.iter()
            .map(budget_alert_notification_from_row)
            .collect()
    }
}

impl RuntimeControlPlaneState {
    pub fn record_budget_alert_notification(
        &mut self,
        notification: StoredBudgetAlertNotification,
    ) {
        self.budget_alert_notifications
            .insert(notification.id.clone(), notification);
    }

    pub fn budget_alert_already_notified(&self, id: &str) -> bool {
        self.budget_alert_notifications.get(id).is_some()
    }

    pub fn list_budget_alert_notifications(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Vec<StoredBudgetAlertNotification> {
        let mut notifications: Vec<_> = self
            .budget_alert_notifications
            .list()
            .into_iter()
            .filter(|notification| {
                notification.scope_type == scope_type
                    && notification.scope_id == scope_id
                    && notification.period_month == period_month
            })
            .collect();
        notifications.sort_by_key(|notification| notification.threshold_pct);
        notifications
    }
}

impl RuntimeStorageRepositories {
    /// Idempotently records that `scope_type`/`scope_id` was notified at
    /// `threshold_pct` for `period_month` (issue #170). Callers should
    /// check [`Self::budget_alert_already_notified`] first and only fire
    /// the webhook (and call this) when it returns `false` -- `ON CONFLICT
    /// (id) DO NOTHING` makes a redundant call harmless either way.
    pub async fn record_budget_alert_notification(
        &self,
        notification: StoredBudgetAlertNotification,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.record_budget_alert_notification(notification);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .record_budget_alert_notification(&notification)
                    .await
            }
        }
    }

    pub async fn budget_alert_already_notified(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.budget_alert_already_notified(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.budget_alert_already_notified(id).await
            }
        }
    }

    pub async fn list_budget_alert_notifications(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
    ) -> Result<Vec<StoredBudgetAlertNotification>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| {
                    control_plane.list_budget_alert_notifications(
                        scope_type,
                        scope_id,
                        period_month,
                    )
                })
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_budget_alert_notifications(scope_type, scope_id, period_month)
                    .await
            }
        }
    }
}
