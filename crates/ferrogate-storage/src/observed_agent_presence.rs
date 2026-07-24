// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Durable, coalesced observed-agent presence (#357). Backs the
// "recent activity" signal of the observed-agent-activity surface with a cheap
// durable store instead of relying only on a scan of the (retention-bounded)
// request logs. A presence touch is ONE short indexed conditional upsert keyed
// on (tenant_id, api_key_id): the row records the MAX last-seen timestamp and a
// coalesced request count, so a burst of touches for the same virtual key never
// grows the table and never contends beyond a single-row upsert. The pure
// observed-activity derivation still owns attribution (which keys surface as
// Unknown) and evidence (token/cost correlation); this store only refines the
// recency that decides running vs inactive. Split into its own file per the
// "one business entity per file" convention (mirrors `agent_schedule.rs`).

use super::{
    postgres_error, PostgresControlPlaneStore, PostgresRow, Repository, RuntimeControlPlaneBackend,
    RuntimeControlPlaneState, RuntimeStorageRepositories, StorageError, StorageOperation,
};

/// A durable presence row for one virtual API key, keyed by
/// `(tenant_id, api_key_id)`. `request_count` is a coalesced tally of touches,
/// not a per-request ledger; `last_seen_at_unix` is the MAX observed timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredObservedAgentPresence {
    pub tenant_id: String,
    pub api_key_id: String,
    pub first_seen_at_unix: i64,
    pub last_seen_at_unix: i64,
    pub request_count: i64,
    pub updated_at_unix: i64,
}

/// One coalesced presence touch. Fire-and-forget from the caller's view: it is
/// enqueued off the request hot path (issue #309 evidence writer) and folded
/// into the single presence row for `(tenant_id, api_key_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedAgentPresenceTouch {
    pub tenant_id: String,
    pub api_key_id: String,
    pub seen_at_unix: i64,
}

/// Composite in-memory identity for a presence row. Length-prefixed on the
/// tenant so a crafted tenant/key pair can never alias another
/// `(tenant, key)` -- the same collision-safety trick as
/// [`crate::agent_schedule_fire_id`].
pub fn observed_agent_presence_key(tenant_id: &str, api_key_id: &str) -> String {
    format!("{}:{tenant_id}:{api_key_id}", tenant_id.len())
}

const OBSERVED_AGENT_PRESENCE_COLUMNS: &str =
    "tenant_id, api_key_id, first_seen_at_unix, last_seen_at_unix, request_count, updated_at_unix";

fn presence_from_row(row: &PostgresRow) -> StoredObservedAgentPresence {
    StoredObservedAgentPresence {
        tenant_id: row.get::<_, String>(0),
        api_key_id: row.get::<_, String>(1),
        first_seen_at_unix: row.get::<_, i64>(2),
        last_seen_at_unix: row.get::<_, i64>(3),
        request_count: row.get::<_, i64>(4),
        updated_at_unix: row.get::<_, i64>(5),
    }
}

impl PostgresControlPlaneStore {
    fn observed_agent_presence_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    /// Coalesced presence touch: ONE conditional upsert on the
    /// `(tenant_id, api_key_id)` primary key. `GREATEST`/`LEAST` keep the row's
    /// last-seen monotonic and first-seen minimal even if a delayed touch
    /// carries an older timestamp, and `request_count + 1` folds the touch in
    /// without a separate read -- so a lost update is impossible under
    /// concurrency and the write stays a single-row hot operation.
    pub(super) async fn touch_observed_agent_presence(
        &self,
        touch: &ObservedAgentPresenceTouch,
    ) -> Result<(), StorageError> {
        let operation = self.observed_agent_presence_operation("touch observed agent presence");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO observed_agent_presence \
                 (tenant_id, api_key_id, first_seen_at_unix, last_seen_at_unix, request_count, \
                  updated_at_unix) \
                 VALUES ($1, $2, $3, $3, 1, $3) \
                 ON CONFLICT (tenant_id, api_key_id) DO UPDATE SET \
                     last_seen_at_unix = GREATEST(observed_agent_presence.last_seen_at_unix, \
                                                  EXCLUDED.last_seen_at_unix), \
                     first_seen_at_unix = LEAST(observed_agent_presence.first_seen_at_unix, \
                                                EXCLUDED.first_seen_at_unix), \
                     request_count = observed_agent_presence.request_count + 1, \
                     updated_at_unix = GREATEST(observed_agent_presence.updated_at_unix, \
                                                EXCLUDED.updated_at_unix)",
                &[&touch.tenant_id, &touch.api_key_id, &touch.seen_at_unix],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    /// Window read: presence rows whose most recent touch is at or after
    /// `since_unix`, newest first. `tenant_scope = Some` restricts to one
    /// tenant (the tenant-scoped admin caller); `None` is the platform-operator
    /// cross-tenant view. Backed by `idx_observed_agent_presence_tenant_last_seen`.
    pub(super) async fn list_observed_agent_presence_since(
        &self,
        tenant_scope: Option<&str>,
        since_unix: i64,
    ) -> Result<Vec<StoredObservedAgentPresence>, StorageError> {
        let operation =
            self.observed_agent_presence_operation("list observed agent presence since");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = match tenant_scope {
            Some(tenant_id) => transaction
                .query(
                    &format!(
                        "SELECT {OBSERVED_AGENT_PRESENCE_COLUMNS} FROM observed_agent_presence \
                         WHERE tenant_id = $1 AND last_seen_at_unix >= $2 \
                         ORDER BY last_seen_at_unix DESC, api_key_id ASC"
                    ),
                    &[&tenant_id, &since_unix],
                )
                .await
                .map_err(postgres_error)?,
            None => transaction
                .query(
                    &format!(
                        "SELECT {OBSERVED_AGENT_PRESENCE_COLUMNS} FROM observed_agent_presence \
                         WHERE last_seen_at_unix >= $1 \
                         ORDER BY last_seen_at_unix DESC, tenant_id ASC, api_key_id ASC"
                    ),
                    &[&since_unix],
                )
                .await
                .map_err(postgres_error)?,
        };
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(presence_from_row).collect())
    }
}

impl RuntimeControlPlaneState {
    /// In-memory analogue of the coalesced upsert. Serialized by the
    /// control-plane mutex the facade holds, so concurrent touches fold into
    /// the same single row without losing an update (mirrors the Postgres
    /// `GREATEST`/`request_count + 1` conflict clause).
    pub(super) fn touch_observed_agent_presence(&mut self, touch: &ObservedAgentPresenceTouch) {
        let key = observed_agent_presence_key(&touch.tenant_id, &touch.api_key_id);
        match self.observed_agent_presence.get(&key) {
            Some(mut existing) => {
                existing.last_seen_at_unix = existing.last_seen_at_unix.max(touch.seen_at_unix);
                existing.first_seen_at_unix = existing.first_seen_at_unix.min(touch.seen_at_unix);
                existing.request_count = existing.request_count.saturating_add(1);
                existing.updated_at_unix = existing.updated_at_unix.max(touch.seen_at_unix);
                self.observed_agent_presence.insert(key, existing);
            }
            None => {
                self.observed_agent_presence.insert(
                    key,
                    StoredObservedAgentPresence {
                        tenant_id: touch.tenant_id.clone(),
                        api_key_id: touch.api_key_id.clone(),
                        first_seen_at_unix: touch.seen_at_unix,
                        last_seen_at_unix: touch.seen_at_unix,
                        request_count: 1,
                        updated_at_unix: touch.seen_at_unix,
                    },
                );
            }
        }
    }

    pub(super) fn list_observed_agent_presence_since(
        &self,
        tenant_scope: Option<&str>,
        since_unix: i64,
    ) -> Vec<StoredObservedAgentPresence> {
        let mut rows: Vec<_> = self
            .observed_agent_presence
            .list()
            .into_iter()
            .filter(|row| row.last_seen_at_unix >= since_unix)
            .filter(|row| tenant_scope.is_none_or(|scope| row.tenant_id == scope))
            .collect();
        rows.sort_by(|left, right| {
            right
                .last_seen_at_unix
                .cmp(&left.last_seen_at_unix)
                .then_with(|| left.tenant_id.cmp(&right.tenant_id))
                .then_with(|| left.api_key_id.cmp(&right.api_key_id))
        });
        rows
    }
}

impl RuntimeStorageRepositories {
    /// Record one coalesced presence touch for a virtual API key. See
    /// [`PostgresControlPlaneStore::touch_observed_agent_presence`].
    pub async fn touch_observed_agent_presence(
        &self,
        touch: ObservedAgentPresenceTouch,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                control_plane
                    .lock()
                    .map_err(|_| {
                        StorageError::Runtime(
                            "observed agent presence repository lock poisoned".into(),
                        )
                    })?
                    .touch_observed_agent_presence(&touch);
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.touch_observed_agent_presence(&touch).await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => {
                Err(super::control_plane_store_d1::unimplemented_surface(
                    "touch_observed_agent_presence",
                ))
            }
        }
    }

    /// List durable presence rows whose most recent touch is within the window
    /// `[since_unix, now]`, newest first, optionally scoped to one tenant.
    pub async fn list_observed_agent_presence_since(
        &self,
        tenant_scope: Option<&str>,
        since_unix: i64,
    ) -> Result<Vec<StoredObservedAgentPresence>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("observed agent presence repository lock poisoned".into())
                })?
                .list_observed_agent_presence_since(tenant_scope, since_unix)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_observed_agent_presence_since(tenant_scope, since_unix)
                    .await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => {
                Err(super::control_plane_store_d1::unimplemented_surface(
                    "list_observed_agent_presence_since",
                ))
            }
        }
    }
}

#[cfg(test)]
#[path = "observed_agent_presence_test.rs"]
mod observed_agent_presence_test;
