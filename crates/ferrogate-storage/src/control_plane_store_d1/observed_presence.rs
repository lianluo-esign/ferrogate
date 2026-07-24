// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: tenant-scoped durable observed-agent presence (issue #460/#357).

//! D1 backend: tenant-scoped durable observed-agent presence (issue #460/#357).
//!
//! The durable, coalesced observed-agent presence signal (issue #357) on the
//! database-per-tenant D1 topology. Like the wallet/usage/schedule families, a
//! tenant's presence rows live in THAT tenant's own D1 database — never the
//! control database — so every op routes through the proxy-Worker binding (issue
//! #450) selected onto a per-tenant `[[d1_databases]]` binding. A REST-only
//! deployment leaves them fail-closed with the typed unimplemented-surface error.
//!
//! ## The coalesced touch — one conditional upsert, SQLite `max`/`min`
//!
//! `touch_observed_agent_presence` mirrors the Postgres `#357` coalesced
//! conditional upsert EXACTLY, translated to the SQLite dialect: an
//! `INSERT ... ON CONFLICT (tenant_id, api_key_id) DO UPDATE` that keeps
//! `last_seen`/`updated_at` monotonic with `max(col, excluded.col)` and `first_seen`
//! minimal with `min(col, excluded.col)`, and folds the touch in with
//! `request_count = request_count + excluded.request_count`. SQLite has NO
//! `GREATEST`/`LEAST`; its `max(x, y)` / `min(x, y)` **scalar** functions (2+ args)
//! are the exact equivalents. So a burst of touches for one virtual key stays a
//! single-row hot write with no table growth, and a delayed touch carrying an older
//! timestamp can never regress the row — identical to Postgres, and a lost update
//! is impossible because SQLite serializes writers per database.
//!
//! ## Numeric affinity (issue #455 lesson) — no CAST here
//!
//! Every value the upsert's `max`/`min`/`+` reads is an `excluded.*` COLUMN
//! reference, which already carries the target column's INTEGER affinity (the bound
//! TEXT param was affinity-coerced on the way into the `excluded` row) — so NO
//! `CAST(? AS INTEGER)` is needed, exactly like the `persist_usage_aggregate`
//! REPLACE. The window read's `last_seen_at_unix >= ?` compares a bare INTEGER
//! COLUMN to the bound param (the column's affinity is applied to the param), so it
//! needs no CAST either. The CAST is only for a bound param entering an arithmetic
//! EXPRESSION (which has no affinity) — none here.
//!
//! ## Routing / divergence (database-per-tenant)
//!
//! `touch` carries a `tenant_id`, so it routes straight to that tenant's binding;
//! an UNPROVISIONED tenant is a typed `NotFound` (the tenant-scoped write
//! divergence, as `reserve`/`persist`/`open` make). `list_since(Some(tenant))` is
//! an opt-in READ routed to that tenant's binding (EMPTY for an unprovisioned org),
//! and `list_since(None)` is the platform-operator cross-tenant view that FANS OUT
//! over the provisioned tenant bindings and re-merges to the Postgres order.

use serde::de::DeserializeOwned;

use super::*;

/// Column list shared by every `observed_agent_presence` read, kept in lockstep
/// with [`ObservedAgentPresenceD1Row`] and the Postgres
/// `OBSERVED_AGENT_PRESENCE_COLUMNS` projection order.
const OBSERVED_AGENT_PRESENCE_COLUMNS: &str = "tenant_id, api_key_id, first_seen_at_unix, \
     last_seen_at_unix, request_count, updated_at_unix";

/// One `observed_agent_presence` row (SQLite integer affinities decoded back to
/// the `Stored*` shape, mirroring the Postgres `presence_from_row`).
#[derive(serde::Deserialize)]
struct ObservedAgentPresenceD1Row {
    tenant_id: String,
    api_key_id: String,
    first_seen_at_unix: i64,
    last_seen_at_unix: i64,
    request_count: i64,
    updated_at_unix: i64,
}

impl From<ObservedAgentPresenceD1Row> for StoredObservedAgentPresence {
    fn from(row: ObservedAgentPresenceD1Row) -> Self {
        Self {
            tenant_id: row.tenant_id,
            api_key_id: row.api_key_id,
            first_seen_at_unix: row.first_seen_at_unix,
            last_seen_at_unix: row.last_seen_at_unix,
            request_count: row.request_count,
            updated_at_unix: row.updated_at_unix,
        }
    }
}

/// Deserialize one D1 result row (`serde_json::Value` keyed by column) into a
/// typed DTO.
fn decode_row<T: DeserializeOwned>(value: &serde_json::Value) -> Result<T, StorageError> {
    serde_json::from_value(value.clone())
        .map_err(|error| StorageError::Serialization(error.to_string()))
}

impl D1ControlPlaneStore {
    // --- Observed-agent presence over the proxy binding, tenant-DB routed
    // (issue #460/#357) ---

    /// Record one coalesced presence touch into the tenant's D1 database as ONE
    /// conditional upsert on the `(tenant_id, api_key_id)` primary key. Mirrors the
    /// Postgres `touch_observed_agent_presence` with SQLite `max`/`min` in place of
    /// `GREATEST`/`LEAST` (see the module docs): last-seen/updated stay monotonic,
    /// first-seen minimal, and `request_count += excluded.request_count` folds the
    /// touch in without a separate read.
    ///
    /// Divergence: an UNPROVISIONED tenant is a typed `NotFound`
    /// (`tenant_proxy_binding` required), where Postgres would just insert.
    pub(super) async fn touch_observed_agent_presence_d1_async(
        &self,
        touch: &ObservedAgentPresenceTouch,
    ) -> Result<(), StorageError> {
        let proxy = self.proxy_client("touch_observed_agent_presence")?;
        let binding = self.tenant_proxy_binding(&touch.tenant_id)?;
        let seen = touch.seen_at_unix.to_string();
        // VALUES seeds first=last=updated=seen, request_count=1. The ON CONFLICT
        // clause reads only `excluded.*`/stored columns (already INTEGER-affinity),
        // so no CAST — SQLite's scalar max/min compare integers numerically.
        let statement = D1ProxyStatement::with_params(
            "INSERT INTO observed_agent_presence \
             (tenant_id, api_key_id, first_seen_at_unix, last_seen_at_unix, request_count, \
              updated_at_unix) \
             VALUES (?, ?, ?, ?, 1, ?) \
             ON CONFLICT (tenant_id, api_key_id) DO UPDATE SET \
             last_seen_at_unix = max(observed_agent_presence.last_seen_at_unix, \
                                     excluded.last_seen_at_unix), \
             first_seen_at_unix = min(observed_agent_presence.first_seen_at_unix, \
                                      excluded.first_seen_at_unix), \
             request_count = observed_agent_presence.request_count + excluded.request_count, \
             updated_at_unix = max(observed_agent_presence.updated_at_unix, \
                                   excluded.updated_at_unix)",
            vec![
                touch.tenant_id.clone(),
                touch.api_key_id.clone(),
                seen.clone(),
                seen.clone(),
                seen,
            ],
        );
        proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        Ok(())
    }

    /// Window read: presence rows whose most recent touch is at or after
    /// `since_unix`, newest first. `tenant_scope = Some` routes to that tenant's own
    /// database (opt-in: EMPTY for an unprovisioned org) and orders
    /// `last_seen_at_unix DESC, api_key_id ASC` to match the Postgres tenant-scoped
    /// read; `None` is the platform-operator cross-tenant view that FANS OUT over
    /// the provisioned tenant bindings and re-sorts the union to the Postgres
    /// operator order `last_seen_at_unix DESC, tenant_id ASC, api_key_id ASC`. Fails
    /// closed without a proxy.
    pub(super) async fn list_observed_agent_presence_since_d1_async(
        &self,
        tenant_scope: Option<&str>,
        since_unix: i64,
    ) -> Result<Vec<StoredObservedAgentPresence>, StorageError> {
        let proxy = self.proxy_client("list_observed_agent_presence_since")?;
        match tenant_scope {
            Some(tenant_id) => {
                let Some(binding) = self.tenant_proxy_binding_optional(tenant_id)? else {
                    return Ok(Vec::new());
                };
                // `last_seen_at_unix >= ?` is a bare INTEGER column vs bound param
                // (column affinity coerces the param), so no CAST.
                let statement = D1ProxyStatement::with_params(
                    format!(
                        "SELECT {OBSERVED_AGENT_PRESENCE_COLUMNS} FROM observed_agent_presence \
                         WHERE tenant_id = ? AND last_seen_at_unix >= ? \
                         ORDER BY last_seen_at_unix DESC, api_key_id ASC"
                    ),
                    vec![tenant_id.to_string(), since_unix.to_string()],
                );
                let result = proxy
                    .query_on(Some(&binding), &statement)
                    .await
                    .map_err(d1_error)?;
                result
                    .results
                    .iter()
                    .map(|row| {
                        decode_row::<ObservedAgentPresenceD1Row>(row)
                            .map(StoredObservedAgentPresence::from)
                    })
                    .collect()
            }
            None => {
                let mut rows = Vec::new();
                for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
                    let statement = D1ProxyStatement::with_params(
                        format!(
                            "SELECT {OBSERVED_AGENT_PRESENCE_COLUMNS} FROM observed_agent_presence \
                             WHERE last_seen_at_unix >= ? \
                             ORDER BY last_seen_at_unix DESC, tenant_id ASC, api_key_id ASC"
                        ),
                        vec![since_unix.to_string()],
                    );
                    let result = proxy
                        .query_on(Some(&binding), &statement)
                        .await
                        .map_err(d1_error)?;
                    for row in &result.results {
                        rows.push(
                            decode_row::<ObservedAgentPresenceD1Row>(row)
                                .map(StoredObservedAgentPresence::from)?,
                        );
                    }
                }
                // Postgres operator order: last_seen DESC, then tenant_id ASC,
                // api_key_id ASC — re-sort the cross-tenant union to match.
                rows.sort_by(|left, right| {
                    right
                        .last_seen_at_unix
                        .cmp(&left.last_seen_at_unix)
                        .then_with(|| left.tenant_id.cmp(&right.tenant_id))
                        .then_with(|| left.api_key_id.cmp(&right.api_key_id))
                });
                Ok(rows)
            }
        }
    }
}
