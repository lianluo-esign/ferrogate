// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: DNS-TXT ownership proof for custom site domains (#488, guards
// the #265 binding surface). A `StoredSiteDomain` on its own only says "this
// tenant asked for this hostname"; it is NOT evidence that the tenant controls
// the hostname, so before #488 any tenant could land-grab `example.com`. This
// module adds the missing evidence as its OWN durable entity: one
// `StoredSiteDomainVerification` per `(tenant_id, hostname)` carrying an
// explicitly modelled state machine
// (`pending_verification` -> `verified` -> `expired`, plus the one-time
// `grandfathered` migration state) and the per-(tenant, hostname) challenge
// token the operator must publish as TXT at `_ferrogate-challenge.<hostname>`.
//
// Keyed on `(tenant_id, hostname)` and NOT on `hostname` alone, deliberately:
//   * a challenge tenant A started can never be redeemed by tenant B -- B's
//     lookup is a DIFFERENT primary key holding a DIFFERENT token, and the TXT
//     value is a digest over the length-prefixed `(tenant, hostname, token)`
//     triple (see the gateway's `site_domain_verification` module), so even a
//     verbatim copy of A's published TXT value proves nothing for B; and
//   * several tenants may hold a PENDING challenge for one hostname at once, so
//     a squatter holding an unverified binding can no longer block the tenant
//     that actually owns the domain (the #488 land-grab).
// Exactly one tenant can hold the SERVABLE `site_domains` row; that row is only
// written/taken over once a verification for that tenant is servable.
//
// Split into its own file per the "one business entity per file" convention
// (mirrors `observed_agent_presence.rs`), and kept OUT of `lib.rs` per its
// line cap.

use super::{
    postgres_error, PostgresControlPlaneStore, PostgresRow, Repository, RuntimeControlPlaneState,
    RuntimeStorageRepositories, StorageError, StorageOperation,
};

/// How long an issued challenge token stays redeemable before the operator has
/// to ask for a fresh one (7 days). A stale token is `expired`, never
/// implicitly still-good.
pub const SITE_DOMAIN_CHALLENGE_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

/// How long a completed verification stays valid before re-verification is
/// required (90 days). Ownership of a domain can change hands; a proof from an
/// unbounded past is not a proof of present control.
pub const SITE_DOMAIN_VERIFICATION_TTL_SECONDS: i64 = 90 * 24 * 60 * 60;

/// The explicit lifecycle of one `(tenant, hostname)` ownership proof. Modelled
/// as a closed enum rather than a `verified: bool` so a binding can never sit
/// in an ambiguous "no record / maybe fine" state: the ABSENCE of a record and
/// every non-servable state both fail closed at the serve gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteDomainVerificationState {
    /// A token has been issued; the TXT record has not been observed yet.
    /// NOT servable.
    PendingVerification,
    /// The TXT challenge was observed and matched. Servable until
    /// `verification_expires_at_unix`.
    Verified,
    /// A #488 migration state, NOT a proof: the binding already existed when
    /// ownership verification was introduced, so it keeps serving instead of
    /// going dark, but it is explicitly distinguishable from `verified` in the
    /// store, in the admin API, and in the startup log. Servable.
    Grandfathered,
    /// The challenge token or a completed verification aged out. NOT servable;
    /// re-binding issues a fresh token.
    Expired,
}

impl SiteDomainVerificationState {
    /// The stable wire/column string.
    pub fn as_str(self) -> &'static str {
        match self {
            SiteDomainVerificationState::PendingVerification => "pending_verification",
            SiteDomainVerificationState::Verified => "verified",
            SiteDomainVerificationState::Grandfathered => "grandfathered",
            SiteDomainVerificationState::Expired => "expired",
        }
    }

    /// Parse a persisted state string. Returns `None` for anything unknown --
    /// the caller turns that into an error, never into a servable default.
    pub fn from_str_opt(raw: &str) -> Option<Self> {
        match raw {
            "pending_verification" => Some(SiteDomainVerificationState::PendingVerification),
            "verified" => Some(SiteDomainVerificationState::Verified),
            "grandfathered" => Some(SiteDomainVerificationState::Grandfathered),
            "expired" => Some(SiteDomainVerificationState::Expired),
            _ => None,
        }
    }

    /// Whether a binding whose verification resolves to this state may serve
    /// traffic. Only a live proof (or the explicit migration grandfather)
    /// qualifies; everything else fails closed.
    pub fn serves(self) -> bool {
        matches!(
            self,
            SiteDomainVerificationState::Verified | SiteDomainVerificationState::Grandfathered
        )
    }
}

/// One durable ownership proof (or in-flight challenge) for
/// `(tenant_id, hostname)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSiteDomainVerification {
    pub tenant_id: String,
    pub hostname: String,
    /// The site the challenge was issued for. Verification takes over the
    /// `site_domains` row for THIS site, so the proof and the thing it makes
    /// servable are recorded together.
    pub site: String,
    pub state: SiteDomainVerificationState,
    /// Per-(tenant, hostname) random token. The published TXT value is a digest
    /// over `(tenant_id, hostname, challenge_token)`, so the token never leaves
    /// the control plane in plaintext and cannot be replayed by another tenant.
    pub challenge_token: String,
    pub issued_at_unix: i64,
    pub token_expires_at_unix: i64,
    pub verified_at_unix: Option<i64>,
    /// When a completed verification must be renewed. `None` only for
    /// `grandfathered` rows (they carry no proof to expire; an operator forces
    /// re-verification by unbinding/re-binding, or by the startup switch).
    pub verification_expires_at_unix: Option<i64>,
    pub last_checked_at_unix: Option<i64>,
    /// Why the last check did not verify. A resolver failure is recorded here
    /// and NEVER promotes the state.
    pub last_failure_reason: Option<String>,
    pub attempt_count: i64,
    pub updated_at_unix: i64,
}

impl StoredSiteDomainVerification {
    /// A freshly issued, not-yet-proven challenge.
    pub fn pending(
        tenant_id: impl Into<String>,
        hostname: impl Into<String>,
        site: impl Into<String>,
        challenge_token: impl Into<String>,
        now_unix: i64,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            hostname: hostname.into(),
            site: site.into(),
            state: SiteDomainVerificationState::PendingVerification,
            challenge_token: challenge_token.into(),
            issued_at_unix: now_unix,
            token_expires_at_unix: now_unix.saturating_add(SITE_DOMAIN_CHALLENGE_TTL_SECONDS),
            verified_at_unix: None,
            verification_expires_at_unix: None,
            last_checked_at_unix: None,
            last_failure_reason: None,
            attempt_count: 0,
            updated_at_unix: now_unix,
        }
    }

    /// The one-time #488 migration record for a binding that predates
    /// verification. Recorded EXPLICITLY (never inferred from a missing row) so
    /// the grandfathered set is auditable and revocable.
    pub fn grandfathered(
        tenant_id: impl Into<String>,
        hostname: impl Into<String>,
        site: impl Into<String>,
        challenge_token: impl Into<String>,
        now_unix: i64,
    ) -> Self {
        Self {
            state: SiteDomainVerificationState::Grandfathered,
            last_failure_reason: Some(
                "binding predates #488 DNS ownership verification; grandfathered at upgrade"
                    .to_string(),
            ),
            ..Self::pending(tenant_id, hostname, site, challenge_token, now_unix)
        }
    }

    /// Promote a matched challenge to `verified` and start the re-verification
    /// clock.
    pub fn mark_verified(&mut self, now_unix: i64) {
        self.state = SiteDomainVerificationState::Verified;
        self.verified_at_unix = Some(now_unix);
        self.verification_expires_at_unix =
            Some(now_unix.saturating_add(SITE_DOMAIN_VERIFICATION_TTL_SECONDS));
        self.last_checked_at_unix = Some(now_unix);
        self.last_failure_reason = None;
        self.attempt_count = self.attempt_count.saturating_add(1);
        self.updated_at_unix = now_unix;
    }

    /// Record a check that did NOT prove ownership -- a missing/mismatched TXT
    /// record or an unreachable resolver. The state is deliberately left
    /// untouched: a failed or impossible check can never promote a binding, and
    /// it must not silently demote a live `verified` one either.
    pub fn mark_check_failed(&mut self, now_unix: i64, reason: impl Into<String>) {
        self.last_checked_at_unix = Some(now_unix);
        self.last_failure_reason = Some(reason.into());
        self.attempt_count = self.attempt_count.saturating_add(1);
        self.updated_at_unix = now_unix;
    }

    /// The state as of `now_unix`, with the time-based transitions applied:
    /// an unredeemed token past its TTL and a verification past its
    /// re-verification deadline both resolve to `expired`. Time is applied at
    /// READ time so an expiry is never dependent on a sweeper having run.
    pub fn effective_state(&self, now_unix: i64) -> SiteDomainVerificationState {
        match self.state {
            SiteDomainVerificationState::PendingVerification
                if now_unix >= self.token_expires_at_unix =>
            {
                SiteDomainVerificationState::Expired
            }
            SiteDomainVerificationState::Verified => match self.verification_expires_at_unix {
                Some(deadline) if now_unix >= deadline => SiteDomainVerificationState::Expired,
                _ => SiteDomainVerificationState::Verified,
            },
            state => state,
        }
    }

    /// Whether the binding this proof backs may serve traffic as of `now_unix`.
    pub fn serves(&self, now_unix: i64) -> bool {
        self.effective_state(now_unix).serves()
    }

    /// Whether this row is a live DNS ownership proof as of `now_unix`.
    ///
    /// This is intentionally narrower than [`Self::serves`]: `grandfathered`
    /// records preserve upgrade availability, but they are not evidence that the
    /// tenant currently controls the hostname.
    pub fn has_live_dns_ownership_proof(&self, now_unix: i64) -> bool {
        self.effective_state(now_unix) == SiteDomainVerificationState::Verified
    }
}

/// Composite in-memory identity for a verification row. Length-prefixed on the
/// tenant so a crafted `(tenant, hostname)` pair can never alias another -- the
/// same collision-safety trick as [`crate::observed_agent_presence_key`] and
/// [`crate::agent_cost_burn_key`]. This is the key that makes tenant B unable
/// to touch the challenge tenant A started for the same hostname.
pub fn site_domain_verification_key(tenant_id: &str, hostname: &str) -> String {
    format!("{}:{tenant_id}:{hostname}", tenant_id.len())
}

const SITE_DOMAIN_VERIFICATION_COLUMNS: &str = "tenant_id, hostname, site, state, \
     challenge_token, issued_at_unix, token_expires_at_unix, verified_at_unix, \
     verification_expires_at_unix, last_checked_at_unix, last_failure_reason, attempt_count, \
     updated_at_unix";

fn verification_from_row(row: &PostgresRow) -> Result<StoredSiteDomainVerification, StorageError> {
    let raw_state = row.get::<_, String>(3);
    let state = SiteDomainVerificationState::from_str_opt(&raw_state).ok_or_else(|| {
        StorageError::Postgres(format!(
            "unknown site_domain_verifications.state {raw_state}"
        ))
    })?;
    Ok(StoredSiteDomainVerification {
        tenant_id: row.get::<_, String>(0),
        hostname: row.get::<_, String>(1),
        site: row.get::<_, String>(2),
        state,
        challenge_token: row.get::<_, String>(4),
        issued_at_unix: row.get::<_, i64>(5),
        token_expires_at_unix: row.get::<_, i64>(6),
        verified_at_unix: row.get::<_, Option<i64>>(7),
        verification_expires_at_unix: row.get::<_, Option<i64>>(8),
        last_checked_at_unix: row.get::<_, Option<i64>>(9),
        last_failure_reason: row.get::<_, Option<String>>(10),
        attempt_count: row.get::<_, i64>(11),
        updated_at_unix: row.get::<_, i64>(12),
    })
}

impl PostgresControlPlaneStore {
    fn site_domain_verification_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    pub(super) async fn upsert_site_domain_verification(
        &self,
        verification: &StoredSiteDomainVerification,
    ) -> Result<(), StorageError> {
        let operation = self.site_domain_verification_operation("upsert site domain verification");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239), as every
        // other control-plane write in this crate does.
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "INSERT INTO site_domain_verifications \
                 (tenant_id, hostname, site, state, challenge_token, issued_at_unix, \
                  token_expires_at_unix, verified_at_unix, verification_expires_at_unix, \
                  last_checked_at_unix, last_failure_reason, attempt_count, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
                 ON CONFLICT (tenant_id, hostname) DO UPDATE SET \
                     site = EXCLUDED.site, \
                     state = EXCLUDED.state, \
                     challenge_token = EXCLUDED.challenge_token, \
                     issued_at_unix = EXCLUDED.issued_at_unix, \
                     token_expires_at_unix = EXCLUDED.token_expires_at_unix, \
                     verified_at_unix = EXCLUDED.verified_at_unix, \
                     verification_expires_at_unix = EXCLUDED.verification_expires_at_unix, \
                     last_checked_at_unix = EXCLUDED.last_checked_at_unix, \
                     last_failure_reason = EXCLUDED.last_failure_reason, \
                     attempt_count = EXCLUDED.attempt_count, \
                     updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &verification.tenant_id,
                    &verification.hostname,
                    &verification.site,
                    &verification.state.as_str(),
                    &verification.challenge_token,
                    &verification.issued_at_unix,
                    &verification.token_expires_at_unix,
                    &verification.verified_at_unix,
                    &verification.verification_expires_at_unix,
                    &verification.last_checked_at_unix,
                    &verification.last_failure_reason,
                    &verification.attempt_count,
                    &verification.updated_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    pub(super) async fn get_site_domain_verification(
        &self,
        tenant_id: &str,
        hostname: &str,
    ) -> Result<Option<StoredSiteDomainVerification>, StorageError> {
        let operation = self.site_domain_verification_operation("get site domain verification");
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
        let row = transaction
            .query_opt(
                &format!(
                    "SELECT {SITE_DOMAIN_VERIFICATION_COLUMNS} FROM site_domain_verifications \
                     WHERE tenant_id = $1 AND hostname = $2"
                ),
                &[&tenant_id, &hostname],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        row.as_ref().map(verification_from_row).transpose()
    }

    pub(super) async fn list_site_domain_verifications(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredSiteDomainVerification>, StorageError> {
        let operation = self.site_domain_verification_operation("list site domain verifications");
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
        let rows = match tenant_id {
            Some(tenant_id) => transaction
                .query(
                    &format!(
                        "SELECT {SITE_DOMAIN_VERIFICATION_COLUMNS} FROM site_domain_verifications \
                         WHERE tenant_id = $1 ORDER BY hostname ASC"
                    ),
                    &[&tenant_id],
                )
                .await
                .map_err(postgres_error)?,
            None => transaction
                .query(
                    &format!(
                        "SELECT {SITE_DOMAIN_VERIFICATION_COLUMNS} FROM site_domain_verifications \
                         ORDER BY tenant_id ASC, hostname ASC"
                    ),
                    &[],
                )
                .await
                .map_err(postgres_error)?,
        };
        transaction.commit().await.map_err(postgres_error)?;
        rows.iter().map(verification_from_row).collect()
    }

    pub(super) async fn delete_site_domain_verification(
        &self,
        tenant_id: &str,
        hostname: &str,
    ) -> Result<bool, StorageError> {
        let operation = self.site_domain_verification_operation("delete site domain verification");
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
        let affected = transaction
            .execute(
                "DELETE FROM site_domain_verifications WHERE tenant_id = $1 AND hostname = $2",
                &[&tenant_id, &hostname],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected > 0)
    }
}

impl RuntimeControlPlaneState {
    pub(super) fn upsert_site_domain_verification(
        &mut self,
        verification: StoredSiteDomainVerification,
    ) {
        let key = site_domain_verification_key(&verification.tenant_id, &verification.hostname);
        self.site_domain_verifications.insert(key, verification);
    }

    pub(super) fn get_site_domain_verification(
        &self,
        tenant_id: &str,
        hostname: &str,
    ) -> Option<StoredSiteDomainVerification> {
        self.site_domain_verifications
            .get(&site_domain_verification_key(tenant_id, hostname))
    }

    pub(super) fn list_site_domain_verifications(
        &self,
        tenant_id: Option<&str>,
    ) -> Vec<StoredSiteDomainVerification> {
        let mut rows: Vec<_> = self
            .site_domain_verifications
            .list()
            .into_iter()
            .filter(|row| tenant_id.is_none_or(|tenant| row.tenant_id == tenant))
            .collect();
        rows.sort_by(|left, right| {
            left.tenant_id
                .cmp(&right.tenant_id)
                .then_with(|| left.hostname.cmp(&right.hostname))
        });
        rows
    }

    pub(super) fn delete_site_domain_verification(
        &mut self,
        tenant_id: &str,
        hostname: &str,
    ) -> bool {
        self.site_domain_verifications
            .remove(&site_domain_verification_key(tenant_id, hostname))
            .is_some()
    }
}

impl RuntimeStorageRepositories {
    /// Write (or refresh) the ownership proof / challenge for
    /// `(tenant_id, hostname)`.
    pub async fn upsert_site_domain_verification(
        &self,
        verification: StoredSiteDomainVerification,
    ) -> Result<(), StorageError> {
        self.control_plane
            .store()
            .upsert_site_domain_verification(verification)
            .await
    }

    /// Read the proof for exactly `(tenant_id, hostname)`. `Ok(None)` means NO
    /// proof exists, which the serve gate treats as not-servable.
    pub async fn get_site_domain_verification(
        &self,
        tenant_id: &str,
        hostname: &str,
    ) -> Result<Option<StoredSiteDomainVerification>, StorageError> {
        self.control_plane
            .store()
            .get_site_domain_verification(tenant_id, hostname)
            .await
    }

    /// Lists proofs, optionally narrowed to one tenant. `None` is the
    /// platform-operator view (used by the #488 startup backfill).
    pub async fn list_site_domain_verifications(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<StoredSiteDomainVerification>, StorageError> {
        self.control_plane
            .store()
            .list_site_domain_verifications(tenant_id)
            .await
    }

    pub async fn delete_site_domain_verification(
        &self,
        tenant_id: &str,
        hostname: &str,
    ) -> Result<bool, StorageError> {
        self.control_plane
            .store()
            .delete_site_domain_verification(tenant_id, hostname)
            .await
    }
}

#[cfg(test)]
#[path = "site_domain_verification_test.rs"]
mod site_domain_verification_test;
