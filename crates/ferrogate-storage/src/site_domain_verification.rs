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

/// The minimum wall-clock gap between two ownership-verification DNS lookups for
/// the SAME `(tenant, hostname)` (#576). A verify call arriving inside this
/// cooldown is refused BEFORE any outbound DNS request is built, so an
/// `admin.write` credential can drive at most one DNS-over-HTTPS lookup per
/// `(tenant, hostname)` per cooldown window instead of the unbounded stream the
/// pre-#576 handler allowed. Scoped per `(tenant, hostname)` on purpose: one
/// tenant hammering its own hostname can never throttle another tenant's
/// verification (the anti-goal in the issue). Anchored to the persisted
/// `last_checked_at_unix`, so the limit survives a restart with durable storage.
pub const SITE_DOMAIN_VERIFICATION_ATTEMPT_COOLDOWN_SECONDS: i64 = 30;

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

/// The verdict of the per-(tenant, hostname) verification rate-limit gate
/// (#576). Returned by [`RuntimeStorageRepositories::try_begin_site_domain_verification_attempt`]
/// and consumed by the site-domain verify handler BEFORE it constructs any
/// outbound DNS request. Typed so a refusal carries a bounded, machine-readable
/// retry time rather than a bare boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteDomainVerificationAttempt {
    /// The cooldown had elapsed (or this is the first attempt): the caller
    /// reserved the DNS slot and MAY perform exactly one lookup. The reservation
    /// advanced the persisted `last_checked_at_unix`, so a concurrent or
    /// immediately following call is refused.
    Allowed,
    /// The cooldown has NOT elapsed for this `(tenant, hostname)`. The caller
    /// must refuse before any DNS request and surface `retry_after_secs` (always
    /// >= 1 and bounded by the cooldown) to the client.
    RateLimited { retry_after_secs: i64 },
}

impl SiteDomainVerificationAttempt {
    /// Whether the DNS lookup slot was reserved.
    pub fn is_allowed(self) -> bool {
        matches!(self, SiteDomainVerificationAttempt::Allowed)
    }
}

/// Pure decision for the verification cooldown, given the persisted
/// `last_checked_at_unix` of the `(tenant, hostname)` row, the injected `now`,
/// and the cooldown width. Split out so the window arithmetic is unit-tested
/// deterministically without any store, and shared verbatim by all three
/// backends so they cannot drift.
///
/// The FIRST attempt (no prior check recorded) is always allowed. Every backend
/// then reserves the slot with an ATOMIC conditional write on exactly this
/// predicate, so the read-then-write race the naive check would open cannot let
/// two concurrent calls both reach the resolver.
pub fn site_domain_verification_attempt_decision(
    last_checked_at_unix: Option<i64>,
    now_unix: i64,
    cooldown_secs: i64,
) -> SiteDomainVerificationAttempt {
    match last_checked_at_unix {
        Some(last) => {
            let ready_at = last.saturating_add(cooldown_secs);
            if now_unix >= ready_at {
                SiteDomainVerificationAttempt::Allowed
            } else {
                // Bounded and never below 1s: the client always gets a concrete,
                // positive hint that is at most one cooldown wide.
                let retry_after_secs = ready_at.saturating_sub(now_unix).max(1);
                SiteDomainVerificationAttempt::RateLimited { retry_after_secs }
            }
        }
        None => SiteDomainVerificationAttempt::Allowed,
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

    /// Atomically reserve one verification DNS slot for `(tenant, hostname)`
    /// (#576). The reservation is a single CONDITIONAL UPDATE -- never a
    /// read-then-write under READ COMMITTED -- that advances
    /// `last_checked_at_unix` to `now_unix` only when the cooldown has elapsed
    /// (or no check was ever recorded). If it updated a row the slot is reserved
    /// (`Allowed`); if it updated none, either the row is absent (nothing to
    /// rate-limit) or the cooldown is still open, and the current
    /// `last_checked_at_unix` yields the bounded retry time. Because the same
    /// predicate both guards and writes in one statement, two concurrent verify
    /// calls can never both reserve a slot inside one cooldown window.
    pub(super) async fn try_begin_site_domain_verification_attempt(
        &self,
        tenant_id: &str,
        hostname: &str,
        now_unix: i64,
        cooldown_secs: i64,
    ) -> Result<SiteDomainVerificationAttempt, StorageError> {
        let operation =
            self.site_domain_verification_operation("begin site domain verification attempt");
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
        let reserved = transaction
            .execute(
                "UPDATE site_domain_verifications \
                 SET last_checked_at_unix = $3, updated_at_unix = $3 \
                 WHERE tenant_id = $1 AND hostname = $2 \
                   AND (last_checked_at_unix IS NULL \
                        OR $3 - last_checked_at_unix >= $4)",
                &[&tenant_id, &hostname, &now_unix, &cooldown_secs],
            )
            .await
            .map_err(postgres_error)?;
        if reserved > 0 {
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(SiteDomainVerificationAttempt::Allowed);
        }
        // No row was reserved: read the current anchor to distinguish "cooldown
        // still open" (RateLimited, with a bounded retry) from "no row at all"
        // (Allowed -- there is nothing to throttle).
        let row = transaction
            .query_opt(
                "SELECT last_checked_at_unix FROM site_domain_verifications \
                 WHERE tenant_id = $1 AND hostname = $2",
                &[&tenant_id, &hostname],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(match row {
            Some(row) => site_domain_verification_attempt_decision(
                row.get::<_, Option<i64>>(0),
                now_unix,
                cooldown_secs,
            ),
            None => SiteDomainVerificationAttempt::Allowed,
        })
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

    /// Reserve one verification DNS slot for `(tenant, hostname)` (#576). The
    /// enclosing control-plane lock is held for the whole get-decide-write, so
    /// this get-then-insert is atomic for the memory backend, mirroring the
    /// single conditional UPDATE the SQL backends use. Only an `Allowed`
    /// decision advances the persisted `last_checked_at_unix`.
    pub(super) fn try_begin_site_domain_verification_attempt(
        &mut self,
        tenant_id: &str,
        hostname: &str,
        now_unix: i64,
        cooldown_secs: i64,
    ) -> SiteDomainVerificationAttempt {
        let key = site_domain_verification_key(tenant_id, hostname);
        match self.site_domain_verifications.get(&key) {
            Some(mut record) => {
                let decision = site_domain_verification_attempt_decision(
                    record.last_checked_at_unix,
                    now_unix,
                    cooldown_secs,
                );
                if decision.is_allowed() {
                    record.last_checked_at_unix = Some(now_unix);
                    record.updated_at_unix = now_unix;
                    self.site_domain_verifications.insert(key, record);
                }
                decision
            }
            // No row to throttle -- there is nothing to rate-limit yet.
            None => SiteDomainVerificationAttempt::Allowed,
        }
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

    /// Atomically reserve one ownership-verification DNS slot for
    /// `(tenant_id, hostname)` (#576), enforcing the per-(tenant, hostname)
    /// cooldown durably across the memory, Postgres, and D1 backends. The verify
    /// handler MUST call this and refuse before building any DNS request when the
    /// result is [`SiteDomainVerificationAttempt::RateLimited`]; only an
    /// `Allowed` result reserves the slot and advances the persisted
    /// `last_checked_at_unix`, so the limit is not silently erased by a restart.
    pub async fn try_begin_site_domain_verification_attempt(
        &self,
        tenant_id: &str,
        hostname: &str,
        now_unix: i64,
        cooldown_secs: i64,
    ) -> Result<SiteDomainVerificationAttempt, StorageError> {
        self.control_plane
            .store()
            .try_begin_site_domain_verification_attempt(
                tenant_id,
                hostname,
                now_unix,
                cooldown_secs,
            )
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
