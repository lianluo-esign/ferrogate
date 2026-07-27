// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: AppState read seam for durable x402 payment attempts (issue
// #352, `## Scope and ownership`: "ferrogate-cli: narrow Admin API to list/get
// attempts and inspect linked wallet reservation/settlement"). Read-only: the
// attempts themselves are written by the #354 settlement loop, never by an
// operator request.

use super::*;

impl AppState {
    /// One bounded page of a tenant's payment attempts, newest-first.
    ///
    /// There is deliberately no unbounded variant on this seam:
    /// `payment_attempts` grows one row per paid egress request, so an "all
    /// rows" read behind an admin endpoint is a one-request DoS on the admin
    /// plane. The `limit` + keyset cursor is enforced by the repository
    /// (`PaymentAttemptQuery`), not by the HTTP handler, so no future caller can
    /// route around it.
    pub(crate) async fn list_payment_attempts(
        &self,
        tenant_id: &str,
        query: &ferrogate_storage::PaymentAttemptQuery,
    ) -> anyhow::Result<ferrogate_storage::PaymentAttemptPage> {
        Ok(self
            .repositories
            .list_payment_attempts(tenant_id, query)
            .await?)
    }

    /// One attempt joined to its wallet hold and captured settlement, enforcing
    /// tenant ownership in the storage predicate. `Ok(None)` when no such
    /// attempt is owned by `tenant_id` -- an attempt owned by ANOTHER tenant is
    /// indistinguishable from a missing one, which is what lets the admin
    /// surface answer `404` without leaking the existence of another tenant's
    /// payment.
    pub(crate) async fn get_payment_attempt_links(
        &self,
        id: &str,
        tenant_id: &str,
    ) -> anyhow::Result<Option<ferrogate_storage::PaymentAttemptLinks>> {
        Ok(self
            .repositories
            .get_payment_attempt_links(id, tenant_id)
            .await?)
    }

    /// The owning tenant of an attempt, without any tenancy filter. Used ONLY by
    /// the platform-operator path of `GET /admin/v1/payment-attempts/{id}`,
    /// where the caller has no tenant of its own to scope by; every
    /// tenant-scoped caller goes through
    /// [`get_payment_attempt_links`](Self::get_payment_attempt_links) instead,
    /// so this can never widen a tenant-scoped read.
    pub(crate) async fn payment_attempt_owner_tenant(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<String>> {
        Ok(self
            .repositories
            .get_payment_attempt(id)
            .await?
            .map(|attempt| attempt.tenant_id))
    }
}
