// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: Static-site custom domains (#265, asset hosting epic #175):
// the `/admin/v1/site-domains` bind/unbind surface plus the data-plane
// `Host: <hostname>` -> `{tenant}/{site}` serve resolution. A bound hostname
// serves through the exact same `serve_site_and_log` path (and therefore the
// same per-site public/private visibility gating) as the #258
// `/sites/{tenant}/{site}/{path...}` route. TLS for bound hostnames rides the
// existing ACME issuance/renewal machinery: bound hostnames are merged into
// the ACME domain set at startup (gateway::serve), and a runtime bind/unbind
// marks the renewal status reload-required and (when configured) triggers the
// same listener-level graceful upgrade a scheduled renewal uses -- no
// duplicate PKI path.
//
// #488 (security): a bind records INTENT, never ownership. Every servable path
// here is now gated on a DNS-TXT ownership proof for the binding's
// `(tenant, hostname)` (see `site_domain_verification.rs`):
//   * the data-plane serve gate refuses a hostname whose proof is missing,
//     pending, or expired -- and refuses it when the proof cannot be READ at
//     all, so a store outage can never open the gate;
//   * binding an unbound hostname issues a challenge and returns 202 instead of
//     making the hostname servable, so an unowned FQDN never lands in the ACME
//     order set (the failed-order rate-limit pollution the issue calls out);
//   * a hostname whose only claim is another tenant's UNVERIFIED binding is no
//     longer defended by the 409 -- the tenant that actually owns the domain
//     can raise its own challenge and take the binding over by proving control.
//     A hostname backed by a LIVE proof still conflicts.

use std::time::{SystemTime, UNIX_EPOCH};

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::{Deserialize, Serialize};

use ferrogate_storage::{StoredSiteDomain, StoredSiteDomainVerification};

use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::route_groups::RequestParts;
use super::site_domain_verification::{
    challenge_record_name, challenge_txt_value, new_challenge_token, resolve_challenge,
    reusable_on_rebind, AdminSiteDomainVerification, ChallengeOutcome, SiteDomainResolverBackend,
};
use super::{FerroGateway, ProxyContext};
use crate::{
    auth::{authenticate, authorize_tenant_scope, enforce_tenant_filter},
    responses::{write_json_error, write_json_error_and_close, write_json_response, AdminList},
};

impl FerroGateway {
    /// Data-plane resolution for a bound custom hostname (#265): when the
    /// request's normalized `Host` maps to a `{tenant}/{site}` binding, the
    /// request is served through the same static-site path (and visibility
    /// gating) as `/sites/{tenant}/{site}/{path...}`, with the request path
    /// used as the in-site file path. Returns `Ok(false)` when the hostname
    /// is not bound (or the binding lookup failed), in which case the caller
    /// falls through to dynamic host/path route matching unchanged --
    /// availability of the proxy surface is never held hostage to the
    /// control-plane store.
    ///
    /// #488: a binding alone is NOT sufficient. The hostname additionally needs
    /// a live DNS-TXT ownership proof for the binding's tenant; a missing,
    /// pending, or expired proof -- and an unreadable one -- all fail closed to
    /// `Ok(false)`, i.e. the tenant's site is not served on this hostname.
    pub(super) async fn try_custom_domain_site_serve(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        req: &RequestParts,
        host: &str,
    ) -> PingoraResult<bool> {
        let state = self.state.current();
        let binding = match state.get_site_domain(host).await {
            Ok(Some(binding)) => binding,
            Ok(None) => return Ok(false),
            Err(error) => {
                tracing::warn!(host = %host, "site custom-domain lookup failed: {error}");
                return Ok(false);
            }
        };
        let now = now_unix_seconds();
        match state
            .get_site_domain_verification(&binding.tenant_id, host)
            .await
        {
            Ok(Some(verification)) if verification.serves(now) => {}
            Ok(Some(verification)) => {
                tracing::warn!(
                    host = %host,
                    tenant = %binding.tenant_id,
                    verification_state = %verification.effective_state(now).as_str(),
                    "refusing to serve a site custom domain without a live DNS ownership proof",
                );
                return Ok(false);
            }
            Ok(None) => {
                tracing::warn!(
                    host = %host,
                    tenant = %binding.tenant_id,
                    "refusing to serve a site custom domain with NO DNS ownership proof",
                );
                return Ok(false);
            }
            Err(error) => {
                // Unavailable is not "verified": if the proof cannot be read,
                // the hostname does not serve.
                tracing::warn!(
                    host = %host,
                    tenant = %binding.tenant_id,
                    "site custom-domain ownership proof unreadable, failing closed: {error}",
                );
                return Ok(false);
            }
        }
        self.serve_site_and_log(
            session,
            ctx,
            &req.headers,
            &req.method,
            &binding.tenant_id,
            &binding.site,
            req.path.trim_start_matches('/'),
        )
        .await?;
        Ok(true)
    }

    /// Dispatch for the `/admin/v1/site-domains[...]` surface: list/bind on
    /// the collection, get/unbind on `/{hostname}`, and the #488 ownership
    /// challenge redemption on `POST /{hostname}/verify`.
    pub(super) async fn handle_admin_site_domains(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        if path == "/admin/v1/site-domains" {
            return match *method {
                Method::GET => {
                    self.handle_admin_site_domain_list(session, ctx, headers, query)
                        .await
                }
                Method::POST => {
                    self.handle_admin_site_domain_bind(session, ctx, headers)
                        .await
                }
                _ => method_not_allowed(session, ctx).await,
            };
        }

        let Some(rest) = path
            .strip_prefix("/admin/v1/site-domains/")
            .filter(|rest| !rest.is_empty())
        else {
            return not_found(session, ctx).await;
        };
        // `/{hostname}/verify` is the only nested sub-resource (#488).
        if let Some(hostname) = rest
            .strip_suffix("/verify")
            .filter(|hostname| !hostname.is_empty() && !hostname.contains('/'))
        {
            return match *method {
                Method::POST => {
                    self.handle_admin_site_domain_verify(session, ctx, headers, hostname, query)
                        .await
                }
                _ => method_not_allowed(session, ctx).await,
            };
        }
        if rest.contains('/') {
            return not_found(session, ctx).await;
        }
        match *method {
            Method::GET => {
                self.handle_admin_site_domain_get(session, ctx, headers, rest)
                    .await
            }
            Method::DELETE => {
                self.handle_admin_site_domain_unbind(session, ctx, headers, rest)
                    .await
            }
            _ => method_not_allowed(session, ctx).await,
        }
    }

    async fn handle_admin_site_domain_list(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };
        // A tenant-scoped key is pinned to its own tenant; a platform operator
        // may narrow to a `?tenant=` filter or see every tenant's bindings.
        let requested_tenant =
            query_param(query, "tenant").or_else(|| query_param(query, "tenant_id"));
        let tenant = enforce_tenant_filter(&auth, requested_tenant);
        let domains = match state.list_site_domains(tenant.as_deref()).await {
            Ok(domains) => domains,
            Err(error) => return storage_error(session, ctx, error.to_string()).await,
        };
        // One bulk read joins every binding to its #488 ownership proof, so the
        // listing shows which hostnames actually serve without an N+1 fan-out.
        let verifications = match state
            .list_site_domain_verifications(tenant.as_deref())
            .await
        {
            Ok(verifications) => verifications,
            Err(error) => return storage_error(session, ctx, error.to_string()).await,
        };
        let now = now_unix_seconds();
        let data = domains
            .iter()
            .map(|domain| {
                let verification = verifications.iter().find(|verification| {
                    verification.tenant_id == domain.tenant_id
                        && verification.hostname == domain.hostname
                });
                admin_site_domain(domain, verification, now)
            })
            .collect();
        write_json_response(
            session,
            StatusCode::OK,
            &AdminList::new(data),
            &ctx.request_id,
        )
        .await
    }

    async fn handle_admin_site_domain_get(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        raw_hostname: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };
        let hostname = crate::routing::normalize_host(raw_hostname);
        let binding = match state.get_site_domain(&hostname).await {
            Ok(Some(binding)) => binding,
            Ok(None) => return domain_not_found(session, ctx, &hostname).await,
            Err(error) => return storage_error(session, ctx, error.to_string()).await,
        };
        // A tenant-scoped caller must not learn another tenant's binding: a
        // cross-tenant hostname reads as absent, mirroring the #258 serve-mode
        // fail-closed posture.
        if authorize_tenant_scope(&auth, &binding.tenant_id).is_err() {
            return domain_not_found(session, ctx, &hostname).await;
        }
        // The #488 proof is surfaced alongside the ACME posture: this is where
        // an operator reads the pending/verified state and the exact TXT record
        // still to be published.
        let verification = match state
            .get_site_domain_verification(&binding.tenant_id, &hostname)
            .await
        {
            Ok(verification) => verification,
            Err(error) => return storage_error(session, ctx, error.to_string()).await,
        };
        let now = now_unix_seconds();
        write_json_response(
            session,
            StatusCode::OK,
            &AdminSiteDomainResponse {
                object: "site_domain",
                site_domain: admin_site_domain(&binding, verification.as_ref(), now),
                acme: self.site_domain_acme_state(&state),
                verification: verification
                    .as_ref()
                    .map(|record| AdminSiteDomainVerification::new(record, now)),
            },
            &ctx.request_id,
        )
        .await
    }

    async fn handle_admin_site_domain_bind(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };

        let body =
            match read_request_body(session, state.limits().admin_small_body_max_bytes()).await? {
                Ok(body) => body,
                Err(limit) => {
                    return write_json_error_and_close(
                        session,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "payload_too_large",
                        format!(
                            "request body exceeds maximum size of {} bytes",
                            limit.max_bytes
                        ),
                        &ctx.request_id,
                    )
                    .await;
                }
            };
        let mutation = match serde_json::from_slice::<AdminSiteDomainMutation>(&body) {
            Ok(mutation) => mutation,
            Err(error) => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    format!("request body must be a JSON site-domain object: {error}"),
                    &ctx.request_id,
                )
                .await;
            }
        };

        let reject = |message: String| {
            state.record_admin_audit_event(admin_audit_event_draft_for_target(
                ctx,
                &auth,
                "site_domain.bind",
                mutation.hostname.as_deref().unwrap_or("new"),
                "rejected",
                message.clone(),
            ));
            message
        };

        let hostname = match validate_site_domain_hostname(mutation.hostname.as_deref()) {
            Ok(hostname) => hostname,
            Err(message) => {
                let message = reject(message);
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_site_domain",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        let (tenant_id, site) = match (
            non_empty(mutation.tenant_id.as_deref()),
            non_empty(mutation.site.as_deref()),
        ) {
            (Some(tenant_id), Some(site)) => (tenant_id.to_string(), site.to_string()),
            _ => {
                let message = reject("tenant_id and site are required".to_string());
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_site_domain",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        // A tenant-scoped caller may only bind hostnames for its own tenant.
        if let Err(error) = authorize_tenant_scope(&auth, &tenant_id) {
            return write_auth_error(session, ctx, error).await;
        }

        // The target site must exist (have a published manifest, #258) so a
        // binding always points at something servable -- and so the audit
        // trail records a meaningful target.
        match self.load_site_manifest(&tenant_id, &site).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                let message = reject(format!("no published site at {tenant_id}/{site}"));
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "site_not_found",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
            Err(error) => return storage_error(session, ctx, error.to_string()).await,
        }

        // A hostname points at exactly one site. Re-binding within the same
        // tenant is an update. A hostname held by ANOTHER tenant is a conflict
        // ONLY when that tenant has actually PROVEN ownership (#488): an
        // unverified claim is a land-grab, not a right, and must not go on
        // defending the squatter against the real owner.
        let now = now_unix_seconds();
        let existing = match state.get_site_domain(&hostname).await {
            Ok(existing) => existing,
            Err(error) => return storage_error(session, ctx, error.to_string()).await,
        };
        if let Some(existing) = existing.as_ref() {
            if existing.tenant_id != tenant_id {
                // Fail closed: if the incumbent's proof cannot be read, do NOT
                // assume it is unproven and hand the hostname over.
                let holder_proven = match state
                    .get_site_domain_verification(&existing.tenant_id, &hostname)
                    .await
                {
                    Ok(Some(verification)) => verification.serves(now),
                    Ok(None) => false,
                    Err(error) => return storage_error(session, ctx, error.to_string()).await,
                };
                if holder_proven {
                    let message = reject(format!(
                        "hostname {hostname} is bound by another tenant with a verified \
                         DNS ownership proof"
                    ));
                    return write_json_error(
                        session,
                        StatusCode::CONFLICT,
                        "site_domain_conflict",
                        message,
                        &ctx.request_id,
                    )
                    .await;
                }
            }
        }

        // The caller's own proof for this hostname, if any. A live proof (or an
        // unexpired challenge) survives a re-bind -- ownership is of the
        // HOSTNAME, not of the site it points at -- so an operator who already
        // published the TXT record is not sent back to DNS.
        let caller_proof = match state
            .get_site_domain_verification(&tenant_id, &hostname)
            .await
        {
            Ok(proof) => proof,
            Err(error) => return storage_error(session, ctx, error.to_string()).await,
        };
        let verification = match caller_proof {
            Some(mut record) if reusable_on_rebind(&record, now) => {
                record.site = site.clone();
                record.updated_at_unix = now;
                record
            }
            _ => {
                let token = match new_challenge_token() {
                    Ok(token) => token,
                    Err(error) => {
                        let message = reject(error.to_string());
                        return storage_error(session, ctx, message).await;
                    }
                };
                StoredSiteDomainVerification::pending(&tenant_id, &hostname, &site, token, now)
            }
        };
        let proven = verification.serves(now);
        if let Err(error) = state
            .upsert_site_domain_verification(verification.clone())
            .await
        {
            let message = reject(error.to_string());
            return storage_error(session, ctx, message).await;
        }

        // The servable binding row is written when the caller already holds the
        // hostname here (unbound, or its own). Taking it over from another
        // tenant's unverified claim requires completing the challenge --
        // `POST /admin/v1/site-domains/{hostname}/verify`.
        let holds_binding = existing
            .as_ref()
            .is_none_or(|existing| existing.tenant_id == tenant_id);
        let domain = StoredSiteDomain {
            hostname: hostname.clone(),
            tenant_id: tenant_id.clone(),
            site: site.clone(),
            created_at_unix: existing
                .as_ref()
                .filter(|existing| existing.tenant_id == tenant_id)
                .map_or(now, |existing| existing.created_at_unix),
            updated_at_unix: now,
        };
        if holds_binding {
            if let Err(error) = state.upsert_site_domain(domain.clone()).await {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "site_domain.bind",
                    &hostname,
                    "rejected",
                    message.clone(),
                ));
                return storage_error(session, ctx, message).await;
            }
        }

        // #488: an unproven hostname must NOT enter the ACME order set. That is
        // both the certificate-issuance rate-limit pollution the issue calls
        // out and a second place an unowned hostname would become real.
        let acme = if proven && holds_binding {
            self.refresh_acme_after_domain_change(&state, &hostname, true)
        } else {
            self.site_domain_acme_state(&state)
        };
        let admin_verification = AdminSiteDomainVerification::new(&verification, now);
        state.record_admin_audit_event(admin_audit_event_draft_for_target(
            ctx,
            &auth,
            "site_domain.bind",
            &hostname,
            "committed",
            format!(
                "custom domain {hostname} bound to site {tenant_id}/{site} \
                 (verification_state={}, serving={proven}, binding_written={holds_binding}, \
                 acme_enabled={}, reload_triggered={})",
                admin_verification.state, acme.enabled, acme.reload_triggered
            ),
        ));
        let terminal = site_domain_bind_status(proven, existing.is_some());
        write_json_response(
            session,
            terminal.status(),
            &AdminSiteDomainResponse {
                object: "site_domain",
                site_domain: admin_site_domain(&domain, Some(&verification), now),
                acme,
                verification: Some(admin_verification),
            },
            &ctx.request_id,
        )
        .await
    }

    /// `POST /admin/v1/site-domains/{hostname}/verify` (#488): resolve the
    /// challenge TXT record and, only on an exact match, promote the binding to
    /// servable.
    ///
    /// Three distinct terminals, and only one of them verifies:
    ///   * match -> 200, `verified`, the binding becomes servable and (only
    ///     now) enters the ACME domain set;
    ///   * no match -> 409, still `pending_verification`;
    ///   * resolver failed -> 503, state UNCHANGED. An unreachable resolver is
    ///     never a pass, and never a demotion either.
    async fn handle_admin_site_domain_verify(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        raw_hostname: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };
        let hostname = crate::routing::normalize_host(raw_hostname);

        // WHOSE challenge is being redeemed. A tenant-scoped key is pinned to
        // its own tenant and cannot name another (its pin wins over any
        // `?tenant=`); a platform operator must say which tenant explicitly.
        // This is what makes "tenant B redeems tenant A's challenge"
        // unreachable even before the token binding is considered.
        let tenant_id = match auth
            .organization_id
            .clone()
            .or_else(|| query_param(query, "tenant"))
            .or_else(|| query_param(query, "tenant_id"))
        {
            Some(tenant_id) => tenant_id,
            None => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_site_domain",
                    "tenant_id is required: name the tenant whose challenge is being verified \
                     (?tenant=<id>)",
                    &ctx.request_id,
                )
                .await;
            }
        };
        if let Err(error) = authorize_tenant_scope(&auth, &tenant_id) {
            return write_auth_error(session, ctx, error).await;
        }

        let mut verification = match state
            .get_site_domain_verification(&tenant_id, &hostname)
            .await
        {
            // A challenge is keyed on (tenant, hostname): another tenant's
            // in-flight challenge for the same hostname simply does not exist
            // from here.
            Ok(Some(verification)) => verification,
            Ok(None) => {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "site_domain_challenge_not_found",
                    format!(
                        "no site-domain ownership challenge for {tenant_id}/{hostname}; \
                         POST /admin/v1/site-domains to issue one"
                    ),
                    &ctx.request_id,
                )
                .await;
            }
            Err(error) => return storage_error(session, ctx, error.to_string()).await,
        };

        let now = now_unix_seconds();
        if verification.effective_state(now)
            == ferrogate_storage::SiteDomainVerificationState::Expired
        {
            return write_json_error(
                session,
                StatusCode::CONFLICT,
                "site_domain_challenge_expired",
                format!(
                    "the ownership challenge for {hostname} has expired; re-bind the hostname \
                     to issue a fresh token"
                ),
                &ctx.request_id,
            )
            .await;
        }

        let record_name = challenge_record_name(&hostname);
        let expected = challenge_txt_value(
            &verification.tenant_id,
            &verification.hostname,
            &verification.challenge_token,
        );
        let resolver = SiteDomainResolverBackend::from_env().build_resolver();
        let outcome = resolve_challenge(&expected, resolver.lookup_txt(&record_name).await);

        let audit = |verdict: &'static str, detail: String| {
            state.record_admin_audit_event(admin_audit_event_draft_for_target(
                ctx,
                &auth,
                "site_domain.verify",
                &hostname,
                verdict,
                detail,
            ));
        };

        match outcome {
            ChallengeOutcome::ResolverUnavailable(reason) => {
                // Record the attempt, leave the STATE alone, and answer 503.
                verification.mark_check_failed(now, format!("resolver unavailable: {reason}"));
                if let Err(error) = state
                    .upsert_site_domain_verification(verification.clone())
                    .await
                {
                    tracing::warn!(
                        hostname = %hostname,
                        "failed to record a site-domain verification attempt: {error}"
                    );
                }
                audit(
                    "rejected",
                    format!("DNS resolver unavailable for {record_name}: {reason}"),
                );
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "dns_resolver_unavailable",
                    format!(
                        "could not resolve {record_name} ({} backend): {reason}. \
                         The domain remains unverified and does not serve.",
                        resolver.backend_name()
                    ),
                    &ctx.request_id,
                )
                .await
            }
            ChallengeOutcome::NotPublished(detail) => {
                verification.mark_check_failed(now, detail.clone());
                if let Err(error) = state
                    .upsert_site_domain_verification(verification.clone())
                    .await
                {
                    return storage_error(session, ctx, error.to_string()).await;
                }
                audit(
                    "rejected",
                    format!("ownership challenge for {hostname} not satisfied: {detail}"),
                );
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "site_domain_challenge_not_satisfied",
                    format!("publish TXT {record_name} = \"{expected}\" and retry: {detail}"),
                    &ctx.request_id,
                )
                .await
            }
            ChallengeOutcome::Verified => {
                // Ownership proven. Now (and only now) the hostname may become
                // servable and enter the ACME domain set. A hostname another
                // tenant has ALREADY proven still wins -- two live proofs for
                // one hostname are resolved first-proof-wins, not last-write.
                let existing = match state.get_site_domain(&hostname).await {
                    Ok(existing) => existing,
                    Err(error) => return storage_error(session, ctx, error.to_string()).await,
                };
                if let Some(existing) = existing.as_ref() {
                    if existing.tenant_id != tenant_id {
                        let holder_proven = match state
                            .get_site_domain_verification(&existing.tenant_id, &hostname)
                            .await
                        {
                            Ok(Some(holder)) => holder.serves(now),
                            Ok(None) => false,
                            Err(error) => {
                                return storage_error(session, ctx, error.to_string()).await
                            }
                        };
                        if holder_proven {
                            audit(
                                "rejected",
                                format!(
                                    "{hostname} is already bound by tenant {} with a verified \
                                     ownership proof",
                                    existing.tenant_id
                                ),
                            );
                            return write_json_error(
                                session,
                                StatusCode::CONFLICT,
                                "site_domain_conflict",
                                format!(
                                    "hostname {hostname} is bound by another tenant with a \
                                     verified DNS ownership proof"
                                ),
                                &ctx.request_id,
                            )
                            .await;
                        }
                    }
                }

                verification.mark_verified(now);
                if let Err(error) = state
                    .upsert_site_domain_verification(verification.clone())
                    .await
                {
                    return storage_error(session, ctx, error.to_string()).await;
                }
                let domain = StoredSiteDomain {
                    hostname: hostname.clone(),
                    tenant_id: tenant_id.clone(),
                    site: verification.site.clone(),
                    created_at_unix: existing
                        .as_ref()
                        .filter(|existing| existing.tenant_id == tenant_id)
                        .map_or(now, |existing| existing.created_at_unix),
                    updated_at_unix: now,
                };
                if let Err(error) = state.upsert_site_domain(domain.clone()).await {
                    return storage_error(session, ctx, error.to_string()).await;
                }
                let acme = self.refresh_acme_after_domain_change(&state, &hostname, true);
                audit(
                    "committed",
                    format!(
                        "DNS ownership of {hostname} verified for {tenant_id}/{} via TXT \
                         {record_name} ({} backend, acme_enabled={}, reload_triggered={})",
                        verification.site,
                        resolver.backend_name(),
                        acme.enabled,
                        acme.reload_triggered
                    ),
                );
                write_json_response(
                    session,
                    StatusCode::OK,
                    &AdminSiteDomainResponse {
                        object: "site_domain",
                        site_domain: admin_site_domain(&domain, Some(&verification), now),
                        acme,
                        verification: Some(AdminSiteDomainVerification::new(&verification, now)),
                    },
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_site_domain_unbind(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        raw_hostname: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };
        let hostname = crate::routing::normalize_host(raw_hostname);
        let binding = match state.get_site_domain(&hostname).await {
            Ok(Some(binding)) => binding,
            Ok(None) => return domain_not_found(session, ctx, &hostname).await,
            Err(error) => return storage_error(session, ctx, error.to_string()).await,
        };
        // Cross-tenant unbind reads as absent (fail closed, no existence leak).
        if authorize_tenant_scope(&auth, &binding.tenant_id).is_err() {
            return domain_not_found(session, ctx, &hostname).await;
        }
        match state.delete_site_domain(&hostname).await {
            Ok(true) => {
                // The ownership proof goes with the binding: a later re-bind
                // must re-prove control rather than inherit a stale proof.
                //
                // #488 review item 6: this used to be warn-only, so the
                // sentence above was a statement of intent that nothing
                // enforced. If the delete failed, the binding was gone and a
                // `verified` record survived, so the NEXT bind hit
                // `reusable_on_rebind` and the hostname was servable again
                // immediately with no re-proof -- evidence diverging from
                // intent, silently and unaudited, in the entity this issue
                // exists to make authoritative. It is now a 503: the unbind
                // has not happened, and the caller can retry.
                if let Err(error) = state
                    .delete_site_domain_verification(&binding.tenant_id, &hostname)
                    .await
                {
                    let message = error.to_string();
                    state.record_admin_audit_event(admin_audit_event_draft_for_target(
                        ctx,
                        &auth,
                        "site_domain.unbind",
                        &hostname,
                        "rejected",
                        format!(
                            "refusing to unbind {hostname}: the ownership proof could not be \
                             dropped, and leaving it behind would let a later re-bind inherit \
                             it without re-proving control ({message})"
                        ),
                    ));
                    return storage_error(session, ctx, message).await;
                }
                let acme = self.refresh_acme_after_domain_change(&state, &hostname, false);
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "site_domain.unbind",
                    &hostname,
                    "committed",
                    format!(
                        "custom domain {hostname} unbound from site {}/{} \
                         (acme_enabled={}, reload_triggered={})",
                        binding.tenant_id, binding.site, acme.enabled, acme.reload_triggered
                    ),
                ));
                write_json_response(
                    session,
                    StatusCode::OK,
                    &crate::responses::AdminDeleteResponse {
                        object: "site_domain",
                        id: hostname.clone(),
                        deleted: true,
                    },
                    &ctx.request_id,
                )
                .await
            }
            Ok(false) => domain_not_found(session, ctx, &hostname).await,
            Err(error) => storage_error(session, ctx, error.to_string()).await,
        }
    }

    /// Reports the ACME posture attached to a bind/unbind response without
    /// changing anything.
    fn site_domain_acme_state(&self, state: &crate::state::AppState) -> AdminSiteDomainAcme {
        AdminSiteDomainAcme {
            enabled: state.config.tls.acme.enabled,
            reload_triggered: false,
        }
    }

    /// Wires a runtime domain-set change into the existing ACME machinery
    /// (#265): marks the shared renewal status reload-required (surfaced on
    /// `/admin/status`) and, when `auto_graceful_reload` plus the graceful-
    /// upgrade plumbing are configured, triggers the SAME listener-level
    /// graceful upgrade a scheduled renewal uses. The replacement process
    /// re-reads the bindings at startup (gateway::serve merges them into the
    /// ACME domain set), issues the expanded/shrunk certificate through
    /// `ensure_certificate`, and takes over the listener -- no duplicate PKI
    /// path. Runs detached so the admin response is never blocked on the
    /// upgrade handoff.
    fn refresh_acme_after_domain_change(
        &self,
        state: &crate::state::AppState,
        hostname: &str,
        bound: bool,
    ) -> AdminSiteDomainAcme {
        let acme = &state.config.tls.acme;
        if !acme.enabled {
            return AdminSiteDomainAcme {
                enabled: false,
                reload_triggered: false,
            };
        }
        state.mark_acme_domains_changed(hostname, bound);

        let reliability = &state.config.reliability;
        let reload_possible = acme.auto_graceful_reload
            && reliability.graceful_upgrade_pid_file.is_some()
            && reliability.graceful_upgrade_sock.is_some()
            && self.state.source_path().is_some();
        if reload_possible {
            let reloader = super::GracefulUpgradeAcmeReloader {
                config: state.config.as_ref().clone(),
                source_path: self.state.source_path().cloned(),
            };
            let hostname = hostname.to_string();
            std::thread::spawn(move || {
                use crate::acme::AcmeCertificateReloader as _;
                if let Err(error) = reloader.reload() {
                    tracing::warn!(
                        hostname = %hostname,
                        "graceful ACME reload after site-domain change failed: {error}"
                    );
                }
            });
        }
        AdminSiteDomainAcme {
            enabled: true,
            reload_triggered: reload_possible,
        }
    }
}

#[derive(Debug, Deserialize)]
struct AdminSiteDomainMutation {
    hostname: Option<String>,
    tenant_id: Option<String>,
    site: Option<String>,
}

#[derive(Debug, Serialize)]
struct AdminSiteDomain {
    object: &'static str,
    hostname: String,
    tenant_id: String,
    site: String,
    /// The equivalent path-based serve prefix, for operator orientation.
    serve_path: String,
    /// The #488 ownership-proof state as of now, expiry applied.
    /// `no_verification` means no proof record exists at all -- which, like
    /// every non-live state, does NOT serve.
    verification_state: &'static str,
    /// Whether a request arriving on this hostname would actually be served.
    /// This is the single field an operator should read to answer "is my
    /// domain live?".
    serving: bool,
    created_at_unix: i64,
    updated_at_unix: i64,
}

#[derive(Debug, Serialize)]
struct AdminSiteDomainAcme {
    /// Whether the gateway's ACME issuance is enabled at all.
    enabled: bool,
    /// Whether this change triggered the listener-level graceful upgrade that
    /// re-issues the certificate with the updated domain set.
    reload_triggered: bool,
}

#[derive(Debug, Serialize)]
struct AdminSiteDomainResponse {
    object: &'static str,
    site_domain: AdminSiteDomain,
    acme: AdminSiteDomainAcme,
    /// The #488 ownership proof, including the exact TXT record to publish
    /// while the state is `pending_verification`. Absent only when the binding
    /// carries no proof record at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    verification: Option<AdminSiteDomainVerification>,
}

fn admin_site_domain(
    domain: &StoredSiteDomain,
    verification: Option<&StoredSiteDomainVerification>,
    now_unix: i64,
) -> AdminSiteDomain {
    AdminSiteDomain {
        object: "site_domain",
        hostname: domain.hostname.clone(),
        tenant_id: domain.tenant_id.clone(),
        site: domain.site.clone(),
        serve_path: format!("/sites/{}/{}/", domain.tenant_id, domain.site),
        verification_state: verification.map_or("no_verification", |record| {
            record.effective_state(now_unix).as_str()
        }),
        serving: verification.is_some_and(|record| record.serves(now_unix)),
        created_at_unix: domain.created_at_unix,
        updated_at_unix: domain.updated_at_unix,
    }
}

/// The three-way terminal of `POST /admin/v1/site-domains` (#530).
///
/// Extracted from the handler so the status set is enumerable by a test: the
/// OpenAPI document declared only 200/201 while the handler could also answer
/// **202**, and a generated client that switches on the declared set had no
/// branch for the one case that matters -- a 2xx meaning "recorded but NOT
/// serving".
///
/// * `202 Accepted` -- ownership unproven. The binding is recorded, the
///   hostname is deliberately kept OUT of the ACME order set (#488), and it
///   will not answer traffic until `POST .../{hostname}/verify` succeeds.
/// * `200 OK` -- an already-proven binding re-bound within the same tenant.
/// * `201 Created` -- a new binding whose ownership was already proven.
fn site_domain_bind_status(proven: bool, existing: bool) -> BindTerminal {
    bind_terminal::BindTerminal::select(proven, existing)
}

/// The bind handler's success status, constructible ONLY by
/// [`site_domain_bind_status`] (#530 review finding 3).
///
/// The first cut of this coupling was a test that called the selector directly
/// and compared its outputs against the OpenAPI document. That pinned a pure
/// function, not the handler: replacing the handler's
/// `let status = site_domain_bind_status(..)` with a literal
/// `StatusCode::NO_CONTENT` left the test green while the gateway answered an
/// undeclared 204 -- the sending-side/applying-side shape.
///
/// A newtype whose field cannot be reached from here makes that mutation a
/// COMPILE error instead of a silent pass: the bind response writer takes a
/// `BindTerminal`, and the only way to obtain one is to run the selector. A
/// test cannot substitute for this, because the property is "no other value
/// can reach the writer", which is a statement about every possible caller.
///
/// The FIRST attempt at this (#530 review round 2) put the newtype in THIS
/// module, next to the handler. Rust field privacy is module-scoped, so
/// `BindTerminal(StatusCode::NO_CONTENT)` was still in scope for the one
/// caller that matters and the mutation compiled clean -- the barrier was
/// documented but not built. It lives in a private submodule now, which is
/// what actually puts the constructor out of the handler's reach.
mod bind_terminal {
    use http::StatusCode;

    /// The bind handler's success status. The field is private to this
    /// module, so nothing in `site_domains` can build one except through
    /// [`BindTerminal::select`].
    pub(super) struct BindTerminal(StatusCode);

    impl BindTerminal {
        /// The three-way terminal. This is the ONLY constructor.
        pub(super) fn select(proven: bool, existing: bool) -> BindTerminal {
            BindTerminal(match (proven, existing) {
                (false, _) => StatusCode::ACCEPTED,
                (true, true) => StatusCode::OK,
                (true, false) => StatusCode::CREATED,
            })
        }

        pub(super) fn status(&self) -> StatusCode {
            self.0
        }
    }
}

use bind_terminal::BindTerminal;

/// Normalizes and validates a bind-request hostname: lowercase, no port, at
/// least two DNS labels of `[a-z0-9-]` (no leading/trailing hyphen), max 253
/// chars, and neither a wildcard nor an IP literal -- the shapes the existing
/// ACME HTTP-01/DNS-01 issuance can actually certify.
fn validate_site_domain_hostname(raw: Option<&str>) -> Result<String, String> {
    let raw = raw.map(str::trim).unwrap_or_default();
    if raw.is_empty() {
        return Err("hostname is required".to_string());
    }
    let hostname = crate::routing::normalize_host(raw);
    if hostname.len() > 253 {
        return Err(format!("hostname {hostname} exceeds 253 characters"));
    }
    if hostname.contains('*') {
        return Err("wildcard hostnames cannot be bound to a site".to_string());
    }
    if hostname.parse::<std::net::IpAddr>().is_ok() || raw.starts_with('[') {
        return Err("an IP address cannot be bound to a site".to_string());
    }
    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.len() < 2 {
        return Err(format!(
            "hostname {hostname} must be a fully qualified domain name"
        ));
    }
    for label in &labels {
        let valid = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !valid {
            return Err(format!("hostname {hostname} is not a valid DNS name"));
        }
    }
    Ok(hostname)
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    let query = query?;
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key && !value.is_empty()).then(|| value.to_string())
    })
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

async fn method_not_allowed(session: &mut Session, ctx: &ProxyContext) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "site domain endpoints support GET, POST, and DELETE",
        &ctx.request_id,
    )
    .await
}

async fn not_found(session: &mut Session, ctx: &ProxyContext) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::NOT_FOUND,
        "site_domain_endpoint_not_found",
        "site domain endpoint not found",
        &ctx.request_id,
    )
    .await
}

async fn domain_not_found(
    session: &mut Session,
    ctx: &ProxyContext,
    hostname: &str,
) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::NOT_FOUND,
        "site_domain_not_found",
        format!("no site domain binding for {hostname}"),
        &ctx.request_id,
    )
    .await
}

async fn storage_error(
    session: &mut Session,
    ctx: &ProxyContext,
    message: String,
) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::SERVICE_UNAVAILABLE,
        "storage_unavailable",
        message,
        &ctx.request_id,
    )
    .await
}

async fn write_auth_error(
    session: &mut Session,
    ctx: &ProxyContext,
    error: crate::auth::AuthError,
) -> PingoraResult<()> {
    write_json_error(
        session,
        error.status,
        error.code,
        error.message,
        &ctx.request_id,
    )
    .await
}

#[cfg(test)]
#[path = "site_domains_test.rs"]
mod site_domains_test;
