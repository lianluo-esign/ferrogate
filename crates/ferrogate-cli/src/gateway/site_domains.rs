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

use std::time::{SystemTime, UNIX_EPOCH};

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::{Deserialize, Serialize};

use ferrogate_storage::StoredSiteDomain;

use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::route_groups::RequestParts;
use super::{FerroGateway, ProxyContext};
use crate::{
    auth::{authenticate, authorize_tenant_scope, enforce_tenant_filter},
    responses::{write_json_error, write_json_error_and_close, write_json_response, AdminList},
};

const MAX_BODY_BYTES: usize = 16 * 1024;

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
    /// the collection, get/unbind on `/{hostname}`.
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
            .filter(|rest| !rest.is_empty() && !rest.contains('/'))
        else {
            return not_found(session, ctx).await;
        };
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
        let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };
        // A tenant-scoped key is pinned to its own tenant; a platform operator
        // may narrow to a `?tenant=` filter or see every tenant's bindings.
        let requested_tenant =
            query_param(query, "tenant").or_else(|| query_param(query, "tenant_id"));
        let tenant = enforce_tenant_filter(&auth, requested_tenant);
        match state.list_site_domains(tenant.as_deref()).await {
            Ok(domains) => {
                let data = domains.iter().map(admin_site_domain).collect();
                write_json_response(
                    session,
                    StatusCode::OK,
                    &AdminList::new(data),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => storage_error(session, ctx, error.to_string()).await,
        }
    }

    async fn handle_admin_site_domain_get(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        raw_hostname: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id) {
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
        write_json_response(
            session,
            StatusCode::OK,
            &AdminSiteDomainResponse {
                object: "site_domain",
                site_domain: admin_site_domain(&binding),
                acme: self.site_domain_acme_state(&state),
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
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => return write_auth_error(session, ctx, error).await,
        };

        let body = match read_request_body(session, MAX_BODY_BYTES).await? {
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
        // tenant is an update; a hostname held by ANOTHER tenant is a
        // conflict (never silently stolen).
        let existing = match state.get_site_domain(&hostname).await {
            Ok(existing) => existing,
            Err(error) => return storage_error(session, ctx, error.to_string()).await,
        };
        if let Some(existing) = existing.as_ref() {
            if existing.tenant_id != tenant_id {
                let message = reject(format!("hostname {hostname} is already bound"));
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

        let now = now_unix_seconds();
        let domain = StoredSiteDomain {
            hostname: hostname.clone(),
            tenant_id: tenant_id.clone(),
            site: site.clone(),
            created_at_unix: existing
                .as_ref()
                .map_or(now, |existing| existing.created_at_unix),
            updated_at_unix: now,
        };
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

        let acme = self.refresh_acme_after_domain_change(&state, &hostname, true);
        state.record_admin_audit_event(admin_audit_event_draft_for_target(
            ctx,
            &auth,
            "site_domain.bind",
            &hostname,
            "committed",
            format!(
                "custom domain {hostname} bound to site {tenant_id}/{site} \
                 (acme_enabled={}, reload_triggered={})",
                acme.enabled, acme.reload_triggered
            ),
        ));
        write_json_response(
            session,
            if existing.is_some() {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            &AdminSiteDomainResponse {
                object: "site_domain",
                site_domain: admin_site_domain(&domain),
                acme,
            },
            &ctx.request_id,
        )
        .await
    }

    async fn handle_admin_site_domain_unbind(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        raw_hostname: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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
}

fn admin_site_domain(domain: &StoredSiteDomain) -> AdminSiteDomain {
    AdminSiteDomain {
        object: "site_domain",
        hostname: domain.hostname.clone(),
        tenant_id: domain.tenant_id.clone(),
        site: domain.site.clone(),
        serve_path: format!("/sites/{}/{}/", domain.tenant_id, domain.site),
        created_at_unix: domain.created_at_unix,
        updated_at_unix: domain.updated_at_unix,
    }
}

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
