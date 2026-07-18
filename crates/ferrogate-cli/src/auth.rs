// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use blake2::{Blake2b512, Digest};
use http::{header, HeaderMap, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::{
    collections::HashSet,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{config::ApiKey, state::AppState};
use ferrogate_auth::ApiKeyAuthenticator;
use ferrogate_core::TenantContext;

/// Explicit "all scopes" marker. An operator-authored static config key (or
/// auth-disabled mode) that wants unrestricted access carries this instead of
/// relying on an empty scope list -- which, for durable/API-created keys, now
/// means "data-plane only, no admin".
pub(crate) const WILDCARD_SCOPE: &str = "*";

#[derive(Debug, Clone)]
pub(crate) struct AuthContext {
    #[allow(dead_code)]
    pub(crate) api_key_id: Option<String>,
    pub(crate) scopes: HashSet<String>,
    pub(crate) allowed_models: HashSet<String>,
    pub(crate) denied_models: HashSet<String>,
    pub(crate) allowed_providers: HashSet<String>,
    pub(crate) denied_providers: HashSet<String>,
    /// Region(s) this key's requests may route to (issue #173). Empty
    /// means unrestricted, mirroring `allowed_models`/`allowed_providers`.
    pub(crate) region_allowlist: HashSet<String>,
    pub(crate) monthly_token_budget: Option<u64>,
    pub(crate) request_limit_per_minute: Option<u64>,
    #[allow(dead_code)]
    pub(crate) organization_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) team_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) project_id: Option<String>,
    pub(crate) workspace_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) user_id: Option<String>,
    pub(crate) log_bodies: bool,
    pub(crate) rbac_subject: Option<ferrogate_auth::PolicySubject>,
    /// Resolved once per request in `finalize_auth`, merging every
    /// `quota_policies` scope in the tenant/project/workspace/key chain
    /// (P1-3). Model-allowlist and TPM checks that need the request body
    /// (unavailable at header-parse time) consult this instead of
    /// re-querying storage.
    pub(crate) effective_quota: ferrogate_policy::EffectiveQuota,
}

impl AuthContext {
    /// A privileged scope must always be granted explicitly (or via the `*`
    /// wildcard) -- it is NOT conferred by the "empty set means all data-plane
    /// scopes" convenience default. Today that is the `admin.*` family
    /// (admin.read/admin.write), the only non-data-plane scopes gated by
    /// `authenticate`.
    pub(crate) fn is_privileged_scope(scope: &str) -> bool {
        scope.starts_with("admin.")
    }

    pub(crate) fn has_scope(&self, scope: &str) -> bool {
        if self.scopes.contains(scope) {
            return true;
        }
        // An explicit `*` wildcard grants every scope, including `admin.*`. It
        // is set for operator-authored *static config* keys (and auth-disabled
        // mode) that historically used an EMPTY scope list to mean "all
        // access" -- that intent is preserved, just made explicit.
        if self.scopes.contains(WILDCARD_SCOPE) {
            return true;
        }
        // A residual empty scope set means a durable/API-created (virtual) key
        // minted without explicit scopes: it grants ordinary data-plane scopes
        // (the convenience default relied on by such keys) but NEVER a
        // privileged `admin.*` scope -- otherwise a tenant admin creating a
        // virtual key with no scopes would silently mint a full tenant-admin
        // credential (round-7 finding).
        self.scopes.is_empty() && !Self::is_privileged_scope(scope)
    }

    pub(crate) fn can_use_model(&self, model: &str) -> bool {
        !self.denied_models.contains(model)
            && (self.allowed_models.is_empty() || self.allowed_models.contains(model))
            && self.effective_quota.allows_model(model)
    }

    pub(crate) fn can_use_provider(&self, provider: &str) -> bool {
        !self.denied_providers.contains(provider)
            && (self.allowed_providers.is_empty() || self.allowed_providers.contains(provider))
    }

    pub(crate) fn tenant_context(&self) -> TenantContext {
        TenantContext {
            organization_id: self.organization_id.clone(),
            team_id: self.team_id.clone(),
            project_id: self.project_id.clone(),
            workspace_id: self.workspace_id.clone(),
            user_id: self.user_id.clone(),
            api_key_id: self.api_key_id.clone(),
        }
    }

    /// The per-minute request (RPM) rate-limit windows to enforce for this
    /// request. Returns BOTH the key's own `request_limit_per_minute` (TOK-12),
    /// always on the per-key counter, AND the resolved quota `rpm_limit` on its
    /// (possibly broader tenant/project/workspace) scope counter -- each as its
    /// own window, all of which the caller must satisfy. Empty when there is no
    /// API key or no RPM cap applies.
    ///
    /// Enforcing both (rather than collapsing to a single `min` counter) closes
    /// an aggregate-cap bypass: previously the broader scope only bound when its
    /// rpm was *strictly* tighter than the key's own limit, so a tenant could
    /// set every key's own limit to (or below) an operator's tenant/project/
    /// workspace cap and have each key counted per-key -- N keys => N x the
    /// aggregate cap. When the quota is itself Key-scoped, the two windows dedup
    /// onto one counter at the tighter limit, preserving per-key counting.
    pub(crate) fn request_windows(&self) -> Vec<(String, u64)> {
        let Some(api_key_id) = self.api_key_id.as_deref() else {
            return Vec::new();
        };
        // Matches QuotaScopeSelector::counter_key's Key branch exactly (same
        // `as_str` namespace), so the per-key window shares a counter with a
        // Key-scoped quota and can never collide with a broader-scope key.
        let per_key_counter = format!(
            "{}:{}",
            ferrogate_storage::QuotaScopeKind::Key.as_str(),
            api_key_id
        );
        let mut windows: Vec<(String, u64)> = Vec::new();
        let mut add = |counter_key: String, limit: u64| match windows
            .iter_mut()
            .find(|(key, _)| *key == counter_key)
        {
            Some(existing) => existing.1 = existing.1.min(limit),
            None => windows.push((counter_key, limit)),
        };
        if let Some(key_limit) = self.request_limit_per_minute {
            add(per_key_counter.clone(), key_limit);
        }
        if let Some(quota_limit) = self.effective_quota.rpm_limit {
            let counter_key = self
                .effective_quota
                .rpm_limit_scope
                .as_ref()
                .map(|scope| scope.counter_key(api_key_id))
                .unwrap_or_else(|| per_key_counter.clone());
            add(counter_key, quota_limit);
        }
        windows
    }

    /// The tokens-per-minute (TPM) rate-limit window for this request:
    /// `(counter_key, limit)`, or `None` when there is no API key or no TPM
    /// cap applies. TPM only comes from the quota chain (there is no per-key
    /// TOK-12 TPM), so the counter is keyed on the scope whose `tpm_limit`
    /// won the min -- aggregating a tenant/project/workspace cap across keys
    /// while a key-scoped cap stays per-key.
    pub(crate) fn tpm_window(&self) -> Option<(String, u64)> {
        let api_key_id = self.api_key_id.as_deref()?;
        let limit = self.effective_quota.tpm_limit?;
        let counter_key = self
            .effective_quota
            .tpm_limit_scope
            .as_ref()
            .map(|scope| scope.counter_key(api_key_id))
            .unwrap_or_else(|| api_key_id.to_string());
        Some((counter_key, limit))
    }

    pub(crate) fn can_record_bodies(&self, global_log_bodies: bool) -> bool {
        global_log_bodies && self.log_bodies
    }

    pub(crate) fn service_account_id(&self) -> Option<&str> {
        match self.rbac_subject.as_ref() {
            Some(ferrogate_auth::PolicySubject::ServiceAccount { service_account_id }) => {
                Some(service_account_id)
            }
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct AuthError {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

/// Denies cross-tenant access to a specific tenant's resource (issue
/// #185): `authenticate()` only ever checks *scope* (`admin.read`/
/// `admin.write`), never whether the caller's own tenant matches the
/// tenant the request actually targets. `provision_gateway_api_key`
/// (`ferrogate-auth`) mints an `admin.read`+`admin.write`-scoped key tied
/// to the logging-in user's own tenant on every admin-console login --
/// without this check, any tenant's console user could read and mutate
/// every *other* tenant's wallets, virtual keys, quota policies, and RBAC
/// bindings (confirmed live before this fix: a tenant-A-scoped key could
/// read AND financially adjust tenant B's wallet balance via `POST
/// /admin/v1/wallets/{other_tenant}/adjust`).
///
/// A platform-operator key (`organization_id: None` -- the "root/
/// bootstrap key manages every tenant" shape this codebase's entire test
/// suite already relies on, and the only way to legitimately administer
/// more than one tenant) is always allowed through unrestricted, exactly
/// as before this check existed. A tenant-scoped key (`organization_id:
/// Some(_)`) is denied whenever the resource it's trying to reach
/// belongs to a *different* tenant.
pub(crate) fn authorize_tenant_scope(
    auth: &AuthContext,
    target_tenant_id: &str,
) -> Result<(), AuthError> {
    match auth.organization_id.as_deref() {
        Some(caller_tenant_id) if caller_tenant_id != target_tenant_id => Err(AuthError {
            status: StatusCode::FORBIDDEN,
            code: "tenant_scope_denied",
            message: "API key is not authorized to access this tenant's resources".into(),
        }),
        _ => Ok(()),
    }
}

/// The list-endpoint counterpart to [`authorize_tenant_scope`] (issue
/// #185): rather than deny outright, a bulk `GET /admin/v1/<resource>`
/// listing narrows down to the caller's own tenant when the key is
/// tenant-scoped. A platform-operator key (no `organization_id`) sees
/// every row unfiltered, same as before this existed.
pub(crate) fn filter_by_tenant_scope<T>(
    auth: &AuthContext,
    rows: Vec<T>,
    tenant_id: impl Fn(&T) -> &str,
) -> Vec<T> {
    match auth.organization_id.as_deref() {
        Some(caller_tenant_id) => rows
            .into_iter()
            .filter(|row| tenant_id(row) == caller_tenant_id)
            .collect(),
        None => rows,
    }
}

/// The `QuotaScopeKind`-aware counterpart to [`authorize_tenant_scope`]
/// (issue #185): scopes that aren't already a bare tenant_id (project,
/// workspace, key) have to be resolved to their owning tenant first via a
/// storage lookup. Shared by `/admin/v1/quota-policies` and
/// `/admin/v1/usage-reports`, the two admin surfaces addressed by scope
/// kind. Fails closed: a tenant-scoped caller is denied both when the
/// resolved tenant differs from their own AND when resolution fails
/// entirely (the referenced project/workspace/key doesn't exist) --
/// "nonexistent means safe to touch" is explicitly the wrong default here.
pub(crate) async fn authorize_scoped_resource(
    state: &AppState,
    auth: &AuthContext,
    scope_type: ferrogate_storage::QuotaScopeKind,
    scope_id: &str,
) -> Result<(), AuthError> {
    use ferrogate_storage::QuotaScopeKind;
    let Some(caller_tenant_id) = auth.organization_id.as_deref() else {
        return Ok(());
    };
    let resolved_tenant_id = match scope_type {
        QuotaScopeKind::Tenant => Some(scope_id.to_string()),
        QuotaScopeKind::Project => state
            .get_project(scope_id)
            .await
            .ok()
            .flatten()
            .map(|project| project.tenant_id),
        QuotaScopeKind::Workspace => state
            .get_workspace(scope_id)
            .await
            .ok()
            .flatten()
            .map(|workspace| workspace.tenant_id),
        QuotaScopeKind::Key => state
            .get_virtual_api_key(scope_id)
            .await
            .ok()
            .flatten()
            .map(|key| key.tenant_id),
    };
    if resolved_tenant_id.as_deref() == Some(caller_tenant_id) {
        Ok(())
    } else {
        Err(AuthError {
            status: StatusCode::FORBIDDEN,
            code: "tenant_scope_denied",
            message: "API key is not authorized to access this tenant's resources".into(),
        })
    }
}

/// Forces a caller-suppliable tenant filter (e.g. the `?tenant=`/
/// `organization_id` query params accepted by the request-log, audit-event,
/// agent-run, and usage-aggregate admin read endpoints) to the caller's own
/// tenant when the caller is tenant-scoped (issue #185) -- otherwise a
/// tenant-scoped key could pass an explicit cross-tenant filter, or omit
/// the filter entirely, to read every tenant's logs/events. A
/// platform-operator key's requested filter passes through unchanged
/// (`None` legitimately means "show every tenant").
pub(crate) fn enforce_tenant_filter(
    auth: &AuthContext,
    requested: Option<String>,
) -> Option<String> {
    match auth.organization_id.as_ref() {
        Some(tenant_id) => Some(tenant_id.clone()),
        None => requested,
    }
}

/// Resolves and checks tenant ownership of a self-hosted worker by bare
/// `worker_id` (issue #186): every self-hosted-worker sub-handler (rotate,
/// heartbeat, telemetry event, artifact, checkpoint, and the single-worker
/// GET) looked the worker up only by id, with no tenant check -- letting a
/// tenant-scoped caller read or mutate (including rotating the identity
/// fingerprint, a takeover primitive) any other tenant's self-hosted
/// worker. Fails closed: if the worker can't be resolved at all, a
/// tenant-scoped caller is denied here rather than falling through to the
/// handler's own not-found path.
pub(crate) fn authorize_self_hosted_worker_scope(
    state: &AppState,
    auth: &AuthContext,
    worker_id: &str,
) -> Result<(), AuthError> {
    let Some(caller_tenant_id) = auth.organization_id.as_deref() else {
        return Ok(());
    };
    let resolved_tenant_id = state
        .self_hosted_worker_record(worker_id)
        .and_then(|record| record.tenant.organization_id);
    if resolved_tenant_id.as_deref() == Some(caller_tenant_id) {
        Ok(())
    } else {
        Err(AuthError {
            status: StatusCode::FORBIDDEN,
            code: "tenant_scope_denied",
            message: "API key is not authorized to access this tenant's resources".into(),
        })
    }
}

/// Denies a tenant-scoped key outright, regardless of which tenant it
/// belongs to (issue #186). `/admin/v1/api-keys*` manages the STATIC
/// config-file-level authentication list -- a caller can set `scopes` and
/// `organization_id` to anything in the request body (`api_key_from_mutation`),
/// so a tenant-scoped `admin.write` key could otherwise mint itself a brand
/// new key with `organization_id: null` and `scopes: ["admin.write"]`: a
/// full platform-operator credential that bypasses every tenant-scope
/// check in the system, not merely a cross-tenant read/write on one
/// resource. The admin-console frontend never calls this endpoint (its
/// key-management UI goes through the tenant-safe `/admin/v1/virtual-keys`
/// instead), so this is a dead capability for tenant-scoped keys, not a
/// designed one.
pub(crate) fn require_platform_operator(auth: &AuthContext) -> Result<(), AuthError> {
    if auth.organization_id.is_some() {
        return Err(AuthError {
            status: StatusCode::FORBIDDEN,
            code: "platform_operator_required",
            message: "this endpoint is restricted to platform-operator API keys".into(),
        });
    }
    Ok(())
}

pub(crate) fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
    request_id: &str,
) -> std::result::Result<AuthContext, AuthError> {
    if !state.auth_required() {
        return Ok(AuthContext {
            region_allowlist: HashSet::new(),
            api_key_id: None,
            // Auth disabled (zero-config): unrestricted access, carried as an
            // explicit wildcard so it survives the empty-set-is-not-admin rule.
            scopes: HashSet::from([WILDCARD_SCOPE.to_string()]),
            allowed_models: HashSet::new(),
            denied_models: HashSet::new(),
            allowed_providers: HashSet::new(),
            denied_providers: HashSet::new(),
            monthly_token_budget: None,
            request_limit_per_minute: None,
            organization_id: None,
            team_id: None,
            project_id: None,
            workspace_id: None,
            user_id: None,
            log_bodies: false,
            rbac_subject: None,
            effective_quota: ferrogate_policy::EffectiveQuota::default(),
        });
    }

    let Some(provided_key) = extract_api_key(headers) else {
        return Err(AuthError {
            status: StatusCode::UNAUTHORIZED,
            code: "missing_api_key",
            message: "missing API key; use Authorization: Bearer or x-api-key".into(),
        });
    };

    if state.config.auth_service.enabled {
        let auth = authenticate_external(state, &provided_key, required_scope, request_id)?;
        return finalize_auth(state, auth, request_id);
    }

    if let Some(auth) = authenticate_durable(state, &provided_key)? {
        if !auth.has_scope(required_scope) {
            return Err(AuthError {
                status: StatusCode::FORBIDDEN,
                code: "scope_denied",
                message: format!("API key does not have required scope {required_scope}"),
            });
        }
        return finalize_auth(state, auth, request_id);
    }

    for configured_key in &state.config.api_keys {
        if configured_key.matches_presented_key(&provided_key) {
            if !configured_key.enabled {
                return Err(AuthError {
                    status: StatusCode::FORBIDDEN,
                    code: "api_key_disabled",
                    message: "API key is disabled".into(),
                });
            }
            if configured_key.is_expired(now_unix_seconds()) {
                return Err(AuthError {
                    status: StatusCode::FORBIDDEN,
                    code: "api_key_expired",
                    message: "API key is expired".into(),
                });
            }
            if configured_key.monthly_token_budget == Some(0) {
                return Err(AuthError {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    code: "token_budget_exceeded",
                    message: "API key token budget is exhausted".into(),
                });
            }
            let auth = AuthContext {
                region_allowlist: configured_key.region_allowlist.iter().cloned().collect(),
                api_key_id: Some(configured_key.id.clone()),
                // A STATIC config key is operator-authored: an empty scope list
                // has always meant "all access" (including admin), so preserve
                // that intent as an explicit wildcard. Durable/virtual keys
                // (authenticate_durable) keep an empty set, which now grants
                // data-plane scopes only -- never admin.
                scopes: if configured_key.scopes.is_empty() {
                    HashSet::from([WILDCARD_SCOPE.to_string()])
                } else {
                    configured_key.scopes.iter().cloned().collect()
                },
                allowed_models: configured_key.allowed_models.iter().cloned().collect(),
                denied_models: configured_key.denied_models.iter().cloned().collect(),
                allowed_providers: configured_key.allowed_providers.iter().cloned().collect(),
                denied_providers: configured_key.denied_providers.iter().cloned().collect(),
                monthly_token_budget: configured_key.monthly_token_budget,
                request_limit_per_minute: configured_key.request_limit_per_minute,
                organization_id: configured_key.organization_id.clone(),
                team_id: configured_key.team_id.clone(),
                project_id: configured_key.project_id.clone(),
                workspace_id: configured_key.workspace_id.clone(),
                user_id: configured_key.user_id.clone(),
                log_bodies: configured_key.log_bodies.unwrap_or(false),
                rbac_subject: None,
                effective_quota: ferrogate_policy::EffectiveQuota::default(),
            };
            if !auth.has_scope(required_scope) {
                return Err(AuthError {
                    status: StatusCode::FORBIDDEN,
                    code: "scope_denied",
                    message: format!("API key does not have required scope {required_scope}"),
                });
            }
            return finalize_auth(state, auth, request_id);
        }
    }

    Err(AuthError {
        status: StatusCode::UNAUTHORIZED,
        code: "invalid_api_key",
        message: "invalid API key".into(),
    })
}

/// Resolve `presented_key` against the durable Supabase-backed virtual key
/// storage (`ferrogate-storage` / TOK-12). This is the primary key source;
/// the YAML `config.api_keys` loop above only runs as a compatibility
/// fallback when no durable key matches.
fn authenticate_durable(
    state: &AppState,
    provided_key: &str,
) -> std::result::Result<Option<AuthContext>, AuthError> {
    let Some(decision) = state
        .durable_api_key_authenticator()
        .authenticate(provided_key)
    else {
        return Ok(None);
    };
    if decision.monthly_token_budget == Some(0) {
        return Err(AuthError {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "token_budget_exceeded",
            message: "API key token budget is exhausted".into(),
        });
    }
    Ok(Some(AuthContext {
        // Durable/Supabase-backed keys don't carry a region allowlist yet
        // (issue #173's initial cut only wires it through the YAML
        // config.api_keys path) -- unrestricted here, not a silent
        // regression, since region enforcement is new and this path never
        // had it. Extending StoredApiKey/ApiKeyDecision with a
        // region_allowlist column is a straightforward follow-up.
        region_allowlist: HashSet::new(),
        api_key_id: decision.tenant.api_key_id.clone(),
        scopes: decision.scopes.into_iter().collect(),
        allowed_models: decision.allowed_models.into_iter().collect(),
        denied_models: HashSet::new(),
        allowed_providers: decision.allowed_providers.into_iter().collect(),
        denied_providers: HashSet::new(),
        monthly_token_budget: decision.monthly_token_budget,
        request_limit_per_minute: decision.request_limit_per_minute,
        organization_id: decision.tenant.organization_id,
        team_id: decision.tenant.team_id,
        project_id: decision.tenant.project_id,
        workspace_id: decision.tenant.workspace_id,
        user_id: decision.tenant.user_id,
        log_bodies: false,
        rbac_subject: None,
        effective_quota: ferrogate_policy::EffectiveQuota::default(),
    }))
}

/// Final, uniform governance step applied to every successfully identified
/// `AuthContext`, regardless of which auth source produced it (durable,
/// YAML, or external): resolve the multi-level `quota_policies` chain
/// (P1-3), fail closed on a disabled scope or a storage error, and enforce
/// one unified per-minute request budget that is the tighter of the key's
/// own `request_limit_per_minute` (TOK-12) and the resolved quota's
/// `rpm_limit` -- a single counter consumption per request either way.
fn finalize_auth(
    state: &AppState,
    mut auth: AuthContext,
    request_id: &str,
) -> std::result::Result<AuthContext, AuthError> {
    let quota = state
        .resolve_effective_quota(&auth.tenant_context())
        .map_err(|error| AuthError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "quota_resolution_unavailable",
            message: format!("quota policy lookup failed: {error}"),
        })?;
    // Assign the resolved quota now so the RPM/TPM/budget windows below can be
    // keyed on the scope that won each dimension's `min` (recorded on the
    // quota) rather than always on the api key.
    auth.effective_quota = quota;
    if let Some(denied_by) = auth.effective_quota.denied_by {
        return Err(AuthError {
            status: StatusCode::FORBIDDEN,
            code: "quota_scope_disabled",
            message: format!(
                "quota policy at scope {} disables this request's tenant/project/workspace/key chain",
                denied_by.as_str()
            ),
        });
    }
    if let Some(budget) = auth.effective_quota.monthly_budget_usd {
        // Enforce the budget against the winning scope's aggregate spend (so a
        // tenant/project/workspace budget holds across every key under it), not
        // the nearest attributed scope.
        let budget_scope = auth.effective_quota.monthly_budget_scope.clone();
        match state.monthly_budget_exceeded(&auth.tenant_context(), budget_scope.as_ref(), budget) {
            Ok(true) => {
                return Err(AuthError {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    code: "monthly_budget_exceeded",
                    message: "quota policy monthly budget has been exhausted for this scope".into(),
                });
            }
            Ok(false) => {}
            Err(error) => {
                return Err(AuthError {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    code: "quota_resolution_unavailable",
                    message: format!("monthly budget lookup failed: {error}"),
                });
            }
        }
    }
    // Prepaid-credit wallet balance (issue #169) -- distinct from and
    // enforced independently of the monthly_budget_usd check above: a
    // wallet tracks money actually paid, monthly_budget_usd is just a
    // configured throttle. Opt-in per tenant: `wallet_balance_exhausted`
    // returns false (never denies) when the tenant has no wallet row at
    // all, so this is purely additive for every tenant that hasn't
    // adopted prepaid billing.
    match state.wallet_balance_exhausted(&auth.tenant_context()) {
        Ok(true) => {
            return Err(AuthError {
                status: StatusCode::TOO_MANY_REQUESTS,
                code: "wallet_balance_exhausted",
                message: "prepaid credit balance has been exhausted for this tenant".into(),
            });
        }
        Ok(false) => {}
        Err(error) => {
            return Err(AuthError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "quota_resolution_unavailable",
                message: format!("wallet balance lookup failed: {error}"),
            });
        }
    }
    for (counter_key, limit) in auth.request_windows() {
        require_request_budget(state, &counter_key, limit, request_id)?;
    }
    Ok(auth)
}

fn require_request_budget(
    state: &AppState,
    counter_key: &str,
    limit: u64,
    request_id: &str,
) -> std::result::Result<(), AuthError> {
    match state.try_consume_api_key_request(counter_key, limit) {
        Ok(true) => Ok(()),
        Ok(false) => Err(AuthError {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limit_exceeded",
            message: format!("API key request rate limit is exhausted for request {request_id}"),
        }),
        Err(error) => Err(AuthError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "governance_counter_unavailable",
            message: format!("gateway counter backend is unavailable: {error}"),
        }),
    }
}

pub(crate) fn authorize_external_rbac(
    state: &AppState,
    auth: &AuthContext,
    action: &str,
    resource: &str,
) -> std::result::Result<(), AuthError> {
    if !state.config.auth_service.enabled {
        return Ok(());
    }
    let Some(subject) = auth.rbac_subject.clone() else {
        return Err(AuthError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "external_auth_unavailable",
            message: "external auth service did not return an RBAC subject".into(),
        });
    };
    let request = ferrogate_auth::AuthorizeRequest {
        tenant: auth.tenant_context(),
        subject,
        action: action.to_string(),
        resource: resource.to_string(),
    };
    let decision: ferrogate_auth::AuthorizationDecision =
        auth_service_post_json(state, "/v1/auth/authorize", &request)
            .map_err(external_authorize_error)?;
    if decision.allowed {
        return Ok(());
    }
    Err(AuthError {
        status: StatusCode::FORBIDDEN,
        code: "rbac_denied",
        message: format!(
            "external RBAC denied {action} on {resource}: {}",
            decision.reason
        ),
    })
}

fn authenticate_external(
    state: &AppState,
    provided_key: &str,
    required_scope: &str,
    request_id: &str,
) -> std::result::Result<AuthContext, AuthError> {
    let request = ferrogate_auth::ResolveApiKeyRequest {
        presented_key: provided_key.to_string(),
    };
    let decision: ferrogate_auth::AuthDecision =
        auth_service_post_json(state, "/v1/auth/resolve-api-key", &request)
            .map_err(|error| external_auth_error(error, request_id))?;
    let auth = AuthContext {
        region_allowlist: HashSet::new(),
        api_key_id: decision.tenant.api_key_id.clone(),
        scopes: decision.scopes.into_iter().collect(),
        allowed_models: decision.allowed_models.into_iter().collect(),
        denied_models: HashSet::new(),
        allowed_providers: decision.allowed_providers.into_iter().collect(),
        denied_providers: HashSet::new(),
        monthly_token_budget: decision.monthly_token_budget,
        request_limit_per_minute: decision.request_limit_per_minute,
        organization_id: decision.tenant.organization_id,
        team_id: decision.tenant.team_id,
        project_id: decision.tenant.project_id,
        workspace_id: decision.tenant.workspace_id,
        user_id: decision.tenant.user_id,
        log_bodies: false,
        rbac_subject: Some(decision.subject),
        effective_quota: ferrogate_policy::EffectiveQuota::default(),
    };
    if !external_scope_allows(&auth.scopes, required_scope) {
        return Err(AuthError {
            status: StatusCode::FORBIDDEN,
            code: "scope_denied",
            message: format!("API key does not have required scope {required_scope}"),
        });
    }
    Ok(auth)
}

fn external_scope_allows(scopes: &HashSet<String>, required_scope: &str) -> bool {
    scopes.contains(required_scope) || scopes.contains("*")
}

fn external_auth_error(error: AuthServiceClientError, request_id: &str) -> AuthError {
    match error {
        AuthServiceClientError::HttpStatus { status: 401, body } => AuthError {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_api_key",
            message: sanitize_auth_error_body(&body),
        },
        AuthServiceClientError::HttpStatus { status: 403, body } => AuthError {
            status: StatusCode::FORBIDDEN,
            code: "external_auth_denied",
            message: sanitize_auth_error_body(&body),
        },
        other => AuthError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "external_auth_unavailable",
            message: format!(
                "external auth service is unavailable for request {request_id}: {other}"
            ),
        },
    }
}

fn external_authorize_error(error: AuthServiceClientError) -> AuthError {
    match error {
        AuthServiceClientError::HttpStatus { status, body } if status == 401 || status == 403 => {
            AuthError {
                status: StatusCode::FORBIDDEN,
                code: "rbac_denied",
                message: sanitize_auth_error_body(&body),
            }
        }
        other => AuthError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "external_auth_unavailable",
            message: format!("external auth service authorization failed: {other}"),
        },
    }
}

fn sanitize_auth_error_body(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/error/message")
                .and_then(|message| message.as_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "external auth service rejected the request".into())
}

fn auth_service_post_json<T, R>(
    state: &AppState,
    path: &str,
    payload: &T,
) -> std::result::Result<R, AuthServiceClientError>
where
    T: serde::Serialize,
    R: DeserializeOwned,
{
    let body = serde_json::to_vec(payload)
        .map_err(|error| AuthServiceClientError::Request(error.to_string()))?;
    let endpoint = build_auth_service_target(&state.config.auth_service.endpoint, path)?;
    let timeout = Duration::from_millis(state.config.auth_service.timeout_millis);
    let attempts = state.config.auth_service.max_retries.saturating_add(1);
    let backoff = Duration::from_millis(state.config.auth_service.retry_backoff_millis);
    let mut last_retryable_error = None;
    for attempt in 0..attempts {
        match auth_service_post_json_once(&endpoint, &body, timeout) {
            Ok(response) => return Ok(response),
            Err(error) if error.is_retryable() && attempt + 1 < attempts => {
                last_retryable_error = Some(error);
                std::thread::sleep(backoff);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_retryable_error.unwrap_or_else(|| {
        AuthServiceClientError::Transport("auth service retry budget exhausted".into())
    }))
}

fn auth_service_post_json_once<R: DeserializeOwned>(
    endpoint: &AuthServiceTarget,
    body: &[u8],
    timeout: Duration,
) -> std::result::Result<R, AuthServiceClientError> {
    let address = endpoint
        .host_port
        .to_socket_addrs()
        .map_err(|error| AuthServiceClientError::Transport(error.to_string()))?
        .next()
        .ok_or_else(|| {
            AuthServiceClientError::Transport("auth service host resolved no addresses".into())
        })?;
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| AuthServiceClientError::Transport(error.to_string()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| AuthServiceClientError::Transport(error.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| AuthServiceClientError::Transport(error.to_string()))?;
    write!(
        stream,
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        endpoint.path,
        endpoint.host_port,
        body.len()
    )
    .map_err(|error| AuthServiceClientError::Transport(error.to_string()))?;
    stream
        .write_all(body)
        .map_err(|error| AuthServiceClientError::Transport(error.to_string()))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| AuthServiceClientError::Transport(error.to_string()))?;
    parse_auth_service_response(&response)
}

fn parse_auth_service_response<R: DeserializeOwned>(
    response: &[u8],
) -> std::result::Result<R, AuthServiceClientError> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| AuthServiceClientError::Response("missing HTTP header terminator".into()))?;
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| AuthServiceClientError::Response("missing HTTP status".into()))?;
    let body = String::from_utf8_lossy(&response[header_end + 4..]).into_owned();
    if !(200..300).contains(&status) {
        return Err(AuthServiceClientError::HttpStatus { status, body });
    }
    serde_json::from_str(&body).map_err(|error| AuthServiceClientError::Response(error.to_string()))
}

fn build_auth_service_target(
    endpoint: &str,
    path: &str,
) -> std::result::Result<AuthServiceTarget, AuthServiceClientError> {
    let trimmed = endpoint.trim().trim_end_matches('/');
    let rest = trimmed.strip_prefix("http://").ok_or_else(|| {
        AuthServiceClientError::Request("auth service endpoint must use http://".into())
    })?;
    let (host_port, base_path) = rest.split_once('/').unwrap_or((rest, ""));
    if host_port.trim().is_empty() {
        return Err(AuthServiceClientError::Request(
            "auth service endpoint host is empty".into(),
        ));
    }
    let path = if base_path.is_empty() {
        path.to_string()
    } else {
        format!(
            "/{}/{}",
            base_path.trim_matches('/'),
            path.trim_start_matches('/')
        )
    };
    Ok(AuthServiceTarget {
        host_port: host_port.to_string(),
        path,
    })
}

#[derive(Debug)]
struct AuthServiceTarget {
    host_port: String,
    path: String,
}

#[derive(Debug)]
enum AuthServiceClientError {
    Request(String),
    Transport(String),
    Response(String),
    HttpStatus { status: u16, body: String },
}

impl AuthServiceClientError {
    fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Transport(_)
                | Self::HttpStatus {
                    status: 500..=599,
                    ..
                }
        )
    }
}

impl std::fmt::Display for AuthServiceClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(message) => write!(formatter, "{message}"),
            Self::Transport(message) => write!(formatter, "{message}"),
            Self::Response(message) => write!(formatter, "{message}"),
            Self::HttpStatus { status, body } => {
                let summary = serde_json::from_str::<serde_json::Value>(body)
                    .unwrap_or_else(|_| json!({ "body": body }));
                write!(formatter, "auth service returned HTTP {status}: {summary}")
            }
        }
    }
}

impl ApiKey {
    fn matches_presented_key(&self, presented_key: &str) -> bool {
        if let Some(secret) = self.secret_value() {
            if constant_time_eq(presented_key.as_bytes(), secret.as_bytes()) {
                return true;
            }
        }
        self.key_hash
            .as_deref()
            .is_some_and(|hash| verify_api_key_secret(presented_key, hash))
    }

    fn secret_value(&self) -> Option<String> {
        if let Some(env_name) = &self.key_env {
            if let Ok(value) = std::env::var(env_name) {
                return Some(value);
            }
        }
        self.key.clone()
    }

    fn is_expired(&self, now_unix_seconds: u64) -> bool {
        self.expires_at_unix
            .is_some_and(|expires_at| expires_at <= now_unix_seconds)
    }
}

pub(crate) fn hash_api_key_secret(secret: &str) -> String {
    let digest = Blake2b512::digest(secret.as_bytes());
    format!("blake2b:{}", encode_hex(&digest))
}

fn verify_api_key_secret(secret: &str, expected_hash: &str) -> bool {
    constant_time_eq(
        hash_api_key_secret(secret).as_bytes(),
        expected_hash.as_bytes(),
    )
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
    {
        if !value.trim().is_empty() {
            return Some(value.trim().to_string());
        }
    }

    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
#[path = "auth_test.rs"]
mod auth_test;
