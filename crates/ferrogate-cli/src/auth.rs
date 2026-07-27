// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The request-admission pipeline: turning a presented credential into an
//! authorized [`AuthContext`], and the two authorizers that have to read the
//! control plane to answer.
//!
//! #553 stage 3b-0 moved the other half of this file --- the authorization
//! vocabulary, the credential primitives and the external auth-service client
//! --- into [`ferrogate_gateway::auth`], because none of it touched
//! [`AppState`]. What is left is everything that does. Between them the
//! functions below reach twelve distinct `AppState` accessors: the credential
//! sources (`auth_required`, `config.auth_service`, `config.tenancy`,
//! `config.api_keys`, `durable_api_key_authenticator`), the governance calls
//! (`require_usable_tenancy`, `resolve_effective_quota`,
//! `monthly_budget_exceeded`, `wallet_balance_exhausted`,
//! `try_consume_api_key_request`) and three control-plane lookups
//! (`get_project`/`get_workspace`/`get_virtual_api_key`,
//! `self_hosted_worker_record`).
//!
//! That is `AppState` itself, not a seam a small trait could invert, so this
//! module travels with the stage-3b trunk rather than ahead of it. It keeps the
//! name `auth` deliberately: renaming it now would churn every remaining call
//! site for a module that is about to be merged back into
//! `ferrogate_gateway::auth` when `AppState` lands there.

use http::{HeaderMap, StatusCode};
use std::collections::HashSet;

use crate::state::AppState;
use ferrogate_auth::ApiKeyAuthenticator;
use ferrogate_gateway::auth::{
    api_key_is_expired, api_key_matches_presented_key, authenticate_external, extract_api_key,
    now_unix_seconds, resolve_platform_operator, AuthContext, AuthError, CallerScope,
    WILDCARD_SCOPE,
};

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
    let CallerScope::Tenant(caller_tenant_id) = auth.caller_scope() else {
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
    let CallerScope::Tenant(caller_tenant_id) = auth.caller_scope() else {
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
pub(crate) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
    request_id: &str,
) -> std::result::Result<AuthContext, AuthError> {
    authenticate_with_admission(
        state,
        headers,
        required_scope,
        request_id,
        LifecycleAdmission::Strict,
    )
    .await
}

/// [`authenticate`] for the handful of routes that exist to turn an off
/// hierarchy back ON: the lifecycle `status` PUT/PATCH on a tenant account,
/// project or workspace (issue #514, finding 5).
///
/// The #514 request-time gate runs inside `finalize_auth`, i.e. BEFORE any
/// handler body, and the admin console's own key is tenant-scoped. So a tenant
/// that used its self-service `disabled` switch on the project its session key
/// is scoped to was refused at `authenticate()` and could never reach the PUT
/// that reverses it: a one-way door out of a reversible state, undoable only by
/// a platform operator. These routes therefore run the
/// [`LifecycleSeam::Recovery`] variant of the same gate, which admits
/// `disabled` and nothing else -- `suspended`/`deleted` remain platform actions
/// that a tenant cannot self-serve out of.
///
/// This is the narrower of the two ways to close finding 5. The alternative --
/// dropping `disabled` from the request-time deny set entirely -- would let a
/// disabled project keep serving `/v1/chat/completions`, which is the whole
/// point of the switch. Scoping the carve-out to the reversal routes keeps the
/// switch real and keeps it reversible.
pub(crate) async fn authenticate_for_lifecycle_recovery(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
    request_id: &str,
) -> std::result::Result<AuthContext, AuthError> {
    authenticate_with_admission(
        state,
        headers,
        required_scope,
        request_id,
        LifecycleAdmission::Recovery,
    )
    .await
}

/// Which #514 request-time seam this authentication runs. Carried as a
/// parameter rather than derived from the route inside `finalize_auth` because
/// `finalize_auth` is reached from every auth source and knows nothing about
/// routing; the three recovery routes opt in explicitly at their call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LifecycleAdmission {
    /// Every ordinary route: `suspended`, `disabled` and `deleted` all deny.
    Strict,
    /// A lifecycle-status reversal route: `disabled` is admitted so the state
    /// is not a one-way door. See [`authenticate_for_lifecycle_recovery`].
    Recovery,
}

impl LifecycleAdmission {
    fn seam(self) -> ferrogate_storage::LifecycleSeam {
        match self {
            Self::Strict => ferrogate_storage::LifecycleSeam::Request,
            Self::Recovery => ferrogate_storage::LifecycleSeam::Recovery,
        }
    }
}

async fn authenticate_with_admission(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
    request_id: &str,
    admission: LifecycleAdmission,
) -> std::result::Result<AuthContext, AuthError> {
    // #542: this branch grants platform root to a caller who presented nothing,
    // so what opens it matters more than what it does. It is now reached only
    // when the operator wrote `[auth] disabled = true` -- a named, deliberate
    // "this gateway is open" -- and never again because a section was left out.
    // `auth_required()` no longer counts credentials, so a deployment whose keys
    // live in the control plane rather than in `[[api_keys]]` does not fall in
    // here, and the durable authenticator below actually runs.
    if !state.auth_required() {
        return Ok(AuthContext {
            region_allowlist: HashSet::new(),
            api_key_id: None,
            // Auth disabled by name: unrestricted access, carried as an
            // explicit wildcard so it survives the empty-set-is-not-admin rule.
            scopes: HashSet::from([WILDCARD_SCOPE.to_string()]),
            allowed_models: HashSet::new(),
            denied_models: HashSet::new(),
            allowed_providers: HashSet::new(),
            denied_providers: HashSet::new(),
            monthly_token_budget: None,
            request_limit_per_minute: None,
            organization_id: None,
            // Auth is switched off: there is no credential to scope, and the
            // whole mode is "unrestricted access". #515 only requires that root
            // be *stated*, and this states it, in code, at the one place that
            // decided it.
            platform_operator: true,
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
        let auth = authenticate_external(
            &state.config.auth_service,
            state.config.tenancy.implicit_platform_operator,
            &provided_key,
            required_scope,
            request_id,
        )?;
        return finalize_auth(state, auth, request_id, admission).await;
    }

    if let Some(auth) = authenticate_durable(state, &provided_key)? {
        if !auth.has_scope(required_scope) {
            return Err(AuthError {
                status: StatusCode::FORBIDDEN,
                code: "scope_denied",
                message: format!("API key does not have required scope {required_scope}"),
            });
        }
        return finalize_auth(state, auth, request_id, admission).await;
    }

    for configured_key in &state.config.api_keys {
        if api_key_matches_presented_key(configured_key, &provided_key) {
            if !configured_key.enabled {
                return Err(AuthError {
                    status: StatusCode::FORBIDDEN,
                    code: "api_key_disabled",
                    message: "API key is disabled".into(),
                });
            }
            if api_key_is_expired(configured_key, now_unix_seconds()) {
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
                // #515: the static-config path used to copy `organization_id`
                // verbatim and let its absence *become* platform root further
                // downstream. The classification is made here instead, from
                // what the key declares.
                platform_operator: resolve_platform_operator(
                    state.config.tenancy.implicit_platform_operator,
                    configured_key.platform_operator,
                    configured_key.organization_id.as_deref(),
                ),
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
            return finalize_auth(state, auth, request_id, admission).await;
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
        // #515: a durable/virtual key is minted under a tenant
        // (`ferrogate_auth::api_key` sets `organization_id = Some(tenant_id)`),
        // so it is always tenant-scoped and there is no way to *declare* root
        // over this path. The same resolver still runs so the compatibility
        // switch has exactly one meaning across every auth source.
        platform_operator: resolve_platform_operator(
            state.config.tenancy.implicit_platform_operator,
            None,
            decision.tenant.organization_id.as_deref(),
        ),
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
async fn finalize_auth(
    state: &AppState,
    mut auth: AuthContext,
    request_id: &str,
    admission: LifecycleAdmission,
) -> std::result::Result<AuthContext, AuthError> {
    // #515, the identity seam. Every auth source funnels through here, so this
    // is the one place that can guarantee no request is ever served by a
    // credential whose tenant-isolation identity is unknown.
    //
    // A credential is unclassified when it names no tenant AND never declared
    // `platform_operator` -- historically the shape that silently became
    // platform root. It is refused here (not downgraded to "tenant with no
    // rows") precisely because a credential whose blast radius is ambiguous
    // must not serve traffic at all: `organization_id` is also the attribution
    // key for quota, metering and lifecycle, so an unscoped identity is wrong
    // on the data plane too, not just on admin routes.
    //
    // Reachable only when an operator has set `[tenancy]
    // implicit_platform_operator = false`; under the (deprecated) legacy
    // default such a credential is classified as an operator, exactly as
    // before #515, and this never fires.
    if !auth.platform_operator && auth.organization_id.is_none() {
        return Err(AuthError {
            status: StatusCode::FORBIDDEN,
            code: "tenant_identity_required",
            message: "API key declares neither an organization_id nor platform_operator = true, \
                      so it has no tenant identity to authorize against"
                .into(),
        });
    }
    // #514, the request-time seam. This is the ONE place it lives: every auth
    // source (durable/virtual, YAML config, external auth service) funnels
    // through `finalize_auth`, so a suspended tenant's pre-existing keys stop
    // serving traffic no matter which credential path identified them and no
    // matter which handler is being called. Running it FIRST is deliberate: a
    // suspended tenant must not even reach quota/wallet resolution, which is
    // where spend is authorized.
    //
    // Platform-operator keys carry no `organization_id`/`project_id`/
    // `workspace_id`, so the chain is empty and this is a no-op for them --
    // which is exactly what keeps un-suspending a tenant possible.
    //
    // The chain is WALKED, not read off the credential: the ids below are what
    // the key DECLARES, and `organization_id` is optional on a native api-key,
    // so a key naming only a project would otherwise be checked against a
    // one-row chain with its (suspended) tenant never read. See
    // `ferrogate_storage::resolve_lifecycle_chain`.
    //
    // `admission` selects the seam: `Recovery` (the lifecycle-status PUT/PATCH
    // routes) admits `disabled` so a tenant's own off switch is reversible.
    state
        .require_usable_tenancy(
            admission.seam(),
            ferrogate_storage::TenancyRefs::new(
                auth.organization_id.as_deref(),
                auth.project_id.as_deref(),
                auth.workspace_id.as_deref(),
            ),
        )
        .await?;
    let quota = state
        .resolve_effective_quota(&auth.tenant_context())
        .await
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
        match state
            .monthly_budget_exceeded(&auth.tenant_context(), budget_scope.as_ref(), budget)
            .await
        {
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
    match state.wallet_balance_exhausted(&auth.tenant_context()).await {
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

#[cfg(test)]
#[path = "auth_test.rs"]
mod auth_test;
