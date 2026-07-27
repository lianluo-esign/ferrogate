// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway -- the authorization
// vocabulary, the credential primitives and the external auth-service client,
// extracted out of ferrogate-cli (issue #553 stage 3b-0).

//! What a caller IS and what it may DO -- and nothing about how a request is
//! admitted.
//!
//! This module is the half of `ferrogate-cli`'s former `auth.rs` that never
//! touched `AppState`. Three groups live here, and the split between them is
//! the natural next one if this file ever needs dividing again:
//!
//! 1. **The authorization vocabulary.** [`AuthContext`], [`CallerScope`],
//!    [`AuthError`], and the five deciders that read them --
//!    [`authorize_tenant_scope`], [`filter_by_tenant_scope`],
//!    [`enforce_tenant_filter`], [`require_platform_operator`] and
//!    [`resolve_platform_operator`]. This is issue #515's answer to "which
//!    tenant is this caller, and is it root?", and it is the reason the module
//!    could move: every one of these is a pure function of the credential.
//! 2. **Credential primitives.** Presented-key extraction, the Blake2b secret
//!    hash and its constant-time comparison, and the static-config-key match
//!    and expiry predicates.
//! 3. **The external auth-service client**, plus the standalone admin-api
//!    service's own fail-closed gate ([`authenticate_admin_gate`]), which was
//!    already written against plain config values rather than against state.
//!
//! # What deliberately did NOT come with it
//!
//! `authenticate()`, `authenticate_for_lifecycle_recovery()`,
//! `finalize_auth()`, `authenticate_durable()`, `authorize_scoped_resource()`
//! and `authorize_self_hosted_worker_scope()` stay in `ferrogate-cli`. They are
//! not vocabulary; they are the request-admission pipeline, and between them
//! they reach twelve distinct `AppState` accessors -- the credential sources
//! (`auth_required`, `config.auth_service`, `config.tenancy`, `config.api_keys`,
//! `durable_api_key_authenticator`), the governance calls
//! (`require_usable_tenancy`, `resolve_effective_quota`,
//! `monthly_budget_exceeded`, `wallet_balance_exhausted`,
//! `try_consume_api_key_request`) and three control-plane lookups
//! (`get_project`/`get_workspace`/`get_virtual_api_key`,
//! `self_hosted_worker_record`). That is not a dependency a small trait
//! inverts; it is `AppState` itself, which arrives here with the stage-3b
//! trunk. Inventing a host trait for it now would put dynamic dispatch on the
//! per-request authentication path to buy an abstraction with exactly one
//! implementor that stage 3b would immediately delete.
//!
//! The same test applies to the tests. The old `auth_test.rs` had 39 cases; 27
//! stayed in `ferrogate-cli` (23 of them build an `AppState`, 4 drive
//! `Config::validate`) because what they cover stayed, and the 12 that need
//! nothing but a credential came here with it. Nothing in this file is covered
//! from the crate it was extracted from -- the standard this crate's `lib.rs`
//! already states, and the reason a whole-file move of `auth.rs` was not on the
//! table.

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

use ferrogate_auth::ApiKeyAuthenticator;
use ferrogate_config::ApiKey;
use ferrogate_core::TenantContext;

/// Explicit "all scopes" marker. An operator-authored static config key (or
/// auth-disabled mode) that wants unrestricted access carries this instead of
/// relying on an empty scope list -- which, for durable/API-created keys, now
/// means "data-plane only, no admin".
pub const WILDCARD_SCOPE: &str = "*";

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub api_key_id: Option<String>,
    pub scopes: HashSet<String>,
    pub allowed_models: HashSet<String>,
    pub denied_models: HashSet<String>,
    pub allowed_providers: HashSet<String>,
    pub denied_providers: HashSet<String>,
    /// Region(s) this key's requests may route to (issue #173). Empty
    /// means unrestricted, mirroring `allowed_models`/`allowed_providers`.
    pub region_allowlist: HashSet<String>,
    pub monthly_token_budget: Option<u64>,
    pub request_limit_per_minute: Option<u64>,
    /// The tenant this credential speaks for -- a `tenants.id`, not free-form
    /// attribution. Read as an authorization identity by every function in the
    /// [`CallerScope`] block below, and as an attribution scope by quota,
    /// metering and lifecycle. `None` is meaningful ONLY together with
    /// [`Self::platform_operator`]; see [`AuthContext::caller_scope`].
    pub organization_id: Option<String>,
    /// Whether this credential holds the unrestricted, cross-tenant
    /// platform-root identity (issue #515). Resolved exactly once per request,
    /// by [`resolve_platform_operator`], from what the credential *declares* --
    /// never re-derived downstream from `organization_id.is_none()`, which is
    /// how "an omitted field" came to mean "root" in the first place.
    pub platform_operator: bool,
    pub team_id: Option<String>,
    pub project_id: Option<String>,
    pub workspace_id: Option<String>,
    pub user_id: Option<String>,
    pub log_bodies: bool,
    pub rbac_subject: Option<ferrogate_auth::PolicySubject>,
    /// Resolved once per request in `finalize_auth`, merging every
    /// `quota_policies` scope in the tenant/project/workspace/key chain
    /// (P1-3). Model-allowlist and TPM checks that need the request body
    /// (unavailable at header-parse time) consult this instead of
    /// re-querying storage.
    pub effective_quota: ferrogate_policy::EffectiveQuota,
}

impl AuthContext {
    /// A privileged scope must always be granted explicitly (or via the `*`
    /// wildcard) -- it is NOT conferred by the "empty set means all data-plane
    /// scopes" convenience default. Today that is the `admin.*` family
    /// (admin.read/admin.write), the only non-data-plane scopes gated by
    /// `authenticate`.
    pub fn is_privileged_scope(scope: &str) -> bool {
        scope.starts_with("admin.")
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        scope_set_allows(&self.scopes, scope)
    }

    pub fn can_use_model(&self, model: &str) -> bool {
        !self.denied_models.contains(model)
            && (self.allowed_models.is_empty() || self.allowed_models.contains(model))
            && self.effective_quota.allows_model(model)
    }

    pub fn can_use_provider(&self, provider: &str) -> bool {
        !self.denied_providers.contains(provider)
            && (self.allowed_providers.is_empty() || self.allowed_providers.contains(provider))
    }

    pub fn tenant_context(&self) -> TenantContext {
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
    pub fn request_windows(&self) -> Vec<(String, u64)> {
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
    pub fn tpm_window(&self) -> Option<(String, u64)> {
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

    pub fn can_record_bodies(&self, global_log_bodies: bool) -> bool {
        global_log_bodies && self.log_bodies
    }

    /// The caller's tenant-isolation identity (issue #515). This is the ONE
    /// place `organization_id` is turned into an authorization answer, so
    /// "which tenant is this?" and "is this root?" can never be spelled two
    /// different ways at two different call sites again.
    pub fn caller_scope(&self) -> CallerScope<'_> {
        if self.platform_operator {
            return CallerScope::PlatformOperator;
        }
        // Defence in depth. A credential that declares neither a tenant nor
        // platform-root is refused in `finalize_auth`, so this branch is
        // unreachable for anything that actually authenticated. If one ever
        // does reach here (a hand-built context in a test, a future auth
        // source that forgets the classification), it must NOT fall into the
        // platform-root branch: it gets a tenant id that no `tenants.id` can
        // equal, which denies every cross-tenant check and filters every
        // listing to nothing.
        CallerScope::Tenant(
            self.organization_id
                .as_deref()
                .unwrap_or(UNSCOPED_TENANT_ID),
        )
    }

    /// True only for a credential that *declared* platform-root, never for one
    /// that merely omitted its tenant.
    pub fn is_platform_operator(&self) -> bool {
        matches!(self.caller_scope(), CallerScope::PlatformOperator)
    }

    /// The tenant narrowing to hand a storage query whose `Option<&str>` tenant
    /// argument treats `None` as "every tenant" -- the shape used by every
    /// paged admin read (request logs, audit events, metering, usage
    /// aggregates, worker records/sessions, observed activity, cost burn) and
    /// by the control-plane overview aggregate.
    ///
    /// This is [`Self::caller_scope`] rendered into that argument, and it is
    /// the reason those call sites must never pass `organization_id` straight
    /// through: `auth.organization_id.as_deref()` collapses "declared platform
    /// root" and "declared nothing at all" into the same `None`, i.e. into the
    /// cross-tenant view. Here only a declared operator gets `None`; anything
    /// else is pinned to its own tenant id, and an unclassified credential is
    /// pinned to [`UNSCOPED_TENANT_ID`], which matches no row.
    pub fn tenant_filter(&self) -> Option<&str> {
        match self.caller_scope() {
            CallerScope::PlatformOperator => None,
            CallerScope::Tenant(tenant_id) => Some(tenant_id),
        }
    }

    pub fn service_account_id(&self) -> Option<&str> {
        match self.rbac_subject.as_ref() {
            Some(ferrogate_auth::PolicySubject::ServiceAccount { service_account_id }) => {
                Some(service_account_id)
            }
            _ => None,
        }
    }
}

/// The single source of truth for scope-set semantics, shared by
/// `AuthContext::has_scope` and the standalone admin-api service's auth
/// gate (#315) so the two can never drift:
/// - an explicit grant always allows;
/// - an explicit `*` wildcard grants every scope, including `admin.*` (set
///   for operator-authored *static config* keys and auth-disabled mode
///   that historically used an EMPTY scope list to mean "all access");
/// - a residual empty scope set means a durable/API-created (virtual) key
///   minted without explicit scopes: it grants ordinary data-plane scopes
///   but NEVER a privileged `admin.*` scope -- otherwise a tenant admin
///   creating a virtual key with no scopes would silently mint a full
///   tenant-admin credential (round-7 finding).
fn scope_set_allows(scopes: &HashSet<String>, scope: &str) -> bool {
    if scopes.contains(scope) {
        return true;
    }
    if scopes.contains(WILDCARD_SCOPE) {
        return true;
    }
    scopes.is_empty() && !AuthContext::is_privileged_scope(scope)
}

/// The tenant id handed to a credential that reached an isolation check
/// without a classification (see [`AuthContext::caller_scope`]). Empty is
/// unforgeable as a real tenant: `Config::validate` refuses a blank
/// `organization_id`, and no `tenants.id` row is the empty string, so every
/// comparison against it fails and every listing filtered by it is empty.
const UNSCOPED_TENANT_ID: &str = "";

/// Who a credential is, for tenant-isolation purposes (issue #515).
///
/// Before this existed the same question was asked as `organization_id
/// .is_none()` at a dozen call sites, which made "the operator omitted a
/// field" and "the operator asked for platform root" literally the same value.
/// They are now different states of a different field, and this enum is the
/// only way to read the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerScope<'a> {
    /// Unrestricted, cross-tenant. Reached only via an explicit
    /// `platform_operator = true` (or the deprecated `[tenancy]
    /// implicit_platform_operator` compatibility default, which says so in the
    /// startup log).
    PlatformOperator,
    /// Scoped to exactly one `tenants.id`.
    Tenant(&'a str),
}

/// Turn what a credential *declares* into whether it holds platform root
/// (issue #515) -- the single chokepoint every auth source funnels through, so
/// a new source cannot accidentally reintroduce "no tenant means root".
///
/// * an explicit `platform_operator` (true or false) always wins: root is
///   something an operator wrote down, and an explicit `false` is a refusal
///   that survives any compatibility default;
/// * a credential that names a tenant is that tenant, never root;
/// * a credential that declares neither is the legacy shape. It is root only
///   while `[tenancy] implicit_platform_operator` is on (the deprecated
///   default, which keeps existing deployments' bootstrap keys working and is
///   warned about at config load); with it off the credential is
///   unclassifiable and [`finalize_auth`] refuses it outright rather than
///   guessing.
pub fn resolve_platform_operator(
    implicit_platform_operator: bool,
    declared: Option<bool>,
    organization_id: Option<&str>,
) -> bool {
    match (declared, organization_id) {
        (Some(declared), _) => declared,
        (None, Some(_)) => false,
        (None, None) => implicit_platform_operator,
    }
}

#[derive(Debug)]
pub struct AuthError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

/// Denies cross-tenant access to a specific tenant's resource (issue
/// #185): `authenticate()` only ever checks *scope* (`admin.read`/
/// `admin.write`), never whether the caller's own tenant matches the
/// tenant the request actually targets. `provision_gateway_api_key`
/// (`ferrogate-auth`) mints a key tied to the logging-in user's own tenant
/// on every admin-console login -- scoped to their membership tier since
/// issue #517, so `admin.write` only for `owner`/`admin`, but scope is not
/// tenancy: an `owner`'s key still carries `admin.read`+`admin.write` and
/// without this check any tenant's console owner could read and mutate
/// every *other* tenant's wallets, virtual keys, quota policies, and RBAC
/// bindings (confirmed live before this fix: a tenant-A-scoped key could
/// read AND financially adjust tenant B's wallet balance via `POST
/// /admin/v1/wallets/{other_tenant}/adjust`).
///
/// A platform-operator key (the "root/bootstrap key manages every tenant"
/// shape this codebase's entire test suite already relies on, and the only
/// way to legitimately administer more than one tenant) is always allowed
/// through unrestricted, exactly as before this check existed. A
/// tenant-scoped key is denied whenever the resource it's trying to reach
/// belongs to a *different* tenant.
///
/// Since #515 "is this a platform operator?" is [`CallerScope`], resolved
/// from a declared `platform_operator`, and no longer a synonym for "the
/// `organization_id` field was omitted".
pub fn authorize_tenant_scope(auth: &AuthContext, target_tenant_id: &str) -> Result<(), AuthError> {
    match auth.caller_scope() {
        CallerScope::PlatformOperator => Ok(()),
        CallerScope::Tenant(caller_tenant_id) if caller_tenant_id == target_tenant_id => Ok(()),
        CallerScope::Tenant(_) => Err(AuthError {
            status: StatusCode::FORBIDDEN,
            code: "tenant_scope_denied",
            message: "API key is not authorized to access this tenant's resources".into(),
        }),
    }
}

/// The list-endpoint counterpart to [`authorize_tenant_scope`] (issue
/// #185): rather than deny outright, a bulk `GET /admin/v1/<resource>`
/// listing narrows down to the caller's own tenant when the key is
/// tenant-scoped. A platform-operator key sees every row unfiltered, same
/// as before this existed -- but since #515 that means a key that DECLARED
/// platform root, not merely one whose `organization_id` is absent.
pub fn filter_by_tenant_scope<T>(
    auth: &AuthContext,
    rows: Vec<T>,
    tenant_id: impl Fn(&T) -> &str,
) -> Vec<T> {
    match auth.caller_scope() {
        CallerScope::PlatformOperator => rows,
        CallerScope::Tenant(caller_tenant_id) => rows
            .into_iter()
            .filter(|row| tenant_id(row) == caller_tenant_id)
            .collect(),
    }
}
/// Forces a caller-suppliable tenant filter (e.g. the `?tenant=`/
/// `organization_id` query params accepted by the request-log, audit-event,
/// agent-run, and usage-aggregate admin read endpoints) to the caller's own
/// tenant when the caller is tenant-scoped (issue #185) -- otherwise a
/// tenant-scoped key could pass an explicit cross-tenant filter, or omit
/// the filter entirely, to read every tenant's logs/events. A
/// platform-operator key's requested filter passes through unchanged
/// (`None` legitimately means "show every tenant" -- but only for a caller
/// that *declared* platform root, since #515; an unclassified credential is
/// pinned to [`UNSCOPED_TENANT_ID`], which matches no row).
pub fn enforce_tenant_filter(auth: &AuthContext, requested: Option<String>) -> Option<String> {
    match auth.caller_scope() {
        CallerScope::PlatformOperator => requested,
        CallerScope::Tenant(tenant_id) => Some(tenant_id.to_string()),
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
///
/// #515 narrowed what gets through: it is no longer "any credential whose
/// `organization_id` happens to be absent" but "a credential that declared
/// itself a platform operator". Under `[tenancy] implicit_platform_operator =
/// false` an unclassified credential never reaches here at all -- it is
/// refused at authentication.
pub fn require_platform_operator(auth: &AuthContext) -> Result<(), AuthError> {
    if !auth.is_platform_operator() {
        return Err(AuthError {
            status: StatusCode::FORBIDDEN,
            code: "platform_operator_required",
            message: "this endpoint is restricted to platform-operator API keys".into(),
        });
    }
    Ok(())
}
/// The standalone admin-api service's fail-closed authentication gate
/// (issue #315). Mirrors [`authenticate`]'s key-source order exactly --
/// external auth service (when `auth_service.enabled`), then durable
/// storage-backed virtual keys, then the static `config.api_keys` fallback
/// -- and shares its scope semantics through [`scope_set_allows`], so a
/// caller the gateway would 401/403 gets the same answer at the admin-api
/// listener BEFORE anything is proxied. Differences, both deliberate:
/// - there is NO auth-disabled open mode here: the admin-api refuses to
///   start without a credential source (enforced by its serve entrypoint),
///   so this gate always demands a key -- never an open proxy;
/// - `finalize_auth`'s quota/budget/rate-limit governance and per-resource
///   tenant scoping are NOT duplicated here: the gateway re-authenticates
///   the forwarded bearer and remains the single enforcement authority for
///   those (defense in depth, not a second implementation that could
///   drift).
pub fn authenticate_admin_gate(
    auth_service: &ferrogate_config::AuthServiceConfig,
    api_keys: &[ApiKey],
    durable_authenticator: Option<&dyn ApiKeyAuthenticator>,
    presented_key: Option<&str>,
    required_scope: &str,
    request_id: &str,
) -> std::result::Result<(), AuthError> {
    let Some(provided_key) = presented_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AuthError {
            status: StatusCode::UNAUTHORIZED,
            code: "missing_api_key",
            message: "missing API key; use Authorization: Bearer or x-api-key".into(),
        });
    };

    if auth_service.enabled {
        // The resulting `AuthContext` is discarded here (this gate checks
        // scope only; the gateway re-authenticates the forwarded bearer and
        // remains the single tenancy authority), so the #515 classification
        // input is irrelevant -- pass the fail-closed value rather than
        // pretending this gate can mint root.
        authenticate_external(
            auth_service,
            false,
            provided_key,
            required_scope,
            request_id,
        )?;
        return Ok(());
    }

    if let Some(decision) =
        durable_authenticator.and_then(|authenticator| authenticator.authenticate(provided_key))
    {
        let scopes: HashSet<String> = decision.scopes.into_iter().collect();
        if !scope_set_allows(&scopes, required_scope) {
            return Err(AuthError {
                status: StatusCode::FORBIDDEN,
                code: "scope_denied",
                message: format!("API key does not have required scope {required_scope}"),
            });
        }
        return Ok(());
    }

    for configured_key in api_keys {
        if api_key_matches_presented_key(configured_key, provided_key) {
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
            // A STATIC config key with an empty scope list has always meant
            // "all access" (operator-authored), identical to `authenticate`.
            let scopes: HashSet<String> = if configured_key.scopes.is_empty() {
                HashSet::from([WILDCARD_SCOPE.to_string()])
            } else {
                configured_key.scopes.iter().cloned().collect()
            };
            if !scope_set_allows(&scopes, required_scope) {
                return Err(AuthError {
                    status: StatusCode::FORBIDDEN,
                    code: "scope_denied",
                    message: format!("API key does not have required scope {required_scope}"),
                });
            }
            return Ok(());
        }
    }

    Err(AuthError {
        status: StatusCode::UNAUTHORIZED,
        code: "invalid_api_key",
        message: "invalid API key".into(),
    })
}
/// Takes the `[auth_service]` block rather than the whole `AppState` it used to
/// take (#553 stage 3b-0). That was its ONLY reach into state -- twice, for the
/// same field -- so narrowing the parameter is what let the external
/// auth-service client travel here as one piece, next to
/// [`authenticate_external`] and the transport they share. The body is
/// unchanged.
pub fn authorize_external_rbac(
    auth_service: &ferrogate_config::AuthServiceConfig,
    auth: &AuthContext,
    action: &str,
    resource: &str,
) -> std::result::Result<(), AuthError> {
    if !auth_service.enabled {
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
        auth_service_post_json(auth_service, "/v1/auth/authorize", &request)
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

pub fn authenticate_external(
    service: &ferrogate_config::AuthServiceConfig,
    implicit_platform_operator: bool,
    provided_key: &str,
    required_scope: &str,
    request_id: &str,
) -> std::result::Result<AuthContext, AuthError> {
    let request = ferrogate_auth::ResolveApiKeyRequest {
        presented_key: provided_key.to_string(),
    };
    let decision: ferrogate_auth::AuthDecision =
        auth_service_post_json(service, "/v1/auth/resolve-api-key", &request)
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
        // #515: the external auth contract (`ferrogate_auth::AuthDecision`)
        // has no way to say "platform operator", so an external service can
        // only produce a tenant-scoped identity or an unclassified one -- and
        // the unclassified one is governed by the same deployment-wide switch
        // as every other source, not by a rule of its own.
        platform_operator: resolve_platform_operator(
            implicit_platform_operator,
            None,
            decision.tenant.organization_id.as_deref(),
        ),
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
    service: &ferrogate_config::AuthServiceConfig,
    path: &str,
    payload: &T,
) -> std::result::Result<R, AuthServiceClientError>
where
    T: serde::Serialize,
    R: DeserializeOwned,
{
    let body = serde_json::to_vec(payload)
        .map_err(|error| AuthServiceClientError::Request(error.to_string()))?;
    let endpoint = build_auth_service_target(&service.endpoint, path)?;
    let timeout = Duration::from_millis(service.timeout_millis);
    let attempts = service.max_retries.saturating_add(1);
    let backoff = Duration::from_millis(service.retry_backoff_millis);
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

/// Split an internal `http://host[:port][/base]` service endpoint into a
/// connectable `host:port` and a joined request path. Shared with the
/// admin-api reverse proxy (#315), which forwards each console request to
/// `admin_api.gateway_url` through exactly this parser.
pub fn build_auth_service_target(
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
pub struct AuthServiceTarget {
    pub host_port: String,
    pub path: String,
}

#[derive(Debug)]
pub enum AuthServiceClientError {
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

// These three were an inherent `impl ApiKey` until #553 stage 3a moved
// `ApiKey` itself into `ferrogate-config`. An inherent impl must live in the
// crate that defines the type, and the credential comparison below is this
// crate's Blake2b hasher, not config vocabulary -- so they became free
// functions here rather than travelling with the type. Bodies are unchanged.
pub fn api_key_matches_presented_key(key: &ApiKey, presented_key: &str) -> bool {
    if let Some(secret) = api_key_secret_value(key) {
        if constant_time_eq(presented_key.as_bytes(), secret.as_bytes()) {
            return true;
        }
    }
    key.key_hash
        .as_deref()
        .is_some_and(|hash| verify_api_key_secret(presented_key, hash))
}

fn api_key_secret_value(key: &ApiKey) -> Option<String> {
    if let Some(env_name) = &key.key_env {
        if let Ok(value) = std::env::var(env_name) {
            return Some(value);
        }
    }
    key.key.clone()
}

pub fn api_key_is_expired(key: &ApiKey, now_unix_seconds: u64) -> bool {
    key.expires_at_unix
        .is_some_and(|expires_at| expires_at <= now_unix_seconds)
}

pub fn hash_api_key_secret(secret: &str) -> String {
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

pub fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub fn extract_api_key(headers: &HeaderMap) -> Option<String> {
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

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
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
