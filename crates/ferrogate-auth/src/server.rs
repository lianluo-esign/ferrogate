// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The auth service process surface: the #147-hardened accept loop,
//! per-connection handling, and request routing across concern modules.

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    io::Write,
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::admin_console::{
    handle_admin_login, handle_admin_logout, handle_admin_me, handle_admin_refresh,
    handle_admin_register, handle_admin_team_change_role, handle_admin_team_invite,
    handle_admin_team_list, handle_admin_team_revoke, handle_rbac_binding_delete,
    handle_rbac_binding_upsert, handle_rbac_bindings_list, handle_rbac_role_delete,
    handle_rbac_role_upsert, handle_rbac_roles_list, AdminChangeRoleRequest, AdminConsoleConfig,
    AdminConsoleState, AdminInviteRequest, AdminLoginRequest, AdminLogoutRequest,
    AdminRefreshRequest, AdminRegisterRequest, BindingUpsertRequest, RoleUpsertRequest,
};
use crate::api_key::ApiKeyAuthenticator;
use crate::http::{
    bad_request, not_found, read_http_request, unauthorized, unprocessable, HttpRequest,
    HttpResponse, RequestLengthError,
};
use crate::rbac::{
    AuthDecision, AuthServiceData, AuthorizationDecision, AuthorizeRequest, RbacAuthService,
    TenantRecord,
};
use crate::scim::{
    handle_admin_scim_token_create, handle_scim_groups_list, handle_scim_user_create,
    handle_scim_user_delete, handle_scim_user_get, handle_scim_user_patch, handle_scim_users_list,
    resolve_scim_tenant, ScimUserRequest,
};
use crate::sso::{
    handle_admin_sso_config_delete, handle_admin_sso_config_get, handle_admin_sso_config_set,
    handle_saml_acs, handle_saml_authorize, handle_sso_authorize, handle_sso_callback,
    SsoConfigRequest,
};

/// Read/write deadline per connection so a slow or idle client cannot park a
/// handler thread forever (slowloris mitigation, issue #147 — ported from the
/// billing service's #138 fix).
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);
/// Upper bound on concurrently-served connections so an anonymous flood
/// cannot exhaust threads/memory (issue #147).
const MAX_CONCURRENT_CONNECTIONS: usize = 512;

#[derive(Clone)]
pub struct AuthService {
    pub(crate) rbac: RbacAuthService,
    api_key_authenticator: Arc<dyn ApiKeyAuthenticator>,
    admin_console: Option<Arc<AdminConsoleState>>,
    cors_allowed_origin: Option<String>,
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthService")
            .field("rbac", &self.rbac)
            .field("api_key_authenticator", &"dyn ApiKeyAuthenticator")
            .field("admin_console", &self.admin_console.is_some())
            .field("cors_allowed_origin", &self.cors_allowed_origin)
            .finish()
    }
}

impl AuthService {
    pub fn from_data(data: AuthServiceData) -> Self {
        let rbac = RbacAuthService::new(data);
        let api_key_authenticator = Arc::new(rbac.clone());
        Self {
            rbac,
            api_key_authenticator,
            admin_console: None,
            cors_allowed_origin: None,
        }
    }

    pub fn with_api_key_authenticator(
        data: AuthServiceData,
        api_key_authenticator: Arc<dyn ApiKeyAuthenticator>,
    ) -> Self {
        Self {
            rbac: RbacAuthService::new(data),
            api_key_authenticator,
            admin_console: None,
            cors_allowed_origin: None,
        }
    }

    /// Enables the admin-console register/login/session endpoints on this
    /// service (issue #157).
    pub fn with_admin_console(mut self, config: AdminConsoleConfig) -> Self {
        self.admin_console = Some(Arc::new(AdminConsoleState::new(config)));
        self
    }

    /// Reflects the given origin back on every response's
    /// `Access-Control-Allow-Origin` header, so a cross-origin admin console
    /// frontend (issue #158/#159) can call this service.
    pub fn with_cors_allowed_origin(mut self, origin: String) -> Self {
        self.cors_allowed_origin = Some(origin);
        self
    }

    pub fn tenants(&self) -> Vec<TenantRecord> {
        self.rbac.tenants()
    }

    pub fn authorize(&self, request: &AuthorizeRequest) -> AuthorizationDecision {
        self.rbac.authorize(request)
    }

    pub fn authenticate(&self, presented_key: &str) -> Option<AuthDecision> {
        self.api_key_authenticator.authenticate(presented_key)
    }
}

#[derive(Clone)]
pub struct AuthServiceConfig {
    pub listen: String,
    pub data: AuthServiceData,
    pub api_key_authenticator: Option<Arc<dyn ApiKeyAuthenticator>>,
    /// Enables the admin-console register/login/session endpoints (issue
    /// #157) when set. Requires durable storage -- there is no in-memory-only
    /// admin console, since a human's account must survive a process
    /// restart.
    pub admin_console: Option<AdminConsoleConfig>,
    /// Value reflected back as `Access-Control-Allow-Origin` on every
    /// response (including the OPTIONS preflight), so a separately-deployed
    /// admin console frontend (issue #158/#159) can call this service
    /// cross-origin. `None` disables CORS headers entirely.
    pub cors_allowed_origin: Option<String>,
}

impl std::fmt::Debug for AuthServiceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthServiceConfig")
            .field("listen", &self.listen)
            .field("data", &self.data)
            .field(
                "api_key_authenticator",
                &self
                    .api_key_authenticator
                    .as_ref()
                    .map(|_| "dyn ApiKeyAuthenticator"),
            )
            .field(
                "admin_console",
                &self.admin_console.as_ref().map(|_| "AdminConsoleConfig"),
            )
            .field("cors_allowed_origin", &self.cors_allowed_origin)
            .finish()
    }
}

/// RAII counter guard that decrements the live-connection count on drop
/// (ported from the billing service's #138 fix for issue #147).
struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The #147-hardened thread-per-connection accept loop: sheds load once
/// `MAX_CONCURRENT_CONNECTIONS` handlers are live instead of spawning
/// unbounded threads under a flood. Extracted (not copied -- the exact
/// duplication lesson from #147) so sibling side services in the same
/// binary (`ferrogate admin-api serve`, issue #315) run the same loop.
/// The handler owns per-connection concerns (timeouts, parsing, response).
pub fn serve_connections(
    listener: TcpListener,
    service_name: &'static str,
    handler: Arc<dyn Fn(TcpStream) -> anyhow::Result<()> + Send + Sync>,
) -> anyhow::Result<()> {
    let live_connections = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Shed load rather than spawn unbounded threads under a flood
                // (issue #147).
                if live_connections.load(Ordering::SeqCst) >= MAX_CONCURRENT_CONNECTIONS {
                    drop(stream);
                    continue;
                }
                live_connections.fetch_add(1, Ordering::SeqCst);
                let guard = ConnectionGuard(live_connections.clone());
                let handler = handler.clone();
                std::thread::spawn(move || {
                    let _guard = guard;
                    if let Err(error) = handler(stream) {
                        eprintln!("{service_name} request failed: {error:#}");
                    }
                });
            }
            Err(error) => eprintln!("{service_name} accept failed: {error}"),
        }
    }
    Ok(())
}

pub fn serve(config: AuthServiceConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.listen)
        .with_context(|| format!("failed to bind ferrogate-auth on {}", config.listen))?;
    let mut service = match config.api_key_authenticator {
        Some(api_key_authenticator) => {
            AuthService::with_api_key_authenticator(config.data, api_key_authenticator)
        }
        None => AuthService::from_data(config.data),
    };
    if let Some(admin_console) = config.admin_console {
        service = service.with_admin_console(admin_console);
    }
    if let Some(origin) = config.cors_allowed_origin {
        service = service.with_cors_allowed_origin(origin);
    }
    let service = Arc::new(service);
    println!("ferrogate-auth listening on {}", config.listen);
    serve_connections(
        listener,
        "ferrogate-auth",
        Arc::new(move |stream| handle_connection(stream, &service)),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveApiKeyRequest {
    pub presented_key: String,
}

fn handle_connection(mut stream: TcpStream, service: &AuthService) -> anyhow::Result<()> {
    stream
        .set_read_timeout(Some(CONNECTION_TIMEOUT))
        .context("failed to set auth service read timeout")?;
    stream
        .set_write_timeout(Some(CONNECTION_TIMEOUT))
        .context("failed to set auth service write timeout")?;
    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err(error) => {
            // A body-framing rejection (unlengthed/chunked, issue #328) is
            // answered with a clean HTTP error rather than dropping the
            // connection; any other parse failure keeps the prior
            // fail-closed behavior of tearing the connection down.
            if let Some(length_error) = error.downcast_ref::<RequestLengthError>() {
                let response = request_length_error_response(*length_error);
                return stream
                    .write_all(&response.to_bytes(service.cors_allowed_origin.as_deref()))
                    .context("failed to write auth service length-error response");
            }
            return Err(error);
        }
    };
    let response = route_request(service, request);
    stream
        .write_all(&response.to_bytes(service.cors_allowed_origin.as_deref()))
        .context("failed to write auth service response")
}

/// Render a [`RequestLengthError`] as this service's JSON error envelope.
fn request_length_error_response(error: RequestLengthError) -> HttpResponse {
    HttpResponse::json(
        error.http_status(),
        json!({
            "error": {
                "code": error.code(),
                "message": error.message(),
            }
        }),
    )
}

pub(crate) fn route_request(service: &AuthService, request: HttpRequest) -> HttpResponse {
    // Answer the CORS preflight for any path uniformly; the actual
    // Allow-* headers are attached in `to_bytes` from `service.cors_allowed_origin`.
    if request.method == "OPTIONS" {
        return HttpResponse::no_content(204);
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") | ("GET", "/v1/healthz") => HttpResponse::json(
            200,
            json!({
                "service": "ferrogate-auth",
                "status": "ok"
            }),
        ),
        ("GET", "/v1/tenants") => HttpResponse::json(200, json!({ "tenants": service.tenants() })),
        ("POST", "/v1/auth/resolve-api-key") => {
            let parsed = serde_json::from_slice::<ResolveApiKeyRequest>(&request.body);
            match parsed {
                Ok(payload) => match service.authenticate(&payload.presented_key) {
                    Some(decision) => HttpResponse::json(200, decision),
                    None => HttpResponse::json(
                        401,
                        json!({
                            "error": {
                                "code": "invalid_api_key",
                                "message": "api key was not recognized by ferrogate-auth"
                            }
                        }),
                    ),
                },
                Err(error) => bad_request(error),
            }
        }
        ("POST", "/v1/auth/authorize") => {
            let parsed = serde_json::from_slice::<AuthorizeRequest>(&request.body);
            match parsed {
                Ok(payload) => HttpResponse::json(200, service.authorize(&payload)),
                Err(error) => bad_request(error),
            }
        }
        ("POST", "/v1/admin/register") => with_admin_console(service, |console| {
            let parsed = serde_json::from_slice::<AdminRegisterRequest>(&request.body);
            match parsed {
                Ok(payload) => handle_admin_register(console, payload),
                Err(error) => bad_request(error),
            }
        }),
        ("POST", "/v1/admin/login") => with_admin_console(service, |console| {
            let parsed = serde_json::from_slice::<AdminLoginRequest>(&request.body);
            match parsed {
                Ok(payload) => handle_admin_login(console, payload),
                Err(error) => bad_request(error),
            }
        }),
        ("POST", "/v1/admin/refresh") => with_admin_console(service, |console| {
            let parsed = serde_json::from_slice::<AdminRefreshRequest>(&request.body);
            match parsed {
                Ok(payload) => handle_admin_refresh(console, payload),
                Err(error) => bad_request(error),
            }
        }),
        ("POST", "/v1/admin/logout") => with_admin_console(service, |console| {
            let parsed = serde_json::from_slice::<AdminLogoutRequest>(&request.body);
            match parsed {
                Ok(payload) => handle_admin_logout(console, payload),
                Err(error) => bad_request(error),
            }
        }),
        ("GET", "/v1/admin/me") => {
            with_admin_console(service, |console| match request.bearer_token() {
                Some(token) => handle_admin_me(console, token),
                None => unauthorized("missing bearer token"),
            })
        }
        ("GET", "/v1/admin/team") => {
            with_admin_console(service, |console| match request.bearer_token() {
                Some(token) => handle_admin_team_list(console, token),
                None => unauthorized("missing bearer token"),
            })
        }
        ("POST", "/v1/admin/team/invite") => {
            with_admin_console(service, |console| match request.bearer_token() {
                Some(token) => {
                    let parsed = serde_json::from_slice::<AdminInviteRequest>(&request.body);
                    match parsed {
                        Ok(payload) => handle_admin_team_invite(console, token, payload),
                        Err(error) => bad_request(error),
                    }
                }
                None => unauthorized("missing bearer token"),
            })
        }
        _ if request.path.starts_with("/v1/admin/team/members/") => {
            with_admin_console(service, |console| {
                let user_id = request
                    .path
                    .strip_prefix("/v1/admin/team/members/")
                    .unwrap_or_default();
                if user_id.is_empty() {
                    return HttpResponse::json(
                        404,
                        json!({ "error": { "code": "not_found", "message": "auth service endpoint not found" } }),
                    );
                }
                let Some(token) = request.bearer_token() else {
                    return unauthorized("missing bearer token");
                };
                match request.method.as_str() {
                    "POST" => {
                        let parsed =
                            serde_json::from_slice::<AdminChangeRoleRequest>(&request.body);
                        match parsed {
                            Ok(payload) => {
                                handle_admin_team_change_role(console, token, user_id, payload)
                            }
                            Err(error) => bad_request(error),
                        }
                    }
                    "DELETE" => handle_admin_team_revoke(console, token, user_id),
                    _ => HttpResponse::json(
                        405,
                        json!({ "error": { "code": "method_not_allowed", "message": "unsupported method for this route" } }),
                    ),
                }
            })
        }
        ("GET", "/v1/rbac/roles") => {
            with_admin_console(service, |console| match request.bearer_token() {
                Some(token) => handle_rbac_roles_list(service, console, token),
                None => unauthorized("missing bearer token"),
            })
        }
        ("POST", "/v1/rbac/roles") => {
            with_admin_console(service, |console| match request.bearer_token() {
                Some(token) => {
                    let parsed = serde_json::from_slice::<RoleUpsertRequest>(&request.body);
                    match parsed {
                        Ok(payload) => handle_rbac_role_upsert(service, console, token, payload),
                        Err(error) => bad_request(error),
                    }
                }
                None => unauthorized("missing bearer token"),
            })
        }
        ("DELETE", path) if path.starts_with("/v1/rbac/roles/") => {
            with_admin_console(service, |console| {
                let role_id = path.strip_prefix("/v1/rbac/roles/").unwrap_or_default();
                match request.bearer_token() {
                    Some(token) if !role_id.is_empty() => {
                        handle_rbac_role_delete(service, console, token, role_id)
                    }
                    Some(_) => not_found("auth service endpoint not found"),
                    None => unauthorized("missing bearer token"),
                }
            })
        }
        ("GET", "/v1/rbac/bindings") => {
            with_admin_console(service, |console| match request.bearer_token() {
                Some(token) => handle_rbac_bindings_list(service, console, token),
                None => unauthorized("missing bearer token"),
            })
        }
        ("POST", "/v1/rbac/bindings") => {
            with_admin_console(service, |console| match request.bearer_token() {
                Some(token) => {
                    let parsed = serde_json::from_slice::<BindingUpsertRequest>(&request.body);
                    match parsed {
                        Ok(payload) => handle_rbac_binding_upsert(service, console, token, payload),
                        Err(error) => bad_request(error),
                    }
                }
                None => unauthorized("missing bearer token"),
            })
        }
        ("DELETE", path) if path.starts_with("/v1/rbac/bindings/") => {
            with_admin_console(service, |console| {
                let binding_id = path.strip_prefix("/v1/rbac/bindings/").unwrap_or_default();
                match request.bearer_token() {
                    Some(token) if !binding_id.is_empty() => {
                        handle_rbac_binding_delete(service, console, token, binding_id)
                    }
                    Some(_) => not_found("auth service endpoint not found"),
                    None => unauthorized("missing bearer token"),
                }
            })
        }
        ("POST", "/v1/admin/team/scim-token") => {
            with_admin_console(service, |console| match request.bearer_token() {
                Some(token) => handle_admin_scim_token_create(console, token),
                None => unauthorized("missing bearer token"),
            })
        }
        ("GET", "/scim/v2/Users") => {
            with_admin_console(service, |console| {
                match resolve_scim_tenant(console, &request) {
                    Ok(tenant_id) => handle_scim_users_list(console, &tenant_id),
                    Err(response) => response,
                }
            })
        }
        ("POST", "/scim/v2/Users") => with_admin_console(service, |console| {
            match resolve_scim_tenant(console, &request) {
                Ok(tenant_id) => {
                    let parsed = serde_json::from_slice::<ScimUserRequest>(&request.body);
                    match parsed {
                        Ok(payload) => handle_scim_user_create(console, &tenant_id, payload),
                        Err(error) => bad_request(error),
                    }
                }
                Err(response) => response,
            }
        }),
        ("GET", "/scim/v2/Groups") => with_admin_console(service, |console| {
            match resolve_scim_tenant(console, &request) {
                Ok(tenant_id) => handle_scim_groups_list(console, &tenant_id),
                Err(response) => response,
            }
        }),
        _ if request.path.starts_with("/scim/v2/Users/") => {
            with_admin_console(service, |console| {
                let user_id = request
                    .path
                    .strip_prefix("/scim/v2/Users/")
                    .unwrap_or_default();
                if user_id.is_empty() {
                    return not_found("auth service endpoint not found");
                }
                let tenant_id = match resolve_scim_tenant(console, &request) {
                    Ok(tenant_id) => tenant_id,
                    Err(response) => return response,
                };
                match request.method.as_str() {
                    "GET" => handle_scim_user_get(console, &tenant_id, user_id),
                    "PATCH" | "PUT" => {
                        handle_scim_user_patch(console, &tenant_id, user_id, &request.body)
                    }
                    "DELETE" => handle_scim_user_delete(console, &tenant_id, user_id),
                    _ => HttpResponse::json(
                        405,
                        json!({ "error": { "code": "method_not_allowed", "message": "unsupported method for this route" } }),
                    ),
                }
            })
        }
        ("POST", "/v1/admin/team/sso-config") => {
            with_admin_console(service, |console| match request.bearer_token() {
                Some(token) => {
                    let parsed = serde_json::from_slice::<SsoConfigRequest>(&request.body);
                    match parsed {
                        Ok(payload) => handle_admin_sso_config_set(console, token, payload),
                        Err(error) => bad_request(error),
                    }
                }
                None => unauthorized("missing bearer token"),
            })
        }
        ("GET", "/v1/admin/team/sso-config") => {
            with_admin_console(service, |console| match request.bearer_token() {
                Some(token) => handle_admin_sso_config_get(console, token),
                None => unauthorized("missing bearer token"),
            })
        }
        ("DELETE", "/v1/admin/team/sso-config") => {
            with_admin_console(service, |console| match request.bearer_token() {
                Some(token) => handle_admin_sso_config_delete(console, token),
                None => unauthorized("missing bearer token"),
            })
        }
        ("GET", "/v1/admin/auth/sso/authorize") => {
            with_admin_console(service, |console| match request.query_param("tenant_id") {
                Some(tenant_id) if !tenant_id.is_empty() => {
                    handle_sso_authorize(console, &tenant_id)
                }
                _ => unprocessable("tenant_id query parameter is required"),
            })
        }
        ("GET", "/v1/admin/auth/sso/callback") => with_admin_console(service, |console| {
            let code = request.query_param("code");
            let state = request.query_param("state");
            match (code, state) {
                (Some(code), Some(state)) if !code.is_empty() && !state.is_empty() => {
                    handle_sso_callback(console, &code, &state)
                }
                _ => unprocessable("code and state query parameters are required"),
            }
        }),
        ("GET", "/v1/admin/auth/saml/authorize") => {
            with_admin_console(service, |console| match request.query_param("tenant_id") {
                Some(tenant_id) if !tenant_id.is_empty() => {
                    handle_saml_authorize(console, &tenant_id)
                }
                _ => unprocessable("tenant_id query parameter is required"),
            })
        }
        // The IdP delivers the SAML Response over the HTTP-Redirect binding as
        // `?SAMLResponse=...&RelayState=...&SigAlg=...&Signature=...`. The raw
        // query string is passed through verbatim so the redirect-binding
        // signature can be reconstructed over the exact received octets.
        ("GET", "/v1/admin/auth/saml/acs") => {
            with_admin_console(service, |console| handle_saml_acs(console, &request.query))
        }
        _ => HttpResponse::json(
            404,
            json!({
                "error": {
                    "code": "not_found",
                    "message": "auth service endpoint not found"
                }
            }),
        ),
    }
}

/// Runs `handler` if the admin console feature is configured, otherwise
/// returns a clear 503 rather than a confusing 404 -- the route exists, it
/// just isn't enabled on this deployment (issue #157).
pub(crate) fn with_admin_console(
    service: &AuthService,
    handler: impl FnOnce(&AdminConsoleState) -> HttpResponse,
) -> HttpResponse {
    match service.admin_console.as_deref() {
        Some(console) => handler(console),
        None => HttpResponse::json(
            503,
            json!({
                "error": {
                    "code": "admin_console_not_configured",
                    "message": "the admin console is not enabled on this ferrogate-auth deployment; \
                                start it with --supabase-dsn and --admin-jwt-secret(-env)"
                }
            }),
        ),
    }
}
