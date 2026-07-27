// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: Standalone admin-console API service (issue #315). A
// dedicated `ferrogate admin-api serve` listener that terminates the
// console's HTTP(S), authenticates the caller with the gateway's own
// admin-scope semantics, and reverse-proxies the path-compatible
// /admin/v1/* (+ /v1/assets/*) surface to the gateway -- so admin
// control-plane traffic never rides the AI data-plane process/listener.
//
// Strategy note (the issue offered two): the gateway's admin handlers are
// written directly against the Pingora `Session` (every handler in
// gateway/*.rs takes `session: &mut Session` and responds through
// `write_json_error`/`write_json_response` on it), so re-mounting them on
// a second transport would mean extracting a response-writing seam across
// ~20 handler modules. This module is therefore the authenticated
// reverse-proxy slice: identical URL surface, identical auth answers at
// the edge (via `auth::authenticate_admin_gate`, which shares
// `scope_set_allows` and the key-source order with the gateway's own
// `authenticate`), with the gateway remaining the single enforcement
// authority for tenant scoping, quotas, and budgets on the forwarded
// request. In-process handler mounting stays available as a follow-up
// without changing this service's config or URL contract.

use anyhow::{anyhow, Context};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use ferrogate_auth::{
    read_http_request_bounded, serve_connections, ApiKeyAuthenticator, HttpRequest, HttpResponse,
    RequestLengthError, StorageApiKeyAuthenticator,
};
use ferrogate_config::Config;
use ferrogate_gateway::auth::{authenticate_admin_gate, build_auth_service_target, AuthError};

/// Canonical wire/log identity of the standalone FerroGate Control Plane API
/// service (issue #359). Emitted in the startup log, the connection-accept
/// service label, and this service's own `/healthz` evidence, so operators
/// see the promoted product name regardless of whether the process was
/// launched via `control-api serve` or the deprecated `admin-api serve`
/// alias. Not part of any REST contract (the `/healthz` probe is deliberately
/// outside the OpenAPI surface).
const CONTROL_PLANE_SERVICE_ID: &str = "ferrogate-control-plane-api";

/// Downstream (console-facing) socket timeout, matching the auth service's
/// #147 hardening value.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);

/// Print the actionable deprecation notice for the `ferrogate admin-api serve`
/// command alias (issue #359). The command still runs the canonical FerroGate
/// Control Plane API service; this only nudges operators toward the new name.
pub(crate) fn emit_admin_api_command_deprecation() {
    tracing::warn!(
        "`ferrogate admin-api serve` is a deprecated alias for `ferrogate control-api serve` \
         (FerroGate Control Plane API). It still works during the migration window; switch to \
         `control-api serve` and rename the [admin_api] config section to [control_api]."
    );
}

/// Header (and framing) headroom added on top of the largest configured
/// per-path body cap when sizing the parser ceiling.
const PROXY_HEADER_HEADROOM_BYTES: usize = 64 * 1024;

/// Overall parse cap for one incoming request, sized so it can never sit
/// below a per-path `[limits]` cap this service enforces after routing
/// (issue #328, finding 3).
///
/// The parser applies this ceiling *before* routing resolves the tighter
/// per-family cap in [`body_cap_bytes`]. If it were a fixed constant below
/// a configured family cap (an operator can raise e.g.
/// `guardrail_policy_body_max_bytes` above the old ~10MB default), a
/// request sized between the two caps would `Err` out of the parser and
/// drop the connection with no HTTP response, instead of getting a clean
/// 413 from the per-path check. Deriving the ceiling from
/// `max(all configured family caps) + headroom` guarantees every request
/// the per-path check would 413 first survives parsing.
fn max_proxy_request_bytes(config: &Config) -> usize {
    let largest_family_cap = [
        config.limits.admin_body_max_bytes(),
        config.limits.admin_config_body_max_bytes(),
        config.limits.guardrail_policy_body_max_bytes(),
        ferrogate_gateway::server::assets::INLINE_ASSET_MAX_BYTES as usize,
    ]
    .into_iter()
    .max()
    .unwrap_or(ferrogate_gateway::server::assets::INLINE_ASSET_MAX_BYTES as usize);
    largest_family_cap.saturating_add(PROXY_HEADER_HEADROOM_BYTES)
}

/// Which admin-console surface a request belongs to. Anything that is
/// neither is refused with 404 -- the AI data plane (e.g.
/// /v1/chat/completions) is deliberately NOT reachable through this
/// listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteClass {
    /// `/admin/*`: the gateway's admin API surface (status + /admin/v1/*).
    Admin,
    /// `/v1/assets*`: the console's asset-management page (issue #178).
    Assets,
}

/// Rewrite a request received under the canonical `/control/v1` URI alias onto
/// the stable `/admin/v1` prefix (issue #453), reusing the shared control-plane
/// contract so this reverse proxy and the in-process gateway fold the alias
/// through one definition. Non-alias requests (including already-canonical
/// `/admin/v1` and the `/v1/assets` surface) are returned unchanged.
fn normalize_control_plane_alias(mut request: HttpRequest) -> HttpRequest {
    if let Some(canonical) = ferrogate_admin::control_plane::canonicalize_alias_path(&request.path)
    {
        request.path = canonical;
    }
    request
}

fn classify_route(path: &str) -> Option<RouteClass> {
    if path == "/admin" || path.starts_with("/admin/") {
        return Some(RouteClass::Admin);
    }
    if path == "/v1/assets" || path.starts_with("/v1/assets/") {
        return Some(RouteClass::Assets);
    }
    None
}

/// The scope the caller must hold BEFORE anything is forwarded. Mirrors
/// the gateway's own handler convention: every GET/HEAD admin route
/// authenticates with `admin.read` and every mutation with `admin.write`
/// (verified across gateway/*.rs -- no mutating admin route accepts
/// `admin.read` alone), and the asset surface uses `assets.read`/
/// `assets.write` the same way.
fn required_scope(class: RouteClass, method: &str) -> &'static str {
    let read = matches!(method, "GET" | "HEAD");
    match (class, read) {
        (RouteClass::Admin, true) => "admin.read",
        (RouteClass::Admin, false) => "admin.write",
        (RouteClass::Assets, true) => "assets.read",
        (RouteClass::Assets, false) => "assets.write",
    }
}

/// Outer request-body cap for a routed path, resolved from the #312
/// `[limits]` section. Each cap is the LOOSEST limit the gateway itself
/// applies within that path family (the gateway still enforces its exact,
/// sometimes tighter, per-endpoint cap on the forwarded request), so this
/// bound sheds oversized payloads early without ever rejecting a request
/// the gateway would have accepted.
fn body_cap_bytes(config: &Config, class: RouteClass, path: &str) -> usize {
    match class {
        RouteClass::Admin => {
            if path.starts_with("/admin/v1/config/") {
                config.limits.admin_config_body_max_bytes()
            } else if path.starts_with("/admin/v1/guardrail-policies") {
                config.limits.guardrail_policy_body_max_bytes()
            } else {
                config.limits.admin_body_max_bytes()
            }
        }
        RouteClass::Assets => ferrogate_gateway::server::assets::INLINE_ASSET_MAX_BYTES as usize,
    }
}

/// Hop-by-hop headers that must not be forwarded verbatim; the proxy sets
/// its own `Host`, `Content-Length`, and `Connection: close`.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

struct AdminApiService {
    config: Config,
    durable_authenticator: Option<Arc<StorageApiKeyAuthenticator>>,
    request_ids: AtomicU64,
}

impl AdminApiService {
    fn next_request_id(&self) -> String {
        let next = self.request_ids.fetch_add(1, Ordering::Relaxed);
        format!("fgadm-{next:016x}")
    }

    fn cors_allowed_origin(&self) -> Option<&str> {
        self.config.admin_api.cors_allowed_origin.as_deref()
    }
}

pub(crate) fn execute_control_api_serve(config: Config) -> anyhow::Result<()> {
    // Fail closed at startup: this service must never be an open control-plane
    // proxy. The gateway's "auth disabled" convenience mode ([auth] disabled,
    // #542) is deliberately NOT mirrored here -- a control-plane edge with no
    // credential source at all is a misconfiguration, not a mode.
    //
    // #542: the credential-source question is now asked through the shared
    // `Config::has_credential_source` predicate, so this service and the
    // gateway's own startup gate cannot drift apart about what counts as one.
    //
    // #542 rework: and the DURABLE half of it is asked through
    // `Config::durable_api_key_store` for the same reason. This line used to
    // re-list `Postgres | Supabase` by hand, which meant a Cloudflare D1
    // control plane passed the credential-source check above and then got no
    // durable authenticator at all -- the service would start and refuse every
    // virtual key it was configured to resolve.
    let durable_key_store = config.durable_api_key_store();
    if !config.has_credential_source() {
        anyhow::bail!(
            "refusing to start an open Control Plane API proxy: the config has no credential \
             source (no [[api_keys]], no enabled [auth_service], and no durable [storage] backend \
             -- postgres, supabase or cloudflare_d1 -- for virtual keys); the FerroGate Control \
             Plane API service authenticates every request before forwarding and cannot do so \
             without one"
        );
    }

    // Resolve durable virtual keys against the SAME shared control plane the
    // gateway reads (`[storage]` from the same config file), through the same
    // authenticator type the gateway's AppState uses -- reuse, not a parallel
    // implementation. With a memory-only storage provider there is nothing
    // shared to resolve against (runtime-minted keys live inside the gateway
    // process), so only static [[api_keys]] and the external auth service
    // apply; a production admin-console deployment always has a shared durable
    // backend (the console itself requires one).
    let durable_authenticator = if durable_key_store.is_some() {
        let repositories = Arc::new(
            ferrogate_gateway::state::runtime_storage_repositories(&config)
                .context("failed to open the shared control-plane storage backend")?,
        );
        Some(Arc::new(StorageApiKeyAuthenticator::new(repositories)))
    } else {
        None
    };

    let tls_config = load_tls_config(&config)?;
    let listen = config.admin_api.listen.clone();
    let listener = TcpListener::bind(&listen)
        .with_context(|| format!("failed to bind {CONTROL_PLANE_SERVICE_ID} on {listen}"))?;
    let service = Arc::new(AdminApiService {
        config,
        durable_authenticator,
        request_ids: AtomicU64::new(1),
    });
    println!(
        "{CONTROL_PLANE_SERVICE_ID} (FerroGate Control Plane API) listening on {listen} \
         (tls: {}), proxying the control-plane surface to {}",
        tls_config.is_some(),
        service.config.admin_api.gateway_url
    );
    serve_connections(
        listener,
        CONTROL_PLANE_SERVICE_ID,
        Arc::new(move |stream| handle_connection(stream, tls_config.clone(), &service)),
    )
}

/// Load the optional listener TLS keypair. Validation already guaranteed
/// the paths come as a complete pair.
fn load_tls_config(config: &Config) -> anyhow::Result<Option<Arc<rustls::ServerConfig>>> {
    use rustls_pki_types::pem::PemObject;

    let (Some(cert_path), Some(key_path)) = (
        config.admin_api.tls_cert_path.as_deref(),
        config.admin_api.tls_key_path.as_deref(),
    ) else {
        return Ok(None);
    };
    let certs = rustls_pki_types::CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("failed to read admin_api.tls_cert_path {cert_path}"))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse admin_api.tls_cert_path {cert_path}"))?;
    if certs.is_empty() {
        anyhow::bail!("admin_api.tls_cert_path {cert_path} contains no certificates");
    }
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("failed to read admin_api.tls_key_path {key_path}"))?;
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build the admin-api TLS server config")?;
    Ok(Some(Arc::new(tls_config)))
}

fn handle_connection(
    stream: TcpStream,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    service: &AdminApiService,
) -> anyhow::Result<()> {
    stream
        .set_read_timeout(Some(CONNECTION_TIMEOUT))
        .context("failed to set admin-api read timeout")?;
    stream
        .set_write_timeout(Some(CONNECTION_TIMEOUT))
        .context("failed to set admin-api write timeout")?;
    let peer_ip = stream.peer_addr().ok().map(|addr| addr.ip());
    match tls_config {
        Some(tls_config) => {
            let connection = rustls::ServerConnection::new(tls_config)
                .context("failed to start admin-api TLS session")?;
            let mut tls_stream = rustls::StreamOwned::new(connection, stream);
            handle_request(&mut tls_stream, peer_ip, service)
        }
        None => {
            let mut stream = stream;
            handle_request(&mut stream, peer_ip, service)
        }
    }
}

fn handle_request<S: Read + Write>(
    stream: &mut S,
    peer_ip: Option<IpAddr>,
    service: &AdminApiService,
) -> anyhow::Result<()> {
    let request = match read_http_request_bounded(stream, max_proxy_request_bytes(&service.config))
    {
        Ok(request) => request,
        Err(error) => {
            // A body-framing rejection (unlengthed/chunked, issue #328,
            // finding 2) is answered with a proper HTTP error response
            // rather than dropping the connection; any other parse
            // failure keeps the prior fail-closed connection teardown.
            if let Some(length_error) = error.downcast_ref::<RequestLengthError>() {
                let response = length_error_response(*length_error, &service.next_request_id());
                return stream
                    .write_all(&response.to_bytes(service.cors_allowed_origin()))
                    .context("failed to write admin-api length-error response");
            }
            return Err(error);
        }
    };
    // Issue #453: fold the canonical `/control/v1` URI alias onto the stable
    // `/admin/v1` prefix so the existing route classification, admin.read/
    // admin.write scope selection, per-path body caps, and upstream forwarding
    // serve BOTH prefixes from one contract and relay the canonical path to the
    // gateway. `/admin/v1` and non-admin requests pass through unchanged.
    let request = normalize_control_plane_alias(request);
    let response = match route_request(&request, service) {
        Routed::Local(response) => response,
        Routed::Forward => {
            return forward_request(stream, &request, peer_ip, service);
        }
    };
    stream
        .write_all(&response.to_bytes(service.cors_allowed_origin()))
        .context("failed to write admin-api response")
}

enum Routed {
    /// Answered locally (health, preflight, or a refusal from the gate).
    Local(HttpResponse),
    /// Authenticated and within caps: relay to the gateway.
    Forward,
}

fn route_request(request: &HttpRequest, service: &AdminApiService) -> Routed {
    // Answer the CORS preflight for any path locally: a browser preflight
    // carries no Authorization header by design, so it must not hit the
    // auth gate (and must not be proxied -- it touches no state).
    if request.method == "OPTIONS" {
        return Routed::Local(HttpResponse::no_content(204));
    }
    if request.method == "GET" && request.path == "/healthz" {
        // This service's own liveness probe; deliberately NOT part of the
        // gateway's OpenAPI contract.
        return Routed::Local(HttpResponse::json(
            200,
            json!({ "service": CONTROL_PLANE_SERVICE_ID, "status": "ok" }),
        ));
    }
    let request_id = service.next_request_id();
    let Some(class) = classify_route(&request.path) else {
        return Routed::Local(error_response(
            404,
            "not_found",
            "not a FerroGate Control Plane API endpoint; the AI data plane is not served by \
             the Control Plane API listener",
            &request_id,
        ));
    };

    // Fail-closed auth gate BEFORE any forwarding: same key sources and
    // scope semantics as the gateway's own `authenticate` (see
    // auth::authenticate_admin_gate). x-api-key takes precedence over the
    // Authorization bearer, mirroring `auth::extract_api_key`.
    let presented_key = request
        .header("x-api-key")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| request.bearer_token().map(str::trim));
    let scope = required_scope(class, &request.method);
    if let Err(error) = authenticate_admin_gate(
        &service.config.auth_service,
        &service.config.api_keys,
        service
            .durable_authenticator
            .as_deref()
            .map(|authenticator| authenticator as &dyn ApiKeyAuthenticator),
        presented_key,
        scope,
        &request_id,
    ) {
        return Routed::Local(auth_error_response(error, &request_id));
    }

    let cap = body_cap_bytes(&service.config, class, &request.path);
    if request.body.len() > cap {
        return Routed::Local(error_response(
            413,
            "payload_too_large",
            format!("request body exceeds maximum size of {cap} bytes"),
            &request_id,
        ));
    }
    Routed::Forward
}

/// Relay the authenticated request to the gateway and stream the response
/// back verbatim (status line, headers, and body untouched, so the
/// console observes byte-identical behavior to calling the gateway
/// directly). `Connection: close` bounds the exchange; request bodies are
/// never logged.
fn forward_request<S: Read + Write>(
    stream: &mut S,
    request: &HttpRequest,
    peer_ip: Option<IpAddr>,
    service: &AdminApiService,
) -> anyhow::Result<()> {
    let request_id = service.next_request_id();
    let timeout = Duration::from_millis(service.config.admin_api.upstream_timeout_millis);
    let mut upstream =
        match connect_upstream(&service.config.admin_api.gateway_url, request, timeout) {
            Ok(upstream) => upstream,
            Err(error) => {
                tracing::warn!(
                    method = %request.method,
                    path = %request.path,
                    "Control Plane API upstream connect failed: {error:#}"
                );
                let response = error_response(
                    502,
                    "admin_upstream_unreachable",
                    "the gateway admin surface is unreachable from the Control Plane API service",
                    &request_id,
                );
                return stream
                    .write_all(&response.to_bytes(service.cors_allowed_origin()))
                    .context("failed to write admin-api 502 response");
            }
        };

    let mut relay = || -> anyhow::Result<()> {
        upstream
            .head
            .write_headers(request, peer_ip, &mut upstream.stream)?;
        upstream
            .stream
            .write_all(&request.body)
            .context("failed to forward the request body to the gateway")?;
        // Stream the response back chunk by chunk until the gateway closes
        // the connection -- constant memory, no response-size assumption.
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            let read = upstream
                .stream
                .read(&mut chunk)
                .context("failed to read the gateway response")?;
            if read == 0 {
                return Ok(());
            }
            stream
                .write_all(&chunk[..read])
                .context("failed to relay the gateway response")?;
        }
    };
    relay().map_err(|error| {
        anyhow!(
            "Control Plane API relay for {} failed: {error:#}",
            request.path
        )
    })
}

struct UpstreamConnection {
    stream: TcpStream,
    head: UpstreamHead,
}

struct UpstreamHead {
    host_port: String,
    path: String,
}

impl UpstreamHead {
    fn write_headers(
        &self,
        request: &HttpRequest,
        peer_ip: Option<IpAddr>,
        upstream: &mut TcpStream,
    ) -> anyhow::Result<()> {
        let target = if request.query.is_empty() {
            self.path.clone()
        } else {
            format!("{}?{}", self.path, request.query)
        };
        write!(
            upstream,
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            request.method,
            target,
            self.host_port,
            request.body.len()
        )
        .context("failed to forward the request line to the gateway")?;
        for (name, value) in &request.headers {
            if is_hop_by_hop(name) || name == "x-forwarded-for" {
                continue;
            }
            write!(upstream, "{name}: {value}\r\n")
                .context("failed to forward a request header to the gateway")?;
        }
        // Append this hop to X-Forwarded-For so the gateway's
        // `network_access` client-IP resolution keeps working behind the
        // proxy (subject to its own trust_forwarded_for setting).
        let forwarded_for = match (request.header("x-forwarded-for"), peer_ip) {
            (Some(existing), Some(peer)) => Some(format!("{existing}, {peer}")),
            (Some(existing), None) => Some(existing.to_string()),
            (None, Some(peer)) => Some(peer.to_string()),
            (None, None) => None,
        };
        if let Some(forwarded_for) = forwarded_for {
            write!(upstream, "x-forwarded-for: {forwarded_for}\r\n")
                .context("failed to forward x-forwarded-for to the gateway")?;
        }
        write!(upstream, "\r\n").context("failed to finish the forwarded request head")?;
        Ok(())
    }
}

fn connect_upstream(
    gateway_url: &str,
    request: &HttpRequest,
    timeout: Duration,
) -> anyhow::Result<UpstreamConnection> {
    let target = build_auth_service_target(gateway_url, &request.path)
        .map_err(|error| anyhow!("invalid admin_api.gateway_url: {error}"))?;
    let address = target
        .host_port
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve gateway host {}", target.host_port))?
        .next()
        .ok_or_else(|| anyhow!("gateway host {} resolved no addresses", target.host_port))?;
    let stream = TcpStream::connect_timeout(&address, timeout)
        .with_context(|| format!("failed to connect to the gateway at {address}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .context("failed to set gateway read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("failed to set gateway write timeout")?;
    Ok(UpstreamConnection {
        stream,
        head: UpstreamHead {
            host_port: target.host_port,
            path: target.path,
        },
    })
}

/// Locally generated errors mirror the gateway's JSON error envelope
/// (`responses::ErrorBody`) so the console's error handling sees one
/// consistent shape regardless of which layer refused the request.
fn error_response(
    status: u16,
    code: &str,
    message: impl Into<String>,
    request_id: &str,
) -> HttpResponse {
    HttpResponse::json(
        status,
        json!({
            "error": {
                "message": message.into(),
                "type": "ferrogate_error",
                "code": code,
                "request_id": request_id,
            }
        }),
    )
}

fn auth_error_response(error: AuthError, request_id: &str) -> HttpResponse {
    error_response(error.status.as_u16(), error.code, error.message, request_id)
}

/// Map a parser body-framing rejection (issue #328, finding 2) to the
/// service's JSON error envelope: 411 for a missing `Content-Length` on a
/// body-bearing method, 400 for unsupported chunked/`Transfer-Encoding`.
fn length_error_response(error: RequestLengthError, request_id: &str) -> HttpResponse {
    error_response(
        error.http_status(),
        error.code(),
        error.message(),
        request_id,
    )
}

#[cfg(test)]
#[path = "admin_api_test.rs"]
mod admin_api_test;
