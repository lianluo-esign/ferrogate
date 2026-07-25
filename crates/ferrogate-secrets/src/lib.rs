// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-06
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Secret-reference resolution for FerroGate (issue #163).
//!
//! Operators can supply upstream provider API keys and other credentials
//! either as plain env-var names (the pre-existing `key_env`/`api_key_env`
//! config fields, unchanged) or as a `secret_ref` URI resolved through this
//! crate:
//!
//! - `env://VAR_NAME` — same as `key_env`, spelled as a URI for a uniform
//!   config surface.
//! - `vault://<mount>/<path>#<field>` — reads a HashiCorp Vault KV v2 secret,
//!   e.g. `vault://secret/data/openai#api_key`.
//! - `cf://<store>/<name>` — a secret in a Cloudflare Secrets Store (issues
//!   #417/#423), e.g. `cf://provider-keys/openai-api-key`. Secrets Store
//!   values are **write-only over REST** (only a Worker binding can read them
//!   back), so value resolution comes from the Worker-binding context
//!   ([`CfSecretBindings`], consulted first); the REST backend
//!   ([`CloudflareSecretResolver`], via the shared `ferrogate-cloudflare` API
//!   client) is write/manage-only plus existence checks and errors precisely
//!   on a value read. See `docs/cloudflare-secrets-resolution.md`.
//!
//! The Vault backend is intentionally a minimal, dependency-light HTTP(S)
//! client (mirrors the pattern already used in `ferrogate-cli`'s
//! `telemetry.rs`/`acme.rs` and `ferrogate-mcp`) rather than a full Vault SDK,
//! since only a KV v2 read is needed. The Cloudflare backend instead reuses the
//! shared [`ferrogate_cloudflare::CloudflareClient`] (auth, retries, envelope +
//! error mapping written once, in #405) so every FerroGate Cloudflare
//! integration talks to the REST API the same way.

mod cloudflare;
mod cloudflare_bindings;
mod cloudflare_caps;

pub use cloudflare::{
    CfSecretsStoreConfig, CloudflareSecretResolver, CF_SECRETS_STORE_BETA_MAX_SECRETS_PER_ACCOUNT,
    CF_SECRETS_STORE_BETA_MAX_STORES_PER_ACCOUNT, CF_SECRETS_STORE_BETA_MAX_VALUE_BYTES,
};
pub use cloudflare_bindings::{cf_binding_env_var, CfSecretBindings, CF_BINDING_ENV_PREFIX};
pub use cloudflare_caps::{
    CfSecretsCapacityPolicy, CfSecretsCapacityWarning, CF_SECRETS_MAX_SECRETS_ENV,
    CF_SECRETS_MAX_VALUE_BYTES_ENV, CF_SECRETS_WARN_AT_ENV, DEFAULT_CF_SECRETS_WARN_AT,
};

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result as AnyResult};
use http::Uri;
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::{pem::PemObject, CertificateDer};

/// A parsed secret reference. See the crate-level docs for the supported
/// URI schemes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    Env {
        name: String,
    },
    Vault {
        mount: String,
        path: String,
        field: String,
    },
    /// A Cloudflare Secrets Store reference: `cf://<store>/<name>`, where
    /// `store` is a Secrets Store id (or name) and `name` is the secret's
    /// name. Values resolve from the Worker-binding context
    /// ([`CfSecretBindings`], decision #423); [`CloudflareSecretResolver`]
    /// (issue #417) is the write/manage REST backend.
    CfSecret {
        store: String,
        name: String,
    },
}

impl SecretRef {
    pub fn parse(raw: &str) -> AnyResult<Self> {
        let raw = raw.trim();
        if let Some(name) = raw.strip_prefix("env://") {
            if name.is_empty() {
                bail!(
                    "env:// secret reference requires a variable name, e.g. env://OPENAI_API_KEY"
                );
            }
            return Ok(Self::Env {
                name: name.to_string(),
            });
        }
        if let Some(rest) = raw.strip_prefix("vault://") {
            let (path_part, field) = rest.split_once('#').ok_or_else(|| {
                anyhow::anyhow!(
                    "vault:// secret reference requires a #field suffix, e.g. vault://secret/data/openai#api_key (got {raw})"
                )
            })?;
            let (mount, path) = path_part.split_once('/').ok_or_else(|| {
                anyhow::anyhow!(
                    "vault:// secret reference requires <mount>/<path>, e.g. vault://secret/data/openai#api_key (got {raw})"
                )
            })?;
            if mount.is_empty() || path.is_empty() {
                bail!("vault:// secret reference requires a non-empty mount and path (got {raw})");
            }
            if field.is_empty() {
                bail!("vault:// secret reference requires a non-empty #field (got {raw})");
            }
            return Ok(Self::Vault {
                mount: mount.to_string(),
                path: path.to_string(),
                field: field.to_string(),
            });
        }
        if let Some(rest) = raw.strip_prefix("cf://") {
            let (store, name) = rest.split_once('/').ok_or_else(|| {
                anyhow::anyhow!(
                    "cf:// secret reference requires <store>/<name>, e.g. cf://provider-keys/openai-api-key (got {raw})"
                )
            })?;
            if store.is_empty() || name.is_empty() {
                bail!(
                    "cf:// secret reference requires a non-empty store and name, e.g. cf://provider-keys/openai-api-key (got {raw})"
                );
            }
            return Ok(Self::CfSecret {
                store: store.to_string(),
                name: name.to_string(),
            });
        }
        bail!("unsupported secret reference scheme (expected env://, vault://, or cf://): {raw}");
    }
}

/// Resolves a [`SecretRef`] to its current value. Implementations should
/// return `Ok(None)` for "not found" (e.g. an unset env var) and `Err` only
/// for genuine failures (unreachable Vault, malformed response), so callers
/// can distinguish "not configured" from "broken".
pub trait SecretResolver: std::fmt::Debug + Send + Sync {
    fn resolve(&self, reference: &SecretRef) -> AnyResult<Option<String>>;
}

/// Resolves `env://NAME` references by reading the process environment.
/// This is the default, zero-configuration resolver and preserves exactly
/// the pre-#163 `key_env`/`api_key_env` behavior (empty values treated as
/// unset).
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvSecretResolver;

impl SecretResolver for EnvSecretResolver {
    fn resolve(&self, reference: &SecretRef) -> AnyResult<Option<String>> {
        let SecretRef::Env { name } = reference else {
            bail!("EnvSecretResolver cannot resolve a non-env:// reference: {reference:?}");
        };
        Ok(std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty()))
    }
}

/// Connection details for a HashiCorp Vault server, sourced from the
/// standard `VAULT_ADDR`/`VAULT_TOKEN`/`VAULT_CACERT` environment variables
/// (matching Vault's own CLI conventions) so operators don't need
/// FerroGate-specific configuration to point at an existing Vault install.
///
/// `Debug` is hand-written — following [`crate::SecretRef`]'s neighbors in
/// `ferrogate-cloudflare` (`HttpRequest`, `HttpResponse`, `ResolvedToken`) —
/// because `token` is a **live Vault token**: a credential that reads every
/// secret the mount exposes. A derived `Debug` would render it from any
/// `{:?}` anywhere, and this type is reachable from several of them: the
/// [`SecretResolver`] trait requires `Debug`, [`VaultSecretResolver`] derives
/// it over this struct, and [`SecretResolverRegistry`] derives it over that.
/// So a single `tracing::debug!(?registry)`, `unwrap()` panic, `anyhow` chain
/// or failing assertion would otherwise spill the token (issue #492).
#[derive(Clone)]
pub struct VaultConfig {
    pub address: String,
    pub token: String,
    pub ca_cert_path: Option<String>,
    pub timeout: Duration,
}

impl std::fmt::Debug for VaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultConfig")
            .field("address", &self.address)
            .field("token", &"<redacted>")
            .field("ca_cert_path", &self.ca_cert_path)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl VaultConfig {
    /// Reads `VAULT_ADDR`, `VAULT_TOKEN`, and optionally `VAULT_CACERT` from
    /// the environment. Returns `None` if `VAULT_ADDR` or `VAULT_TOKEN` is
    /// unset/empty, so callers can treat "no Vault configured" as a normal,
    /// non-error case.
    pub fn from_env() -> Option<Self> {
        let address = non_empty_env("VAULT_ADDR")?;
        let token = non_empty_env("VAULT_TOKEN")?;
        Some(Self {
            address,
            token,
            ca_cert_path: non_empty_env("VAULT_CACERT"),
            timeout: Duration::from_secs(5),
        })
    }
}

pub(crate) fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// Resolves `vault://<mount>/<path>#<field>` references against a HashiCorp
/// Vault KV v2 secrets engine via a single authenticated `GET
/// {mount}/data/{path}` request.
#[derive(Debug, Clone)]
pub struct VaultSecretResolver {
    config: VaultConfig,
}

impl VaultSecretResolver {
    pub fn new(config: VaultConfig) -> Self {
        Self { config }
    }
}

impl SecretResolver for VaultSecretResolver {
    fn resolve(&self, reference: &SecretRef) -> AnyResult<Option<String>> {
        let SecretRef::Vault { mount, path, field } = reference else {
            bail!("VaultSecretResolver cannot resolve a non-vault:// reference: {reference:?}");
        };
        let url = format!(
            "{}/v1/{mount}/data/{path}",
            self.config.address.trim_end_matches('/')
        );
        let body = http_get(
            &url,
            &[("X-Vault-Token".to_string(), self.config.token.clone())],
            self.config.timeout,
            self.config.ca_cert_path.as_deref(),
        )
        .with_context(|| format!("failed to read Vault secret {mount}/{path}"))?;
        let json: serde_json::Value =
            serde_json::from_slice(&body).context("invalid Vault response JSON")?;
        if let Some(errors) = json.get("errors").and_then(|value| value.as_array()) {
            if !errors.is_empty() {
                bail!("Vault returned errors for {mount}/{path}: {errors:?}");
            }
        }
        Ok(json["data"]["data"][field]
            .as_str()
            .map(|value| value.to_string()))
    }
}

// The Cloudflare Secrets Store backend lives in `cloudflare.rs`
// (REST write/manage plane) and `cloudflare_bindings.rs` (Worker-binding
// value resolution) — see the re-exports at the top of this file.

/// Dispatches a `secret_ref` string to the right backend: `env://` always
/// resolves via [`EnvSecretResolver`]; `vault://` requires a configured
/// [`VaultSecretResolver`]; `cf://` resolves through the always-installed
/// Worker-binding context ([`CfSecretBindings`], decision #423) first, then
/// falls back to the configured [`CloudflareSecretResolver`] (write/manage
/// REST backend, via [`SecretResolverRegistry::from_env`] or the `with_*`
/// constructors) whose existence check yields `Ok(None)` for a missing secret
/// and a precise unsupported-resolve error for an existing one. A reference
/// whose backend is not configured fails clearly rather than silently
/// returning `None`.
#[derive(Debug, Default)]
pub struct SecretResolverRegistry {
    vault: Option<VaultSecretResolver>,
    cloudflare: Option<CloudflareSecretResolver>,
    /// Worker-binding value context for `cf://` references. Always present
    /// (the default consults only the `FERROGATE_CF_SECRET_*` environment
    /// convention), like [`EnvSecretResolver`] for `env://`.
    cf_bindings: CfSecretBindings,
}

impl SecretResolverRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_vault(vault: VaultSecretResolver) -> Self {
        Self {
            vault: Some(vault),
            ..Self::default()
        }
    }

    /// Enable the Cloudflare Secrets Store REST (write/manage + existence
    /// check) backend on this registry.
    pub fn with_cloudflare(mut self, cloudflare: CloudflareSecretResolver) -> Self {
        self.cloudflare = Some(cloudflare);
        self
    }

    /// Replace the Worker-binding context consulted for `cf://` value
    /// resolution (decision #423) — e.g. a [`CfSecretBindings::from_map`]
    /// built by embedding glue that holds the bound values directly. The
    /// default context already honors the `FERROGATE_CF_SECRET_*` environment
    /// convention, so this is only needed for direct injection.
    pub fn with_cf_bindings(mut self, bindings: CfSecretBindings) -> Self {
        self.cf_bindings = bindings;
        self
    }

    /// Builds a registry with backends enabled from the environment: Vault when
    /// `VAULT_ADDR` + `VAULT_TOKEN` are set, and the Cloudflare Secrets Store
    /// manage plane when `CLOUDFLARE_ACCOUNT_ID` + `CLOUDFLARE_API_TOKEN` are
    /// set. The `cf://` Worker-binding value convention
    /// (`FERROGATE_CF_SECRET_*`) is always active and needs neither variable.
    /// A Cloudflare config that is present but whose client cannot be built is
    /// logged and treated as "not configured" (the `cf://` path then errors
    /// clearly unless a binding provides the value).
    pub fn from_env() -> Self {
        let vault = VaultConfig::from_env().map(VaultSecretResolver::new);
        let cloudflare = CfSecretsStoreConfig::from_env().and_then(|config| {
            match CloudflareSecretResolver::new(config) {
                Ok(resolver) => Some(resolver),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "Cloudflare Secrets Store is configured but its client could not be built; cf:// references will error"
                    );
                    None
                }
            }
        });
        Self {
            vault,
            cloudflare,
            cf_bindings: CfSecretBindings::default(),
        }
    }

    pub fn resolve(&self, raw: &str) -> AnyResult<Option<String>> {
        let reference = SecretRef::parse(raw)?;
        match &reference {
            SecretRef::Env { .. } => EnvSecretResolver.resolve(&reference),
            SecretRef::Vault { .. } => match &self.vault {
                Some(resolver) => resolver.resolve(&reference),
                None => bail!(
                    "secret reference {raw} requires Vault, but VAULT_ADDR/VAULT_TOKEN are not configured"
                ),
            },
            SecretRef::CfSecret { name, .. } => {
                // Decision #423: the Worker-binding context is the only path
                // that can produce a Secrets Store value (values are
                // write-only over REST), so it is consulted first — no
                // network, no API token needed.
                if let Some(value) = self.cf_bindings.resolve(&reference)? {
                    return Ok(Some(value));
                }
                match &self.cloudflare {
                    Some(resolver) => resolver.resolve(&reference),
                    None => bail!(
                        "cf:// secret {raw} could not be resolved: no Worker-binding value found \
                         (checked the {} environment variable and the injected binding map; see \
                         docs/cloudflare-secrets-resolution.md), and the Cloudflare Secrets Store \
                         REST backend is not configured (set CLOUDFLARE_ACCOUNT_ID + \
                         CLOUDFLARE_API_TOKEN to enable existence checks — note Secrets Store \
                         values are write-only over REST and can never be fetched at load time)",
                        cf_binding_env_var(name)
                    ),
                }
            }
        }
    }
}

/// rustls 0.23 requires selecting a process-wide default `CryptoProvider`
/// once more than one crypto backend is compiled into the binary — which
/// happens here because `ferrogate-auth` depends on `rustls` with the
/// `ring` feature while this crate uses the default `aws-lc-rs` backend.
/// Installing the default explicitly and idempotently avoids the "Could not
/// automatically determine the process-level CryptoProvider" panic in any
/// binary/test that links both.
fn ensure_rustls_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn tls_client_config(ca_cert_path: Option<&str>) -> AnyResult<Arc<ClientConfig>> {
    ensure_rustls_crypto_provider();
    let mut roots = RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    if !native_certs.errors.is_empty() {
        bail!(
            "failed to load platform native certificates: {:?}",
            native_certs.errors
        );
    }
    for cert in native_certs.certs {
        let _ = roots.add(cert);
    }
    if let Some(path) = ca_cert_path {
        let bytes =
            std::fs::read(path).with_context(|| format!("failed to read CA cert {path}"))?;
        let certs = CertificateDer::pem_reader_iter(&mut bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("failed to parse CA cert {path} as PEM"))?;
        for cert in certs {
            roots
                .add(cert)
                .with_context(|| format!("failed to trust certificate from {path}"))?;
        }
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Performs a single `GET` request and returns the response body. Supports
/// both `http://` and `https://` (real TLS via rustls); fails clearly on
/// anything else. General-purpose enough to be reused by any FerroGate
/// crate that needs a minimal, dependency-light HTTP client (matching the
/// pattern already used by `ferrogate-cli`'s `telemetry.rs`/`acme.rs` and
/// `ferrogate-mcp`) rather than pulling in `reqwest`/a full async runtime.
pub fn http_get(
    url: &str,
    headers: &[(String, String)],
    timeout: Duration,
    ca_cert_path: Option<&str>,
) -> AnyResult<Vec<u8>> {
    http_request("GET", url, headers, None, timeout, ca_cert_path)
}

/// Performs a single `POST` request with a raw body and returns the
/// response body. Callers set `Content-Type` themselves via `headers` (form-
/// encoded for OAuth/OIDC token exchange, JSON for most other APIs).
pub fn http_post(
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    timeout: Duration,
    ca_cert_path: Option<&str>,
) -> AnyResult<Vec<u8>> {
    http_request("POST", url, headers, Some(body), timeout, ca_cert_path)
}

fn http_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    timeout: Duration,
    ca_cert_path: Option<&str>,
) -> AnyResult<Vec<u8>> {
    let uri: Uri = url.parse().with_context(|| format!("invalid URL {url}"))?;
    let is_https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => bail!("URL must use http or https: {url}"),
    };
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("URL must include a host: {url}"))?;
    let host = authority.host().to_string();
    let port = authority
        .port_u16()
        .unwrap_or(if is_https { 443 } else { 80 });
    let path_query = uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let address = (host.as_str(), port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve {host}:{port}"))?;

    let tcp = TcpStream::connect_timeout(&address, timeout)
        .with_context(|| format!("failed to connect to {host}:{port}"))?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;

    if is_https {
        let server_name = ServerName::try_from(host.clone())
            .with_context(|| format!("invalid TLS server name {host}"))?;
        let config = tls_client_config(ca_cert_path)?;
        let connection = ClientConnection::new(config, server_name)
            .context("failed to initialize TLS client")?;
        let mut stream = StreamOwned::new(connection, tcp);
        send_http_request(&mut stream, method, &host, port, &path_query, headers, body)
    } else {
        let mut stream = tcp;
        send_http_request(&mut stream, method, &host, port, &path_query, headers, body)
    }
}

fn send_http_request<S: Read + Write>(
    stream: &mut S,
    method: &str,
    host: &str,
    port: u16,
    path_query: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> AnyResult<Vec<u8>> {
    let host_header = if (port == 80) || (port == 443) {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    write!(
        stream,
        "{method} {path_query} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nAccept: application/json\r\n"
    )?;
    if let Some(body) = body {
        write!(stream, "Content-Length: {}\r\n", body.len())?;
    }
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "\r\n")?;
    if let Some(body) = body {
        stream.write_all(body)?;
    }
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    if reader.read_line(&mut status_line)? == 0 {
        bail!("connection closed before sending a response");
    }
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP response status line: {status_line}"))?;

    let mut content_length = None;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().ok();
            }
        }
    }

    let mut raw = Vec::new();
    match content_length {
        Some(len) => {
            raw.resize(len, 0);
            reader.read_exact(&mut raw)?;
        }
        None => {
            reader.read_to_end(&mut raw)?;
        }
    }

    if !(200..300).contains(&status) {
        bail!(
            "request failed with HTTP {status}: {}",
            String::from_utf8_lossy(&raw)
        );
    }
    Ok(raw)
}

#[cfg(test)]
#[path = "cloudflare_test.rs"]
mod cloudflare_test;

#[cfg(test)]
#[path = "cloudflare_caps_test.rs"]
mod cloudflare_caps_test;

#[cfg(test)]
#[path = "vault_debug_test.rs"]
mod vault_debug_test;

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::CertifiedKey;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn parses_env_reference() {
        let reference = SecretRef::parse("env://OPENAI_API_KEY").unwrap();
        assert_eq!(
            reference,
            SecretRef::Env {
                name: "OPENAI_API_KEY".into()
            }
        );
    }

    #[test]
    fn rejects_empty_env_reference() {
        assert!(SecretRef::parse("env://").is_err());
    }

    #[test]
    fn parses_vault_reference() {
        let reference = SecretRef::parse("vault://secret/data/openai#api_key").unwrap();
        assert_eq!(
            reference,
            SecretRef::Vault {
                mount: "secret".into(),
                path: "data/openai".into(),
                field: "api_key".into(),
            }
        );
    }

    #[test]
    fn rejects_vault_reference_missing_field() {
        assert!(SecretRef::parse("vault://secret/data/openai").is_err());
    }

    #[test]
    fn rejects_vault_reference_missing_path() {
        assert!(SecretRef::parse("vault://secret#api_key").is_err());
    }

    #[test]
    fn rejects_unsupported_scheme() {
        let error = SecretRef::parse("aws-sm://foo").unwrap_err().to_string();
        assert!(error.contains("env://, vault://, or cf://"));
    }

    #[test]
    fn env_resolver_reads_and_ignores_empty_values() {
        std::env::set_var("FERROGATE_SECRETS_TEST_KEY", "s3cr3t");
        let reference = SecretRef::Env {
            name: "FERROGATE_SECRETS_TEST_KEY".into(),
        };
        assert_eq!(
            EnvSecretResolver.resolve(&reference).unwrap().as_deref(),
            Some("s3cr3t")
        );

        std::env::set_var("FERROGATE_SECRETS_TEST_EMPTY", "");
        let empty_reference = SecretRef::Env {
            name: "FERROGATE_SECRETS_TEST_EMPTY".into(),
        };
        assert_eq!(EnvSecretResolver.resolve(&empty_reference).unwrap(), None);
    }

    #[test]
    fn registry_resolves_env_without_vault_configured() {
        std::env::set_var("FERROGATE_SECRETS_TEST_REGISTRY", "value-1");
        let registry = SecretResolverRegistry::new();
        assert_eq!(
            registry
                .resolve("env://FERROGATE_SECRETS_TEST_REGISTRY")
                .unwrap()
                .as_deref(),
            Some("value-1")
        );
    }

    #[test]
    fn registry_errors_on_vault_reference_without_vault_configured() {
        let registry = SecretResolverRegistry::new();
        let error = registry
            .resolve("vault://secret/data/openai#api_key")
            .unwrap_err()
            .to_string();
        assert!(error.contains("VAULT_ADDR"));
    }

    fn spawn_https_json_server(
        cert_der: rustls::pki_types::CertificateDer<'static>,
        key_der: Vec<u8>,
        response_json: String,
    ) -> std::net::SocketAddr {
        // Must run before any rustls ClientConfig/ServerConfig builder in
        // this process — see `ensure_rustls_crypto_provider` above.
        ensure_rustls_crypto_provider();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)
            .expect("valid self-signed test certificate");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut tls_stream = StreamOwned::new(conn, tcp);
            let mut received = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = Read::read(&mut tls_stream, &mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..n]);
                if received.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_json.len(),
                response_json
            );
            tls_stream.write_all(response.as_bytes()).unwrap();
            tls_stream.flush().unwrap();
        });
        addr
    }

    #[test]
    fn vault_resolver_reads_kv2_field_over_real_tls() {
        let CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, cert.pem()).unwrap();

        let vault_response = serde_json::json!({
            "data": {
                "data": {"api_key": "sk-from-vault"}
            }
        })
        .to_string();
        let addr = spawn_https_json_server(
            cert.der().clone(),
            signing_key.serialize_der(),
            vault_response,
        );

        let resolver = VaultSecretResolver::new(VaultConfig {
            address: format!("https://{addr}"),
            token: "test-token".into(),
            ca_cert_path: Some(ca_path.to_string_lossy().into_owned()),
            timeout: Duration::from_secs(5),
        });
        let reference = SecretRef::Vault {
            mount: "secret".into(),
            path: "data/openai".into(),
            field: "api_key".into(),
        };
        let value = resolver.resolve(&reference).unwrap();
        assert_eq!(value.as_deref(), Some("sk-from-vault"));
    }

    #[test]
    fn vault_resolver_returns_none_for_missing_field() {
        let CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, cert.pem()).unwrap();

        let vault_response = serde_json::json!({"data": {"data": {}}}).to_string();
        let addr = spawn_https_json_server(
            cert.der().clone(),
            signing_key.serialize_der(),
            vault_response,
        );

        let resolver = VaultSecretResolver::new(VaultConfig {
            address: format!("https://{addr}"),
            token: "test-token".into(),
            ca_cert_path: Some(ca_path.to_string_lossy().into_owned()),
            timeout: Duration::from_secs(5),
        });
        let reference = SecretRef::Vault {
            mount: "secret".into(),
            path: "data/openai".into(),
            field: "missing_field".into(),
        };
        assert_eq!(resolver.resolve(&reference).unwrap(), None);
    }
}
