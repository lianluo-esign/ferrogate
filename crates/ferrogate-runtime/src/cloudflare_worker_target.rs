// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Cloudflare Worker hosted-function invocation entry with governed egress (#416).
//!
//! Mirrors the Supabase edge-function target (`supabase_edge_function.rs`): a
//! deployed Worker at `https://<worker>.<account>.workers.dev/<path>` (or a
//! custom-domain route base) is modeled as a validated, fail-closed target, and
//! the governed HTTP request — `Authorization: Bearer …` from a
//! [`FunctionCredential`] resolved at call time — is built purely and testably.
//!
//! Governance is *identical* to the Supabase path by construction:
//! [`prepare_governed_worker_invocation`] composes the same fail-closed
//! pipeline (per-tenant [`FunctionEgressAllowlist`] authorize → mint a scoped
//! [`FunctionTokenMinter`] JWT → build the request) and emits the same
//! transport-agnostic [`EdgeFunctionHttpRequest`] the gateway's TLS egress
//! executor already runs, so a Cloudflare-hosted function clears the same
//! allowlist/auth/policy gates as a Supabase edge function.
//!
//! Deploying the target Worker is out of scope: the Worker is operator-provided
//! (or deployed via the existing `cloudflare_gateway_deploy` plumbing).

use serde::{Deserialize, Serialize};

use crate::function_egress::{FunctionEgressAllowlist, FunctionEgressDenied};
use crate::function_token::{FunctionTokenError, FunctionTokenMinter};
use crate::supabase_edge_function::{EdgeFunctionHttpRequest, FunctionCredential};

/// Default per-call timeout for a Worker invocation (parity with the
/// edge-function default).
pub const DEFAULT_WORKER_INVOCATION_TIMEOUT_MILLIS: u64 = 30_000;

/// Capability recorded in the minted scoped token — the same capability the
/// Supabase broker records, so Worker-side and edge-function-side authorization
/// see one uniform claim shape.
pub const WORKER_FUNCTION_CAPABILITY: &str = "function";

/// Where a hosted Cloudflare Worker function lives and how to authenticate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareWorkerTarget {
    /// Worker base URL, e.g. `https://my-worker.my-account.workers.dev` or a
    /// custom-domain route base (no trailing slash required).
    pub base_url: String,
    /// Invocation path segment under the base, e.g. `run-tool`. Must be a
    /// single clean path segment (no traversal / nesting / query), exactly like
    /// the Supabase function slug — this is what the egress allowlist matches.
    pub invoke_path: String,
    /// Reference (id) of the stored secret that holds the bearer credential;
    /// never the raw key itself.
    ///
    /// **Reserved — not yet dereferenced**, matching
    /// `SupabaseEdgeFunctionTarget::auth_key_ref`: validated non-empty
    /// (fail-closed), but the broker currently sources credentials from its
    /// process-wide config. Per-tenant secret-store resolution is deferred with
    /// the multi-project credential work.
    pub auth_key_ref: String,
}

/// A concrete, governed invocation of a Cloudflare Worker function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareWorkerInvocation {
    pub target: CloudflareWorkerTarget,
    /// HTTP method; Worker function handlers are POST by default.
    pub method: String,
    /// JSON request body (already serialized). Empty string means no body.
    pub body_json: String,
    pub timeout_millis: u64,
}

/// Fail-closed validation errors for a Worker target/invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflareWorkerTargetError {
    InsecureBaseUrl(String),
    EmptyBaseUrl,
    InvalidInvokePath(String),
    EmptyAuthKeyRef,
    UnsupportedMethod(String),
    EmptyResolvedBearer,
}

impl std::fmt::Display for CloudflareWorkerTargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsecureBaseUrl(url) => {
                write!(f, "worker base_url must be https: {url}")
            }
            Self::EmptyBaseUrl => write!(f, "worker base_url must not be empty"),
            Self::InvalidInvokePath(path) => write!(
                f,
                "worker invoke_path must be a single non-empty path segment: {path}"
            ),
            Self::EmptyAuthKeyRef => write!(f, "worker auth_key_ref must not be empty"),
            Self::UnsupportedMethod(method) => {
                write!(f, "worker method not allowed: {method}")
            }
            Self::EmptyResolvedBearer => {
                write!(f, "resolved worker bearer credential must not be empty")
            }
        }
    }
}

impl std::error::Error for CloudflareWorkerTargetError {}

const ALLOWED_METHODS: [&str; 2] = ["POST", "GET"];

impl CloudflareWorkerTarget {
    /// Validate the target, fail-closed. Enforces https, a clean single-segment
    /// invoke path (no traversal / query / nested paths), and a non-empty key
    /// reference — the same rules the Supabase target enforces on its slug.
    pub fn validate(&self) -> Result<(), CloudflareWorkerTargetError> {
        let base = self.base_url.trim();
        if base.is_empty() {
            return Err(CloudflareWorkerTargetError::EmptyBaseUrl);
        }
        if !base.starts_with("https://") {
            return Err(CloudflareWorkerTargetError::InsecureBaseUrl(
                base.to_string(),
            ));
        }
        let path = self.invoke_path.trim();
        if path.is_empty()
            || path.contains('/')
            || path.contains('?')
            || path.contains('#')
            || path.contains("..")
            || path.contains(char::is_whitespace)
        {
            return Err(CloudflareWorkerTargetError::InvalidInvokePath(
                self.invoke_path.clone(),
            ));
        }
        if self.auth_key_ref.trim().is_empty() {
            return Err(CloudflareWorkerTargetError::EmptyAuthKeyRef);
        }
        Ok(())
    }

    /// Fully-qualified invocation URL: `{base}/{invoke_path}`.
    pub fn invocation_url(&self) -> String {
        format!(
            "{}/{}",
            self.base_url.trim().trim_end_matches('/'),
            self.invoke_path.trim()
        )
    }
}

impl CloudflareWorkerInvocation {
    /// Construct a POST invocation with the default timeout.
    pub fn post(target: CloudflareWorkerTarget, body_json: impl Into<String>) -> Self {
        Self {
            target,
            method: "POST".to_string(),
            body_json: body_json.into(),
            timeout_millis: DEFAULT_WORKER_INVOCATION_TIMEOUT_MILLIS,
        }
    }

    fn normalized_method(&self) -> Result<String, CloudflareWorkerTargetError> {
        let method = self.method.trim().to_ascii_uppercase();
        if ALLOWED_METHODS.contains(&method.as_str()) {
            Ok(method)
        } else {
            Err(CloudflareWorkerTargetError::UnsupportedMethod(
                self.method.clone(),
            ))
        }
    }

    /// Build the governed HTTP request. Only `credential.bearer_token` is
    /// consumed — a minted scoped JWT ([`FunctionCredential::scoped_token`]) or
    /// an interim static key ([`FunctionCredential::static_key`]) — and it is
    /// injected into the `Authorization` header at build time, never stored
    /// elsewhere. Workers have no Supabase `apikey` concept, so no `apikey`
    /// header is emitted. Returns the same [`EdgeFunctionHttpRequest`] shape the
    /// gateway's TLS egress executor already accepts, so execution is shared
    /// with the Supabase path.
    pub fn build_http_request(
        &self,
        credential: &FunctionCredential,
    ) -> Result<EdgeFunctionHttpRequest, CloudflareWorkerTargetError> {
        self.target.validate()?;
        let method = self.normalized_method()?;
        if credential.bearer_token.trim().is_empty() {
            return Err(CloudflareWorkerTargetError::EmptyResolvedBearer);
        }
        let mut headers = std::collections::BTreeMap::new();
        headers.insert(
            "authorization".to_string(),
            format!("Bearer {}", credential.bearer_token),
        );
        headers.insert("content-type".to_string(), "application/json".to_string());
        Ok(EdgeFunctionHttpRequest {
            method,
            url: self.target.invocation_url(),
            headers,
            body: self.body_json.clone(),
        })
    }
}

/// The request an agent/worker sends to invoke a hosted Worker function via the
/// broker (no secrets) — the Cloudflare mirror of `FunctionInvocationRequest`.
///
/// `tenant` is advisory only — the gateway attributes the call to the
/// authenticated identity, never this field — so it is optional on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerInvocationRequest {
    #[serde(default)]
    pub tenant: String,
    pub target: CloudflareWorkerTarget,
    #[serde(default = "default_invocation_method")]
    pub method: String,
    #[serde(default)]
    pub body_json: String,
}

fn default_invocation_method() -> String {
    "POST".to_string()
}

/// Why the broker rejected a governed Worker invocation before executing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerBrokerError {
    Denied(FunctionEgressDenied),
    Token(FunctionTokenError),
    Build(CloudflareWorkerTargetError),
}

impl std::fmt::Display for WorkerBrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(error) => write!(f, "{error}"),
            Self::Token(error) => write!(f, "{error}"),
            Self::Build(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for WorkerBrokerError {}

/// The ready-to-execute result of the fail-closed Worker broker pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedWorkerInvocation {
    /// The governed request, in the shared executor shape. Carries the bearer;
    /// never logged.
    pub http_request: EdgeFunctionHttpRequest,
    /// The invoke path, for the invocation outcome/audit record.
    pub invoke_path: String,
    pub timeout_millis: u64,
}

/// Fail-closed pipeline for a Cloudflare-hosted function — the exact governance
/// sequence the Supabase broker runs (`prepare_brokered_invocation`): authorize
/// the target against the tenant's egress allowlist, mint a short-lived scoped
/// token bound to this tenant + invoke path, and build the governed HTTP
/// request. Deny-by-default at every step; no network I/O.
pub fn prepare_governed_worker_invocation(
    allowlist: &FunctionEgressAllowlist,
    minter: &FunctionTokenMinter,
    tenant: &str,
    request: &WorkerInvocationRequest,
    now_unix: u64,
    token_ttl_secs: u64,
) -> Result<PreparedWorkerInvocation, WorkerBrokerError> {
    allowlist
        .authorize_cloudflare_worker(tenant, &request.target)
        .map_err(WorkerBrokerError::Denied)?;

    let invoke_path = request.target.invoke_path.trim().to_string();
    let token = minter
        .mint(
            tenant,
            &invoke_path,
            WORKER_FUNCTION_CAPABILITY,
            now_unix,
            token_ttl_secs,
        )
        .map_err(WorkerBrokerError::Token)?;

    // Workers consume only the bearer; the Supabase-specific apikey slot is
    // intentionally left empty and is never emitted as a header.
    let credential = FunctionCredential::scoped_token(token, String::new());
    let invocation = CloudflareWorkerInvocation {
        target: request.target.clone(),
        method: request.method.clone(),
        body_json: request.body_json.clone(),
        timeout_millis: DEFAULT_WORKER_INVOCATION_TIMEOUT_MILLIS,
    };
    let timeout_millis = invocation.timeout_millis;
    let http_request = invocation
        .build_http_request(&credential)
        .map_err(WorkerBrokerError::Build)?;
    Ok(PreparedWorkerInvocation {
        http_request,
        invoke_path,
        timeout_millis,
    })
}

#[cfg(test)]
#[path = "cloudflare_worker_target_test.rs"]
mod cloudflare_worker_target_test;
