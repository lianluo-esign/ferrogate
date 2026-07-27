// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Cloudflare Worker branch of the gateway function egress broker (#435).
//!
//! Mirrors `function_egress.rs` (the Supabase branch) for a hosted Cloudflare
//! Worker target: the operator declares the target platform with the
//! `FG_FN_TARGET_KIND` discriminant and the Worker itself (including its
//! secret-ref credential) with `FG_FN_CF_WORKER`, and `/v1/functions/execute`
//! then dispatches to the runtime's governed Worker pipeline
//! ([`prepare_governed_worker_invocation`], landed in #416) instead of the
//! Supabase builder. Exactly one branch is active per process — the
//! discriminant is the same fail-closed single-credential rule as the
//! Supabase single-project enforcement (TOK-6).
//!
//! Environment surface (all `FG_FN_*`, shared names reused where semantics
//! are identical):
//! - `FG_FN_TARGET_KIND`: `supabase` (default when unset) or
//!   `cloudflare_worker`; any other value disables both branches (fail-closed).
//! - `FG_FN_JWT_SECRET`: reused — signs the short-lived scoped bearer JWT.
//! - `FG_FN_CF_WORKER`: JSON [`CloudflareWorkerTarget`]
//!   (`{"base_url","invoke_path","auth_key_ref"}`), validated fail-closed;
//!   `auth_key_ref` is the operator-declared secret reference (reserved, not
//!   yet dereferenced — parity with the Supabase `auth_key_ref`).
//! - `FG_FN_ALLOWLIST`: reused — per-tenant rules whose `function_slugs` match
//!   the Worker `invoke_path`; every rule must point at the configured Worker
//!   `base_url` (single-worker rule, mirroring TOK-6).
//! - `FG_FN_APIKEY`: Supabase-only; Workers have no apikey concept and the
//!   Worker request never emits that header.

use std::sync::OnceLock;

use ferrogate_runtime::{
    prepare_governed_worker_invocation, CloudflareWorkerTarget, EdgeFunctionHttpRequest,
    FunctionEgressAllowlist, FunctionEgressRule, FunctionTokenMinter, WorkerBrokerError,
    WorkerInvocationRequest, DEFAULT_FUNCTION_TOKEN_TTL_SECS,
};

use super::function_egress::{normalize_base_url, FUNCTION_TOKEN_ISSUER};

/// Which hosted-function platform the `/v1/functions/execute` broker targets —
/// the `FG_FN_TARGET_KIND` config discriminant (#435).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FunctionTargetKind {
    /// Supabase edge functions — the default, preserving pre-#435 behavior.
    Supabase,
    /// A hosted Cloudflare Worker declared via `FG_FN_CF_WORKER`.
    CloudflareWorker,
}

/// Parse the target-kind discriminant. Absent/blank means Supabase (the
/// pre-#435 default); an unknown value returns `None` so BOTH broker branches
/// stay disabled (fail-closed) instead of silently falling back to Supabase
/// with credentials the operator meant for another platform.
pub(crate) fn parse_function_target_kind(value: Option<&str>) -> Option<FunctionTargetKind> {
    match value.map(str::trim) {
        None | Some("") | Some("supabase") => Some(FunctionTargetKind::Supabase),
        Some("cloudflare_worker") => Some(FunctionTargetKind::CloudflareWorker),
        Some(other) => {
            tracing::warn!(
                target_kind = other,
                "function egress broker disabled: FG_FN_TARGET_KIND must be \
                 'supabase' or 'cloudflare_worker'"
            );
            None
        }
    }
}

/// Read the discriminant from the environment.
pub(crate) fn env_function_target_kind() -> Option<FunctionTargetKind> {
    parse_function_target_kind(std::env::var("FG_FN_TARGET_KIND").ok().as_deref())
}

/// Runtime configuration for the Cloudflare Worker function egress branch —
/// the Worker-side mirror of `FunctionEgressGatewayConfig`. Sourced from the
/// environment; the signing secret is resolved at runtime and never persisted
/// to the control-plane DB. Disabled (fail-closed) unless the operator
/// explicitly selected the Cloudflare kind AND declared a valid Worker target.
pub(crate) struct CloudflareFunctionEgressGatewayConfig {
    allowlist: FunctionEgressAllowlist,
    minter: FunctionTokenMinter,
    /// The operator-declared Worker target. Its `auth_key_ref` is the
    /// authoritative secret reference for the credential (reserved, not yet
    /// dereferenced); the wire request's `auth_key_ref` is never trusted.
    worker: CloudflareWorkerTarget,
}

impl CloudflareFunctionEgressGatewayConfig {
    /// Load from the environment. Returns `None` (branch disabled) unless
    /// `FG_FN_TARGET_KIND=cloudflare_worker`, a signing secret is configured,
    /// and `FG_FN_CF_WORKER` declares a valid Worker target.
    pub(crate) fn from_env() -> Option<Self> {
        Self::from_values(
            std::env::var("FG_FN_TARGET_KIND").ok(),
            std::env::var("FG_FN_JWT_SECRET").ok(),
            std::env::var("FG_FN_CF_WORKER").ok(),
            std::env::var("FG_FN_ALLOWLIST").ok(),
        )
    }

    fn from_values(
        target_kind: Option<String>,
        signing_secret: Option<String>,
        worker_json: Option<String>,
        allowlist_json: Option<String>,
    ) -> Option<Self> {
        if parse_function_target_kind(target_kind.as_deref())
            != Some(FunctionTargetKind::CloudflareWorker)
        {
            return None;
        }
        let signing_secret = signing_secret.filter(|value| !value.trim().is_empty())?;
        let worker_json = worker_json.filter(|value| !value.trim().is_empty())?;
        let worker: CloudflareWorkerTarget = match serde_json::from_str(&worker_json) {
            Ok(worker) => worker,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "cloudflare function egress branch disabled: FG_FN_CF_WORKER is not valid JSON"
                );
                return None;
            }
        };
        // Config-time validation (fail-closed): https-only base, clean
        // single-segment invoke path, non-empty secret-ref credential — the
        // same rules the runtime enforces per call, surfaced at startup.
        if let Err(error) = worker.validate() {
            tracing::warn!(
                error = %error,
                "cloudflare function egress branch disabled: FG_FN_CF_WORKER is not a valid \
                 worker target"
            );
            return None;
        }
        let minter = FunctionTokenMinter::new(FUNCTION_TOKEN_ISSUER, signing_secret).ok()?;
        let rules: Vec<FunctionEgressRule> = match allowlist_json {
            Some(json) => match serde_json::from_str(&json) {
                Ok(rules) => rules,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "cloudflare function egress branch disabled: FG_FN_ALLOWLIST is not \
                         valid JSON"
                    );
                    return None;
                }
            },
            None => Vec::new(),
        };
        // Single-worker enforcement, mirroring the Supabase single-project rule
        // (TOK-6): one process-wide signing secret and one declared Worker
        // target mean an allowlist rule pointing at any other base_url could
        // never be served coherently — refuse to enable rather than misroute.
        let worker_base = normalize_base_url(&worker.base_url);
        if rules
            .iter()
            .any(|rule| normalize_base_url(&rule.base_url) != worker_base)
        {
            tracing::warn!(
                "cloudflare function egress branch disabled: FG_FN_ALLOWLIST lists a base_url \
                 other than the FG_FN_CF_WORKER target. List rules for the declared worker \
                 base_url only."
            );
            return None;
        }
        Some(Self {
            allowlist: FunctionEgressAllowlist::new(rules),
            minter,
            worker,
        })
    }
}

/// Process-wide Cloudflare branch config, resolved once from the environment —
/// the Worker-side mirror of `function_egress_config`.
pub(crate) fn cloudflare_function_egress_config(
) -> Option<&'static CloudflareFunctionEgressGatewayConfig> {
    static CONFIG: OnceLock<Option<CloudflareFunctionEgressGatewayConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(CloudflareFunctionEgressGatewayConfig::from_env)
        .as_ref()
}

/// Fail-closed pipeline for the Cloudflare branch — the Worker-side mirror of
/// `prepare_brokered_invocation`: authorize the target against the tenant's
/// allowlist, mint a short-lived scoped token, and build the governed HTTP
/// request (runtime pipeline from #416). Returns the request, the invoke path
/// for the outcome/audit record, and the timeout. No network I/O.
pub(crate) fn prepare_cloudflare_invocation(
    config: &CloudflareFunctionEgressGatewayConfig,
    tenant: &str,
    request: &WorkerInvocationRequest,
    now_unix: u64,
) -> Result<(EdgeFunctionHttpRequest, String, u64), WorkerBrokerError> {
    // The configured secret-ref is authoritative: whatever `auth_key_ref` the
    // wire request carries is replaced with the operator-declared one before
    // the governed pipeline runs, so a (future) credential dereference can
    // never be steered by the caller.
    let mut governed = request.clone();
    governed.target.auth_key_ref = config.worker.auth_key_ref.clone();
    let prepared = prepare_governed_worker_invocation(
        &config.allowlist,
        &config.minter,
        tenant,
        &governed,
        now_unix,
        DEFAULT_FUNCTION_TOKEN_TTL_SECS,
    )?;
    Ok((
        prepared.http_request,
        prepared.invoke_path,
        prepared.timeout_millis,
    ))
}

#[cfg(test)]
#[path = "function_egress_cloudflare_test.rs"]
mod function_egress_cloudflare_test;
