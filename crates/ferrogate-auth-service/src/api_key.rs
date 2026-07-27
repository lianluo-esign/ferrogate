// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Virtual API key material, hashing, and the storage-backed authenticator
//! shared with the gateway's virtual-key surface (issue #157).

use blake2::{Blake2b512, Digest};
use ferrogate_core::TenantContext;
use ferrogate_storage::{RuntimeStorageRepositories, StoredApiKey};
use sha2::Sha256;
use std::sync::Arc;

use crate::rbac::{AuthDecision, PolicySubject};
use crate::util::{
    block_on_sync_bridge, constant_time_eq, encode_hex, generate_random_hex, now_unix_seconds,
};

const VIRTUAL_API_KEY_PREFIX_CHARS: usize = 16;

pub trait ApiKeyAuthenticator: Send + Sync {
    fn authenticate(&self, presented_key: &str) -> Option<AuthDecision>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualApiKeyMaterial {
    pub key_prefix: String,
    pub key_hash: String,
    pub last4: String,
}

pub fn virtual_api_key_material(secret: &str) -> Option<VirtualApiKeyMaterial> {
    let secret = secret.trim();
    if secret.is_empty() {
        return None;
    }
    Some(VirtualApiKeyMaterial {
        key_prefix: virtual_api_key_prefix(secret)?,
        key_hash: hash_virtual_api_key_secret(secret),
        last4: secret
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect(),
    })
}

pub fn hash_virtual_api_key_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.trim().as_bytes());
    format!("sha256:{}", encode_hex(&digest))
}

#[derive(Clone)]
pub struct StorageApiKeyAuthenticator {
    repositories: Arc<RuntimeStorageRepositories>,
    now_unix_seconds: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl std::fmt::Debug for StorageApiKeyAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StorageApiKeyAuthenticator")
            .field("repositories", &"RuntimeStorageRepositories")
            .finish_non_exhaustive()
    }
}

impl StorageApiKeyAuthenticator {
    pub fn new(repositories: Arc<RuntimeStorageRepositories>) -> Self {
        Self {
            repositories,
            now_unix_seconds: Arc::new(now_unix_seconds),
        }
    }

    pub fn with_clock(
        repositories: Arc<RuntimeStorageRepositories>,
        now_unix_seconds: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            repositories,
            now_unix_seconds,
        }
    }
}

impl ApiKeyAuthenticator for StorageApiKeyAuthenticator {
    fn authenticate(&self, presented_key: &str) -> Option<AuthDecision> {
        let presented_key = presented_key.trim();
        let key_prefix = virtual_api_key_prefix(presented_key)?;
        let now_unix_seconds = (self.now_unix_seconds)();
        let candidates = block_on_sync_bridge(
            self.repositories
                .find_api_key_records_by_prefix(&key_prefix),
        )
        .ok()?;

        candidates.into_iter().find_map(|api_key| {
            if !api_key_record_is_active(&api_key, now_unix_seconds)
                || !api_key_record_last4_matches(&api_key, presented_key)
                || !verify_virtual_api_key_secret(presented_key, &api_key.key_hash)
            {
                return None;
            }

            Some(AuthDecision {
                tenant: api_key_tenant_context(&api_key),
                subject: PolicySubject::ApiKey {
                    api_key_id: api_key.id.clone(),
                },
                scopes: api_key.scopes,
                allowed_models: api_key.allowed_models,
                allowed_providers: api_key.allowed_providers,
                monthly_token_budget: api_key.monthly_token_budget,
                request_limit_per_minute: api_key.request_limit_per_minute,
            })
        })
    }
}

/// Generate a fresh virtual-API-key secret in the exact `fg_<hex>` format the
/// gateway's own `/admin/v1/virtual-keys` endpoint produces, so a console
/// -provisioned key is indistinguishable from one an operator creates
/// directly. Public so `ferrogate-cli`'s virtual-key handler can call this
/// single implementation instead of maintaining its own copy.
pub fn generate_virtual_api_key_secret() -> anyhow::Result<String> {
    Ok(format!("fg_{}", generate_random_hex(24)?))
}

fn virtual_api_key_prefix(secret: &str) -> Option<String> {
    let secret = secret.trim();
    if secret.is_empty() {
        return None;
    }
    Some(secret.chars().take(VIRTUAL_API_KEY_PREFIX_CHARS).collect())
}

fn verify_virtual_api_key_secret(secret: &str, expected_hash: &str) -> bool {
    if let Some(expected) = expected_hash.strip_prefix("sha256:") {
        let digest = Sha256::digest(secret.as_bytes());
        return constant_time_eq(encode_hex(&digest).as_bytes(), expected.as_bytes());
    }
    if let Some(expected) = expected_hash.strip_prefix("blake2b:") {
        let digest = Blake2b512::digest(secret.as_bytes());
        return constant_time_eq(encode_hex(&digest).as_bytes(), expected.as_bytes());
    }
    false
}

fn api_key_record_is_active(api_key: &StoredApiKey, now_unix_seconds: u64) -> bool {
    api_key.enabled
        && api_key.revoked_at_unix.is_none()
        && api_key
            .expires_at_unix
            .is_none_or(|expires_at| expires_at > now_unix_seconds)
}

fn api_key_record_last4_matches(api_key: &StoredApiKey, presented_key: &str) -> bool {
    api_key.last4.is_empty() || presented_key.ends_with(&api_key.last4)
}

fn api_key_tenant_context(api_key: &StoredApiKey) -> TenantContext {
    let mut tenant = api_key.tenant.clone();
    if tenant.organization_id.is_none() && !api_key.tenant_id.is_empty() {
        tenant.organization_id = Some(api_key.tenant_id.clone());
    }
    if tenant.project_id.is_none() && !api_key.project_id.is_empty() {
        tenant.project_id = Some(api_key.project_id.clone());
    }
    if tenant.workspace_id.is_none() && !api_key.workspace_id.is_empty() {
        tenant.workspace_id = Some(api_key.workspace_id.clone());
    }
    tenant.api_key_id = Some(api_key.id.clone());
    tenant
}
