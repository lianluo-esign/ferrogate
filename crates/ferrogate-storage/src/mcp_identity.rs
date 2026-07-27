// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Durable, ciphertext-only per-user MCP OAuth credential repository.

use serde::{Deserialize, Serialize};
use std::{future::Future, time::Duration};

use super::{
    AppendRepository, LifecycleStatus, PostgresControlPlaneStore, PostgresRow, Repository,
    RuntimeControlPlaneBackend, RuntimeControlPlaneState, RuntimeStorageRepositories, StorageError,
    StorageOperation, StoredAuditEvent,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMcpOauthFlow {
    pub id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub user_id: String,
    pub server_name: String,
    pub pkce_nonce: Vec<u8>,
    pub pkce_ciphertext: Vec<u8>,
    pub oidc_nonce: String,
    pub authorization_generation: u64,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    pub consumed_at_unix: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMcpOauthCredential {
    pub id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub user_id: String,
    pub server_name: String,
    pub issuer: String,
    pub subject: String,
    pub token_type: String,
    pub scopes: Vec<String>,
    pub access_token_nonce: Vec<u8>,
    pub access_token_ciphertext: Vec<u8>,
    pub refresh_token_nonce: Option<Vec<u8>>,
    pub refresh_token_ciphertext: Option<Vec<u8>>,
    pub expires_at_unix: i64,
    pub key_version: u32,
    pub version: u64,
    pub authorization_generation: u64,
    pub refresh_lease_id: Option<String>,
    pub refresh_lease_expires_at_unix: Option<i64>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
    pub revoked_at_unix: Option<i64>,
    pub last_refresh_outcome: Option<String>,
    pub last_revocation_outcome: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpIdentityAccessRequest {
    pub tenant_id: String,
    pub workspace_id: String,
    pub user_id: String,
    pub server_name: String,
    pub permission_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpIdentityAccessOutcome {
    Allowed(Box<Option<StoredMcpOauthCredential>>),
    PermissionDenied,
    UserInactive,
    MembershipRevoked,
    WorkspaceInactive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRefreshClaimRequest {
    pub tenant_id: String,
    pub credential_id: String,
    pub expected_version: u64,
    pub authorization_generation: u64,
    pub lease_id: String,
    pub now_unix: i64,
    pub lease_ttl_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRefreshRenewRequest {
    pub tenant_id: String,
    pub credential_id: String,
    pub expected_version: u64,
    pub authorization_generation: u64,
    pub lease_id: String,
    pub expected_lease_expires_at_unix: i64,
    pub now_unix: i64,
    pub lease_ttl_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpOauthCallbackCommitOutcome {
    Committed,
    AuthorizationChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpRefreshClaimOutcome {
    Acquired(StoredMcpOauthCredential),
    Busy { lease_expires_at_unix: i64 },
    Changed(Option<StoredMcpOauthCredential>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpRefreshRenewOutcome {
    Renewed { lease_expires_at_unix: i64 },
    Missing,
    Revoked,
    CredentialChanged,
    OwnershipChanged,
    Expired { lease_expires_at_unix: Option<i64> },
    NotExtended { lease_expires_at_unix: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpIdentityRevocationOutcome {
    pub credential: StoredMcpOauthCredential,
    pub revoked_at_unix: i64,
}

#[async_trait::async_trait]
pub trait McpCredentialRepository {
    async fn authorize_mcp_identity(
        &self,
        request: &McpIdentityAccessRequest,
    ) -> Result<McpIdentityAccessOutcome, StorageError>;
    async fn authorize_mcp_identity_with_operation(
        &self,
        request: &McpIdentityAccessRequest,
        operation: &StorageOperation,
    ) -> Result<McpIdentityAccessOutcome, StorageError>;
    async fn begin_mcp_oauth_flow(
        &self,
        flow: StoredMcpOauthFlow,
    ) -> Result<StoredMcpOauthFlow, StorageError>;
    async fn consume_mcp_oauth_flow(
        &self,
        id: &str,
        consumed_at_unix: i64,
    ) -> Result<Option<StoredMcpOauthFlow>, StorageError>;
    async fn commit_mcp_oauth_callback(
        &self,
        flow: &StoredMcpOauthFlow,
        credential: StoredMcpOauthCredential,
        permission_key: &str,
    ) -> Result<McpOauthCallbackCommitOutcome, StorageError>;
    async fn get_mcp_oauth_credential(
        &self,
        tenant_id: &str,
        workspace_id: &str,
        user_id: &str,
        server_name: &str,
    ) -> Result<Option<StoredMcpOauthCredential>, StorageError>;
    async fn list_mcp_oauth_credentials(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredMcpOauthCredential>, StorageError>;
    async fn claim_mcp_oauth_refresh(
        &self,
        request: &McpRefreshClaimRequest,
    ) -> Result<McpRefreshClaimOutcome, StorageError>;
    async fn renew_mcp_oauth_refresh(
        &self,
        request: &McpRefreshRenewRequest,
    ) -> Result<McpRefreshRenewOutcome, StorageError>;
    async fn complete_mcp_oauth_refresh(
        &self,
        credential: StoredMcpOauthCredential,
        lease_id: &str,
    ) -> Result<bool, StorageError>;
    async fn release_mcp_oauth_refresh(
        &self,
        tenant_id: &str,
        credential_id: &str,
        lease_id: &str,
        outcome: &str,
    ) -> Result<bool, StorageError>;
    async fn claim_mcp_oauth_refresh_with_operation(
        &self,
        request: &McpRefreshClaimRequest,
        operation: &StorageOperation,
    ) -> Result<McpRefreshClaimOutcome, StorageError>;
    async fn renew_mcp_oauth_refresh_with_operation(
        &self,
        request: &McpRefreshRenewRequest,
        operation: &StorageOperation,
    ) -> Result<McpRefreshRenewOutcome, StorageError>;
    async fn reconcile_mcp_oauth_refresh_claim(
        &self,
        request: &McpRefreshClaimRequest,
    ) -> Result<McpRefreshClaimOutcome, StorageError>;
    async fn reconcile_mcp_oauth_refresh_renewal(
        &self,
        request: &McpRefreshRenewRequest,
    ) -> Result<McpRefreshRenewOutcome, StorageError>;
    async fn complete_mcp_oauth_refresh_with_operation(
        &self,
        credential: StoredMcpOauthCredential,
        lease_id: &str,
        operation: &StorageOperation,
    ) -> Result<bool, StorageError>;
    async fn release_mcp_oauth_refresh_with_operation(
        &self,
        tenant_id: &str,
        credential_id: &str,
        lease_id: &str,
        outcome: &str,
        operation: &StorageOperation,
    ) -> Result<bool, StorageError>;
    async fn revoke_mcp_oauth_identity(
        &self,
        request: &McpIdentityAccessRequest,
        revoked_at_unix: i64,
        outcome: &str,
    ) -> Result<Option<McpIdentityRevocationOutcome>, StorageError>;
    async fn update_mcp_oauth_revocation_outcome(
        &self,
        tenant_id: &str,
        workspace_id: &str,
        user_id: &str,
        server_name: &str,
        outcome: &str,
    ) -> Result<bool, StorageError>;
}

fn oauth_flow_from_row(row: &PostgresRow) -> StoredMcpOauthFlow {
    StoredMcpOauthFlow {
        id: row.get(0),
        tenant_id: row.get(1),
        workspace_id: row.get(2),
        user_id: row.get(3),
        server_name: row.get(4),
        pkce_nonce: row.get(5),
        pkce_ciphertext: row.get(6),
        oidc_nonce: row.get(7),
        authorization_generation: u64::try_from(row.get::<_, i64>(8)).unwrap_or(u64::MAX),
        created_at_unix: row.get(9),
        expires_at_unix: row.get(10),
        consumed_at_unix: row.get(11),
    }
}

fn oauth_credential_from_row(row: &PostgresRow) -> Result<StoredMcpOauthCredential, StorageError> {
    let scopes = super::deserialize_storage_document(&row.get::<_, String>("scopes_json"))?;
    Ok(StoredMcpOauthCredential {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        workspace_id: row.get("workspace_id"),
        user_id: row.get("user_id"),
        server_name: row.get("server_name"),
        issuer: row.get("issuer"),
        subject: row.get("subject"),
        token_type: row.get("token_type"),
        scopes,
        access_token_nonce: row.get("access_token_nonce"),
        access_token_ciphertext: row.get("access_token_ciphertext"),
        refresh_token_nonce: row.get("refresh_token_nonce"),
        refresh_token_ciphertext: row.get("refresh_token_ciphertext"),
        expires_at_unix: row.get("expires_at_unix"),
        key_version: u32::try_from(row.get::<_, i64>("key_version")).unwrap_or(u32::MAX),
        version: u64::try_from(row.get::<_, i64>("version")).unwrap_or(u64::MAX),
        authorization_generation: u64::try_from(row.get::<_, i64>("authorization_generation"))
            .unwrap_or(u64::MAX),
        refresh_lease_id: row.get("refresh_lease_id"),
        refresh_lease_expires_at_unix: row.get("refresh_lease_expires_at_unix"),
        created_at_unix: row.get("created_at_unix"),
        updated_at_unix: row.get("updated_at_unix"),
        revoked_at_unix: row.get("revoked_at_unix"),
        last_refresh_outcome: row.get("last_refresh_outcome"),
        last_revocation_outcome: row.get("last_revocation_outcome"),
    })
}

const CREDENTIAL_COLUMNS: &str = "id, tenant_id, workspace_id, user_id, server_name, issuer, \
    subject, token_type, scopes_json::text, access_token_nonce, access_token_ciphertext, \
    refresh_token_nonce, refresh_token_ciphertext, expires_at_unix, key_version, version, \
    authorization_generation, refresh_lease_id, refresh_lease_expires_at_unix, created_at_unix, \
    updated_at_unix, revoked_at_unix, last_refresh_outcome, last_revocation_outcome";
const AUTHORIZATION_CREDENTIAL_COLUMNS: &str = "credential.id, credential.tenant_id, \
    credential.workspace_id, credential.user_id, credential.server_name, credential.issuer, \
    credential.subject, credential.token_type, credential.scopes_json::text AS scopes_json, \
    credential.access_token_nonce, credential.access_token_ciphertext, \
    credential.refresh_token_nonce, credential.refresh_token_ciphertext, \
    credential.expires_at_unix, credential.key_version, credential.version, \
    credential.authorization_generation, credential.refresh_lease_id, \
    credential.refresh_lease_expires_at_unix, credential.created_at_unix, \
    credential.updated_at_unix, credential.revoked_at_unix, \
    credential.last_refresh_outcome, credential.last_revocation_outcome";
const MCP_REFRESH_MUTATION_LOCK_TIMEOUT_MILLIS: i32 = 1;
const MCP_REFRESH_MUTATION_STATEMENT_TIMEOUT_MILLIS: i32 = 3_000;
const MCP_IDENTITY_AUTHORIZATION_LOCK_TIMEOUT_MILLIS: i32 = 1;
const MCP_REFRESH_AUTHORITATIVE_REREAD_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq)]
struct McpRefreshLeaseState {
    tenant_matches: bool,
    version: u64,
    authorization_generation: u64,
    refresh_lease_id: Option<String>,
    refresh_lease_expires_at_unix: Option<i64>,
    revoked: bool,
}

impl McpRefreshLeaseState {
    fn from_credential(credential: &StoredMcpOauthCredential, tenant_id: &str) -> Self {
        Self {
            tenant_matches: credential.tenant_id == tenant_id,
            version: credential.version,
            authorization_generation: credential.authorization_generation,
            refresh_lease_id: credential.refresh_lease_id.clone(),
            refresh_lease_expires_at_unix: credential.refresh_lease_expires_at_unix,
            revoked: credential.revoked_at_unix.is_some(),
        }
    }
}

fn mcp_refresh_renewal_rejection(
    current: Option<&McpRefreshLeaseState>,
    request: &McpRefreshRenewRequest,
    operation_now_unix: i64,
    lease_expires_at_unix: Option<i64>,
) -> Option<McpRefreshRenewOutcome> {
    let Some(current) = current else {
        return Some(McpRefreshRenewOutcome::Missing);
    };
    if !current.tenant_matches {
        return Some(McpRefreshRenewOutcome::Missing);
    }
    if current.revoked {
        return Some(McpRefreshRenewOutcome::Revoked);
    }
    if current.version != request.expected_version
        || current.authorization_generation != request.authorization_generation
    {
        return Some(McpRefreshRenewOutcome::CredentialChanged);
    }
    if current.refresh_lease_id.as_deref() != Some(request.lease_id.as_str()) {
        return Some(McpRefreshRenewOutcome::OwnershipChanged);
    }
    let Some(current_expiry) = current.refresh_lease_expires_at_unix else {
        return Some(McpRefreshRenewOutcome::Expired {
            lease_expires_at_unix: None,
        });
    };
    if current_expiry <= operation_now_unix {
        return Some(McpRefreshRenewOutcome::Expired {
            lease_expires_at_unix: Some(current_expiry),
        });
    }
    if current_expiry != request.expected_lease_expires_at_unix {
        return Some(McpRefreshRenewOutcome::NotExtended {
            lease_expires_at_unix: current_expiry,
        });
    }
    if lease_expires_at_unix.is_none_or(|expiry| expiry <= current_expiry) {
        return Some(McpRefreshRenewOutcome::NotExtended {
            lease_expires_at_unix: current_expiry,
        });
    }
    None
}

fn derive_refresh_lease_expiry(operation_now_unix: i64, lease_ttl_secs: i64) -> Option<i64> {
    (lease_ttl_secs > 0).then(|| operation_now_unix.saturating_add(lease_ttl_secs))
}

fn derive_refresh_lease_renewal_expiry(
    operation_now_unix: i64,
    lease_ttl_secs: i64,
    current_expiry: Option<i64>,
) -> Option<i64> {
    let ttl_expiry = derive_refresh_lease_expiry(operation_now_unix, lease_ttl_secs)?;
    Some(
        current_expiry
            .map(|expiry| expiry.saturating_add(1))
            .unwrap_or(ttl_expiry)
            .max(ttl_expiry),
    )
}

fn require_refresh_lease_expiry(
    operation_now_unix: i64,
    lease_ttl_secs: i64,
) -> Result<i64, StorageError> {
    derive_refresh_lease_expiry(operation_now_unix, lease_ttl_secs).ok_or_else(|| {
        StorageError::Runtime("MCP refresh lease TTL must be greater than zero".into())
    })
}

fn conservative_mcp_refresh_claim_busy(
    request: &McpRefreshClaimRequest,
) -> Result<McpRefreshClaimOutcome, StorageError> {
    Ok(McpRefreshClaimOutcome::Busy {
        lease_expires_at_unix: require_refresh_lease_expiry(
            request.now_unix,
            request.lease_ttl_secs,
        )?,
    })
}

fn postgres_refresh_claim_query() -> String {
    format!(
        "/* ferrogate:mcp_identity_refresh_claim */ \
         WITH operation_clock AS MATERIALIZED ( \
           SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT AS now_unix \
         ) \
         UPDATE mcp_oauth_credentials \
         SET refresh_lease_id=$5, \
             refresh_lease_expires_at_unix=LEAST( \
               operation_clock.now_unix::NUMERIC + $6::BIGINT, \
               9223372036854775807::NUMERIC \
             )::BIGINT, \
             last_refresh_outcome='refreshing' \
         FROM operation_clock \
         WHERE tenant_id=$1 AND id=$2 AND version=$3 \
           AND authorization_generation=$4 AND revoked_at_unix IS NULL \
           AND (refresh_lease_id IS NULL \
                OR refresh_lease_expires_at_unix <= operation_clock.now_unix) \
         RETURNING {CREDENTIAL_COLUMNS}"
    )
}

fn postgres_refresh_renewal_query() -> &'static str {
    "/* ferrogate:mcp_identity_refresh_renewal */ \
     WITH operation_clock AS MATERIALIZED ( \
       SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT AS now_unix \
     ), renewed AS ( \
       UPDATE mcp_oauth_credentials \
       SET refresh_lease_expires_at_unix=LEAST( \
             GREATEST( \
               operation_clock.now_unix::NUMERIC + $6::BIGINT, \
               refresh_lease_expires_at_unix::NUMERIC + 1 \
             ), \
             9223372036854775807::NUMERIC \
           )::BIGINT \
       FROM operation_clock \
       WHERE tenant_id=$1 AND id=$2 AND version=$3 \
         AND authorization_generation=$4 AND refresh_lease_id=$5 \
         AND refresh_lease_expires_at_unix=$7 \
         AND revoked_at_unix IS NULL \
         AND refresh_lease_expires_at_unix > operation_clock.now_unix \
         AND LEAST( \
               GREATEST( \
                 operation_clock.now_unix::NUMERIC + $6::BIGINT, \
                 refresh_lease_expires_at_unix::NUMERIC + 1 \
               ), \
               9223372036854775807::NUMERIC \
             )::BIGINT > refresh_lease_expires_at_unix \
       RETURNING refresh_lease_expires_at_unix \
     ) \
     SELECT TRUE AS renewed, refresh_lease_expires_at_unix, \
            NULL::BIGINT AS version, NULL::BIGINT AS authorization_generation, \
            NULL::TEXT AS refresh_lease_id, NULL::BIGINT AS current_expiry, \
            NULL::BOOLEAN AS revoked, NULL::BIGINT AS now_unix \
     FROM renewed \
     UNION ALL \
     SELECT FALSE, NULL::BIGINT, credential.version, \
            credential.authorization_generation, credential.refresh_lease_id, \
            credential.refresh_lease_expires_at_unix, \
            credential.revoked_at_unix IS NOT NULL, operation_clock.now_unix \
     FROM mcp_oauth_credentials AS credential CROSS JOIN operation_clock \
     WHERE credential.tenant_id=$1 AND credential.id=$2 \
       AND NOT EXISTS (SELECT 1 FROM renewed) \
     LIMIT 1"
}

fn postgres_refresh_authoritative_reread_query() -> String {
    format!(
        "/* ferrogate:mcp_identity_refresh_authoritative_reread */ \
         WITH operation_clock AS MATERIALIZED ( \
           SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT AS now_unix \
         ) \
         SELECT {CREDENTIAL_COLUMNS}, operation_clock.now_unix AS operation_now_unix \
         FROM operation_clock \
         LEFT JOIN mcp_oauth_credentials \
           ON tenant_id=$1 AND id=$2"
    )
}

fn postgres_mcp_identity_authorization_query() -> String {
    format!(
        "SELECT \
           EXISTS( \
             SELECT 1 FROM permissions AS permission \
             JOIN tenant_role_bindings AS binding ON binding.tenant_id=$1 \
             JOIN roles AS role ON role.id=binding.role_id \
             WHERE permission.key=$5 \
               AND jsonb_exists(role.permission_keys_json, permission.key) \
           ) AS has_permission, \
           EXISTS( \
             SELECT 1 FROM admin_users \
             WHERE id=$3 AND disabled_at_unix IS NULL \
           ) AS user_active, \
           EXISTS( \
             SELECT 1 FROM admin_user_tenant_memberships \
             WHERE user_id=$3 AND tenant_id=$1 \
           ) AS member, \
           EXISTS( \
             SELECT 1 FROM workspaces \
             WHERE id=$2 AND tenant_id=$1 AND status='active' \
           ) AS workspace_active, \
           {AUTHORIZATION_CREDENTIAL_COLUMNS} \
         FROM (VALUES (TRUE)) AS singleton(present) \
         LEFT JOIN mcp_oauth_credentials AS credential \
           ON credential.tenant_id=$1 \
          AND credential.workspace_id=$2 \
          AND credential.user_id=$3 \
          AND credential.server_name=$4"
    )
}

fn postgres_mcp_identity_revoke_query() -> String {
    format!(
        "/* ferrogate:mcp_identity_revoke */ \
         WITH revoked AS ( \
           UPDATE mcp_oauth_credentials \
           SET revoked_at_unix=$5,updated_at_unix=$5,version=version+1, \
               authorization_generation=authorization_generation+1, \
               refresh_lease_id=NULL,refresh_lease_expires_at_unix=NULL, \
               last_revocation_outcome=$6 \
           WHERE tenant_id=$1 AND workspace_id=$2 AND user_id=$3 AND server_name=$4 \
             AND revoked_at_unix IS NULL \
           RETURNING * \
         ), generation AS ( \
           INSERT INTO mcp_oauth_authorization_states \
             (tenant_id,workspace_id,user_id,server_name,generation,updated_at_unix) \
           SELECT tenant_id,workspace_id,user_id,server_name,authorization_generation,$5 \
           FROM revoked \
           ON CONFLICT (tenant_id,workspace_id,user_id,server_name) DO UPDATE SET \
             generation=GREATEST(mcp_oauth_authorization_states.generation,EXCLUDED.generation), \
             updated_at_unix=EXCLUDED.updated_at_unix \
           RETURNING generation \
         ), consumed_flows AS ( \
           UPDATE mcp_oauth_flows AS flow SET consumed_at_unix=$5 \
           FROM revoked \
           WHERE flow.tenant_id=revoked.tenant_id \
             AND flow.workspace_id=revoked.workspace_id \
             AND flow.user_id=revoked.user_id \
             AND flow.server_name=revoked.server_name \
             AND flow.consumed_at_unix IS NULL \
           RETURNING flow.id \
         ) \
         SELECT {CREDENTIAL_COLUMNS} FROM revoked"
    )
}

fn classify_postgres_mcp_refresh_renewal(
    renewed: Option<&PostgresRow>,
    request: &McpRefreshRenewRequest,
) -> McpRefreshRenewOutcome {
    let Some(renewed) = renewed else {
        return McpRefreshRenewOutcome::Missing;
    };
    if renewed.get::<_, bool>(0) {
        return McpRefreshRenewOutcome::Renewed {
            lease_expires_at_unix: renewed.get(1),
        };
    }
    let current = McpRefreshLeaseState {
        tenant_matches: true,
        version: u64::try_from(renewed.get::<_, i64>(2)).unwrap_or(u64::MAX),
        authorization_generation: u64::try_from(renewed.get::<_, i64>(3)).unwrap_or(u64::MAX),
        refresh_lease_id: renewed.get(4),
        refresh_lease_expires_at_unix: renewed.get(5),
        revoked: renewed.get(6),
    };
    let operation_now_unix = renewed.get::<_, i64>(7);
    let lease_expires_at_unix = derive_refresh_lease_renewal_expiry(
        operation_now_unix,
        request.lease_ttl_secs,
        current.refresh_lease_expires_at_unix,
    );
    mcp_refresh_renewal_rejection(
        Some(&current),
        request,
        operation_now_unix,
        lease_expires_at_unix,
    )
    .unwrap_or(McpRefreshRenewOutcome::OwnershipChanged)
}

fn reconcile_mcp_refresh_renewal_state(
    current: Option<&McpRefreshLeaseState>,
    request: &McpRefreshRenewRequest,
    operation_now_unix: i64,
) -> McpRefreshRenewOutcome {
    if let Some(current) = current {
        if current.tenant_matches
            && !current.revoked
            && current.version == request.expected_version
            && current.authorization_generation == request.authorization_generation
            && current.refresh_lease_id.as_deref() == Some(request.lease_id.as_str())
            && current.refresh_lease_expires_at_unix.is_some_and(|expiry| {
                expiry > request.expected_lease_expires_at_unix && expiry > operation_now_unix
            })
        {
            return McpRefreshRenewOutcome::Renewed {
                lease_expires_at_unix: current
                    .refresh_lease_expires_at_unix
                    .unwrap_or(operation_now_unix),
            };
        }
    }
    let candidate_expiry = current
        .and_then(|state| state.refresh_lease_expires_at_unix)
        .and_then(|expiry| {
            derive_refresh_lease_renewal_expiry(
                operation_now_unix,
                request.lease_ttl_secs,
                Some(expiry),
            )
        });
    mcp_refresh_renewal_rejection(current, request, operation_now_unix, candidate_expiry).unwrap_or(
        McpRefreshRenewOutcome::NotExtended {
            lease_expires_at_unix: request.expected_lease_expires_at_unix,
        },
    )
}

fn reconcile_mcp_refresh_claim_state(
    current: Option<StoredMcpOauthCredential>,
    request: &McpRefreshClaimRequest,
    operation_now_unix: i64,
) -> McpRefreshClaimOutcome {
    let Some(current) = current else {
        return McpRefreshClaimOutcome::Changed(None);
    };
    if current.tenant_id != request.tenant_id
        || current.version != request.expected_version
        || current.authorization_generation != request.authorization_generation
        || current.revoked_at_unix.is_some()
    {
        return McpRefreshClaimOutcome::Changed(Some(current));
    }
    if current.refresh_lease_id.as_deref() == Some(request.lease_id.as_str())
        && current
            .refresh_lease_expires_at_unix
            .is_some_and(|expiry| expiry > operation_now_unix)
    {
        return McpRefreshClaimOutcome::Acquired(current);
    }
    if let Some(lease_expires_at_unix) = current
        .refresh_lease_expires_at_unix
        .filter(|expiry| *expiry > operation_now_unix)
    {
        return McpRefreshClaimOutcome::Busy {
            lease_expires_at_unix,
        };
    }
    McpRefreshClaimOutcome::Changed(Some(current))
}

fn mcp_refresh_transaction_setup_query() -> &'static str {
    "SELECT set_config('ferrogate.tenant_id', $1, true), \
            set_config('ferrogate.platform_mode', 'off', true), \
            set_config('lock_timeout', $2, true), \
            set_config('statement_timeout', $3, true)"
}

fn mcp_refresh_transaction_statement_timeout_millis(
    operation: Option<&StorageOperation>,
    stage: &'static str,
) -> Result<i32, StorageError> {
    match operation {
        Some(operation) => mcp_statement_timeout_for_operation(operation, stage),
        None => Ok(MCP_REFRESH_MUTATION_STATEMENT_TIMEOUT_MILLIS),
    }
}

fn mcp_refresh_mutation_lock_timeout_millis(
    operation: Option<&StorageOperation>,
) -> Result<i32, StorageError> {
    let timeout_millis = match operation {
        Some(operation) => {
            mcp_statement_timeout_for_operation(operation, "refresh claim lock timeout")?
                .min(MCP_REFRESH_MUTATION_LOCK_TIMEOUT_MILLIS)
        }
        None => MCP_REFRESH_MUTATION_LOCK_TIMEOUT_MILLIS,
    };
    Ok(timeout_millis.max(1))
}

fn is_mcp_refresh_lock_timeout(error: &tokio_postgres::Error) -> bool {
    is_mcp_refresh_lock_timeout_code(error.code())
}

fn is_mcp_refresh_lock_timeout_code(code: Option<&tokio_postgres::error::SqlState>) -> bool {
    code == Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE)
}

enum McpRefreshClaimClassification {
    Acquirable(StoredMcpOauthCredential),
    Outcome(McpRefreshClaimOutcome),
}

fn classify_mcp_refresh_claim(
    current: Option<StoredMcpOauthCredential>,
    request: &McpRefreshClaimRequest,
    operation_now_unix: i64,
) -> McpRefreshClaimClassification {
    let Some(current) = current else {
        return McpRefreshClaimClassification::Outcome(McpRefreshClaimOutcome::Changed(None));
    };
    if current.tenant_id != request.tenant_id
        || current.version != request.expected_version
        || current.authorization_generation != request.authorization_generation
        || current.revoked_at_unix.is_some()
    {
        return McpRefreshClaimClassification::Outcome(McpRefreshClaimOutcome::Changed(Some(
            current,
        )));
    }
    if current
        .refresh_lease_expires_at_unix
        .is_some_and(|expiry| expiry > operation_now_unix)
        && current.refresh_lease_id.is_some()
    {
        return McpRefreshClaimClassification::Outcome(McpRefreshClaimOutcome::Busy {
            lease_expires_at_unix: current
                .refresh_lease_expires_at_unix
                .unwrap_or(operation_now_unix),
        });
    }
    McpRefreshClaimClassification::Acquirable(current)
}

fn claim_in_memory_mcp_oauth_refresh(
    store: &mut RuntimeControlPlaneState,
    request: &McpRefreshClaimRequest,
    operation: Option<&StorageOperation>,
) -> Result<McpRefreshClaimOutcome, StorageError> {
    let lease_expires_at_unix =
        require_refresh_lease_expiry(request.now_unix, request.lease_ttl_secs)?;
    let current = store.mcp_oauth_credentials.get(&request.credential_id);
    let mut current = match classify_mcp_refresh_claim(current, request, request.now_unix) {
        McpRefreshClaimClassification::Acquirable(current) => current,
        McpRefreshClaimClassification::Outcome(outcome) => return Ok(outcome),
    };
    if let Some(operation) = operation {
        operation.begin_commit("in-memory refresh claim")?;
    }
    current.refresh_lease_id = Some(request.lease_id.clone());
    current.refresh_lease_expires_at_unix = Some(lease_expires_at_unix);
    current.last_refresh_outcome = Some("refreshing".into());
    store
        .mcp_oauth_credentials
        .insert(current.id.clone(), current.clone());
    if let Some(operation) = operation {
        operation.finish_commit();
    }
    Ok(McpRefreshClaimOutcome::Acquired(current))
}

fn renew_in_memory_mcp_oauth_refresh(
    store: &mut RuntimeControlPlaneState,
    request: &McpRefreshRenewRequest,
    operation: Option<&StorageOperation>,
) -> Result<McpRefreshRenewOutcome, StorageError> {
    let current = store.mcp_oauth_credentials.get(&request.credential_id);
    let lease_state = current
        .as_ref()
        .map(|credential| McpRefreshLeaseState::from_credential(credential, &request.tenant_id));
    let lease_expires_at_unix = derive_refresh_lease_renewal_expiry(
        request.now_unix,
        request.lease_ttl_secs,
        lease_state
            .as_ref()
            .and_then(|state| state.refresh_lease_expires_at_unix),
    );
    if let Some(outcome) = mcp_refresh_renewal_rejection(
        lease_state.as_ref(),
        request,
        request.now_unix,
        lease_expires_at_unix,
    ) {
        return Ok(outcome);
    }
    let Some(mut current) = current else {
        return Ok(McpRefreshRenewOutcome::Missing);
    };
    let lease_expires_at_unix = lease_expires_at_unix.ok_or_else(|| {
        StorageError::Runtime("MCP refresh renewal accepted a nonpositive lease TTL".into())
    })?;
    if let Some(operation) = operation {
        operation.begin_commit("in-memory refresh renewal")?;
    }
    current.refresh_lease_expires_at_unix = Some(lease_expires_at_unix);
    store
        .mcp_oauth_credentials
        .insert(current.id.clone(), current);
    if let Some(operation) = operation {
        operation.finish_commit();
    }
    Ok(McpRefreshRenewOutcome::Renewed {
        lease_expires_at_unix,
    })
}

fn complete_in_memory_mcp_oauth_refresh(
    store: &mut RuntimeControlPlaneState,
    mut credential: StoredMcpOauthCredential,
    lease_id: &str,
    operation: Option<&StorageOperation>,
) -> Result<bool, StorageError> {
    let Some(current) = store.mcp_oauth_credentials.get(&credential.id) else {
        return Ok(false);
    };
    if current.version != credential.version
        || current.authorization_generation != credential.authorization_generation
        || current.refresh_lease_id.as_deref() != Some(lease_id)
        || current.revoked_at_unix.is_some()
    {
        return Ok(false);
    }
    if let Some(operation) = operation {
        operation.begin_commit("in-memory refresh completion")?;
    }
    credential.version = current.version.saturating_add(1);
    credential.refresh_lease_id = None;
    credential.refresh_lease_expires_at_unix = None;
    store
        .mcp_oauth_credentials
        .insert(credential.id.clone(), credential);
    if let Some(operation) = operation {
        operation.finish_commit();
    }
    Ok(true)
}

fn release_in_memory_mcp_oauth_refresh(
    store: &mut RuntimeControlPlaneState,
    tenant_id: &str,
    credential_id: &str,
    lease_id: &str,
    outcome: &str,
    operation: Option<&StorageOperation>,
) -> Result<bool, StorageError> {
    let Some(mut credential) = store.mcp_oauth_credentials.get(credential_id) else {
        return Ok(false);
    };
    if credential.tenant_id != tenant_id
        || credential.refresh_lease_id.as_deref() != Some(lease_id)
        || credential.revoked_at_unix.is_some()
    {
        return Ok(false);
    }
    if let Some(operation) = operation {
        operation.begin_commit("in-memory refresh release")?;
    }
    credential.refresh_lease_id = None;
    credential.refresh_lease_expires_at_unix = None;
    credential.last_refresh_outcome = Some(outcome.to_string());
    store
        .mcp_oauth_credentials
        .insert(credential.id.clone(), credential);
    if let Some(operation) = operation {
        operation.finish_commit();
    }
    Ok(true)
}

async fn set_mcp_rls_context_async(
    transaction: &deadpool_postgres::Transaction<'_>,
    tenant_id: Option<&str>,
) -> Result<(), StorageError> {
    let platform_mode = if tenant_id.is_some() { "off" } else { "on" };
    transaction
        .query_one(
            "SELECT set_config('ferrogate.tenant_id', COALESCE($1, ''), TRUE), \
                    set_config('ferrogate.platform_mode', $2, TRUE)",
            &[&tenant_id, &platform_mode],
        )
        .await
        .map_err(super::postgres_error)?;
    Ok(())
}

async fn postgres_authorize_mcp_actor(
    transaction: &deadpool_postgres::Transaction<'_>,
    request: &McpIdentityAccessRequest,
    operation: &StorageOperation,
) -> Result<McpIdentityAccessOutcome, StorageError> {
    let query = postgres_mcp_identity_authorization_query();
    let row = transaction
        .query_one(
            &query,
            &[
                &request.tenant_id,
                &request.workspace_id,
                &request.user_id,
                &request.server_name,
                &request.permission_key,
            ],
        )
        .await
        .map_err(|error| {
            if is_mcp_authorization_statement_timeout_code(error.code()) {
                let _ = operation.cancel();
                StorageError::OperationDeadlineExceeded {
                    operation: operation.name(),
                    stage: "authorization read",
                    commit_started: false,
                }
            } else {
                super::postgres_error(error)
            }
        })?;
    let has_permission = row.get::<_, bool>("has_permission");
    if !has_permission {
        return Ok(McpIdentityAccessOutcome::PermissionDenied);
    }
    let user_active = row.get::<_, bool>("user_active");
    if !user_active {
        return Ok(McpIdentityAccessOutcome::UserInactive);
    }
    let member = row.get::<_, bool>("member");
    if !member {
        return Ok(McpIdentityAccessOutcome::MembershipRevoked);
    }
    let workspace_active = row.get::<_, bool>("workspace_active");
    if !workspace_active {
        return Ok(McpIdentityAccessOutcome::WorkspaceInactive);
    }
    let credential = row
        .get::<_, Option<String>>("id")
        .map(|_| oauth_credential_from_row(&row))
        .transpose()?;
    Ok(McpIdentityAccessOutcome::Allowed(Box::new(credential)))
}

fn is_mcp_authorization_statement_timeout_code(
    code: Option<&tokio_postgres::error::SqlState>,
) -> bool {
    code == Some(&tokio_postgres::error::SqlState::QUERY_CANCELED)
}

fn mcp_statement_timeout_for_operation(
    operation: &StorageOperation,
    stage: &'static str,
) -> Result<i32, StorageError> {
    operation.remaining(stage).map(mcp_statement_timeout_millis)
}

fn mcp_statement_timeout_millis(remaining: std::time::Duration) -> i32 {
    let fractional_millis = u128::from(!remaining.subsec_nanos().is_multiple_of(1_000_000));
    let rounded_up = remaining.as_millis().saturating_add(fractional_millis);
    i32::try_from(rounded_up.clamp(1, i32::MAX as u128)).unwrap_or(i32::MAX)
}

fn mcp_transaction_commit_outcome_unknown(operation: &StorageOperation) -> StorageError {
    StorageError::OperationCommitOutcomeUnknown {
        operation: operation.name(),
        stage: "transaction commit",
    }
}

fn mcp_async_operation_deadline(operation: &StorageOperation, stage: &'static str) -> StorageError {
    let _ = operation.cancel();
    StorageError::OperationDeadlineExceeded {
        operation: operation.name(),
        stage,
        commit_started: false,
    }
}

async fn await_mcp_async_postgres_stage<T, F>(
    operation: &StorageOperation,
    stage: &'static str,
    future: F,
) -> Result<T, StorageError>
where
    F: Future<Output = Result<T, tokio_postgres::Error>>,
{
    let remaining = operation.remaining(stage)?;
    match tokio::time::timeout(remaining, future).await {
        Ok(Ok(output)) => {
            operation.check_active(stage)?;
            Ok(output)
        }
        Ok(Err(error))
            if error.code() == Some(&tokio_postgres::error::SqlState::QUERY_CANCELED) =>
        {
            Err(mcp_async_operation_deadline(operation, stage))
        }
        Ok(Err(error)) => Err(super::postgres_error(error)),
        Err(_) => Err(mcp_async_operation_deadline(operation, stage)),
    }
}

async fn rollback_mcp_async_storage_transaction(
    transaction: deadpool_postgres::Transaction<'_>,
    operation: &StorageOperation,
    stage: &'static str,
) -> Result<(), StorageError> {
    await_mcp_async_postgres_stage(operation, stage, transaction.rollback()).await
}

async fn commit_mcp_async_storage_transaction(
    transaction: deadpool_postgres::Transaction<'_>,
    operation: &StorageOperation,
) -> Result<(), StorageError> {
    operation.begin_commit("before transaction commit")?;
    let result = transaction.commit().await.map_err(|error| {
        tracing::warn!(
            operation = operation.name(),
            storage_stage = "transaction commit",
            sqlstate = error.code().map(tokio_postgres::error::SqlState::code),
            outcome = "commit_outcome_unknown",
            "PostgreSQL returned an error after the async MCP storage commit fence"
        );
        mcp_transaction_commit_outcome_unknown(operation)
    });
    operation.finish_commit();
    result
}

impl PostgresControlPlaneStore {
    async fn append_mcp_identity_audit_event_with_operation(
        &self,
        event: &StoredAuditEvent,
        operation: &StorageOperation,
    ) -> Result<(), StorageError> {
        // Serialization is pure CPU work; the first deadline-bounded stage is the
        // pool acquisition below, matching authorize/claim/renew so an exhausted
        // pool reports `audit pool acquisition` rather than a spurious pre-check.
        let audit_json = super::serialize_storage_document(event)?;
        let tenant_context_id = super::tenant_storage_key(&event.tenant);
        let workflow_version = event.workflow_version.map(|value| value.to_string());
        let occurred_at_unix = super::saturating_i64(
            event
                .occurred_at_unix
                .unwrap_or_else(super::now_unix_seconds),
        );
        let mut client = self
            .async_pool
            .acquire(
                operation.name(),
                operation.remaining("audit pool acquisition")?,
            )
            .await?;
        let transaction = await_mcp_async_postgres_stage(
            operation,
            "audit transaction setup",
            client.transaction(),
        )
        .await?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            await_mcp_async_postgres_stage(
                operation,
                "audit transaction setup",
                transaction.batch_execute(search_path_sql),
            )
            .await?;
        }
        let statement_timeout = format!(
            "{}ms",
            mcp_statement_timeout_for_operation(operation, "audit transaction setup")?
        );
        await_mcp_async_postgres_stage(
            operation,
            "audit transaction setup",
            transaction.execute(
                "SELECT set_config('statement_timeout', $1, true)",
                &[&statement_timeout],
            ),
        )
        .await?;
        let affected = await_mcp_async_postgres_stage(
            operation,
            "audit insert",
            transaction.execute(
                "INSERT INTO audit_events \
                     (id, request_id, trace_id, agent_run_id, workflow_id, workflow_version, \
                      workflow_node_id, cluster_id, node_id, actor_api_key_id, tenant, action, target, \
                      outcome, occurred_at_unix, audit_json) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
                             $16::text::jsonb) \
                     ON CONFLICT (id) DO NOTHING",
                    &[
                        &event.id,
                        &event.request_id,
                        &event.trace_id,
                        &event.agent_run_id,
                        &event.workflow_id,
                        &workflow_version,
                        &event.workflow_node_id,
                        &event.cluster_id,
                        &event.node_id,
                        &event.actor_api_key_id,
                        &tenant_context_id,
                        &event.action,
                        &event.target,
                        &event.outcome,
                        &occurred_at_unix,
                        &audit_json,
                    ],
            ),
        )
        .await?;
        if affected == 0 {
            rollback_mcp_async_storage_transaction(transaction, operation, "audit no-op rollback")
                .await?;
            return Ok(());
        }
        commit_mcp_async_storage_transaction(transaction, operation).await
    }

    async fn begin_mcp_async_refresh_transaction<'a>(
        &self,
        client: &'a mut deadpool_postgres::Object,
        tenant_id: &str,
        operation: &StorageOperation,
        stage: &'static str,
    ) -> Result<deadpool_postgres::Transaction<'a>, StorageError> {
        let transaction =
            await_mcp_async_postgres_stage(operation, stage, client.transaction()).await?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            await_mcp_async_postgres_stage(
                operation,
                stage,
                transaction.batch_execute(search_path_sql),
            )
            .await?;
        }
        let lock_timeout = format!(
            "{}ms",
            mcp_refresh_mutation_lock_timeout_millis(Some(operation))?
        );
        let statement_timeout = format!(
            "{}ms",
            mcp_refresh_transaction_statement_timeout_millis(Some(operation), stage)?
        );
        await_mcp_async_postgres_stage(
            operation,
            stage,
            transaction.execute(
                mcp_refresh_transaction_setup_query(),
                &[&tenant_id, &lock_timeout, &statement_timeout],
            ),
        )
        .await?;
        Ok(transaction)
    }

    async fn authorize_mcp_identity(
        &self,
        request: &McpIdentityAccessRequest,
    ) -> Result<McpIdentityAccessOutcome, StorageError> {
        self.authorize_mcp_identity_impl(request, None).await
    }

    async fn authorize_mcp_identity_with_operation(
        &self,
        request: &McpIdentityAccessRequest,
        operation: &StorageOperation,
    ) -> Result<McpIdentityAccessOutcome, StorageError> {
        self.authorize_mcp_identity_impl(request, Some(operation))
            .await
    }

    async fn authorize_mcp_identity_impl(
        &self,
        request: &McpIdentityAccessRequest,
        operation: Option<&StorageOperation>,
    ) -> Result<McpIdentityAccessOutcome, StorageError> {
        let default_operation = operation.is_none().then(|| {
            StorageOperation::new(
                "authorize MCP identity actor",
                self.async_pool.statement_timeout(),
            )
        });
        let operation = operation
            .or(default_operation.as_ref())
            .expect("default MCP authorization operation");
        let mut client = self
            .async_pool
            .acquire(
                operation.name(),
                operation.remaining("authorization pool acquisition")?,
            )
            .await?;
        let transaction_budget = operation.remaining("authorization transaction")?;
        tokio::time::timeout(transaction_budget, async {
            let transaction = client
                .build_transaction()
                .read_only(true)
                .start()
                .await
                .map_err(super::postgres_error)?;
            if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
                transaction
                    .batch_execute(search_path_sql)
                    .await
                    .map_err(super::postgres_error)?;
            }
            let statement_timeout = format!(
                "{}ms",
                mcp_statement_timeout_for_operation(operation, "authorization RLS context")?
            );
            let lock_timeout = format!("{MCP_IDENTITY_AUTHORIZATION_LOCK_TIMEOUT_MILLIS}ms");
            transaction
                .execute(
                    "SELECT set_config('ferrogate.tenant_id', $1, true), \
                            set_config('ferrogate.platform_mode', 'off', true), \
                            set_config('lock_timeout', $2, true), \
                            set_config('statement_timeout', $3, true)",
                    &[&request.tenant_id, &lock_timeout, &statement_timeout],
                )
                .await
                .map_err(super::postgres_error)?;
            operation.check_active("authorization read")?;
            let outcome = postgres_authorize_mcp_actor(&transaction, request, operation).await?;
            operation.check_active("before authorization transaction commit")?;
            transaction.commit().await.map_err(super::postgres_error)?;
            Ok(outcome)
        })
        .await
        .map_err(|_| {
            let _ = operation.cancel();
            StorageError::OperationDeadlineExceeded {
                operation: operation.name(),
                stage: "authorization transaction",
                commit_started: false,
            }
        })?
    }

    fn mcp_oauth_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    async fn begin_mcp_oauth_flow(
        &self,
        flow: &StoredMcpOauthFlow,
    ) -> Result<StoredMcpOauthFlow, StorageError> {
        let operation = self.mcp_oauth_operation("begin MCP OAuth flow");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(super::postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(super::postgres_error)?;
        }
        set_mcp_rls_context_async(&transaction, Some(&flow.tenant_id)).await?;
        transaction
            .execute(
                "INSERT INTO mcp_oauth_authorization_states \
                     (tenant_id,workspace_id,user_id,server_name,generation,updated_at_unix) \
                     VALUES ($1,$2,$3,$4,1,$5) ON CONFLICT DO NOTHING",
                &[
                    &flow.tenant_id,
                    &flow.workspace_id,
                    &flow.user_id,
                    &flow.server_name,
                    &flow.created_at_unix,
                ],
            )
            .await
            .map_err(super::postgres_error)?;
        let generation = transaction
            .query_one(
                "SELECT generation FROM mcp_oauth_authorization_states \
                     WHERE tenant_id=$1 AND workspace_id=$2 AND user_id=$3 AND server_name=$4",
                &[
                    &flow.tenant_id,
                    &flow.workspace_id,
                    &flow.user_id,
                    &flow.server_name,
                ],
            )
            .await
            .map_err(super::postgres_error)?
            .get::<_, i64>(0);
        let mut flow = flow.clone();
        flow.authorization_generation = u64::try_from(generation).unwrap_or(u64::MAX);
        transaction
            .execute(
                "INSERT INTO mcp_oauth_flows \
                     (id,tenant_id,workspace_id,user_id,server_name,pkce_nonce,pkce_ciphertext, \
                      oidc_nonce,authorization_generation,created_at_unix,expires_at_unix,consumed_at_unix) \
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                &[
                    &flow.id,
                    &flow.tenant_id,
                    &flow.workspace_id,
                    &flow.user_id,
                    &flow.server_name,
                    &flow.pkce_nonce,
                    &flow.pkce_ciphertext,
                    &flow.oidc_nonce,
                    &generation,
                    &flow.created_at_unix,
                    &flow.expires_at_unix,
                    &flow.consumed_at_unix,
                ],
            )
            .await
            .map_err(super::postgres_error)?;
        transaction.commit().await.map_err(super::postgres_error)?;
        Ok(flow)
    }

    async fn consume_mcp_oauth_flow(
        &self,
        id: &str,
        consumed_at_unix: i64,
    ) -> Result<Option<StoredMcpOauthFlow>, StorageError> {
        let operation = self.mcp_oauth_operation("consume MCP OAuth flow");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(super::postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(super::postgres_error)?;
        }
        set_mcp_rls_context_async(&transaction, None).await?;
        let row = transaction
            .query_opt(
                "UPDATE mcp_oauth_flows SET consumed_at_unix = $2 \
                 WHERE id = $1 AND consumed_at_unix IS NULL AND expires_at_unix >= $2 \
                 RETURNING id, tenant_id, workspace_id, user_id, server_name, pkce_nonce, \
                 pkce_ciphertext, oidc_nonce, authorization_generation, created_at_unix, \
                 expires_at_unix, consumed_at_unix",
                &[&id, &consumed_at_unix],
            )
            .await
            .map_err(super::postgres_error)?;
        transaction.commit().await.map_err(super::postgres_error)?;
        Ok(row.as_ref().map(oauth_flow_from_row))
    }

    async fn commit_mcp_oauth_callback(
        &self,
        flow: &StoredMcpOauthFlow,
        credential: &StoredMcpOauthCredential,
        permission_key: &str,
    ) -> Result<McpOauthCallbackCommitOutcome, StorageError> {
        let scopes = super::serialize_storage_document(&credential.scopes)?;
        let key_version = i64::from(credential.key_version);
        let version = super::saturating_i64(credential.version);
        let generation = super::saturating_i64(flow.authorization_generation);
        let operation = self.mcp_oauth_operation("commit MCP OAuth callback");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(super::postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(super::postgres_error)?;
        }
        set_mcp_rls_context_async(&transaction, Some(&flow.tenant_id)).await?;
        let row = transaction.query_opt(
                "INSERT INTO mcp_oauth_credentials \
                 (id,tenant_id,workspace_id,user_id,server_name,issuer,subject,token_type,scopes_json, \
                  access_token_nonce,access_token_ciphertext,refresh_token_nonce,refresh_token_ciphertext, \
                  expires_at_unix,key_version,version,authorization_generation,refresh_lease_id, \
                  refresh_lease_expires_at_unix,created_at_unix,updated_at_unix,revoked_at_unix, \
                  last_refresh_outcome,last_revocation_outcome) \
                 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9::text::jsonb,$10,$11,$12,$13,$14,$15,$16,$17, \
                        NULL,NULL,$18,$19,$20,$21,$22 \
                 FROM mcp_oauth_authorization_states AS state \
                 WHERE state.tenant_id=$2 AND state.workspace_id=$3 AND state.user_id=$4 \
                   AND state.server_name=$5 AND state.generation=$17 \
                   AND EXISTS (SELECT 1 FROM permissions AS permission \
                     JOIN tenant_role_bindings AS binding ON binding.tenant_id=$2 \
                     JOIN roles AS role ON role.id=binding.role_id \
                     WHERE permission.key=$23 \
                       AND jsonb_exists(role.permission_keys_json, permission.key)) \
                   AND EXISTS (SELECT 1 FROM admin_users WHERE id=$4 AND disabled_at_unix IS NULL) \
                   AND EXISTS (SELECT 1 FROM admin_user_tenant_memberships \
                               WHERE user_id=$4 AND tenant_id=$2) \
                   AND EXISTS (SELECT 1 FROM workspaces \
                               WHERE id=$3 AND tenant_id=$2 AND status='active') \
                 ON CONFLICT (tenant_id,workspace_id,user_id,server_name) DO UPDATE SET \
                  id=EXCLUDED.id,issuer=EXCLUDED.issuer,subject=EXCLUDED.subject,token_type=EXCLUDED.token_type, \
                  scopes_json=EXCLUDED.scopes_json,access_token_nonce=EXCLUDED.access_token_nonce, \
                  access_token_ciphertext=EXCLUDED.access_token_ciphertext, \
                  refresh_token_nonce=EXCLUDED.refresh_token_nonce,refresh_token_ciphertext=EXCLUDED.refresh_token_ciphertext, \
                  expires_at_unix=EXCLUDED.expires_at_unix,key_version=EXCLUDED.key_version, \
                  version=mcp_oauth_credentials.version+1,updated_at_unix=EXCLUDED.updated_at_unix, \
                  authorization_generation=EXCLUDED.authorization_generation,refresh_lease_id=NULL, \
                  refresh_lease_expires_at_unix=NULL,revoked_at_unix=NULL, \
                  last_refresh_outcome=EXCLUDED.last_refresh_outcome,last_revocation_outcome=NULL \
                 RETURNING id",
                &[
                    &credential.id,&credential.tenant_id,&credential.workspace_id,&credential.user_id,
                    &credential.server_name,&credential.issuer,&credential.subject,&credential.token_type,
                    &scopes,&credential.access_token_nonce,&credential.access_token_ciphertext,
                    &credential.refresh_token_nonce,&credential.refresh_token_ciphertext,
                    &credential.expires_at_unix,&key_version,&version,&generation,&credential.created_at_unix,
                    &credential.updated_at_unix,&credential.revoked_at_unix,
                    &credential.last_refresh_outcome,&credential.last_revocation_outcome,&permission_key,
                ],
            ).await.map_err(super::postgres_error)?;
        transaction.commit().await.map_err(super::postgres_error)?;
        Ok(if row.is_some() {
            McpOauthCallbackCommitOutcome::Committed
        } else {
            McpOauthCallbackCommitOutcome::AuthorizationChanged
        })
    }

    async fn get_mcp_oauth_credential(
        &self,
        tenant_id: &str,
        workspace_id: &str,
        user_id: &str,
        server_name: &str,
    ) -> Result<Option<StoredMcpOauthCredential>, StorageError> {
        let query = format!(
            "SELECT {CREDENTIAL_COLUMNS} FROM mcp_oauth_credentials \
             WHERE tenant_id=$1 AND workspace_id=$2 AND user_id=$3 AND server_name=$4"
        );
        let operation = self.mcp_oauth_operation("get MCP OAuth credential");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(super::postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(super::postgres_error)?;
        }
        set_mcp_rls_context_async(&transaction, Some(tenant_id)).await?;
        let row = transaction
            .query_opt(&query, &[&tenant_id, &workspace_id, &user_id, &server_name])
            .await
            .map_err(super::postgres_error)?;
        transaction.commit().await.map_err(super::postgres_error)?;
        row.as_ref().map(oauth_credential_from_row).transpose()
    }

    async fn list_mcp_oauth_credentials(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredMcpOauthCredential>, StorageError> {
        let query = format!(
            "SELECT {CREDENTIAL_COLUMNS} FROM mcp_oauth_credentials \
             WHERE tenant_id=$1 ORDER BY user_id,workspace_id,server_name"
        );
        let operation = self.mcp_oauth_operation("list MCP OAuth credentials");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(super::postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(super::postgres_error)?;
        }
        set_mcp_rls_context_async(&transaction, Some(tenant_id)).await?;
        let rows = transaction
            .query(&query, &[&tenant_id])
            .await
            .map_err(super::postgres_error)?;
        transaction.commit().await.map_err(super::postgres_error)?;
        rows.iter().map(oauth_credential_from_row).collect()
    }

    async fn claim_mcp_oauth_refresh(
        &self,
        request: &McpRefreshClaimRequest,
    ) -> Result<McpRefreshClaimOutcome, StorageError> {
        self.claim_mcp_oauth_refresh_impl(request, None).await
    }

    async fn claim_mcp_oauth_refresh_with_operation(
        &self,
        request: &McpRefreshClaimRequest,
        operation: &StorageOperation,
    ) -> Result<McpRefreshClaimOutcome, StorageError> {
        self.claim_mcp_oauth_refresh_impl(request, Some(operation))
            .await
    }

    async fn claim_mcp_oauth_refresh_impl(
        &self,
        request: &McpRefreshClaimRequest,
        operation: Option<&StorageOperation>,
    ) -> Result<McpRefreshClaimOutcome, StorageError> {
        let busy = conservative_mcp_refresh_claim_busy(request)?;
        let expected_version = super::saturating_i64(request.expected_version);
        let generation = super::saturating_i64(request.authorization_generation);
        let query = postgres_refresh_claim_query();
        let default_operation = operation.is_none().then(|| {
            StorageOperation::new(
                "claim MCP refresh lease",
                self.async_pool
                    .statement_timeout()
                    .min(Duration::from_millis(
                        u64::try_from(MCP_REFRESH_MUTATION_STATEMENT_TIMEOUT_MILLIS)
                            .unwrap_or(u64::MAX),
                    )),
            )
        });
        let operation = operation
            .or(default_operation.as_ref())
            .expect("default MCP refresh claim operation");
        let mut client = self
            .async_pool
            .acquire(
                operation.name(),
                operation.remaining("refresh claim pool acquisition")?,
            )
            .await?;
        let transaction = self
            .begin_mcp_async_refresh_transaction(
                &mut client,
                &request.tenant_id,
                operation,
                "refresh claim transaction setup",
            )
            .await?;
        let query_timeout = operation.remaining("refresh claim CAS")?;
        let claimed = match tokio::time::timeout(
            query_timeout,
            transaction.query_opt(
                &query,
                &[
                    &request.tenant_id,
                    &request.credential_id,
                    &expected_version,
                    &generation,
                    &request.lease_id,
                    &request.lease_ttl_secs,
                ],
            ),
        )
        .await
        {
            Ok(Ok(claimed)) => claimed,
            Ok(Err(error)) if is_mcp_refresh_lock_timeout(&error) => {
                rollback_mcp_async_storage_transaction(
                    transaction,
                    operation,
                    "refresh claim lock-conflict rollback",
                )
                .await?;
                tracing::info!(
                    operation = operation.name(),
                    storage_stage = "refresh claim CAS",
                    outcome = "lock_conflict_busy",
                    "mapped async MCP refresh claim lock contention to waiter backoff"
                );
                return Ok(busy);
            }
            Ok(Err(error))
                if error.code() == Some(&tokio_postgres::error::SqlState::QUERY_CANCELED) =>
            {
                return Err(mcp_async_operation_deadline(operation, "refresh claim CAS"));
            }
            Ok(Err(error)) => return Err(super::postgres_error(error)),
            Err(_) => return Err(mcp_async_operation_deadline(operation, "refresh claim CAS")),
        };
        operation.check_active("after refresh claim CAS")?;
        let Some(claimed) = claimed.as_ref() else {
            rollback_mcp_async_storage_transaction(
                transaction,
                operation,
                "refresh claim no-op rollback",
            )
            .await?;
            tracing::debug!(
                operation = operation.name(),
                storage_stage = "refresh claim CAS",
                outcome = "cas_busy",
                "async MCP refresh claim CAS did not acquire the lease"
            );
            return Ok(busy);
        };
        let outcome = McpRefreshClaimOutcome::Acquired(oauth_credential_from_row(claimed)?);
        commit_mcp_async_storage_transaction(transaction, operation).await?;
        Ok(outcome)
    }

    async fn renew_mcp_oauth_refresh(
        &self,
        request: &McpRefreshRenewRequest,
    ) -> Result<McpRefreshRenewOutcome, StorageError> {
        self.renew_mcp_oauth_refresh_impl(request, None).await
    }

    async fn renew_mcp_oauth_refresh_with_operation(
        &self,
        request: &McpRefreshRenewRequest,
        operation: &StorageOperation,
    ) -> Result<McpRefreshRenewOutcome, StorageError> {
        self.renew_mcp_oauth_refresh_impl(request, Some(operation))
            .await
    }

    async fn renew_mcp_oauth_refresh_impl(
        &self,
        request: &McpRefreshRenewRequest,
        operation: Option<&StorageOperation>,
    ) -> Result<McpRefreshRenewOutcome, StorageError> {
        let _ = require_refresh_lease_expiry(request.now_unix, request.lease_ttl_secs)?;
        let expected_version = super::saturating_i64(request.expected_version);
        let generation = super::saturating_i64(request.authorization_generation);
        let default_operation = operation.is_none().then(|| {
            StorageOperation::new(
                "renew MCP refresh lease",
                self.async_pool
                    .statement_timeout()
                    .min(Duration::from_millis(
                        u64::try_from(MCP_REFRESH_MUTATION_STATEMENT_TIMEOUT_MILLIS)
                            .unwrap_or(u64::MAX),
                    )),
            )
        });
        let operation = operation
            .or(default_operation.as_ref())
            .expect("default MCP refresh renewal operation");
        let mut client = self
            .async_pool
            .acquire(
                operation.name(),
                operation.remaining("refresh renewal pool acquisition")?,
            )
            .await?;
        let transaction = self
            .begin_mcp_async_refresh_transaction(
                &mut client,
                &request.tenant_id,
                operation,
                "refresh renewal transaction setup",
            )
            .await?;
        let query_timeout = operation.remaining("refresh renewal CAS")?;
        let renewed = match tokio::time::timeout(
            query_timeout,
            transaction.query_opt(
                postgres_refresh_renewal_query(),
                &[
                    &request.tenant_id,
                    &request.credential_id,
                    &expected_version,
                    &generation,
                    &request.lease_id,
                    &request.lease_ttl_secs,
                    &request.expected_lease_expires_at_unix,
                ],
            ),
        )
        .await
        {
            Ok(Ok(renewed)) => renewed,
            Ok(Err(error)) if is_mcp_refresh_lock_timeout(&error) => {
                rollback_mcp_async_storage_transaction(
                    transaction,
                    operation,
                    "refresh renewal lock-conflict rollback",
                )
                .await?;
                tracing::warn!(
                    operation = operation.name(),
                    storage_stage = "refresh renewal CAS",
                    outcome = "lock_conflict_fenced",
                    "fenced async MCP refresh renewal after bounded lock contention"
                );
                return Ok(McpRefreshRenewOutcome::OwnershipChanged);
            }
            Ok(Err(error))
                if error.code() == Some(&tokio_postgres::error::SqlState::QUERY_CANCELED) =>
            {
                return Err(mcp_async_operation_deadline(
                    operation,
                    "refresh renewal CAS",
                ));
            }
            Ok(Err(error)) => return Err(super::postgres_error(error)),
            Err(_) => {
                return Err(mcp_async_operation_deadline(
                    operation,
                    "refresh renewal CAS",
                ));
            }
        };
        operation.check_active("after refresh renewal CAS")?;
        let outcome = classify_postgres_mcp_refresh_renewal(renewed.as_ref(), request);
        if !matches!(outcome, McpRefreshRenewOutcome::Renewed { .. }) {
            rollback_mcp_async_storage_transaction(
                transaction,
                operation,
                "refresh renewal no-op rollback",
            )
            .await?;
            tracing::warn!(
                operation = operation.name(),
                storage_stage = "refresh renewal CAS",
                outcome = "cas_fenced",
                "classified an async MCP refresh renewal that lost its mutation fence"
            );
            return Ok(outcome);
        }
        commit_mcp_async_storage_transaction(transaction, operation).await?;
        Ok(outcome)
    }

    async fn read_mcp_refresh_authoritative_state(
        &self,
        tenant_id: &str,
        credential_id: &str,
    ) -> Result<(Option<StoredMcpOauthCredential>, i64), StorageError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(MCP_REFRESH_AUTHORITATIVE_REREAD_TIMEOUT)
            .ok_or_else(|| {
                StorageError::Runtime("authoritative PostgreSQL reread deadline overflow".into())
            })?;
        let mut client = self
            .async_pool
            .acquire(
                "reconcile MCP refresh state",
                deadline.saturating_duration_since(tokio::time::Instant::now()),
            )
            .await?;
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                StorageError::Runtime("authoritative PostgreSQL reread deadline elapsed".into())
            })?;
        let statement_timeout = format!("{}ms", mcp_statement_timeout_millis(remaining));
        let query = postgres_refresh_authoritative_reread_query();
        tokio::time::timeout(remaining, async {
            let transaction = client.transaction().await.map_err(super::postgres_error)?;
            if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
                transaction
                    .batch_execute(search_path_sql)
                    .await
                    .map_err(super::postgres_error)?;
            }
            transaction
                .execute(
                    "SELECT set_config('ferrogate.tenant_id', $1, true), \
                            set_config('ferrogate.platform_mode', 'off', true), \
                            set_config('statement_timeout', $2, true)",
                    &[&tenant_id, &statement_timeout],
                )
                .await
                .map_err(super::postgres_error)?;
            let row = transaction
                .query_one(&query, &[&tenant_id, &credential_id])
                .await
                .map_err(super::postgres_error)?;
            let operation_now_unix = row.get::<_, i64>("operation_now_unix");
            let credential = if row.get::<_, Option<String>>(0).is_some() {
                Some(oauth_credential_from_row(&row)?)
            } else {
                None
            };
            transaction.commit().await.map_err(super::postgres_error)?;
            Ok((credential, operation_now_unix))
        })
        .await
        .map_err(|_| StorageError::OperationDeadlineExceeded {
            operation: "reconcile MCP refresh state",
            stage: "authoritative reread",
            commit_started: false,
        })?
    }

    async fn reconcile_mcp_oauth_refresh_claim(
        &self,
        request: &McpRefreshClaimRequest,
    ) -> Result<McpRefreshClaimOutcome, StorageError> {
        let (current, operation_now_unix) = self
            .read_mcp_refresh_authoritative_state(&request.tenant_id, &request.credential_id)
            .await?;
        Ok(reconcile_mcp_refresh_claim_state(
            current,
            request,
            operation_now_unix,
        ))
    }

    async fn reconcile_mcp_oauth_refresh_renewal(
        &self,
        request: &McpRefreshRenewRequest,
    ) -> Result<McpRefreshRenewOutcome, StorageError> {
        let (credential, operation_now_unix) = self
            .read_mcp_refresh_authoritative_state(&request.tenant_id, &request.credential_id)
            .await?;
        let current = credential.as_ref().map(|credential| {
            McpRefreshLeaseState::from_credential(credential, &request.tenant_id)
        });
        Ok(reconcile_mcp_refresh_renewal_state(
            current.as_ref(),
            request,
            operation_now_unix,
        ))
    }

    async fn complete_mcp_oauth_refresh(
        &self,
        credential: &StoredMcpOauthCredential,
        lease_id: &str,
    ) -> Result<bool, StorageError> {
        self.complete_mcp_oauth_refresh_impl(credential, lease_id, None)
            .await
    }

    async fn complete_mcp_oauth_refresh_with_operation(
        &self,
        credential: &StoredMcpOauthCredential,
        lease_id: &str,
        operation: &StorageOperation,
    ) -> Result<bool, StorageError> {
        self.complete_mcp_oauth_refresh_impl(credential, lease_id, Some(operation))
            .await
    }

    async fn complete_mcp_oauth_refresh_impl(
        &self,
        credential: &StoredMcpOauthCredential,
        lease_id: &str,
        operation: Option<&StorageOperation>,
    ) -> Result<bool, StorageError> {
        let scopes = super::serialize_storage_document(&credential.scopes)?;
        let key_version = i64::from(credential.key_version);
        let expected_version = super::saturating_i64(credential.version);
        let generation = super::saturating_i64(credential.authorization_generation);
        let default_operation = operation.is_none().then(|| {
            StorageOperation::new(
                "complete MCP refresh lease",
                self.async_pool
                    .statement_timeout()
                    .min(Duration::from_millis(
                        u64::try_from(MCP_REFRESH_MUTATION_STATEMENT_TIMEOUT_MILLIS)
                            .unwrap_or(u64::MAX),
                    )),
            )
        });
        let operation = operation
            .or(default_operation.as_ref())
            .expect("default MCP refresh completion operation");
        let mut client = self
            .async_pool
            .acquire(
                operation.name(),
                operation.remaining("refresh completion pool acquisition")?,
            )
            .await?;
        let transaction = self
            .begin_mcp_async_refresh_transaction(
                &mut client,
                &credential.tenant_id,
                operation,
                "refresh completion transaction setup",
            )
            .await?;
        let affected = await_mcp_async_postgres_stage(
            operation,
            "refresh completion CAS",
            transaction.execute(
                "UPDATE mcp_oauth_credentials SET issuer=$3,subject=$4,token_type=$5, \
                 scopes_json=$6::text::jsonb,access_token_nonce=$7,access_token_ciphertext=$8, \
                 refresh_token_nonce=$9,refresh_token_ciphertext=$10,expires_at_unix=$11,key_version=$12, \
                 version=version+1,updated_at_unix=$13,refresh_lease_id=NULL, \
                 refresh_lease_expires_at_unix=NULL,last_refresh_outcome=$14 \
                 WHERE tenant_id=$1 AND id=$2 AND version=$15 AND authorization_generation=$16 \
                   AND refresh_lease_id=$17 AND revoked_at_unix IS NULL",
                &[
                    &credential.tenant_id,&credential.id,&credential.issuer,&credential.subject,
                    &credential.token_type,&scopes,&credential.access_token_nonce,
                    &credential.access_token_ciphertext,&credential.refresh_token_nonce,
                    &credential.refresh_token_ciphertext,&credential.expires_at_unix,&key_version,
                    &credential.updated_at_unix,&credential.last_refresh_outcome,&expected_version,
                    &generation,&lease_id,
                ],
            ),
        )
        .await?;
        if affected != 1 {
            rollback_mcp_async_storage_transaction(
                transaction,
                operation,
                "refresh completion no-op rollback",
            )
            .await?;
            return Ok(false);
        }
        commit_mcp_async_storage_transaction(transaction, operation).await?;
        Ok(true)
    }

    async fn release_mcp_oauth_refresh(
        &self,
        tenant_id: &str,
        credential_id: &str,
        lease_id: &str,
        outcome: &str,
    ) -> Result<bool, StorageError> {
        self.release_mcp_oauth_refresh_impl(tenant_id, credential_id, lease_id, outcome, None)
            .await
    }

    async fn release_mcp_oauth_refresh_with_operation(
        &self,
        tenant_id: &str,
        credential_id: &str,
        lease_id: &str,
        outcome: &str,
        operation: &StorageOperation,
    ) -> Result<bool, StorageError> {
        self.release_mcp_oauth_refresh_impl(
            tenant_id,
            credential_id,
            lease_id,
            outcome,
            Some(operation),
        )
        .await
    }

    async fn release_mcp_oauth_refresh_impl(
        &self,
        tenant_id: &str,
        credential_id: &str,
        lease_id: &str,
        outcome: &str,
        operation: Option<&StorageOperation>,
    ) -> Result<bool, StorageError> {
        let default_operation = operation.is_none().then(|| {
            StorageOperation::new(
                "release MCP refresh lease",
                self.async_pool
                    .statement_timeout()
                    .min(Duration::from_millis(
                        u64::try_from(MCP_REFRESH_MUTATION_STATEMENT_TIMEOUT_MILLIS)
                            .unwrap_or(u64::MAX),
                    )),
            )
        });
        let operation = operation
            .or(default_operation.as_ref())
            .expect("default MCP refresh release operation");
        let mut client = self
            .async_pool
            .acquire(
                operation.name(),
                operation.remaining("refresh release pool acquisition")?,
            )
            .await?;
        let transaction = self
            .begin_mcp_async_refresh_transaction(
                &mut client,
                tenant_id,
                operation,
                "refresh release transaction setup",
            )
            .await?;
        let affected = await_mcp_async_postgres_stage(
            operation,
            "refresh release CAS",
            transaction.execute(
                "UPDATE mcp_oauth_credentials SET refresh_lease_id=NULL, \
                 refresh_lease_expires_at_unix=NULL,last_refresh_outcome=$4 \
                 WHERE tenant_id=$1 AND id=$2 AND refresh_lease_id=$3 AND revoked_at_unix IS NULL",
                &[&tenant_id, &credential_id, &lease_id, &outcome],
            ),
        )
        .await?;
        if affected != 1 {
            rollback_mcp_async_storage_transaction(
                transaction,
                operation,
                "refresh release no-op rollback",
            )
            .await?;
            return Ok(false);
        }
        commit_mcp_async_storage_transaction(transaction, operation).await?;
        Ok(true)
    }

    async fn revoke_mcp_oauth_identity(
        &self,
        request: &McpIdentityAccessRequest,
        revoked_at_unix: i64,
        outcome: &str,
    ) -> Result<Option<McpIdentityRevocationOutcome>, StorageError> {
        let operation = self.mcp_oauth_operation("revoke MCP identity");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(super::postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(super::postgres_error)?;
        }
        // Preserve the synchronous CAS setup: `prepare_mcp_refresh_transaction`
        // with `None` sets the tenant RLS context (platform_mode off) plus the
        // fixed mutation lock/statement timeouts, so replicate that exactly here.
        let lock_timeout = format!("{}ms", mcp_refresh_mutation_lock_timeout_millis(None)?);
        let statement_timeout = format!(
            "{}ms",
            mcp_refresh_transaction_statement_timeout_millis(None, "MCP identity revoke CAS")?
        );
        transaction
            .execute(
                mcp_refresh_transaction_setup_query(),
                &[&request.tenant_id, &lock_timeout, &statement_timeout],
            )
            .await
            .map_err(super::postgres_error)?;
        let query = postgres_mcp_identity_revoke_query();
        let row = transaction
            .query_opt(
                &query,
                &[
                    &request.tenant_id,
                    &request.workspace_id,
                    &request.user_id,
                    &request.server_name,
                    &revoked_at_unix,
                    &outcome,
                ],
            )
            .await
            .map_err(super::postgres_error)?;
        transaction.commit().await.map_err(super::postgres_error)?;
        row.as_ref()
            .map(oauth_credential_from_row)
            .transpose()
            .map(|credential| {
                credential.map(|credential| McpIdentityRevocationOutcome {
                    credential,
                    revoked_at_unix,
                })
            })
    }

    async fn update_mcp_oauth_revocation_outcome(
        &self,
        tenant_id: &str,
        workspace_id: &str,
        user_id: &str,
        server_name: &str,
        outcome: &str,
    ) -> Result<bool, StorageError> {
        let operation = self.mcp_oauth_operation("update MCP revocation outcome");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(super::postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(super::postgres_error)?;
        }
        set_mcp_rls_context_async(&transaction, Some(tenant_id)).await?;
        let affected = transaction
            .execute(
                "UPDATE mcp_oauth_credentials SET last_revocation_outcome=$5,version=version+1 \
                 WHERE tenant_id=$1 AND workspace_id=$2 AND user_id=$3 AND server_name=$4 \
                 AND revoked_at_unix IS NOT NULL",
                &[&tenant_id, &workspace_id, &user_id, &server_name, &outcome],
            )
            .await
            .map_err(super::postgres_error)?;
        transaction.commit().await.map_err(super::postgres_error)?;
        Ok(affected == 1)
    }
}

impl RuntimeStorageRepositories {
    pub async fn append_mcp_identity_audit_event_with_operation(
        &self,
        event: StoredAuditEvent,
        operation: &StorageOperation,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(store) => {
                store
                    .append_mcp_identity_audit_event_with_operation(&event, operation)
                    .await
            }
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                operation.begin_commit("in-memory MCP identity audit append")?;
                let result = control_plane
                    .audit_events
                    .lock()
                    .map_err(|_| StorageError::Runtime("audit event store lock poisoned".into()))
                    .map(|mut events| events.append(event));
                operation.finish_commit();
                result
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => {
                Err(super::control_plane_store_d1::unimplemented_surface(
                    "append_mcp_identity_audit_event_with_operation",
                ))
            }
        }
    }
}

fn authorization_generation_key(request: &McpIdentityAccessRequest) -> String {
    format!(
        "{}\0{}\0{}\0{}",
        request.tenant_id, request.workspace_id, request.user_id, request.server_name
    )
}

fn memory_authorize_mcp_actor(
    store: &super::RuntimeControlPlaneState,
    request: &McpIdentityAccessRequest,
) -> McpIdentityAccessOutcome {
    let permission_exists = store
        .permissions
        .list()
        .into_iter()
        .any(|permission| permission.key == request.permission_key);
    let has_permission = permission_exists
        && store
            .tenant_role_bindings
            .list()
            .into_iter()
            .filter(|binding| binding.tenant_id == request.tenant_id)
            .any(|binding| {
                store.roles.get(&binding.role_id).is_some_and(|role| {
                    role.permission_keys
                        .iter()
                        .any(|key| key == &request.permission_key)
                })
            });
    if !has_permission {
        return McpIdentityAccessOutcome::PermissionDenied;
    }
    if store
        .admin_users
        .get(&request.user_id)
        .is_none_or(|user| user.disabled_at_unix.is_some())
    {
        return McpIdentityAccessOutcome::UserInactive;
    }
    if !store
        .admin_user_memberships
        .list()
        .into_iter()
        .any(|membership| {
            membership.user_id == request.user_id && membership.tenant_id == request.tenant_id
        })
    {
        return McpIdentityAccessOutcome::MembershipRevoked;
    }
    // #514: `status` is interpreted through the one shared vocabulary rather
    // than a bare `== "active"` string test, so a legacy row whose status was
    // never written (empty/NULL) stays usable while an explicitly
    // suspended/disabled/deleted workspace is refused -- the same verdict the
    // Postgres path's `status='active'` filter reaches for the tokens that
    // actually occur.
    if !store
        .workspaces
        .get(&request.workspace_id)
        .is_some_and(|workspace| {
            workspace.tenant_id == request.tenant_id
                && LifecycleStatus::parse(&workspace.status).is_active()
        })
    {
        return McpIdentityAccessOutcome::WorkspaceInactive;
    }
    let credential = store.mcp_oauth_credentials.list().into_iter().find(|row| {
        row.tenant_id == request.tenant_id
            && row.workspace_id == request.workspace_id
            && row.user_id == request.user_id
            && row.server_name == request.server_name
    });
    McpIdentityAccessOutcome::Allowed(Box::new(credential))
}

#[async_trait::async_trait]
impl McpCredentialRepository for RuntimeStorageRepositories {
    async fn authorize_mcp_identity(
        &self,
        request: &McpIdentityAccessRequest,
    ) -> Result<McpIdentityAccessOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => {
                let store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP identity control-plane lock poisoned".into())
                })?;
                Ok(memory_authorize_mcp_actor(&store, request))
            }
            RuntimeControlPlaneBackend::Postgres(store) => {
                store.authorize_mcp_identity(request).await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("authorize_mcp_identity"),
            ),
        }
    }

    async fn authorize_mcp_identity_with_operation(
        &self,
        request: &McpIdentityAccessRequest,
        operation: &StorageOperation,
    ) -> Result<McpIdentityAccessOutcome, StorageError> {
        operation.check_active("before MCP identity authorization")?;
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => {
                let store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP identity control-plane lock poisoned".into())
                })?;
                operation.check_active("MCP identity authorization")?;
                Ok(memory_authorize_mcp_actor(&store, request))
            }
            RuntimeControlPlaneBackend::Postgres(store) => {
                store
                    .authorize_mcp_identity_with_operation(request, operation)
                    .await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => {
                Err(super::control_plane_store_d1::unimplemented_surface(
                    "authorize_mcp_identity_with_operation",
                ))
            }
        }
    }

    async fn begin_mcp_oauth_flow(
        &self,
        mut flow: StoredMcpOauthFlow,
    ) -> Result<StoredMcpOauthFlow, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth flow store lock poisoned".into())
                })?;
                if store.mcp_oauth_flows.get(&flow.id).is_some() {
                    return Err(StorageError::Conflict(format!(
                        "MCP OAuth flow {} already exists",
                        flow.id
                    )));
                }
                let request = McpIdentityAccessRequest {
                    tenant_id: flow.tenant_id.clone(),
                    workspace_id: flow.workspace_id.clone(),
                    user_id: flow.user_id.clone(),
                    server_name: flow.server_name.clone(),
                    permission_key: String::new(),
                };
                let key = authorization_generation_key(&request);
                let generation = store
                    .mcp_oauth_authorization_generations
                    .get(&key)
                    .unwrap_or(1);
                store
                    .mcp_oauth_authorization_generations
                    .insert(key, generation);
                flow.authorization_generation = generation;
                store.mcp_oauth_flows.insert(flow.id.clone(), flow.clone());
                Ok(flow)
            }
            RuntimeControlPlaneBackend::Postgres(store) => store.begin_mcp_oauth_flow(&flow).await,
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("begin_mcp_oauth_flow"),
            ),
        }
    }

    async fn consume_mcp_oauth_flow(
        &self,
        id: &str,
        consumed_at_unix: i64,
    ) -> Result<Option<StoredMcpOauthFlow>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth flow store lock poisoned".into())
                })?;
                let Some(mut flow) = store.mcp_oauth_flows.get(id) else {
                    return Ok(None);
                };
                if flow.consumed_at_unix.is_some() || flow.expires_at_unix < consumed_at_unix {
                    return Ok(None);
                }
                flow.consumed_at_unix = Some(consumed_at_unix);
                store.mcp_oauth_flows.insert(flow.id.clone(), flow.clone());
                Ok(Some(flow))
            }
            RuntimeControlPlaneBackend::Postgres(store) => {
                store.consume_mcp_oauth_flow(id, consumed_at_unix).await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("consume_mcp_oauth_flow"),
            ),
        }
    }

    async fn commit_mcp_oauth_callback(
        &self,
        flow: &StoredMcpOauthFlow,
        mut credential: StoredMcpOauthCredential,
        permission_key: &str,
    ) -> Result<McpOauthCallbackCommitOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                let request = McpIdentityAccessRequest {
                    tenant_id: flow.tenant_id.clone(),
                    workspace_id: flow.workspace_id.clone(),
                    user_id: flow.user_id.clone(),
                    server_name: flow.server_name.clone(),
                    permission_key: permission_key.to_string(),
                };
                if !matches!(
                    memory_authorize_mcp_actor(&store, &request),
                    McpIdentityAccessOutcome::Allowed(_)
                ) {
                    return Ok(McpOauthCallbackCommitOutcome::AuthorizationChanged);
                }
                let generation = store
                    .mcp_oauth_authorization_generations
                    .get(&authorization_generation_key(&request));
                if generation != Some(flow.authorization_generation) {
                    return Ok(McpOauthCallbackCommitOutcome::AuthorizationChanged);
                }
                if let Some(current) = store.mcp_oauth_credentials.get(&credential.id) {
                    credential.version = current.version.saturating_add(1);
                }
                credential.authorization_generation = flow.authorization_generation;
                credential.refresh_lease_id = None;
                credential.refresh_lease_expires_at_unix = None;
                credential.revoked_at_unix = None;
                store
                    .mcp_oauth_credentials
                    .insert(credential.id.clone(), credential);
                Ok(McpOauthCallbackCommitOutcome::Committed)
            }
            RuntimeControlPlaneBackend::Postgres(store) => {
                store
                    .commit_mcp_oauth_callback(flow, &credential, permission_key)
                    .await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("commit_mcp_oauth_callback"),
            ),
        }
    }

    async fn get_mcp_oauth_credential(
        &self,
        tenant_id: &str,
        workspace_id: &str,
        user_id: &str,
        server_name: &str,
    ) -> Result<Option<StoredMcpOauthCredential>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => Ok(store
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?
                .mcp_oauth_credentials
                .list()
                .into_iter()
                .find(|row| {
                    row.tenant_id == tenant_id
                        && row.workspace_id == workspace_id
                        && row.user_id == user_id
                        && row.server_name == server_name
                })),
            RuntimeControlPlaneBackend::Postgres(store) => {
                store
                    .get_mcp_oauth_credential(tenant_id, workspace_id, user_id, server_name)
                    .await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("get_mcp_oauth_credential"),
            ),
        }
    }

    async fn list_mcp_oauth_credentials(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredMcpOauthCredential>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => Ok(store
                .lock()
                .map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?
                .mcp_oauth_credentials
                .list()
                .into_iter()
                .filter(|row| row.tenant_id == tenant_id)
                .collect()),
            RuntimeControlPlaneBackend::Postgres(store) => {
                store.list_mcp_oauth_credentials(tenant_id).await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("list_mcp_oauth_credentials"),
            ),
        }
    }

    async fn claim_mcp_oauth_refresh(
        &self,
        request: &McpRefreshClaimRequest,
    ) -> Result<McpRefreshClaimOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                claim_in_memory_mcp_oauth_refresh(&mut store, request, None)
            }
            RuntimeControlPlaneBackend::Postgres(store) => {
                store.claim_mcp_oauth_refresh(request).await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("claim_mcp_oauth_refresh"),
            ),
        }
    }

    async fn renew_mcp_oauth_refresh(
        &self,
        request: &McpRefreshRenewRequest,
    ) -> Result<McpRefreshRenewOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                renew_in_memory_mcp_oauth_refresh(&mut store, request, None)
            }
            RuntimeControlPlaneBackend::Postgres(store) => {
                store.renew_mcp_oauth_refresh(request).await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("renew_mcp_oauth_refresh"),
            ),
        }
    }

    async fn complete_mcp_oauth_refresh(
        &self,
        credential: StoredMcpOauthCredential,
        lease_id: &str,
    ) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                complete_in_memory_mcp_oauth_refresh(&mut store, credential, lease_id, None)
            }
            RuntimeControlPlaneBackend::Postgres(store) => {
                store
                    .complete_mcp_oauth_refresh(&credential, lease_id)
                    .await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("complete_mcp_oauth_refresh"),
            ),
        }
    }

    async fn release_mcp_oauth_refresh(
        &self,
        tenant_id: &str,
        credential_id: &str,
        lease_id: &str,
        outcome: &str,
    ) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                release_in_memory_mcp_oauth_refresh(
                    &mut store,
                    tenant_id,
                    credential_id,
                    lease_id,
                    outcome,
                    None,
                )
            }
            RuntimeControlPlaneBackend::Postgres(store) => {
                store
                    .release_mcp_oauth_refresh(tenant_id, credential_id, lease_id, outcome)
                    .await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("release_mcp_oauth_refresh"),
            ),
        }
    }

    async fn claim_mcp_oauth_refresh_with_operation(
        &self,
        request: &McpRefreshClaimRequest,
        operation: &StorageOperation,
    ) -> Result<McpRefreshClaimOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(store) => {
                store
                    .claim_mcp_oauth_refresh_with_operation(request, operation)
                    .await
            }
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                claim_in_memory_mcp_oauth_refresh(&mut store, request, Some(operation))
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => {
                Err(super::control_plane_store_d1::unimplemented_surface(
                    "claim_mcp_oauth_refresh_with_operation",
                ))
            }
        }
    }

    async fn renew_mcp_oauth_refresh_with_operation(
        &self,
        request: &McpRefreshRenewRequest,
        operation: &StorageOperation,
    ) -> Result<McpRefreshRenewOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(store) => {
                store
                    .renew_mcp_oauth_refresh_with_operation(request, operation)
                    .await
            }
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                renew_in_memory_mcp_oauth_refresh(&mut store, request, Some(operation))
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => {
                Err(super::control_plane_store_d1::unimplemented_surface(
                    "renew_mcp_oauth_refresh_with_operation",
                ))
            }
        }
    }

    async fn reconcile_mcp_oauth_refresh_claim(
        &self,
        request: &McpRefreshClaimRequest,
    ) -> Result<McpRefreshClaimOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(store) => {
                store.reconcile_mcp_oauth_refresh_claim(request).await
            }
            RuntimeControlPlaneBackend::Memory(store) => {
                let store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                let current = store.mcp_oauth_credentials.get(&request.credential_id);
                Ok(reconcile_mcp_refresh_claim_state(
                    current,
                    request,
                    request.now_unix,
                ))
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => {
                Err(super::control_plane_store_d1::unimplemented_surface(
                    "reconcile_mcp_oauth_refresh_claim",
                ))
            }
        }
    }

    async fn reconcile_mcp_oauth_refresh_renewal(
        &self,
        request: &McpRefreshRenewRequest,
    ) -> Result<McpRefreshRenewOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(store) => {
                store.reconcile_mcp_oauth_refresh_renewal(request).await
            }
            RuntimeControlPlaneBackend::Memory(store) => {
                let store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                let current =
                    store
                        .mcp_oauth_credentials
                        .get(&request.credential_id)
                        .map(|credential| {
                            McpRefreshLeaseState::from_credential(&credential, &request.tenant_id)
                        });
                Ok(reconcile_mcp_refresh_renewal_state(
                    current.as_ref(),
                    request,
                    request.now_unix,
                ))
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => {
                Err(super::control_plane_store_d1::unimplemented_surface(
                    "reconcile_mcp_oauth_refresh_renewal",
                ))
            }
        }
    }

    async fn complete_mcp_oauth_refresh_with_operation(
        &self,
        credential: StoredMcpOauthCredential,
        lease_id: &str,
        operation: &StorageOperation,
    ) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(store) => {
                store
                    .complete_mcp_oauth_refresh_with_operation(&credential, lease_id, operation)
                    .await
            }
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                complete_in_memory_mcp_oauth_refresh(
                    &mut store,
                    credential,
                    lease_id,
                    Some(operation),
                )
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => {
                Err(super::control_plane_store_d1::unimplemented_surface(
                    "complete_mcp_oauth_refresh_with_operation",
                ))
            }
        }
    }

    async fn release_mcp_oauth_refresh_with_operation(
        &self,
        tenant_id: &str,
        credential_id: &str,
        lease_id: &str,
        outcome: &str,
        operation: &StorageOperation,
    ) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(store) => {
                store
                    .release_mcp_oauth_refresh_with_operation(
                        tenant_id,
                        credential_id,
                        lease_id,
                        outcome,
                        operation,
                    )
                    .await
            }
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                release_in_memory_mcp_oauth_refresh(
                    &mut store,
                    tenant_id,
                    credential_id,
                    lease_id,
                    outcome,
                    Some(operation),
                )
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => {
                Err(super::control_plane_store_d1::unimplemented_surface(
                    "release_mcp_oauth_refresh_with_operation",
                ))
            }
        }
    }

    async fn revoke_mcp_oauth_identity(
        &self,
        request: &McpIdentityAccessRequest,
        revoked_at_unix: i64,
        outcome: &str,
    ) -> Result<Option<McpIdentityRevocationOutcome>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                let Some(mut credential) =
                    store.mcp_oauth_credentials.list().into_iter().find(|row| {
                        row.tenant_id == request.tenant_id
                            && row.workspace_id == request.workspace_id
                            && row.user_id == request.user_id
                            && row.server_name == request.server_name
                            && row.revoked_at_unix.is_none()
                    })
                else {
                    return Ok(None);
                };
                let key = authorization_generation_key(request);
                let generation = store
                    .mcp_oauth_authorization_generations
                    .get(&key)
                    .unwrap_or(1)
                    .saturating_add(1);
                store
                    .mcp_oauth_authorization_generations
                    .insert(key, generation);
                for mut flow in store.mcp_oauth_flows.list().into_iter().filter(|flow| {
                    flow.tenant_id == request.tenant_id
                        && flow.workspace_id == request.workspace_id
                        && flow.user_id == request.user_id
                        && flow.server_name == request.server_name
                        && flow.consumed_at_unix.is_none()
                }) {
                    flow.consumed_at_unix = Some(revoked_at_unix);
                    store.mcp_oauth_flows.insert(flow.id.clone(), flow);
                }
                let prior = credential.clone();
                credential.revoked_at_unix = Some(revoked_at_unix);
                credential.updated_at_unix = revoked_at_unix;
                credential.version = credential.version.saturating_add(1);
                credential.authorization_generation = generation;
                credential.refresh_lease_id = None;
                credential.refresh_lease_expires_at_unix = None;
                credential.last_revocation_outcome = Some(outcome.to_string());
                store
                    .mcp_oauth_credentials
                    .insert(credential.id.clone(), credential);
                Ok(Some(McpIdentityRevocationOutcome {
                    credential: prior,
                    revoked_at_unix,
                }))
            }
            RuntimeControlPlaneBackend::Postgres(store) => {
                store
                    .revoke_mcp_oauth_identity(request, revoked_at_unix, outcome)
                    .await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("revoke_mcp_oauth_identity"),
            ),
        }
    }

    async fn update_mcp_oauth_revocation_outcome(
        &self,
        tenant_id: &str,
        workspace_id: &str,
        user_id: &str,
        server_name: &str,
        outcome: &str,
    ) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                let Some(mut credential) =
                    store.mcp_oauth_credentials.list().into_iter().find(|row| {
                        row.tenant_id == tenant_id
                            && row.workspace_id == workspace_id
                            && row.user_id == user_id
                            && row.server_name == server_name
                            && row.revoked_at_unix.is_some()
                    })
                else {
                    return Ok(false);
                };
                credential.last_revocation_outcome = Some(outcome.to_string());
                credential.version = credential.version.saturating_add(1);
                store
                    .mcp_oauth_credentials
                    .insert(credential.id.clone(), credential);
                Ok(true)
            }
            RuntimeControlPlaneBackend::Postgres(store) => {
                store
                    .update_mcp_oauth_revocation_outcome(
                        tenant_id,
                        workspace_id,
                        user_id,
                        server_name,
                        outcome,
                    )
                    .await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => {
                Err(super::control_plane_store_d1::unimplemented_surface(
                    "update_mcp_oauth_revocation_outcome",
                ))
            }
        }
    }
}

#[cfg(test)]
#[path = "mcp_identity_test.rs"]
mod mcp_identity_test;
