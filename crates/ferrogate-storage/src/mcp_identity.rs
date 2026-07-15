// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Durable, ciphertext-only per-user MCP OAuth credential repository.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::{
    AppendRepository, PostgresControlPlaneStore, PostgresRow, Repository,
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
    fn authorize_mcp_identity(
        &self,
        request: &McpIdentityAccessRequest,
    ) -> Result<McpIdentityAccessOutcome, StorageError>;
    fn authorize_mcp_identity_with_operation(
        &self,
        request: &McpIdentityAccessRequest,
        operation: &StorageOperation,
    ) -> Result<McpIdentityAccessOutcome, StorageError>;
    fn begin_mcp_oauth_flow(
        &self,
        flow: StoredMcpOauthFlow,
    ) -> Result<StoredMcpOauthFlow, StorageError>;
    fn consume_mcp_oauth_flow(
        &self,
        id: &str,
        consumed_at_unix: i64,
    ) -> Result<Option<StoredMcpOauthFlow>, StorageError>;
    fn commit_mcp_oauth_callback(
        &self,
        flow: &StoredMcpOauthFlow,
        credential: StoredMcpOauthCredential,
        permission_key: &str,
    ) -> Result<McpOauthCallbackCommitOutcome, StorageError>;
    fn get_mcp_oauth_credential(
        &self,
        tenant_id: &str,
        workspace_id: &str,
        user_id: &str,
        server_name: &str,
    ) -> Result<Option<StoredMcpOauthCredential>, StorageError>;
    fn list_mcp_oauth_credentials(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredMcpOauthCredential>, StorageError>;
    fn claim_mcp_oauth_refresh(
        &self,
        request: &McpRefreshClaimRequest,
    ) -> Result<McpRefreshClaimOutcome, StorageError>;
    fn renew_mcp_oauth_refresh(
        &self,
        request: &McpRefreshRenewRequest,
    ) -> Result<McpRefreshRenewOutcome, StorageError>;
    fn complete_mcp_oauth_refresh(
        &self,
        credential: StoredMcpOauthCredential,
        lease_id: &str,
    ) -> Result<bool, StorageError>;
    fn release_mcp_oauth_refresh(
        &self,
        tenant_id: &str,
        credential_id: &str,
        lease_id: &str,
        outcome: &str,
    ) -> Result<bool, StorageError>;
    fn claim_mcp_oauth_refresh_with_operation(
        &self,
        request: &McpRefreshClaimRequest,
        operation: &StorageOperation,
    ) -> Result<McpRefreshClaimOutcome, StorageError>;
    fn renew_mcp_oauth_refresh_with_operation(
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
    fn complete_mcp_oauth_refresh_with_operation(
        &self,
        credential: StoredMcpOauthCredential,
        lease_id: &str,
        operation: &StorageOperation,
    ) -> Result<bool, StorageError>;
    fn release_mcp_oauth_refresh_with_operation(
        &self,
        tenant_id: &str,
        credential_id: &str,
        lease_id: &str,
        outcome: &str,
        operation: &StorageOperation,
    ) -> Result<bool, StorageError>;
    fn revoke_mcp_oauth_identity(
        &self,
        request: &McpIdentityAccessRequest,
        revoked_at_unix: i64,
        outcome: &str,
    ) -> Result<Option<McpIdentityRevocationOutcome>, StorageError>;
    fn update_mcp_oauth_revocation_outcome(
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
    let scopes = super::deserialize_storage_document(&row.get::<_, String>(8))?;
    Ok(StoredMcpOauthCredential {
        id: row.get(0),
        tenant_id: row.get(1),
        workspace_id: row.get(2),
        user_id: row.get(3),
        server_name: row.get(4),
        issuer: row.get(5),
        subject: row.get(6),
        token_type: row.get(7),
        scopes,
        access_token_nonce: row.get(9),
        access_token_ciphertext: row.get(10),
        refresh_token_nonce: row.get(11),
        refresh_token_ciphertext: row.get(12),
        expires_at_unix: row.get(13),
        key_version: u32::try_from(row.get::<_, i64>(14)).unwrap_or(u32::MAX),
        version: u64::try_from(row.get::<_, i64>(15)).unwrap_or(u64::MAX),
        authorization_generation: u64::try_from(row.get::<_, i64>(16)).unwrap_or(u64::MAX),
        refresh_lease_id: row.get(17),
        refresh_lease_expires_at_unix: row.get(18),
        created_at_unix: row.get(19),
        updated_at_unix: row.get(20),
        revoked_at_unix: row.get(21),
        last_refresh_outcome: row.get(22),
        last_revocation_outcome: row.get(23),
    })
}

const CREDENTIAL_COLUMNS: &str = "id, tenant_id, workspace_id, user_id, server_name, issuer, \
    subject, token_type, scopes_json::text, access_token_nonce, access_token_ciphertext, \
    refresh_token_nonce, refresh_token_ciphertext, expires_at_unix, key_version, version, \
    authorization_generation, refresh_lease_id, refresh_lease_expires_at_unix, created_at_unix, \
    updated_at_unix, revoked_at_unix, last_refresh_outcome, last_revocation_outcome";
const MCP_REFRESH_MUTATION_LOCK_TIMEOUT_MILLIS: i32 = 1;
const MCP_REFRESH_MUTATION_STATEMENT_TIMEOUT_MILLIS: i32 = 3_000;
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

fn prepare_mcp_refresh_transaction(
    transaction: &mut postgres::Transaction<'_>,
    tenant_id: &str,
    operation: Option<&StorageOperation>,
    stage: &'static str,
) -> Result<(), StorageError> {
    let lock_timeout = format!("{}ms", mcp_refresh_mutation_lock_timeout_millis(operation)?);
    let statement_timeout_millis =
        mcp_refresh_transaction_statement_timeout_millis(operation, stage)?;
    let statement_timeout = format!("{statement_timeout_millis}ms");
    transaction
        .execute(
            mcp_refresh_transaction_setup_query(),
            &[&tenant_id, &lock_timeout, &statement_timeout],
        )
        .map_err(super::postgres_error)?;
    if let Some(operation) = operation {
        operation.check_active(stage)?;
    }
    Ok(())
}

fn mcp_refresh_transaction_statement_timeout_millis(
    operation: Option<&StorageOperation>,
    stage: &'static str,
) -> Result<i32, StorageError> {
    match operation {
        Some(operation) => operation
            .reconciliation_commit_timeout()
            .map(mcp_statement_timeout_millis)
            .map(Ok)
            .unwrap_or_else(|| mcp_statement_timeout_for_operation(operation, stage)),
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

fn is_mcp_refresh_lock_timeout(error: &postgres::Error) -> bool {
    is_mcp_refresh_lock_timeout_code(error.code())
}

fn is_mcp_refresh_lock_timeout_code(code: Option<&postgres::error::SqlState>) -> bool {
    code == Some(&postgres::error::SqlState::LOCK_NOT_AVAILABLE)
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

fn set_mcp_rls_context(
    transaction: &mut postgres::Transaction<'_>,
    tenant_id: Option<&str>,
) -> Result<(), StorageError> {
    let platform_mode = if tenant_id.is_some() { "off" } else { "on" };
    transaction
        .query_one(
            "SELECT set_config('ferrogate.tenant_id', COALESCE($1, ''), TRUE), \
                    set_config('ferrogate.platform_mode', $2, TRUE)",
            &[&tenant_id, &platform_mode],
        )
        .map_err(super::postgres_error)?;
    Ok(())
}

fn postgres_authorize_mcp_actor(
    transaction: &mut postgres::Transaction<'_>,
    request: &McpIdentityAccessRequest,
) -> Result<McpIdentityAccessOutcome, StorageError> {
    let has_permission = transaction
        .query_one(
            "SELECT EXISTS( \
               SELECT 1 FROM permissions AS permission \
               JOIN tenant_role_bindings AS binding ON binding.tenant_id=$1 \
               JOIN roles AS role ON role.id=binding.role_id \
               WHERE permission.key=$2 \
                 AND jsonb_exists(role.permission_keys_json, permission.key) \
             )",
            &[&request.tenant_id, &request.permission_key],
        )
        .map_err(super::postgres_error)?
        .get::<_, bool>(0);
    if !has_permission {
        return Ok(McpIdentityAccessOutcome::PermissionDenied);
    }
    let user_active = transaction
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM admin_users WHERE id=$1 AND disabled_at_unix IS NULL)",
            &[&request.user_id],
        )
        .map_err(super::postgres_error)?
        .get::<_, bool>(0);
    if !user_active {
        return Ok(McpIdentityAccessOutcome::UserInactive);
    }
    let member = transaction
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM admin_user_tenant_memberships \
             WHERE user_id=$1 AND tenant_id=$2)",
            &[&request.user_id, &request.tenant_id],
        )
        .map_err(super::postgres_error)?
        .get::<_, bool>(0);
    if !member {
        return Ok(McpIdentityAccessOutcome::MembershipRevoked);
    }
    let workspace_active = transaction
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM workspaces \
             WHERE id=$1 AND tenant_id=$2 AND status='active')",
            &[&request.workspace_id, &request.tenant_id],
        )
        .map_err(super::postgres_error)?
        .get::<_, bool>(0);
    if !workspace_active {
        return Ok(McpIdentityAccessOutcome::WorkspaceInactive);
    }
    let query = format!(
        "SELECT {CREDENTIAL_COLUMNS} FROM mcp_oauth_credentials \
         WHERE tenant_id=$1 AND workspace_id=$2 AND user_id=$3 AND server_name=$4"
    );
    let credential = transaction
        .query_opt(
            &query,
            &[
                &request.tenant_id,
                &request.workspace_id,
                &request.user_id,
                &request.server_name,
            ],
        )
        .map_err(super::postgres_error)?
        .as_ref()
        .map(oauth_credential_from_row)
        .transpose()?;
    Ok(McpIdentityAccessOutcome::Allowed(Box::new(credential)))
}

fn prepare_mcp_storage_statement(
    transaction: &mut postgres::Transaction<'_>,
    operation: Option<&StorageOperation>,
    stage: &'static str,
) -> Result<(), StorageError> {
    let Some(operation) = operation else {
        return Ok(());
    };
    let timeout_millis = mcp_statement_timeout_for_operation(operation, stage)?;
    let timeout = format!("{timeout_millis}ms");
    transaction
        .execute(
            "SELECT set_config('statement_timeout', $1, true)",
            &[&timeout],
        )
        .map_err(super::postgres_error)?;
    operation.check_active(stage)
}

fn mcp_statement_timeout_for_operation(
    operation: &StorageOperation,
    stage: &'static str,
) -> Result<i32, StorageError> {
    operation.remaining(stage).map(mcp_statement_timeout_millis)
}

fn mcp_statement_timeout_millis(remaining: std::time::Duration) -> i32 {
    let fractional_millis = u128::from(remaining.subsec_nanos() % 1_000_000 != 0);
    let rounded_up = remaining.as_millis().saturating_add(fractional_millis);
    i32::try_from(rounded_up.clamp(1, i32::MAX as u128)).unwrap_or(i32::MAX)
}

fn mcp_transaction_commit_outcome_unknown(operation: &StorageOperation) -> StorageError {
    StorageError::OperationCommitOutcomeUnknown {
        operation: operation.name(),
        stage: "transaction commit",
    }
}

fn commit_mcp_storage_transaction(
    transaction: postgres::Transaction<'_>,
    operation: Option<&StorageOperation>,
) -> Result<(), StorageError> {
    let Some(operation) = operation else {
        return transaction.commit().map_err(super::postgres_error);
    };
    operation.begin_commit("before transaction commit")?;
    let result = transaction.commit().map_err(|error| {
        tracing::warn!(
            operation = operation.name(),
            storage_stage = "transaction commit",
            sqlstate = error.code().map(postgres::error::SqlState::code),
            outcome = "commit_outcome_unknown",
            "PostgreSQL returned an error after the MCP refresh commit fence"
        );
        mcp_transaction_commit_outcome_unknown(operation)
    });
    operation.finish_commit();
    result
}

fn commit_mcp_storage_read_transaction(
    transaction: postgres::Transaction<'_>,
    operation: Option<&StorageOperation>,
) -> Result<(), StorageError> {
    let Some(operation) = operation else {
        return transaction.commit().map_err(super::postgres_error);
    };
    operation.check_active("before read transaction commit")?;
    transaction.commit().map_err(|error| {
        if error.code() == Some(&postgres::error::SqlState::QUERY_CANCELED) {
            StorageError::OperationDeadlineExceeded {
                operation: operation.name(),
                stage: "read transaction commit",
                commit_started: false,
            }
        } else {
            super::postgres_error(error)
        }
    })
}

enum McpStorageWatchdogOutcome {
    Disarmed,
    CancellationRequested(Result<(), StorageError>),
    CommitCancellationRequested(Result<(), StorageError>),
    CommitAlreadyStarted,
}

struct McpStorageWatchdog {
    disarm: std::sync::mpsc::SyncSender<()>,
    thread: std::thread::JoinHandle<McpStorageWatchdogOutcome>,
}

impl McpStorageWatchdog {
    fn start(
        client: &postgres::Client,
        operation: &StorageOperation,
        config: &super::PostgresStorageConfig,
    ) -> Result<Self, StorageError> {
        let remaining = operation.remaining("storage cancellation watchdog setup")?;
        let cancel_token = client.cancel_token();
        let operation = operation.clone();
        let config = config.clone();
        let (disarm, receiver) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || match receiver.recv_timeout(remaining) {
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                McpStorageWatchdogOutcome::Disarmed
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => match operation.cancel() {
                super::StorageOperationCancelOutcome::Cancelled
                | super::StorageOperationCancelOutcome::AlreadyCancelled => {
                    McpStorageWatchdogOutcome::CancellationRequested(cancel_mcp_storage_query(
                        &cancel_token,
                        &config,
                    ))
                }
                super::StorageOperationCancelOutcome::CommitStarted
                    if !operation.reconciles_commit_after_deadline() =>
                {
                    McpStorageWatchdogOutcome::CommitCancellationRequested(
                        cancel_mcp_storage_query(&cancel_token, &config),
                    )
                }
                super::StorageOperationCancelOutcome::CommitStarted
                | super::StorageOperationCancelOutcome::Finished => {
                    McpStorageWatchdogOutcome::CommitAlreadyStarted
                }
            },
        });
        Ok(Self { disarm, thread })
    }

    fn disarm_and_join(self) -> Result<McpStorageWatchdogOutcome, StorageError> {
        let _ = self.disarm.send(());
        self.thread
            .join()
            .map_err(|_| StorageError::Runtime("MCP storage cancellation watchdog panicked".into()))
    }
}

fn cancel_mcp_storage_query(
    token: &postgres::CancelToken,
    config: &super::PostgresStorageConfig,
) -> Result<(), StorageError> {
    match config.tls_mode {
        super::PostgresTlsMode::Disable => token
            .cancel_query(postgres::NoTls)
            .map_err(super::postgres_connection_error),
        super::PostgresTlsMode::Prefer
        | super::PostgresTlsMode::Require
        | super::PostgresTlsMode::VerifyCa
        | super::PostgresTlsMode::VerifyFull => token
            .cancel_query(super::build_postgres_tls_connector(config)?)
            .map_err(super::postgres_connection_error),
    }
}

impl PostgresControlPlaneStore {
    fn with_mcp_storage_operation<T: Send>(
        &self,
        operation: Option<&StorageOperation>,
        action: impl FnOnce(&mut postgres::Client, Option<&StorageOperation>) -> Result<T, StorageError>
            + Send,
    ) -> Result<T, StorageError> {
        if let Some(operation) = operation {
            let mut client = self.pool.acquire_until(operation)?;
            if let Err(error) = operation.check_active("before storage operation") {
                self.pool.release(client);
                return Err(error);
            }
            let watchdog = match McpStorageWatchdog::start(&client, operation, &self.pool.config) {
                Ok(watchdog) => watchdog,
                Err(error) => {
                    self.pool.release(client);
                    return Err(error);
                }
            };
            let result = operation
                .check_active("before transaction-local timeout setup")
                .and_then(|_| action(&mut client, Some(operation)));
            let watchdog_discard =
                observe_mcp_storage_watchdog(operation.name(), watchdog.disarm_and_join());
            if watchdog_discard {
                let watchdog_error = StorageError::Runtime(
                    "PostgreSQL cancellation watchdog retired the operation connection".into(),
                );
                replenish_mcp_pool_after_discard(
                    Arc::clone(&self.pool),
                    client,
                    "retire a watchdog-cancelled connection",
                    &watchdog_error,
                    storage_result_kind(&result),
                );
                return normalize_mcp_storage_operation_result(result, operation);
            }
            self.pool.release(client);
            normalize_mcp_storage_operation_result(result, operation)
        } else {
            self.with_client_storage(|client| action(client, None))
        }
    }

    fn append_mcp_identity_audit_event_with_operation(
        &self,
        event: &StoredAuditEvent,
        operation: &StorageOperation,
    ) -> Result<(), StorageError> {
        operation.check_active("audit serialization")?;
        let audit_json = super::serialize_storage_document(event)?;
        let tenant_context_id = super::tenant_storage_key(&event.tenant);
        let workflow_version = event.workflow_version.map(|value| value.to_string());
        let occurred_at_unix = super::saturating_i64(
            event
                .occurred_at_unix
                .unwrap_or_else(super::now_unix_seconds),
        );
        self.with_mcp_storage_operation(Some(operation), |client, operation| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            prepare_mcp_storage_statement(&mut transaction, operation, "audit insert")?;
            transaction
                .execute(
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
                )
                .map_err(super::postgres_error)?;
            commit_mcp_storage_transaction(transaction, operation)
        })
    }

    fn authorize_mcp_identity(
        &self,
        request: &McpIdentityAccessRequest,
    ) -> Result<McpIdentityAccessOutcome, StorageError> {
        self.authorize_mcp_identity_impl(request, None)
    }

    fn authorize_mcp_identity_with_operation(
        &self,
        request: &McpIdentityAccessRequest,
        operation: &StorageOperation,
    ) -> Result<McpIdentityAccessOutcome, StorageError> {
        self.authorize_mcp_identity_impl(request, Some(operation))
    }

    fn authorize_mcp_identity_impl(
        &self,
        request: &McpIdentityAccessRequest,
        operation: Option<&StorageOperation>,
    ) -> Result<McpIdentityAccessOutcome, StorageError> {
        self.with_mcp_storage_operation(operation, |client, operation| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            prepare_mcp_storage_statement(
                &mut transaction,
                operation,
                "authorization RLS context",
            )?;
            set_mcp_rls_context(&mut transaction, Some(&request.tenant_id))?;
            prepare_mcp_storage_statement(&mut transaction, operation, "authorization read")?;
            let outcome = postgres_authorize_mcp_actor(&mut transaction, request)?;
            commit_mcp_storage_read_transaction(transaction, operation)?;
            Ok(outcome)
        })
    }

    fn begin_mcp_oauth_flow(
        &self,
        flow: &StoredMcpOauthFlow,
    ) -> Result<StoredMcpOauthFlow, StorageError> {
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            set_mcp_rls_context(&mut transaction, Some(&flow.tenant_id))?;
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
                .map_err(super::postgres_error)?;
            transaction.commit().map_err(super::postgres_error)?;
            Ok(flow)
        })
    }

    fn consume_mcp_oauth_flow(
        &self,
        id: &str,
        consumed_at_unix: i64,
    ) -> Result<Option<StoredMcpOauthFlow>, StorageError> {
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            set_mcp_rls_context(&mut transaction, None)?;
            let row = transaction
                .query_opt(
                    "UPDATE mcp_oauth_flows SET consumed_at_unix = $2 \
                 WHERE id = $1 AND consumed_at_unix IS NULL AND expires_at_unix >= $2 \
                 RETURNING id, tenant_id, workspace_id, user_id, server_name, pkce_nonce, \
                 pkce_ciphertext, oidc_nonce, authorization_generation, created_at_unix, \
                 expires_at_unix, consumed_at_unix",
                    &[&id, &consumed_at_unix],
                )
                .map_err(super::postgres_error)?;
            transaction.commit().map_err(super::postgres_error)?;
            Ok(row.as_ref().map(oauth_flow_from_row))
        })
    }

    fn commit_mcp_oauth_callback(
        &self,
        flow: &StoredMcpOauthFlow,
        credential: &StoredMcpOauthCredential,
        permission_key: &str,
    ) -> Result<McpOauthCallbackCommitOutcome, StorageError> {
        let scopes = super::serialize_storage_document(&credential.scopes)?;
        let key_version = i64::from(credential.key_version);
        let version = super::saturating_i64(credential.version);
        let generation = super::saturating_i64(flow.authorization_generation);
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            set_mcp_rls_context(&mut transaction, Some(&flow.tenant_id))?;
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
            ).map_err(super::postgres_error)?;
            transaction.commit().map_err(super::postgres_error)?;
            Ok(if row.is_some() {
                McpOauthCallbackCommitOutcome::Committed
            } else {
                McpOauthCallbackCommitOutcome::AuthorizationChanged
            })
        })
    }

    fn get_mcp_oauth_credential(
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
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            set_mcp_rls_context(&mut transaction, Some(tenant_id))?;
            let row = transaction
                .query_opt(&query, &[&tenant_id, &workspace_id, &user_id, &server_name])
                .map_err(super::postgres_error)?;
            transaction.commit().map_err(super::postgres_error)?;
            row.as_ref().map(oauth_credential_from_row).transpose()
        })
    }

    fn list_mcp_oauth_credentials(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredMcpOauthCredential>, StorageError> {
        let query = format!(
            "SELECT {CREDENTIAL_COLUMNS} FROM mcp_oauth_credentials \
             WHERE tenant_id=$1 ORDER BY user_id,workspace_id,server_name"
        );
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            set_mcp_rls_context(&mut transaction, Some(tenant_id))?;
            let rows = transaction
                .query(&query, &[&tenant_id])
                .map_err(super::postgres_error)?;
            transaction.commit().map_err(super::postgres_error)?;
            rows.iter().map(oauth_credential_from_row).collect()
        })
    }

    fn claim_mcp_oauth_refresh(
        &self,
        request: &McpRefreshClaimRequest,
    ) -> Result<McpRefreshClaimOutcome, StorageError> {
        self.claim_mcp_oauth_refresh_impl(request, None)
    }

    fn claim_mcp_oauth_refresh_with_operation(
        &self,
        request: &McpRefreshClaimRequest,
        operation: &StorageOperation,
    ) -> Result<McpRefreshClaimOutcome, StorageError> {
        self.claim_mcp_oauth_refresh_impl(request, Some(operation))
    }

    fn claim_mcp_oauth_refresh_impl(
        &self,
        request: &McpRefreshClaimRequest,
        operation: Option<&StorageOperation>,
    ) -> Result<McpRefreshClaimOutcome, StorageError> {
        let busy = conservative_mcp_refresh_claim_busy(request)?;
        let expected_version = super::saturating_i64(request.expected_version);
        let generation = super::saturating_i64(request.authorization_generation);
        let query = postgres_refresh_claim_query();
        self.with_mcp_storage_operation(operation, |client, operation| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            prepare_mcp_refresh_transaction(
                &mut transaction,
                &request.tenant_id,
                operation,
                "refresh claim CAS",
            )?;
            let claimed = match transaction.query_opt(
                &query,
                &[
                    &request.tenant_id,
                    &request.credential_id,
                    &expected_version,
                    &generation,
                    &request.lease_id,
                    &request.lease_ttl_secs,
                ],
            ) {
                Ok(claimed) => claimed,
                Err(error) if is_mcp_refresh_lock_timeout(&error) => {
                    transaction.rollback().map_err(super::postgres_error)?;
                    tracing::info!(
                        operation = operation
                            .map(StorageOperation::name)
                            .unwrap_or("claim MCP refresh lease"),
                        storage_stage = "refresh claim CAS",
                        outcome = "lock_conflict_busy",
                        "mapped MCP refresh claim lock contention to waiter backoff"
                    );
                    return Ok(busy);
                }
                Err(error) => return Err(super::postgres_error(error)),
            };
            let Some(claimed) = claimed.as_ref() else {
                commit_mcp_storage_transaction(transaction, operation)?;
                tracing::debug!(
                    operation = operation
                        .map(StorageOperation::name)
                        .unwrap_or("claim MCP refresh lease"),
                    storage_stage = "refresh claim CAS",
                    outcome = "cas_busy",
                    "MCP refresh claim CAS did not acquire the lease"
                );
                return Ok(busy);
            };
            let outcome = McpRefreshClaimOutcome::Acquired(oauth_credential_from_row(claimed)?);
            commit_mcp_storage_transaction(transaction, operation)?;
            Ok(outcome)
        })
    }

    fn renew_mcp_oauth_refresh(
        &self,
        request: &McpRefreshRenewRequest,
    ) -> Result<McpRefreshRenewOutcome, StorageError> {
        self.renew_mcp_oauth_refresh_impl(request, None)
    }

    fn renew_mcp_oauth_refresh_with_operation(
        &self,
        request: &McpRefreshRenewRequest,
        operation: &StorageOperation,
    ) -> Result<McpRefreshRenewOutcome, StorageError> {
        self.renew_mcp_oauth_refresh_impl(request, Some(operation))
    }

    fn renew_mcp_oauth_refresh_impl(
        &self,
        request: &McpRefreshRenewRequest,
        operation: Option<&StorageOperation>,
    ) -> Result<McpRefreshRenewOutcome, StorageError> {
        let _ = require_refresh_lease_expiry(request.now_unix, request.lease_ttl_secs)?;
        let expected_version = super::saturating_i64(request.expected_version);
        let generation = super::saturating_i64(request.authorization_generation);
        self.with_mcp_storage_operation(operation, |client, operation| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            prepare_mcp_refresh_transaction(
                &mut transaction,
                &request.tenant_id,
                operation,
                "refresh renewal CAS",
            )?;
            let renewed = match transaction.query_opt(
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
            ) {
                Ok(renewed) => renewed,
                Err(error) if is_mcp_refresh_lock_timeout(&error) => {
                    transaction.rollback().map_err(super::postgres_error)?;
                    tracing::warn!(
                        operation = operation
                            .map(StorageOperation::name)
                            .unwrap_or("renew MCP refresh lease"),
                        storage_stage = "refresh renewal CAS",
                        outcome = "lock_conflict_fenced",
                        "fenced MCP refresh renewal after bounded lock contention"
                    );
                    return Ok(McpRefreshRenewOutcome::OwnershipChanged);
                }
                Err(error) => return Err(super::postgres_error(error)),
            };
            let outcome = classify_postgres_mcp_refresh_renewal(renewed.as_ref(), request);
            if !matches!(outcome, McpRefreshRenewOutcome::Renewed { .. }) {
                commit_mcp_storage_transaction(transaction, operation)?;
                tracing::warn!(
                    operation = operation
                        .map(StorageOperation::name)
                        .unwrap_or("renew MCP refresh lease"),
                    storage_stage = "refresh renewal CAS",
                    outcome = "cas_fenced",
                    "classified an MCP refresh renewal that lost its mutation fence"
                );
                return Ok(outcome);
            }
            commit_mcp_storage_transaction(transaction, operation)?;
            Ok(outcome)
        })
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

    fn complete_mcp_oauth_refresh(
        &self,
        credential: &StoredMcpOauthCredential,
        lease_id: &str,
    ) -> Result<bool, StorageError> {
        self.complete_mcp_oauth_refresh_impl(credential, lease_id, None)
    }

    fn complete_mcp_oauth_refresh_with_operation(
        &self,
        credential: &StoredMcpOauthCredential,
        lease_id: &str,
        operation: &StorageOperation,
    ) -> Result<bool, StorageError> {
        self.complete_mcp_oauth_refresh_impl(credential, lease_id, Some(operation))
    }

    fn complete_mcp_oauth_refresh_impl(
        &self,
        credential: &StoredMcpOauthCredential,
        lease_id: &str,
        operation: Option<&StorageOperation>,
    ) -> Result<bool, StorageError> {
        let scopes = super::serialize_storage_document(&credential.scopes)?;
        let key_version = i64::from(credential.key_version);
        let expected_version = super::saturating_i64(credential.version);
        let generation = super::saturating_i64(credential.authorization_generation);
        self.with_mcp_storage_operation(operation, |client, operation| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            prepare_mcp_refresh_transaction(
                &mut transaction,
                &credential.tenant_id,
                operation,
                "refresh completion CAS",
            )?;
            let affected = transaction.execute(
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
            ).map_err(super::postgres_error)?;
            commit_mcp_storage_transaction(transaction, operation)?;
            Ok(affected == 1)
        })
    }

    fn release_mcp_oauth_refresh(
        &self,
        tenant_id: &str,
        credential_id: &str,
        lease_id: &str,
        outcome: &str,
    ) -> Result<bool, StorageError> {
        self.release_mcp_oauth_refresh_impl(tenant_id, credential_id, lease_id, outcome, None)
    }

    fn release_mcp_oauth_refresh_with_operation(
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
    }

    fn release_mcp_oauth_refresh_impl(
        &self,
        tenant_id: &str,
        credential_id: &str,
        lease_id: &str,
        outcome: &str,
        operation: Option<&StorageOperation>,
    ) -> Result<bool, StorageError> {
        self.with_mcp_storage_operation(operation, |client, operation| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            prepare_mcp_refresh_transaction(
                &mut transaction,
                tenant_id,
                operation,
                "refresh release CAS",
            )?;
            let affected = transaction
                .execute(
                    "UPDATE mcp_oauth_credentials SET refresh_lease_id=NULL, \
                 refresh_lease_expires_at_unix=NULL,last_refresh_outcome=$4 \
                 WHERE tenant_id=$1 AND id=$2 AND refresh_lease_id=$3 AND revoked_at_unix IS NULL",
                    &[&tenant_id, &credential_id, &lease_id, &outcome],
                )
                .map_err(super::postgres_error)?;
            commit_mcp_storage_transaction(transaction, operation)?;
            Ok(affected == 1)
        })
    }

    fn revoke_mcp_oauth_identity(
        &self,
        request: &McpIdentityAccessRequest,
        revoked_at_unix: i64,
        outcome: &str,
    ) -> Result<Option<McpIdentityRevocationOutcome>, StorageError> {
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            prepare_mcp_refresh_transaction(
                &mut transaction,
                &request.tenant_id,
                None,
                "MCP identity revoke CAS",
            )?;
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
                .map_err(super::postgres_error)?;
            transaction.commit().map_err(super::postgres_error)?;
            row.as_ref()
                .map(oauth_credential_from_row)
                .transpose()
                .map(|credential| {
                    credential.map(|credential| McpIdentityRevocationOutcome {
                        credential,
                        revoked_at_unix,
                    })
                })
        })
    }

    fn update_mcp_oauth_revocation_outcome(
        &self,
        tenant_id: &str,
        workspace_id: &str,
        user_id: &str,
        server_name: &str,
        outcome: &str,
    ) -> Result<bool, StorageError> {
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            set_mcp_rls_context(&mut transaction, Some(tenant_id))?;
            let affected = transaction.execute(
                "UPDATE mcp_oauth_credentials SET last_revocation_outcome=$5,version=version+1 \
                 WHERE tenant_id=$1 AND workspace_id=$2 AND user_id=$3 AND server_name=$4 \
                 AND revoked_at_unix IS NOT NULL",
                &[&tenant_id, &workspace_id, &user_id, &server_name, &outcome],
            ).map_err(super::postgres_error)?;
            transaction.commit().map_err(super::postgres_error)?;
            Ok(affected == 1)
        })
    }
}

impl RuntimeStorageRepositories {
    pub fn append_mcp_identity_audit_event_with_operation(
        &self,
        event: StoredAuditEvent,
        operation: &StorageOperation,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(store) => {
                store.append_mcp_identity_audit_event_with_operation(&event, operation)
            }
            RuntimeControlPlaneBackend::Memory(_) => {
                operation.begin_commit("in-memory MCP identity audit append")?;
                let result = self
                    .audit_events
                    .lock()
                    .map_err(|_| StorageError::Runtime("audit event store lock poisoned".into()))
                    .map(|mut events| events.append(event));
                operation.finish_commit();
                result
            }
        }
    }
}

fn storage_result_kind<T>(result: &Result<T, StorageError>) -> &'static str {
    match result {
        Ok(_) => "success",
        Err(StorageError::UnsupportedProvider { .. }) => "unsupported_provider",
        Err(StorageError::Postgres(_)) => "postgres_error",
        Err(StorageError::Runtime(_)) => "runtime_error",
        Err(StorageError::Serialization(_)) => "serialization_error",
        Err(StorageError::Conflict(_)) => "conflict",
        Err(StorageError::NotFound(_)) => "not_found",
        Err(StorageError::OperationDeadlineExceeded { .. }) => "deadline_exceeded",
        Err(StorageError::OperationCancelled { .. }) => "cancelled",
        Err(StorageError::OperationCommitOutcomeUnknown { .. }) => "commit_outcome_unknown",
    }
}

fn normalize_mcp_storage_operation_result<T>(
    result: Result<T, StorageError>,
    operation: &StorageOperation,
) -> Result<T, StorageError> {
    match result {
        Err(StorageError::Postgres(error)) if error.contains("statement timeout") => {
            let _ = operation.cancel();
            Err(StorageError::OperationDeadlineExceeded {
                operation: operation.name(),
                stage: "SQL execution",
                commit_started: false,
            })
        }
        Err(error @ StorageError::Postgres(_)) => match operation.remaining("after SQL error") {
            Err(deadline @ StorageError::OperationDeadlineExceeded { .. })
            | Err(deadline @ StorageError::OperationCancelled { .. }) => Err(deadline),
            _ => Err(error),
        },
        result => result,
    }
}

fn observe_mcp_storage_watchdog(
    operation: &'static str,
    outcome: Result<McpStorageWatchdogOutcome, StorageError>,
) -> bool {
    match outcome {
        Ok(McpStorageWatchdogOutcome::Disarmed) => false,
        Ok(McpStorageWatchdogOutcome::CommitAlreadyStarted) => {
            tracing::debug!(
                operation,
                outcome = "watchdog_commit_started",
                "MCP storage cancellation watchdog left commit reconciliation authoritative"
            );
            false
        }
        Ok(McpStorageWatchdogOutcome::CancellationRequested(Ok(()))) => {
            tracing::warn!(
                operation,
                storage_stage = "SQL execution",
                outcome = "watchdog_cancel_requested",
                pool_action = "discard_and_replenish",
                "MCP storage cancellation watchdog requested PostgreSQL query cancellation"
            );
            true
        }
        Ok(McpStorageWatchdogOutcome::CommitCancellationRequested(Ok(()))) => {
            tracing::warn!(
                operation,
                storage_stage = "transaction commit",
                outcome = "watchdog_commit_cancel_requested",
                pool_action = "discard_and_replenish",
                "MCP storage cancellation watchdog requested cancellation of an ambiguous commit"
            );
            true
        }
        Ok(McpStorageWatchdogOutcome::CancellationRequested(Err(error))) | Err(error) => {
            tracing::warn!(
                operation,
                error_kind = storage_result_kind::<()>(&Err(error.clone())),
                error_detail = %super::sanitize_storage_error(&error.to_string()),
                outcome = "watchdog_cancel_failed",
                "MCP storage cancellation watchdog could not confirm query cancellation"
            );
            true
        }
        Ok(McpStorageWatchdogOutcome::CommitCancellationRequested(Err(error))) => {
            tracing::warn!(
                operation,
                error_kind = storage_result_kind::<()>(&Err(error.clone())),
                error_detail = %super::sanitize_storage_error(&error.to_string()),
                outcome = "watchdog_commit_cancel_failed",
                "MCP storage cancellation watchdog could not confirm ambiguous commit cancellation"
            );
            true
        }
    }
}

fn replenish_mcp_pool_after_discard(
    pool: Arc<super::PostgresClientPool>,
    client: postgres::Client,
    stage: &'static str,
    error: &StorageError,
    operation_result: &'static str,
) {
    tracing::warn!(
        stage,
        operation_result,
        cleanup_error = %super::sanitize_storage_error(&error.to_string()),
        pool_state = "replenishing",
        "discarded a contaminated MCP storage client without overriding its authoritative operation result"
    );
    let _ = std::thread::spawn(move || {
        drop(client);
        retry_mcp_pool_replenishment(
            || {
                let replacement = super::connect_postgres_client(&pool.config)?;
                pool.release(replacement);
                Ok(())
            },
            std::thread::sleep,
            |attempt, error| {
                tracing::error!(
                    stage,
                    attempt,
                    pool_state = "replenish_retry",
                    error_detail = %super::sanitize_storage_error(&error.to_string()),
                    "failed to replenish MCP storage pool; capacity remains scheduled for recovery"
                );
            },
        );
        tracing::info!(
            stage,
            pool_state = "restored",
            "replenished MCP storage pool after discarding a contaminated client"
        );
    });
}

fn retry_mcp_pool_replenishment(
    mut replenish: impl FnMut() -> Result<(), StorageError>,
    mut wait: impl FnMut(std::time::Duration),
    mut on_failure: impl FnMut(u32, &StorageError),
) {
    let mut attempt = 0_u32;
    loop {
        match replenish() {
            Ok(()) => return,
            Err(error) => {
                attempt = attempt.saturating_add(1);
                on_failure(attempt, &error);
                wait(mcp_pool_replenish_backoff(attempt));
            }
        }
    }
}

fn mcp_pool_replenish_backoff(attempt: u32) -> std::time::Duration {
    let exponent = attempt.saturating_sub(1).min(6);
    std::time::Duration::from_millis(100_u64.saturating_mul(1_u64 << exponent))
        .min(std::time::Duration::from_secs(5))
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
    if !store
        .workspaces
        .get(&request.workspace_id)
        .is_some_and(|workspace| {
            workspace.tenant_id == request.tenant_id && workspace.status == "active"
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
    fn authorize_mcp_identity(
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
            RuntimeControlPlaneBackend::Postgres(store) => store.authorize_mcp_identity(request),
        }
    }

    fn authorize_mcp_identity_with_operation(
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
                store.authorize_mcp_identity_with_operation(request, operation)
            }
        }
    }

    fn begin_mcp_oauth_flow(
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
            RuntimeControlPlaneBackend::Postgres(store) => store.begin_mcp_oauth_flow(&flow),
        }
    }

    fn consume_mcp_oauth_flow(
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
                store.consume_mcp_oauth_flow(id, consumed_at_unix)
            }
        }
    }

    fn commit_mcp_oauth_callback(
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
                store.commit_mcp_oauth_callback(flow, &credential, permission_key)
            }
        }
    }

    fn get_mcp_oauth_credential(
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
                store.get_mcp_oauth_credential(tenant_id, workspace_id, user_id, server_name)
            }
        }
    }

    fn list_mcp_oauth_credentials(
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
                store.list_mcp_oauth_credentials(tenant_id)
            }
        }
    }

    fn claim_mcp_oauth_refresh(
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
            RuntimeControlPlaneBackend::Postgres(store) => store.claim_mcp_oauth_refresh(request),
        }
    }

    fn renew_mcp_oauth_refresh(
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
            RuntimeControlPlaneBackend::Postgres(store) => store.renew_mcp_oauth_refresh(request),
        }
    }

    fn complete_mcp_oauth_refresh(
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
                store.complete_mcp_oauth_refresh(&credential, lease_id)
            }
        }
    }

    fn release_mcp_oauth_refresh(
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
                store.release_mcp_oauth_refresh(tenant_id, credential_id, lease_id, outcome)
            }
        }
    }

    fn claim_mcp_oauth_refresh_with_operation(
        &self,
        request: &McpRefreshClaimRequest,
        operation: &StorageOperation,
    ) -> Result<McpRefreshClaimOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(store) => {
                store.claim_mcp_oauth_refresh_with_operation(request, operation)
            }
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                claim_in_memory_mcp_oauth_refresh(&mut store, request, Some(operation))
            }
        }
    }

    fn renew_mcp_oauth_refresh_with_operation(
        &self,
        request: &McpRefreshRenewRequest,
        operation: &StorageOperation,
    ) -> Result<McpRefreshRenewOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(store) => {
                store.renew_mcp_oauth_refresh_with_operation(request, operation)
            }
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                renew_in_memory_mcp_oauth_refresh(&mut store, request, Some(operation))
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
        }
    }

    fn complete_mcp_oauth_refresh_with_operation(
        &self,
        credential: StoredMcpOauthCredential,
        lease_id: &str,
        operation: &StorageOperation,
    ) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(store) => {
                store.complete_mcp_oauth_refresh_with_operation(&credential, lease_id, operation)
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
        }
    }

    fn release_mcp_oauth_refresh_with_operation(
        &self,
        tenant_id: &str,
        credential_id: &str,
        lease_id: &str,
        outcome: &str,
        operation: &StorageOperation,
    ) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Postgres(store) => store
                .release_mcp_oauth_refresh_with_operation(
                    tenant_id,
                    credential_id,
                    lease_id,
                    outcome,
                    operation,
                ),
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
        }
    }

    fn revoke_mcp_oauth_identity(
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
                store.revoke_mcp_oauth_identity(request, revoked_at_unix, outcome)
            }
        }
    }

    fn update_mcp_oauth_revocation_outcome(
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
            RuntimeControlPlaneBackend::Postgres(store) => store
                .update_mcp_oauth_revocation_outcome(
                    tenant_id,
                    workspace_id,
                    user_id,
                    server_name,
                    outcome,
                ),
        }
    }
}

#[cfg(test)]
#[path = "mcp_identity_test.rs"]
mod mcp_identity_test;
