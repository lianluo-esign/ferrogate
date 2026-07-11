// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Durable, ciphertext-only per-user MCP OAuth credential repository.

use serde::{Deserialize, Serialize};

use super::{
    PostgresControlPlaneStore, PostgresRow, Repository, RuntimeControlPlaneBackend,
    RuntimeStorageRepositories, StorageError,
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

pub trait McpCredentialRepository {
    fn authorize_mcp_identity(
        &self,
        request: &McpIdentityAccessRequest,
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

    fn from_postgres_row(row: &PostgresRow) -> Self {
        Self {
            tenant_matches: true,
            version: u64::try_from(row.get::<_, i64>(0)).unwrap_or(u64::MAX),
            authorization_generation: u64::try_from(row.get::<_, i64>(1)).unwrap_or(u64::MAX),
            refresh_lease_id: row.get(2),
            refresh_lease_expires_at_unix: row.get(3),
            revoked: row.get::<_, Option<i64>>(4).is_some(),
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

impl PostgresControlPlaneStore {
    fn authorize_mcp_identity(
        &self,
        request: &McpIdentityAccessRequest,
    ) -> Result<McpIdentityAccessOutcome, StorageError> {
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            set_mcp_rls_context(&mut transaction, Some(&request.tenant_id))?;
            let outcome = postgres_authorize_mcp_actor(&mut transaction, request)?;
            transaction.commit().map_err(super::postgres_error)?;
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
        let expected_version = super::saturating_i64(request.expected_version);
        let generation = super::saturating_i64(request.authorization_generation);
        let query = format!(
            "SELECT {CREDENTIAL_COLUMNS} FROM mcp_oauth_credentials \
             WHERE tenant_id=$1 AND id=$2 FOR UPDATE"
        );
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            set_mcp_rls_context(&mut transaction, Some(&request.tenant_id))?;
            let current = transaction
                .query_opt(&query, &[&request.tenant_id, &request.credential_id])
                .map_err(super::postgres_error)?
                .as_ref()
                .map(oauth_credential_from_row)
                .transpose()?;
            let operation_now_unix = transaction
                .query_one(
                    "SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT",
                    &[],
                )
                .map_err(super::postgres_error)?
                .get::<_, i64>(0);
            let lease_expires_at_unix =
                require_refresh_lease_expiry(operation_now_unix, request.lease_ttl_secs)?;
            let current = match classify_mcp_refresh_claim(current, request, operation_now_unix) {
                McpRefreshClaimClassification::Acquirable(current) => current,
                McpRefreshClaimClassification::Outcome(outcome) => {
                    transaction.commit().map_err(super::postgres_error)?;
                    return Ok(outcome);
                }
            };
            let claimed = transaction
                .query_opt(
                    &format!(
                        "UPDATE mcp_oauth_credentials SET refresh_lease_id=$5, \
                         refresh_lease_expires_at_unix=$6,last_refresh_outcome='refreshing' \
                         WHERE tenant_id=$1 AND id=$2 AND version=$3 \
                           AND authorization_generation=$4 AND revoked_at_unix IS NULL \
                           AND (refresh_lease_id IS NULL OR refresh_lease_expires_at_unix <= $7) \
                         RETURNING {CREDENTIAL_COLUMNS}"
                    ),
                    &[
                        &request.tenant_id,
                        &request.credential_id,
                        &expected_version,
                        &generation,
                        &request.lease_id,
                        &lease_expires_at_unix,
                        &operation_now_unix,
                    ],
                )
                .map_err(super::postgres_error)?;
            let Some(claimed) = claimed.as_ref() else {
                return Err(StorageError::Conflict(format!(
                    "MCP refresh credential {} changed while claiming the locked lease",
                    current.id
                )));
            };
            let outcome = McpRefreshClaimOutcome::Acquired(oauth_credential_from_row(claimed)?);
            transaction.commit().map_err(super::postgres_error)?;
            Ok(outcome)
        })
    }

    fn renew_mcp_oauth_refresh(
        &self,
        request: &McpRefreshRenewRequest,
    ) -> Result<McpRefreshRenewOutcome, StorageError> {
        let expected_version = super::saturating_i64(request.expected_version);
        let generation = super::saturating_i64(request.authorization_generation);
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            set_mcp_rls_context(&mut transaction, Some(&request.tenant_id))?;
            let current = transaction
                .query_opt(
                    "SELECT version, authorization_generation, refresh_lease_id, \
                            refresh_lease_expires_at_unix, revoked_at_unix \
                     FROM mcp_oauth_credentials \
                     WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                    &[&request.tenant_id, &request.credential_id],
                )
                .map_err(super::postgres_error)?
                .as_ref()
                .map(McpRefreshLeaseState::from_postgres_row);
            if current.is_none() {
                transaction.commit().map_err(super::postgres_error)?;
                return Ok(McpRefreshRenewOutcome::Missing);
            }
            let operation_now_unix = transaction
                .query_one(
                    "SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT",
                    &[],
                )
                .map_err(super::postgres_error)?
                .get::<_, i64>(0);
            let lease_expires_at_unix = derive_refresh_lease_renewal_expiry(
                operation_now_unix,
                request.lease_ttl_secs,
                current
                    .as_ref()
                    .and_then(|state| state.refresh_lease_expires_at_unix),
            );
            if let Some(outcome) = mcp_refresh_renewal_rejection(
                current.as_ref(),
                request,
                operation_now_unix,
                lease_expires_at_unix,
            ) {
                transaction.commit().map_err(super::postgres_error)?;
                return Ok(outcome);
            }
            let lease_expires_at_unix = lease_expires_at_unix.ok_or_else(|| {
                StorageError::Runtime("MCP refresh renewal accepted a nonpositive lease TTL".into())
            })?;
            let affected = transaction
                .execute(
                    "UPDATE mcp_oauth_credentials SET refresh_lease_expires_at_unix=$7 \
                     WHERE tenant_id=$1 AND id=$2 AND version=$3 \
                       AND authorization_generation=$4 AND refresh_lease_id=$5 \
                       AND revoked_at_unix IS NULL \
                       AND refresh_lease_expires_at_unix > $6 \
                       AND $7 > refresh_lease_expires_at_unix",
                    &[
                        &request.tenant_id,
                        &request.credential_id,
                        &expected_version,
                        &generation,
                        &request.lease_id,
                        &operation_now_unix,
                        &lease_expires_at_unix,
                    ],
                )
                .map_err(super::postgres_error)?;
            if affected != 1 {
                return Err(StorageError::Conflict(format!(
                    "MCP refresh lease {} changed while renewing",
                    request.lease_id
                )));
            }
            transaction.commit().map_err(super::postgres_error)?;
            Ok(McpRefreshRenewOutcome::Renewed {
                lease_expires_at_unix,
            })
        })
    }

    fn complete_mcp_oauth_refresh(
        &self,
        credential: &StoredMcpOauthCredential,
        lease_id: &str,
    ) -> Result<bool, StorageError> {
        let scopes = super::serialize_storage_document(&credential.scopes)?;
        let key_version = i64::from(credential.key_version);
        let expected_version = super::saturating_i64(credential.version);
        let generation = super::saturating_i64(credential.authorization_generation);
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            set_mcp_rls_context(&mut transaction, Some(&credential.tenant_id))?;
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
            transaction.commit().map_err(super::postgres_error)?;
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
        self.with_client_storage(|client| {
            let mut transaction = client.transaction().map_err(super::postgres_error)?;
            set_mcp_rls_context(&mut transaction, Some(tenant_id))?;
            let affected = transaction
                .execute(
                    "UPDATE mcp_oauth_credentials SET refresh_lease_id=NULL, \
                 refresh_lease_expires_at_unix=NULL,last_refresh_outcome=$4 \
                 WHERE tenant_id=$1 AND id=$2 AND refresh_lease_id=$3 AND revoked_at_unix IS NULL",
                    &[&tenant_id, &credential_id, &lease_id, &outcome],
                )
                .map_err(super::postgres_error)?;
            transaction.commit().map_err(super::postgres_error)?;
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
            set_mcp_rls_context(&mut transaction, Some(&request.tenant_id))?;
            let query = format!("SELECT {CREDENTIAL_COLUMNS} FROM mcp_oauth_credentials \
                 WHERE tenant_id=$1 AND workspace_id=$2 AND user_id=$3 AND server_name=$4 \
                   AND revoked_at_unix IS NULL FOR UPDATE");
            let Some(row) = transaction.query_opt(
                &query,
                &[&request.tenant_id,&request.workspace_id,&request.user_id,&request.server_name],
            ).map_err(super::postgres_error)? else {
                transaction.commit().map_err(super::postgres_error)?;
                return Ok(None);
            };
            let credential = oauth_credential_from_row(&row)?;
            let generation = transaction.query_one(
                "INSERT INTO mcp_oauth_authorization_states \
                 (tenant_id,workspace_id,user_id,server_name,generation,updated_at_unix) \
                 VALUES ($1,$2,$3,$4,2,$5) \
                 ON CONFLICT (tenant_id,workspace_id,user_id,server_name) DO UPDATE SET \
                   generation=mcp_oauth_authorization_states.generation+1,updated_at_unix=EXCLUDED.updated_at_unix \
                 RETURNING generation",
                &[&request.tenant_id,&request.workspace_id,&request.user_id,&request.server_name,&revoked_at_unix],
            ).map_err(super::postgres_error)?.get::<_, i64>(0);
            transaction.execute(
                "UPDATE mcp_oauth_flows SET consumed_at_unix=$5 \
                 WHERE tenant_id=$1 AND workspace_id=$2 AND user_id=$3 AND server_name=$4 \
                   AND consumed_at_unix IS NULL",
                &[&request.tenant_id,&request.workspace_id,&request.user_id,&request.server_name,&revoked_at_unix],
            ).map_err(super::postgres_error)?;
            transaction.execute(
                "UPDATE mcp_oauth_credentials SET revoked_at_unix=$5,updated_at_unix=$5, \
                 version=version+1,authorization_generation=$6,refresh_lease_id=NULL, \
                 refresh_lease_expires_at_unix=NULL,last_revocation_outcome=$7 \
                 WHERE tenant_id=$1 AND workspace_id=$2 AND user_id=$3 AND server_name=$4",
                &[&request.tenant_id,&request.workspace_id,&request.user_id,&request.server_name,
                  &revoked_at_unix,&generation,&outcome],
            ).map_err(super::postgres_error)?;
            transaction.commit().map_err(super::postgres_error)?;
            Ok(Some(McpIdentityRevocationOutcome { credential, revoked_at_unix }))
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
        let lease_expires_at_unix =
            require_refresh_lease_expiry(request.now_unix, request.lease_ttl_secs)?;
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
                let current = store.mcp_oauth_credentials.get(&request.credential_id);
                let mut current =
                    match classify_mcp_refresh_claim(current, request, request.now_unix) {
                        McpRefreshClaimClassification::Acquirable(current) => current,
                        McpRefreshClaimClassification::Outcome(outcome) => return Ok(outcome),
                    };
                current.refresh_lease_id = Some(request.lease_id.clone());
                current.refresh_lease_expires_at_unix = Some(lease_expires_at_unix);
                current.last_refresh_outcome = Some("refreshing".into());
                store
                    .mcp_oauth_credentials
                    .insert(current.id.clone(), current.clone());
                Ok(McpRefreshClaimOutcome::Acquired(current))
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
                let current = store.mcp_oauth_credentials.get(&request.credential_id);
                let lease_state = current.as_ref().map(|credential| {
                    McpRefreshLeaseState::from_credential(credential, &request.tenant_id)
                });
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
                    StorageError::Runtime(
                        "MCP refresh renewal accepted a nonpositive lease TTL".into(),
                    )
                })?;
                current.refresh_lease_expires_at_unix = Some(lease_expires_at_unix);
                store
                    .mcp_oauth_credentials
                    .insert(current.id.clone(), current);
                Ok(McpRefreshRenewOutcome::Renewed {
                    lease_expires_at_unix,
                })
            }
            RuntimeControlPlaneBackend::Postgres(store) => store.renew_mcp_oauth_refresh(request),
        }
    }

    fn complete_mcp_oauth_refresh(
        &self,
        mut credential: StoredMcpOauthCredential,
        lease_id: &str,
    ) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(store) => {
                let mut store = store.lock().map_err(|_| {
                    StorageError::Runtime("MCP OAuth credential store lock poisoned".into())
                })?;
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
                credential.version = current.version.saturating_add(1);
                credential.refresh_lease_id = None;
                credential.refresh_lease_expires_at_unix = None;
                store
                    .mcp_oauth_credentials
                    .insert(credential.id.clone(), credential);
                Ok(true)
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
                let Some(mut credential) = store.mcp_oauth_credentials.get(credential_id) else {
                    return Ok(false);
                };
                if credential.tenant_id != tenant_id
                    || credential.refresh_lease_id.as_deref() != Some(lease_id)
                    || credential.revoked_at_unix.is_some()
                {
                    return Ok(false);
                }
                credential.refresh_lease_id = None;
                credential.refresh_lease_expires_at_unix = None;
                credential.last_refresh_outcome = Some(outcome.to_string());
                store
                    .mcp_oauth_credentials
                    .insert(credential.id.clone(), credential);
                Ok(true)
            }
            RuntimeControlPlaneBackend::Postgres(store) => {
                store.release_mcp_oauth_refresh(tenant_id, credential_id, lease_id, outcome)
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
