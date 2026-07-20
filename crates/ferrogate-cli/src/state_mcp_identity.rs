// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Per-user MCP OAuth/OIDC identity lifecycle and fail-closed dispatch resolution.

use super::*;
use crate::auth::AuthContext;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use ferrogate_mcp::{McpAuthType, McpDispatchHeaders, McpOauthConfig};
use ferrogate_storage::{
    McpCredentialRepository, McpIdentityAccessOutcome, McpIdentityAccessRequest,
    McpOauthCallbackCommitOutcome, McpRefreshClaimOutcome, McpRefreshClaimRequest,
    McpRefreshRenewOutcome, McpRefreshRenewRequest, StorageOperation,
    StorageOperationCancelOutcome, StoredMcpOauthCredential, StoredMcpOauthFlow,
};
use http::StatusCode;
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::future::Future;
use tracing::Instrument;

const MCP_IDENTITY_KEY_ENV: &str = "FERROGATE_MCP_IDENTITY_KEY";
const OAUTH_FLOW_TTL_SECS: i64 = 600;
const SIGNED_IDENTITY_TTL_SECS: i64 = 60;
const TOKEN_REFRESH_SKEW_SECS: i64 = 30;
const REFRESH_LEASE_SECS: i64 = 30;
const REFRESH_HEARTBEAT_SECS: u64 = 3;
const REFRESH_RENEWAL_TIMEOUT_SECS: u64 = 11;
const REFRESH_OWNER_TIMEOUT_SECS: u64 = 60;
const REFRESH_WAIT_TIMEOUT_SECS: u64 = 45;
const REFRESH_WAIT_MIN_MILLIS: u64 = 50;
const REFRESH_WAIT_MAX_MILLIS: u64 = 750;
const REFRESH_WAIT_JITTER_MILLIS: u64 = 50;
const REFRESH_STORAGE_OPERATION_TIMEOUT_SECS: u64 = 4;
const REFRESH_STORAGE_RESPONSE_TIMEOUT_SECS: u64 = 5;
const REFRESH_STORAGE_RECONCILABLE_COMMIT_TIMEOUT_SECS: u64 = 10;
// Claim is a short optimistic CAS. Keep its deadline separate so the waiter state
// machine cannot turn ordinary contention into a long database lock wait.
const REFRESH_CLAIM_OPERATION_TIMEOUT_SECS: u64 = 4;
const REFRESH_CLAIM_RESPONSE_TIMEOUT_SECS: u64 = 5;
const MCP_IDENTITY_AUTH_READ_OPERATION_TIMEOUT_SECS: u64 = 4;
const MCP_IDENTITY_AUTH_READ_RESPONSE_TIMEOUT_SECS: u64 = 5;
const REFRESH_AUTH_READ_OPERATION_TIMEOUT_SECS: u64 = 8;
const REFRESH_AUTH_READ_RESPONSE_TIMEOUT_SECS: u64 = 10;
const REFRESH_STORAGE_RECONCILE_TIMEOUT_SECS: u64 = 1;
const REFRESH_STORAGE_AUTHORITATIVE_CANCEL_GRACE_SECS: u64 = 1;
const REFRESH_STORAGE_AUTHORITATIVE_REREAD_TIMEOUT_SECS: u64 = 3;
const MCP_IDENTITY_ERROR_AUDIT_TIMEOUT: Duration = Duration::from_secs(1);
const MCP_IDENTITY_ERROR_AUDIT_JOIN_GRACE: Duration = Duration::from_millis(250);
const MAX_OIDC_RESPONSE_BYTES: usize = 1024 * 1024;

const _: () = {
    assert!(
        REFRESH_LEASE_SECS as u64 > REFRESH_HEARTBEAT_SECS + (2 * REFRESH_RENEWAL_TIMEOUT_SECS) + 1
    );
    assert!(
        REFRESH_WAIT_TIMEOUT_SECS
            >= REFRESH_LEASE_SECS as u64 + REFRESH_CLAIM_RESPONSE_TIMEOUT_SECS + 5
    );
    assert!(REFRESH_OWNER_TIMEOUT_SECS > REFRESH_WAIT_TIMEOUT_SECS);
    assert!(REFRESH_RENEWAL_TIMEOUT_SECS > REFRESH_STORAGE_RESPONSE_TIMEOUT_SECS);
    assert!(
        REFRESH_RENEWAL_TIMEOUT_SECS
            > REFRESH_STORAGE_RESPONSE_TIMEOUT_SECS
                + REFRESH_STORAGE_AUTHORITATIVE_CANCEL_GRACE_SECS
                + REFRESH_STORAGE_AUTHORITATIVE_REREAD_TIMEOUT_SECS
                + 1
    );
    assert!(REFRESH_STORAGE_RESPONSE_TIMEOUT_SECS > REFRESH_STORAGE_OPERATION_TIMEOUT_SECS);
    assert!(
        REFRESH_STORAGE_RECONCILABLE_COMMIT_TIMEOUT_SECS
            > REFRESH_STORAGE_RESPONSE_TIMEOUT_SECS + REFRESH_STORAGE_RECONCILE_TIMEOUT_SECS
    );
    assert!(REFRESH_CLAIM_RESPONSE_TIMEOUT_SECS > REFRESH_CLAIM_OPERATION_TIMEOUT_SECS);
    assert!(
        MCP_IDENTITY_AUTH_READ_RESPONSE_TIMEOUT_SECS
            > MCP_IDENTITY_AUTH_READ_OPERATION_TIMEOUT_SECS
    );
    assert!(REFRESH_AUTH_READ_RESPONSE_TIMEOUT_SECS > REFRESH_AUTH_READ_OPERATION_TIMEOUT_SECS);
    assert!(REFRESH_WAIT_TIMEOUT_SECS > REFRESH_AUTH_READ_RESPONSE_TIMEOUT_SECS);
};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct McpOauthAuthorizeView {
    pub(crate) object: &'static str,
    pub(crate) server_name: String,
    pub(crate) authorize_url: String,
    pub(crate) state: String,
    pub(crate) expires_at_unix: i64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct McpIdentityStatusView {
    pub(crate) object: &'static str,
    pub(crate) server_name: String,
    pub(crate) auth_type: String,
    pub(crate) connected: bool,
    pub(crate) credential_source: String,
    pub(crate) subject: Option<String>,
    pub(crate) expires_at_unix: Option<i64>,
    pub(crate) revoked_at_unix: Option<i64>,
    pub(crate) last_refresh_outcome: Option<String>,
    pub(crate) last_revocation_outcome: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct McpIdentityResolution {
    pub(crate) headers: McpDispatchHeaders,
    pub(crate) credential_source: &'static str,
    pub(crate) subject: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct McpIdentityError {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl McpIdentityError {
    fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message: message.into(),
        }
    }

    fn unauthorized(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code,
            message: message.into(),
        }
    }

    fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code,
            message: message.into(),
        }
    }

    fn unavailable(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "mcp_identity_not_found",
            message: message.into(),
        }
    }
}

struct IdentityCipher(XChaCha20Poly1305);

impl IdentityCipher {
    fn from_env() -> Result<Self, McpIdentityError> {
        let raw = std::env::var(MCP_IDENTITY_KEY_ENV).map_err(|_| {
            McpIdentityError::unavailable(
                "mcp_identity_key_unavailable",
                format!("{MCP_IDENTITY_KEY_ENV} is required for per-user MCP identity"),
            )
        })?;
        let bytes = decode_hex_32(raw.trim()).ok_or_else(|| {
            McpIdentityError::unavailable(
                "mcp_identity_key_invalid",
                format!("{MCP_IDENTITY_KEY_ENV} must contain exactly 64 hexadecimal characters"),
            )
        })?;
        Ok(Self(XChaCha20Poly1305::new(Key::from_slice(&bytes))))
    }

    fn encrypt(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), McpIdentityError> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .0
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| {
                McpIdentityError::unavailable(
                    "mcp_identity_encrypt_failed",
                    "MCP identity encryption failed",
                )
            })?;
        Ok((nonce.to_vec(), ciphertext))
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, McpIdentityError> {
        if nonce.len() != 24 {
            return Err(McpIdentityError::unavailable(
                "mcp_identity_decrypt_failed",
                "MCP identity ciphertext nonce is invalid",
            ));
        }
        self.0
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| {
                McpIdentityError::unavailable(
                    "mcp_identity_decrypt_failed",
                    "MCP identity credential could not be decrypted",
                )
            })
    }

    fn signing_key(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ferrogate:mcp:signed-identity:v1");
        // The AEAD implementation deliberately does not expose its key. Use
        // the same deployment secret as input, but domain-separate it.
        let raw = std::env::var(MCP_IDENTITY_KEY_ENV).unwrap_or_default();
        hasher.update(raw.as_bytes());
        hasher.finalize().into()
    }
}

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    revocation_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OauthTokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default = "default_token_type")]
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

fn default_token_type() -> String {
    "Bearer".into()
}

#[derive(Debug, Serialize)]
struct SignedMcpIdentityClaims {
    iss: &'static str,
    sub: String,
    aud: String,
    tenant_id: String,
    workspace_id: String,
    server_name: String,
    iat: i64,
    exp: i64,
    jti: String,
}

impl AppState {
    pub(crate) async fn start_mcp_oauth(
        &self,
        auth: &AuthContext,
        server_name: &str,
    ) -> Result<McpOauthAuthorizeView, McpIdentityError> {
        let (actor, _) = self
            .load_mcp_identity_access(auth, server_name, "mcp.identity.connect")
            .await?;
        let server = self.mcp_identity_server(server_name)?;
        if server.auth_type != McpAuthType::PerUserOauth {
            return Err(McpIdentityError::bad_request(
                "mcp_identity_mode_mismatch",
                format!("MCP server {server_name} does not use per_user_oauth"),
            ));
        }
        let oauth = server
            .oauth
            .as_ref()
            .expect("validated per_user_oauth config");
        let discovery = fetch_discovery(oauth).await?;
        let cipher = IdentityCipher::from_env()?;
        let verifier = random_urlsafe(48);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let state = random_urlsafe(32);
        let state_id = sha256_hex(state.as_bytes());
        let oidc_nonce = random_urlsafe(24);
        let aad = flow_aad(&state_id, &actor, server_name);
        let (pkce_nonce, pkce_ciphertext) = cipher.encrypt(verifier.as_bytes(), aad.as_bytes())?;
        let now = now_i64();
        let stored_oidc_nonce = oidc_nonce.clone();
        let stored_server_name = server_name.to_string();
        self.repositories
            .begin_mcp_oauth_flow(StoredMcpOauthFlow {
                id: state_id,
                tenant_id: actor.tenant_id.clone(),
                workspace_id: actor.workspace_id.clone(),
                user_id: actor.user_id.clone(),
                server_name: stored_server_name,
                pkce_nonce,
                pkce_ciphertext,
                oidc_nonce: stored_oidc_nonce,
                authorization_generation: 0,
                created_at_unix: now,
                expires_at_unix: now + OAUTH_FLOW_TTL_SECS,
                consumed_at_unix: None,
            })
            .await
            .map_err(storage_identity_error)?;
        let mut authorize_url =
            reqwest::Url::parse(&discovery.authorization_endpoint).map_err(|_| {
                McpIdentityError::unavailable(
                    "mcp_identity_provider_invalid",
                    "OIDC authorization endpoint is invalid",
                )
            })?;
        authorize_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &oauth.client_id)
            .append_pair(
                "redirect_uri",
                oauth.redirect_uri.as_deref().unwrap_or_default(),
            )
            .append_pair("scope", &oauth.scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("nonce", &oidc_nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(McpOauthAuthorizeView {
            object: "mcp_oauth_authorization",
            server_name: server_name.to_string(),
            authorize_url: authorize_url.to_string(),
            state,
            expires_at_unix: now + OAUTH_FLOW_TTL_SECS,
        })
    }

    pub(crate) async fn complete_mcp_oauth(
        &self,
        state: &str,
        code: &str,
        request_id: &str,
        trace_id: Option<String>,
    ) -> Result<McpIdentityStatusView, McpIdentityError> {
        if state.trim().is_empty() || code.trim().is_empty() {
            return Err(McpIdentityError::bad_request(
                "mcp_oauth_callback_invalid",
                "OAuth callback requires code and state",
            ));
        }
        let now = now_i64();
        let state_id = sha256_hex(state.as_bytes());
        let flow = self
            .repositories
            .consume_mcp_oauth_flow(&state_id, now)
            .await
            .map_err(storage_identity_error)?
            .ok_or_else(|| {
                McpIdentityError::unauthorized(
                    "mcp_oauth_state_invalid",
                    "OAuth state is unknown, expired, or already used",
                )
            })?;
        let actor = McpIdentityActor {
            tenant_id: flow.tenant_id.clone(),
            workspace_id: flow.workspace_id.clone(),
            user_id: flow.user_id.clone(),
        };
        self.authorize_mcp_identity_actor(&actor, &flow.server_name, "mcp.identity.connect")
            .await?;
        let server = self.mcp_identity_server(&flow.server_name)?;
        if server.auth_type != McpAuthType::PerUserOauth {
            return Err(McpIdentityError::bad_request(
                "mcp_identity_mode_mismatch",
                "MCP server identity mode changed during OAuth flow",
            ));
        }
        let oauth = server
            .oauth
            .as_ref()
            .expect("validated per_user_oauth config");
        let discovery = fetch_discovery(oauth).await?;
        let cipher = IdentityCipher::from_env()?;
        let aad = flow_aad(&state_id, &actor, &flow.server_name);
        let verifier = cipher.decrypt(&flow.pkce_nonce, &flow.pkce_ciphertext, aad.as_bytes())?;
        let verifier = String::from_utf8(verifier).map_err(|_| {
            McpIdentityError::unavailable("mcp_identity_decrypt_failed", "PKCE verifier is invalid")
        })?;
        let client_secret = resolve_client_secret(oauth).await?;
        let form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            (
                "redirect_uri",
                oauth.redirect_uri.clone().unwrap_or_default(),
            ),
            ("client_id", oauth.client_id.clone()),
            ("client_secret", client_secret),
            ("code_verifier", verifier),
        ];
        let token = post_token_form(&discovery.token_endpoint, &form).await?;
        if !token.token_type.eq_ignore_ascii_case("bearer") || token.access_token.trim().is_empty()
        {
            return Err(McpIdentityError::unavailable(
                "mcp_identity_provider_invalid",
                "OIDC token endpoint did not return a usable bearer token",
            ));
        }
        let id_token = token.id_token.as_deref().ok_or_else(|| {
            McpIdentityError::unauthorized(
                "mcp_oidc_id_token_missing",
                "OIDC token response did not include id_token",
            )
        })?;
        let subject =
            validate_oidc_token(oauth, &discovery, id_token, Some(&flow.oidc_nonce)).await?;
        if subject != actor.user_id {
            return Err(McpIdentityError::forbidden(
                "mcp_identity_subject_mismatch",
                "OIDC subject does not match the FerroGate user that started this flow",
            ));
        }
        let credential_id = credential_id(&actor, &flow.server_name);
        let credential_aad = credential_aad(&credential_id, &actor, &flow.server_name);
        let (access_token_nonce, access_token_ciphertext) =
            cipher.encrypt(token.access_token.as_bytes(), credential_aad.as_bytes())?;
        let (refresh_token_nonce, refresh_token_ciphertext) = match token.refresh_token.as_deref() {
            Some(refresh) => {
                let (nonce, ciphertext) =
                    cipher.encrypt(refresh.as_bytes(), credential_aad.as_bytes())?;
                (Some(nonce), Some(ciphertext))
            }
            None => (None, None),
        };
        let expires_at_unix =
            now.saturating_add(i64::try_from(token.expires_in.unwrap_or(300)).unwrap_or(i64::MAX));
        let credential = StoredMcpOauthCredential {
            id: credential_id,
            tenant_id: actor.tenant_id.clone(),
            workspace_id: actor.workspace_id.clone(),
            user_id: actor.user_id.clone(),
            server_name: flow.server_name.clone(),
            issuer: oauth.issuer.clone(),
            subject: subject.clone(),
            token_type: "Bearer".into(),
            scopes: token
                .scope
                .as_deref()
                .map(str::split_whitespace)
                .into_iter()
                .flatten()
                .map(str::to_string)
                .collect(),
            access_token_nonce,
            access_token_ciphertext,
            refresh_token_nonce,
            refresh_token_ciphertext,
            expires_at_unix,
            key_version: 1,
            version: 1,
            authorization_generation: flow.authorization_generation,
            refresh_lease_id: None,
            refresh_lease_expires_at_unix: None,
            created_at_unix: now,
            updated_at_unix: now,
            revoked_at_unix: None,
            last_refresh_outcome: Some("connected".into()),
            last_revocation_outcome: None,
        };
        let commit = self
            .repositories
            .commit_mcp_oauth_callback(&flow, credential, "mcp.identity.connect")
            .await
            .map_err(storage_identity_error)?;
        if commit != McpOauthCallbackCommitOutcome::Committed {
            return Err(McpIdentityError::forbidden(
                "mcp_oauth_authorization_changed",
                "MCP OAuth authorization changed before callback completion",
            ));
        }
        self.record_admin_audit_event(AdminAuditEventDraft {
            action_identity: Default::default(),
            request_id: request_id.to_string(),
            trace_id,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            actor_api_key_id: None,
            tenant: ferrogate_core::TenantContext {
                organization_id: Some(actor.tenant_id.clone()),
                workspace_id: Some(actor.workspace_id.clone()),
                user_id: Some(actor.user_id.clone()),
                ..ferrogate_core::TenantContext::default()
            },
            action: "mcp.identity.connect".into(),
            target: format!("mcp:{}/subject:{}", flow.server_name, actor.user_id),
            outcome: "connected".into(),
            message: format!(
                "server={} workspace={} subject={} source=per_user_oauth decision=allow",
                flow.server_name, actor.workspace_id, subject
            ),
        });
        Ok(McpIdentityStatusView {
            object: "mcp_identity",
            server_name: flow.server_name,
            auth_type: "per_user_oauth".into(),
            connected: true,
            credential_source: "per_user_oauth".into(),
            subject: Some(subject),
            expires_at_unix: Some(expires_at_unix),
            revoked_at_unix: None,
            last_refresh_outcome: Some("connected".into()),
            last_revocation_outcome: None,
        })
    }

    pub(crate) async fn mcp_identity_status(
        &self,
        auth: &AuthContext,
        server_name: &str,
    ) -> Result<McpIdentityStatusView, McpIdentityError> {
        let server = self.mcp_identity_server(server_name)?;
        let (_, credential) = self
            .load_mcp_identity_access(auth, server_name, "mcp.identity.read")
            .await?;
        Ok(McpIdentityStatusView {
            object: "mcp_identity",
            server_name: server_name.to_string(),
            auth_type: server.auth_type.as_str().into(),
            connected: credential
                .as_ref()
                .is_some_and(|row| row.revoked_at_unix.is_none()),
            credential_source: server.auth_type.as_str().into(),
            subject: credential.as_ref().map(|row| row.subject.clone()),
            expires_at_unix: credential.as_ref().map(|row| row.expires_at_unix),
            revoked_at_unix: credential.as_ref().and_then(|row| row.revoked_at_unix),
            last_refresh_outcome: credential
                .as_ref()
                .and_then(|row| row.last_refresh_outcome.clone()),
            last_revocation_outcome: credential.and_then(|row| row.last_revocation_outcome),
        })
    }

    pub(crate) async fn revoke_mcp_identity(
        &self,
        auth: &AuthContext,
        server_name: &str,
    ) -> Result<McpIdentityStatusView, McpIdentityError> {
        let server = self.mcp_identity_server(server_name)?;
        let (actor, credential) = self
            .load_mcp_identity_access(auth, server_name, "mcp.identity.revoke")
            .await?;
        let credential = credential
            .filter(|credential| credential.revoked_at_unix.is_none())
            .ok_or_else(|| {
                McpIdentityError::not_found("no MCP identity is connected for this subject")
            })?;
        let now = now_i64();
        let request = actor.access_request(server_name, "mcp.identity.revoke");
        let revoked = self
            .repositories
            .revoke_mcp_oauth_identity(&request, now, "local_revoked")
            .await
            .map_err(storage_identity_error)?;
        if revoked.is_none() {
            return Err(McpIdentityError::not_found(
                "MCP identity is already revoked",
            ));
        }
        let credential = revoked
            .map(|outcome| outcome.credential)
            .unwrap_or(credential);
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_mcp_identity_revocation();
        }
        let mut outcome = "local_revoked".to_string();
        if let Some(oauth) = server.oauth.as_ref() {
            if let Ok(discovery) = fetch_discovery(oauth).await {
                if let Some(endpoint) = discovery.revocation_endpoint {
                    if let Ok(cipher) = IdentityCipher::from_env() {
                        let aad = credential_aad(&credential.id, &actor, server_name);
                        let token = credential
                            .refresh_token_nonce
                            .as_deref()
                            .zip(credential.refresh_token_ciphertext.as_deref())
                            .and_then(|(nonce, ciphertext)| {
                                cipher.decrypt(nonce, ciphertext, aad.as_bytes()).ok()
                            })
                            .or_else(|| {
                                cipher
                                    .decrypt(
                                        &credential.access_token_nonce,
                                        &credential.access_token_ciphertext,
                                        aad.as_bytes(),
                                    )
                                    .ok()
                            });
                        if let Some(token) = token.and_then(|value| String::from_utf8(value).ok()) {
                            let secret = resolve_client_secret(oauth).await.unwrap_or_default();
                            let form = vec![
                                ("token", token),
                                ("client_id", oauth.client_id.clone()),
                                ("client_secret", secret),
                            ];
                            outcome = if post_empty_form(&endpoint, &form).await.is_ok() {
                                "upstream_revoked"
                            } else {
                                "upstream_revocation_failed"
                            }
                            .into();
                        }
                    }
                }
            }
        }
        self.repositories
            .update_mcp_oauth_revocation_outcome(
                &actor.tenant_id,
                &actor.workspace_id,
                &actor.user_id,
                server_name,
                &outcome,
            )
            .await
            .map_err(storage_identity_error)?;
        Ok(McpIdentityStatusView {
            object: "mcp_identity",
            server_name: server_name.into(),
            auth_type: server.auth_type.as_str().into(),
            connected: false,
            credential_source: server.auth_type.as_str().into(),
            subject: Some(credential.subject),
            expires_at_unix: Some(credential.expires_at_unix),
            revoked_at_unix: Some(now),
            last_refresh_outcome: credential.last_refresh_outcome,
            last_revocation_outcome: Some(outcome),
        })
    }

    pub(crate) async fn resolve_mcp_identity(
        &self,
        auth: &AuthContext,
        server_name: &str,
        original_bearer: Option<&str>,
    ) -> Result<McpIdentityResolution, McpIdentityError> {
        let server = self.mcp_identity_server(server_name)?;
        match server.auth_type {
            McpAuthType::None | McpAuthType::SharedHeaders => Ok(McpIdentityResolution {
                headers: McpDispatchHeaders::empty(),
                credential_source: server.auth_type.as_str(),
                subject: None,
            }),
            McpAuthType::PerUserOauth => {
                let (actor, credential) = self
                    .load_mcp_identity_access(auth, server_name, "mcp.identity.use")
                    .await?;
                let mut credential = credential
                    .filter(|row| row.revoked_at_unix.is_none())
                    .ok_or_else(|| {
                        McpIdentityError::unauthorized(
                            "mcp_identity_not_connected",
                            "per-user MCP identity is not connected",
                        )
                    })?;
                if credential.expires_at_unix <= now_i64().saturating_add(TOKEN_REFRESH_SKEW_SECS) {
                    credential = self
                        .refresh_mcp_credential(&actor, &server, credential)
                        .await?;
                }
                let cipher = IdentityCipher::from_env()?;
                let aad = credential_aad(&credential.id, &actor, server_name);
                let token = cipher.decrypt(
                    &credential.access_token_nonce,
                    &credential.access_token_ciphertext,
                    aad.as_bytes(),
                )?;
                let token = String::from_utf8(token).map_err(|_| {
                    McpIdentityError::unavailable(
                        "mcp_identity_decrypt_failed",
                        "MCP access token is invalid",
                    )
                })?;
                Ok(McpIdentityResolution {
                    headers: dispatch_bearer(token)?,
                    credential_source: "per_user_oauth",
                    subject: Some(credential.subject),
                })
            }
            McpAuthType::OriginalBearer => {
                let (actor, _) = self
                    .load_mcp_identity_access(auth, server_name, "mcp.identity.use")
                    .await?;
                let token = original_bearer
                    .filter(|value| !value.trim().is_empty())
                    .ok_or_else(|| {
                        McpIdentityError::unauthorized(
                            "mcp_original_bearer_missing",
                            "validated original bearer token is required",
                        )
                    })?;
                let oauth = server
                    .oauth
                    .as_ref()
                    .expect("validated original_bearer config");
                let discovery = fetch_discovery(oauth).await?;
                let subject = validate_oidc_token(oauth, &discovery, token, None).await?;
                if subject != actor.user_id {
                    return Err(McpIdentityError::forbidden(
                        "mcp_identity_subject_mismatch",
                        "original bearer subject does not match authenticated user",
                    ));
                }
                Ok(McpIdentityResolution {
                    headers: dispatch_bearer(token.to_string())?,
                    credential_source: "original_bearer",
                    subject: Some(subject),
                })
            }
            McpAuthType::FerrogateSignedJwt => {
                let (actor, _) = self
                    .load_mcp_identity_access(auth, server_name, "mcp.identity.use")
                    .await?;
                let cipher = IdentityCipher::from_env()?;
                let now = now_i64();
                let claims = SignedMcpIdentityClaims {
                    iss: "ferrogate",
                    sub: actor.user_id.clone(),
                    aud: server.signed_jwt_audience.clone().unwrap_or_default(),
                    tenant_id: actor.tenant_id,
                    workspace_id: actor.workspace_id,
                    server_name: server_name.into(),
                    iat: now,
                    exp: now + SIGNED_IDENTITY_TTL_SECS,
                    jti: random_urlsafe(18),
                };
                let token = encode(
                    &Header::new(Algorithm::HS256),
                    &claims,
                    &EncodingKey::from_secret(&cipher.signing_key()),
                )
                .map_err(|_| {
                    McpIdentityError::unavailable(
                        "mcp_signed_identity_failed",
                        "failed to sign MCP identity",
                    )
                })?;
                Ok(McpIdentityResolution {
                    headers: dispatch_bearer(token)?,
                    credential_source: "ferrogate_signed_jwt",
                    subject: Some(claims.sub),
                })
            }
            McpAuthType::Oauth | McpAuthType::PerUserHeaders => Err(McpIdentityError::unavailable(
                "mcp_identity_mode_unsupported",
                "MCP identity mode passed validation without a runtime implementation",
            )),
        }
    }

    async fn refresh_mcp_credential(
        &self,
        actor: &McpIdentityActor,
        server: &ferrogate_mcp::McpServerConfig,
        credential: StoredMcpOauthCredential,
    ) -> Result<StoredMcpOauthCredential, McpIdentityError> {
        tracing::debug!(
            credential_id = %credential.id,
            phase = "refresh_orchestration_enter",
            "entered MCP credential refresh orchestration"
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(REFRESH_WAIT_TIMEOUT_SECS);
        let mut candidate = credential;
        let mut busy_logged = false;
        let mut busy_attempt = 0_u32;
        loop {
            if candidate.revoked_at_unix.is_some() {
                return Err(McpIdentityError::unauthorized(
                    "mcp_identity_not_connected",
                    "per-user MCP identity is revoked",
                ));
            }
            if candidate.expires_at_unix > now_i64().saturating_add(TOKEN_REFRESH_SKEW_SECS) {
                return Ok(candidate);
            }
            let now = now_i64();
            let lease_id = random_urlsafe(18);
            let tenant_id = candidate.tenant_id.clone();
            let credential_id = candidate.id.clone();
            let version = candidate.version;
            let generation = candidate.authorization_generation;
            let repositories = Arc::clone(&self.repositories);
            let Some((claim_operation_budget, claim_response_budget)) =
                refresh_claim_storage_budgets(deadline)
            else {
                return Err(McpIdentityError::unavailable(
                    "mcp_identity_refresh_timeout",
                    "timed out while claiming the MCP refresh lease",
                ));
            };
            let request = McpRefreshClaimRequest {
                tenant_id,
                credential_id,
                expected_version: version,
                authorization_generation: generation,
                lease_id: lease_id.clone(),
                now_unix: now,
                lease_ttl_secs: REFRESH_LEASE_SECS,
            };
            let primary_request = request.clone();
            let primary = self
                .run_mcp_refresh_async_storage_with_budgets(
                    "claim MCP refresh lease",
                    claim_operation_budget,
                    claim_response_budget,
                    move |operation| async move {
                        repositories
                            .claim_mcp_oauth_refresh_with_operation(&primary_request, &operation)
                            .await
                    },
                )
                .await;
            let (claim, reconciled) = match primary {
                Ok(outcome) => (outcome, false),
                Err(error) if error.code == "mcp_identity_storage_reconcile_required" => {
                    (self.reconcile_mcp_refresh_claim(request).await?, true)
                }
                Err(error) => return Err(error),
            };
            let claim = if reconciled {
                match resolve_reconciled_mcp_refresh_claim(claim) {
                    Ok(claim) => {
                        if let Ok(mut metrics) = self.metrics.lock() {
                            metrics.record_mcp_refresh_late_reconciliation();
                        }
                        claim
                    }
                    Err(error) => {
                        self.record_mcp_refresh_storage_outcome_unknown();
                        return Err(error);
                    }
                }
            } else {
                claim
            };
            match claim {
                McpRefreshClaimOutcome::Acquired(claimed) => {
                    let claim_outcome = if candidate.refresh_lease_id.is_some() {
                        "takeover"
                    } else {
                        "acquired"
                    };
                    let tenant_id = claimed.tenant_id.clone();
                    let credential_id = claimed.id.clone();
                    let expected_version = claimed.version;
                    let authorization_generation = claimed.authorization_generation;
                    let lease_expiry_state = Arc::new(std::sync::atomic::AtomicI64::new(
                        claimed.refresh_lease_expires_at_unix.unwrap_or(now),
                    ));
                    tracing::info!(
                        credential_id,
                        outcome = claim_outcome,
                        "claimed MCP OAuth refresh lease"
                    );
                    let refresh = self.prepare_refreshed_mcp_credential(actor, server, &claimed);
                    let provider_outcome = run_with_refresh_heartbeat_tagged(
                        refresh,
                        Duration::from_secs(REFRESH_HEARTBEAT_SECS),
                        Duration::from_secs(REFRESH_RENEWAL_TIMEOUT_SECS),
                        Duration::from_secs(REFRESH_OWNER_TIMEOUT_SECS),
                        || {
                            let lease_expiry_state = Arc::clone(&lease_expiry_state);
                            self.renew_mcp_refresh_lease(
                                &tenant_id,
                                &credential_id,
                                expected_version,
                                authorization_generation,
                                &lease_id,
                                lease_expiry_state,
                            )
                        },
                    )
                    .await;
                    return match provider_outcome {
                        RefreshHeartbeatOutcome::Work(Ok(next)) => {
                            self.complete_claimed_mcp_credential(
                                actor, server, claimed, lease_id, next,
                            )
                            .await
                        }
                        RefreshHeartbeatOutcome::Work(Err(error)) => {
                            self.release_failed_mcp_refresh(&claimed, &lease_id).await;
                            Err(error)
                        }
                        RefreshHeartbeatOutcome::HeartbeatFailed(error)
                        | RefreshHeartbeatOutcome::OwnerTimedOut(error) => Err(error),
                    };
                }
                McpRefreshClaimOutcome::Busy {
                    lease_expires_at_unix,
                } => {
                    if tokio::time::Instant::now() >= deadline {
                        tracing::warn!(
                            credential_id = candidate.id,
                            lease_expires_at_unix,
                            outcome = "waiter_timeout",
                            "timed out waiting for MCP OAuth refresh lease"
                        );
                        return Err(McpIdentityError::unavailable(
                            "mcp_identity_refresh_timeout",
                            "timed out waiting for the active MCP refresh lease",
                        ));
                    }
                    if !busy_logged {
                        tracing::debug!(
                            credential_id = candidate.id,
                            lease_expires_at_unix,
                            outcome = "busy",
                            "MCP OAuth refresh lease is owned by another request"
                        );
                        busy_logged = true;
                    }
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    let delay = refresh_wait_backoff(
                        lease_expires_at_unix,
                        now_i64(),
                        busy_attempt,
                        remaining,
                        &lease_id,
                    );
                    busy_attempt = busy_attempt.saturating_add(1);
                    tokio::time::sleep(delay).await;
                    candidate = self
                        .authorize_mcp_identity_actor_for_refresh(
                            actor,
                            &server.name,
                            "mcp.identity.use",
                            deadline,
                        )
                        .await?
                        .filter(|row| row.revoked_at_unix.is_none())
                        .ok_or_else(|| {
                            McpIdentityError::unauthorized(
                                "mcp_identity_not_connected",
                                "per-user MCP identity changed while waiting for refresh",
                            )
                        })?;
                }
                McpRefreshClaimOutcome::Changed(Some(current)) => {
                    tracing::debug!(
                        credential_id = candidate.id,
                        outcome = "credential_changed",
                        "MCP OAuth credential changed while claiming refresh lease"
                    );
                    candidate = current;
                    busy_attempt = 0;
                }
                McpRefreshClaimOutcome::Changed(None) => {
                    tracing::warn!(
                        credential_id = candidate.id,
                        outcome = "missing",
                        "MCP OAuth credential disappeared while claiming refresh lease"
                    );
                    return Err(McpIdentityError::unauthorized(
                        "mcp_identity_not_connected",
                        "per-user MCP identity changed before refresh",
                    ));
                }
            }
        }
    }

    async fn prepare_refreshed_mcp_credential(
        &self,
        actor: &McpIdentityActor,
        server: &ferrogate_mcp::McpServerConfig,
        credential: &StoredMcpOauthCredential,
    ) -> Result<StoredMcpOauthCredential, McpIdentityError> {
        let oauth = server
            .oauth
            .as_ref()
            .expect("validated per_user_oauth config");
        let discovery = fetch_discovery(oauth).await?;
        let cipher = IdentityCipher::from_env()?;
        let aad = credential_aad(&credential.id, actor, &server.name);
        let refresh = credential
            .refresh_token_nonce
            .as_deref()
            .zip(credential.refresh_token_ciphertext.as_deref())
            .ok_or_else(|| {
                McpIdentityError::unauthorized(
                    "mcp_refresh_token_missing",
                    "MCP identity expired and has no refresh token",
                )
            })?;
        let refresh_plaintext = cipher.decrypt(refresh.0, refresh.1, aad.as_bytes())?;
        let refresh_plaintext = String::from_utf8(refresh_plaintext).map_err(|_| {
            McpIdentityError::unavailable(
                "mcp_identity_decrypt_failed",
                "MCP refresh token is invalid",
            )
        })?;
        let client_secret = resolve_client_secret(oauth).await?;
        let form = vec![
            ("grant_type", "refresh_token".into()),
            ("refresh_token", refresh_plaintext.clone()),
            ("client_id", oauth.client_id.clone()),
            ("client_secret", client_secret),
        ];
        let token = post_token_form(&discovery.token_endpoint, &form).await?;
        if !token.token_type.eq_ignore_ascii_case("bearer") || token.access_token.trim().is_empty()
        {
            return Err(McpIdentityError::unavailable(
                "mcp_identity_provider_invalid",
                "refresh response did not contain a usable bearer token",
            ));
        }
        let now = now_i64();
        let (access_token_nonce, access_token_ciphertext) =
            cipher.encrypt(token.access_token.as_bytes(), aad.as_bytes())?;
        let refresh_value = token.refresh_token.as_deref().unwrap_or(&refresh_plaintext);
        let (refresh_token_nonce, refresh_token_ciphertext) =
            cipher.encrypt(refresh_value.as_bytes(), aad.as_bytes())?;
        let mut next = credential.clone();
        next.access_token_nonce = access_token_nonce;
        next.access_token_ciphertext = access_token_ciphertext;
        next.refresh_token_nonce = Some(refresh_token_nonce);
        next.refresh_token_ciphertext = Some(refresh_token_ciphertext);
        next.expires_at_unix =
            now.saturating_add(i64::try_from(token.expires_in.unwrap_or(300)).unwrap_or(i64::MAX));
        next.updated_at_unix = now;
        next.last_refresh_outcome = Some("refreshed".into());
        Ok(next)
    }

    async fn release_failed_mcp_refresh(
        &self,
        credential: &StoredMcpOauthCredential,
        lease_id: &str,
    ) {
        let repositories = Arc::clone(&self.repositories);
        let tenant_id = credential.tenant_id.clone();
        let credential_id = credential.id.clone();
        let release_lease_id = lease_id.to_string();
        let _ = self
            .run_mcp_refresh_async_storage(
                "release failed MCP refresh lease",
                move |operation| async move {
                    repositories
                        .release_mcp_oauth_refresh_with_operation(
                            &tenant_id,
                            &credential_id,
                            &release_lease_id,
                            "refresh_failed",
                            &operation,
                        )
                        .await
                },
            )
            .await;
    }

    async fn complete_claimed_mcp_credential(
        &self,
        actor: &McpIdentityActor,
        server: &ferrogate_mcp::McpServerConfig,
        credential: StoredMcpOauthCredential,
        lease_id: String,
        mut next: StoredMcpOauthCredential,
    ) -> Result<StoredMcpOauthCredential, McpIdentityError> {
        let repositories = Arc::clone(&self.repositories);
        let persisted = next.clone();
        let completion = self
            .run_mcp_refresh_async_completion_storage(
                "complete MCP refresh lease",
                move |operation| async move {
                    repositories
                        .complete_mcp_oauth_refresh_with_operation(persisted, &lease_id, &operation)
                        .await
                },
            )
            .await;
        let completed = match completion {
            Ok(completed) => completed,
            Err(error) if error.code == "mcp_identity_storage_reconcile_required" => {
                let current = self
                    .authorize_mcp_identity_actor(actor, &server.name, "mcp.identity.use")
                    .await?;
                let resolved =
                    resolve_ambiguous_mcp_refresh_completion_reread(current, credential.version);
                match &resolved {
                    Ok(_) => {
                        if let Ok(mut metrics) = self.metrics.lock() {
                            metrics.record_mcp_refresh_late_reconciliation();
                            metrics.record_mcp_identity_refresh();
                        }
                        tracing::warn!(
                            credential_id = credential.id,
                            outcome = "authoritative_reread_resolved",
                            "resolved an ambiguous MCP refresh completion from durable state"
                        );
                    }
                    Err(error) if error.code == "mcp_identity_storage_outcome_unknown" => {
                        self.record_mcp_refresh_storage_outcome_unknown();
                    }
                    Err(_) => {}
                }
                return resolved;
            }
            Err(error) => return Err(error),
        };
        if completed {
            next.version = next.version.saturating_add(1);
            next.refresh_lease_id = None;
            next.refresh_lease_expires_at_unix = None;
            if let Ok(mut metrics) = self.metrics.lock() {
                metrics.record_mcp_identity_refresh();
            }
            tracing::info!(
                credential_id = next.id,
                outcome = "completed",
                "completed MCP OAuth credential refresh"
            );
            return Ok(next);
        }
        tracing::warn!(
            credential_id = credential.id,
            outcome = "completion_conflict",
            "MCP OAuth credential refresh completion lost its fence"
        );
        let current = self
            .authorize_mcp_identity_actor(actor, &server.name, "mcp.identity.use")
            .await?;
        resolve_mcp_refresh_completion_reread(current, credential.version)
    }

    async fn renew_mcp_refresh_lease(
        &self,
        tenant_id: &str,
        credential_id: &str,
        expected_version: u64,
        authorization_generation: u64,
        lease_id: &str,
        lease_expiry_state: Arc<std::sync::atomic::AtomicI64>,
    ) -> Result<(), McpIdentityError> {
        let now = now_i64();
        let expected_lease_expires_at_unix =
            lease_expiry_state.load(std::sync::atomic::Ordering::Acquire);
        let repositories = Arc::clone(&self.repositories);
        let request = McpRefreshRenewRequest {
            tenant_id: tenant_id.to_string(),
            credential_id: credential_id.to_string(),
            expected_version,
            authorization_generation,
            lease_id: lease_id.to_string(),
            expected_lease_expires_at_unix,
            now_unix: now,
            lease_ttl_secs: REFRESH_LEASE_SECS,
        };
        let primary_request = request.clone();
        let primary = self
            .run_mcp_refresh_async_storage("renew MCP refresh lease", move |operation| async move {
                repositories
                    .renew_mcp_oauth_refresh_with_operation(&primary_request, &operation)
                    .await
            })
            .await;
        let (outcome, reconciled) = match primary {
            Ok(outcome) => (outcome, false),
            Err(error) if error.code == "mcp_identity_storage_reconcile_required" => {
                (self.reconcile_mcp_refresh_renewal(request).await?, true)
            }
            Err(error) => return Err(error),
        };
        let outcome = if reconciled {
            match resolve_reconciled_mcp_refresh_renewal(outcome, expected_lease_expires_at_unix) {
                Ok(outcome) => {
                    if let Ok(mut metrics) = self.metrics.lock() {
                        metrics.record_mcp_refresh_late_reconciliation();
                    }
                    outcome
                }
                Err(error) => {
                    self.record_mcp_refresh_storage_outcome_unknown();
                    return Err(error);
                }
            }
        } else {
            outcome
        };
        match outcome {
            McpRefreshRenewOutcome::Renewed {
                lease_expires_at_unix,
            } => {
                lease_expiry_state
                    .store(lease_expires_at_unix, std::sync::atomic::Ordering::Release);
                tracing::debug!(
                    credential_id,
                    lease_expires_at_unix,
                    outcome = "renewed",
                    "renewed MCP OAuth refresh lease"
                );
                Ok(())
            }
            McpRefreshRenewOutcome::Missing => {
                tracing::warn!(
                    credential_id,
                    outcome = "missing",
                    "lost MCP OAuth refresh lease"
                );
                Err(McpIdentityError::unauthorized(
                    "mcp_identity_not_connected",
                    "per-user MCP identity was removed during refresh",
                ))
            }
            McpRefreshRenewOutcome::Revoked => {
                tracing::warn!(
                    credential_id,
                    outcome = "revoked",
                    "lost MCP OAuth refresh lease"
                );
                Err(McpIdentityError::unauthorized(
                    "mcp_identity_not_connected",
                    "per-user MCP identity was revoked during refresh",
                ))
            }
            McpRefreshRenewOutcome::CredentialChanged => refresh_lease_conflict(
                credential_id,
                "credential_changed",
                "MCP identity changed during refresh",
            ),
            McpRefreshRenewOutcome::OwnershipChanged => refresh_lease_conflict(
                credential_id,
                "ownership_changed",
                "MCP refresh ownership changed during refresh",
            ),
            McpRefreshRenewOutcome::Expired {
                lease_expires_at_unix,
            } => {
                tracing::warn!(
                    credential_id,
                    ?lease_expires_at_unix,
                    outcome = "expired",
                    "lost MCP OAuth refresh lease"
                );
                Err(McpIdentityError::unavailable(
                    "mcp_identity_refresh_conflict",
                    "MCP refresh lease expired before renewal",
                ))
            }
            McpRefreshRenewOutcome::NotExtended {
                lease_expires_at_unix,
            } => {
                tracing::warn!(
                    credential_id,
                    lease_expires_at_unix,
                    outcome = "not_extended",
                    "MCP OAuth refresh lease was not extended"
                );
                Err(McpIdentityError::unavailable(
                    "mcp_identity_refresh_conflict",
                    "MCP refresh lease renewal did not extend ownership",
                ))
            }
        }
    }

    async fn reconcile_mcp_refresh_renewal(
        &self,
        request: McpRefreshRenewRequest,
    ) -> Result<McpRefreshRenewOutcome, McpIdentityError> {
        let repositories = Arc::clone(&self.repositories);
        await_mcp_authoritative_reread(
            Arc::clone(&self.metrics),
            "renew MCP refresh lease",
            repositories.reconcile_mcp_oauth_refresh_renewal(&request),
            Duration::from_secs(REFRESH_STORAGE_AUTHORITATIVE_REREAD_TIMEOUT_SECS),
        )
        .await
    }

    async fn reconcile_mcp_refresh_claim(
        &self,
        request: McpRefreshClaimRequest,
    ) -> Result<McpRefreshClaimOutcome, McpIdentityError> {
        let repositories = Arc::clone(&self.repositories);
        await_mcp_authoritative_reread(
            Arc::clone(&self.metrics),
            "claim MCP refresh lease",
            repositories.reconcile_mcp_oauth_refresh_claim(&request),
            Duration::from_secs(REFRESH_STORAGE_AUTHORITATIVE_REREAD_TIMEOUT_SECS),
        )
        .await
    }

    async fn load_mcp_identity_access(
        &self,
        auth: &AuthContext,
        server_name: &str,
        action: &str,
    ) -> Result<(McpIdentityActor, Option<StoredMcpOauthCredential>), McpIdentityError> {
        let actor = McpIdentityActor::from_auth(auth)?;
        let credential = self
            .authorize_mcp_identity_actor(&actor, server_name, action)
            .await?;
        Ok((actor, credential))
    }

    async fn authorize_mcp_identity_actor_for_refresh(
        &self,
        actor: &McpIdentityActor,
        server_name: &str,
        action: &str,
        deadline: tokio::time::Instant,
    ) -> Result<Option<StoredMcpOauthCredential>, McpIdentityError> {
        let (operation_budget, response_budget) = refresh_authorization_read_budgets(deadline)
            .ok_or_else(|| {
                McpIdentityError::unavailable(
                    "mcp_identity_refresh_timeout",
                    "timed out while reloading MCP refresh authorization",
                )
            })?;
        let request = actor.access_request(server_name, action);
        let outcome = self
            .run_mcp_identity_authorization_read(
                "authorize MCP refresh identity actor",
                operation_budget,
                response_budget,
                request,
                true,
            )
            .await?;
        authorize_mcp_identity_outcome(outcome, action)
    }

    async fn authorize_mcp_identity_actor(
        &self,
        actor: &McpIdentityActor,
        server_name: &str,
        action: &str,
    ) -> Result<Option<StoredMcpOauthCredential>, McpIdentityError> {
        let request = actor.access_request(server_name, action);
        let outcome = self
            .run_mcp_identity_authorization_read(
                "authorize MCP identity actor",
                Duration::from_secs(MCP_IDENTITY_AUTH_READ_OPERATION_TIMEOUT_SECS),
                Duration::from_secs(MCP_IDENTITY_AUTH_READ_RESPONSE_TIMEOUT_SECS),
                request,
                false,
            )
            .await?;
        authorize_mcp_identity_outcome(outcome, action)
    }

    async fn run_mcp_identity_authorization_read(
        &self,
        operation_name: &'static str,
        operation_timeout: Duration,
        response_timeout: Duration,
        request: McpIdentityAccessRequest,
        record_refresh_metrics: bool,
    ) -> Result<McpIdentityAccessOutcome, McpIdentityError> {
        let operation = StorageOperation::new(operation_name, operation_timeout);
        let result = tokio::time::timeout(
            response_timeout,
            self.repositories
                .authorize_mcp_identity_with_operation(&request, &operation),
        )
        .await;
        match result {
            Ok(result) => {
                if record_refresh_metrics
                    && matches!(
                        &result,
                        Err(StorageError::OperationDeadlineExceeded { .. }
                            | StorageError::OperationCancelled { .. })
                    )
                {
                    self.record_mcp_refresh_storage_cancellation();
                }
                result.map_err(storage_identity_error)
            }
            Err(_) => {
                let cancel_outcome = operation.cancel();
                if record_refresh_metrics {
                    if let Ok(mut metrics) = self.metrics.lock() {
                        metrics.record_mcp_refresh_response_deadline();
                    }
                    if matches!(
                        cancel_outcome,
                        StorageOperationCancelOutcome::Cancelled
                            | StorageOperationCancelOutcome::AlreadyCancelled
                    ) {
                        self.record_mcp_refresh_storage_cancellation();
                    }
                }
                tracing::warn!(
                    operation = operation_name,
                    ?cancel_outcome,
                    outcome = "authorization_response_deadline",
                    "MCP identity authorization read exceeded its response deadline"
                );
                Err(McpIdentityError::unavailable(
                    "mcp_identity_storage_deadline",
                    format!("MCP identity authorization read {operation_name} timed out"),
                ))
            }
        }
    }

    async fn run_mcp_refresh_async_storage<T, F, Fut>(
        &self,
        operation_name: &'static str,
        action: F,
    ) -> Result<T, McpIdentityError>
    where
        T: Send + 'static,
        F: FnOnce(StorageOperation) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, StorageError>> + Send + 'static,
    {
        self.run_mcp_refresh_async_storage_with_options(
            operation_name,
            Duration::from_secs(REFRESH_STORAGE_OPERATION_TIMEOUT_SECS),
            Duration::from_secs(REFRESH_STORAGE_RESPONSE_TIMEOUT_SECS),
            false,
            action,
        )
        .await
    }

    async fn run_mcp_refresh_async_completion_storage<T, F, Fut>(
        &self,
        operation_name: &'static str,
        action: F,
    ) -> Result<T, McpIdentityError>
    where
        T: Send + 'static,
        F: FnOnce(StorageOperation) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, StorageError>> + Send + 'static,
    {
        self.run_mcp_refresh_async_storage_with_options(
            operation_name,
            Duration::from_secs(REFRESH_STORAGE_OPERATION_TIMEOUT_SECS),
            Duration::from_secs(REFRESH_STORAGE_RESPONSE_TIMEOUT_SECS),
            true,
            action,
        )
        .await
    }

    async fn run_mcp_refresh_async_storage_with_budgets<T, F, Fut>(
        &self,
        operation_name: &'static str,
        operation_timeout: Duration,
        response_timeout: Duration,
        action: F,
    ) -> Result<T, McpIdentityError>
    where
        T: Send + 'static,
        F: FnOnce(StorageOperation) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, StorageError>> + Send + 'static,
    {
        self.run_mcp_refresh_async_storage_with_options(
            operation_name,
            operation_timeout,
            response_timeout,
            false,
            action,
        )
        .await
    }

    async fn run_mcp_refresh_async_storage_with_options<T, F, Fut>(
        &self,
        operation_name: &'static str,
        operation_timeout: Duration,
        response_timeout: Duration,
        reconcile_commit: bool,
        action: F,
    ) -> Result<T, McpIdentityError>
    where
        T: Send + 'static,
        F: FnOnce(StorageOperation) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, StorageError>> + Send + 'static,
    {
        let operation = if reconcile_commit {
            StorageOperation::new_reconcilable_commit(
                operation_name,
                operation_timeout,
                Duration::from_secs(REFRESH_STORAGE_RECONCILABLE_COMMIT_TIMEOUT_SECS),
            )
        } else {
            StorageOperation::new(operation_name, operation_timeout)
        };
        let task_operation = operation.clone();
        let operation_span = tracing::Span::current();
        let task_span = operation_span.clone();
        tracing::debug!(
            operation = operation_name,
            phase = "async_task_scheduled",
            "scheduled async MCP refresh storage operation"
        );
        let mut task = tokio::spawn(
            async move {
                tracing::debug!(
                    operation = operation_name,
                    phase = "async_task_enter",
                    "entered async MCP refresh storage operation"
                );
                let result = action(task_operation).await;
                tracing::debug!(
                    operation = operation_name,
                    phase = "async_task_exit",
                    storage_result = match &result {
                        Ok(_) => "success",
                        Err(error) => mcp_storage_error_kind(error),
                    },
                    "exited async MCP refresh storage operation"
                );
                result
            }
            .instrument(task_span),
        );
        match tokio::time::timeout(response_timeout, &mut task).await {
            Ok(joined) => {
                let result = joined.map_err(|error| {
                    McpIdentityError::unavailable(
                        "mcp_identity_storage_unavailable",
                        format!("failed to {operation_name}: async storage task failed: {error}"),
                    )
                })?;
                if matches!(
                    &result,
                    Err(StorageError::OperationDeadlineExceeded { .. }
                        | StorageError::OperationCancelled { .. })
                ) {
                    self.record_mcp_refresh_storage_cancellation();
                }
                result.map_err(storage_identity_error)
            }
            Err(_) => {
                reconcile_mcp_refresh_storage_after_deadline(
                    Arc::clone(&self.metrics),
                    operation_name,
                    operation,
                    task,
                    Duration::from_secs(REFRESH_STORAGE_RECONCILE_TIMEOUT_SECS),
                    Duration::from_secs(REFRESH_STORAGE_AUTHORITATIVE_CANCEL_GRACE_SECS),
                    operation_span,
                )
                .await
            }
        }
    }

    pub(crate) async fn record_mcp_identity_error_audit(
        &self,
        event: AdminAuditEventDraft,
        original_error: McpIdentityError,
    ) -> McpIdentityError {
        let event = self.prepare_admin_audit_event(event);
        let repositories = Arc::clone(&self.repositories);
        preserve_mcp_identity_error_after_bounded_audit(
            Arc::clone(&self.metrics),
            Arc::clone(&self.mcp_identity_error_audit_permits),
            original_error,
            MCP_IDENTITY_ERROR_AUDIT_TIMEOUT,
            move |operation| async move {
                repositories
                    .append_mcp_identity_audit_event_with_operation(event, &operation)
                    .await
            },
        )
        .await
    }

    fn record_mcp_refresh_storage_cancellation(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_mcp_refresh_storage_cancellation();
        }
    }

    fn record_mcp_refresh_storage_outcome_unknown(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_mcp_refresh_storage_outcome_unknown();
        }
    }

    fn mcp_identity_server(
        &self,
        server_name: &str,
    ) -> Result<ferrogate_mcp::McpServerConfig, McpIdentityError> {
        self.config
            .mcp_servers
            .iter()
            .find(|server| server.name == server_name)
            .cloned()
            .ok_or_else(|| {
                McpIdentityError::not_found(format!("MCP server {server_name} was not found"))
            })
    }

    pub(crate) fn record_mcp_identity_resolution_metric(&self, allowed: bool) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_mcp_identity_resolution(allowed);
        }
    }
}

fn authorize_mcp_identity_outcome(
    outcome: McpIdentityAccessOutcome,
    action: &str,
) -> Result<Option<StoredMcpOauthCredential>, McpIdentityError> {
    match outcome {
        McpIdentityAccessOutcome::Allowed(credential) => Ok(*credential),
        McpIdentityAccessOutcome::PermissionDenied => Err(McpIdentityError::forbidden(
            "mcp_identity_rbac_denied",
            format!("tenant roles do not grant required action {action}"),
        )),
        McpIdentityAccessOutcome::UserInactive => Err(McpIdentityError::forbidden(
            "mcp_identity_user_inactive",
            "MCP identity user is missing or disabled",
        )),
        McpIdentityAccessOutcome::MembershipRevoked => Err(McpIdentityError::forbidden(
            "mcp_identity_membership_revoked",
            "MCP identity user is no longer a tenant member",
        )),
        McpIdentityAccessOutcome::WorkspaceInactive => Err(McpIdentityError::forbidden(
            "mcp_identity_workspace_inactive",
            "MCP identity workspace is missing, inactive, or belongs to another tenant",
        )),
    }
}

async fn preserve_mcp_identity_error_after_bounded_audit<F, Fut>(
    metrics: Arc<Mutex<GatewayMetricsAccumulator>>,
    permits: Arc<tokio::sync::Semaphore>,
    original_error: McpIdentityError,
    timeout: Duration,
    action: F,
) -> McpIdentityError
where
    F: FnOnce(StorageOperation) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), StorageError>> + Send + 'static,
{
    let original_error_code = original_error.code;
    let permit = match permits.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            record_mcp_identity_error_audit_deadline(&metrics);
            tracing::warn!(
                original_error_code,
                audit_outcome = "capacity_rejected",
                original_error_preserved = true,
                "skipped MCP identity error audit because bounded audit capacity was exhausted"
            );
            return original_error;
        }
    };
    let operation = StorageOperation::new("record MCP identity error audit", timeout);
    let task_operation = operation.clone();
    let operation_span = tracing::Span::current();
    let task_span = operation_span.clone();
    let mut task = tokio::spawn(
        async move {
            let _permit = permit;
            action(task_operation).await
        }
        .instrument(task_span),
    );
    let response_wait = timeout.saturating_add(MCP_IDENTITY_ERROR_AUDIT_JOIN_GRACE);

    match tokio::time::timeout(response_wait, &mut task).await {
        Ok(Ok(Ok(()))) => tracing::debug!(
            original_error_code,
            audit_outcome = "persisted",
            original_error_preserved = true,
            "persisted MCP identity error audit within its response budget"
        ),
        Ok(Ok(Err(error))) => {
            if matches!(
                error,
                StorageError::OperationDeadlineExceeded { .. }
                    | StorageError::OperationCancelled { .. }
            ) {
                record_mcp_identity_error_audit_deadline(&metrics);
            }
            tracing::warn!(
                original_error_code,
                audit_outcome = mcp_storage_error_kind(&error),
                audit_error = %sanitize_mcp_storage_error(&error),
                original_error_preserved = true,
                "MCP identity error audit failed without replacing the original response"
            );
        }
        Ok(Err(error)) => tracing::warn!(
            original_error_code,
            audit_outcome = "task_error",
            audit_error = %sanitize_mcp_reconciliation_text(&error.to_string()),
            original_error_preserved = true,
            "MCP identity error audit task failed without replacing the original response"
        ),
        Err(_) => {
            let cancel_outcome = operation.cancel();
            record_mcp_identity_error_audit_deadline(&metrics);
            tracing::warn!(
                original_error_code,
                ?cancel_outcome,
                audit_outcome = "response_deadline",
                original_error_preserved = true,
                "MCP identity error audit exceeded its bounded response budget"
            );
            match cancel_outcome {
                StorageOperationCancelOutcome::Cancelled
                | StorageOperationCancelOutcome::AlreadyCancelled => {
                    task.abort();
                    let _ = task.await;
                }
                StorageOperationCancelOutcome::CommitStarted
                | StorageOperationCancelOutcome::Finished => {
                    tokio::spawn(
                        async move {
                            match task.await {
                                Ok(Ok(())) => tracing::warn!(
                                    audit_outcome = "late_commit_observed",
                                    "observed MCP identity error audit commit after response deadline"
                                ),
                                Ok(Err(error)) => tracing::warn!(
                                    audit_outcome = mcp_storage_error_kind(&error),
                                    audit_error = %sanitize_mcp_storage_error(&error),
                                    "observed MCP identity error audit failure after response deadline"
                                ),
                                Err(error) => tracing::warn!(
                                    audit_outcome = "task_error",
                                    audit_error = %sanitize_mcp_reconciliation_text(&error.to_string()),
                                    "observed MCP identity error audit task failure after response deadline"
                                ),
                            }
                        }
                        .instrument(operation_span),
                    );
                }
            }
        }
    }
    original_error
}

fn record_mcp_identity_error_audit_deadline(metrics: &Arc<Mutex<GatewayMetricsAccumulator>>) {
    if let Ok(mut metrics) = metrics.lock() {
        metrics.record_mcp_identity_error_audit_deadline();
    }
}

fn refresh_wait_backoff(
    lease_expires_at_unix: i64,
    now_unix: i64,
    attempt: u32,
    waiter_remaining: Duration,
    jitter_key: &str,
) -> Duration {
    if waiter_remaining.is_zero() {
        return Duration::ZERO;
    }
    let exponent = attempt.min(4);
    let base = REFRESH_WAIT_MIN_MILLIS
        .saturating_mul(1_u64 << exponent)
        .min(REFRESH_WAIT_MAX_MILLIS);
    let seed = jitter_key.bytes().fold(0_u64, |hash, byte| {
        hash.wrapping_mul(31).wrapping_add(u64::from(byte))
    });
    let jitter =
        seed.wrapping_add(u64::from(attempt).wrapping_mul(17)) % REFRESH_WAIT_JITTER_MILLIS;
    let candidate = Duration::from_millis(base.saturating_add(jitter).min(REFRESH_WAIT_MAX_MILLIS));
    let until_expiry = lease_expires_at_unix.saturating_sub(now_unix);
    let lease_cap = if until_expiry > 0 {
        Duration::from_secs(u64::try_from(until_expiry).unwrap_or(u64::MAX))
    } else {
        Duration::from_millis(REFRESH_WAIT_MIN_MILLIS)
    };
    candidate.min(lease_cap).min(waiter_remaining)
}

fn resolve_reconciled_mcp_refresh_claim(
    outcome: McpRefreshClaimOutcome,
) -> Result<McpRefreshClaimOutcome, McpIdentityError> {
    if matches!(outcome, McpRefreshClaimOutcome::Acquired(_)) {
        return Ok(outcome);
    }
    Err(McpIdentityError::unavailable(
        "mcp_identity_storage_outcome_unknown",
        "MCP refresh claim remained unchanged while its commit outcome was unresolved",
    ))
}

fn resolve_reconciled_mcp_refresh_renewal(
    outcome: McpRefreshRenewOutcome,
    expected_lease_expires_at_unix: i64,
) -> Result<McpRefreshRenewOutcome, McpIdentityError> {
    if matches!(
        outcome,
        McpRefreshRenewOutcome::NotExtended {
            lease_expires_at_unix
        } if lease_expires_at_unix == expected_lease_expires_at_unix
    ) {
        return Err(McpIdentityError::unavailable(
            "mcp_identity_storage_outcome_unknown",
            "MCP refresh renewal remained unchanged while its commit outcome was unresolved",
        ));
    }
    Ok(outcome)
}

fn refresh_claim_storage_budgets(deadline: tokio::time::Instant) -> Option<(Duration, Duration)> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let cancellation_grace = Duration::from_secs(
        REFRESH_CLAIM_RESPONSE_TIMEOUT_SECS - REFRESH_CLAIM_OPERATION_TIMEOUT_SECS,
    );
    let operation_timeout = remaining
        .checked_sub(cancellation_grace)?
        .min(Duration::from_secs(REFRESH_CLAIM_OPERATION_TIMEOUT_SECS));
    (!operation_timeout.is_zero()).then(|| {
        (
            operation_timeout,
            remaining.min(Duration::from_secs(REFRESH_CLAIM_RESPONSE_TIMEOUT_SECS)),
        )
    })
}

fn refresh_authorization_read_budgets(
    deadline: tokio::time::Instant,
) -> Option<(Duration, Duration)> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let cancellation_grace = Duration::from_secs(
        REFRESH_AUTH_READ_RESPONSE_TIMEOUT_SECS - REFRESH_AUTH_READ_OPERATION_TIMEOUT_SECS,
    );
    let operation_timeout = remaining
        .checked_sub(cancellation_grace)?
        .min(Duration::from_secs(
            REFRESH_AUTH_READ_OPERATION_TIMEOUT_SECS,
        ));
    (!operation_timeout.is_zero()).then(|| {
        (
            operation_timeout,
            remaining.min(Duration::from_secs(REFRESH_AUTH_READ_RESPONSE_TIMEOUT_SECS)),
        )
    })
}

async fn await_mcp_authoritative_reread<T, F>(
    metrics: Arc<Mutex<GatewayMetricsAccumulator>>,
    operation_name: &'static str,
    reread: F,
    timeout: Duration,
) -> Result<T, McpIdentityError>
where
    F: std::future::Future<Output = Result<T, StorageError>>,
{
    match tokio::time::timeout(timeout, reread).await {
        Ok(Ok(outcome)) => {
            tracing::warn!(
                operation = operation_name,
                outcome = "authoritative_reread_observed",
                "observed durable state for an ambiguous MCP refresh mutation"
            );
            Ok(outcome)
        }
        Ok(Err(error)) => {
            if let Ok(mut metrics) = metrics.lock() {
                metrics.record_mcp_refresh_storage_outcome_unknown();
            }
            tracing::error!(
                operation = operation_name,
                error_detail = %sanitize_mcp_storage_error(&error),
                outcome = "storage_outcome_unknown",
                "failed to observe durable state for an ambiguous MCP refresh mutation"
            );
            Err(McpIdentityError::unavailable(
                "mcp_identity_storage_outcome_unknown",
                format!("{operation_name} outcome could not be proven from durable storage"),
            ))
        }
        Err(_) => {
            if let Ok(mut metrics) = metrics.lock() {
                metrics.record_mcp_refresh_storage_outcome_unknown();
            }
            tracing::error!(
                operation = operation_name,
                outcome = "storage_outcome_unknown",
                "authoritative MCP refresh reread exceeded its caller deadline"
            );
            Err(McpIdentityError::unavailable(
                "mcp_identity_storage_outcome_unknown",
                format!("{operation_name} outcome reread exceeded its caller deadline"),
            ))
        }
    }
}

async fn reconcile_mcp_refresh_storage_after_deadline<T: Send + 'static>(
    metrics: Arc<Mutex<GatewayMetricsAccumulator>>,
    operation_name: &'static str,
    operation: StorageOperation,
    mut task: tokio::task::JoinHandle<Result<T, StorageError>>,
    reconcile_timeout: Duration,
    authoritative_cancel_grace: Duration,
    operation_span: tracing::Span,
) -> Result<T, McpIdentityError> {
    if let Ok(mut metrics) = metrics.lock() {
        metrics.record_mcp_refresh_response_deadline();
    }
    let cancel_outcome = operation.cancel();
    tracing::warn!(
        operation = operation_name,
        ?cancel_outcome,
        outcome = "response_deadline",
        "MCP refresh storage operation exceeded its response deadline"
    );
    match cancel_outcome {
        StorageOperationCancelOutcome::Cancelled
        | StorageOperationCancelOutcome::AlreadyCancelled => {
            if let Ok(mut metrics) = metrics.lock() {
                metrics.record_mcp_refresh_storage_cancellation();
            }
            task.abort();
            let result = task.await;
            trace_mcp_refresh_reconciliation_result(
                operation_name,
                &result,
                "async_precommit_task_aborted",
            );
            Err(McpIdentityError::unavailable(
                "mcp_identity_storage_deadline",
                format!(
                    "MCP refresh storage operation {operation_name} was cancelled before commit"
                ),
            ))
        }
        StorageOperationCancelOutcome::CommitStarted | StorageOperationCancelOutcome::Finished
            if !operation.reconciles_commit_after_deadline() =>
        {
            match tokio::time::timeout(authoritative_cancel_grace, &mut task).await {
                Ok(joined) => {
                    if matches!(
                        &joined,
                        Ok(Err(StorageError::OperationDeadlineExceeded { .. }
                            | StorageError::OperationCancelled { .. }))
                    ) {
                        if let Ok(mut metrics) = metrics.lock() {
                            metrics.record_mcp_refresh_storage_cancellation();
                        }
                    }
                    trace_mcp_refresh_reconciliation_result(
                        operation_name,
                        &joined,
                        "late_cancel_policy_observed",
                    );
                    joined
                        .map_err(|error| {
                            McpIdentityError::unavailable(
                                "mcp_identity_storage_unavailable",
                                format!(
                                    "failed to observe cancelled {operation_name}: storage task failed: {error}"
                                ),
                            )
                        })?
                        .map_err(storage_identity_error)
                }
                Err(_) => {
                    tracing::warn!(
                        operation = operation_name,
                        outcome = "authoritative_reread_required",
                        "MCP refresh storage result requires a bounded authoritative reread"
                    );
                    observe_mcp_refresh_storage_task(
                        operation_name,
                        task,
                        operation_span,
                        "late_outcome_unknown_observed",
                    );
                    Err(McpIdentityError::unavailable(
                        "mcp_identity_storage_reconcile_required",
                        format!(
                            "MCP refresh storage operation {operation_name} requires authoritative reread"
                        ),
                    ))
                }
            }
        }
        StorageOperationCancelOutcome::CommitStarted | StorageOperationCancelOutcome::Finished => {
            match tokio::time::timeout(reconcile_timeout, &mut task).await {
                Ok(joined) => {
                    if let Ok(mut metrics) = metrics.lock() {
                        metrics.record_mcp_refresh_late_reconciliation();
                    }
                    trace_mcp_refresh_reconciliation_result(
                        operation_name,
                        &joined,
                        "late_completion_reconciled",
                    );
                    joined
                        .map_err(|error| {
                            McpIdentityError::unavailable(
                                "mcp_identity_storage_unavailable",
                                format!(
                                    "failed to reconcile {operation_name}: storage task failed: {error}"
                                ),
                            )
                        })?
                        .map_err(storage_identity_error)
                }
                Err(_) => {
                    tokio::spawn(
                        async move {
                            let result = task.await;
                            if let Ok(mut metrics) = metrics.lock() {
                                metrics.record_mcp_refresh_late_reconciliation();
                            }
                            trace_mcp_refresh_reconciliation_result(
                                operation_name,
                                &result,
                                "late_completion_reconciled",
                            );
                        }
                        .instrument(operation_span),
                    );
                    Err(McpIdentityError::unavailable(
                        "mcp_identity_storage_reconciliation_pending",
                        format!(
                            "MCP refresh storage operation {operation_name} crossed its commit fence; final outcome is being reconciled"
                        ),
                    ))
                }
            }
        }
    }
}

fn observe_mcp_refresh_storage_task<T: Send + 'static>(
    operation_name: &'static str,
    task: tokio::task::JoinHandle<Result<T, StorageError>>,
    operation_span: tracing::Span,
    outcome: &'static str,
) {
    tokio::spawn(
        async move {
            let result = task.await;
            trace_mcp_refresh_reconciliation_result(operation_name, &result, outcome);
        }
        .instrument(operation_span),
    );
}

fn trace_mcp_refresh_reconciliation_result<T>(
    operation_name: &'static str,
    result: &Result<Result<T, StorageError>, tokio::task::JoinError>,
    outcome: &'static str,
) {
    match result {
        Ok(Ok(_)) => tracing::warn!(
            operation = operation_name,
            storage_result = "success",
            outcome,
            "reconciled MCP refresh storage result after response deadline"
        ),
        Ok(Err(error)) => tracing::warn!(
            operation = operation_name,
            storage_result = "storage_error",
            error_kind = mcp_storage_error_kind(error),
            error_detail = %sanitize_mcp_storage_error(error),
            outcome,
            "reconciled MCP refresh storage error after response deadline"
        ),
        Err(error) => tracing::warn!(
            operation = operation_name,
            storage_result = "task_error",
            error_detail = %sanitize_mcp_reconciliation_text(&error.to_string()),
            outcome,
            "reconciled MCP refresh task error after response deadline"
        ),
    }
}

fn mcp_storage_error_kind(error: &StorageError) -> &'static str {
    match error {
        StorageError::UnsupportedProvider { .. } => "unsupported_provider",
        StorageError::Postgres(_) => "postgres",
        StorageError::Runtime(_) => "runtime",
        StorageError::Serialization(_) => "serialization",
        StorageError::Conflict(_) => "conflict",
        StorageError::NotFound(_) => "not_found",
        StorageError::OperationDeadlineExceeded { .. } => "deadline_exceeded",
        StorageError::OperationCancelled { .. } => "cancelled",
        StorageError::OperationCommitOutcomeUnknown { .. } => "commit_outcome_unknown",
    }
}

fn sanitize_mcp_storage_error(error: &StorageError) -> String {
    sanitize_mcp_reconciliation_text(&error.to_string())
}

fn sanitize_mcp_reconciliation_text(input: &str) -> String {
    let mut sanitized = input.to_string();
    for marker in ["password=", "passfile=", "sslpassword="] {
        sanitized = redact_mcp_marker_values(&sanitized, marker);
    }
    if let Some(scheme) = sanitized.find("://") {
        let authority_start = scheme + 3;
        if let Some(at_offset) = sanitized[authority_start..].find('@') {
            let at = authority_start + at_offset;
            if let Some(colon_offset) = sanitized[authority_start..at].find(':') {
                let password_start = authority_start + colon_offset + 1;
                sanitized.replace_range(password_start..at, "[redacted]");
            }
        }
    }
    sanitized.truncate(512);
    sanitized
}

fn redact_mcp_marker_values(input: &str, marker: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find(marker) {
        output.push_str(&rest[..start + marker.len()]);
        output.push_str("[redacted]");
        let value_rest = &rest[start + marker.len()..];
        let value_end = value_rest
            .find(char::is_whitespace)
            .unwrap_or(value_rest.len());
        rest = &value_rest[value_end..];
    }
    output.push_str(rest);
    output
}

fn refresh_lease_conflict(
    credential_id: &str,
    outcome: &'static str,
    message: &'static str,
) -> Result<(), McpIdentityError> {
    tracing::warn!(credential_id, outcome, "lost MCP OAuth refresh lease");
    Err(McpIdentityError::unavailable(
        "mcp_identity_refresh_conflict",
        message,
    ))
}

fn resolve_mcp_refresh_completion_reread(
    current: Option<StoredMcpOauthCredential>,
    previous_version: u64,
) -> Result<StoredMcpOauthCredential, McpIdentityError> {
    match current {
        None => Err(McpIdentityError::unauthorized(
            "mcp_identity_not_connected",
            "per-user MCP identity was removed during refresh",
        )),
        Some(current) if current.revoked_at_unix.is_some() => Err(McpIdentityError::unauthorized(
            "mcp_identity_not_connected",
            "per-user MCP identity was revoked during refresh",
        )),
        Some(current) if current.version > previous_version => Ok(current),
        Some(_) => Err(McpIdentityError::unavailable(
            "mcp_identity_refresh_conflict",
            "MCP identity changed during refresh",
        )),
    }
}

fn resolve_ambiguous_mcp_refresh_completion_reread(
    current: Option<StoredMcpOauthCredential>,
    previous_version: u64,
) -> Result<StoredMcpOauthCredential, McpIdentityError> {
    match current {
        None => Err(McpIdentityError::unauthorized(
            "mcp_identity_not_connected",
            "per-user MCP identity was removed during refresh",
        )),
        Some(current) if current.revoked_at_unix.is_some() => Err(McpIdentityError::unauthorized(
            "mcp_identity_not_connected",
            "per-user MCP identity was revoked during refresh",
        )),
        Some(current) if current.version > previous_version => Ok(current),
        Some(_) => Err(McpIdentityError::unavailable(
            "mcp_identity_storage_outcome_unknown",
            "MCP refresh completion commit outcome could not be proven from durable storage",
        )),
    }
}

enum RefreshHeartbeatOutcome<T> {
    Work(Result<T, McpIdentityError>),
    HeartbeatFailed(McpIdentityError),
    OwnerTimedOut(McpIdentityError),
}

async fn run_with_refresh_heartbeat_tagged<T, Work, Renew, RenewFuture>(
    work: Work,
    heartbeat_interval: Duration,
    renewal_timeout: Duration,
    owner_timeout: Duration,
    mut renew: Renew,
) -> RefreshHeartbeatOutcome<T>
where
    Work: Future<Output = Result<T, McpIdentityError>>,
    Renew: FnMut() -> RenewFuture,
    RenewFuture: Future<Output = Result<(), McpIdentityError>>,
{
    let owner_deadline = tokio::time::Instant::now() + owner_timeout;
    tokio::pin!(work);
    loop {
        let tick = tokio::time::sleep(heartbeat_interval);
        tokio::pin!(tick);
        tokio::select! {
            result = &mut work => return RefreshHeartbeatOutcome::Work(result),
            _ = tokio::time::sleep_until(owner_deadline) => {
                return RefreshHeartbeatOutcome::OwnerTimedOut(refresh_owner_timeout());
            }
            _ = &mut tick => {}
        }

        let renewal = tokio::time::timeout(renewal_timeout, renew());
        tokio::pin!(renewal);
        let pending = tokio::select! {
            result = &mut renewal => {
                match result {
                    Ok(Ok(())) => continue,
                    Ok(Err(error)) => return RefreshHeartbeatOutcome::HeartbeatFailed(error),
                    Err(_) => {
                        return RefreshHeartbeatOutcome::HeartbeatFailed(refresh_renewal_timeout());
                    }
                }
            }
            result = &mut work => RefreshHeartbeatOutcome::Work(result),
            _ = tokio::time::sleep_until(owner_deadline) => {
                RefreshHeartbeatOutcome::OwnerTimedOut(refresh_owner_timeout())
            }
        };

        return match renewal.await {
            Ok(Ok(())) => pending,
            Ok(Err(error)) => RefreshHeartbeatOutcome::HeartbeatFailed(error),
            Err(_) => RefreshHeartbeatOutcome::HeartbeatFailed(refresh_renewal_timeout()),
        };
    }
}

fn refresh_owner_timeout() -> McpIdentityError {
    tracing::warn!(
        outcome = "owner_response_timeout",
        "stopped waiting for MCP OAuth refresh owner at the response deadline"
    );
    McpIdentityError::unavailable(
        "mcp_identity_refresh_owner_timeout",
        "MCP refresh exceeded its bounded response deadline",
    )
}

fn refresh_renewal_timeout() -> McpIdentityError {
    tracing::warn!(
        outcome = "renewal_response_timeout",
        "stopped waiting for MCP OAuth refresh lease renewal at the response deadline"
    );
    McpIdentityError::unavailable(
        "mcp_identity_refresh_renewal_timeout",
        "MCP refresh lease renewal exceeded its bounded response deadline",
    )
}

pub(super) fn validate_mcp_identity_runtime(config: &Config) -> anyhow::Result<()> {
    let requires_identity_key = config.mcp_servers.iter().any(|server| {
        matches!(
            server.auth_type,
            McpAuthType::PerUserOauth | McpAuthType::FerrogateSignedJwt
        )
    });
    if requires_identity_key {
        IdentityCipher::from_env().map_err(|error| anyhow::anyhow!(error.message))?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct McpIdentityActor {
    tenant_id: String,
    workspace_id: String,
    user_id: String,
}

impl McpIdentityActor {
    fn from_auth(auth: &AuthContext) -> Result<Self, McpIdentityError> {
        Ok(Self {
            tenant_id: auth.organization_id.clone().ok_or_else(|| {
                McpIdentityError::forbidden(
                    "mcp_identity_tenant_required",
                    "per-user MCP identity requires a tenant",
                )
            })?,
            workspace_id: auth.workspace_id.clone().ok_or_else(|| {
                McpIdentityError::forbidden(
                    "mcp_identity_workspace_required",
                    "per-user MCP identity requires a workspace",
                )
            })?,
            user_id: auth.user_id.clone().ok_or_else(|| {
                McpIdentityError::forbidden(
                    "mcp_identity_user_required",
                    "per-user MCP identity requires an authenticated user",
                )
            })?,
        })
    }

    fn access_request(&self, server_name: &str, permission_key: &str) -> McpIdentityAccessRequest {
        McpIdentityAccessRequest {
            tenant_id: self.tenant_id.clone(),
            workspace_id: self.workspace_id.clone(),
            user_id: self.user_id.clone(),
            server_name: server_name.to_string(),
            permission_key: permission_key.to_string(),
        }
    }
}

fn credential_id(actor: &McpIdentityActor, server_name: &str) -> String {
    format!(
        "mcp-credential-{}",
        sha256_hex(
            format!(
                "{}\0{}\0{}\0{server_name}",
                actor.tenant_id, actor.workspace_id, actor.user_id
            )
            .as_bytes()
        )
    )
}

fn flow_aad(id: &str, actor: &McpIdentityActor, server_name: &str) -> String {
    format!(
        "flow\0{id}\0{}\0{}\0{}\0{server_name}",
        actor.tenant_id, actor.workspace_id, actor.user_id
    )
}

fn credential_aad(id: &str, actor: &McpIdentityActor, server_name: &str) -> String {
    format!(
        "credential\0{id}\0{}\0{}\0{}\0{server_name}\0v1",
        actor.tenant_id, actor.workspace_id, actor.user_id
    )
}

fn storage_identity_error(error: StorageError) -> McpIdentityError {
    let code = match &error {
        StorageError::OperationDeadlineExceeded { .. }
        | StorageError::OperationCancelled { .. } => "mcp_identity_storage_deadline",
        StorageError::OperationCommitOutcomeUnknown { .. } => {
            "mcp_identity_storage_reconcile_required"
        }
        _ => "mcp_identity_storage_unavailable",
    };
    McpIdentityError::unavailable(
        code,
        format!("MCP identity storage is unavailable: {error}"),
    )
}

async fn fetch_discovery(config: &McpOauthConfig) -> Result<OidcDiscovery, McpIdentityError> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        config.issuer.trim_end_matches('/')
    );
    let discovery = get_json(&url, "OIDC discovery").await?;
    validate_discovery_endpoints(config, &discovery)?;
    Ok(discovery)
}

fn validate_discovery_endpoints(
    config: &McpOauthConfig,
    discovery: &OidcDiscovery,
) -> Result<(), McpIdentityError> {
    let endpoints = [
        discovery.authorization_endpoint.as_str(),
        discovery.token_endpoint.as_str(),
        discovery.jwks_uri.as_str(),
    ]
    .into_iter()
    .chain(discovery.revocation_endpoint.as_deref());
    for endpoint in endpoints {
        let url = reqwest::Url::parse(endpoint).map_err(|_| {
            McpIdentityError::unavailable(
                "mcp_identity_provider_invalid",
                "OIDC discovery returned an invalid endpoint",
            )
        })?;
        if url.host_str().is_none()
            || (!config.allow_insecure_http && url.scheme() != "https")
            || (config.allow_insecure_http && !matches!(url.scheme(), "http" | "https"))
        {
            return Err(McpIdentityError::unavailable(
                "mcp_identity_provider_invalid",
                "OIDC discovery returned an endpoint with a disallowed scheme",
            ));
        }
    }
    Ok(())
}

async fn validate_oidc_token(
    config: &McpOauthConfig,
    discovery: &OidcDiscovery,
    token: &str,
    expected_nonce: Option<&str>,
) -> Result<String, McpIdentityError> {
    let jwks: jsonwebtoken::jwk::JwkSet = get_json(&discovery.jwks_uri, "OIDC JWKS").await?;
    let header = decode_header(token).map_err(|_| {
        McpIdentityError::unauthorized("mcp_oidc_token_invalid", "OIDC token header is invalid")
    })?;
    let kid = header.kid.as_deref().ok_or_else(|| {
        McpIdentityError::unauthorized("mcp_oidc_token_invalid", "OIDC token has no key id")
    })?;
    let jwk = jwks.find(kid).ok_or_else(|| {
        McpIdentityError::unauthorized("mcp_oidc_token_invalid", "OIDC token key id was not found")
    })?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| {
        McpIdentityError::unauthorized("mcp_oidc_token_invalid", "OIDC token key is unsupported")
    })?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&[config.audience.as_deref().unwrap_or(&config.client_id)]);
    let claims = decode::<Value>(token, &key, &validation)
        .map_err(|_| {
            McpIdentityError::unauthorized("mcp_oidc_token_invalid", "OIDC token validation failed")
        })?
        .claims;
    if expected_nonce
        .is_some_and(|nonce| claims.get("nonce").and_then(Value::as_str) != Some(nonce))
    {
        return Err(McpIdentityError::unauthorized(
            "mcp_oidc_nonce_mismatch",
            "OIDC token nonce does not match the authorization flow",
        ));
    }
    claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|sub| !sub.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            McpIdentityError::unauthorized("mcp_oidc_subject_missing", "OIDC token has no subject")
        })
}

async fn resolve_client_secret(config: &McpOauthConfig) -> Result<String, McpIdentityError> {
    let reference = config.client_secret_ref.clone().ok_or_else(|| {
        McpIdentityError::unavailable(
            "mcp_identity_client_secret_missing",
            "OIDC client secret reference is missing",
        )
    })?;
    tokio::task::spawn_blocking(move || {
        ferrogate_secrets::SecretResolverRegistry::from_env().resolve(&reference)
    })
    .await
    .map_err(|_| {
        McpIdentityError::unavailable(
            "mcp_identity_client_secret_unavailable",
            "OIDC client secret task failed",
        )
    })?
    .map_err(|_| {
        McpIdentityError::unavailable(
            "mcp_identity_client_secret_unavailable",
            "OIDC client secret could not be resolved",
        )
    })?
    .filter(|value| !value.trim().is_empty())
    .ok_or_else(|| {
        McpIdentityError::unavailable(
            "mcp_identity_client_secret_unavailable",
            "OIDC client secret is empty",
        )
    })
}

async fn get_json<T: serde::de::DeserializeOwned>(
    url: &str,
    label: &str,
) -> Result<T, McpIdentityError> {
    let response = identity_http_client()?
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| {
            McpIdentityError::unavailable(
                "mcp_identity_provider_unavailable",
                format!("{label} endpoint is unavailable"),
            )
        })?;
    if !response.status().is_success() {
        return Err(McpIdentityError::unavailable(
            "mcp_identity_provider_unavailable",
            format!(
                "{label} endpoint returned HTTP {}",
                response.status().as_u16()
            ),
        ));
    }
    let body = response.bytes().await.map_err(|_| {
        McpIdentityError::unavailable(
            "mcp_identity_provider_invalid",
            format!("{label} response could not be read"),
        )
    })?;
    if body.len() > MAX_OIDC_RESPONSE_BYTES {
        return Err(McpIdentityError::unavailable(
            "mcp_identity_provider_invalid",
            format!("{label} response is too large"),
        ));
    }
    serde_json::from_slice(&body).map_err(|_| {
        McpIdentityError::unavailable(
            "mcp_identity_provider_invalid",
            format!("{label} response is invalid"),
        )
    })
}

async fn post_token_form(
    endpoint: &str,
    form: &[(&str, String)],
) -> Result<OauthTokenResponse, McpIdentityError> {
    let response = post_form(endpoint, form).await.map_err(|_| {
        McpIdentityError::unavailable(
            "mcp_identity_provider_unavailable",
            "OIDC token endpoint is unavailable",
        )
    })?;
    if !response.status().is_success() {
        return Err(McpIdentityError::unavailable(
            "mcp_identity_provider_unavailable",
            format!(
                "OIDC token endpoint returned HTTP {}",
                response.status().as_u16()
            ),
        ));
    }
    let body = response.bytes().await.map_err(|_| {
        McpIdentityError::unavailable(
            "mcp_identity_provider_invalid",
            "OIDC token response could not be read",
        )
    })?;
    if body.len() > MAX_OIDC_RESPONSE_BYTES {
        return Err(McpIdentityError::unavailable(
            "mcp_identity_provider_invalid",
            "OIDC token response is too large",
        ));
    }
    serde_json::from_slice(&body).map_err(|_| {
        McpIdentityError::unavailable(
            "mcp_identity_provider_invalid",
            "OIDC token response is invalid",
        )
    })
}

async fn post_empty_form(endpoint: &str, form: &[(&str, String)]) -> Result<(), McpIdentityError> {
    let response = post_form(endpoint, form).await.map_err(|_| {
        McpIdentityError::unavailable(
            "mcp_identity_provider_unavailable",
            "OIDC revocation endpoint is unavailable",
        )
    })?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(McpIdentityError::unavailable(
            "mcp_identity_provider_unavailable",
            "OIDC revocation endpoint rejected the token",
        ))
    }
}

async fn post_form(
    endpoint: &str,
    form: &[(&str, String)],
) -> Result<reqwest::Response, McpIdentityError> {
    let body = form
        .iter()
        .map(|(key, value)| format!("{}={}", form_url_encode(key), form_url_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    identity_http_client()?
        .post(endpoint)
        .timeout(Duration::from_secs(10))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|_| {
            McpIdentityError::unavailable(
                "mcp_identity_provider_unavailable",
                "OIDC form endpoint is unavailable",
            )
        })
}

fn identity_http_client() -> Result<reqwest::Client, McpIdentityError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| {
            McpIdentityError::unavailable(
                "mcp_identity_provider_unavailable",
                "failed to initialize OIDC HTTP client",
            )
        })
}

fn dispatch_bearer(token: String) -> Result<McpDispatchHeaders, McpIdentityError> {
    McpDispatchHeaders::bearer(token).map_err(|_| {
        McpIdentityError::unavailable(
            "mcp_identity_provider_invalid",
            "OIDC provider returned an invalid bearer token",
        )
    })
}

fn form_url_encode(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        let character = byte as char;
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '~') {
            output.push(character);
        } else if character == ' ' {
            output.push('+');
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn random_urlsafe(bytes: usize) -> String {
    let mut output = Vec::with_capacity(bytes);
    while output.len() < bytes {
        output.extend_from_slice(&XChaCha20Poly1305::generate_nonce(&mut OsRng));
    }
    output.truncate(bytes);
    URL_SAFE_NO_PAD.encode(output)
}

fn sha256_hex(input: &[u8]) -> String {
    Sha256::digest(input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(output)
}

fn now_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "state_mcp_identity_test.rs"]
mod state_mcp_identity_test;
