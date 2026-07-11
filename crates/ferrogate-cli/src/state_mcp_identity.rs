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
    StoredMcpOauthCredential, StoredMcpOauthFlow,
};
use http::StatusCode;
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const MCP_IDENTITY_KEY_ENV: &str = "FERROGATE_MCP_IDENTITY_KEY";
const OAUTH_FLOW_TTL_SECS: i64 = 600;
const SIGNED_IDENTITY_TTL_SECS: i64 = 60;
const TOKEN_REFRESH_SKEW_SECS: i64 = 30;
const REFRESH_LEASE_SECS: i64 = 10;
const REFRESH_WAIT_TIMEOUT_SECS: u64 = 12;
const REFRESH_POLL_MILLIS: u64 = 50;
const MAX_OIDC_RESPONSE_BYTES: usize = 1024 * 1024;

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
        let repositories = Arc::clone(&self.repositories);
        self.run_mcp_identity_storage("begin OAuth flow", move || {
            repositories.begin_mcp_oauth_flow(StoredMcpOauthFlow {
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
        })
        .await?;
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
        let repositories = Arc::clone(&self.repositories);
        let consumed_state_id = state_id.clone();
        let flow = self
            .run_mcp_identity_storage("consume OAuth flow", move || {
                repositories.consume_mcp_oauth_flow(&consumed_state_id, now)
            })
            .await?
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
        let repositories = Arc::clone(&self.repositories);
        let committed_flow = flow.clone();
        let commit = self
            .run_mcp_identity_storage("commit OAuth callback", move || {
                repositories.commit_mcp_oauth_callback(
                    &committed_flow,
                    credential,
                    "mcp.identity.connect",
                )
            })
            .await?;
        if commit != McpOauthCallbackCommitOutcome::Committed {
            return Err(McpIdentityError::forbidden(
                "mcp_oauth_authorization_changed",
                "MCP OAuth authorization changed before callback completion",
            ));
        }
        self.record_admin_audit_event(AdminAuditEventDraft {
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
        let repositories = Arc::clone(&self.repositories);
        let revoked = self
            .run_mcp_identity_storage("revoke MCP identity", move || {
                repositories.revoke_mcp_oauth_identity(&request, now, "local_revoked")
            })
            .await?;
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
        let repositories = Arc::clone(&self.repositories);
        let tenant_id = actor.tenant_id.clone();
        let workspace_id = actor.workspace_id.clone();
        let user_id = actor.user_id.clone();
        let server_name_owned = server_name.to_string();
        let stored_outcome = outcome.clone();
        self.run_mcp_identity_storage("record MCP revocation outcome", move || {
            repositories.update_mcp_oauth_revocation_outcome(
                &tenant_id,
                &workspace_id,
                &user_id,
                &server_name_owned,
                &stored_outcome,
            )
        })
        .await?;
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
        let deadline = tokio::time::Instant::now() + Duration::from_secs(REFRESH_WAIT_TIMEOUT_SECS);
        let mut candidate = credential;
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
            let claim_lease_id = lease_id.clone();
            let repositories = Arc::clone(&self.repositories);
            let claim = self
                .run_mcp_identity_storage("claim MCP refresh lease", move || {
                    repositories.claim_mcp_oauth_refresh(&McpRefreshClaimRequest {
                        tenant_id,
                        credential_id,
                        expected_version: version,
                        authorization_generation: generation,
                        lease_id: claim_lease_id,
                        now_unix: now,
                        lease_expires_at_unix: now.saturating_add(REFRESH_LEASE_SECS),
                    })
                })
                .await?;
            match claim {
                McpRefreshClaimOutcome::Acquired(claimed) => {
                    return self
                        .refresh_claimed_mcp_credential(actor, server, claimed, lease_id)
                        .await;
                }
                McpRefreshClaimOutcome::Busy { .. } => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(McpIdentityError::unavailable(
                            "mcp_identity_refresh_timeout",
                            "timed out waiting for the active MCP refresh lease",
                        ));
                    }
                    tokio::time::sleep(Duration::from_millis(REFRESH_POLL_MILLIS)).await;
                    candidate = self
                        .authorize_mcp_identity_actor(actor, &server.name, "mcp.identity.use")
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
                    candidate = current;
                }
                McpRefreshClaimOutcome::Changed(None) => {
                    return Err(McpIdentityError::unauthorized(
                        "mcp_identity_not_connected",
                        "per-user MCP identity changed before refresh",
                    ));
                }
            }
        }
    }

    async fn refresh_claimed_mcp_credential(
        &self,
        actor: &McpIdentityActor,
        server: &ferrogate_mcp::McpServerConfig,
        credential: StoredMcpOauthCredential,
        lease_id: String,
    ) -> Result<StoredMcpOauthCredential, McpIdentityError> {
        let oauth = server
            .oauth
            .as_ref()
            .expect("validated per_user_oauth config");
        let refresh_result = async {
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
            if !token.token_type.eq_ignore_ascii_case("bearer")
                || token.access_token.trim().is_empty()
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
            next.expires_at_unix = now
                .saturating_add(i64::try_from(token.expires_in.unwrap_or(300)).unwrap_or(i64::MAX));
            next.updated_at_unix = now;
            next.last_refresh_outcome = Some("refreshed".into());
            Ok(next)
        }
        .await;
        let mut next = match refresh_result {
            Ok(next) => next,
            Err(error) => {
                let repositories = Arc::clone(&self.repositories);
                let tenant_id = credential.tenant_id.clone();
                let credential_id = credential.id.clone();
                let release_lease_id = lease_id.clone();
                let _ = self
                    .run_mcp_identity_storage("release failed MCP refresh lease", move || {
                        repositories.release_mcp_oauth_refresh(
                            &tenant_id,
                            &credential_id,
                            &release_lease_id,
                            "refresh_failed",
                        )
                    })
                    .await;
                return Err(error);
            }
        };
        let repositories = Arc::clone(&self.repositories);
        let persisted = next.clone();
        let completed = self
            .run_mcp_identity_storage("complete MCP refresh lease", move || {
                repositories.complete_mcp_oauth_refresh(persisted, &lease_id)
            })
            .await?;
        if completed {
            next.version = next.version.saturating_add(1);
            next.refresh_lease_id = None;
            next.refresh_lease_expires_at_unix = None;
            if let Ok(mut metrics) = self.metrics.lock() {
                metrics.record_mcp_identity_refresh();
            }
            return Ok(next);
        }
        self.authorize_mcp_identity_actor(actor, &server.name, "mcp.identity.use")
            .await?
            .filter(|row| row.revoked_at_unix.is_none() && row.version > credential.version)
            .ok_or_else(|| {
                McpIdentityError::unavailable(
                    "mcp_identity_refresh_conflict",
                    "MCP identity changed during refresh",
                )
            })
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

    async fn authorize_mcp_identity_actor(
        &self,
        actor: &McpIdentityActor,
        server_name: &str,
        action: &str,
    ) -> Result<Option<StoredMcpOauthCredential>, McpIdentityError> {
        let request = actor.access_request(server_name, action);
        let repositories = Arc::clone(&self.repositories);
        let outcome = self
            .run_mcp_identity_storage("authorize MCP identity actor", move || {
                repositories.authorize_mcp_identity(&request)
            })
            .await?;
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

    async fn run_mcp_identity_storage<T, F>(
        &self,
        operation: &'static str,
        action: F,
    ) -> Result<T, McpIdentityError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, StorageError> + Send + 'static,
    {
        tokio::task::spawn_blocking(action)
            .await
            .map_err(|error| {
                McpIdentityError::unavailable(
                    "mcp_identity_storage_unavailable",
                    format!("failed to {operation}: blocking task failed: {error}"),
                )
            })?
            .map_err(storage_identity_error)
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
    McpIdentityError::unavailable(
        "mcp_identity_storage_unavailable",
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
mod tests {
    use super::*;

    static IDENTITY_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn ciphertext_is_bound_to_subject_aad_and_debug_never_contains_plaintext() {
        let _guard = IDENTITY_ENV_LOCK.lock().unwrap();
        std::env::set_var(MCP_IDENTITY_KEY_ENV, "11".repeat(32));
        let cipher = IdentityCipher::from_env().unwrap();
        let (nonce, ciphertext) = cipher
            .encrypt(b"secret-access-token", b"tenant-a/user-a")
            .unwrap();
        assert!(!ciphertext
            .windows(19)
            .any(|window| window == b"secret-access-token"));
        assert_eq!(
            cipher
                .decrypt(&nonce, &ciphertext, b"tenant-a/user-a")
                .unwrap(),
            b"secret-access-token"
        );
        assert!(cipher
            .decrypt(&nonce, &ciphertext, b"tenant-a/user-b")
            .is_err());
        std::env::remove_var(MCP_IDENTITY_KEY_ENV);
    }

    #[test]
    fn encryption_key_requires_exact_hex_material() {
        let _guard = IDENTITY_ENV_LOCK.lock().unwrap();
        std::env::set_var(MCP_IDENTITY_KEY_ENV, "short");
        let error = match IdentityCipher::from_env() {
            Ok(_) => panic!("short encryption key unexpectedly passed validation"),
            Err(error) => error,
        };
        assert_eq!(error.code, "mcp_identity_key_invalid");
        std::env::remove_var(MCP_IDENTITY_KEY_ENV);
    }
}
