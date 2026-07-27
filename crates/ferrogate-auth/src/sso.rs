// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! OIDC (Authorization Code + PKCE) and SAML SSO flows plus the per-tenant
//! SSO configuration endpoints (issues #160/#283).

use anyhow::Context;
use base64::Engine as _;
use ferrogate_storage::{
    StoredAdminUser, StoredAdminUserMembership, StoredSsoPendingFlow, StoredSsoProviderConfig,
};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, time::Duration};

use crate::admin_console::{
    current_admin_session, issue_session, provision_gateway_api_key, resolve_default_workspace,
    AdminConsoleState, AdminSessionResponse, AdminTenantView, AdminUserView,
    ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
};
use crate::http::{
    forbidden, internal_error, not_found, storage_error, unauthorized, unprocessable, HttpResponse,
};
use crate::membership_role::MembershipRole;
use crate::saml;
use crate::scim::membership_role_in_tenant;
use crate::util::{
    block_on_sync_bridge, generate_random_hex, is_valid_email, next_id, now_unix_seconds,
    unusable_password_hash,
};

// -- issue #160: OIDC SSO (Authorization Code + PKCE) ----------------------

fn default_sso_role() -> String {
    "member".to_string()
}

fn default_group_claim() -> String {
    "groups".to_string()
}

fn default_provider_kind() -> String {
    "oidc".to_string()
}

/// Request body for `POST /v1/admin/team/sso-config` (issue #160, made durable
/// and SAML-capable in #283). Only a tenant `owner` may set this. The provider
/// kind (OIDC by default, or SAML) determines which fields are required.
///
/// The OIDC client secret is supplied as a ferrogate-secrets `secret_ref`
/// (`env://...` / `vault://...`), never as a plaintext value -- so it is never
/// persisted in the control plane in the clear.
#[derive(Debug, Clone, Deserialize)]
pub struct SsoConfigRequest {
    #[serde(default = "default_provider_kind")]
    pub provider_kind: String,
    #[serde(default)]
    pub group_role_mapping: HashMap<String, String>,
    #[serde(default = "default_sso_role")]
    pub default_role: String,
    // --- OIDC ---
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    /// ferrogate-secrets reference URI for the OIDC client secret. Never a
    /// plaintext secret.
    #[serde(default)]
    pub client_secret_ref: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// ID-token claim carrying the caller's IdP group memberships (an array of
    /// strings), used with `group_role_mapping`. Defaults to `"groups"`, the
    /// common Okta/Azure AD/Keycloak convention.
    #[serde(default = "default_group_claim")]
    pub group_claim: String,
    // --- SAML ---
    #[serde(default)]
    pub idp_entity_id: Option<String>,
    #[serde(default)]
    pub idp_sso_url: Option<String>,
    /// The IdP's signing certificate (PEM or bare base64 DER).
    #[serde(default)]
    pub idp_certificate: Option<String>,
    #[serde(default)]
    pub sp_entity_id: Option<String>,
    #[serde(default)]
    pub acs_url: Option<String>,
    #[serde(default)]
    pub email_attribute: Option<String>,
    #[serde(default)]
    pub name_attribute: Option<String>,
    #[serde(default)]
    pub groups_attribute: Option<String>,
}

/// An OIDC configuration resolved from durable storage, with the client
/// secret still referenced (not yet fetched) -- authorize needs no secret, and
/// the callback resolves the ref just-in-time.
#[derive(Debug, Clone)]
struct ResolvedOidcConfig {
    issuer: String,
    client_id: String,
    client_secret_ref: String,
    redirect_uri: String,
    group_role_mapping: HashMap<String, String>,
    default_role: String,
    group_claim: String,
}

/// An in-flight SSO flow may sit in the browser for a while (IdP login,
/// possibly MFA); 10 minutes is generous without leaving stale entries
/// around indefinitely.
const SSO_FLOW_TTL_SECS: i64 = 600;

/// Reads the durable per-tenant SSO config (#283), returning `None` if none is
/// configured or the store errored (callers translate `None` to a 404).
fn read_stored_sso_config(
    console: &AdminConsoleState,
    tenant_id: &str,
) -> Option<StoredSsoProviderConfig> {
    block_on_sync_bridge(console.repositories.get_sso_provider_config(tenant_id))
        .ok()
        .flatten()
}

/// Projects a stored config into the OIDC runtime shape, or `None` if the
/// tenant is configured for a different provider kind / is missing a required
/// OIDC field (fail closed).
fn resolve_oidc_config(stored: &StoredSsoProviderConfig) -> Option<ResolvedOidcConfig> {
    if stored.provider_kind != "oidc" {
        return None;
    }
    Some(ResolvedOidcConfig {
        issuer: stored.oidc_issuer.clone()?,
        client_id: stored.oidc_client_id.clone()?,
        client_secret_ref: stored.oidc_client_secret_ref.clone()?,
        redirect_uri: stored.oidc_redirect_uri.clone()?,
        group_role_mapping: stored.group_role_mapping.clone().into_iter().collect(),
        default_role: stored.default_role.clone(),
        group_claim: stored
            .oidc_group_claim
            .clone()
            .unwrap_or_else(default_group_claim),
    })
}

/// Configures SSO (OIDC or SAML) for the caller's own tenant (issue #160/#283)
/// and PERSISTS it durably so it survives a gateway restart. Only a tenant
/// `owner` may do this; re-posting replaces the config.
pub(crate) fn handle_admin_sso_config_set(
    console: &AdminConsoleState,
    token: &str,
    payload: SsoConfigRequest,
) -> HttpResponse {
    let (_caller, membership) = match current_admin_session(console, token) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if !MembershipRole::from_stored(&membership.role).is_owner() {
        return forbidden("only a tenant owner can configure SSO");
    }
    // Validate the tiers this config can JIT-provision (issue #517) BEFORE
    // persisting it: `default_role` and every `group_role_mapping` value ends
    // up written verbatim into `admin_user_tenant_memberships.role` on a first
    // SSO login, so an unvalidated one is an unvalidated role write with an
    // IdP round-trip in between.
    let default_role = match MembershipRole::parse(payload.default_role.trim()) {
        Ok(role) => role,
        Err(error) => return unprocessable(&format!("default_role: {error}")),
    };
    let mut group_role_mapping: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (group, role) in &payload.group_role_mapping {
        match MembershipRole::parse(role.trim()) {
            Ok(role) => {
                group_role_mapping.insert(group.clone(), role.to_string());
            }
            Err(error) => return unprocessable(&format!("group_role_mapping[{group:?}]: {error}")),
        }
    }
    let now = now_unix_seconds() as i64;
    let existing = read_stored_sso_config(console, &membership.tenant_id);
    let created_at_unix = existing.map(|config| config.created_at_unix).unwrap_or(now);

    let stored = match payload.provider_kind.as_str() {
        "oidc" => {
            let issuer = payload
                .issuer
                .as_deref()
                .unwrap_or_default()
                .trim()
                .trim_end_matches('/')
                .to_string();
            let client_id = payload
                .client_id
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            let client_secret_ref = payload
                .client_secret_ref
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            let redirect_uri = payload
                .redirect_uri
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            if issuer.is_empty()
                || client_id.is_empty()
                || client_secret_ref.is_empty()
                || redirect_uri.is_empty()
            {
                return unprocessable(
                    "issuer, client_id, client_secret_ref, and redirect_uri are required for oidc",
                );
            }
            // Validate the secret reference parses now, so a misconfiguration
            // surfaces at config time rather than mid-login.
            if let Err(error) = ferrogate_secrets::SecretRef::parse(&client_secret_ref) {
                return unprocessable(&format!(
                    "client_secret_ref is not a valid secret reference: {error}"
                ));
            }
            StoredSsoProviderConfig {
                tenant_id: membership.tenant_id.clone(),
                provider_kind: "oidc".into(),
                default_role: default_role.to_string(),
                group_role_mapping,
                oidc_issuer: Some(issuer),
                oidc_client_id: Some(client_id),
                oidc_client_secret_ref: Some(client_secret_ref),
                oidc_redirect_uri: Some(redirect_uri),
                oidc_group_claim: Some(payload.group_claim.clone()),
                saml_idp_entity_id: None,
                saml_idp_sso_url: None,
                saml_idp_certificate: None,
                saml_sp_entity_id: None,
                saml_acs_url: None,
                saml_email_attribute: None,
                saml_name_attribute: None,
                saml_groups_attribute: None,
                created_at_unix,
                updated_at_unix: now,
            }
        }
        "saml" => {
            let idp_sso_url = payload
                .idp_sso_url
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            let idp_certificate = payload
                .idp_certificate
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            let sp_entity_id = payload
                .sp_entity_id
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            let acs_url = payload
                .acs_url
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            if idp_sso_url.is_empty()
                || idp_certificate.is_empty()
                || sp_entity_id.is_empty()
                || acs_url.is_empty()
            {
                return unprocessable(
                    "idp_sso_url, idp_certificate, sp_entity_id, and acs_url are required for saml",
                );
            }
            // Fail closed at config time if the certificate cannot be parsed
            // into a usable verification key.
            if let Err(error) = saml::parse_idp_public_key(&idp_certificate) {
                return unprocessable(&format!(
                    "idp_certificate is not a usable X.509 certificate: {error}"
                ));
            }
            StoredSsoProviderConfig {
                tenant_id: membership.tenant_id.clone(),
                provider_kind: "saml".into(),
                default_role: default_role.to_string(),
                group_role_mapping,
                oidc_issuer: None,
                oidc_client_id: None,
                oidc_client_secret_ref: None,
                oidc_redirect_uri: None,
                oidc_group_claim: None,
                saml_idp_entity_id: payload
                    .idp_entity_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string),
                saml_idp_sso_url: Some(idp_sso_url),
                saml_idp_certificate: Some(idp_certificate),
                saml_sp_entity_id: Some(sp_entity_id),
                saml_acs_url: Some(acs_url),
                saml_email_attribute: payload.email_attribute.clone(),
                saml_name_attribute: payload.name_attribute.clone(),
                saml_groups_attribute: payload.groups_attribute.clone(),
                created_at_unix,
                updated_at_unix: now,
            }
        }
        other => {
            return unprocessable(&format!(
                "unsupported provider_kind {other:?}; expected \"oidc\" or \"saml\""
            ));
        }
    };

    if let Err(error) =
        block_on_sync_bridge(console.repositories.upsert_sso_provider_config(stored))
    {
        return storage_error(&error);
    }
    HttpResponse::json(
        200,
        json!({
            "object": "sso_config",
            "configured": true,
            "provider_kind": payload.provider_kind,
        }),
    )
}

/// Returns the caller tenant's current SSO configuration with secrets/keys
/// redacted (issue #283). Only a tenant `owner` may read it.
pub(crate) fn handle_admin_sso_config_get(
    console: &AdminConsoleState,
    token: &str,
) -> HttpResponse {
    let (_caller, membership) = match current_admin_session(console, token) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if !MembershipRole::from_stored(&membership.role).is_owner() {
        return forbidden("only a tenant owner can read the SSO configuration");
    }
    let Some(config) = read_stored_sso_config(console, &membership.tenant_id) else {
        return not_found("SSO is not configured for this tenant");
    };
    HttpResponse::json(
        200,
        json!({
            "object": "sso_config",
            "provider_kind": config.provider_kind,
            "default_role": config.default_role,
            "group_role_mapping": config.group_role_mapping,
            "oidc": {
                "issuer": config.oidc_issuer,
                "client_id": config.oidc_client_id,
                // The secret reference is shown (it is a pointer, not the
                // secret itself); the resolved secret is never returned.
                "client_secret_ref": config.oidc_client_secret_ref,
                "redirect_uri": config.oidc_redirect_uri,
                "group_claim": config.oidc_group_claim,
            },
            "saml": {
                "idp_entity_id": config.saml_idp_entity_id,
                "idp_sso_url": config.saml_idp_sso_url,
                "sp_entity_id": config.saml_sp_entity_id,
                "acs_url": config.saml_acs_url,
                "email_attribute": config.saml_email_attribute,
                "name_attribute": config.saml_name_attribute,
                "groups_attribute": config.saml_groups_attribute,
                // The certificate is public but bulky; expose only whether one
                // is configured.
                "certificate_configured": config.saml_idp_certificate.is_some(),
            },
        }),
    )
}

/// Removes the caller tenant's SSO configuration (issue #283). Only a tenant
/// `owner` may do this.
pub(crate) fn handle_admin_sso_config_delete(
    console: &AdminConsoleState,
    token: &str,
) -> HttpResponse {
    let (_caller, membership) = match current_admin_session(console, token) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if !MembershipRole::from_stored(&membership.role).is_owner() {
        return forbidden("only a tenant owner can remove the SSO configuration");
    }
    match block_on_sync_bridge(
        console
            .repositories
            .delete_sso_provider_config(&membership.tenant_id),
    ) {
        Ok(removed) => {
            HttpResponse::json(200, json!({ "object": "sso_config", "deleted": removed }))
        }
        Err(error) => storage_error(&error),
    }
}

#[derive(Debug, Clone, Deserialize)]
struct OidcDiscoveryDocument {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

fn fetch_oidc_discovery(issuer: &str) -> anyhow::Result<OidcDiscoveryDocument> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let body = ferrogate_secrets::http_get(&url, &[], Duration::from_secs(10), None)
        .context("failed to fetch OIDC discovery document")?;
    serde_json::from_slice(&body).context("invalid OIDC discovery document")
}

fn fetch_jwks(jwks_uri: &str) -> anyhow::Result<jsonwebtoken::jwk::JwkSet> {
    let body = ferrogate_secrets::http_get(jwks_uri, &[], Duration::from_secs(10), None)
        .context("failed to fetch JWKS")?;
    serde_json::from_slice(&body).context("invalid JWKS document")
}

/// Minimal percent-encoding for query/form values -- avoids a new
/// dependency for what's otherwise a one-screen helper.
pub(crate) fn urlencode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// Generates a PKCE `code_verifier`/`code_challenge` pair (S256), per
/// RFC 7636.
fn generate_pkce_pair() -> anyhow::Result<(String, String)> {
    let verifier = generate_random_hex(48)?;
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    Ok((verifier, challenge))
}

/// Starts an OIDC Authorization Code + PKCE flow for `tenant_id` (issue
/// #160). Unauthenticated by design -- the browser isn't logged in yet.
/// Returns the IdP authorize URL for the console to redirect to, rather
/// than issuing an HTTP redirect itself, so a JSON-API-only client can
/// drive the flow too.
pub(crate) fn handle_sso_authorize(console: &AdminConsoleState, tenant_id: &str) -> HttpResponse {
    let Some(stored) = read_stored_sso_config(console, tenant_id) else {
        return not_found("SSO is not configured for this tenant");
    };
    let Some(config) = resolve_oidc_config(&stored) else {
        return unprocessable(
            "this tenant is not configured for OIDC SSO; use the SAML authorize endpoint",
        );
    };
    let discovery = match fetch_oidc_discovery(&config.issuer) {
        Ok(discovery) => discovery,
        Err(error) => return internal_error(&format!("OIDC discovery failed: {error:#}")),
    };
    let (code_verifier, code_challenge) = match generate_pkce_pair() {
        Ok(pair) => pair,
        Err(error) => return internal_error(&error.to_string()),
    };
    let state = match generate_random_hex(24) {
        Ok(state) => state,
        Err(error) => return internal_error(&error.to_string()),
    };
    let now = now_unix_seconds() as i64;
    let flow = StoredSsoPendingFlow {
        state: state.clone(),
        tenant_id: tenant_id.to_string(),
        provider_kind: "oidc".into(),
        code_verifier: Some(code_verifier),
        request_id: None,
        created_at_unix: now,
        expires_at_unix: now + SSO_FLOW_TTL_SECS,
    };
    if let Err(error) = block_on_sync_bridge(console.repositories.insert_sso_pending_flow(flow)) {
        return storage_error(&error);
    }
    let authorize_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid%20email%20profile&state={}&code_challenge={}&code_challenge_method=S256",
        discovery.authorization_endpoint,
        urlencode(&config.client_id),
        urlencode(&config.redirect_uri),
        state,
        code_challenge,
    );
    HttpResponse::json(
        200,
        json!({ "authorize_url": authorize_url, "state": state }),
    )
}

#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    id_token: String,
}

/// Completes an OIDC Authorization Code + PKCE flow (issue #160):
/// - exchanges `code` for tokens using the stashed PKCE `code_verifier`,
/// - validates the returned ID token's signature against the IdP's JWKS
///   (matched by `kid`), issuer, audience, and expiry,
/// - maps the IdP's group claim to a tenant role via `group_role_mapping`,
/// - just-in-time provisions the `StoredAdminUser` + membership on first
///   login (never overwriting a role an owner set explicitly afterward),
/// - and issues the same session shape `register`/`login` return.
pub(crate) fn handle_sso_callback(
    console: &AdminConsoleState,
    code: &str,
    state: &str,
) -> HttpResponse {
    let now = now_unix_seconds() as i64;
    let flow = match block_on_sync_bridge(console.repositories.take_sso_pending_flow(state, now)) {
        Ok(flow) => flow,
        Err(error) => return storage_error(&error),
    };
    let Some(flow) = flow else {
        return unauthorized("unknown, expired, or already-used SSO state");
    };
    let Some(code_verifier) = flow.code_verifier.clone() else {
        return unprocessable("this pending flow is not an OIDC flow");
    };
    let Some(stored) = read_stored_sso_config(console, &flow.tenant_id) else {
        return internal_error("SSO configuration was removed mid-flow");
    };
    let Some(config) = resolve_oidc_config(&stored) else {
        return internal_error("SSO configuration is no longer OIDC");
    };
    // Resolve the client secret from its reference just-in-time; it is never
    // persisted in plaintext (#283).
    let client_secret = match console.secret_resolver.resolve(&config.client_secret_ref) {
        Ok(Some(secret)) => secret,
        Ok(None) => {
            return internal_error("OIDC client_secret_ref did not resolve to a secret");
        }
        Err(error) => {
            return internal_error(&format!("failed to resolve OIDC client secret: {error:#}"));
        }
    };
    let discovery = match fetch_oidc_discovery(&config.issuer) {
        Ok(discovery) => discovery,
        Err(error) => return internal_error(&format!("OIDC discovery failed: {error:#}")),
    };

    let form_body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
        urlencode(code),
        urlencode(&config.redirect_uri),
        urlencode(&config.client_id),
        urlencode(&client_secret),
        urlencode(&code_verifier),
    );
    let token_response_body = match ferrogate_secrets::http_post(
        &discovery.token_endpoint,
        &[(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        form_body.as_bytes(),
        Duration::from_secs(10),
        None,
    ) {
        Ok(body) => body,
        Err(error) => return internal_error(&format!("token exchange failed: {error:#}")),
    };
    let token_response: OidcTokenResponse = match serde_json::from_slice(&token_response_body) {
        Ok(value) => value,
        Err(error) => return internal_error(&format!("invalid token endpoint response: {error}")),
    };

    let header = match decode_header(&token_response.id_token) {
        Ok(header) => header,
        Err(error) => return unauthorized(&format!("invalid ID token header: {error}")),
    };
    let Some(kid) = header.kid else {
        return unauthorized("ID token is missing a key id (kid)");
    };
    let jwks = match fetch_jwks(&discovery.jwks_uri) {
        Ok(jwks) => jwks,
        Err(error) => return internal_error(&format!("failed to fetch JWKS: {error:#}")),
    };
    let Some(jwk) = jwks.find(&kid) else {
        return unauthorized("ID token key id was not found in the IdP's JWKS");
    };
    let decoding_key = match DecodingKey::from_jwk(jwk) {
        Ok(key) => key,
        Err(error) => return internal_error(&format!("unsupported JWK: {error}")),
    };
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[config.client_id.as_str()]);
    validation.set_issuer(&[config.issuer.as_str()]);
    let claims =
        match decode::<serde_json::Value>(&token_response.id_token, &decoding_key, &validation) {
            Ok(data) => data.claims,
            Err(error) => return unauthorized(&format!("ID token validation failed: {error}")),
        };

    let email = claims
        .get("email")
        .and_then(serde_json::Value::as_str)
        .map(str::to_ascii_lowercase)
        .filter(|email| is_valid_email(email));
    let Some(email) = email else {
        return unprocessable("ID token did not include a usable email claim");
    };
    // Defense-in-depth: never trust an email an IdP explicitly marks unverified
    // (a tenant-controlled IdP asserting someone else's email). Absent claim is
    // tolerated (many IdPs omit it); an explicit `false` is rejected.
    if claims
        .get("email_verified")
        .and_then(serde_json::Value::as_bool)
        == Some(false)
    {
        return unauthorized("the identity provider reported this email as unverified");
    }
    let display_name = claims
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&email)
        .to_string();
    let groups: Vec<String> = claims
        .get(&config.group_claim)
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    complete_sso_login(
        console,
        &flow.tenant_id,
        &email,
        &display_name,
        &groups,
        &config.group_role_mapping,
        &config.default_role,
    )
}

/// Shared tail of an OIDC or SAML login once a verified `email`, display name,
/// and IdP group list have been established (issue #283). Maps groups to a
/// tenant role, JIT-provisions the admin user + membership on first login
/// (never overwriting a role an owner set later), and issues the same session
/// shape `register`/`login` return.
#[allow(clippy::too_many_arguments)]
fn complete_sso_login(
    console: &AdminConsoleState,
    tenant_id: &str,
    email: &str,
    display_name: &str,
    groups: &[String],
    group_role_mapping: &HashMap<String, String>,
    default_role: &str,
) -> HttpResponse {
    // Resolve the IdP's group claim to a tier. Both the mapping values and
    // `default_role` are validated at config time (issue #517), but a config
    // persisted BEFORE that validator existed can still hold junk -- resolve
    // it to the least privilege rather than storing an unknown role or
    // defaulting up to owner.
    let mapped_role = MembershipRole::from_stored(
        groups
            .iter()
            .find_map(|group| group_role_mapping.get(group).map(String::as_str))
            .unwrap_or(default_role),
    );

    let existing = match block_on_sync_bridge(console.repositories.get_admin_user_by_email(email)) {
        Ok(existing) => existing,
        Err(error) => return storage_error(&error),
    };
    let user = match existing {
        Some(user) => {
            // Cross-tenant account-takeover guard: SSO trust is per-tenant (each
            // tenant owner freely configures its own IdP), but admin accounts
            // are keyed globally by email. Without this check a tenant owner
            // running their own IdP could assert a VICTIM's email and this
            // callback would mint a session/refresh-token bound to the victim's
            // global account. Only allow SSO to sign in a pre-existing account
            // that is ALREADY a member of the flow's tenant (provisioned via
            // the normal invite/team flow); a brand-new email is JIT-created
            // below and belongs only to this tenant.
            if membership_role_in_tenant(console, tenant_id, &user.id).is_none() {
                return unauthorized(
                    "this account is not provisioned for single sign-on in this tenant",
                );
            }
            user
        }
        None => {
            let password_hash = match unusable_password_hash() {
                Ok(hash) => hash,
                Err(error) => return internal_error(&error.to_string()),
            };
            let now = now_unix_seconds() as i64;
            let user = StoredAdminUser {
                id: next_id("user"),
                email: email.to_string(),
                password_hash,
                display_name: display_name.to_string(),
                superadmin: false,
                created_at_unix: now,
                updated_at_unix: now,
                last_login_at_unix: Some(now),
                disabled_at_unix: None,
            };
            if let Err(error) =
                block_on_sync_bridge(console.repositories.upsert_admin_user(user.clone()))
            {
                return storage_error(&error);
            }
            user
        }
    };
    if user.disabled_at_unix.is_some() {
        return unauthorized("this account has been disabled");
    }

    // Only set a role on first join -- never let a later SSO login silently
    // override a role an owner explicitly changed afterward via the
    // team-management API.
    let effective_role = match membership_role_in_tenant(console, tenant_id, &user.id) {
        Some(role) => MembershipRole::from_stored(&role),
        None => {
            let membership = StoredAdminUserMembership {
                id: next_id("membership"),
                user_id: user.id.clone(),
                tenant_id: tenant_id.to_string(),
                role: mapped_role.to_string(),
                created_at_unix: now_unix_seconds() as i64,
            };
            if let Err(error) = block_on_sync_bridge(
                console
                    .repositories
                    .upsert_admin_user_membership(membership),
            ) {
                return storage_error(&error);
            }
            mapped_role
        }
    };

    let tenant_account =
        match block_on_sync_bridge(console.repositories.get_tenant_account(tenant_id)) {
            Ok(Some(account)) => account,
            Ok(None) => return internal_error("tenant account no longer exists"),
            Err(error) => return storage_error(&error),
        };
    let workspace = match resolve_default_workspace(console, tenant_id) {
        Ok(Some(workspace)) => workspace,
        Ok(None) => return internal_error("no workspace found for this tenant"),
        Err(error) => return storage_error(&error),
    };
    // The tier that mints the key is `effective_role` -- the group-mapped /
    // default_role tier resolved above, NOT a fixed grant (issue #517).
    // `group_role_mapping` is how a real tenant assigns `viewer` at scale,
    // so this is the mint site that decides most non-owner sessions'
    // authority. It also revokes this user's prior session keys for the
    // tenant, so a repeated SSO login cannot accumulate keys and an
    // IdP-side demotion (or an owner's change-role) is not outlived by an
    // old key.
    let gateway_api_key = match provision_gateway_api_key(
        console,
        &workspace.id,
        &workspace.project_id,
        tenant_id,
        &user.id,
        effective_role,
    ) {
        Ok(secret) => secret,
        // #514: a suspended/deleted tenancy is a 403 with the gateway's own
        // `tenancy_suspended` code, not a 500 -- and, crucially, not a live
        // `fg_...` secret, which is what this path returned before the gate
        // became reachable from `ferrogate-auth`.
        Err(error) => return error.into_response(),
    };
    match issue_session(console, &user.id, email, tenant_id, effective_role.as_str()) {
        Ok((access_token, refresh_token)) => HttpResponse::json(
            200,
            AdminSessionResponse {
                access_token,
                refresh_token,
                expires_in: ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
                user: AdminUserView {
                    id: user.id,
                    email: email.to_string(),
                    display_name: user.display_name,
                },
                tenant: AdminTenantView {
                    id: tenant_account.id,
                    name: tenant_account.name,
                    role: effective_role.to_string(),
                },
                gateway_api_key,
            },
        ),
        Err(error) => internal_error(&error.to_string()),
    }
}

/// Starts a SAML 2.0 SP-initiated login for `tenant_id` (issue #283) using the
/// HTTP-Redirect binding: build a (deflated, base64, url-encoded)
/// `AuthnRequest`, persist a restart-safe pending flow keyed by an opaque
/// `state` (carried as `RelayState`), and return the IdP redirect URL. Like
/// the OIDC authorize endpoint it is unauthenticated (the browser isn't logged
/// in yet) and returns JSON rather than a 302 so a JSON-only client can drive
/// it too.
pub(crate) fn handle_saml_authorize(console: &AdminConsoleState, tenant_id: &str) -> HttpResponse {
    let Some(stored) = read_stored_sso_config(console, tenant_id) else {
        return not_found("SSO is not configured for this tenant");
    };
    if stored.provider_kind != "saml" {
        return unprocessable(
            "this tenant is not configured for SAML SSO; use the OIDC authorize endpoint",
        );
    }
    let (Some(idp_sso_url), Some(sp_entity_id), Some(acs_url)) = (
        stored.saml_idp_sso_url.clone(),
        stored.saml_sp_entity_id.clone(),
        stored.saml_acs_url.clone(),
    ) else {
        return internal_error("SAML configuration is incomplete");
    };
    let state = match generate_random_hex(24) {
        Ok(state) => state,
        Err(error) => return internal_error(&error.to_string()),
    };
    let request_id = format!(
        "_{}",
        match generate_random_hex(20) {
            Ok(value) => value,
            Err(error) => return internal_error(&error.to_string()),
        }
    );
    let redirect_url = match saml::build_authn_request_redirect(
        &idp_sso_url,
        &acs_url,
        &sp_entity_id,
        &request_id,
        &state,
    ) {
        Ok(url) => url,
        Err(error) => {
            return internal_error(&format!("failed to build SAML AuthnRequest: {error:#}"))
        }
    };
    let now = now_unix_seconds() as i64;
    let flow = StoredSsoPendingFlow {
        state: state.clone(),
        tenant_id: tenant_id.to_string(),
        provider_kind: "saml".into(),
        code_verifier: None,
        request_id: Some(request_id),
        created_at_unix: now,
        expires_at_unix: now + SSO_FLOW_TTL_SECS,
    };
    if let Err(error) = block_on_sync_bridge(console.repositories.insert_sso_pending_flow(flow)) {
        return storage_error(&error);
    }
    HttpResponse::json(
        200,
        json!({ "authorize_url": redirect_url, "state": state }),
    )
}

/// SAML 2.0 assertion consumer service (issue #283). Receives the IdP's signed
/// Response over the HTTP-Redirect binding, and FAILS CLOSED on any of:
/// missing/invalid redirect-binding signature, unknown/expired flow, status !=
/// Success, issuer/audience mismatch, clock-skew-adjusted validity window, or a
/// missing usable email. `raw_query` is the verbatim request query string, used
/// to reconstruct the exact signed octet string.
pub(crate) fn handle_saml_acs(console: &AdminConsoleState, raw_query: &str) -> HttpResponse {
    let params = saml::RedirectBindingParams::parse(raw_query);
    let Some(state) = params
        .relay_state
        .as_deref()
        .filter(|value| !value.is_empty())
    else {
        return unprocessable("missing RelayState");
    };
    let now = now_unix_seconds() as i64;
    let flow = match block_on_sync_bridge(console.repositories.take_sso_pending_flow(state, now)) {
        Ok(flow) => flow,
        Err(error) => return storage_error(&error),
    };
    let Some(flow) = flow else {
        return unauthorized("unknown, expired, or already-used SAML state");
    };
    if flow.provider_kind != "saml" {
        return unprocessable("this pending flow is not a SAML flow");
    }
    let Some(stored) = read_stored_sso_config(console, &flow.tenant_id) else {
        return internal_error("SAML configuration was removed mid-flow");
    };
    if stored.provider_kind != "saml" {
        return internal_error("SSO configuration is no longer SAML");
    }
    let Some(certificate) = stored.saml_idp_certificate.as_deref() else {
        return internal_error("SAML configuration is missing the IdP certificate");
    };
    // 1. Verify the redirect-binding signature over the exact received octets,
    //    against the configured IdP certificate. Fail closed if absent/invalid.
    if let Err(error) = saml::verify_redirect_signature(&params, certificate) {
        return unauthorized(&format!("SAML signature verification failed: {error}"));
    }
    // 2. Inflate + parse the now-authenticated Response.
    let Some(saml_response) = params.saml_response.as_deref() else {
        return unprocessable("missing SAMLResponse");
    };
    let assertion = match saml::parse_and_validate_response(
        saml_response,
        &saml::AssertionExpectations {
            sp_entity_id: stored.saml_sp_entity_id.as_deref().unwrap_or_default(),
            idp_entity_id: stored.saml_idp_entity_id.as_deref(),
            in_response_to: flow.request_id.as_deref(),
            email_attribute: stored.saml_email_attribute.as_deref(),
            name_attribute: stored.saml_name_attribute.as_deref(),
            groups_attribute: stored.saml_groups_attribute.as_deref(),
            now_unix: now,
            clock_skew_secs: SAML_CLOCK_SKEW_SECS,
        },
    ) {
        Ok(assertion) => assertion,
        Err(error) => return unauthorized(&format!("SAML assertion rejected: {error}")),
    };

    let group_role_mapping: HashMap<String, String> =
        stored.group_role_mapping.clone().into_iter().collect();
    complete_sso_login(
        console,
        &flow.tenant_id,
        &assertion.email,
        &assertion.display_name,
        &assertion.groups,
        &group_role_mapping,
        &stored.default_role,
    )
}

/// Permitted clock skew (either direction) when checking SAML assertion
/// `NotBefore`/`NotOnOrAfter` conditions -- IdP and SP clocks are rarely
/// perfectly aligned.
const SAML_CLOCK_SKEW_SECS: i64 = 300;
