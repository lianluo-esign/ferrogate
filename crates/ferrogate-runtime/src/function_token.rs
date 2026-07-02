// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Short-lived, scoped HS256 JWT minting for edge-function auth (#118).
//!
//! Instead of handing a static Supabase service-role key to workers, the gateway
//! mints a per-call JWT scoped to one tenant + function + capability with a small
//! TTL, signed HS256 with the project's JWT secret. Supabase verifies it and the
//! edge function can re-check the claims. The signing secret never leaves the
//! gateway; a leaked token authorizes at most one function for a few seconds.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Maximum TTL a scoped function token may be minted for.
pub const MAX_FUNCTION_TOKEN_TTL_SECS: u64 = 300;
/// Default TTL when the caller does not specify one.
pub const DEFAULT_FUNCTION_TOKEN_TTL_SECS: u64 = 60;

/// Claims embedded in a scoped function token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionTokenClaims {
    /// Issuer, e.g. `ferrogate`.
    pub iss: String,
    /// Audience — the function slug this token may invoke.
    pub aud: String,
    /// Tenant the call is attributed to.
    pub tenant: String,
    /// Capability the call exercises (for edge-function-side authorization).
    pub capability: String,
    /// Issued-at (unix seconds).
    pub iat: u64,
    /// Expiry (unix seconds).
    pub exp: u64,
}

/// Errors from minting or verifying a scoped function token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionTokenError {
    EmptySigningSecret,
    EmptyField(&'static str),
    ZeroTtl,
    Encoding(String),
    MalformedToken,
    BadSignature,
    Expired,
}

impl std::fmt::Display for FunctionTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySigningSecret => {
                write!(f, "function token signing secret must not be empty")
            }
            Self::EmptyField(field) => write!(f, "function token field {field} must not be empty"),
            Self::ZeroTtl => write!(f, "function token ttl must be greater than zero"),
            Self::Encoding(message) => write!(f, "function token encoding failed: {message}"),
            Self::MalformedToken => write!(f, "function token is malformed"),
            Self::BadSignature => write!(f, "function token signature is invalid"),
            Self::Expired => write!(f, "function token has expired"),
        }
    }
}

impl std::error::Error for FunctionTokenError {}

const HS256_HEADER_JSON: &str = r#"{"alg":"HS256","typ":"JWT"}"#;

/// Mints scoped HS256 function tokens signed with a project's JWT secret.
#[derive(Clone)]
pub struct FunctionTokenMinter {
    issuer: String,
    signing_secret: Vec<u8>,
}

impl std::fmt::Debug for FunctionTokenMinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the signing secret.
        f.debug_struct("FunctionTokenMinter")
            .field("issuer", &self.issuer)
            .field("signing_secret", &"<redacted>")
            .finish()
    }
}

impl FunctionTokenMinter {
    pub fn new(
        issuer: impl Into<String>,
        signing_secret: impl Into<String>,
    ) -> Result<Self, FunctionTokenError> {
        let issuer = issuer.into();
        let signing_secret = signing_secret.into();
        if issuer.trim().is_empty() {
            return Err(FunctionTokenError::EmptyField("iss"));
        }
        if signing_secret.trim().is_empty() {
            return Err(FunctionTokenError::EmptySigningSecret);
        }
        Ok(Self {
            issuer,
            signing_secret: signing_secret.into_bytes(),
        })
    }

    /// Mint a token scoped to `function_slug` + `tenant` + `capability`, valid
    /// from `now_unix` for `ttl_secs` (clamped to [1, MAX]).
    pub fn mint(
        &self,
        tenant: &str,
        function_slug: &str,
        capability: &str,
        now_unix: u64,
        ttl_secs: u64,
    ) -> Result<String, FunctionTokenError> {
        if tenant.trim().is_empty() {
            return Err(FunctionTokenError::EmptyField("tenant"));
        }
        if function_slug.trim().is_empty() {
            return Err(FunctionTokenError::EmptyField("aud"));
        }
        if capability.trim().is_empty() {
            return Err(FunctionTokenError::EmptyField("capability"));
        }
        if ttl_secs == 0 {
            return Err(FunctionTokenError::ZeroTtl);
        }
        let ttl = ttl_secs.min(MAX_FUNCTION_TOKEN_TTL_SECS);
        let claims = FunctionTokenClaims {
            iss: self.issuer.clone(),
            aud: function_slug.to_string(),
            tenant: tenant.to_string(),
            capability: capability.to_string(),
            iat: now_unix,
            exp: now_unix.saturating_add(ttl),
        };
        let claims_json = serde_json::to_string(&claims)
            .map_err(|error| FunctionTokenError::Encoding(error.to_string()))?;
        let signing_input = format!(
            "{}.{}",
            B64URL.encode(HS256_HEADER_JSON.as_bytes()),
            B64URL.encode(claims_json.as_bytes())
        );
        let signature = self.sign(signing_input.as_bytes());
        Ok(format!("{signing_input}.{}", B64URL.encode(signature)))
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.signing_secret)
            .expect("HMAC accepts keys of any length");
        mac.update(message);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify a token against this minter's secret and `now_unix`, returning the
    /// claims. Signature is checked in constant time; expiry is enforced.
    pub fn verify(
        &self,
        token: &str,
        now_unix: u64,
    ) -> Result<FunctionTokenClaims, FunctionTokenError> {
        let mut parts = token.split('.');
        let header_b64 = parts.next().ok_or(FunctionTokenError::MalformedToken)?;
        let claims_b64 = parts.next().ok_or(FunctionTokenError::MalformedToken)?;
        let sig_b64 = parts.next().ok_or(FunctionTokenError::MalformedToken)?;
        if parts.next().is_some() {
            return Err(FunctionTokenError::MalformedToken);
        }

        let signing_input = format!("{header_b64}.{claims_b64}");
        let expected = self.sign(signing_input.as_bytes());
        let presented = B64URL
            .decode(sig_b64)
            .map_err(|_| FunctionTokenError::MalformedToken)?;
        if expected.len() != presented.len() || expected.ct_eq(&presented).unwrap_u8() != 1 {
            return Err(FunctionTokenError::BadSignature);
        }

        let claims_json = B64URL
            .decode(claims_b64)
            .map_err(|_| FunctionTokenError::MalformedToken)?;
        let claims: FunctionTokenClaims =
            serde_json::from_slice(&claims_json).map_err(|_| FunctionTokenError::MalformedToken)?;
        if now_unix >= claims.exp {
            return Err(FunctionTokenError::Expired);
        }
        Ok(claims)
    }
}

#[cfg(test)]
#[path = "function_token_test.rs"]
mod function_token_test;
