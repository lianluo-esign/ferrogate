// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Server authority for short-lived client action time tokens (#548).

use std::{fmt, sync::Arc, time::SystemTime};

use async_trait::async_trait;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use ferrogate_control_plane_client::action_identity::ACTION_TIME_PREFLIGHT_PATH;
use hmac::{Hmac, Mac};
use http::{HeaderMap, Method, StatusCode};
use pingora::{
    http::{RequestHeader, ResponseHeader},
    modules::http::{HttpModule, HttpModuleBuilder, Module},
    Error, ErrorType, Result as PingoraResult,
};
use sha2::Sha256;

pub(crate) const ACTION_ID_HEADER: &str = "x-ferrogate-action-id";
pub(crate) const TIME_TOKEN_HEADER: &str = "x-ferrogate-time-token";
const TOKEN_VERSION: &str = "v1";
const ACTION_ID_PREFIX: &str = "fgact_";
const ACTION_ID_HEX_LEN: usize = 32;
const TOKEN_TTL_SECONDS: u64 = 30;
const SIGNING_KEY_BYTES: usize = 32;
const MAX_TOKEN_TTL_SECONDS: u64 = 60;
const SIGNING_KEY_ENV: &str = "FERROGATE_CLIENT_ACTION_TIME_SIGNING_KEY";
const TRUSTED_KEYS_ENV: &str = "FERROGATE_CLIENT_ACTION_TIME_TRUSTED_KEYS";
const TOKEN_TTL_ENV: &str = "FERROGATE_CLIENT_ACTION_TIME_TTL_SECONDS";

type HmacSha256 = Hmac<Sha256>;

/// Deployment authority for action-bound time tokens.
///
/// The active key and optional previous verification keys come from deployment
/// environment variables. Replicas configured with the same keyring can verify
/// one another's tokens; keeping the old key in the trusted list during a
/// rolling rotation preserves in-flight tokens until their short TTL expires.
pub(crate) struct ServerTimeTokenSigner {
    signing_key: Option<[u8; SIGNING_KEY_BYTES]>,
    verification_keys: Vec<[u8; SIGNING_KEY_BYTES]>,
    ttl_seconds: u64,
}

impl fmt::Debug for ServerTimeTokenSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerTimeTokenSigner")
            .field("signing_key", &"[REDACTED]")
            .field("verification_key_count", &self.verification_keys.len())
            .field("ttl_seconds", &self.ttl_seconds)
            .finish()
    }
}

impl ServerTimeTokenSigner {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        let ttl_seconds = match std::env::var(TOKEN_TTL_ENV) {
            Ok(raw) => raw.trim().parse::<u64>().map_err(|_| {
                anyhow::anyhow!(
                    "{TOKEN_TTL_ENV} must be an integer between 1 and {MAX_TOKEN_TTL_SECONDS}"
                )
            })?,
            Err(std::env::VarError::NotPresent) => TOKEN_TTL_SECONDS,
            Err(error) => return Err(anyhow::anyhow!("failed to read {TOKEN_TTL_ENV}: {error}")),
        };
        if !(1..=MAX_TOKEN_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(anyhow::anyhow!(
                "{TOKEN_TTL_ENV} must be between 1 and {MAX_TOKEN_TTL_SECONDS} seconds"
            ));
        }

        let signing_key = match std::env::var(SIGNING_KEY_ENV) {
            Ok(raw) if !raw.trim().is_empty() => Some(decode_authority_key(&raw, SIGNING_KEY_ENV)?),
            Ok(_) | Err(std::env::VarError::NotPresent) => None,
            Err(error) => return Err(anyhow::anyhow!("failed to read {SIGNING_KEY_ENV}: {error}")),
        };
        let trusted_raw = match std::env::var(TRUSTED_KEYS_ENV) {
            Ok(raw) => Some(raw),
            Err(std::env::VarError::NotPresent) => None,
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "failed to read {TRUSTED_KEYS_ENV}: {error}"
                ))
            }
        };
        if signing_key.is_none()
            && trusted_raw
                .as_deref()
                .is_some_and(|raw| !raw.trim().is_empty())
        {
            return Err(anyhow::anyhow!(
                "{TRUSTED_KEYS_ENV} is set but {SIGNING_KEY_ENV} is absent; a serving node must be able to issue challenge tokens"
            ));
        }

        let mut verification_keys = signing_key.iter().copied().collect::<Vec<_>>();
        if let Some(raw) = trusted_raw.filter(|raw| !raw.trim().is_empty()) {
            for (index, encoded) in raw.split(',').enumerate() {
                if encoded.trim().is_empty() {
                    return Err(anyhow::anyhow!("{TRUSTED_KEYS_ENV} entry {index} is empty"));
                }
                let key = decode_authority_key(
                    encoded,
                    "FERROGATE_CLIENT_ACTION_TIME_TRUSTED_KEYS entry",
                )?;
                if !verification_keys.contains(&key) {
                    verification_keys.push(key);
                }
            }
        }

        Ok(Self {
            signing_key,
            verification_keys,
            ttl_seconds,
        })
    }

    #[cfg(test)]
    fn fixture() -> Self {
        Self {
            signing_key: Some([0x5a; SIGNING_KEY_BYTES]),
            verification_keys: vec![[0x5a; SIGNING_KEY_BYTES]],
            ttl_seconds: TOKEN_TTL_SECONDS,
        }
    }

    fn ensure_available(&self) -> Result<(), ClientActionTimeError> {
        if self.signing_key.is_none() || self.verification_keys.is_empty() {
            return Err(ClientActionTimeError::unavailable(format!(
                "client action time authority is not configured; set {SIGNING_KEY_ENV} to the same base64-encoded 32-byte key on every replica"
            )));
        }
        Ok(())
    }

    pub(crate) fn is_configured(&self) -> bool {
        self.signing_key.is_some() && !self.verification_keys.is_empty()
    }

    fn try_issue(
        &self,
        action_id: &str,
        issued_at_unix: u64,
    ) -> Result<String, ClientActionTimeError> {
        let key = self.signing_key.as_ref().ok_or_else(|| {
            ClientActionTimeError::unavailable("client action time signing key is unavailable")
        })?;
        let payload = format!(
            "{TOKEN_VERSION};issued_at={issued_at_unix};ttl={};action_id={action_id}",
            self.ttl_seconds
        );
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC-SHA256 accepts a fixed 32-byte signing key");
        mac.update(payload.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        Ok(format!("{payload};sig={signature}"))
    }

    #[cfg(test)]
    fn issue(&self, action_id: &str, issued_at_unix: u64) -> String {
        self.try_issue(action_id, issued_at_unix)
            .expect("a token is issued only after the deployment authority is validated")
    }

    fn validate(
        &self,
        raw: &str,
        presented_action_id: &str,
        received_at_unix: u64,
    ) -> Result<(), ClientActionTimeError> {
        let (payload, encoded_signature) = raw
            .rsplit_once(";sig=")
            .filter(|(_, signature)| !signature.is_empty() && !signature.contains(';'))
            .ok_or_else(|| ClientActionTimeError::invalid("time token has no terminal sig"))?;
        let signature = URL_SAFE_NO_PAD
            .decode(encoded_signature)
            .map_err(|_| ClientActionTimeError::invalid("time token signature is not base64url"))?;
        self.ensure_available()?;
        let signature_valid = self.verification_keys.iter().any(|key| {
            let mut mac = HmacSha256::new_from_slice(key)
                .expect("HMAC-SHA256 accepts a fixed 32-byte signing key");
            mac.update(payload.as_bytes());
            mac.verify_slice(&signature).is_ok()
        });
        if !signature_valid {
            return Err(ClientActionTimeError::invalid(
                "time token signature is invalid",
            ));
        }

        let mut segments = payload.split(';');
        if segments.next() != Some(TOKEN_VERSION) {
            return Err(ClientActionTimeError::invalid(
                "time token schema version is unsupported",
            ));
        }
        let mut issued_at = None;
        let mut ttl = None;
        let mut action_id = None;
        for segment in segments {
            let Some((name, value)) = segment.split_once('=') else {
                return Err(ClientActionTimeError::invalid(
                    "time token contains a malformed segment",
                ));
            };
            match name {
                "issued_at" if issued_at.is_none() => issued_at = value.parse::<u64>().ok(),
                "ttl" if ttl.is_none() => ttl = value.parse::<u64>().ok(),
                "action_id" if action_id.is_none() => action_id = Some(value),
                "issued_at" | "ttl" | "action_id" => {
                    return Err(ClientActionTimeError::invalid(
                        "time token contains a duplicate required field",
                    ));
                }
                _ => {}
            }
        }
        let issued_at = issued_at.ok_or_else(|| {
            ClientActionTimeError::invalid("time token issued_at is missing or non-numeric")
        })?;
        let ttl = ttl.ok_or_else(|| {
            ClientActionTimeError::invalid("time token ttl is missing or non-numeric")
        })?;
        let action_id = action_id
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ClientActionTimeError::invalid("time token action_id is missing"))?;

        if action_id != presented_action_id {
            return Err(ClientActionTimeError::invalid(
                "time token is bound to a different action id",
            ));
        }
        if received_at_unix < issued_at || received_at_unix > issued_at.saturating_add(ttl) {
            return Err(ClientActionTimeError::invalid(
                "time token is outside its server-authoritative TTL",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientActionTimeError {
    InvalidRequest(String),
    ServerClock(String),
}

impl ClientActionTimeError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidRequest(message.into())
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self::ServerClock(message.into())
    }

    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::ServerClock(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_client_action_time_token",
            Self::ServerClock(_) => "client_action_time_unavailable",
        }
    }
}

impl fmt::Display for ClientActionTimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) | Self::ServerClock(message) => {
                formatter.write_str(message)
            }
        }
    }
}

fn server_unix_seconds() -> Result<u64, ClientActionTimeError> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|error| {
            ClientActionTimeError::ServerClock(format!(
                "server clock is before the Unix epoch; refusing to mint or validate an authoritative time token ({error})"
            ))
        })
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<Option<&'a str>, ClientActionTimeError> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ClientActionTimeError::invalid(format!(
            "request carries more than one {name} header"
        )));
    }
    first
        .to_str()
        .map(Some)
        .map_err(|_| ClientActionTimeError::invalid(format!("{name} is not valid ASCII")))
}

fn is_well_formed_action_id(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(ACTION_ID_PREFIX) else {
        return false;
    };
    hex.len() == ACTION_ID_HEX_LEN
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Per-request downstream hook. Request validation uses the server receive
/// clock; response issuance reads the server clock again at the actual header
/// write. The client-reported clock header is intentionally never read here.
pub(crate) struct ClientActionTimeModule {
    signer: Arc<ServerTimeTokenSigner>,
    response_action_id: Option<String>,
    request_error: Option<ClientActionTimeError>,
}

impl ClientActionTimeModule {
    fn new(signer: Arc<ServerTimeTokenSigner>) -> Self {
        Self {
            signer,
            response_action_id: None,
            request_error: None,
        }
    }

    pub(crate) fn request_error(&self) -> Option<ClientActionTimeError> {
        self.request_error.clone()
    }

    #[cfg(test)]
    fn inspect_request_at(&mut self, headers: &HeaderMap, received_at_unix: u64) {
        self.request_error = self
            .inspect_request_inner(headers, received_at_unix, false)
            .err();
    }

    fn inspect_request_inner(
        &mut self,
        headers: &HeaderMap,
        received_at_unix: u64,
        allow_missing_token: bool,
    ) -> Result<(), ClientActionTimeError> {
        let action_id = single_header(headers, ACTION_ID_HEADER)?;
        let token = single_header(headers, TIME_TOKEN_HEADER)?;
        let Some(action_id) = action_id else {
            if token.is_some() {
                return Err(ClientActionTimeError::invalid(
                    "time token was presented without an action id",
                ));
            }
            return Ok(());
        };
        if !is_well_formed_action_id(action_id) {
            return Err(ClientActionTimeError::invalid(
                "action id does not match the fgact_<128-bit lowercase hex> wire format",
            ));
        }
        self.signer.ensure_available()?;
        match token {
            Some(token) => self.signer.validate(token, action_id, received_at_unix)?,
            None if !allow_missing_token => {
                return Err(ClientActionTimeError::invalid(format!(
                    "{TIME_TOKEN_HEADER} is required when {ACTION_ID_HEADER} is present; obtain one from the safe GET {ACTION_TIME_PREFLIGHT_PATH} challenge before sending the API request"
                )))
            }
            None => {}
        }
        // Only a valid echo or the explicit safe challenge may mint the next
        // token. Setting this before validation lets a rejected effect request
        // bootstrap from its own 400 response, bypassing the health-only rule.
        self.response_action_id = Some(action_id.to_string());
        Ok(())
    }

    fn issue_response_at(
        &self,
        response: &mut ResponseHeader,
        issued_at_unix: u64,
    ) -> PingoraResult<()> {
        if let Some(action_id) = self.response_action_id.as_deref() {
            let token = self
                .signer
                .try_issue(action_id, issued_at_unix)
                .map_err(|error| {
                    Error::because(
                        ErrorType::InternalError,
                        "failed to mint client action time token",
                        std::io::Error::other(error.to_string()),
                    )
                })?;
            response.insert_header(TIME_TOKEN_HEADER, token)?;
        }
        Ok(())
    }
}

fn decode_authority_key(
    raw: &str,
    source: &'static str,
) -> anyhow::Result<[u8; SIGNING_KEY_BYTES]> {
    let decoded = STANDARD
        .decode(raw.trim().as_bytes())
        .map_err(|_| anyhow::anyhow!("{source} must be standard base64"))?;
    decoded.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "{source} must decode to exactly {SIGNING_KEY_BYTES} bytes (got {})",
            decoded.len()
        )
    })
}

#[async_trait]
impl HttpModule for ClientActionTimeModule {
    async fn request_header_filter(&mut self, request: &mut RequestHeader) -> PingoraResult<()> {
        match server_unix_seconds() {
            Ok(received_at_unix) => {
                let allow_missing_token = request.method == Method::GET
                    && request.uri.path().ends_with(ACTION_TIME_PREFLIGHT_PATH);
                self.request_error = self
                    .inspect_request_inner(&request.headers, received_at_unix, allow_missing_token)
                    .err();
            }
            Err(error) => self.request_error = Some(error),
        }
        Ok(())
    }

    async fn response_header_filter(
        &mut self,
        response: &mut ResponseHeader,
        _end_of_stream: bool,
    ) -> PingoraResult<()> {
        if self.response_action_id.is_none() {
            return Ok(());
        }
        let issued_at_unix = server_unix_seconds().map_err(|error| {
            Error::because(
                ErrorType::InternalError,
                "failed to mint client action time token",
                std::io::Error::other(error.to_string()),
            )
        })?;
        self.issue_response_at(response, issued_at_unix)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

pub(crate) struct ClientActionTimeModuleBuilder {
    signer: Arc<ServerTimeTokenSigner>,
}

impl ClientActionTimeModuleBuilder {
    pub(crate) fn new(signer: Arc<ServerTimeTokenSigner>) -> Box<Self> {
        Box::new(Self { signer })
    }
}

impl HttpModuleBuilder for ClientActionTimeModuleBuilder {
    fn init(&self) -> Module {
        Box::new(ClientActionTimeModule::new(Arc::clone(&self.signer)))
    }
}

#[cfg(test)]
#[path = "client_action_time_test.rs"]
mod client_action_time_test;
