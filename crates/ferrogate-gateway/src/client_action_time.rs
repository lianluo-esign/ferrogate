// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Server authority for short-lived client action time tokens (#548).

use std::{fmt, sync::Arc, time::SystemTime};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use http::{HeaderMap, StatusCode};
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

type HmacSha256 = Hmac<Sha256>;

/// Process-lifetime authority for action-bound time tokens.
///
/// The key is generated once in [`crate::state::SharedAppState`] and is never
/// exposed through `Debug`. Tokens therefore survive hot config reloads but,
/// deliberately, not a process restart.
pub(crate) struct ServerTimeTokenSigner {
    key: [u8; SIGNING_KEY_BYTES],
    ttl_seconds: u64,
}

impl fmt::Debug for ServerTimeTokenSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerTimeTokenSigner")
            .field("key", &"[REDACTED]")
            .field("ttl_seconds", &self.ttl_seconds)
            .finish()
    }
}

impl ServerTimeTokenSigner {
    pub(crate) fn generate() -> anyhow::Result<Self> {
        let mut key = [0_u8; SIGNING_KEY_BYTES];
        getrandom::getrandom(&mut key).map_err(|error| {
            anyhow::anyhow!(
                "could not initialize client action time-token signing: OS random source is unavailable ({error})"
            )
        })?;
        Ok(Self {
            key,
            ttl_seconds: TOKEN_TTL_SECONDS,
        })
    }

    #[cfg(test)]
    fn fixture() -> Self {
        Self {
            key: [0x5a; SIGNING_KEY_BYTES],
            ttl_seconds: TOKEN_TTL_SECONDS,
        }
    }

    fn issue(&self, action_id: &str, issued_at_unix: u64) -> String {
        let payload = format!(
            "{TOKEN_VERSION};issued_at={issued_at_unix};ttl={};action_id={action_id}",
            self.ttl_seconds
        );
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .expect("HMAC-SHA256 accepts a fixed 32-byte signing key");
        mac.update(payload.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{payload};sig={signature}")
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
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .expect("HMAC-SHA256 accepts a fixed 32-byte signing key");
        mac.update(payload.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| ClientActionTimeError::invalid("time token signature is invalid"))?;

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

    fn inspect_request_at(&mut self, headers: &HeaderMap, received_at_unix: u64) {
        self.request_error = self.inspect_request_inner(headers, received_at_unix).err();
    }

    fn inspect_request_inner(
        &mut self,
        headers: &HeaderMap,
        received_at_unix: u64,
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
        self.response_action_id = Some(action_id.to_string());
        if let Some(token) = token {
            self.signer.validate(token, action_id, received_at_unix)?;
        }
        Ok(())
    }

    fn issue_response_at(
        &self,
        response: &mut ResponseHeader,
        issued_at_unix: u64,
    ) -> PingoraResult<()> {
        if let Some(action_id) = self.response_action_id.as_deref() {
            response.insert_header(
                TIME_TOKEN_HEADER,
                self.signer.issue(action_id, issued_at_unix),
            )?;
        }
        Ok(())
    }
}

#[async_trait]
impl HttpModule for ClientActionTimeModule {
    async fn request_header_filter(&mut self, request: &mut RequestHeader) -> PingoraResult<()> {
        match server_unix_seconds() {
            Ok(received_at_unix) => self.inspect_request_at(&request.headers, received_at_unix),
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
