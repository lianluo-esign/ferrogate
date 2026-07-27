// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Structured client errors and stable exit-code classes (issue #360).
//!
//! The client maps every failure onto one of a small, stable set of
//! [`ExitClass`] values so scripts can branch on *why* a command failed
//! without parsing English text. HTTP status codes and the server's
//! `ferrogate_error` envelope are folded into the same classification, so a
//! `401` from the Control Plane API and a locally-detected missing credential
//! both surface as [`ExitClass::Auth`].

use std::fmt;

/// Stable process exit-code classes.
///
/// The numeric values are a versioned product contract: later resource
/// commands (#361–#365) map their failures onto these classes, and the exit
/// codes must not be renumbered without a compatibility note. The layout
/// deliberately mirrors the failure taxonomy in the issue: usage/config, auth,
/// not-found/conflict, validation, transport/timeout, and server failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExitClass {
    /// Everything succeeded.
    Success,
    /// Caller-side misuse: bad flags, unknown command, or invalid local
    /// configuration/context.
    Usage,
    /// Authentication or authorization failure (missing/invalid credential,
    /// insufficient scope, wrong tenant).
    Auth,
    /// The addressed resource does not exist, or the mutation conflicts with
    /// current state.
    NotFoundConflict,
    /// The request reached the server but was rejected as invalid.
    Validation,
    /// The request never produced an authoritative server answer: connection
    /// failure, timeout, TLS failure, or a retryable throttle.
    Transport,
    /// The server accepted the request but failed to process it.
    Server,
}

impl ExitClass {
    /// The stable process exit code for this class.
    pub fn code(self) -> i32 {
        match self {
            ExitClass::Success => 0,
            ExitClass::Usage => 2,
            ExitClass::Auth => 3,
            ExitClass::NotFoundConflict => 4,
            ExitClass::Validation => 5,
            ExitClass::Transport => 6,
            ExitClass::Server => 7,
        }
    }

    /// Classify an HTTP status returned by the Control Plane API.
    ///
    /// Only the status is consulted here; the richer [`ApiError`] carries the
    /// server's own error `code`, which callers may use for finer messaging
    /// but never to override the exit class (the class is what scripts depend
    /// on).
    pub fn from_http_status(status: u16) -> ExitClass {
        match status {
            200..=299 => ExitClass::Success,
            401 | 403 => ExitClass::Auth,
            404 | 409 | 410 => ExitClass::NotFoundConflict,
            408 | 425 | 429 => ExitClass::Transport,
            400 | 422 => ExitClass::Validation,
            // Any other client error is a validation/usage-class rejection
            // from the server's perspective.
            402 | 405..=499 => ExitClass::Validation,
            500..=599 => ExitClass::Server,
            // Sub-200 informational codes are never a terminal client result;
            // treat an unexpected one as a transport-level surprise rather
            // than silently succeeding.
            _ => ExitClass::Transport,
        }
    }
}

/// The server's `ferrogate_error` envelope, decoded into typed fields.
///
/// Mirrors `components.schemas.ErrorResponse` in the enforced OpenAPI contract
/// (`error.{message,type,code,request_id}`). `details` preserves any
/// additional structured payload the server attached without forcing the
/// foundation to model every resource-specific error schema up front — #365
/// can tighten this against the generated contract.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiError {
    /// HTTP status the response carried.
    pub http_status: u16,
    /// Stable machine error code (e.g. `asset_not_found`).
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Correlation id echoed for support/audit (`x-request-id` header or the
    /// `request_id` envelope field).
    pub request_id: Option<String>,
    /// Distributed trace id (`x-trace-id` header) when present.
    pub trace_id: Option<String>,
    /// Retry hint in seconds parsed from a `Retry-After` header, when present.
    pub retry_after_secs: Option<u64>,
    /// Any remaining structured error payload the server returned.
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    /// The exit class implied by the HTTP status.
    pub fn exit_class(&self) -> ExitClass {
        ExitClass::from_http_status(self.http_status)
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "control-plane API error {} ({}): {}",
            self.http_status, self.code, self.message
        )?;
        if let Some(request_id) = &self.request_id {
            write!(f, " [request_id={request_id}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

/// The top-level client error type. Every variant carries enough context to
/// render a faithful diagnostic to stderr and to pick a stable [`ExitClass`].
#[derive(Debug)]
pub enum CliError {
    /// Caller-side misuse or invalid local configuration/context.
    Usage(String),
    /// A credential could not be resolved or was rejected before any request.
    Auth(String),
    /// The transport failed to obtain an authoritative answer (connect,
    /// timeout, TLS, decode).
    Transport(String),
    /// The server returned a structured error envelope. Boxed to keep
    /// `CliError` (and thus every `CliResult`) small.
    Api(Box<ApiError>),
}

impl CliError {
    /// The stable exit class for this error.
    pub fn exit_class(&self) -> ExitClass {
        match self {
            CliError::Usage(_) => ExitClass::Usage,
            CliError::Auth(_) => ExitClass::Auth,
            CliError::Transport(_) => ExitClass::Transport,
            CliError::Api(error) => error.exit_class(),
        }
    }

    /// Convenience for constructing a usage error from anything displayable.
    pub fn usage(message: impl Into<String>) -> CliError {
        CliError::Usage(message.into())
    }

    /// Convenience for constructing an auth error.
    pub fn auth(message: impl Into<String>) -> CliError {
        CliError::Auth(message.into())
    }

    /// Convenience for constructing a transport error.
    pub fn transport(message: impl Into<String>) -> CliError {
        CliError::Transport(message.into())
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Usage(message) => write!(f, "{message}"),
            CliError::Auth(message) => write!(f, "{message}"),
            CliError::Transport(message) => write!(f, "{message}"),
            CliError::Api(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<ApiError> for CliError {
    fn from(error: ApiError) -> Self {
        CliError::Api(Box::new(error))
    }
}

/// Convenience alias for client results.
pub type CliResult<T> = Result<T, CliError>;

#[cfg(test)]
#[path = "error_test.rs"]
mod error_test;
