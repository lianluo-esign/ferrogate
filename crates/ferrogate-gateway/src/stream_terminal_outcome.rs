// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Typed terminal outcome of a streamed provider response and the
// durable evidence vocabulary it is recorded under (issue #571).

use pingora::{BError, Result as PingoraResult};

/// How one streamed provider response actually ended.
///
/// A streamed answer has no status line of its own: the `200` header is written
/// before the first provider byte arrives, so a stream that dies halfway still
/// looks like a success to anything that only reads `status_code`. This enum is
/// the discriminant that tells the two apart in durable evidence, and it is
/// deliberately split at the **first emitted byte** — the boundary that decides
/// whether the request is still replayable:
///
/// - nothing emitted yet: the client holds no partial answer, so the gateway
///   may still retry the provider or fall back to another route;
/// - bytes already emitted: the client holds a partial answer no retry can take
///   back, so a replay would duplicate every tool call that answer already
///   carried. The gateway does not replay past this point, and the evidence
///   must say the outcome is partial rather than complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum StreamTerminalOutcome {
    /// The provider stream reached EOF and the terminal chunk was flushed to
    /// the client. The only outcome that may be recorded without an error code.
    Completed,
    /// The provider stream failed before any response byte reached the client.
    ProviderFailedBeforeFirstByte,
    /// The provider stream failed after the client had already received bytes.
    /// The delivered answer is partial and the generation's true end state is
    /// unknown to the gateway.
    ProviderFailedAfterFirstByte,
    /// Writing downstream failed before any response byte landed.
    ///
    /// Covers a client that went away mid-header as well as a local failure to
    /// build or write the response header: the gateway cannot tell those apart
    /// from its own side, and the operator-relevant fact — the client holds
    /// nothing — is the same for both.
    DownstreamFailedBeforeFirstByte,
    /// Writing downstream failed after the client had received bytes. Whatever
    /// the provider generated past that point was billed but never delivered.
    DownstreamFailedAfterFirstByte,
}

impl StreamTerminalOutcome {
    /// Frozen wire token for [`Self::Completed`].
    pub(crate) const COMPLETED_TOKEN: &'static str = "stream_completed";
    /// Frozen wire token for [`Self::ProviderFailedBeforeFirstByte`].
    pub(crate) const PROVIDER_FAILED_BEFORE_FIRST_BYTE_TOKEN: &'static str =
        "provider_stream_failed_before_first_byte";
    /// Frozen wire token for [`Self::ProviderFailedAfterFirstByte`].
    pub(crate) const PROVIDER_FAILED_AFTER_FIRST_BYTE_TOKEN: &'static str =
        "provider_stream_failed_after_first_byte";
    /// Frozen wire token for [`Self::DownstreamFailedBeforeFirstByte`].
    pub(crate) const DOWNSTREAM_FAILED_BEFORE_FIRST_BYTE_TOKEN: &'static str =
        "stream_downstream_failed_before_first_byte";
    /// Frozen wire token for [`Self::DownstreamFailedAfterFirstByte`].
    pub(crate) const DOWNSTREAM_FAILED_AFTER_FIRST_BYTE_TOKEN: &'static str =
        "stream_downstream_failed_after_first_byte";

    /// The stable token this outcome is recorded as.
    pub(crate) fn as_wire_token(self) -> &'static str {
        match self {
            Self::Completed => Self::COMPLETED_TOKEN,
            Self::ProviderFailedBeforeFirstByte => Self::PROVIDER_FAILED_BEFORE_FIRST_BYTE_TOKEN,
            Self::ProviderFailedAfterFirstByte => Self::PROVIDER_FAILED_AFTER_FIRST_BYTE_TOKEN,
            Self::DownstreamFailedBeforeFirstByte => {
                Self::DOWNSTREAM_FAILED_BEFORE_FIRST_BYTE_TOKEN
            }
            Self::DownstreamFailedAfterFirstByte => Self::DOWNSTREAM_FAILED_AFTER_FIRST_BYTE_TOKEN,
        }
    }

    /// The `error_code` a request log must carry for this outcome.
    ///
    /// `None` only for [`Self::Completed`]. Every non-completing outcome yields
    /// a non-empty typed code, which is also what makes the request count as an
    /// error on the Admin overview — that surface counts `error_code.is_some()`
    /// rather than the status code, so a stream that broke after its `200`
    /// header is otherwise invisible there.
    pub(crate) fn request_log_error_code(self) -> Option<&'static str> {
        match self {
            Self::Completed => None,
            other => Some(other.as_wire_token()),
        }
    }

    /// Read a non-completing outcome back out of a stored request log's
    /// `error_code`, for the read paths that must not call a broken stream a
    /// success.
    ///
    /// Returns `None` for anything this build does not recognise as one of its
    /// own stream tokens — an absent code, a code from some other failure
    /// vocabulary, or a token from a future producer. `None` therefore means
    /// only "this row says nothing about a stream", never "the stream was
    /// fine": callers decide what an unrecognised code means, and no caller
    /// gets to upgrade an unknown code into [`Self::Completed`], which is
    /// deliberately not producible here.
    pub(crate) fn from_request_log_error_code(error_code: Option<&str>) -> Option<Self> {
        match error_code? {
            Self::PROVIDER_FAILED_BEFORE_FIRST_BYTE_TOKEN => {
                Some(Self::ProviderFailedBeforeFirstByte)
            }
            Self::PROVIDER_FAILED_AFTER_FIRST_BYTE_TOKEN => {
                Some(Self::ProviderFailedAfterFirstByte)
            }
            Self::DOWNSTREAM_FAILED_BEFORE_FIRST_BYTE_TOKEN => {
                Some(Self::DownstreamFailedBeforeFirstByte)
            }
            Self::DOWNSTREAM_FAILED_AFTER_FIRST_BYTE_TOKEN => {
                Some(Self::DownstreamFailedAfterFirstByte)
            }
            _ => None,
        }
    }

    /// Whether the client received any response byte before the stream ended.
    ///
    /// This is the replay boundary: `true` means a retry or fallback would
    /// duplicate an answer the client already partly holds, together with any
    /// tool call that answer already carried.
    pub(crate) fn client_received_bytes(self) -> bool {
        match self {
            Self::Completed
            | Self::ProviderFailedAfterFirstByte
            | Self::DownstreamFailedAfterFirstByte => true,
            Self::ProviderFailedBeforeFirstByte | Self::DownstreamFailedBeforeFirstByte => false,
        }
    }

    /// Whether the delivered answer is known to be complete. Anything else is
    /// partial or unknown and must never be reported as a finished generation.
    pub(crate) fn is_complete(self) -> bool {
        matches!(self, Self::Completed)
    }
}

/// The result of streaming one provider response downstream.
///
/// Both halves are needed at the call site and neither is derivable from the
/// other: `result` is what the Pingora handler must return, while `outcome` is
/// what the evidence chain must record. A broken stream still has usage to
/// settle and a request log to write, so the error cannot be propagated with
/// `?` before that work happens — which is exactly how the terminal evidence
/// came to claim `200` with no error code for streams that never finished.
pub(crate) struct StreamedResponse {
    /// The typed terminal state, for durable evidence.
    pub(crate) outcome: StreamTerminalOutcome,
    /// The value the handler returns to Pingora.
    pub(crate) result: PingoraResult<()>,
}

impl StreamedResponse {
    /// A stream that ran to completion.
    pub(crate) fn completed() -> Self {
        Self {
            outcome: StreamTerminalOutcome::Completed,
            result: Ok(()),
        }
    }

    /// A stream the provider side broke, classified by whether the client had
    /// already been given bytes.
    pub(crate) fn provider_failed(bytes_emitted: u64, error: BError) -> Self {
        Self {
            outcome: if bytes_emitted > 0 {
                StreamTerminalOutcome::ProviderFailedAfterFirstByte
            } else {
                StreamTerminalOutcome::ProviderFailedBeforeFirstByte
            },
            result: Err(error),
        }
    }

    /// A stream whose downstream write failed, classified the same way.
    pub(crate) fn downstream_failed(bytes_emitted: u64, error: BError) -> Self {
        Self {
            outcome: if bytes_emitted > 0 {
                StreamTerminalOutcome::DownstreamFailedAfterFirstByte
            } else {
                StreamTerminalOutcome::DownstreamFailedBeforeFirstByte
            },
            result: Err(error),
        }
    }
}

#[cfg(test)]
#[path = "stream_terminal_outcome_test.rs"]
mod stream_terminal_outcome_test;
