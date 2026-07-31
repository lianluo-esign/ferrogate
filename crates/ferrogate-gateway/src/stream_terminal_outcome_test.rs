// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Focused terminal-outcome evidence invariants for streamed
// provider responses (#571).

use super::*;
use pingora::{Error as PingoraError, ErrorType};

const ALL: [StreamTerminalOutcome; 5] = [
    StreamTerminalOutcome::Completed,
    StreamTerminalOutcome::ProviderFailedBeforeFirstByte,
    StreamTerminalOutcome::ProviderFailedAfterFirstByte,
    StreamTerminalOutcome::DownstreamFailedBeforeFirstByte,
    StreamTerminalOutcome::DownstreamFailedAfterFirstByte,
];

fn read_error() -> BError {
    PingoraError::explain(ErrorType::ReadError, "provider stream broke")
}

#[test]
fn only_a_completed_stream_may_be_recorded_without_an_error_code() {
    for outcome in ALL {
        let code = outcome.request_log_error_code();
        if outcome == StreamTerminalOutcome::Completed {
            assert_eq!(code, None, "{outcome:?} must record no error code");
        } else {
            // Blanking any of these is exactly the mutation this pins: an
            // unfinished stream that carries no code is invisible in the Admin
            // overview, which counts `error_code.is_some()`.
            let code = code.unwrap_or_else(|| panic!("{outcome:?} must record an error code"));
            assert!(
                !code.is_empty(),
                "{outcome:?} must not record an empty code"
            );
            assert_eq!(code, outcome.as_wire_token());
        }
    }
}

#[test]
fn every_outcome_has_a_distinct_frozen_token() {
    let mut tokens: Vec<&'static str> = ALL.iter().map(|outcome| outcome.as_wire_token()).collect();
    tokens.sort_unstable();
    let distinct = tokens.len();
    tokens.dedup();
    assert_eq!(
        tokens.len(),
        distinct,
        "collapsing two outcomes onto one token loses the distinction the evidence exists for"
    );
    assert_eq!(
        StreamTerminalOutcome::ProviderFailedAfterFirstByte.as_wire_token(),
        "provider_stream_failed_after_first_byte"
    );
    assert_eq!(
        StreamTerminalOutcome::DownstreamFailedAfterFirstByte.as_wire_token(),
        "stream_downstream_failed_after_first_byte"
    );
}

#[test]
fn a_recorded_code_round_trips_back_to_the_outcome_that_wrote_it() {
    for outcome in ALL {
        let recovered =
            StreamTerminalOutcome::from_request_log_error_code(outcome.request_log_error_code());
        if outcome == StreamTerminalOutcome::Completed {
            assert_eq!(recovered, None, "a completed stream writes no code to read");
        } else {
            assert_eq!(recovered, Some(outcome));
        }
    }
}

#[test]
fn an_unrecognised_code_is_never_promoted_to_a_stream_verdict() {
    // Nothing here may come back as `Completed`: a read path that cannot
    // recognise a code must not be able to conclude the stream was fine.
    for code in [
        None,
        Some(""),
        Some("rate_limit_exceeded"),
        Some("provider_dispatch_error"),
        Some(StreamTerminalOutcome::COMPLETED_TOKEN),
        Some("PROVIDER_STREAM_FAILED_AFTER_FIRST_BYTE"),
        Some(" provider_stream_failed_after_first_byte "),
        Some("some_future_stream_outcome"),
    ] {
        assert_eq!(
            StreamTerminalOutcome::from_request_log_error_code(code),
            None,
            "{code:?} must not be read as a stream verdict"
        );
    }
}

#[test]
fn the_first_byte_boundary_is_what_separates_the_failure_pairs() {
    assert!(!StreamTerminalOutcome::ProviderFailedBeforeFirstByte.client_received_bytes());
    assert!(StreamTerminalOutcome::ProviderFailedAfterFirstByte.client_received_bytes());
    assert!(!StreamTerminalOutcome::DownstreamFailedBeforeFirstByte.client_received_bytes());
    assert!(StreamTerminalOutcome::DownstreamFailedAfterFirstByte.client_received_bytes());
}

#[test]
fn no_failed_stream_reports_a_complete_generation() {
    for outcome in ALL {
        assert_eq!(
            outcome.is_complete(),
            outcome == StreamTerminalOutcome::Completed,
            "{outcome:?} must not claim the generation finished"
        );
    }
}

#[test]
fn a_failure_with_bytes_already_emitted_is_never_classified_as_replayable() {
    // One emitted byte is enough: the client holds a partial answer, so the
    // request is past the point where a retry could stay invisible.
    let provider = StreamedResponse::provider_failed(1, read_error());
    assert_eq!(
        provider.outcome,
        StreamTerminalOutcome::ProviderFailedAfterFirstByte
    );
    assert!(provider.result.is_err());

    let downstream = StreamedResponse::downstream_failed(1, read_error());
    assert_eq!(
        downstream.outcome,
        StreamTerminalOutcome::DownstreamFailedAfterFirstByte
    );
    assert!(downstream.result.is_err());
}

#[test]
fn a_failure_before_the_first_byte_keeps_the_request_replayable() {
    assert_eq!(
        StreamedResponse::provider_failed(0, read_error()).outcome,
        StreamTerminalOutcome::ProviderFailedBeforeFirstByte
    );
    assert_eq!(
        StreamedResponse::downstream_failed(0, read_error()).outcome,
        StreamTerminalOutcome::DownstreamFailedBeforeFirstByte
    );
}

#[test]
fn the_ok_result_belongs_to_the_completed_outcome_alone() {
    let completed = StreamedResponse::completed();
    assert!(completed.result.is_ok());
    assert!(completed.outcome.is_complete());
    for streamed in [
        StreamedResponse::provider_failed(0, read_error()),
        StreamedResponse::provider_failed(9, read_error()),
        StreamedResponse::downstream_failed(0, read_error()),
        StreamedResponse::downstream_failed(9, read_error()),
    ] {
        assert!(
            streamed.result.is_err(),
            "{:?} must not hand the handler an Ok",
            streamed.outcome
        );
    }
}
