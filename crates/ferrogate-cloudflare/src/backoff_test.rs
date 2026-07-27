// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Retry/backoff schedule tests with an injected clock and scripted transport (NO real sleeps).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::client::{
    Clock, CloudflareClient, HttpRequest, HttpResponse, HttpTransport, RetryPolicy,
};
use crate::config::CloudflareConfig;
use crate::error::CloudflareError;
use crate::resolver::EnvTokenResolver;

/// A clock that records requested sleep durations instead of sleeping. This is
/// what lets the backoff *schedule* be asserted with zero real time elapsed.
#[derive(Default)]
struct FakeClock {
    delays: Mutex<Vec<Duration>>,
}

#[async_trait]
impl Clock for FakeClock {
    async fn sleep(&self, duration: Duration) {
        self.delays.lock().unwrap().push(duration);
    }
}

/// A transport that replays a pre-scripted sequence of results in order.
struct ScriptedTransport {
    responses: Mutex<VecDeque<Result<HttpResponse, CloudflareError>>>,
    calls: Mutex<u32>,
}

impl ScriptedTransport {
    fn new(responses: Vec<Result<HttpResponse, CloudflareError>>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            calls: Mutex::new(0),
        }
    }
}

#[async_trait]
impl HttpTransport for ScriptedTransport {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, CloudflareError> {
        *self.calls.lock().unwrap() += 1;
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted transport ran out of responses")
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn ok(
    status: u16,
    retry_after: Option<Duration>,
    body: &str,
) -> Result<HttpResponse, CloudflareError> {
    Ok(HttpResponse {
        status,
        retry_after,
        body: body.as_bytes().to_vec(),
    })
}

const SUCCESS_BODY: &str = r#"{ "success": true, "errors": [], "result": {} }"#;

fn client(
    transport: Arc<ScriptedTransport>,
    clock: Arc<FakeClock>,
    retry: RetryPolicy,
) -> CloudflareClient {
    CloudflareClient::from_parts(
        // Inline plaintext token: no env/network needed to resolve.
        CloudflareConfig::new("acct-test", "plaintext-token"),
        Arc::new(EnvTokenResolver::from_process_env()),
        transport,
        clock,
        retry,
    )
}

fn short_policy() -> RetryPolicy {
    RetryPolicy {
        max_retries: 4,
        base_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(60),
    }
}

#[test]
fn exponential_backoff_schedule_on_repeated_429() {
    let transport = Arc::new(ScriptedTransport::new(vec![
        ok(429, None, "{}"),
        ok(429, None, "{}"),
        ok(200, None, SUCCESS_BODY),
    ]));
    let clock = Arc::new(FakeClock::default());
    let cf = client(transport.clone(), clock.clone(), short_policy());

    let value: serde_json::Value = runtime()
        .block_on(cf.get_json("accounts/{account_id}", None))
        .expect("should succeed after backing off");
    assert!(value.is_object());

    // Two retries: base*2^0 = 1s, base*2^1 = 2s. No real time elapsed.
    let delays = clock.delays.lock().unwrap().clone();
    assert_eq!(delays, vec![Duration::from_secs(1), Duration::from_secs(2)]);
    assert_eq!(*transport.calls.lock().unwrap(), 3);
}

#[test]
fn retry_after_header_overrides_exponential_schedule() {
    let transport = Arc::new(ScriptedTransport::new(vec![
        ok(429, Some(Duration::from_secs(5)), "{}"),
        ok(200, None, SUCCESS_BODY),
    ]));
    let clock = Arc::new(FakeClock::default());
    let cf = client(transport, clock.clone(), short_policy());

    let _v: serde_json::Value = runtime()
        .block_on(cf.get_json("accounts/{account_id}", None))
        .unwrap();

    let delays = clock.delays.lock().unwrap().clone();
    assert_eq!(delays, vec![Duration::from_secs(5)]);
}

#[test]
fn retry_after_is_capped_at_max_backoff() {
    let transport = Arc::new(ScriptedTransport::new(vec![
        ok(429, Some(Duration::from_secs(9999)), "{}"),
        ok(200, None, SUCCESS_BODY),
    ]));
    let clock = Arc::new(FakeClock::default());
    let retry = RetryPolicy {
        max_retries: 4,
        base_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(30),
    };
    let cf = client(transport, clock.clone(), retry);

    let _v: serde_json::Value = runtime()
        .block_on(cf.get_json("accounts/{account_id}", None))
        .unwrap();

    assert_eq!(*clock.delays.lock().unwrap(), vec![Duration::from_secs(30)]);
}

#[test]
fn exhausting_retries_on_429_yields_rate_limited_with_attempt_count() {
    let retry = RetryPolicy {
        max_retries: 2,
        base_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(60),
    };
    let transport = Arc::new(ScriptedTransport::new(vec![
        ok(429, None, "{}"),
        ok(429, None, "{}"),
        ok(429, None, "{}"),
    ]));
    let clock = Arc::new(FakeClock::default());
    let cf = client(transport, clock.clone(), retry);

    let err = runtime()
        .block_on(cf.get_json::<serde_json::Value>("accounts/{account_id}", None))
        .unwrap_err();

    match err {
        CloudflareError::RateLimited { attempts, .. } => assert_eq!(attempts, 3),
        other => panic!("expected RateLimited, got {other:?}"),
    }
    // Two backoffs before exhausting: 1s, 2s.
    assert_eq!(
        *clock.delays.lock().unwrap(),
        vec![Duration::from_secs(1), Duration::from_secs(2)]
    );
}

#[test]
fn transport_error_is_retried_then_succeeds() {
    let transport = Arc::new(ScriptedTransport::new(vec![
        Err(CloudflareError::Transport("connection reset".into())),
        ok(200, None, SUCCESS_BODY),
    ]));
    let clock = Arc::new(FakeClock::default());
    let cf = client(transport, clock.clone(), short_policy());

    let _v: serde_json::Value = runtime()
        .block_on(cf.get_json("accounts/{account_id}", None))
        .unwrap();
    assert_eq!(*clock.delays.lock().unwrap(), vec![Duration::from_secs(1)]);
}

#[test]
fn retryable_5xx_is_retried() {
    let transport = Arc::new(ScriptedTransport::new(vec![
        ok(503, None, "{}"),
        ok(200, None, SUCCESS_BODY),
    ]));
    let clock = Arc::new(FakeClock::default());
    let cf = client(transport, clock.clone(), short_policy());

    let _v: serde_json::Value = runtime()
        .block_on(cf.get_json("accounts/{account_id}", None))
        .unwrap();
    assert_eq!(*clock.delays.lock().unwrap(), vec![Duration::from_secs(1)]);
}

#[test]
fn exhausting_retries_on_transport_error_yields_exhausted_retries() {
    let retry = RetryPolicy {
        max_retries: 1,
        base_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(60),
    };
    let transport = Arc::new(ScriptedTransport::new(vec![
        Err(CloudflareError::Transport("reset".into())),
        Err(CloudflareError::Transport("reset".into())),
    ]));
    let clock = Arc::new(FakeClock::default());
    let cf = client(transport, clock.clone(), retry);

    let err = runtime()
        .block_on(cf.get_json::<serde_json::Value>("accounts/{account_id}", None))
        .unwrap_err();
    match err {
        CloudflareError::ExhaustedRetries { attempts, .. } => assert_eq!(attempts, 2),
        other => panic!("expected ExhaustedRetries, got {other:?}"),
    }
    assert_eq!(*clock.delays.lock().unwrap(), vec![Duration::from_secs(1)]);
}

#[test]
fn non_retryable_error_is_not_retried() {
    let transport = Arc::new(ScriptedTransport::new(vec![ok(
        403,
        None,
        r#"{ "success": false, "errors": [{ "code": 9109, "message": "denied" }] }"#,
    )]));
    let clock = Arc::new(FakeClock::default());
    let cf = client(transport.clone(), clock.clone(), short_policy());

    let err = runtime()
        .block_on(cf.get_json::<serde_json::Value>("accounts/{account_id}", None))
        .unwrap_err();
    assert!(
        matches!(err, CloudflareError::MissingScope { .. }),
        "got {err:?}"
    );
    // No retries, no sleeps for a terminal auth/scope failure.
    assert!(clock.delays.lock().unwrap().is_empty());
    assert_eq!(*transport.calls.lock().unwrap(), 1);
}

#[test]
fn preflight_maps_missing_scope() {
    let transport = Arc::new(ScriptedTransport::new(vec![ok(
        403,
        None,
        r#"{ "success": false, "errors": [{ "code": 9109, "message": "denied" }] }"#,
    )]));
    let clock = Arc::new(FakeClock::default());
    let cf = client(transport, clock, short_policy());

    let err = runtime().block_on(cf.preflight(None)).unwrap_err();
    match err {
        CloudflareError::MissingScope { required, .. } => {
            assert!(required.iter().any(|g| g.contains("AI Gateway")));
        }
        other => panic!("expected MissingScope, got {other:?}"),
    }
}

#[test]
fn preflight_succeeds_on_healthy_account() {
    let transport = Arc::new(ScriptedTransport::new(vec![ok(
        200,
        None,
        r#"{ "success": true, "errors": [], "result": { "id": "acct-test" } }"#,
    )]));
    let clock = Arc::new(FakeClock::default());
    let cf = client(transport, clock, short_policy());

    runtime()
        .block_on(cf.preflight(None))
        .expect("preflight should pass");
}

#[test]
fn code_10013_at_400_reaches_the_caller_as_api_after_exactly_one_request() {
    // Issue #493, consumer-level pin. `error_test.rs` proves the *mapping*
    // in isolation; this proves what an R2 caller actually observes, and it
    // is the assertion that records the real mechanism: the backoff loop is
    // driven by HTTP status (`is_retryable_status` = 429|500|502|503|504),
    // NOT by `CloudflareError::is_retryable`, which `from_response` output
    // never reaches — `from_response` runs after the loop has returned.
    // Hence a 400 is issued once and only once, no matter what code the
    // envelope carries.
    let transport = Arc::new(ScriptedTransport::new(vec![ok(
        400,
        None,
        r#"{ "success": false, "errors": [{ "code": 10013, "message": "IncompleteBody" }] }"#,
    )]));
    let clock = Arc::new(FakeClock::default());
    let cf = client(transport.clone(), clock.clone(), short_policy());

    let err = runtime()
        .block_on(cf.get_json::<serde_json::Value>("accounts/{account_id}", None))
        .unwrap_err();

    match err {
        CloudflareError::Api { status, ref errors } => {
            assert_eq!(status, 400, "got {err:?}");
            assert_eq!(errors[0].code, 10013, "got {err:?}");
        }
        other => panic!("expected Api {{ status: 400 }}, got {other:?}"),
    }
    // The load-bearing half: one request, zero backoff sleeps. Restoring the
    // old `code == 10013 => RateLimited` branch would change the variant
    // above but NOT this count — which is exactly why the pre-#493 rationale
    // ("retried until the backoff budget was burned") was wrong.
    assert_eq!(*transport.calls.lock().unwrap(), 1, "400 must not be retried");
    assert!(
        clock.delays.lock().unwrap().is_empty(),
        "400 must not back off, got {:?}",
        clock.delays.lock().unwrap()
    );
}

#[test]
fn the_same_code_10013_at_500_is_retried_because_status_drives_the_loop() {
    // Companion to the test above: identical envelope code, different HTTP
    // status, opposite retry behaviour — so the file records that the status
    // is the mechanism. In the general `client/v4` namespace 10013 surfaces
    // as `workers.api.error.unknown` (HTTP 500), which IS retryable.
    let retry = RetryPolicy {
        max_retries: 2,
        base_backoff: Duration::from_secs(1),
        max_backoff: Duration::from_secs(60),
    };
    let body = r#"{ "success": false, "errors": [{ "code": 10013, "message": "workers.api.error.unknown" }] }"#;
    let transport = Arc::new(ScriptedTransport::new(vec![
        ok(500, None, body),
        ok(500, None, body),
        ok(500, None, body),
    ]));
    let clock = Arc::new(FakeClock::default());
    let cf = client(transport.clone(), clock.clone(), retry);

    let err = runtime()
        .block_on(cf.get_json::<serde_json::Value>("accounts/{account_id}", None))
        .unwrap_err();

    match err {
        CloudflareError::Api { status, ref errors } => {
            assert_eq!(status, 500, "got {err:?}");
            assert_eq!(errors[0].code, 10013, "got {err:?}");
        }
        other => panic!("expected Api {{ status: 500 }}, got {other:?}"),
    }
    assert_eq!(
        *transport.calls.lock().unwrap(),
        3,
        "500 must be retried max_retries times"
    );
    assert_eq!(
        *clock.delays.lock().unwrap(),
        vec![Duration::from_secs(1), Duration::from_secs(2)]
    );
}
