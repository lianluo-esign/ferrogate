// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The x402 seam of the worker's REAL governed REST response path (#353).
//!
//! Two properties are proven here against live loopback sockets, because both
//! are properties of the production path rather than of a pure function:
//!
//! 1. **Redaction.** Bearer material never reaches recorded evidence.
//!    `run_authorized_rest_action` records an excerpt of the raw HTTP response —
//!    headers included — into `rest.requested` event metadata and into the
//!    self-hosted governed-workload output. A `PAYMENT-SIGNATURE` there is a
//!    signed, submittable SVM transaction; an `authorization` or `set-cookie`
//!    there is a live credential. Public x402 protocol evidence
//!    (`PAYMENT-REQUIRED`, `PAYMENT-RESPONSE`) must survive, or the audit trail
//!    #354 depends on is destroyed.
//!
//! 2. **Wire stage.** A failed dispatch is classified by how far the request
//!    got, and the classification is asymmetric on purpose: only a failure
//!    PROVEN to be pre-send may release a wallet hold. Every other outcome —
//!    including the genuinely ambiguous ones — must retain it.
//!
//! Plus the worker's non-custodial `402` detection: it surfaces the challenge
//! and refuses. It never pays, and it never replays.

use std::sync::mpsc;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde_json::json;

use super::*;
use crate::x402_client::{HoldDisposition, RequestWireStage, REDACTED_HEADER_VALUE};

// Golden devnet payment terms, matching `x402_client_test.rs` so the two files
// describe the same merchant. Only the resource URL varies, because the
// authorized egress URL is a loopback address chosen at runtime.
const DEVNET_CAIP2: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const RECIPIENT: &str = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4";
const FEE_PAYER: &str = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd";
const ATOMIC_AMOUNT: u64 = 2500;

/// Stand-in for a signed SVM transaction. Long enough that a 512-character
/// excerpt of an unredacted response would still carry a usable prefix of it,
/// which is what makes the redact-before-truncate ordering load-bearing.
fn proof_bytes() -> String {
    "PROOFSIGNATUREDONOTLOG".repeat(24)
}

fn x402_session() -> FrameworkAdapterSession {
    FrameworkAdapterSession {
        session_id: "x402-session".to_string(),
        run_id: "x402-run".to_string(),
        tenant_id: "x402-tenant".to_string(),
        workspace_id: "x402-workspace".to_string(),
        worker_id: "x402-worker".to_string(),
        isolation_backend: "firecracker".to_string(),
        adapter_name: "native-harness".to_string(),
        adapter_version: env!("CARGO_PKG_VERSION").to_string(),
        framework: SupportedFramework::NativeHarness,
        mode: FrameworkAdapterMode::Managed,
    }
}

fn allowing_gate() -> RuntimeGatewayExternalActionAuthorizer<SimpleCapabilityAuthorizer> {
    RuntimeGatewayExternalActionAuthorizer::new(SimpleCapabilityAuthorizer::new(CapabilityPolicy {
        allowed_actions: BTreeSet::from([CapabilityAction::Rest]),
        class_only_policy_mode: ferrogate_runtime::ClassOnlyPolicyMode::LegacyClassWide,
        ..CapabilityPolicy::default()
    }))
}

fn rest_action(endpoint: SocketAddr, timeout_millis: u64) -> ManagedRestAction {
    ManagedRestAction {
        method: "GET".to_string(),
        url: format!("http://{endpoint}/authorized"),
        headers_policy: "deny_credentials".to_string(),
        body_policy: "empty_body".to_string(),
        timeout_millis,
        retry_limit: 0,
        resolved_ips: vec!["127.0.0.1".to_string()],
        redirect_chain: Vec::new(),
    }
}

/// Base64 `PAYMENT-REQUIRED` challenge for `resource_url`, on the golden devnet
/// terms. Built rather than checked in because the authorized loopback URL is
/// only known at runtime.
fn challenge_header(resource_url: &str) -> String {
    let challenge = json!({
        "x402Version": 2,
        "resource": { "url": resource_url, "mimeType": "application/json" },
        "accepts": [{
            "scheme": "exact",
            "network": DEVNET_CAIP2,
            "amount": ATOMIC_AMOUNT.to_string(),
            "asset": MINT,
            "payTo": RECIPIENT,
            "maxTimeoutSeconds": 120,
            "extra": { "feePayer": FEE_PAYER },
        }],
    });
    BASE64_STANDARD.encode(challenge.to_string().as_bytes())
}

/// A loopback origin serving a canned raw response, which records every request
/// it receives — so "the worker never replayed" is observed at the origin
/// rather than inferred from a return value.
///
/// The accept loop is detached: after the worker's single synchronous dispatch
/// returns, any replay would already have been recorded, so the channel can be
/// drained without blocking.
struct CannedOrigin {
    endpoint: SocketAddr,
    requests: mpsc::Receiver<String>,
}

impl CannedOrigin {
    fn spawn(response: String) -> Self {
        Self::spawn_with(|_| response)
    }

    /// Bind first, then let the caller build a response that names the bound
    /// address — a challenge must be able to point at the very URL the action
    /// authorizes.
    fn spawn_with(build_response: impl FnOnce(SocketAddr) -> String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let response = build_response(endpoint);
        let (tx, requests) = mpsc::channel();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buffer = [0_u8; 2048];
                let read = stream.read(&mut buffer).unwrap_or(0);
                if tx
                    .send(String::from_utf8_lossy(&buffer[..read]).to_string())
                    .is_err()
                {
                    break;
                }
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.shutdown(Shutdown::Write);
            }
        });
        Self { endpoint, requests }
    }

    fn served_requests(&self) -> Vec<String> {
        self.requests.try_iter().collect()
    }
}

fn http_response(status_line: &str, headers: &[(&str, String)], body: &str) -> String {
    let mut response = format!("{status_line}\r\n");
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!("content-length: {}\r\n", body.len()));
    response.push_str("connection: close\r\n\r\n");
    response.push_str(body);
    response
}

/// Drive the REAL governed path end to end and return the `rest.requested`
/// event metadata the worker recorded.
fn rest_event_metadata(
    action: ManagedRestAction,
) -> Result<BTreeMap<String, String>, FrameworkAdapterError> {
    let events = execute_governed_rest_action(&allowing_gate(), x402_session(), action, false)?;
    Ok(events[1].metadata.clone())
}

// ---------------------------------------------------------------------------
// 1. Redaction on the real response path
// ---------------------------------------------------------------------------

/// The load-bearing leak test: a response carrying a signed payment proof and
/// two live credentials must leave none of them in recorded evidence.
///
/// Reverting `response_excerpt` to `response.chars().take(512).collect()` makes
/// this fail on the first assertion.
#[test]
fn recorded_rest_evidence_never_carries_bearer_material() {
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 200 OK",
        &[
            ("PAYMENT-SIGNATURE", proof_bytes()),
            ("authorization", "Bearer super-secret-token".to_string()),
            ("set-cookie", "session=abc123; HttpOnly".to_string()),
            ("content-type", "text/plain".to_string()),
        ],
        "ferrogate governed rest smoke\n",
    ));

    let metadata = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap();
    let excerpt = metadata.get("response_excerpt").expect("excerpt recorded");

    assert!(
        !excerpt.contains("PROOFSIGNATUREDONOTLOG"),
        "signed payment proof leaked into recorded evidence: {excerpt}"
    );
    assert!(
        !excerpt.contains("super-secret-token"),
        "authorization credential leaked into recorded evidence: {excerpt}"
    );
    assert!(
        !excerpt.contains("abc123"),
        "session cookie leaked into recorded evidence: {excerpt}"
    );
    // The header NAMES survive, so an operator can still see that a proof and
    // credentials were present.
    assert!(excerpt.contains("PAYMENT-SIGNATURE"), "{excerpt}");
    assert!(excerpt.contains("authorization"), "{excerpt}");
    assert_eq!(
        excerpt.matches(REDACTED_HEADER_VALUE).count(),
        3,
        "expected exactly the three bearer headers redacted: {excerpt}"
    );
    // Non-bearer headers and the body are untouched.
    assert!(excerpt.contains("text/plain"), "{excerpt}");
    assert!(
        excerpt.contains("ferrogate governed rest smoke"),
        "{excerpt}"
    );
}

/// Redaction must not become censorship: the two PUBLIC x402 protocol headers
/// are the audit trail that answers "why was this payment made and what
/// happened to it?" (#354). Over-redacting them destroys evidence and protects
/// nothing — neither is bearer material.
#[test]
fn public_x402_protocol_evidence_survives_redaction() {
    let settlement = BASE64_STANDARD.encode(br#"{"success":true}"#);
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 200 OK",
        &[
            ("PAYMENT-RESPONSE", settlement.clone()),
            ("content-type", "text/plain".to_string()),
        ],
        "paid resource\n",
    ));

    let metadata = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap();
    let excerpt = metadata.get("response_excerpt").expect("excerpt recorded");

    assert!(
        excerpt.contains(&settlement),
        "settlement evidence must be preserved verbatim: {excerpt}"
    );
    assert!(!excerpt.contains(REDACTED_HEADER_VALUE), "{excerpt}");
}

/// Ordering matters: the excerpt is capped at 512 characters, so redacting
/// after truncating would still ship a long usable prefix of the proof. The
/// proof here sits first, exactly where a surviving prefix would land.
#[test]
fn redaction_precedes_truncation_so_no_proof_prefix_survives() {
    let proof = proof_bytes();
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 200 OK",
        &[("PAYMENT-SIGNATURE", proof.clone())],
        "body\n",
    ));

    let metadata = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap();
    let excerpt = metadata.get("response_excerpt").expect("excerpt recorded");

    // Not just the whole proof — no prefix of it either.
    for prefix_len in [8, 16, 32, 64] {
        assert!(
            !excerpt.contains(&proof[..prefix_len]),
            "a {prefix_len}-char proof prefix survived truncation: {excerpt}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Non-custodial 402 detection
// ---------------------------------------------------------------------------

/// A merchant demanding payment gets a typed refusal naming the challenge, and
/// exactly one request at the origin. The worker surfaces; it does not pay and
/// does not replay.
#[test]
fn a_payment_required_challenge_is_surfaced_and_refused_not_paid() {
    let origin = CannedOrigin::spawn_with(|endpoint| {
        http_response(
            "HTTP/1.1 402 Payment Required",
            &[(
                "PAYMENT-REQUIRED",
                challenge_header(&format!("http://{endpoint}/authorized")),
            )],
            "payment required\n",
        )
    });

    let error = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap_err();
    let message = error.to_string();

    assert!(
        message.contains("will not self-authorize"),
        "the refusal must say the worker does not authorize its own spend: {message}"
    );
    assert!(
        message.contains(&ATOMIC_AMOUNT.to_string()),
        "the refusal must name the amount demanded: {message}"
    );
    assert!(
        message.contains(RECIPIENT),
        "the refusal must name the payee: {message}"
    );
    assert!(
        message.contains(DEVNET_CAIP2),
        "the refusal must name the network: {message}"
    );
    // No proof, no signer, no key material anywhere in the refusal.
    assert!(!message.contains("PAYMENT-SIGNATURE"), "{message}");

    assert_eq!(
        origin.served_requests().len(),
        1,
        "a 402 must not trigger a replay"
    );
}

/// A challenge whose protected resource is NOT the egress URL FerroGate
/// authorized is a payment redirect: it fails closed, and the refusal says so.
#[test]
fn a_redirected_payment_challenge_fails_closed() {
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 402 Payment Required",
        &[(
            "PAYMENT-REQUIRED",
            challenge_header("https://attacker.example.com/drain"),
        )],
        "payment required\n",
    ));

    let error = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap_err();
    let message = error.to_string();

    assert!(
        message.contains("failed closed"),
        "a redirected challenge must fail closed: {message}"
    );
    assert!(
        message.contains("attacker.example.com"),
        "the refusal must name the resource it refused: {message}"
    );
}

/// A 402 with no challenge header at all is still a refusal — not a payment,
/// not a panic.
#[test]
fn a_payment_required_without_a_challenge_header_fails_closed() {
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 402 Payment Required",
        &[("content-type", "text/plain".to_string())],
        "pay me somehow\n",
    ));

    let error = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap_err();
    let message = error.to_string();

    assert!(
        message.contains("without a PAYMENT-REQUIRED challenge header"),
        "{message}"
    );
    assert!(message.contains("nothing was paid"), "{message}");
}

/// An unparseable challenge is refused, and the refusal does not echo the
/// merchant's raw header back — it is attacker-controlled input.
#[test]
fn a_malformed_payment_challenge_fails_closed() {
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 402 Payment Required",
        &[("PAYMENT-REQUIRED", "not-base64-at-all!!".to_string())],
        "payment required\n",
    ));

    let error = rest_event_metadata(rest_action(origin.endpoint, 1_000)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed closed"), "{message}");
    assert!(!message.contains("not-base64-at-all"), "{message}");
}

// ---------------------------------------------------------------------------
// 3. Wire stage → hold disposition, and its asymmetry
// ---------------------------------------------------------------------------

/// The ONLY case that may release a hold: the connection never came up, so no
/// request byte can have reached anyone.
#[test]
fn a_refused_connection_is_proven_unsent_and_may_release_the_hold() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    drop(listener); // nothing is listening now

    let failure = run_authorized_rest_action(&rest_action(endpoint, 200)).unwrap_err();

    assert_eq!(failure.stage, RequestWireStage::ProvenNotSent);
    assert_eq!(
        failure.stage.hold_disposition(),
        HoldDisposition::ReleasableBeforeSubmission
    );
}

/// Validation failures are proven pre-send too — the socket is never opened.
#[test]
fn a_rejected_action_is_proven_unsent() {
    let mut action = rest_action("127.0.0.1:9".parse().unwrap(), 200);
    action.method = "POST".to_string();

    let failure = run_authorized_rest_action(&action).unwrap_err();

    assert_eq!(failure.stage, RequestWireStage::ProvenNotSent);
}

/// The request was fully written and the peer went silent. The proof — if #381
/// had attached one — is on the wire and may have settled, so the hold must be
/// RETAINED, never released.
#[test]
fn a_silent_peer_after_a_complete_request_retains_the_hold() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let accepted = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        // Hold the connection open, silently, until the client's read timeout
        // fires.
        thread::sleep(Duration::from_millis(400));
        drop(stream);
    });

    let failure = run_authorized_rest_action(&rest_action(endpoint, 60)).unwrap_err();

    assert_eq!(failure.stage, RequestWireStage::SentOrUnknown);
    assert_eq!(
        failure.stage.hold_disposition(),
        HoldDisposition::RetainOutcomeUnknown
    );

    let _ = accepted.join();
}

/// The explicitly AMBIGUOUS case, which is the one that matters.
///
/// The peer accepts and tears the connection down without reading or replying,
/// so depending on kernel buffering and scheduling the client may fail inside
/// `write_all`, inside `shutdown`, or by reading an empty response — and it
/// cannot tell which bytes, if any, the peer consumed.
///
/// Whichever syscall loses the race, the classification must be identical and
/// must be RETAIN. That invariance across interleavings is the assertion: there
/// is no timing in which an ambiguous teardown yields a release.
#[test]
fn an_ambiguous_teardown_always_retains_the_hold() {
    for attempt in 0..8 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let accepted = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            drop(stream); // neither read nor reply
        });

        let failure = run_authorized_rest_action(&rest_action(endpoint, 200)).unwrap_err();

        assert_eq!(
            failure.stage,
            RequestWireStage::SentOrUnknown,
            "attempt {attempt}: an ambiguous teardown must never be classified as unsent \
             (error was: {})",
            failure.error
        );
        assert_eq!(
            failure.stage.hold_disposition(),
            HoldDisposition::RetainOutcomeUnknown,
            "attempt {attempt}"
        );

        let _ = accepted.join();
    }
}

/// A 402 is by definition post-send. Had the #381 binding attached a proof to
/// this dispatch, the merchant received it, so this may never release.
#[test]
fn a_payment_required_response_retains_the_hold() {
    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 402 Payment Required",
        &[("content-type", "text/plain".to_string())],
        "pay me\n",
    ));

    let failure = run_authorized_rest_action(&rest_action(origin.endpoint, 1_000)).unwrap_err();

    assert_eq!(
        failure.stage.hold_disposition(),
        HoldDisposition::RetainOutcomeUnknown
    );
}

/// The stage is not test-only bookkeeping: it reaches the operator. A refused
/// connection and a silent peer produce visibly different answers to "did my
/// request actually reach the upstream?" on the very same code path.
#[test]
fn the_wire_stage_reaches_the_operator_facing_error() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let unbound = listener.local_addr().unwrap();
    drop(listener);
    let refused = run_authorized_rest_action(&rest_action(unbound, 200))
        .unwrap_err()
        .into_error()
        .to_string();
    assert!(
        refused.contains("no request byte reached the upstream"),
        "{refused}"
    );

    let origin = CannedOrigin::spawn(http_response(
        "HTTP/1.1 500 Internal Server Error",
        &[],
        "boom\n",
    ));
    let sent = run_authorized_rest_action(&rest_action(origin.endpoint, 1_000))
        .unwrap_err()
        .into_error()
        .to_string();
    assert!(
        sent.contains("the request may have reached the upstream"),
        "{sent}"
    );
}

/// The structural guarantee behind all of the above: a failure nobody
/// explicitly classified converts to RETAIN. Adding a new `?` to the dispatch
/// without thinking about the wire stage is therefore safe by construction;
/// only a deliberate `proven_not_sent` can authorize a release.
///
/// Flipping `RequestWireStage::default()` to `ProvenNotSent` fails this test and
/// `an_ambiguous_teardown_always_retains_the_hold` together.
#[test]
fn an_unclassified_dispatch_failure_defaults_to_retaining_the_hold() {
    let failure: RestDispatchFailure =
        FrameworkAdapterError::CapabilityDenied("something new and unclassified".to_string())
            .into();

    assert_eq!(failure.stage, RequestWireStage::SentOrUnknown);
    assert_eq!(
        failure.stage.hold_disposition(),
        HoldDisposition::RetainOutcomeUnknown
    );
    assert_eq!(RequestWireStage::default(), RequestWireStage::SentOrUnknown);
}
