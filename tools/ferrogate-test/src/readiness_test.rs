// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-29
// description: Regression tests for the shared harness gateway readiness identity + port-hijack classification.

use super::*;
use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
};

/// Label every start-failure assertion below expects to see, so a failure is
/// attributable to the scenario that owns the gateway.
const LABEL: &str = "readiness unit gateway";

/// Bounded ceiling for the live-process cases: every one of them reaches its
/// decision from an observed answer, so this is only the failure bound.
const UNIT_TIMEOUT: Duration = Duration::from_secs(10);

/// A real HTTP responder holding a real ephemeral port: the unit-layer stand-in
/// for the parallel-harness mock that wins a released gateway port (#444). It
/// answers every connection with the same canned response, exactly like a mock
/// that replies 200 to whatever a readiness probe asks it.
struct StubServer {
    addr: String,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl StubServer {
    fn spawn(status: u16, headers: &[&str], body: &str) -> Self {
        let mut canned = format!("HTTP/1.1 {status} OK\r\n");
        for header in headers {
            canned.push_str(header);
            canned.push_str("\r\n");
        }
        canned.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub responder");
        let addr = listener
            .local_addr()
            .expect("stub responder address")
            .to_string();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker = {
            let shutdown = Arc::clone(&shutdown);
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(mut stream) = stream else { continue };
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                    let mut request = [0_u8; 4096];
                    let _ = stream.read(&mut request);
                    let _ = stream.write_all(canned.as_bytes());
                    let _ = stream.flush();
                }
            })
        };
        Self {
            addr,
            shutdown,
            worker: Some(worker),
        }
    }

    /// A squatting mock: a valid HTTP 200 that is not FerroGate's healthz and
    /// carries none of FerroGate's response evidence -- the #444 signature.
    fn spawn_squatting_mock() -> Self {
        Self::spawn(
            200,
            &["content-type: application/json"],
            r#"{"object":"list","data":[{"id":"provider-chat"}]}"#,
        )
    }

    /// A live FerroGate: a ready `/healthz` stamped the way the gateway stamps
    /// every response it writes.
    fn spawn_ferrogate_healthz() -> Self {
        Self::spawn(
            200,
            &[
                "content-type: application/json",
                "x-ferrogate-runtime: pingora",
            ],
            r#"{"service":"ferrogate","status":"ok"}"#,
        )
    }

    /// A live `ferrogate-auth`: `route_request` answers `GET /healthz` with this
    /// body before any auth/CORS gate, and the service stamps no runtime header.
    fn spawn_auth_healthz() -> Self {
        Self::spawn(
            200,
            &["content-type: application/json"],
            r#"{"service":"ferrogate-auth","status":"ok"}"#,
        )
    }

    fn addr(&self) -> &str {
        &self.addr
    }
}

impl Drop for StubServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Unblock the accept() the worker is parked on so the thread can observe
        // the shutdown flag and the port is released with the test.
        let _ = TcpStream::connect(&self.addr);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// A long-lived child standing in for a `ferrogate` process that has NOT exited:
/// the readiness path must decide from the port's answer, not from the child.
struct LiveChild {
    child: Child,
}

impl LiveChild {
    fn spawn() -> Self {
        let child = Command::new("sleep")
            .arg("600")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn long-lived stand-in child");
        Self { child }
    }
}

impl Drop for LiveChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn response(status: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status,
        body: body.to_string(),
        raw: format!("HTTP/1.1 {status}\r\n\r\n{body}"),
    }
}

fn ok(status: u16, body: &str) -> Result<HttpResponse> {
    Ok(response(status, body))
}

/// A response the way the FerroGate *gateway* actually writes one: every
/// gateway-authored answer carries `x-ferrogate-runtime: pingora`.
fn ferrogate_stamped(status: u16, body: &str) -> Result<HttpResponse> {
    Ok(HttpResponse {
        status,
        body: body.to_string(),
        raw: format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nx-ferrogate-runtime: pingora\r\n\r\n{body}"
        ),
    })
}

#[test]
fn readiness_accepts_only_a_live_ferrogate_healthz() {
    let healthz = ok(200, r#"{"service":"ferrogate","status":"ok"}"#);

    // The readiness *decision* — the only thing `wait_for_gateway_start` acts on —
    // must treat a live FerroGate as ready. If the gate regresses to status-only,
    // the hijack cases below go red, not this one.
    assert_eq!(
        classify_readiness(GATEWAY, &healthz),
        ServiceReadiness::Ready
    );
    assert!(healthz_identifies_service(
        GATEWAY,
        healthz.as_ref().unwrap()
    ));
}

#[test]
fn readiness_flags_a_squatting_mock_models_200_as_port_hijack_not_ready() {
    // The exact #444 signature: a parallel-harness mock that won the released
    // gateway port answers with HTTP 200 and a valid body that is not FerroGate's
    // healthz (here a provider `/v1/models` list). Accepting it as ready is the
    // original flake, so the readiness decision must classify it as a port hijack
    // — never Ready — which is what drives the harness to rotate to a fresh port
    // (LocalHarness) or fail by name (scenario-owned gateways).
    let provider_models = ok(200, r#"{"object":"list","data":[{"id":"provider-chat"}]}"#);

    let verdict = classify_readiness(GATEWAY, &provider_models);

    assert_eq!(verdict, ServiceReadiness::PortHijacked);
    assert_ne!(verdict, ServiceReadiness::Ready);
}

#[test]
fn readiness_flags_any_non_ferrogate_positive_answer_as_port_hijack() {
    let wrong_service = ok(200, r#"{"service":"ferrogate-auth","status":"ok"}"#);
    let plain_200 = ok(200, "ok");
    let mock_404 = ok(404, r#"{"error":"not found"}"#);

    assert_eq!(
        classify_readiness(GATEWAY, &wrong_service),
        ServiceReadiness::PortHijacked
    );
    assert_eq!(
        classify_readiness(GATEWAY, &plain_200),
        ServiceReadiness::PortHijacked
    );
    assert_eq!(
        classify_readiness(GATEWAY, &mock_404),
        ServiceReadiness::PortHijacked
    );
}

#[test]
fn readiness_keeps_polling_when_nobody_has_bound_the_port_yet() {
    // Connection refused / read timeout before Pingora binds: keep polling the
    // same address rather than misreading the absence of an answer as a hijack.
    let refused: Result<HttpResponse> = Err(anyhow::anyhow!("connection refused"));

    assert_eq!(
        classify_readiness(GATEWAY, &refused),
        ServiceReadiness::Pending
    );
}

#[test]
fn readiness_treats_a_ferrogate_stamped_error_answer_as_pending_not_hijack() {
    // Our own gateway can legitimately answer a readiness probe with something
    // other than a ready healthz: an unauthenticated rate limit, an IP deny, any
    // error envelope. Those bodies carry no `service` field, so only the runtime
    // header FerroGate stamps on every response it writes tells them apart from a
    // squatting mock. Misreading one as a hijack would fail the scenario at start
    // on the gateway's own answer.
    let rate_limited = ferrogate_stamped(
        429,
        r#"{"error":{"code":"unauthenticated_rate_limited","type":"ferrogate_error"}}"#,
    );

    assert_eq!(
        classify_readiness(GATEWAY, &rate_limited),
        ServiceReadiness::Pending
    );
}

#[test]
fn wait_for_gateway_start_reports_a_squatting_mock_as_a_port_hijack() {
    // End of the wait path, over a real socket: a live child plus a foreign
    // process answering 200 on the gateway port must terminate the wait as
    // PortHijacked -- the value LocalHarness rotates ports on. Polling it can
    // never reach FerroGate, so returning Pending here would burn the deadline.
    let squatter = StubServer::spawn_squatting_mock();
    let mut child = LiveChild::spawn();

    let outcome = wait_for_gateway_start(&mut child.child, squatter.addr(), LABEL, UNIT_TIMEOUT)
        .expect("a squatting responder is a classification, not an error");

    assert_eq!(outcome, ServiceStartOutcome::PortHijacked);
}

#[test]
fn require_gateway_ready_refuses_to_run_against_a_squatting_mock() {
    // The reason the scenario-owned harnesses call `require_gateway_ready`: a
    // gateway address baked into an already-rendered config cannot rotate, so a
    // proven hijack must fail HERE, by name, instead of letting the scenario run
    // against a mock (which is how #444 surfaced as `GET /v1/models` missing a
    // configured model rather than as a start failure).
    let squatter = StubServer::spawn_squatting_mock();
    let mut child = LiveChild::spawn();

    let error = require_gateway_ready(&mut child.child, squatter.addr(), LABEL, UNIT_TIMEOUT)
        .expect_err("a scenario must not be run against a non-FerroGate responder");

    let message = format!("{error:#}");
    assert!(
        message.contains(LABEL),
        "start failure must name the scenario that owns the gateway: {message}"
    );
    assert!(
        message.contains(squatter.addr()),
        "start failure must name the hijacked address: {message}"
    );
}

#[test]
fn require_gateway_ready_accepts_a_live_ferrogate_on_the_gateway_port() {
    // The control for the refusal above: the refusal must be conditional on the
    // responder's identity, not on "a responder answered". A stamped, ready
    // healthz is the gateway itself and must start the scenario.
    let gateway = StubServer::spawn_ferrogate_healthz();
    let mut child = LiveChild::spawn();

    require_gateway_ready(&mut child.child, gateway.addr(), LABEL, UNIT_TIMEOUT)
        .expect("a live FerroGate healthz on the gateway port is ready");
}

#[test]
fn require_gateway_ready_fails_when_the_child_exited_before_readiness() {
    // A gateway that died during startup (bad config, migration failure) must be
    // reported as an exit, not waited out to the deadline. The child is reaped
    // first so the exit is already observable on the first check and the address
    // is never probed.
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("exit 7")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn failing stand-in child");
    child.wait().expect("reap failing stand-in child");

    let error = require_gateway_ready(&mut child, "127.0.0.1:9", LABEL, UNIT_TIMEOUT)
        .expect_err("a gateway that exited before readiness must fail the scenario");

    let message = format!("{error:#}");
    assert!(
        message.contains(LABEL),
        "start failure must name the scenario that owns the gateway: {message}"
    );
    assert!(
        message.contains("exited before readiness"),
        "a dead child must be reported as an exit, not as a timeout: {message}"
    );
}

#[test]
fn require_gateway_ready_with_socket_waits_for_the_gateway_created_socket() {
    // The managed-worker scenarios need both a ready gateway and the unix socket
    // the gateway publishes. A ready gateway whose socket never appears must fail
    // naming that path, and both waits must share the caller's single ceiling.
    let gateway = StubServer::spawn_ferrogate_healthz();
    let dir = tempfile::tempdir().expect("scenario dir");
    let missing = dir.path().join("authorizer-missing.sock");
    let mut child = LiveChild::spawn();

    let error = require_gateway_ready_with_socket(
        &mut child.child,
        gateway.addr(),
        &missing,
        LABEL,
        Duration::from_secs(1),
    )
    .expect_err("a gateway without its authorizer socket is not usable by the scenario");

    let message = format!("{error:#}");
    assert!(
        message.contains(&missing.display().to_string()),
        "start failure must name the socket that never appeared: {message}"
    );

    // Same gateway, socket present: the composed gate must accept.
    let published = dir.path().join("authorizer.sock");
    std::fs::write(&published, b"").expect("publish authorizer socket path");
    require_gateway_ready_with_socket(
        &mut child.child,
        gateway.addr(),
        &published,
        LABEL,
        UNIT_TIMEOUT,
    )
    .expect("a ready gateway that published its socket starts the scenario");
}

#[test]
fn readiness_is_decided_against_the_expected_service_not_any_ferrogate() {
    // Every harness service address comes from `free_addr()`, so the auth and
    // billing ports carry the same release->rebind window as the gateway port
    // (#444). What makes a responder legitimate there is that service's OWN
    // identity: `ferrogate-auth` on the auth port is ready, and the GATEWAY
    // answering on the auth port is a foreign process for that harness -- even
    // though it is FerroGate, and even though it stamps the runtime header, which
    // is gateway-only evidence and must not vouch for another service.
    let auth_healthz = ok(200, r#"{"service":"ferrogate-auth","status":"ok"}"#);
    let billing_healthz = ok(200, r#"{"service":"ferrogate-billing","status":"ok"}"#);
    let gateway_healthz = ferrogate_stamped(200, r#"{"service":"ferrogate","status":"ok"}"#);

    assert_eq!(
        classify_readiness(AUTH, &auth_healthz),
        ServiceReadiness::Ready
    );
    assert_eq!(
        classify_readiness(BILLING, &billing_healthz),
        ServiceReadiness::Ready
    );

    // Cross-service answers are hijacks in every direction.
    assert_eq!(
        classify_readiness(AUTH, &gateway_healthz),
        ServiceReadiness::PortHijacked
    );
    assert_eq!(
        classify_readiness(AUTH, &billing_healthz),
        ServiceReadiness::PortHijacked
    );
    assert_eq!(
        classify_readiness(BILLING, &auth_healthz),
        ServiceReadiness::PortHijacked
    );
    assert_eq!(
        classify_readiness(GATEWAY, &auth_healthz),
        ServiceReadiness::PortHijacked
    );
}

#[test]
fn readiness_flags_a_squatting_mock_on_the_auth_port_as_a_port_hijack() {
    // The #444 class at the auth gate: the squatting mock answers 200 to whatever
    // the probe asks, which is what the status-only loop accepted.
    let squatter = StubServer::spawn_squatting_mock();
    let mut child = LiveChild::spawn();

    let error = require_service_ready(
        AUTH,
        &mut child.child,
        squatter.addr(),
        LABEL,
        Duration::from_secs(2),
    )
    .expect_err("a scenario must not be run against a non-ferrogate-auth responder");

    let message = format!("{error:#}");
    assert!(
        message.contains(LABEL) && message.contains(squatter.addr()),
        "start failure must name the scenario and the hijacked address: {message}"
    );
    assert!(
        message.contains("ferrogate-auth"),
        "start failure must name the service that was expected: {message}"
    );
}

#[test]
fn require_service_ready_accepts_a_live_auth_service_on_the_auth_port() {
    // The control for the refusal above: the refusal is conditional on identity,
    // not on "a responder answered", so a real `ferrogate-auth` healthz starts the
    // scenario.
    let auth = StubServer::spawn_auth_healthz();
    let mut child = LiveChild::spawn();

    require_service_ready(AUTH, &mut child.child, auth.addr(), LABEL, UNIT_TIMEOUT)
        .expect("a live ferrogate-auth healthz on the auth port is ready");
}

#[test]
fn readiness_treats_our_own_gateway_answering_not_ready_as_pending_not_hijack() {
    // Defensive: a body that claims `service:ferrogate` but is not a ready 200 is
    // still our process, so keep polling instead of rotating ports away from it.
    let ours_not_ready = ok(503, r#"{"service":"ferrogate","status":"starting"}"#);

    assert!(!healthz_identifies_service(
        GATEWAY,
        ours_not_ready.as_ref().unwrap()
    ));
    assert_eq!(
        classify_readiness(GATEWAY, &ours_not_ready),
        ServiceReadiness::Pending
    );
}

#[test]
fn a_ready_answer_from_a_foreign_process_tree_is_a_hijack_not_readiness() {
    // The residual #444 left open: identity proves "that is a FerroGate", not
    // "that is MY FerroGate". Another harness's gateway that won this released
    // ephemeral port answers a byte-identical stamped `/healthz` and would then
    // serve the scenario ITS models -- which is exactly `GET /v1/models` missing
    // `fast-chat`. Ownership is what separates the two, so a foreign owner of an
    // otherwise-ready port must terminate the wait as a hijack.
    assert_eq!(
        ready_outcome_for_owner(PortOwnership::Foreign),
        ServiceStartOutcome::PortHijacked
    );
    // ...and must stay conditional on ownership being *proven*: our own service,
    // and any host where ownership cannot be observed at all, still start.
    assert_eq!(
        ready_outcome_for_owner(PortOwnership::OurProcessTree),
        ServiceStartOutcome::Ready
    );
    assert_eq!(
        ready_outcome_for_owner(PortOwnership::Unknown),
        ServiceStartOutcome::Ready
    );
}

#[test]
fn port_ownership_never_accuses_without_an_observed_listening_socket() {
    // No listening inode means nothing was observed -- a non-Linux host, an
    // unreadable /proc, or a racing read. That is Unknown, never Foreign: the
    // check may only ever add a refusal it can prove.
    let ours = BTreeSet::from([41_u64]);

    assert_eq!(
        classify_port_ownership(&BTreeSet::new(), &ours),
        PortOwnership::Unknown
    );
    assert_eq!(
        classify_port_ownership(&BTreeSet::from([99]), &ours),
        PortOwnership::Foreign
    );
    assert_eq!(
        classify_port_ownership(&BTreeSet::from([99, 41]), &ours),
        PortOwnership::OurProcessTree
    );
}

#[test]
fn listening_inodes_are_read_only_for_listening_sockets_on_the_probed_port() {
    // Real `/proc/net/tcp` shape. Only state 0A (LISTEN) on the probed port
    // counts: an ESTABLISHED connection *to* that port, and a listener on any
    // other port, are not evidence about who holds it.
    let table = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000   0 424242 1 x
   1: 0100007F:1F90 0100007F:C000 01 00000000:00000000 00:00000000 00000000  1000   0 515151 1 x
   2: 00000000:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000   0 616161 1 x
";

    assert_eq!(
        parse_listening_inodes(table, 0x1F90),
        BTreeSet::from([424_242])
    );
    // A wildcard listener on 0.0.0.0 serves 127.0.0.1 too, so it is collected.
    assert_eq!(
        parse_listening_inodes(table, 0x1F91),
        BTreeSet::from([616_161])
    );
    assert!(parse_listening_inodes(table, 0x0050).is_empty());
}

#[test]
fn a_listener_this_process_holds_is_observed_as_ours_through_real_proc() {
    // The plumbing above the pure decisions, against the real kernel tables: a
    // socket this test process actually holds must resolve to our process tree.
    // Without this, `observe_port_ownership` could return Unknown for everything
    // and the refusal would never fire in production.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an owned listener");
    let addr = listener
        .local_addr()
        .expect("owned listener address")
        .to_string();
    let child = LiveChild::spawn();

    assert_eq!(
        observe_port_ownership(&addr, child.child.id()),
        PortOwnership::OurProcessTree,
        "a socket held by this process must not be reported as a foreign squatter"
    );

    drop(listener);
    assert_eq!(
        parse_socket_inode("socket:[424242]"),
        Some(424_242),
        "fd links are how a pid's sockets are enumerated"
    );
    assert_eq!(parse_socket_inode("/dev/null"), None);
    assert_eq!(
        parse_ppid("Name:\tsleep\nPPid:\t1234\nState:\tS\n"),
        Some(1234)
    );
}
