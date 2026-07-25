// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: ContainerControlClient verb tests (issue #415) — assert each container verb hits
//   the right /container/* route with the bearer token, instance name, and spec shape; that
//   ungoverned egress and invalid identities are rejected client-side with NO HTTP; that the
//   Worker's error vocabulary maps to typed errors; and that the CF container descriptor is
//   selectable when policy allows yet fails closed for the unimplemented snapshot capability.

use std::collections::VecDeque;
use std::sync::Mutex;

use ferrogate_cloudflare::{HttpMethod, HttpRequest, HttpResponse};

use super::{
    cloudflare_container_capabilities, cloudflare_container_descriptor, ContainerControlClient,
    ContainerControlError, ContainerExecSpec, ContainerInstanceTier, ContainerPrepareSpec,
    ContainerSignal, ContainerStartSpec,
};
use crate::cloudflare_agent_memory::AgentInstanceIdentity;
use crate::cloudflare_container_egress::ContainerEgressPosture;
use crate::cloudflare_gateway_control::GatewayControlTransport;
use crate::cloudflare_worker::CloudflareControlSurfaceError;
use crate::isolation::{
    select_isolation_backend, IsolationBackendCapabilities, IsolationBackendKind, IsolationError,
    IsolationPolicy,
};

/// A synchronous scripted transport: records requests, replays responses.
struct MockContainerTransport {
    responses: Mutex<VecDeque<HttpResponse>>,
    captured: Mutex<Vec<HttpRequest>>,
}

impl MockContainerTransport {
    fn new(responses: Vec<HttpResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            captured: Mutex::new(Vec::new()),
        }
    }

    fn last(&self) -> HttpRequest {
        self.captured.lock().unwrap().last().cloned().unwrap()
    }

    fn captured_len(&self) -> usize {
        self.captured.lock().unwrap().len()
    }
}

impl GatewayControlTransport for MockContainerTransport {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareControlSurfaceError> {
        self.captured.lock().unwrap().push(request);
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("mock container transport ran out of responses"))
    }
}

fn ok(body: &str) -> HttpResponse {
    HttpResponse {
        status: 200,
        retry_after: None,
        body: body.as_bytes().to_vec(),
    }
}

fn status(code: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status: code,
        retry_after: None,
        body: body.as_bytes().to_vec(),
    }
}

fn client(responses: Vec<HttpResponse>) -> ContainerControlClient<MockContainerTransport> {
    ContainerControlClient::new(
        "https://ferrogate-agent-gateway.example.workers.dev",
        "control-secret",
        MockContainerTransport::new(responses),
    )
}

fn identity() -> AgentInstanceIdentity {
    AgentInstanceIdentity::new("tenant-a", "sess-1", "run-9")
}

fn body_json(req: &HttpRequest) -> serde_json::Value {
    serde_json::from_slice(req.body.as_ref().unwrap()).unwrap()
}

// ---- prepare ----------------------------------------------------------------

#[test]
fn prepare_posts_image_and_tier() {
    let c = client(vec![ok(
        r#"{ "instance": "fg.tenant-a.sess-1.run-9", "preparedId": "prep-1" }"#,
    )]);
    let spec = ContainerPrepareSpec::new(
        "registry/agent-sandbox:latest",
        ContainerInstanceTier::Standard2,
    );
    let prepared = c.prepare(&identity(), &spec).unwrap();
    assert_eq!(prepared.prepared_id, "prep-1");
    assert_eq!(prepared.instance, "fg.tenant-a.sess-1.run-9");

    let req = c.transport().last();
    assert_eq!(req.method, HttpMethod::Post);
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/container/prepare"
    );
    assert_eq!(req.bearer_token, "control-secret");
    let body = body_json(&req);
    assert_eq!(body["instance"], "fg.tenant-a.sess-1.run-9");
    assert_eq!(body["container"]["image"], "registry/agent-sandbox:latest");
    assert_eq!(body["container"]["tier"], "standard-2");
}

#[test]
fn prepare_rejects_empty_image_without_http() {
    let c = client(vec![]);
    let spec = ContainerPrepareSpec::new("   ", ContainerInstanceTier::Lite);
    let err = c.prepare(&identity(), &spec).unwrap_err();
    assert!(
        matches!(err, ContainerControlError::InvalidSpec(_)),
        "got {err:?}"
    );
    assert_eq!(c.transport().captured_len(), 0);
}

// ---- start + egress governance (issue #471) ---------------------------------

/// Build the `egress` attestation the Worker returns for a posture.
fn attested(posture: &ContainerEgressPosture) -> String {
    let allowed = serde_json::to_string(posture.allowed_hosts()).unwrap();
    let denied = serde_json::to_string(posture.denied_hosts()).unwrap();
    format!(
        r#"{{ "instance": "fg.tenant-a.sess-1.run-9", "instanceId": "cf-abc", "running": true,
             "egress": {{ "directPublicEgress": false, "posture": "{}",
                          "allowedHosts": {allowed}, "deniedHosts": {denied} }} }}"#,
        posture.wire_label()
    )
}

#[test]
fn start_defaults_to_sealed_egress_and_posts_env() {
    let sealed = ContainerEgressPosture::Sealed;
    let c = client(vec![ok(&attested(&sealed))]);
    let mut spec = ContainerStartSpec::default();
    spec.env.insert("FOO".into(), "bar".into());
    let started = c.start(&identity(), &spec).unwrap();
    assert_eq!(started.instance_id, "cf-abc");
    assert!(started.running);

    let body = body_json(&c.transport().last());
    // `direct_public_egress = false` is asserted on the wire and is not a knob:
    // ContainerStartSpec has no field that could set it true.
    assert_eq!(body["enableInternet"], false);
    assert_eq!(body["directPublicEgress"], false);
    assert_eq!(body["egressPosture"], "sealed");
    assert_eq!(body["env"]["FOO"], "bar");
    assert!(body["egressAllowlist"].as_array().unwrap().is_empty());
    assert!(body["egressDenylist"].as_array().unwrap().is_empty());
}

#[test]
fn tethered_start_posts_the_governed_allowlist_and_the_provider_denylist() {
    let posture = ContainerEgressPosture::tethered_to("gw.ferrogate.internal").unwrap();
    let c = client(vec![ok(&attested(&posture))]);
    let spec = ContainerStartSpec {
        egress: posture,
        ..ContainerStartSpec::default()
    };
    c.start(&identity(), &spec).unwrap();
    let body = body_json(&c.transport().last());
    assert_eq!(body["enableInternet"], false);
    assert_eq!(body["egressPosture"], "gateway-tethered");
    assert_eq!(body["egressAllowlist"][0], "gw.ferrogate.internal");
    let denylist = body["egressDenylist"].as_array().unwrap();
    assert!(denylist.iter().any(|h| h == "api.anthropic.com"));
    assert!(denylist.iter().any(|h| h == "api.openai.com"));
}

#[test]
fn a_provider_endpoint_can_never_be_put_in_a_start_spec() {
    // The bypass this tier exists to prevent is unrepresentable: the posture
    // refuses to construct, so no HTTP is ever attempted.
    let err = ContainerEgressPosture::tethered_to("api.anthropic.com").unwrap_err();
    assert!(err.to_string().contains("LLM provider endpoint"), "{err}");
    let err = ContainerEgressPosture::tethered_to("*").unwrap_err();
    assert!(err.to_string().contains("wildcard"), "{err}");
}

#[test]
fn an_unattested_start_is_refused() {
    // A Worker deployment without the #471 posture attestation: the instance may
    // be running with whatever egress it likes, so the start fails closed.
    let c = client(vec![ok(
        r#"{ "instance": "fg.tenant-a.sess-1.run-9", "instanceId": "cf-abc", "running": true }"#,
    )]);
    let err = c
        .start(&identity(), &ContainerStartSpec::default())
        .unwrap_err();
    match err {
        ContainerControlError::EgressNotGoverned(m) => {
            assert!(m.contains("did not attest"), "got {m}")
        }
        other => panic!("expected EgressNotGoverned, got {other:?}"),
    }
}

#[test]
fn a_start_whose_worker_dropped_the_allowlist_is_refused() {
    let posture = ContainerEgressPosture::tethered_to("gw.ferrogate.internal").unwrap();
    let c = client(vec![ok(
        r#"{ "instance": "fg.tenant-a.sess-1.run-9", "instanceId": "cf-abc", "running": true,
             "egress": { "directPublicEgress": false, "posture": "gateway-tethered",
                         "allowedHosts": [], "deniedHosts": [] } }"#,
    )]);
    let spec = ContainerStartSpec {
        egress: posture,
        ..ContainerStartSpec::default()
    };
    let err = c.start(&identity(), &spec).unwrap_err();
    assert!(
        matches!(err, ContainerControlError::EgressNotGoverned(_)),
        "got {err:?}"
    );
}

#[test]
fn a_start_attesting_direct_public_egress_is_refused() {
    let c = client(vec![ok(
        r#"{ "instance": "fg.tenant-a.sess-1.run-9", "instanceId": "cf-abc", "running": true,
             "egress": { "directPublicEgress": true, "posture": "sealed",
                         "allowedHosts": [], "deniedHosts": [] } }"#,
    )]);
    let err = c
        .start(&identity(), &ContainerStartSpec::default())
        .unwrap_err();
    match err {
        ContainerControlError::EgressNotGoverned(m) => {
            assert!(m.contains("direct public egress"), "got {m}")
        }
        other => panic!("expected EgressNotGoverned, got {other:?}"),
    }
}

// ---- exec -------------------------------------------------------------------

#[test]
fn exec_command_posts_command_step() {
    let c = client(vec![ok(
        r#"{ "instance": "fg.tenant-a.sess-1.run-9", "exitCode": 0, "stdout": "hi\n", "stderr": "", "truncated": false }"#,
    )]);
    let spec = ContainerExecSpec::command(["/bin/echo", "hi"]).with_timeout_millis(5_000);
    let out = c.exec(&identity(), &spec).unwrap();
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(out.stdout, "hi\n");

    let req = c.transport().last();
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/container/exec"
    );
    let body = body_json(&req);
    assert_eq!(body["step"]["mode"], "command");
    assert_eq!(body["step"]["command"][0], "/bin/echo");
    assert_eq!(body["step"]["command"][1], "hi");
    assert_eq!(body["step"]["timeoutMillis"], 5_000);
}

#[test]
fn exec_code_posts_code_step() {
    let c = client(vec![ok(
        r#"{ "instance": "fg.tenant-a.sess-1.run-9", "exitCode": 0, "stdout": "42\n" }"#,
    )]);
    let spec = ContainerExecSpec::code("python", "print(6 * 7)");
    let out = c.exec(&identity(), &spec).unwrap();
    assert_eq!(out.stdout, "42\n");
    let body = body_json(&c.transport().last());
    assert_eq!(body["step"]["mode"], "code");
    assert_eq!(body["step"]["language"], "python");
    assert_eq!(body["step"]["source"], "print(6 * 7)");
}

#[test]
fn exec_rejects_empty_command_without_http() {
    let c = client(vec![]);
    let spec = ContainerExecSpec::command(Vec::<String>::new());
    let err = c.exec(&identity(), &spec).unwrap_err();
    assert!(
        matches!(err, ContainerControlError::InvalidSpec(_)),
        "got {err:?}"
    );
    assert_eq!(c.transport().captured_len(), 0);
}

// ---- stop / logs / artifacts / cleanup -------------------------------------

#[test]
fn stop_posts_signal() {
    let c = client(vec![ok(
        r#"{ "instance": "fg.tenant-a.sess-1.run-9", "signal": "SIGKILL", "running": false }"#,
    )]);
    let stopped = c.stop(&identity(), ContainerSignal::Kill).unwrap();
    assert_eq!(stopped.signal, "SIGKILL");
    assert!(!stopped.running);
    let body = body_json(&c.transport().last());
    assert_eq!(body["signal"], "SIGKILL");
}

#[test]
fn logs_posts_tail_and_maps_lines() {
    let c = client(vec![ok(
        r#"{ "instance": "fg.tenant-a.sess-1.run-9", "lines": ["a", "b"] }"#,
    )]);
    let logs = c.collect_logs(&identity(), Some(50)).unwrap();
    assert_eq!(logs.lines, vec!["a", "b"]);
    let body = body_json(&c.transport().last());
    assert_eq!(body["tail"], 50);
}

#[test]
fn artifacts_maps_entries() {
    let c = client(vec![ok(r#"{ "instance": "fg.tenant-a.sess-1.run-9",
             "artifacts": [ { "path": "/workspace/out.txt", "sizeBytes": 12, "contentType": "text/plain" } ] }"#)]);
    let arts = c.collect_artifacts(&identity(), None).unwrap();
    assert_eq!(arts.artifacts.len(), 1);
    assert_eq!(arts.artifacts[0].path, "/workspace/out.txt");
    assert_eq!(arts.artifacts[0].size_bytes, 12);
    assert_eq!(
        arts.artifacts[0].content_type.as_deref(),
        Some("text/plain")
    );
}

#[test]
fn cleanup_posts_instance() {
    let c = client(vec![ok(
        r#"{ "instance": "fg.tenant-a.sess-1.run-9", "destroyed": true }"#,
    )]);
    let cleaned = c.cleanup(&identity()).unwrap();
    assert!(cleaned.destroyed);
    let req = c.transport().last();
    assert_eq!(
        req.url,
        "https://ferrogate-agent-gateway.example.workers.dev/container/cleanup"
    );
}

// ---- identity + error mapping ----------------------------------------------

#[test]
fn invalid_identity_is_rejected_before_any_http() {
    let c = client(vec![]);
    let bad = AgentInstanceIdentity::new("tenant.a", "s", "r");
    let spec = ContainerPrepareSpec::new("img", ContainerInstanceTier::Lite);
    let err = c.prepare(&bad, &spec).unwrap_err();
    assert!(
        matches!(err, ContainerControlError::InvalidIdentity(_)),
        "got {err:?}"
    );
    assert_eq!(c.transport().captured_len(), 0);
}

#[test]
fn denied_bearer_maps_to_denied() {
    let c = client(vec![status(403, r#"{ "error": "invalid bearer token" }"#)]);
    let err = c.cleanup(&identity()).unwrap_err();
    assert!(
        matches!(err, ContainerControlError::Denied(_)),
        "got {err:?}"
    );
}

#[test]
fn worker_side_invalid_spec_422_maps_to_invalid_spec() {
    let c = client(vec![status(
        422,
        r#"{ "error": "invalid_spec", "message": "tier must be lite..standard-4" }"#,
    )]);
    let spec = ContainerPrepareSpec::new("img", ContainerInstanceTier::Lite);
    let err = c.prepare(&identity(), &spec).unwrap_err();
    match err {
        ContainerControlError::InvalidSpec(m) => assert!(m.contains("standard-4"), "got {m}"),
        other => panic!("expected InvalidSpec, got {other:?}"),
    }
}

#[test]
fn unbound_501_maps_to_unbound() {
    let c = client(vec![status(
        501,
        r#"{ "error": "container_unbound", "message": "no CONTAINER_SANDBOX binding" }"#,
    )]);
    let err = c
        .start(&identity(), &ContainerStartSpec::default())
        .unwrap_err();
    assert!(
        matches!(err, ContainerControlError::Unbound(_)),
        "got {err:?}"
    );
}

#[test]
fn not_running_409_maps_to_not_running() {
    let c = client(vec![status(
        409,
        r#"{ "error": "not_running", "message": "no running instance" }"#,
    )]);
    let spec = ContainerExecSpec::command(["/bin/true"]);
    let err = c.exec(&identity(), &spec).unwrap_err();
    assert!(
        matches!(err, ContainerControlError::NotRunning(_)),
        "got {err:?}"
    );
}

#[test]
fn other_failures_map_to_request_failed_with_verb_and_status() {
    let c = client(vec![status(
        502,
        r#"{ "error": "container call failed: boom" }"#,
    )]);
    let err = c.collect_logs(&identity(), None).unwrap_err();
    match err {
        ContainerControlError::RequestFailed { verb, status, .. } => {
            assert_eq!(verb, "logs");
            assert_eq!(status, 502);
        }
        other => panic!("expected RequestFailed, got {other:?}"),
    }
}

// ---- descriptor selectability + fail-closed capability gating --------------

#[test]
fn descriptor_is_selectable_when_policy_allows_the_kind() {
    let descriptor = cloudflare_container_descriptor("gateway-driven");
    let policy = IsolationPolicy {
        allowed_kinds: vec![IsolationBackendKind::CloudflareContainer],
        ..IsolationPolicy::default()
    };
    let selected = select_isolation_backend(&policy, std::slice::from_ref(&descriptor)).unwrap();
    assert_eq!(selected.kind, IsolationBackendKind::CloudflareContainer);
    assert_eq!(selected.backend_name, "cloudflare-container");
    assert!(selected.gateway_controls_backend);
}

#[test]
fn descriptor_fails_closed_for_the_unimplemented_snapshot_capability() {
    // Snapshot/checkpoint is NOT implemented (no CF primitive), so the
    // descriptor advertises it false; a policy that REQUIRES it can never
    // select this backend.
    let descriptor = cloudflare_container_descriptor("gateway-driven");
    let mut required = IsolationBackendCapabilities::none();
    required.snapshot_or_checkpoint = true;
    let policy = IsolationPolicy {
        allowed_kinds: vec![IsolationBackendKind::CloudflareContainer],
        required_capabilities: required,
        ..IsolationPolicy::default()
    };
    let error = select_isolation_backend(&policy, std::slice::from_ref(&descriptor)).unwrap_err();
    assert!(matches!(error, IsolationError::NoCompatibleBackend(_)));
}

#[test]
fn advertised_capabilities_exclude_snapshot_and_secret_injection() {
    // The advertised set is a strict subset of the implemented lifecycle ops:
    // snapshot (no CF primitive) and secret injection (gateway-mediated) are
    // deliberately OFF so selection never routes them here.
    let caps = cloudflare_container_capabilities();
    assert!(caps.prepare && caps.start && caps.exec_or_attach && caps.stop);
    assert!(caps.collect_logs && caps.collect_artifacts && caps.cleanup);
    assert!(caps.governed_egress);
    assert!(!caps.snapshot_or_checkpoint);
    assert!(!caps.secret_injection);
}
