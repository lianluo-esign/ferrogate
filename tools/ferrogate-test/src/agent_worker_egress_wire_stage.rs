// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: End-to-end closure for the worker-side egress wire-stage
// discriminant (#353): the SHIPPED agent-worker binary really dispatches a
// governed REST egress and really emits the typed hold-edge discriminant.

//! # `agent-worker-egress-wire-stage`
//!
//! ## The gap this closes
//!
//! `#353` delivers the worker half of the non-custodial x402 boundary. Its
//! load-bearing acceptance box is not the 402 parse — it is this:
//!
//! > The wire stage the worker observes is emitted as a **typed discriminant**
//! > ([`ferrogate_runtime::EGRESS_REQUEST_WIRE_STAGE_KEY`]), with the fail-safe
//! > direction — retain the hold unless the request is *proven* unsent —
//! > surviving the management wire in both directions.
//!
//! That is a claim about a **process boundary**. The gateway owns the durable
//! attempt API (`X402SettlementLoop::cancel` is the RELEASE edge on a wallet
//! hold) and runs in a different process from the worker that observed how far
//! the request got.
//!
//! Be precise about what was already covered, because over-claiming here would
//! be the same sin this command exists to catch. The in-crate `agent-worker`
//! tests DO cover the emit call itself: delete
//! `RequestWireStage::write_event_metadata` from the dispatch-metadata builder
//! and `a_completed_dispatch_also_records_the_wire_stage` goes red. What they
//! cannot cover is the last hop — the shipped binary's own **operator-facing
//! output**. Measured, not assumed: dropping `metadata` from the events
//! `governed-rest-execution-smoke` prints leaves all 22 in-crate x402 tests
//! green (`test result: ok. 22 passed`) and is caught only here
//! (`Error: event carried no metadata object`). Everything between the correct
//! in-memory map and the bytes an operator or a gateway actually reads was
//! unverified.
//!
//! Before this command, no harness scenario executed the `agent-worker` binary
//! at all. This one does, and it is the only place the discriminant is observed
//! as a real process's real output.
//!
//! ## What it drives, and what it deliberately does not
//!
//! * **Cloud mode** (`governed-rest-execution-smoke`): the binary authorizes a
//!   REST action through its own capability gate, opens a real TCP connection to
//!   a loopback listener it spawned, and emits `capability.allowed` +
//!   `rest.requested` events as JSON. The listener echoes the request line back,
//!   so "the request was really on the wire" is observed at the origin rather
//!   than inferred from the exit code.
//! * **Self-hosted mode**: the same binary, report-only. The workload runs and
//!   the denied decision is recorded rather than enforced (#242/#247).
//!
//! **Not** driven: the `402` branch itself. `run_authorized_rest_action` is a
//! loopback smoke executor whose only non-test caller points a hardcoded action
//! at a listener it spawns itself and which answers `200` — there is no CLI or
//! management-wire surface that can aim the shipped binary at a `402` peer, so
//! the merchant-facing half of #353 is provable only in-crate until #381 lands a
//! real egress executor. That limit is stated here rather than papered over: see
//! the boundary note in `crates/agent-worker/src/x402_client.rs`.

use std::{collections::BTreeMap, path::Path, process::Command};

use anyhow::{bail, ensure, Context, Result};
use ferrogate_runtime::{
    HoldDisposition, RequestWireStage, EGRESS_HOLD_DISPOSITION_KEY, EGRESS_REQUEST_WIRE_STAGE_KEY,
};
use serde_json::Value;

/// Credential markers that must never appear in recorded egress evidence.
const BEARER_MARKERS: &[&str] = &[
    "Bearer ",
    "PAYMENT-SIGNATURE",
    "set-cookie",
    "authorization",
];

pub(crate) fn run_agent_worker_egress_wire_stage(binary: &Path) -> Result<()> {
    ensure_binary(binary)?;

    println!("== agent-worker-egress-wire-stage: cloud-mode governed REST dispatch ==");
    let cloud = run_smoke(binary, &[])?;
    let events = cloud
        .get("events")
        .and_then(Value::as_array)
        .context("cloud-mode governed REST smoke emitted no `events` array")?;
    let served = cloud
        .get("served_request")
        .and_then(Value::as_str)
        .context("cloud-mode governed REST smoke recorded no `served_request`")?;
    ensure!(
        served.starts_with("GET /governed-rest-smoke "),
        "the origin must have observed the real request line, got {served:?}"
    );

    let dispatch = find_event(events, "rest.requested")?;
    let metadata = string_metadata(dispatch)?;
    verify_typed_discriminant(&metadata)?;
    verify_consumer_side_is_fail_safe(&metadata)?;
    verify_no_bearer_material(&metadata)?;

    println!("== agent-worker-egress-wire-stage: self-hosted report-only dispatch ==");
    verify_self_hosted_report_only(binary)?;

    println!("agent-worker-egress-wire-stage: OK");
    Ok(())
}

fn ensure_binary(binary: &Path) -> Result<()> {
    ensure!(
        binary.exists(),
        "agent-worker binary does not exist at {}; run `cargo build -p agent-worker` first or \
         pass --agent-worker-bin",
        binary.display()
    );
    Ok(())
}

fn run_smoke(binary: &Path, prefix_args: &[&str]) -> Result<Value> {
    let mut command = Command::new(binary);
    command.args(prefix_args);
    command.arg("governed-rest-execution-smoke");
    let output = command
        .output()
        .with_context(|| format!("run {} governed-rest-execution-smoke", binary.display()))?;
    ensure!(
        output.status.success(),
        "{} {prefix_args:?} governed-rest-execution-smoke failed ({}): {}",
        binary.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse governed-rest-execution-smoke JSON: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn find_event<'a>(events: &'a [Value], kind: &str) -> Result<&'a Value> {
    events
        .iter()
        .find(|event| event.get("kind").and_then(Value::as_str) == Some(kind))
        .with_context(|| format!("the smoke emitted no `{kind}` event"))
}

/// Re-materialize the event's metadata as the `BTreeMap<String, String>` a
/// consumer in another process would hold, so the typed accessor is exercised
/// against the real serialized shape rather than an in-memory fixture.
fn string_metadata(event: &Value) -> Result<BTreeMap<String, String>> {
    let object = event
        .get("metadata")
        .and_then(Value::as_object)
        .context("event carried no metadata object")?;
    let mut metadata = BTreeMap::new();
    for (key, value) in object {
        let Some(value) = value.as_str() else {
            bail!("metadata key {key} is not a string on the management wire");
        };
        metadata.insert(key.clone(), value.to_string());
    }
    Ok(metadata)
}

/// Both keys must be present, be drawn from the FROZEN vocabulary, and agree.
///
/// "Agree" is the part a prose message cannot give you: the disposition is
/// derived from the stage at write time, so a binary that emitted the two
/// independently — or emitted a stage token nothing recognizes — would be read
/// by the gateway as `retain`, and the mismatch would never surface.
fn verify_typed_discriminant(metadata: &BTreeMap<String, String>) -> Result<()> {
    let stage_token = metadata
        .get(EGRESS_REQUEST_WIRE_STAGE_KEY)
        .with_context(|| {
            format!("the shipped binary emitted no {EGRESS_REQUEST_WIRE_STAGE_KEY}")
        })?;
    let disposition_token = metadata
        .get(EGRESS_HOLD_DISPOSITION_KEY)
        .with_context(|| format!("the shipped binary emitted no {EGRESS_HOLD_DISPOSITION_KEY}"))?;

    ensure!(
        [
            RequestWireStage::PROVEN_NOT_SENT_TOKEN,
            RequestWireStage::SENT_OR_UNKNOWN_TOKEN,
        ]
        .contains(&stage_token.as_str()),
        "{EGRESS_REQUEST_WIRE_STAGE_KEY}={stage_token:?} is outside the frozen vocabulary"
    );

    let stage = RequestWireStage::from_event_metadata(metadata);
    ensure!(
        stage.as_wire_token() == stage_token,
        "the typed accessor read {:?} back from the token {stage_token:?} the binary wrote",
        stage.as_wire_token()
    );
    ensure!(
        stage.hold_disposition().as_wire_token() == disposition_token,
        "{EGRESS_HOLD_DISPOSITION_KEY}={disposition_token:?} disagrees with the disposition \
         {:?} that stage {stage_token:?} mandates",
        stage.hold_disposition().as_wire_token()
    );

    // A completed dispatch really did put the request on the wire, so the only
    // correct edge is RETAIN. A binary that reported the release edge here would
    // let the gateway cancel a hold for a request the merchant already answered.
    ensure!(
        stage == RequestWireStage::SentOrUnknown
            && stage.hold_disposition() == HoldDisposition::RetainOutcomeUnknown,
        "a completed dispatch must carry the retain edge, got {stage_token:?}/{disposition_token:?}"
    );
    println!("  typed discriminant: {stage_token} -> {disposition_token}");
    Ok(())
}

/// The fail-safe direction, asserted on the REAL wire shape.
///
/// Take the metadata the shipped binary actually emitted and damage only the
/// stage token the way a version skew or a dropped write would: remove it, empty
/// it, change its case, replace it with the release token spelled slightly
/// differently. Every one of those must read back as RETAIN. This is the
/// asymmetry the whole design rests on — an unrecognized token must never be
/// read as permission to release a wallet hold.
fn verify_consumer_side_is_fail_safe(metadata: &BTreeMap<String, String>) -> Result<()> {
    for damaged in [
        None,
        Some(""),
        Some("Proven_Not_Sent"),
        Some("PROVEN_NOT_SENT"),
        Some(" proven_not_sent"),
        Some("proven_not_sent_v2"),
        Some("releasable_before_submission"),
    ] {
        let mut probe = metadata.clone();
        match damaged {
            None => {
                probe.remove(EGRESS_REQUEST_WIRE_STAGE_KEY);
            }
            Some(token) => {
                probe.insert(EGRESS_REQUEST_WIRE_STAGE_KEY.to_string(), token.to_string());
            }
        }
        let stage = RequestWireStage::from_event_metadata(&probe);
        ensure!(
            stage.hold_disposition() == HoldDisposition::RetainOutcomeUnknown,
            "an unrecognized wire-stage token {damaged:?} was read as {:?}; anything that is not \
             exactly {:?} must retain the hold",
            stage.hold_disposition().as_wire_token(),
            RequestWireStage::PROVEN_NOT_SENT_TOKEN
        );
    }

    // The positive control: the one exact token that MAY release still does, so
    // the assertion above is proving fail-safety rather than a constant.
    let mut releasing = metadata.clone();
    releasing.insert(
        EGRESS_REQUEST_WIRE_STAGE_KEY.to_string(),
        RequestWireStage::PROVEN_NOT_SENT_TOKEN.to_string(),
    );
    ensure!(
        RequestWireStage::from_event_metadata(&releasing).hold_disposition()
            == HoldDisposition::ReleasableBeforeSubmission,
        "the exact proven-unsent token must still take the release edge"
    );
    println!("  fail-safe read-back: 7 damaged tokens all retain, exact token still releases");
    Ok(())
}

/// Recorded egress evidence crosses into audit storage and, for a managed
/// worker, into model-visible output. No credential material may ride along.
fn verify_no_bearer_material(metadata: &BTreeMap<String, String>) -> Result<()> {
    let excerpt = metadata
        .get("response_excerpt")
        .context("the dispatch event recorded no response excerpt")?;
    for marker in BEARER_MARKERS {
        ensure!(
            !excerpt.contains(marker),
            "recorded egress evidence carries credential marker {marker:?}: {excerpt}"
        );
    }
    Ok(())
}

/// The self-hosted surface is a DIFFERENT evidence shape (#247): report-only,
/// decision recorded rather than enforced. Pin what it does carry, and pin that
/// it does not silently claim a hold edge it never computed — an operator
/// reading this surface must not believe it authorizes a release.
fn verify_self_hosted_report_only(binary: &Path) -> Result<()> {
    let output = run_smoke(binary, &["--worker-type", "self-hosted"])?;
    let evidence = output
        .get("evidence")
        .and_then(Value::as_object)
        .context("self-hosted smoke emitted no evidence object")?;

    ensure!(
        evidence.get("workload_ran") == Some(&Value::Bool(true)),
        "the self-hosted workload must really run: {evidence:?}"
    );
    ensure!(
        evidence.get("report_only") == Some(&Value::Bool(true))
            && evidence.get("recorded_decision") == Some(&Value::String("denied".to_string())),
        "self-hosted must record the denied decision report-only: {evidence:?}"
    );
    ensure!(
        output
            .get("served_request")
            .and_then(Value::as_str)
            .is_some_and(|line| line.starts_with("GET /governed-rest-smoke ")),
        "the self-hosted report-only path must still put the request on the wire"
    );
    ensure!(
        !evidence.contains_key(EGRESS_REQUEST_WIRE_STAGE_KEY)
            && !evidence.contains_key(EGRESS_HOLD_DISPOSITION_KEY),
        "the self-hosted report-only surface must not claim a hold edge it never computed; if it \
         starts carrying one, this scenario must start verifying it instead of pinning its \
         absence: {evidence:?}"
    );
    println!("  self-hosted: workload ran report-only, no unearned hold edge claimed");
    Ok(())
}

#[cfg(test)]
#[path = "agent_worker_egress_wire_stage_test.rs"]
mod agent_worker_egress_wire_stage_test;
