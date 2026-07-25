// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Unit tests for the live R2-token probe's #489 cleanup ordering — a failing revoke must still delete the bucket.

//! Executable pins for the #489 cleanup invariant in `r2_token_live_probe`.
//!
//! The probe itself needs live Cloudflare credentials, which made its cleanup
//! ordering unpinnable and let a `revoke(...).await?` regression sail through a
//! green suite. [`cleanup_and_finish`](crate::cleanup_and_finish) takes the two
//! cleanup steps as **lazy futures**, so "was this step run?" is directly
//! observable here with no network: a step that is dropped instead of awaited
//! never records itself.
//!
//! This file lives in `examples/support/` rather than `examples/` because Cargo
//! auto-discovers every `examples/*.rs` as its own example target; a nested
//! directory without a `main.rs` is not a target.

use std::cell::RefCell;

use crate::{cleanup_and_finish, ProbeResult};

/// Records which cleanup steps actually ran, in order.
struct CleanupLog(RefCell<Vec<&'static str>>);

impl CleanupLog {
    fn new() -> Self {
        Self(RefCell::new(Vec::new()))
    }

    /// A cleanup step that records itself and then yields `outcome`.
    async fn step(&self, name: &'static str, outcome: ProbeResult) -> ProbeResult {
        self.0.borrow_mut().push(name);
        outcome
    }

    fn ran(&self) -> Vec<&'static str> {
        self.0.borrow().clone()
    }
}

/// `cleanup_and_finish` holds `RefCell` borrows across awaits, so it must run on
/// a single-threaded runtime — which is also what the probe's `main` uses.
fn block_on(future: impl std::future::Future<Output = ProbeResult>) -> ProbeResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime")
        .block_on(future)
}

fn boom(what: &str) -> Box<dyn std::error::Error> {
    what.into()
}

/// **The #489 regression guard.** A revoke that fails must NOT skip the bucket
/// delete: `revoke.await?` would return early and leak both a live
/// bucket-scoped token and the probe bucket into a real Cloudflare account.
#[test]
fn a_failing_revoke_still_runs_the_bucket_delete() {
    let log = CleanupLog::new();

    let result = block_on(cleanup_and_finish(
        Ok(()),
        log.step("revoke", Err(boom("revoke of token tok123 failed"))),
        log.step("delete", Ok(())),
    ));

    assert_eq!(
        log.ran(),
        vec!["revoke", "delete"],
        "a failing revoke must not short-circuit the bucket delete (#489)"
    );
    let err = result.expect_err("the revoke failure must still be raised");
    assert!(
        err.to_string().contains("revoke of token tok123 failed"),
        "the revoke failure must survive cleanup, got: {err}"
    );
}

/// The mirror direction: a failing bucket delete is reported after a successful
/// revoke, so neither step can hide the other.
#[test]
fn a_failing_bucket_delete_is_raised_after_a_successful_revoke() {
    let log = CleanupLog::new();

    let result = block_on(cleanup_and_finish(
        Ok(()),
        log.step("revoke", Ok(())),
        log.step("delete", Err(boom("delete of bucket probe-1 failed"))),
    ));

    assert_eq!(log.ran(), vec!["revoke", "delete"]);
    let err = result.expect_err("the delete failure must be raised");
    assert!(
        err.to_string().contains("delete of bucket probe-1 failed"),
        "got: {err}"
    );
}

/// Precedence: the probe's own failure is the diagnostic that matters, so it is
/// re-raised ahead of any cleanup failure — and cleanup still runs in full.
#[test]
fn a_probe_failure_takes_precedence_and_still_runs_every_cleanup_step() {
    let log = CleanupLog::new();

    let result = block_on(cleanup_and_finish(
        Err(boom("token policy is not scoped to the probe bucket")),
        log.step("revoke", Err(boom("revoke of token tok123 failed"))),
        log.step("delete", Err(boom("delete of bucket probe-1 failed"))),
    ));

    assert_eq!(
        log.ran(),
        vec!["revoke", "delete"],
        "cleanup must run in full even when the probe checks failed (#489)"
    );
    let err = result.expect_err("a failed probe must fail the run");
    assert!(
        err.to_string()
            .contains("token policy is not scoped to the probe bucket"),
        "the probe failure must win over cleanup failures, got: {err}"
    );
}

/// The happy path stays green: both cleanup steps run and the probe passes.
#[test]
fn a_clean_run_attempts_both_cleanup_steps_and_succeeds() {
    let log = CleanupLog::new();

    let result = block_on(cleanup_and_finish(
        Ok(()),
        log.step("revoke", Ok(())),
        log.step("delete", Ok(())),
    ));

    assert_eq!(log.ran(), vec!["revoke", "delete"]);
    result.expect("a clean probe run must succeed");
}
