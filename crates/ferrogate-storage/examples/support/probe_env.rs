// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Shared opt-in credential gate for the live D1 probes (#495) — skip cleanly with no creds, hard-error when half-configured.

//! The one place a `d1_live_*` probe may read its credentials from.
//!
//! Every probe in `examples/` is opt-in: it talks to a REAL Cloudflare account
//! and must be a no-op for the overwhelming majority of contributors, who have
//! no credentials. Before #495 each probe spelled that rule out for itself and
//! got it wrong the same way nine times over — a missing variable returned
//! `Err` from `main`, so `cargo run --example <probe>` exited **1**. The first
//! runner that loops over the probes would have read every one of them as a
//! failure. `examples/../ferrogate-cloudflare/examples/r2_live_probe.rs` had
//! the right convention (print a notice, exit 0) and this module is that
//! convention made shared, so the tenth probe cannot drift again.
//!
//! # The rule
//!
//! [`OPT_IN_VAR`] alone decides opt-in — it is the switch, not one credential
//! among many:
//!
//! * **unset (or empty) → SKIP.** Print a `SKIP:`-style notice naming every
//!   variable the probe needs and return `Ok(())`. Exit code 0.
//! * **set, but some other required variable is unset or empty → HARD ERROR.**
//!   The operator said "run live" and the environment cannot honour it. A half
//!   configured environment is an operator mistake, not an opt-out, and a probe
//!   that skipped there would let the gate believe it ran a live check that
//!   never ran — the "green guard holding nothing" failure this repo keeps
//!   filing (#499/#509/#510/#511). Loud and wrong beats quiet and wrong when
//!   the quiet answer is indistinguishable from success.
//!
//! This is exactly `r2_live_probe`'s behaviour, not a second convention: it
//! gates on [`OPT_IN_VAR`] and then fails outright if `FERROGATE_CF_API_TOKEN`
//! is missing (its `EnvTokenResolver` errors). The only differences here are
//! that the failure names every missing variable at once instead of the first,
//! and that an exported-but-empty value counts as unset — an empty string is
//! never a usable account id, database uuid or bearer token, and letting one
//! through only moves the failure to a confusing 401.
//!
//! # Using it
//!
//! ```ignore
//! #[path = "support/probe_env.rs"]
//! mod probe_env;
//!
//! const PROBE: &str = "d1_live_454_guardrail_cas_probe"; // == this file's stem
//!
//! async fn run() -> Result<(), Box<dyn std::error::Error>> {
//!     let Some(env) = probe_env::opt_in(PROBE, &["FERROGATE_CF_API_TOKEN"])? else {
//!         return Ok(());
//!     };
//!     let account_id = env.account_id();
//!     ...
//! }
//! ```
//!
//! [`OPT_IN_VAR`] is implicit — do not list it. `tests/d1_live_probe_env_audit.rs`
//! holds this contract over the real `examples/` tree: a new `d1_live_*.rs` that
//! reads `std::env::var` directly, skips the module, misnames its `PROBE`, or
//! reads a variable it never declared fails that audit.
//!
//! This file lives in `examples/support/` rather than `examples/` because Cargo
//! auto-discovers every `examples/*.rs` as its own example target; a nested
//! directory without a `main.rs` is not a target.

// Each probe declares only the variables it needs, so no single includer uses
// the whole surface; the audit test includes the module too, and uses less again.
#![allow(dead_code)]

/// The single variable that decides whether a live probe runs at all.
///
/// Every probe needs a Cloudflare account id, and nothing else in a developer
/// environment plausibly sets this name for an unrelated reason, which is what
/// makes it safe to read as an explicit "run the live probes" instruction.
pub const OPT_IN_VAR: &str = "FERROGATE_CF_ACCOUNT_ID";

/// The credentials a probe declared, every one of them proven present and
/// non-empty. Only [`resolve`] can build one, so holding a `ProbeEnv` *is* the
/// evidence that the environment is fully configured.
pub struct ProbeEnv {
    /// `(name, value)` in declaration order, [`OPT_IN_VAR`] first.
    values: Vec<(String, String)>,
}

impl ProbeEnv {
    /// The Cloudflare account id ([`OPT_IN_VAR`]), always present.
    pub fn account_id(&self) -> String {
        self.var(OPT_IN_VAR)
    }

    /// The value of a declared variable.
    ///
    /// Panics on a name the probe never declared to [`opt_in`], which is a bug
    /// in the probe rather than an environment problem. The panic is
    /// unreachable in practice because it needs live credentials to be reached
    /// at all; `tests/d1_live_probe_env_audit.rs` is what actually catches the
    /// undeclared read, statically and with no credentials.
    pub fn var(&self, name: &str) -> String {
        self.values
            .iter()
            .find(|(declared, _)| declared == name)
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| {
                panic!(
                    "{name} was read but never declared to probe_env::opt_in; add it to the \
                     probe's required list"
                )
            })
    }
}

/// What [`resolve`] decided about an environment.
pub enum Outcome {
    /// Not opted in: print `notice` and exit 0.
    Skip {
        /// The full one-line notice, naming every variable the probe needs.
        notice: String,
    },
    /// Opted in and fully configured.
    Ready(ProbeEnv),
}

/// The decision, over an arbitrary environment.
///
/// `lookup` is a parameter so the rule above can be *executed* against a
/// half-configured environment in a test, with no credentials and without
/// mutating the process environment (which is global to a test binary and
/// therefore racy). `required` must not include [`OPT_IN_VAR`]; it is implicit.
pub fn resolve(
    probe: &str,
    required: &[&str],
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Outcome, String> {
    let declared = |joiner: &str| {
        std::iter::once(OPT_IN_VAR)
            .chain(required.iter().copied())
            .collect::<Vec<_>>()
            .join(joiner)
    };

    let Some(account_id) = present(&lookup, OPT_IN_VAR) else {
        return Ok(Outcome::Skip {
            notice: format!(
                "{probe}: SKIP (live probe is opt-in; set {} to run it)",
                declared(", ")
            ),
        });
    };

    let mut values = vec![(OPT_IN_VAR.to_string(), account_id)];
    let mut missing = Vec::new();
    for name in required {
        match present(&lookup, name) {
            Some(value) => values.push(((*name).to_string(), value)),
            None => missing.push(*name),
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "{probe}: {OPT_IN_VAR} is set, so the live probe is opted IN, but these required \
             variables are unset or empty: {}. A half-configured environment is an operator \
             mistake, not an opt-out — set them (the probe needs {}), or unset {OPT_IN_VAR} to \
             skip the probe entirely.",
            missing.join(", "),
            declared(", "),
        ));
    }
    Ok(Outcome::Ready(ProbeEnv { values }))
}

/// The value of `name` if it is set to something other than whitespace.
fn present(lookup: &impl Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    lookup(name).filter(|value| !value.trim().is_empty())
}

/// [`resolve`] against the process environment: prints the notice and yields
/// `None` when the probe should skip, so a probe's whole missing-credential
/// path is `else { return Ok(()) }`.
pub fn opt_in(
    probe: &str,
    required: &[&str],
) -> Result<Option<ProbeEnv>, Box<dyn std::error::Error>> {
    match resolve(probe, required, |name| std::env::var(name).ok())? {
        Outcome::Skip { notice } => {
            println!("{notice}");
            Ok(None)
        }
        Outcome::Ready(env) => Ok(Some(env)),
    }
}
