// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Opt-in live probe for the #442 production container-control transport bridge.

//! Gate-owned live validation for the #442 `ContainerControlClient::production`
//! reqwest bridge: drive a REAL `prepare` (and cleanup) round-trip against the
//! DEPLOYED agent-gateway Worker — proving auth header, instance naming, JSON
//! wire shapes, and the blocking bridge outside any mock. `prepare` is used
//! because it is validation-only on the Worker side; the deeper start/exec
//! lifecycle is gated on the #415 rework.
//!
//! Opt-in only — requires:
//!   FERROGATE_CF_GATEWAY_URL (e.g. https://ferrogate-agent-gateway.<acct>.workers.dev)
//!   FERROGATE_CF_GATEWAY_CONTROL_TOKEN
//!
//! `FERROGATE_CF_GATEWAY_URL` is the opt-in switch: unset, the probe prints a
//! notice and exits **0**, so running it without a deployed Worker is a no-op
//! rather than a failure. Set it with the control token missing and the probe
//! hard-errors — a half-configured environment is an operator mistake, not an
//! opt-out (#495, `ferrogate-storage/examples/support/probe_env.rs`).
//!
//! Run: cargo run -p ferrogate-runtime --example cf_container_live_probe

use ferrogate_runtime::{
    AgentInstanceIdentity, ContainerControlClient, ContainerInstanceTier, ContainerPrepareSpec,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Skip cleanly when the opt-in switch is absent (the gate sets it).
    let Ok(base_url) = std::env::var("FERROGATE_CF_GATEWAY_URL") else {
        println!(
            "cf_container_live_probe: SKIP (set FERROGATE_CF_GATEWAY_URL and \
             FERROGATE_CF_GATEWAY_CONTROL_TOKEN to run the live container-control bridge probe)"
        );
        return Ok(());
    };
    // Opted in but half-configured is a hard error, not a second opt-out.
    let token = std::env::var("FERROGATE_CF_GATEWAY_CONTROL_TOKEN").map_err(|_| {
        "FERROGATE_CF_GATEWAY_CONTROL_TOKEN is required once FERROGATE_CF_GATEWAY_URL is set \
         (the live probe is opted IN); unset FERROGATE_CF_GATEWAY_URL to skip it instead"
    })?;

    let client = ContainerControlClient::production(base_url, token)?;
    let identity = AgentInstanceIdentity::new("gate", "liveprobe", "prod-bridge");

    let prepared = client.prepare(
        &identity,
        &ContainerPrepareSpec {
            image: "docker.io/cloudflare/sandbox:0.12.4".to_string(),
            tier: ContainerInstanceTier::Lite,
            workspace_path: None,
        },
    )?;
    println!("prepare over production bridge: ok ({prepared:?})");

    client.cleanup(&identity)?;
    println!("cleanup: ok");
    println!("cf_container_live_probe: PASS");
    Ok(())
}
