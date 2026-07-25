// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Opt-in live R2 bucket-provisioning probe for the test gate (#461): real create/list/delete lifecycle.

//! Gate-owned live validation probe for the #461 R2 bucket-provisioning surface.
//!
//! Runs the REAL [`CloudflareClient`] R2 methods against a REAL Cloudflare
//! account: create a uniquely-named probe bucket, verify `list_r2_buckets` sees
//! it, then delete it and verify the exact name is gone. The probe bucket is
//! **self-cleaned even on failure** (the delete runs before any error from the
//! assertion phase is propagated), and re-running idempotent-create against the
//! existing bucket is exercised too.
//!
//! Both list assertions depend on `list_r2_buckets` walking every page (issue
//! #490): on a page-1-only list the "probe visible" check fails spuriously and
//! the "absent after delete" check passes vacuously, because the probe name
//! need never have been on the first page at all.
//!
//! Opt-in only — requires (same convention as `d1_live_probe`):
//!   FERROGATE_CF_ACCOUNT_ID  — Cloudflare account id
//!   FERROGATE_CF_API_TOKEN   — account API token with **Workers R2 Storage**
//!                              (Read, Edit) permission, presented as Bearer
//!
//! SKIPS cleanly (prints a notice, exits 0) when `FERROGATE_CF_ACCOUNT_ID` is
//! unset, so `cargo run --example r2_live_probe` is a no-op without creds; the
//! gate, which has real CF creds, runs the full lifecycle.
//!
//! Run: cargo run -p ferrogate-cloudflare --example r2_live_probe

use std::sync::Arc;

use ferrogate_cloudflare::r2::R2CreateBucketRequest;
use ferrogate_cloudflare::{CloudflareClient, CloudflareConfig, EnvTokenResolver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The workspace tokio has no `macros` feature; build the runtime manually.
    tokio::runtime::Runtime::new()?.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Skip cleanly when the opt-in creds are absent (the gate sets them).
    let Ok(account_id) = std::env::var("FERROGATE_CF_ACCOUNT_ID") else {
        println!(
            "r2_live_probe: SKIP (set FERROGATE_CF_ACCOUNT_ID and FERROGATE_CF_API_TOKEN to run \
             the live R2 bucket-provisioning probe)"
        );
        return Ok(());
    };
    let config = CloudflareConfig::new(account_id, "env://FERROGATE_CF_API_TOKEN");
    let client = Arc::new(CloudflareClient::new(
        config,
        Arc::new(EnvTokenResolver::from_process_env()),
    )?);

    // R2 bucket names: 3–63 chars, lowercase alphanumeric + hyphens. A
    // timestamp keeps concurrent/aborted runs disjoint.
    let name = format!(
        "ferrogate-gate-probe-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    );
    println!("probe bucket: {name}");

    let created = client
        .create_r2_bucket(&R2CreateBucketRequest::named(name.clone()))
        .await?;
    if !created.was_created() {
        return Err(format!("probe bucket {name} already existed before the run").into());
    }
    println!("created: {name}");

    // Everything between create and delete is fallible; capture its result so
    // the bucket is deleted on BOTH success and failure (RAII-style cleanup).
    let checks = async {
        let listed = client.list_r2_buckets().await?;
        if !listed
            .iter()
            .any(|b| b.name.as_deref() == Some(name.as_str()))
        {
            return Err("list_r2_buckets did not include the probe bucket".into());
        }
        println!(
            "list_r2_buckets: probe visible among {} buckets",
            listed.len()
        );

        // Idempotent-create against the now-existing bucket must be Ok (no-op).
        let again = client
            .create_r2_bucket(&R2CreateBucketRequest::named(name.clone()))
            .await?;
        if again.was_created() {
            return Err("idempotent create reported Created for an existing bucket".into());
        }
        println!("idempotent re-create: ok (AlreadyExists)");
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    // Cleanup runs on success AND failure; exact-name verification after.
    client.delete_r2_bucket(&name).await?;
    let remaining = client.list_r2_buckets().await?;
    if remaining
        .iter()
        .any(|b| b.name.as_deref() == Some(name.as_str()))
    {
        return Err("probe bucket still listed after delete".into());
    }
    println!("deleted + verified absent");

    checks?;
    println!("r2_live_probe: PASS");
    Ok(())
}
