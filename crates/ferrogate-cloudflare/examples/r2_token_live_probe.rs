// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Opt-in live scoped-R2-token probe for the test gate (#462): real create -> assert bucket-scoped -> revoke, self-cleaning.

//! Gate-owned live validation probe for the #462 scoped R2 API-token surface.
//!
//! Runs the REAL [`CloudflareClient`] against a REAL Cloudflare account:
//!
//! 1. ensure a uniquely-named probe bucket (reusing #461's ensure);
//! 2. mint a **bucket-scoped** read+write R2 token for it
//!    ([`CloudflareClient::create_scoped_r2_token`]);
//! 3. assert the credential shape (Access Key ID == token id; secret is a
//!    64-char lowercase-hex SHA-256) and that the token is genuinely
//!    bucket-scoped — re-read via `GET /accounts/{account_id}/tokens/{id}` and
//!    confirm its policy `resources` names exactly the probe bucket;
//! 4. **revoke the token on BOTH success and failure** (RAII-style), then delete
//!    the probe bucket. Cleanup is *unconditional in both directions*: a failing
//!    revoke does not skip the bucket delete (and vice versa) — each failure is
//!    reported and re-raised only after every cleanup step has been attempted,
//!    so no probe bucket or live token is ever left behind (#489).
//!
//! Step 4 is the invariant this probe exists to hold, so it is factored into
//! [`cleanup_and_finish`] and **unit-tested in place** — see
//! `examples/support/r2_token_live_probe_test.rs`. `cargo test
//! -p ferrogate-cloudflare` runs those tests (the `[[example]]` target sets
//! `test = true`), so breaking the ordering turns the suite red without any
//! Cloudflare credentials.
//!
//! Opt-in only — requires (same convention as `r2_live_probe`, #461):
//!   FERROGATE_CF_ACCOUNT_ID  — Cloudflare account id
//!   FERROGATE_CF_API_TOKEN   — account API token with **Workers R2 Storage**
//!                              (Read, Edit) **and the user-scoped API Tokens
//!                              (Write)** permission (the latter is needed to
//!                              mint/revoke scoped tokens, and is granted via
//!                              the dashboard's "Create additional tokens"
//!                              template), presented as Bearer
//!
//! SKIPS cleanly (prints a notice, exits 0) when `FERROGATE_CF_ACCOUNT_ID` is
//! unset, so `cargo run --example r2_token_live_probe` is a no-op without creds;
//! the gate, which has real CF creds, runs the full lifecycle.
//!
//! Run: cargo run -p ferrogate-cloudflare --example r2_token_live_probe

use std::future::Future;
use std::sync::Arc;

use ferrogate_cloudflare::r2::R2CreateBucketRequest;
use ferrogate_cloudflare::r2_token::R2ScopedTokenRequest;
use ferrogate_cloudflare::{CloudflareClient, CloudflareConfig, EnvTokenResolver};

/// Every probe step is fallible and the failures come from different layers
/// (Cloudflare errors, shape assertions), so they are boxed into one type.
pub(crate) type ProbeResult = Result<(), Box<dyn std::error::Error>>;

fn main() -> ProbeResult {
    // The workspace tokio has no `macros` feature; build the runtime manually.
    tokio::runtime::Runtime::new()?.block_on(run())
}

async fn run() -> ProbeResult {
    // Skip cleanly when the opt-in creds are absent (the gate sets them).
    let Ok(account_id) = std::env::var("FERROGATE_CF_ACCOUNT_ID") else {
        println!(
            "r2_token_live_probe: SKIP (set FERROGATE_CF_ACCOUNT_ID and FERROGATE_CF_API_TOKEN to \
             run the live scoped-R2-token probe)"
        );
        return Ok(());
    };
    let config = CloudflareConfig::new(account_id.clone(), "env://FERROGATE_CF_API_TOKEN");
    let client = Arc::new(CloudflareClient::new(
        config,
        Arc::new(EnvTokenResolver::from_process_env()),
    )?);

    // R2 bucket names: 3–63 chars, lowercase alphanumeric + hyphens. A timestamp
    // keeps concurrent/aborted runs disjoint.
    let bucket = format!(
        "ferrogate-tok-probe-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    );
    println!("probe bucket: {bucket}");

    let created = client
        .create_r2_bucket(&R2CreateBucketRequest::named(bucket.clone()))
        .await?;
    if !created.was_created() {
        return Err(format!("probe bucket {bucket} already existed before the run").into());
    }
    println!("created bucket: {bucket}");

    // Mint the bucket-scoped token. If minting itself fails there is no token to
    // revoke, but the probe bucket must still be cleaned up.
    let token_name = format!("ferrogate-r2-{bucket}");
    let token = match client
        .create_scoped_r2_token(&R2ScopedTokenRequest::read_write(
            token_name.clone(),
            bucket.clone(),
        ))
        .await
    {
        Ok(token) => token,
        Err(mint_err) => {
            let _ = client.delete_r2_bucket(&bucket).await;
            return Err(mint_err.into());
        }
    };
    let token_id = token.token_id.clone();
    println!("minted scoped token id: {token_id}");

    // Everything between mint and cleanup is fallible; capture its result so the
    // token is revoked and the bucket deleted on BOTH success and failure.
    let checks = async {
        // Credential shape: Access Key ID == token id; secret is 64-char lower-hex.
        if token.access_key_id != token.token_id {
            return Err("access_key_id must equal the token id".into());
        }
        if token.secret_access_key.len() != 64
            || !token
                .secret_access_key
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err("secret_access_key is not a 64-char lowercase-hex SHA-256".into());
        }
        println!("credential shape ok (AKID == token id; 64-hex secret)");

        // Prove bucket-scoping: re-read the token and confirm its policy resources
        // name exactly the probe bucket.
        let detail: serde_json::Value = client
            .get_json(&format!("accounts/{{account_id}}/tokens/{token_id}"), None)
            .await?;
        let expected_scope = format!("com.cloudflare.edge.r2.bucket.{account_id}_default_{bucket}");
        let scoped = detail["policies"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|p| p["resources"].as_object())
            .any(|res| res.contains_key(&expected_scope));
        if !scoped {
            return Err(format!(
                "token policy is not scoped to the probe bucket (expected resource \
                 {expected_scope}); got policies: {}",
                detail["policies"]
            )
            .into());
        }
        println!("bucket-scope verified: {expected_scope}");
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    cleanup_and_finish(
        checks,
        async {
            match client.revoke_r2_token(&token_id).await {
                Ok(()) => {
                    println!("revoked token: {token_id}");
                    Ok(())
                }
                Err(err) => Err(format!("revoke of token {token_id} failed: {err}").into()),
            }
        },
        async {
            match client.delete_r2_bucket(&bucket).await {
                Ok(()) => {
                    println!("deleted bucket: {bucket}");
                    Ok(())
                }
                Err(err) => Err(format!("delete of bucket {bucket} failed: {err}").into()),
            }
        },
    )
    .await?;

    println!("r2_token_live_probe: PASS");
    Ok(())
}

/// Attempt **both** cleanup steps, then fold the three outcomes in precedence
/// order: probe `checks` first, then `revoke`, then `delete`.
///
/// This is the #489 invariant in executable form, and it has two halves:
///
/// * **Unconditional cleanup.** `revoke` is awaited into a *value*, never
///   `?`-ed. Writing `revoke.await?` here would return before `delete` is ever
///   polled — leaking BOTH a live bucket-scoped token and the probe bucket into
///   a real Cloudflare account, which is exactly the defect #489 was filed for.
/// * **Error precedence.** `checks?` is re-raised first, so a cleanup failure
///   never masks the real probe failure; cleanup failures surface only when the
///   probe itself passed.
///
/// The futures are passed lazily (nothing is polled until awaited here), so a
/// dropped step is observably a step that never ran — which is what the sibling
/// unit tests assert.
pub(crate) async fn cleanup_and_finish(
    checks: ProbeResult,
    revoke: impl Future<Output = ProbeResult>,
    delete: impl Future<Output = ProbeResult>,
) -> ProbeResult {
    let revoked = revoke.await;
    if let Err(err) = &revoked {
        eprintln!("cleanup WARNING: {err}");
    }
    let bucket_deleted = delete.await;
    if let Err(err) = &bucket_deleted {
        eprintln!("cleanup WARNING: {err}");
    }

    checks?;
    revoked?;
    bucket_deleted?;
    Ok(())
}

#[cfg(test)]
#[path = "support/r2_token_live_probe_test.rs"]
mod r2_token_live_probe_test;
