// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Opt-in live D1 probe for the test gate (#440): real create/query/delete lifecycle.

//! Gate-owned live validation probe for the #420/#440 D1 backend surface.
//!
//! Runs the REAL `D1Client` against a REAL Cloudflare account: create a
//! uniquely-named database, run DDL + parameterized INSERT/SELECT through
//! `/query`, verify `list_databases` sees it, then delete it and verify the
//! exact name is gone (RAII-style cleanup on the happy path; on failure the
//! probe name is printed so an operator can clean up).
//!
//! Opt-in only — requires:
//!   FERROGATE_CF_ACCOUNT_ID / FERROGATE_CF_API_TOKEN
//! Run: cargo run -p ferrogate-cloudflare --example d1_live_probe

use std::sync::Arc;

use ferrogate_cloudflare::d1::{D1Client, D1CreateDatabaseRequest};
use ferrogate_cloudflare::{CloudflareClient, CloudflareConfig, EnvTokenResolver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The workspace tokio has no `macros` feature; build the runtime manually.
    tokio::runtime::Runtime::new()?.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let account_id = std::env::var("FERROGATE_CF_ACCOUNT_ID")
        .map_err(|_| "FERROGATE_CF_ACCOUNT_ID is required (live probe is opt-in)")?;
    let config = CloudflareConfig::new(account_id, "env://FERROGATE_CF_API_TOKEN");
    let client = CloudflareClient::new(config, Arc::new(EnvTokenResolver::from_process_env()))?;
    let d1 = D1Client::new(Arc::new(client));

    // Unique per-run name; timestamp keeps concurrent/aborted runs disjoint.
    let name = format!(
        "ferrogate-gate-probe-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    );
    println!("probe database: {name}");

    let created = d1
        .create_database(&D1CreateDatabaseRequest::named(name.clone()))
        .await?;
    let id = created
        .uuid
        .clone()
        .ok_or("create_database returned no uuid")?;
    println!("created: uuid={id}");

    // DDL + parameterized write + read through the real /query surface.
    let run = async {
        d1.query(
            &id,
            "CREATE TABLE gate_probe (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
            &[],
        )
        .await?;
        d1.query(
            &id,
            "INSERT INTO gate_probe (k, v) VALUES (?1, ?2)",
            &["gate".to_string(), "live-d1-#440".to_string()],
        )
        .await?;
        let rows = d1
            .query(
                &id,
                "SELECT v FROM gate_probe WHERE k = ?1",
                &["gate".to_string()],
            )
            .await?;
        let value = rows
            .first()
            .and_then(|r| r.results.first())
            .and_then(|row| row.get("v"))
            .and_then(|v| v.as_str())
            .ok_or("SELECT returned no rows")?
            .to_string();
        if value != "live-d1-#440" {
            return Err(format!("round-trip mismatch: {value}").into());
        }
        println!("query round-trip: ok ({value})");

        let listed = d1.list_databases().await?;
        if !listed
            .iter()
            .any(|db| db.name.as_deref() == Some(name.as_str()))
        {
            return Err("list_databases did not include the probe database".into());
        }
        println!(
            "list_databases: probe visible among {} databases",
            listed.len()
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    // Cleanup runs on success AND failure; exact-name verification after.
    d1.delete_database(&id).await?;
    let remaining = d1.list_databases().await?;
    if remaining
        .iter()
        .any(|db| db.name.as_deref() == Some(name.as_str()))
    {
        return Err("probe database still listed after delete".into());
    }
    println!("deleted + verified absent");

    run?;
    println!("d1_live_probe: PASS");
    Ok(())
}
