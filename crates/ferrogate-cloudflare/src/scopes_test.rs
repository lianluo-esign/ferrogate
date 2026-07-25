// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Behavioural pins for the required token permission groups — what preflight tells an operator, and doc/code parity.

//! Executable pins for [`crate::scopes::REQUIRED_TOKEN_PERMISSION_GROUPS`].
//!
//! The table only earns its keep through two observable behaviours, and both
//! are asserted here rather than the list's contents:
//!
//! 1. **What an under-scoped operator is told.** A token that authenticates but
//!    lacks a permission group makes
//!    [`CloudflareClient::preflight`](crate::CloudflareClient::preflight) fail
//!    with [`CloudflareError::MissingScope`], whose `required` list *is* the
//!    remediation instructions. Dropping a row silently removes a group from
//!    those instructions — which is the #489 defect — so the assertions below
//!    drive `preflight` end-to-end over a scripted transport and pin the
//!    operator-visible outcome, not the constant.
//! 2. **Doc/code parity.** `docs/cloudflare-integration.md` §9 claims to match
//!    this table "byte-for-byte"; nothing enforced that, so the operator-facing
//!    doc and the machine list could drift in either direction. The parity test
//!    reads the shipped doc with `include_str!` and compares the parsed rows.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::client::{
    Clock, CloudflareClient, HttpRequest, HttpResponse, HttpTransport, RetryPolicy,
};
use crate::config::CloudflareConfig;
use crate::error::CloudflareError;
use crate::resolver::EnvTokenResolver;
use crate::scopes::REQUIRED_TOKEN_PERMISSION_GROUPS;

/// The operator-facing doc whose §9 table claims parity with the code table.
const INTEGRATION_DOC: &str = include_str!("../../../docs/cloudflare-integration.md");

/// Cloudflare's answer to a token that authenticates but is not scoped for the
/// resource: HTTP 403 with error code 9109 ("Unauthorized to access requested
/// resource"). This is the exact wire shape the #489 defect surfaced on.
const UNDER_SCOPED_BODY: &str = r#"{ "success": false, "errors": [{ "code": 9109, "message": "Unauthorized to access requested resource" }], "result": null }"#;

/// A transport that answers every request with one canned response.
struct CannedTransport {
    status: u16,
    body: &'static str,
}

#[async_trait]
impl HttpTransport for CannedTransport {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, CloudflareError> {
        Ok(HttpResponse {
            status: self.status,
            retry_after: None,
            body: self.body.as_bytes().to_vec(),
        })
    }
}

/// A clock that never sleeps (nothing under test here is retryable anyway).
struct NoSleepClock;

#[async_trait]
impl Clock for NoSleepClock {
    async fn sleep(&self, _duration: Duration) {}
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("test runtime")
}

/// Run a real `preflight` against an under-scoped Cloudflare answer and return
/// the typed error an operator would see.
fn preflight_against_under_scoped_cloudflare() -> CloudflareError {
    let client = CloudflareClient::from_parts(
        // Inline plaintext token: no env/network needed to resolve.
        CloudflareConfig::new("acct-test", "plaintext-token"),
        Arc::new(EnvTokenResolver::from_process_env()),
        Arc::new(CannedTransport {
            status: 403,
            body: UNDER_SCOPED_BODY,
        }),
        Arc::new(NoSleepClock),
        RetryPolicy {
            max_retries: 0,
            base_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(1),
        },
    );
    runtime()
        .block_on(client.preflight(None))
        .expect_err("an under-scoped token must fail preflight")
}

fn required_groups_from_preflight() -> Vec<&'static str> {
    match preflight_against_under_scoped_cloudflare() {
        CloudflareError::MissingScope { required, .. } => required,
        other => panic!("expected MissingScope from an under-scoped preflight, got {other:?}"),
    }
}

/// **The #489 regression guard.** An operator whose token is missing the
/// `API Tokens (Write)` group must be *told* to grant it: without that group
/// the #462 per-tenant path cannot `POST`/`DELETE
/// /accounts/{account_id}/tokens`, and a remediation list that omits it sends
/// the operator back into exactly the state this issue exists to prevent.
///
/// The assertion is on the preflight *outcome*, not on the constant, so
/// deleting the `API Tokens` row from `REQUIRED_TOKEN_PERMISSION_GROUPS` turns
/// this red.
#[test]
fn preflight_tells_an_under_scoped_operator_to_grant_api_tokens_for_the_462_mint_path() {
    let required = required_groups_from_preflight();

    assert!(
        required.contains(&"API Tokens"),
        "preflight must name the API Tokens group so an operator can mint/revoke \
         bucket-scoped R2 tokens (#462/#489); it named: {required:?}"
    );
}

/// The whole remediation list, not two spot-checks: dropping *any* row silently
/// narrows what an operator is told to grant, so the full set is pinned in the
/// order the client reports it.
#[test]
fn preflight_names_every_required_permission_group_in_order() {
    let required = required_groups_from_preflight();

    assert_eq!(
        required,
        vec![
            "AI Gateway",
            "Secrets Store",
            "D1",
            "Workers Scripts",
            "Workers R2 Storage",
            "API Tokens",
            "Cloudflare Pages",
            "Workflows (Workers Scripts)",
        ],
        "preflight's remediation list changed; update docs/cloudflare-integration.md §9 too"
    );
}

/// The list has to survive rendering: an operator reads the error *message*,
/// not the enum's fields.
#[test]
fn the_missing_scope_message_an_operator_reads_names_api_tokens() {
    let rendered = preflight_against_under_scoped_cloudflare().to_string();

    assert!(
        rendered.contains("API Tokens"),
        "the operator-facing preflight failure must name API Tokens: {rendered}"
    );
    assert!(
        rendered.contains("permission group"),
        "message was: {rendered}"
    );
}

/// A correctly scoped token must NOT be told to go grant anything — the guard
/// above would also pass if preflight failed for everyone.
#[test]
fn a_correctly_scoped_token_passes_preflight() {
    let client = CloudflareClient::from_parts(
        CloudflareConfig::new("acct-test", "plaintext-token"),
        Arc::new(EnvTokenResolver::from_process_env()),
        Arc::new(CannedTransport {
            status: 200,
            body: r#"{ "success": true, "errors": [], "result": { "id": "acct-test" } }"#,
        }),
        Arc::new(NoSleepClock),
        RetryPolicy {
            max_retries: 0,
            base_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(1),
        },
    );

    runtime()
        .block_on(client.preflight(None))
        .expect("a scoped token must pass preflight");
}

/// Parse the §9 "Required token-scopes table" out of the operator doc into
/// `(permission group, access, used_by)` triples, in document order.
///
/// Markdown emphasis/code ticks are stripped so the doc stays free to format
/// (`` `cf://` ``) without the comparison caring.
fn scope_rows_from_the_operator_doc() -> Vec<(String, String, String)> {
    let mut rows = Vec::new();
    let mut in_table = false;
    for line in INTEGRATION_DOC.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("| Permission group") && trimmed.contains("| Access") {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        if !trimmed.starts_with('|') {
            break;
        }
        let cells: Vec<String> = trimmed
            .trim_matches('|')
            .split('|')
            .map(|cell| cell.trim().trim_matches('`').replace(['`', '*'], ""))
            .collect();
        // The `|---|---|---|` separator row.
        if cells.iter().all(|cell| cell.chars().all(|c| c == '-')) {
            continue;
        }
        assert_eq!(
            cells.len(),
            3,
            "§9 scope table rows must have 3 columns, got: {trimmed}"
        );
        rows.push((cells[0].clone(), cells[1].clone(), cells[2].clone()));
    }
    rows
}

/// The doc calls itself "**authoritative**" and claims it "matches the
/// foundation client's preflight set byte-for-byte". Nothing enforced that, so
/// the table an operator provisions from could drift from the table the code
/// reports — including losing the `API Tokens (Write)` row on either side.
///
/// This also pins the `access` column, which no runtime path reads: `Write` vs
/// `Read` is the difference between a token that can mint scoped R2 credentials
/// and one that cannot.
#[test]
fn the_operator_doc_scope_table_matches_the_code_table_row_for_row() {
    let documented = scope_rows_from_the_operator_doc();
    assert!(
        !documented.is_empty(),
        "failed to locate the §9 required token-scopes table in \
         docs/cloudflare-integration.md — the parser, not the table, is probably broken"
    );

    let in_code: Vec<(String, String, String)> = REQUIRED_TOKEN_PERMISSION_GROUPS
        .iter()
        .map(|g| {
            (
                g.name.to_string(),
                g.access.to_string(),
                g.used_by.replace('`', ""),
            )
        })
        .collect();

    assert_eq!(
        documented, in_code,
        "docs/cloudflare-integration.md §9 drifted from \
         REQUIRED_TOKEN_PERMISSION_GROUPS (scopes.rs); they must agree row for row"
    );
}
