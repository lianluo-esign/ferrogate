// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Docker-free E2E coverage for the Cloudflare Worker branch of /v1/functions/execute (#435).

//! End-to-end proof that the `/v1/functions/execute` Cloudflare branch (#435)
//! is operator-selectable and fail-closed through the real gateway: the broker
//! is enabled with `FG_FN_TARGET_KIND=cloudflare_worker` + `FG_FN_CF_WORKER`,
//! and live HTTP requests walk the same status ladder the Supabase scenario
//! uses — 401 unauthenticated, 403 `function_denied` for a non-allowlisted or
//! traversal invoke path, and 502 `function_upstream_error` on the allowlisted
//! path against a deliberately unreachable https Worker base. Reaching 502
//! proves auth → allowlist → scoped-token mint → governed request build →
//! egress attempt all ran on the Cloudflare branch (mirroring the Supabase
//! scenario's design; no TLS upstream needed).

use crate::{
    cli::LocalArgs,
    constants::JSON_CONTENT,
    http::{free_addr, http_request_addr, HttpResponse},
    readiness::{require_gateway_ready, GATEWAY_READINESS_TIMEOUT},
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    env, fs,
    path::Path,
    process::{Child, Command, Stdio},
};

const CLIENT_AUTH: &str = "Authorization: Bearer cf-fn-client-secret";
const WORKER_BASE: &str = "https://127.0.0.1:1";

pub(crate) fn run_function_egress_cloudflare_api(args: &LocalArgs) -> Result<()> {
    if !args.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
            args.ferrogate_bin.display()
        );
    }

    let gateway_addr = free_addr()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("function-egress-cloudflare.yaml");
    fs::write(&config_path, scenario_config(&gateway_addr))?;
    let _gateway = GatewayGuard::start(&args.ferrogate_bin, &config_path, &gateway_addr)?;

    // Unauthenticated -> 401 (the Cloudflare branch is enabled, so this is an
    // auth failure, not a 503 disabled-broker response).
    let unauthenticated = execute(&gateway_addr, &[JSON_CONTENT], "charge-credits")?;
    if unauthenticated.status != 401 {
        bail!(
            "unauthenticated CF function execute expected 401, got {}; raw: {}",
            unauthenticated.status,
            unauthenticated.raw
        );
    }

    // Authenticated, invoke path not on the tenant allowlist -> 403 fail-closed.
    let denied = execute(
        &gateway_addr,
        &[CLIENT_AUTH, JSON_CONTENT],
        "not-allowlisted",
    )?;
    assert_json_error(
        &denied,
        403,
        "function_denied",
        "non-allowlisted invoke path",
    )?;

    // Authenticated, traversal invoke path -> 403 fail-closed via the #416
    // InvalidWorkerTarget deny (never reaches egress).
    let traversal = execute(&gateway_addr, &[CLIENT_AUTH, JSON_CONTENT], "../secrets")?;
    assert_json_error(&traversal, 403, "function_denied", "traversal invoke path")?;

    // Authenticated + allowlisted: the gateway authorizes against the single
    // declared Worker, mints a scoped token, builds the governed request, and
    // attempts egress to the unreachable Worker base -> 502. Reaching this
    // status proves the whole Cloudflare-branch pipeline ran end to end.
    let upstream = execute(
        &gateway_addr,
        &[CLIENT_AUTH, JSON_CONTENT],
        "charge-credits",
    )?;
    assert_json_error(
        &upstream,
        502,
        "function_upstream_error",
        "allowlisted invoke path (full pipeline)",
    )?;

    println!("function-egress-cloudflare-api scenario passed");
    Ok(())
}

fn execute(addr: &str, headers: &[&str], invoke_path: &str) -> Result<HttpResponse> {
    let body = serde_json::json!({
        "target": {
            "base_url": WORKER_BASE,
            "invoke_path": invoke_path,
            // The wire ref is deliberately attacker-controlled junk: #435
            // replaces it with the operator-declared FG_FN_CF_WORKER ref
            // before the governed pipeline runs.
            "auth_key_ref": "secret:wire-ref-must-not-be-trusted"
        },
        "body_json": "{\"amount\":5}"
    })
    .to_string();
    http_request_addr(addr, "POST", "/v1/functions/execute", headers, &body)
}

fn scenario_config(gateway_addr: &str) -> String {
    format!(
        r#"listen: {gateway_addr:?}
cluster:
  enabled: true
  cluster_id: "cf-fn-egress-e2e"
  node_id: "cf-fn-egress-node"
  node_region: "local"
  node_zone: "local-a"
  state_backend: "local"
  counter_backend: "local"
providers:
  - name: "openai"
    kind: "openai"
    base_url: "http://127.0.0.1:1/v1"
    api_key_env: "FERROGATE_PROVIDER_SECRET"
models:
  - name: "fast-chat"
    provider: "openai"
    provider_model: "gpt-4o-mini"
    capabilities: ["chat"]
api_keys:
  - id: "cf-fn-client"
    name: "Cloudflare function egress E2E client"
    key: "cf-fn-client-secret"
    scopes: ["functions.execute"]
    organization_id: "org_cf_fn_e2e"
    project_id: "project_cf_fn_e2e"
"#
    )
}

struct GatewayGuard {
    child: Child,
}

impl GatewayGuard {
    fn start(binary: &Path, config_path: &Path, gateway_addr: &str) -> Result<Self> {
        let child = Command::new(binary)
            .args(["run", "--config"])
            .arg(config_path)
            .env("FERROGATE_PROVIDER_SECRET", "provider-secret")
            // The Cloudflare branch of the function egress broker (#435): the
            // declared Worker base is deliberately unreachable so the scenario
            // proves auth + allowlist + token mint + governed build + egress
            // attempt without a TLS upstream (same design as the Supabase
            // scenario's FG_FN_* block).
            .env("FG_FN_TARGET_KIND", "cloudflare_worker")
            .env("FG_FN_JWT_SECRET", "cf-fn-signing-secret")
            .env(
                "FG_FN_CF_WORKER",
                format!(
                    r#"{{"base_url":"{WORKER_BASE}","invoke_path":"charge-credits","auth_key_ref":"secret:worker-bearer"}}"#
                ),
            )
            .env(
                "FG_FN_ALLOWLIST",
                format!(
                    r#"[{{"tenant":"org_cf_fn_e2e","base_url":"{WORKER_BASE}","function_slugs":["charge-credits"]}}]"#
                ),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(
                if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
                    Stdio::inherit()
                } else {
                    Stdio::null()
                },
            )
            .spawn()
            .with_context(|| format!("failed to start {}", binary.display()))?;
        let mut guard = Self { child };
        guard.wait_for_readiness(gateway_addr)?;
        Ok(guard)
    }

    fn wait_for_readiness(&mut self, gateway_addr: &str) -> Result<()> {
        require_gateway_ready(
            &mut self.child,
            gateway_addr,
            "CF function egress E2E gateway",
            GATEWAY_READINESS_TIMEOUT,
        )
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn assert_json_error(response: &HttpResponse, status: u16, code: &str, what: &str) -> Result<()> {
    if response.status != status {
        bail!(
            "{what}: expected {status}, got {}; raw: {}",
            response.status,
            response.raw
        );
    }
    let body: Value = serde_json::from_str(&response.body)
        .with_context(|| format!("{what}: error body was not JSON: {}", response.body))?;
    if body["error"]["code"] != code {
        bail!("{what}: expected error code {code}, got: {body}");
    }
    Ok(())
}
