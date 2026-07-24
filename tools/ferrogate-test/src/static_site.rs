// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Docker-free E2E coverage for the static-site publish/serve/per-file family (#441).

//! End-to-end proof of the static-site asset family over a real gateway
//! (#441, gate-owned harness growth): a #397 zip bundle is published through
//! the REAL `PUT /v1/assets/static_site/{site}/{version}` surface (per-file
//! objects under `__site_file__:{version}:{path}` + a serving channel), the
//! site serves from `/sites/{tenant}/{site}/…`, and the console-facing
//! bare-path per-file surfaces work against it:
//!
//! - `GET /v1/assets/static_site/{site}/{percent-encoded-path}` resolves a
//!   nested file of the published bundle — the #402 bare-path → prefixed-key
//!   remap on top of the #398 encoded-slash decode.
//! - `DELETE` on the same bare path unpublishes exactly that file; the site
//!   root (and the reserved `__site_manifest__`) keep serving.
//! - A legacy-shaped site (non-zip push, no serving channel) still round-trips
//!   its bare path unchanged — the #402 guard's passthrough case.

use crate::{
    cli::LocalArgs,
    constants::JSON_CONTENT,
    http::{free_addr, http_request_addr, HttpResponse},
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    env, fs,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const ADMIN_AUTH: &str = "Authorization: Bearer site-e2e-admin-secret";
const CLIENT_AUTH: &str = "Authorization: Bearer site-e2e-client-secret";
const TENANT: &str = "org_site_e2e";
const SITE: &str = "docs-site";
const LEGACY_SITE: &str = "legacy-blob-site";
const NESTED_PATH: &str = "docs/deep/readme.md";
const NESTED_PATH_ENCODED: &str = "docs%2Fdeep%2Freadme.md";
const NESTED_CONTENT: &[u8] = b"# deep readme for the #402 remap";
const GATEWAY_READINESS_TIMEOUT: Duration = Duration::from_secs(180);

pub(crate) fn run_static_site_api(args: &LocalArgs) -> Result<()> {
    if !args.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
            args.ferrogate_bin.display()
        );
    }

    let gateway_addr = free_addr()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("static-site.yaml");
    fs::write(&config_path, scenario_config(&gateway_addr))?;
    let _gateway = GatewayGuard::start(&args.ferrogate_bin, &config_path, &gateway_addr)?;

    // Hosting is plan-gated (#168): create a plan with asset_hosting_enabled
    // and bind the tenant to it through the real Admin API.
    let plan = http_request_addr(
        &gateway_addr,
        "POST",
        "/admin/v1/plans",
        &[ADMIN_AUTH, JSON_CONTENT],
        r#"{"id":"site-e2e-plan","name":"Site E2E plan","slug":"site-e2e-plan","asset_hosting_enabled":true}"#,
    )?;
    if plan.status != 200 && plan.status != 201 {
        bail!("failed to create hosting plan: {}", plan.raw);
    }
    let tenant = http_request_addr(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[ADMIN_AUTH, JSON_CONTENT],
        &format!(
            r#"{{"id":"{TENANT}","name":"Site E2E","slug":"site-e2e","plan_id":"site-e2e-plan"}}"#
        ),
    )?;
    if tenant.status != 200 && tenant.status != 201 {
        bail!("failed to create hosting tenant: {}", tenant.raw);
    }

    // Publish a #397 zip bundle (stored entries; the unpacker does not
    // validate CRCs) with a nested path for the encoded-slash surfaces.
    let bundle = build_stored_zip(&[
        ("index.html", b"<h1>site e2e</h1>" as &[u8]),
        ("style.css", b"body{}"),
        (NESTED_PATH, NESTED_CONTENT),
    ]);
    let published = crate::http::http_request_addr_bytes(
        &gateway_addr,
        "PUT",
        &format!("/v1/assets/static_site/{SITE}/v1"),
        &[
            CLIENT_AUTH,
            "Content-Type: application/zip",
            // Explicit public opt-in (#397 serving policy): the site serves
            // anonymously, which is also what the serve assertions below rely on.
            "x-site-public: true",
        ],
        &bundle,
    )?;
    if published.status != 200 && published.status != 201 {
        bail!("bundle publish failed: {}", published.raw);
    }

    // The bundle serves: root resolves index.html, the nested path serves its
    // exact bytes.
    let root = http_request_addr(
        &gateway_addr,
        "GET",
        &format!("/sites/{TENANT}/{SITE}/"),
        &[],
        "",
    )?;
    if root.status != 200 || !root.body.contains("site e2e") {
        bail!("published site root did not serve index.html: {}", root.raw);
    }
    let nested_serve = http_request_addr(
        &gateway_addr,
        "GET",
        &format!("/sites/{TENANT}/{SITE}/{NESTED_PATH}"),
        &[],
        "",
    )?;
    if nested_serve.status != 200 || nested_serve.body.as_bytes() != NESTED_CONTENT {
        bail!(
            "nested path did not serve from the bundle: {}",
            nested_serve.raw
        );
    }

    // #402 + #398: the console-facing bare per-file download resolves the
    // #397 `__site_file__:{version}:{path}` key from the percent-encoded bare
    // path of the SERVING bundle.
    let bare_download = http_request_addr(
        &gateway_addr,
        "GET",
        &format!("/v1/assets/static_site/{SITE}/{NESTED_PATH_ENCODED}"),
        &[CLIENT_AUTH],
        "",
    )?;
    if bare_download.status != 200 || bare_download.body.as_bytes() != NESTED_CONTENT {
        bail!(
            "bare-path per-file download did not resolve the #397 bundle file: {}",
            bare_download.raw
        );
    }

    // Per-file unpublish on the same bare path removes exactly that file …
    let unpublish = http_request_addr(
        &gateway_addr,
        "DELETE",
        &format!("/v1/assets/static_site/{SITE}/{NESTED_PATH_ENCODED}"),
        &[CLIENT_AUTH],
        "",
    )?;
    if unpublish.status != 200 {
        bail!("bare-path per-file unpublish failed: {}", unpublish.raw);
    }
    let gone = http_request_addr(
        &gateway_addr,
        "GET",
        &format!("/v1/assets/static_site/{SITE}/{NESTED_PATH_ENCODED}"),
        &[CLIENT_AUTH],
        "",
    )?;
    if gone.status != 404 {
        bail!(
            "unpublished file still resolves (expected 404): {}",
            gone.raw
        );
    }
    // … while the site root (manifest + remaining files) keeps serving.
    let root_after = http_request_addr(
        &gateway_addr,
        "GET",
        &format!("/sites/{TENANT}/{SITE}/"),
        &[],
        "",
    )?;
    if root_after.status != 200 || !root_after.body.contains("site e2e") {
        bail!(
            "site root stopped serving after a per-file unpublish: {}",
            root_after.raw
        );
    }

    // Legacy control (#402 guard passthrough): a non-zip static_site push has
    // no serving channel; its bare path must round-trip byte-for-byte exactly
    // as before the remap existed.
    let legacy = push_asset(
        &gateway_addr,
        &format!("/v1/assets/static_site/{LEGACY_SITE}/v1"),
        "text/plain",
        b"legacy opaque blob",
    )?;
    if legacy.status != 200 && legacy.status != 201 {
        bail!("legacy-site push failed: {}", legacy.raw);
    }
    let legacy_pull = http_request_addr(
        &gateway_addr,
        "GET",
        &format!("/v1/assets/static_site/{LEGACY_SITE}/v1"),
        &[CLIENT_AUTH],
        "",
    )?;
    if legacy_pull.status != 200 || legacy_pull.body != "legacy opaque blob" {
        bail!(
            "legacy bare-path pull no longer round-trips: {}",
            legacy_pull.raw
        );
    }

    println!("static-site-api scenario passed");
    Ok(())
}

fn push_asset(addr: &str, path: &str, content_type: &str, body: &[u8]) -> Result<HttpResponse> {
    let content_type_header = format!("Content-Type: {content_type}");
    crate::http::http_request_addr_bytes(
        addr,
        "PUT",
        path,
        &[CLIENT_AUTH, &content_type_header],
        body,
    )
}

/// Minimal stored-method zip (no compression; the gateway's unpacker does not
/// validate CRCs) — the same construction the sites unit tests use.
fn build_stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();

    for (name, data) in entries {
        let offset = out.len() as u32;
        let name_bytes = name.as_bytes();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn scenario_config(gateway_addr: &str) -> String {
    format!(
        r#"listen: {gateway_addr:?}
cluster:
  enabled: true
  cluster_id: "static-site-e2e"
  node_id: "static-site-node"
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
  - id: "site-e2e-admin"
    name: "Static site E2E host operator"
    key: "site-e2e-admin-secret"
    scopes: ["admin.read", "admin.write"]
  - id: "site-e2e-client"
    name: "Static site E2E tenant client"
    key: "site-e2e-client-secret"
    scopes: ["assets.read", "assets.write"]
    organization_id: "org_site_e2e"
    project_id: "project_site_e2e"
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
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < GATEWAY_READINESS_TIMEOUT {
            if let Some(status) = self.child.try_wait()? {
                bail!("FerroGate exited before static-site E2E readiness: {status}");
            }
            match http_request_addr(gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("timed out waiting for the static-site E2E gateway: {last}")
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// Silence an unused-import lint if Value ends up unneeded during evolution.
#[allow(unused)]
fn _assert_json(_: &Value) {}
