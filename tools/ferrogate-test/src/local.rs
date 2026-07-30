// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::{
    assertions::{
        agent_run_otlp_trace_is_reconstructable, assert_secret_redacted, http_request_body,
    },
    constants::{ADMIN_AUTH, JSON_CONTENT},
    fixtures::{
        auth_service_config, blocking_stdio_mcp_script, local_gateway_config, LocalGatewayConfig,
    },
    http::{free_addr, http_request_addr},
    mocks::{
        spawn_local_provider_upstream, spawn_mock_agent_server, spawn_mock_billing_server,
        spawn_mock_mcp_server, spawn_mock_otlp_server, MockBillingServer, MockOtlpServer,
    },
    readiness::{
        require_service_ready, wait_for_gateway_start, ServiceStartOutcome, AUTH, BILLING,
    },
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    env,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// Readiness ceiling for the in-process local harness gateway. Deliberately much
/// tighter than [`crate::readiness::GATEWAY_READINESS_TIMEOUT`]: this gateway has
/// no storage bootstrap to wait on, and a short deadline is what lets a hijacked
/// port be rotated instead of eating the scenario's whole budget (#444).
const LOCAL_GATEWAY_READINESS_TIMEOUT: Duration = Duration::from_secs(20);

/// Readiness ceiling for the local harness `ferrogate-auth` child; preserved from
/// the status-only loop this replaced.
const AUTH_READINESS_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) struct AuthHarness {
    _dir: tempfile::TempDir,
    pub(crate) auth_addr: String,
    auth: Child,
}

impl AuthHarness {
    pub(crate) fn start(ferrogate_auth_bin: &Path) -> Result<Self> {
        if !ferrogate_auth_bin.exists() {
            bail!(
                "ferrogate-auth binary does not exist at {}; run `cargo build -p ferrogate-auth-service` first or pass --ferrogate-auth-bin",
                ferrogate_auth_bin.display()
            );
        }

        let auth_addr = free_addr()?;
        let dir = tempfile::tempdir()?;
        let config_path = dir.path().join("auth-service.yaml");
        std::fs::write(&config_path, auth_service_config())?;

        let auth = Command::new(ferrogate_auth_bin)
            .args(["serve", "--listen"])
            .arg(&auth_addr)
            .args(["--data"])
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            // #264: pipe stderr so an exit-before-readiness surfaces the child's
            // own error (drained into the bail) instead of a bare exit status.
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start {}", ferrogate_auth_bin.display()))?;

        let mut harness = Self {
            _dir: dir,
            auth_addr,
            auth,
        };
        harness.wait_for_auth()?;
        Ok(harness)
    }

    /// Readiness is the shared identity-checked decision (#444). `auth_addr` comes
    /// from `free_addr()`, so it carries the same release->rebind window as the
    /// gateway port: a parallel harness mock that wins it answers 200 to anything,
    /// and accepting that handed the whole scenario to a squatter. `ferrogate-auth`
    /// proves itself with `service: ferrogate-auth`, not the gateway's runtime
    /// header, so it is checked against its own identity.
    fn wait_for_auth(&mut self) -> Result<()> {
        let auth_addr = self.auth_addr.clone();
        require_service_ready(
            AUTH,
            &mut self.auth,
            &auth_addr,
            "local harness auth service",
            AUTH_READINESS_TIMEOUT,
        )
    }

    pub(crate) fn expect_json<F>(
        &self,
        method: &str,
        path: &str,
        headers: &[&str],
        body: &str,
        expected_status: u16,
        check: F,
    ) -> Result<()>
    where
        F: FnOnce(Value) -> Result<()>,
    {
        let response = http_request_addr(&self.auth_addr, method, path, headers, body)?;
        if response.status != expected_status {
            bail!(
                "{method} {path} expected status {expected_status}, got {}; raw: {}",
                response.status,
                response.raw
            );
        }
        let body: Value = serde_json::from_str(&response.body).with_context(|| {
            format!(
                "failed to parse JSON body for {method} {path}: {}",
                response.body
            )
        })?;
        check(body)
    }
}

impl Drop for AuthHarness {
    fn drop(&mut self) {
        let _ = self.auth.kill();
        let _ = self.auth.wait();
    }
}

/// A real `ferrogate billing serve` child process for the billing-chain E2E
/// (issues #129/#131/#134). Uses the built-in default rate card and an
/// in-memory ledger; a durable-Supabase variant can pass `--supabase-dsn`.
pub(crate) struct BillingHarness {
    pub(crate) billing_addr: String,
    billing: Child,
}

impl BillingHarness {
    pub(crate) fn start(ferrogate_bin: &Path) -> Result<Self> {
        Self::start_inner(ferrogate_bin, None)
    }

    pub(crate) fn start_supabase(
        ferrogate_bin: &Path,
        dsn: &str,
        schema: &str,
        tls_mode: &str,
    ) -> Result<Self> {
        Self::start_inner(ferrogate_bin, Some((dsn, schema, tls_mode)))
    }

    pub(crate) fn start_supabase_concurrent_pair(
        ferrogate_bin: &Path,
        dsn: &str,
        schema: &str,
        tls_mode: &str,
    ) -> Result<(Self, Self)> {
        // This is a bounded two-process correctness race for migration locking,
        // never a Supabase throughput or pressure test. Do not scale the pair
        // into a fan-out loop: live performance traffic belongs on local
        // infrastructure, not the shared external service.
        let (mut first, timeout) = Self::spawn_inner(ferrogate_bin, Some((dsn, schema, tls_mode)))?;
        let (mut second, _) = Self::spawn_inner(ferrogate_bin, Some((dsn, schema, tls_mode)))?;
        first.wait_for_billing(timeout)?;
        second.wait_for_billing(timeout)?;
        Ok((first, second))
    }

    fn start_inner(ferrogate_bin: &Path, supabase: Option<(&str, &str, &str)>) -> Result<Self> {
        let (mut harness, readiness_timeout) = Self::spawn_inner(ferrogate_bin, supabase)?;
        harness.wait_for_billing(readiness_timeout)?;
        Ok(harness)
    }

    fn spawn_inner(
        ferrogate_bin: &Path,
        supabase: Option<(&str, &str, &str)>,
    ) -> Result<(Self, Duration)> {
        if !ferrogate_bin.exists() {
            bail!(
                "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
                ferrogate_bin.display()
            );
        }

        let billing_addr = free_addr()?;
        let readiness_timeout = if supabase.is_some() {
            Duration::from_secs(180)
        } else {
            Duration::from_secs(20)
        };
        let mut command = Command::new(ferrogate_bin);
        command
            .args(["billing", "serve", "--listen"])
            .arg(&billing_addr)
            // Exercise the authenticated path (issue #136): the gateway config
            // carries the matching token, and the harness sends it on reads.
            .args(["--token", crate::constants::BILLING_SERVICE_TOKEN])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            // #264: pipe stderr so a start failure is self-diagnosing. On an
            // exit-before-readiness the child's stderr is drained into the bail
            // message instead of being silently discarded (the old default),
            // unless FERROGATE_TEST_DEBUG_STDERR=1 asks to stream it live.
            .stderr(
                if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
                    Stdio::inherit()
                } else {
                    Stdio::piped()
                },
            );
        if let Some((dsn, schema, tls_mode)) = supabase {
            // Keep the DSN out of argv/process listings. The live scenario owns
            // this unique schema and drops it after both billing and gateway
            // processes stop.
            command
                .env("FERROGATE_BILLING_SUPABASE_DSN", dsn)
                .env("FERROGATE_BILLING_SUPABASE_SCHEMA", schema)
                .env("FERROGATE_BILLING_SUPABASE_TLS_MODE", tls_mode)
                .env("FERROGATE_BILLING_SUPABASE_INIT_SCHEMA", "true");
        }
        let billing = command.spawn().with_context(|| {
            format!("failed to start {} billing serve", ferrogate_bin.display())
        })?;

        Ok((
            Self {
                billing_addr,
                billing,
            },
            readiness_timeout,
        ))
    }

    /// Readiness is the shared identity-checked decision (#444); see
    /// `AuthHarness::wait_for_auth` for why a bare 200 on a `free_addr()` port is
    /// not proof of identity. `/healthz` is exempt from the billing shared secret
    /// (#136), so a live service always answers it with its own identity. The
    /// caller's storage-derived ceiling is preserved, and the child's own stderr
    /// still reaches the failure message through `crate::readiness` (#264).
    fn wait_for_billing(&mut self, readiness_timeout: Duration) -> Result<()> {
        let billing_addr = self.billing_addr.clone();
        require_service_ready(
            BILLING,
            &mut self.billing,
            &billing_addr,
            "local harness billing service",
            readiness_timeout,
        )
    }

    /// Poll `GET /v1/billing/ledger` until an entry matching `matches` appears,
    /// returning that entry. The gateway reports usage fire-and-forget, so this
    /// tolerates the asynchronous settle by polling with a timeout.
    pub(crate) fn wait_for_ledger_entry<F>(&self, matches: F) -> Result<Value>
    where
        F: Fn(&Value) -> bool,
    {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(10) {
            match http_request_addr(
                &self.billing_addr,
                "GET",
                "/v1/billing/ledger?limit=200",
                &[crate::constants::BILLING_AUTH],
                "",
            ) {
                Ok(response) if response.status == 200 => {
                    let body: Value = serde_json::from_str(&response.body).with_context(|| {
                        format!("failed to parse billing ledger body: {}", response.body)
                    })?;
                    if let Some(entries) = body["entries"].as_array() {
                        if let Some(entry) = entries.iter().find(|entry| matches(entry)) {
                            return Ok(entry.clone());
                        }
                    }
                    last = response.body;
                }
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(150));
        }
        bail!(
            "timed out waiting for a matching billing ledger entry on {}; last ledger: {last}",
            self.billing_addr
        );
    }
}

impl Drop for BillingHarness {
    fn drop(&mut self) {
        let _ = self.billing.kill();
        let _ = self.billing.wait();
    }
}

#[derive(Clone, Copy)]
struct ProviderSecretBinding<'a> {
    secret_ref: &'a str,
    binding_env: &'a str,
    binding_value: &'a str,
}

#[derive(Default)]
struct LocalHarnessOptions<'a> {
    billing: Option<MockBillingServer>,
    auth_addr: Option<&'a str>,
    include_agent: bool,
    billing_service_addr: Option<&'a str>,
    provider_secret_binding: Option<ProviderSecretBinding<'a>>,
    config_template: Option<&'a str>,
    scheduler_tick_interval_secs: Option<u64>,
}

pub(crate) struct LocalHarness {
    _dir: tempfile::TempDir,
    config_path: PathBuf,
    pub(crate) gateway_addr: String,
    gateway: Child,
    provider: Option<JoinHandle<Vec<String>>>,
    provider_stop: Arc<AtomicBool>,
    mcp_server: Option<JoinHandle<Vec<String>>>,
    mcp_stop: Arc<AtomicBool>,
    agent_server: Option<JoinHandle<Vec<String>>>,
    agent_addr: Option<String>,
    billing: Option<MockBillingServer>,
    observability: Option<MockOtlpServer>,
}

impl LocalHarness {
    pub(crate) fn start(ferrogate_bin: &Path, expected_provider_requests: usize) -> Result<Self> {
        Self::start_inner(
            ferrogate_bin,
            expected_provider_requests,
            LocalHarnessOptions::default(),
        )
    }

    /// Start the standard local process harness with a test-owned config
    /// template. The template's `__FERROGATE_TEST_LISTEN__` marker is replaced
    /// with the reserved listener, while process readiness and teardown remain
    /// identical to the ordinary harness.
    pub(crate) fn start_with_config_template(
        ferrogate_bin: &Path,
        expected_provider_requests: usize,
        config_template: &str,
    ) -> Result<Self> {
        Self::start_inner(
            ferrogate_bin,
            expected_provider_requests,
            LocalHarnessOptions {
                config_template: Some(config_template),
                ..LocalHarnessOptions::default()
            },
        )
    }

    pub(crate) fn start_with_billing_and_agent(
        ferrogate_bin: &Path,
        expected_provider_requests: usize,
    ) -> Result<Self> {
        let billing = spawn_mock_billing_server(expected_provider_requests)
            .context("start billing provider")?;
        Self::start_inner(
            ferrogate_bin,
            expected_provider_requests,
            LocalHarnessOptions {
                billing: Some(billing),
                include_agent: true,
                ..LocalHarnessOptions::default()
            },
        )
    }

    pub(crate) fn start_with_external_auth(
        ferrogate_bin: &Path,
        expected_provider_requests: usize,
        auth_addr: &str,
    ) -> Result<Self> {
        Self::start_inner(
            ferrogate_bin,
            expected_provider_requests,
            LocalHarnessOptions {
                auth_addr: Some(auth_addr),
                ..LocalHarnessOptions::default()
            },
        )
    }

    pub(crate) fn start_with_billing_service(
        ferrogate_bin: &Path,
        expected_provider_requests: usize,
        billing_service_addr: &str,
    ) -> Result<Self> {
        Self::start_inner(
            ferrogate_bin,
            expected_provider_requests,
            LocalHarnessOptions {
                billing_service_addr: Some(billing_service_addr),
                ..LocalHarnessOptions::default()
            },
        )
    }

    /// Start a gateway whose primary provider credential can only resolve from
    /// one explicit secret-reference binding. Cloudflare REST credentials and
    /// the ordinary provider-key fallback are removed from the child process,
    /// so a `cf://` E2E cannot pass through an unrelated credential path.
    pub(crate) fn start_with_provider_secret_binding(
        ferrogate_bin: &Path,
        expected_provider_requests: usize,
        secret_ref: &str,
        binding_env: &str,
        binding_value: &str,
    ) -> Result<Self> {
        Self::start_inner(
            ferrogate_bin,
            expected_provider_requests,
            LocalHarnessOptions {
                provider_secret_binding: Some(ProviderSecretBinding {
                    secret_ref,
                    binding_env,
                    binding_value,
                }),
                ..LocalHarnessOptions::default()
            },
        )
    }

    fn start_inner(
        ferrogate_bin: &Path,
        expected_provider_requests: usize,
        options: LocalHarnessOptions<'_>,
    ) -> Result<Self> {
        let LocalHarnessOptions {
            billing,
            auth_addr,
            include_agent,
            billing_service_addr,
            provider_secret_binding,
            config_template,
            scheduler_tick_interval_secs,
        } = options;
        if !ferrogate_bin.exists() {
            bail!(
                "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
                ferrogate_bin.display()
            );
        }

        let provider_stop = Arc::new(AtomicBool::new(false));
        let (provider_addr, provider) =
            spawn_local_provider_upstream(expected_provider_requests, provider_stop.clone())
                .context("start provider")?;
        // The MCP mock serves for the whole harness lifetime and is torn down
        // deterministically on `Drop` via this stop flag (issue #431), instead of
        // a fixed wall-clock lifetime the long gateway-api MCP section could race.
        let mcp_stop = Arc::new(AtomicBool::new(false));
        let (mcp_addr, mcp_server) =
            spawn_mock_mcp_server(mcp_stop.clone()).context("start mcp provider")?;
        let (agent_addr, agent_server) = if include_agent {
            let (addr, server) = spawn_mock_agent_server().context("start agent provider")?;
            (Some(addr), Some(server))
        } else {
            (None, None)
        };
        let dir = tempfile::tempdir()?;
        let stdio_mcp_path = dir.path().join("blocking-stdio-mcp.py");
        std::fs::write(&stdio_mcp_path, blocking_stdio_mcp_script())?;
        let observability =
            spawn_mock_otlp_server().context("start observability provider mock")?;
        let config_path = dir.path().join("ferrogate.toml");

        // Render the gateway config for a given listener. Kept as a closure so a
        // hijacked gateway port can be rotated (see the start loop below) by
        // re-rendering with a fresh address rather than baking the port in once.
        let build_config = |gateway_addr: &str| -> Result<String> {
            if let Some(template) = config_template {
                const LISTEN_MARKER: &str = "__FERROGATE_TEST_LISTEN__";
                if !template.contains(LISTEN_MARKER) {
                    bail!("custom gateway config is missing {LISTEN_MARKER}");
                }
                Ok(template.replace(LISTEN_MARKER, gateway_addr))
            } else {
                Ok(local_gateway_config(LocalGatewayConfig {
                    gateway_addr,
                    provider_addr: &provider_addr,
                    mcp_addr: &mcp_addr,
                    agent_addr: agent_addr.as_deref().unwrap_or("http://127.0.0.1:1/a2a"),
                    stdio_mcp_path: &stdio_mcp_path,
                    billing: billing.as_ref(),
                    observability: Some(&observability),
                    auth_addr,
                    billing_service_addr,
                    primary_provider_secret_ref: provider_secret_binding
                        .as_ref()
                        .map(|binding| binding.secret_ref),
                    scheduler_tick_interval_secs,
                }))
            }
        };

        let spawn_gateway = |config_path: &Path| -> Result<Child> {
            let mut command = Command::new(ferrogate_bin);
            command
                .args(["run", "--config"])
                .arg(config_path)
                .env(
                    "FERROGATE_TEST_AWS_SECRET_ACCESS_KEY",
                    "ferrogate-test-aws-secret",
                )
                .env("FERROGATE_TEST_GCP_ACCESS_TOKEN", "ferrogate-test-gcp-token")
                // Enable the function egress broker (#119) for the org_demo client so
                // the function-egress scenario can exercise the live gateway pipeline.
                // The allowlisted base is deliberately unreachable so the test proves
                // auth + allowlist + token mint + build + egress-attempt without a TLS
                // upstream.
                .env("FG_FN_JWT_SECRET", "test-fn-signing-secret")
                .env("FG_FN_APIKEY", "test-project-anon-key")
                .env(
                    "FG_FN_ALLOWLIST",
                    r#"[{"tenant":"org_demo","base_url":"https://127.0.0.1:1","function_slugs":["charge-credits"]}]"#,
                )
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(
                    if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
                        Stdio::inherit()
                    } else {
                        Stdio::null()
                    },
                );
            if let Some(binding) = provider_secret_binding {
                command
                    .env_remove("FERROGATE_PROVIDER_SECRET")
                    .env_remove("CLOUDFLARE_ACCOUNT_ID")
                    .env_remove("CLOUDFLARE_API_TOKEN")
                    .env_remove("CLOUDFLARE_API_BASE_URL")
                    .env(binding.binding_env, binding.binding_value);
            } else {
                command.env("FERROGATE_PROVIDER_SECRET", "provider-secret");
            }
            command
                .spawn()
                .with_context(|| format!("failed to start {}", ferrogate_bin.display()))
        };

        // Start the gateway child and confirm a *FerroGate* is the process that
        // answers readiness on the configured port.
        //
        // `free_addr()` binds `127.0.0.1:0`, records the port, then drops the
        // listener before the child rebinds it. Allocating the gateway port after
        // every in-process `bind(:0)` mock keeps this process's own mocks off the
        // released port, but a mock in *another* parallel harness can still win it
        // inside that release->rebind window (#444). A squatter that wins the port
        // holds it for its whole lifetime while Pingora retries its bind forever,
        // so polling that address can never reach FerroGate. `crate::readiness`
        // identifies the responder for every harness-started gateway, and here a
        // proven hijack rotates to a fresh gateway port under a bounded retry
        // instead of silently trusting the squatter (the original flake) or
        // hanging until the readiness deadline.
        const MAX_GATEWAY_START_ATTEMPTS: usize = 5;
        let mut hijacked_addrs: Vec<String> = Vec::new();
        let (gateway, gateway_addr) = loop {
            let gateway_addr = free_addr()?;
            std::fs::write(&config_path, build_config(&gateway_addr)?)?;
            let mut gateway = spawn_gateway(&config_path)?;
            match wait_for_gateway_start(
                &mut gateway,
                &gateway_addr,
                "local harness gateway",
                LOCAL_GATEWAY_READINESS_TIMEOUT,
            )? {
                ServiceStartOutcome::Ready => break (gateway, gateway_addr),
                ServiceStartOutcome::PortHijacked => {
                    let _ = gateway.kill();
                    let _ = gateway.wait();
                    hijacked_addrs.push(gateway_addr);
                    if hijacked_addrs.len() >= MAX_GATEWAY_START_ATTEMPTS {
                        bail!(
                            "gateway port hijacked by a non-ferrogate process on every attempt \
                             ({} tries): {hijacked_addrs:?}",
                            hijacked_addrs.len(),
                        );
                    }
                }
            }
        };

        let harness = Self {
            _dir: dir,
            config_path,
            gateway_addr,
            gateway,
            provider: Some(provider),
            provider_stop,
            mcp_server: Some(mcp_server),
            mcp_stop,
            agent_server,
            agent_addr,
            billing,
            observability: Some(observability),
        };
        Ok(harness)
    }

    pub(crate) fn expect_json<F>(
        &self,
        method: &str,
        path: &str,
        headers: &[&str],
        body: &str,
        expected_status: u16,
        check: F,
    ) -> Result<()>
    where
        F: FnOnce(Value) -> Result<()>,
    {
        let response = http_request_addr(&self.gateway_addr, method, path, headers, body)?;
        if response.status != expected_status {
            bail!(
                "{method} {path} expected status {expected_status}, got {}; raw: {}",
                response.status,
                response.raw
            );
        }
        let body: Value = serde_json::from_str(&response.body).with_context(|| {
            format!(
                "failed to parse JSON body for {method} {path}: {}",
                response.body
            )
        })?;
        check(body)
    }

    pub(crate) fn enable_scheduler(&self, tick_interval_secs: u64) -> Result<()> {
        let mut config_toml = std::fs::read_to_string(&self.config_path)
            .with_context(|| format!("read {}", self.config_path.display()))?;
        if config_toml.contains("\n[scheduler]") || config_toml.starts_with("[scheduler]") {
            bail!(
                "local harness config already contains [scheduler]; refusing duplicate section in {}",
                self.config_path.display()
            );
        }
        config_toml.push_str(&format!(
            r#"
[scheduler]
enabled = true
tick_interval_secs = {tick_interval_secs}
"#
        ));
        std::fs::write(&self.config_path, &config_toml)
            .with_context(|| format!("write {}", self.config_path.display()))?;
        let payload = serde_json::json!({ "config_toml": config_toml }).to_string();
        self.expect_json(
            "POST",
            "/admin/v1/config/reload",
            &[ADMIN_AUTH, JSON_CONTENT],
            &payload,
            200,
            |body| {
                assert_eq!(body["valid"], true);
                assert_eq!(body["committed"], true);
                assert_eq!(body["listener_reload_required"], false);
                Ok(())
            },
        )
    }

    pub(crate) fn expect_text<F>(
        &self,
        method: &str,
        path: &str,
        headers: &[&str],
        body: &str,
        expected_status: u16,
        check: F,
    ) -> Result<()>
    where
        F: FnOnce(&str) -> Result<()>,
    {
        let response = http_request_addr(&self.gateway_addr, method, path, headers, body)?;
        if response.status != expected_status {
            bail!(
                "{method} {path} expected status {expected_status}, got {}; raw: {}",
                response.status,
                response.raw
            );
        }
        check(&response.body)
    }

    pub(crate) fn expect_mcp_json<F>(
        &self,
        method: &str,
        path: &str,
        headers: &[&str],
        body: &str,
        expected_status: u16,
        check: F,
    ) -> Result<()>
    where
        F: FnOnce(Value) -> Result<()>,
    {
        self.expect_json(method, path, headers, body, expected_status, check)
    }

    pub(crate) fn agent_endpoint(&self) -> Result<&str> {
        self.agent_addr
            .as_deref()
            .context("agent harness is not configured")
    }

    pub(crate) fn take_provider_requests(&mut self) -> Result<Vec<String>> {
        let Some(provider) = self.provider.take() else {
            bail!("provider mock request collector is not configured");
        };
        provider
            .join()
            .map_err(|_| anyhow::anyhow!("provider mock thread panicked"))
    }

    pub(crate) fn expect_openmeter_export(&self) -> Result<()> {
        let Some(billing) = &self.billing else {
            bail!("billing provider mock is not configured");
        };
        let mut last = None;
        let body = loop {
            let request = billing
                .received
                .recv_timeout(Duration::from_secs(5))
                .context("timed out waiting for OpenMeter export")?;
            assert!(request.starts_with("POST /api/v1/events "));
            assert!(request.contains("Authorization: Bearer test-metering-token"));
            let payload = http_request_body(&request)?;
            let body: Value = serde_json::from_str(payload)
                .with_context(|| format!("failed to parse billing export payload: {payload}"))?;
            let is_chat_usage = body["data"]["prompt_tokens"] == 1
                && body["data"]["completion_tokens"] == 1
                && body["data"]["total_tokens"] == 2;
            if is_chat_usage {
                break body;
            }
            last = Some(body);
        };
        assert_eq!(body["specversion"], "1.0");
        assert_eq!(body["type"], "ai.tokens");
        assert_eq!(body["source"], "ferrogate-test");
        assert_eq!(body["subject"], "client");
        assert!(body["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("ferrogate:")));
        assert_eq!(body["data"]["logical_model"], "fast-chat");
        assert_eq!(body["data"]["provider"], "openai");
        assert_eq!(body["data"]["provider_model"], "gpt-4o-mini");
        assert_eq!(body["data"]["prompt_tokens"], 1);
        assert_eq!(body["data"]["completion_tokens"], 1);
        assert_eq!(body["data"]["total_tokens"], 2);
        assert_eq!(body["data"]["tenant"]["organization_id"], "org_demo");
        assert_eq!(body["data"]["tenant"]["project_id"], "project_gateway");
        drop(last);
        Ok(())
    }

    pub(crate) fn wait_for_metering_export_status(&self) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(5) {
            let response = http_request_addr(
                &self.gateway_addr,
                "GET",
                "/admin/v1/metering-export-status",
                &[ADMIN_AUTH],
                "",
            )?;
            if response.status == 200
                && response.body.contains("openmeter")
                && response.body.contains("exported")
            {
                return Ok(());
            }
            last = response.raw;
            thread::sleep(Duration::from_millis(100));
        }
        bail!("timed out waiting for metering export status; last response: {last}")
    }

    pub(crate) fn expect_vector_otlp_export(&self) -> Result<()> {
        let Some(observability) = &self.observability else {
            bail!("observability provider mock is not configured");
        };
        let mut requests = Vec::new();
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(12) {
            let request = observability
                .received
                .recv_timeout(Duration::from_millis(500))
                .context("timed out waiting for Vector-compatible OTLP export")?;
            requests.push(request);
            if requests
                .iter()
                .any(|request| request.starts_with("POST /v1/metrics "))
                && requests
                    .iter()
                    .any(|request| request.starts_with("POST /v1/logs "))
                && requests
                    .iter()
                    .any(|request| request.starts_with("POST /v1/traces "))
            {
                break;
            }
        }
        let raw = requests.join("\n---otlp-request---\n");
        assert!(raw.contains("Content-Type: application/json"));
        assert!(
            raw.contains("POST /v1/metrics "),
            "missing OTLP metrics request: {raw}"
        );
        assert!(
            raw.contains("POST /v1/logs "),
            "missing OTLP logs request: {raw}"
        );
        assert!(
            raw.contains("POST /v1/traces "),
            "missing OTLP traces request: {raw}"
        );
        assert!(raw.contains("\"service.name\""));
        assert!(raw.contains("ferrogate-test"));
        assert!(raw.contains("ferrogate.request_logs"));
        assert!(raw.contains("ferrogate.billing_events"));
        assert!(raw.contains("ferrogate.gateway.request"));
        assert!(raw.contains("\"event_family\""));
        assert!(raw.contains("\"request\""));
        assert!(raw.contains("\"audit\""));
        assert!(raw.contains("\"billing_event_observed\""));
        assert!(raw.contains("\"audit_action\""));
        assert!(raw.contains("api_key.upsert"));
        assert!(raw.contains("logical_model"));
        assert!(raw.contains("fast-chat"));
        assert!(raw.contains("provider"));
        assert!(raw.contains("openai"));
        assert!(raw.contains("api_key_id"));
        assert!(raw.contains("test-client"));
        assert_secret_redacted(&raw);
        assert!(!raw.contains("provider-secret"));
        assert!(!raw.contains("test-secret"));
        Ok(())
    }

    pub(crate) fn expect_agent_run_otlp_trace_export(&self, agent_run_id: &str) -> Result<()> {
        let Some(observability) = &self.observability else {
            bail!("observability provider mock is not configured");
        };
        let mut trace_payloads = Vec::new();
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(12) {
            match observability
                .received
                .recv_timeout(Duration::from_millis(500))
            {
                Ok(request) => {
                    if !request.starts_with("POST /v1/traces ") {
                        continue;
                    }
                    let payload = http_request_body(&request)?.to_string();
                    trace_payloads.push(payload.clone());
                    let body = serde_json::from_str::<Value>(&payload).with_context(|| {
                        format!("failed to parse OTLP trace payload: {payload}")
                    })?;
                    if agent_run_otlp_trace_is_reconstructable(&body, agent_run_id)? {
                        assert_secret_redacted(&payload);
                        assert!(!payload.contains("provider-secret"));
                        assert!(!payload.contains("test-secret"));
                        return Ok(());
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        bail!(
            "timed out waiting for reconstructable OTLP trace for agent run {agent_run_id}; trace payloads: {}",
            trace_payloads.join("\n---otlp-trace-payload---\n")
        )
    }
}

impl Drop for LocalHarness {
    fn drop(&mut self) {
        let _ = self.gateway.kill();
        let _ = self.gateway.wait();
        if let Some(provider) = self.provider.take() {
            // Signal the provider mock to stop waiting for more requests so a
            // request-count mismatch does not block teardown up to 90s (#142).
            self.provider_stop.store(true, Ordering::Relaxed);
            let _ = provider.join();
        }
        if let Some(mcp_server) = self.mcp_server.take() {
            // Signal the MCP mock to stop accepting so teardown does not block on
            // its safety cap; the listener stays alive until exactly here (#431).
            self.mcp_stop.store(true, Ordering::Relaxed);
            let _ = mcp_server.join();
        }
        if let Some(agent_server) = self.agent_server.take() {
            let _ = agent_server.join();
        }
        if let Some(billing) = self.billing.as_mut() {
            let _ = billing.handle.take().map(|handle| handle.join());
        }
        if let Some(observability) = self.observability.as_mut() {
            let _ = observability.handle.take().map(|handle| handle.join());
        }
    }
}
