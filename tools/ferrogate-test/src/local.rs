// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::{
    assertions::{
        agent_run_otlp_trace_is_reconstructable, assert_secret_redacted, http_request_body,
    },
    constants::ADMIN_AUTH,
    fixtures::{
        auth_service_config, blocking_stdio_mcp_script, local_gateway_config, LocalGatewayConfig,
    },
    http::{free_addr, http_request_addr},
    mocks::{
        spawn_local_provider_upstream, spawn_mock_agent_server, spawn_mock_billing_server,
        spawn_mock_mcp_server, spawn_mock_otlp_server, MockBillingServer, MockOtlpServer,
    },
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    env,
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub(crate) struct AuthHarness {
    _dir: tempfile::TempDir,
    pub(crate) auth_addr: String,
    auth: Child,
}

impl AuthHarness {
    pub(crate) fn start(ferrogate_auth_bin: &Path) -> Result<Self> {
        if !ferrogate_auth_bin.exists() {
            bail!(
                "ferrogate-auth binary does not exist at {}; run `cargo build -p ferrogate-auth` first or pass --ferrogate-auth-bin",
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
            .stderr(Stdio::null())
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

    fn wait_for_auth(&mut self) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(20) {
            if let Some(status) = self.auth.try_wait()? {
                bail!("ferrogate-auth process exited before readiness check: {status}");
            }
            match http_request_addr(&self.auth_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!(
            "timed out waiting for ferrogate-auth on {}; last response: {last}",
            self.auth_addr
        );
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

pub(crate) struct LocalHarness {
    _dir: tempfile::TempDir,
    pub(crate) gateway_addr: String,
    gateway: Child,
    provider: Option<JoinHandle<Vec<String>>>,
    mcp_server: Option<JoinHandle<Vec<String>>>,
    agent_server: Option<JoinHandle<Vec<String>>>,
    agent_addr: Option<String>,
    billing: Option<MockBillingServer>,
    observability: Option<MockOtlpServer>,
}

impl LocalHarness {
    pub(crate) fn start(ferrogate_bin: &Path, expected_provider_requests: usize) -> Result<Self> {
        Self::start_inner(ferrogate_bin, expected_provider_requests, None, None, false)
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
            Some(billing),
            None,
            true,
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
            None,
            Some(auth_addr),
            false,
        )
    }

    fn start_inner(
        ferrogate_bin: &Path,
        expected_provider_requests: usize,
        billing: Option<MockBillingServer>,
        auth_addr: Option<&str>,
        include_agent: bool,
    ) -> Result<Self> {
        if !ferrogate_bin.exists() {
            bail!(
                "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
                ferrogate_bin.display()
            );
        }

        let gateway_addr = free_addr()?;
        let (provider_addr, provider) =
            spawn_local_provider_upstream(expected_provider_requests).context("start provider")?;
        let (mcp_addr, mcp_server) = spawn_mock_mcp_server().context("start mcp provider")?;
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
        std::fs::write(
            &config_path,
            local_gateway_config(LocalGatewayConfig {
                gateway_addr: &gateway_addr,
                provider_addr: &provider_addr,
                mcp_addr: &mcp_addr,
                agent_addr: agent_addr.as_deref().unwrap_or("http://127.0.0.1:1/a2a"),
                stdio_mcp_path: &stdio_mcp_path,
                billing: billing.as_ref(),
                observability: Some(&observability),
                auth_addr,
            }),
        )?;

        let gateway = Command::new(ferrogate_bin)
            .args(["run", "--config"])
            .arg(&config_path)
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
            .with_context(|| format!("failed to start {}", ferrogate_bin.display()))?;

        let mut harness = Self {
            _dir: dir,
            gateway_addr,
            gateway,
            provider: Some(provider),
            mcp_server: Some(mcp_server),
            agent_server,
            agent_addr,
            billing,
            observability: Some(observability),
        };
        harness.wait_for_gateway()?;
        Ok(harness)
    }

    fn wait_for_gateway(&mut self) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(20) {
            if let Some(status) = self.gateway.try_wait()? {
                bail!("ferrogate process exited before readiness check: {status}");
            }
            match http_request_addr(&self.gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!(
            "timed out waiting for ferrogate on {}; last response: {last}",
            self.gateway_addr
        );
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
            let _ = provider.join();
        }
        if let Some(mcp_server) = self.mcp_server.take() {
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
