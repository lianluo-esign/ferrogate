// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::{
    fixtures::auth_service_config,
    http::{free_addr, http_request_addr},
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    thread,
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
