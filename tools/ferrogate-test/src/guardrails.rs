// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Live Supabase end-to-end coverage for the Guardrail detector runtime.

use crate::{
    cli::SupabaseLiveRestartArgs,
    http::{free_addr, http_request_addr, HttpResponse},
    mocks::{read_http_request, spawn_local_provider_upstream},
};
use anyhow::{bail, Context, Result};
use native_tls::{Certificate, TlsConnector};
use postgres::{config::SslMode, Client, Config as PostgresConfig};
use postgres_native_tls::MakeTlsConnector;
use serde_json::Value;
use std::{
    env, fs,
    io::Write,
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CLIENT_AUTH: &str = "Authorization: Bearer guardrail-client-secret";
const ADMIN_AUTH: &str = "Authorization: Bearer guardrail-admin-secret";
const JSON_CONTENT: &str = "Content-Type: application/json";
const DETECTOR_SECRET: &str = "guardrail-detector-e2e-secret";

pub(crate) fn run_guardrail_supabase(args: &SupabaseLiveRestartArgs) -> Result<()> {
    if args.supabase_dsn.trim().is_empty() {
        bail!("--supabase-dsn must not be empty");
    }
    if !args.local.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
            args.local.ferrogate_bin.display()
        );
    }

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_millis();
    let schema = format!("ferrogate_guardrail_e2e_{suffix}");
    let mut evidence = SupabaseEvidence::connect(args, schema.clone())?;

    let gateway_addr = free_addr()?;
    let provider_stop = Arc::new(AtomicBool::new(false));
    let (provider_addr, provider_handle) =
        spawn_local_provider_upstream(1, Arc::clone(&provider_stop))
            .context("start local model provider")?;
    let mut provider = ProviderGuard::new(provider_stop, provider_handle);
    let mut detector = MockDetector::start(2)?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("guardrail-supabase.yaml");
    fs::write(
        &config_path,
        guardrail_supabase_config(&gateway_addr, &provider_addr, &detector.addr, &schema, args)?,
    )?;

    let gateway = GatewayGuard::start(
        &args.local.ferrogate_bin,
        &config_path,
        &gateway_addr,
        args.supabase_dsn.trim(),
    )?;

    let detected = send_chat(&gateway_addr, "my email is pii@example.com")?;
    assert_json_error(&detected, 403, "guardrail_pii_detected")?;

    let allowed = send_chat(&gateway_addr, "ordinary safe request")?;
    if allowed.status != 200 {
        bail!(
            "safe Guardrail request expected 200, got {}; raw: {}",
            allowed.status,
            allowed.raw
        );
    }
    let allowed_body: Value = serde_json::from_str(&allowed.body)
        .with_context(|| format!("safe provider response was not JSON: {}", allowed.body))?;
    if allowed_body["choices"][0]["message"]["content"] != "ok" {
        bail!("safe request did not reach the local model provider");
    }

    let detector_requests = detector.join()?;
    if detector_requests.len() != 2 {
        bail!(
            "Guardrail detector expected 2 requests, got {}",
            detector_requests.len()
        );
    }
    for request in &detector_requests {
        let lowercase = request.to_ascii_lowercase();
        if !lowercase.contains(&format!(
            "authorization: bearer {}",
            DETECTOR_SECRET.to_ascii_lowercase()
        )) {
            bail!("Guardrail detector request did not contain the resolved bearer credential");
        }
        if !request.contains("\"contract_version\":1")
            || !request.contains("\"organization_id\":\"org_guardrail_e2e\"")
            || !request.contains("\"model\":\"fast-chat\"")
            || !request.contains("\"provider\":\"openai\"")
        {
            bail!("Guardrail detector request omitted required execution context");
        }
    }

    let provider_requests = provider.join()?;
    if provider_requests.len() != 1 || !provider_requests[0].contains("ordinary safe request") {
        bail!("only the safe request should reach the model provider");
    }

    // The detector listener is now closed. A new request must fail closed and
    // generate both runtime metrics and durable Supabase evidence.
    let unavailable = send_chat(&gateway_addr, "detector must now fail closed")?;
    assert_json_error(&unavailable, 403, "guardrail_provider_unavailable")?;
    let request_id = response_header(&unavailable, "x-request-id")
        .context("Guardrail failure response omitted x-request-id")?;

    let metrics = http_request_addr(&gateway_addr, "GET", "/metrics", &[ADMIN_AUTH], "")?;
    if metrics.status != 200
        || !metrics
            .body
            .lines()
            .any(|line| line == "ferrogate_guardrail_detector_errors_total 1")
    {
        bail!(
            "Guardrail detector failure metric missing or incorrect: {}",
            metrics.body
        );
    }

    evidence.wait_for_detector_error(&request_id)?;
    drop(gateway);
    evidence.cleanup()?;
    println!("guardrail-supabase scenario passed");
    Ok(())
}

fn send_chat(addr: &str, content: &str) -> Result<HttpResponse> {
    let body = serde_json::json!({
        "model": "fast-chat",
        "messages": [{"role": "user", "content": content}],
        "stream": false
    })
    .to_string();
    http_request_addr(
        addr,
        "POST",
        "/v1/chat/completions",
        &[CLIENT_AUTH, JSON_CONTENT],
        &body,
    )
}

fn assert_json_error(response: &HttpResponse, status: u16, code: &str) -> Result<()> {
    if response.status != status {
        bail!(
            "Guardrail error expected status {status}, got {}; raw: {}",
            response.status,
            response.raw
        );
    }
    let body: Value = serde_json::from_str(&response.body)
        .with_context(|| format!("Guardrail error body was not JSON: {}", response.body))?;
    if body["error"]["code"] != code {
        bail!(
            "Guardrail error expected code {code}, got {}",
            body["error"]["code"]
        );
    }
    Ok(())
}

fn response_header(response: &HttpResponse, expected_name: &str) -> Option<String> {
    response.raw.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(expected_name)
            .then(|| value.trim().to_string())
    })
}

fn guardrail_supabase_config(
    gateway_addr: &str,
    provider_addr: &str,
    detector_addr: &str,
    schema: &str,
    args: &SupabaseLiveRestartArgs,
) -> Result<String> {
    let tls_mode = match args.tls_mode.as_str() {
        "require" | "verify_ca" | "verify_full" => args.tls_mode.as_str(),
        other => bail!(
            "--tls-mode must be require, verify_ca, or verify_full for live Supabase, got {other}"
        ),
    };
    let ca_path = args
        .tls_ca_cert_path
        .as_ref()
        .map(|path| {
            format!(
                "  postgres_tls_ca_cert_path: {}\n",
                yaml_string(&path.to_string_lossy())
            )
        })
        .unwrap_or_default();
    Ok(format!(
        r#"listen: {gateway_addr:?}
cluster:
  enabled: true
  cluster_id: "guardrail-supabase-e2e"
  node_id: "guardrail-supabase-node"
  node_region: "local"
  node_zone: "local-a"
  state_backend: "local"
  counter_backend: "local"
storage:
  provider: "supabase"
  required: true
  provider_order:
    - "supabase"
    - "postgres"
  supabase_dsn_env: "FERROGATE_SUPABASE_DSN"
  postgres_pool_size: 2
  postgres_tls_mode: "{tls_mode}"
{ca_path}  postgres_connect_timeout_secs: 10
  postgres_statement_timeout_millis: 30000
  postgres_schema: "{schema}"
  postgres_search_path:
    - "public"
  migration_mode: "auto"
providers:
  - name: "openai"
    kind: "openai"
    base_url: "http://{provider_addr}/v1"
    api_key_env: "FERROGATE_PROVIDER_SECRET"
models:
  - name: "fast-chat"
    provider: "openai"
    provider_model: "gpt-4o-mini"
    capabilities: ["chat"]
api_keys:
  - id: "guardrail-e2e-client"
    name: "Guardrail E2E client"
    key: "guardrail-client-secret"
    scopes: ["models.read", "chat.completions"]
    allowed_models: ["fast-chat"]
    organization_id: "org_guardrail_e2e"
    project_id: "project_guardrail_e2e"
  - id: "guardrail-e2e-admin"
    name: "Guardrail E2E admin"
    key: "guardrail-admin-secret"
    scopes: ["admin.read"]
guardrails:
  - id: "e2e-pii-detector"
    name: "E2E PII detector"
    enabled: true
    stage: "request"
    organization_ids: ["org_guardrail_e2e"]
    models: ["fast-chat"]
    providers: ["openai"]
    provider: "custom_http"
    provider_endpoint: "http://{detector_addr}/check"
    provider_timeout_ms: 250
    provider_on_error: "block"
    provider_max_concurrency: 2
    provider_circuit_failure_threshold: 2
    provider_circuit_cooldown_ms: 1000
    provider_max_retries: 0
    provider_max_payload_bytes: 65536
    provider_max_response_bytes: 16384
    provider_allow_private_network: true
    provider_secret_ref: "env://FERROGATE_TEST_GUARDRAIL_SECRET"
    effect: "deny"
    code: "guardrail_pii_detected"
    message: "request blocked by E2E detector"
"#
    ))
}

fn yaml_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

struct GatewayGuard {
    child: Child,
}

impl GatewayGuard {
    fn start(
        binary: &Path,
        config_path: &Path,
        gateway_addr: &str,
        supabase_dsn: &str,
    ) -> Result<Self> {
        let child = Command::new(binary)
            .args(["run", "--config"])
            .arg(config_path)
            .env("FERROGATE_SUPABASE_DSN", supabase_dsn)
            .env("FERROGATE_PROVIDER_SECRET", "provider-secret")
            .env("FERROGATE_TEST_GUARDRAIL_SECRET", DETECTOR_SECRET)
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
        while started.elapsed() < Duration::from_secs(60) {
            if let Some(status) = self.child.try_wait()? {
                bail!("FerroGate exited before Guardrail E2E readiness: {status}");
            }
            match http_request_addr(gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("timed out waiting for Guardrail E2E gateway: {last}")
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct ProviderGuard {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Vec<String>>>,
}

impl ProviderGuard {
    fn new(stop: Arc<AtomicBool>, handle: JoinHandle<Vec<String>>) -> Self {
        Self {
            stop,
            handle: Some(handle),
        }
    }

    fn join(&mut self) -> Result<Vec<String>> {
        self.handle
            .take()
            .context("provider mock join handle missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("provider mock thread panicked"))
    }
}

impl Drop for ProviderGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct MockDetector {
    addr: String,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Vec<String>>>,
}

impl MockDetector {
    fn start(expected_requests: usize) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            let started = Instant::now();
            while requests.len() < expected_requests
                && started.elapsed() < Duration::from_secs(60)
                && !server_stop.load(Ordering::Relaxed)
            {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let Ok(request) = read_http_request(&mut stream) else {
                            continue;
                        };
                        let body = if request.contains("pii@example.com") {
                            r#"{"verdict":"fail","findings":[{"category":"pii","severity":"high","matched_text":"pii@example.com"}],"patches":[],"detector_version":"e2e-1"}"#
                        } else {
                            r#"{"verdict":"pass","findings":[],"patches":[],"detector_version":"e2e-1"}"#
                        };
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        requests.push(request);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
            requests
        });
        Ok(Self {
            addr,
            stop,
            handle: Some(handle),
        })
    }

    fn join(&mut self) -> Result<Vec<String>> {
        self.handle
            .take()
            .context("Guardrail detector mock join handle missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("Guardrail detector mock thread panicked"))
    }
}

impl Drop for MockDetector {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct SupabaseEvidence {
    client: Client,
    schema: String,
    cleaned: bool,
}

impl SupabaseEvidence {
    fn connect(args: &SupabaseLiveRestartArgs, schema: String) -> Result<Self> {
        if !schema
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            bail!("generated Supabase schema contains invalid characters");
        }
        let mut config = PostgresConfig::from_str(args.supabase_dsn.trim())
            .context("failed to parse Supabase PostgreSQL DSN")?;
        config.connect_timeout(Duration::from_secs(10));
        config.ssl_mode(SslMode::Require);
        let mut tls = TlsConnector::builder();
        if let Some(path) = args.tls_ca_cert_path.as_ref() {
            let bytes = fs::read(path)
                .with_context(|| format!("failed to read Supabase CA file {}", path.display()))?;
            let certificate = Certificate::from_pem(&bytes)
                .or_else(|_| Certificate::from_der(&bytes))
                .context("failed to parse Supabase CA certificate")?;
            tls.add_root_certificate(certificate);
        }
        match args.tls_mode.as_str() {
            "verify_full" => {}
            "verify_ca" => {
                tls.danger_accept_invalid_hostnames(true);
            }
            "require" => {
                tls.danger_accept_invalid_certs(true);
                tls.danger_accept_invalid_hostnames(true);
            }
            other => bail!(
                "--tls-mode must be require, verify_ca, or verify_full for live Supabase, got {other}"
            ),
        }
        let connector = MakeTlsConnector::new(
            tls.build()
                .context("failed to initialize Supabase TLS connector")?,
        );
        let client = config
            .connect(connector)
            .context("failed to connect to live Supabase PostgreSQL")?;
        Ok(Self {
            client,
            schema,
            cleaned: false,
        })
    }

    fn wait_for_detector_error(&mut self, request_id: &str) -> Result<()> {
        let audit_query = format!(
            "SELECT action, target, outcome, tenant, audit_json::text FROM \"{}\".audit_events WHERE request_id = $1 AND action = 'guardrail.detector_error'",
            self.schema
        );
        let request_query = format!(
            "SELECT status_code, error_code, request_json::text FROM \"{}\".request_logs WHERE request_id = $1",
            self.schema
        );
        let started = Instant::now();
        let mut last = "Supabase evidence row not visible yet".to_string();
        while started.elapsed() < Duration::from_secs(15) {
            match self.client.query_opt(&audit_query, &[&request_id]) {
                Ok(Some(audit_row)) => {
                    let action: String = audit_row.get(0);
                    let target: Option<String> = audit_row.get(1);
                    let outcome: String = audit_row.get(2);
                    let tenant: Option<String> = audit_row.get(3);
                    let audit_json: String = audit_row.get(4);
                    let audit: Value = serde_json::from_str(&audit_json)
                        .context("Supabase Guardrail audit_json was invalid")?;
                    if action != "guardrail.detector_error"
                        || target.as_deref() != Some("e2e-pii-detector")
                        || outcome != "blocked"
                        || tenant.as_deref()
                            != Some(
                                "org:org_guardrail_e2e|team:|project:project_guardrail_e2e|workspace:|user:|api_key:guardrail-e2e-client",
                            )
                        || audit["request_id"] != request_id
                        || audit["tenant"]["organization_id"] != "org_guardrail_e2e"
                    {
                        bail!("Supabase Guardrail detector audit evidence was incomplete");
                    }

                    let request_row = self
                        .client
                        .query_opt(&request_query, &[&request_id])
                        .context("failed to read Guardrail request evidence from Supabase")?
                        .context("Supabase omitted the Guardrail failure request log")?;
                    let status_code: Option<i32> = request_row.get(0);
                    let error_code: Option<String> = request_row.get(1);
                    let request_json: String = request_row.get(2);
                    let request: Value = serde_json::from_str(&request_json)
                        .context("Supabase Guardrail request_json was invalid")?;
                    if status_code != Some(403)
                        || error_code.as_deref() != Some("guardrail_provider_unavailable")
                        || request["tenant"]["organization_id"] != "org_guardrail_e2e"
                    {
                        bail!("Supabase Guardrail request evidence was incomplete");
                    }
                    return Ok(());
                }
                Ok(None) => {}
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(150));
        }
        bail!("timed out reading Guardrail evidence directly from Supabase: {last}")
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        self.client
            .batch_execute(&format!(
                "DROP SCHEMA IF EXISTS \"{}\" CASCADE",
                self.schema
            ))
            .context("failed to remove Guardrail E2E Supabase schema")?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for SupabaseEvidence {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
