// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::{bail, Context, Result as AnyResult};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use pingora::tls::load_certs_and_key_files;
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{hash_map::DefaultHasher, BTreeMap},
    fs,
    hash::{Hash, Hasher},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};

use crate::config::TlsAcmeConfig;

#[derive(Debug, Clone)]
pub(crate) struct AcmeCertificatePaths {
    pub(crate) cert_path: String,
    pub(crate) key_path: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct AcmeRenewalStatus {
    pub(crate) enabled: bool,
    pub(crate) domains: Vec<String>,
    pub(crate) cert_path: String,
    pub(crate) key_path: String,
    pub(crate) certificate_expires_at_unix: Option<u64>,
    pub(crate) renewal_window_secs: u64,
    pub(crate) renewal_due: bool,
    pub(crate) last_renewal_status: &'static str,
    pub(crate) last_renewal_at_unix: Option<u64>,
    pub(crate) last_renewal_error: Option<String>,
    pub(crate) next_check_at_unix: Option<u64>,
    pub(crate) reload_required: bool,
    pub(crate) reload_mode: &'static str,
}

#[derive(Debug)]
pub(crate) struct AcmeRenewalHandle {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Debug)]
pub(crate) struct SharedAcmeRenewalState {
    inner: Mutex<AcmeRenewalStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcmeRenewalDecision {
    RenewNow,
    WaitUntil(u64),
}

pub(crate) trait AcmeCertificateRenewer: Send + Sync + 'static {
    fn renew(&self, acme: &TlsAcmeConfig, paths: &AcmeCertificatePaths) -> AnyResult<()>;
}

pub(crate) trait AcmeCertificateReloader: Send + Sync + 'static {
    fn reload(&self) -> AnyResult<()>;
}

#[derive(Debug, Default)]
struct IssuingAcmeRenewer;

struct AcmeRenewalRuntime<S>
where
    S: Fn(Duration),
{
    renewer: Arc<dyn AcmeCertificateRenewer>,
    reloader: Arc<dyn AcmeCertificateReloader>,
    stop: Arc<AtomicBool>,
    now: fn() -> u64,
    sleep: S,
}

#[derive(Debug, Clone)]
struct DnsRecord {
    domain: String,
    name: String,
    value: String,
}

struct Http01ChallengeServer {
    listen: SocketAddr,
    responses: Arc<Mutex<BTreeMap<String, String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

#[derive(Debug, Serialize)]
struct DnsHookPayload<'a> {
    action: &'a str,
    provider: Option<&'a str>,
    provider_config: &'a BTreeMap<String, String>,
    domain: &'a str,
    dns_name: &'a str,
    dns_value: &'a str,
}

impl Http01ChallengeServer {
    fn start(listen: &str) -> AnyResult<Self> {
        let listen = listen
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid ACME http-01 listen address {listen}"))?;
        let listener =
            TcpListener::bind(listen).with_context(|| format!("failed to bind {listen}"))?;
        listener
            .set_nonblocking(true)
            .context("failed to configure ACME http-01 listener")?;
        let listen = listener.local_addr()?;
        let responses = Arc::new(Mutex::new(BTreeMap::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_responses = Arc::clone(&responses);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            serve_http01_challenges(listener, thread_responses, thread_stop);
        });
        info!(listen = %listen, "ACME http-01 challenge server listening");
        Ok(Self {
            listen,
            responses,
            stop,
            handle: Some(handle),
        })
    }

    fn insert_response(&self, token: String, response: String) -> AnyResult<()> {
        let mut responses = self
            .responses
            .lock()
            .map_err(|_| anyhow::anyhow!("ACME http-01 response map is poisoned"))?;
        responses.insert(token, response);
        Ok(())
    }
}

impl Drop for Http01ChallengeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.listen);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl SharedAcmeRenewalState {
    pub(crate) fn new(acme: &TlsAcmeConfig, paths: &AcmeCertificatePaths) -> Self {
        Self {
            inner: Mutex::new(initial_renewal_status(acme, paths)),
        }
    }

    pub(crate) fn snapshot(&self) -> AcmeRenewalStatus {
        match self.inner.lock() {
            Ok(status) => status.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn update(&self, update: impl FnOnce(&mut AcmeRenewalStatus)) {
        match self.inner.lock() {
            Ok(mut status) => update(&mut status),
            Err(poisoned) => update(&mut poisoned.into_inner()),
        }
    }
}

impl Drop for AcmeRenewalHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl AcmeCertificateRenewer for IssuingAcmeRenewer {
    fn renew(&self, acme: &TlsAcmeConfig, paths: &AcmeCertificatePaths) -> AnyResult<()> {
        issue_certificate_blocking(acme, paths)
    }
}

pub(crate) fn ensure_certificate(acme: &TlsAcmeConfig) -> AnyResult<AcmeCertificatePaths> {
    let paths = certificate_paths(acme);
    if existing_certificate_is_usable(&paths)? {
        info!(
            cert_path = %paths.cert_path,
            key_path = %paths.key_path,
            "using cached ACME certificate"
        );
        return Ok(paths);
    }

    fs::create_dir_all(certificate_storage_dir(acme)).with_context(|| {
        format!(
            "failed to create ACME certificate storage directory {}",
            certificate_storage_dir(acme).display()
        )
    })?;

    issue_certificate_blocking(acme, &paths)?;
    Ok(paths)
}

pub(crate) fn start_renewal_scheduler(
    acme: TlsAcmeConfig,
    paths: AcmeCertificatePaths,
    state: Arc<SharedAcmeRenewalState>,
    reloader: Arc<dyn AcmeCertificateReloader>,
) -> AcmeRenewalHandle {
    start_renewal_scheduler_with(
        acme,
        paths,
        state,
        Arc::new(IssuingAcmeRenewer),
        reloader,
        system_time_unix_seconds,
        thread::sleep,
    )
}

fn start_renewal_scheduler_with(
    acme: TlsAcmeConfig,
    paths: AcmeCertificatePaths,
    state: Arc<SharedAcmeRenewalState>,
    renewer: Arc<dyn AcmeCertificateRenewer>,
    reloader: Arc<dyn AcmeCertificateReloader>,
    now: fn() -> u64,
    sleep: fn(Duration),
) -> AcmeRenewalHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        let runtime = AcmeRenewalRuntime {
            renewer,
            reloader,
            stop: thread_stop,
            now,
            sleep,
        };
        run_renewal_loop(acme, paths, state, runtime);
    });
    AcmeRenewalHandle {
        stop,
        handle: Some(handle),
    }
}

fn run_renewal_loop(
    acme: TlsAcmeConfig,
    paths: AcmeCertificatePaths,
    state: Arc<SharedAcmeRenewalState>,
    runtime: AcmeRenewalRuntime<impl Fn(Duration)>,
) {
    while !runtime.stop.load(Ordering::Relaxed) {
        let current = (runtime.now)();
        let expires_at = certificate_expires_at_unix(&paths).ok().flatten();
        let decision = renewal_decision(
            current,
            expires_at,
            acme.renewal_window_secs,
            acme.renewal_check_interval_secs,
        );
        match decision {
            AcmeRenewalDecision::WaitUntil(next_check) => {
                state.update(|status| {
                    status.certificate_expires_at_unix = expires_at;
                    status.renewal_due = false;
                    status.next_check_at_unix = Some(next_check);
                });
                interruptible_sleep(
                    Duration::from_secs(next_check.saturating_sub(current)),
                    &runtime.stop,
                    &runtime.sleep,
                );
            }
            AcmeRenewalDecision::RenewNow => {
                state.update(|status| {
                    status.certificate_expires_at_unix = expires_at;
                    status.renewal_due = true;
                    status.next_check_at_unix = None;
                });
                let renewal_started = (runtime.now)();
                match runtime.renewer.renew(&acme, &paths) {
                    Ok(()) => {
                        let renewed_expires_at = certificate_expires_at_unix(&paths).ok().flatten();
                        let next_check = next_successful_check_at(
                            (runtime.now)(),
                            renewed_expires_at,
                            acme.renewal_window_secs,
                            acme.renewal_check_interval_secs,
                        );
                        state.update(|status| {
                            status.certificate_expires_at_unix = renewed_expires_at;
                            status.renewal_due = false;
                            status.last_renewal_status = "success";
                            status.last_renewal_at_unix = Some(renewal_started);
                            status.last_renewal_error = None;
                            status.next_check_at_unix = Some(next_check);
                            status.reload_required = true;
                        });
                        if acme.auto_graceful_reload {
                            match runtime.reloader.reload() {
                                Ok(()) => state.update(|status| {
                                    status.reload_required = false;
                                    status.reload_mode = "listener-level-graceful-upgrade";
                                }),
                                Err(error) => {
                                    warn!(error = %error, "ACME renewed certificate but automatic reload failed");
                                    state.update(|status| {
                                        status.reload_required = true;
                                        status.reload_mode = "listener-level-required";
                                        status.last_renewal_error = Some(format!(
                                            "certificate renewed but reload failed: {error}"
                                        ));
                                    });
                                }
                            }
                        }
                        interruptible_sleep(
                            Duration::from_secs(next_check.saturating_sub((runtime.now)())),
                            &runtime.stop,
                            &runtime.sleep,
                        );
                    }
                    Err(error) => {
                        warn!(error = %error, "ACME background renewal failed; will retry");
                        let retry_at =
                            (runtime.now)().saturating_add(acme.renewal_retry_interval_secs);
                        state.update(|status| {
                            status.renewal_due = true;
                            status.last_renewal_status = "failed";
                            status.last_renewal_at_unix = Some(renewal_started);
                            status.last_renewal_error = Some(error.to_string());
                            status.next_check_at_unix = Some(retry_at);
                        });
                        interruptible_sleep(
                            Duration::from_secs(acme.renewal_retry_interval_secs),
                            &runtime.stop,
                            &runtime.sleep,
                        );
                    }
                }
            }
        }
    }
}

fn interruptible_sleep(duration: Duration, stop: &AtomicBool, sleep: &impl Fn(Duration)) {
    let mut remaining = duration.as_secs();
    while remaining > 0 && !stop.load(Ordering::Relaxed) {
        let step = remaining.min(1);
        sleep(Duration::from_secs(step));
        remaining -= step;
    }
}

fn existing_certificate_is_usable(paths: &AcmeCertificatePaths) -> AnyResult<bool> {
    let cert_path = Path::new(&paths.cert_path);
    let key_path = Path::new(&paths.key_path);
    if !cert_path.exists() || !key_path.exists() {
        return Ok(false);
    }
    let certs_and_key = load_certs_and_key_files(&paths.cert_path, &paths.key_path)
        .context("failed to load cached ACME certificate or private key")?;
    if certs_and_key.is_some() {
        Ok(true)
    } else {
        warn!(
            cert_path = %paths.cert_path,
            key_path = %paths.key_path,
            "cached ACME certificate is invalid; requesting a new certificate"
        );
        Ok(false)
    }
}

fn issue_certificate_blocking(acme: &TlsAcmeConfig, paths: &AcmeCertificatePaths) -> AnyResult<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start ACME runtime")?;
    runtime.block_on(issue_certificate(acme, paths))
}

async fn issue_certificate(acme: &TlsAcmeConfig, paths: &AcmeCertificatePaths) -> AnyResult<()> {
    let account = load_or_create_account(acme).await?;
    let identifiers = acme
        .domains
        .iter()
        .map(|domain| Identifier::Dns(domain.clone()))
        .collect::<Vec<_>>();
    let mut order = account
        .new_order(&NewOrder::new(identifiers.as_slice()))
        .await
        .context("failed to create ACME order")?;

    let mut provisioned = Vec::new();
    let mut http01_server = None;
    let authorization_result: AnyResult<()> = async {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.context("failed to fetch ACME authorization")?;
            match authz.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                status => bail!("ACME authorization is not pending: {status:?}"),
            }

            let challenge_type = acme_challenge_type(acme)?;
            let mut challenge = authz.challenge(challenge_type).ok_or_else(|| {
                anyhow::anyhow!("ACME authorization has no {} challenge", acme.challenge)
            })?;
            let identifier = challenge.identifier();
            let Identifier::Dns(domain) = identifier.identifier else {
                bail!("ACME supports DNS identifiers only");
            };
            match acme.challenge.as_str() {
                "dns-01" => {
                    let record = DnsRecord {
                        domain: domain.clone(),
                        name: dns01_record_name(domain),
                        value: challenge.key_authorization().dns_value(),
                    };
                    run_dns_action(acme, "set", &record).with_context(|| {
                        format!("failed to provision ACME DNS record {}", record.name)
                    })?;
                    provisioned.push(record);
                    tokio::time::sleep(Duration::from_secs(acme.dns_propagation_delay_secs)).await;
                }
                "http-01" => {
                    let server = get_or_start_http01_server(&mut http01_server, acme)?;
                    server.insert_response(
                        challenge.token.clone(),
                        challenge.key_authorization().as_str().to_string(),
                    )?;
                }
                _ => bail!("unsupported ACME challenge {}", acme.challenge),
            }
            challenge
                .set_ready()
                .await
                .context("failed to mark ACME challenge as ready")?;
        }
        Ok(())
    }
    .await;
    if let Err(error) = authorization_result {
        cleanup_dns_records(acme, &provisioned);
        return Err(error);
    }

    let ready_result = order
        .poll_ready(&RetryPolicy::default().timeout(Duration::from_secs(120)))
        .await;
    cleanup_dns_records(acme, &provisioned);
    drop(http01_server);

    let status = ready_result.context("ACME order did not become ready")?;
    if status != OrderStatus::Ready {
        let order_error = format!("{:?}", order.state().error);
        let authz_errors = collect_authorization_errors(&mut order).await;
        bail!(
            "ACME order did not become ready: {status:?}; order_error={order_error}; authorizations={authz_errors}"
        );
    }

    let private_key_pem = order
        .finalize()
        .await
        .context("failed to finalize ACME order")?;
    let cert_chain_pem = order
        .poll_certificate(&RetryPolicy::default().timeout(Duration::from_secs(120)))
        .await
        .context("failed to download ACME certificate chain")?;

    write_private_file(
        Path::new(&paths.cert_path),
        cert_chain_pem.as_bytes(),
        0o644,
    )
    .with_context(|| format!("failed to write ACME certificate {}", paths.cert_path))?;
    write_private_file(
        Path::new(&paths.key_path),
        private_key_pem.as_bytes(),
        0o600,
    )
    .with_context(|| format!("failed to write ACME private key {}", paths.key_path))?;
    info!(
        cert_path = %paths.cert_path,
        key_path = %paths.key_path,
        "issued ACME certificate"
    );
    Ok(())
}

async fn collect_authorization_errors(order: &mut instant_acme::Order) -> String {
    let mut details = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        match result {
            Ok(mut authz) => match authz.refresh().await {
                Ok(state) => {
                    details.push(format!(
                        "identifier={}; status={:?}; challenges={:?}",
                        state.identifier(),
                        state.status,
                        state.challenges
                    ));
                }
                Err(error) => details.push(format!("refresh_error={error}")),
            },
            Err(error) => details.push(format!("authorization_error={error}")),
        }
    }
    details.join(" | ")
}

async fn load_or_create_account(acme: &TlsAcmeConfig) -> AnyResult<Account> {
    let path = account_credentials_path(acme);
    if path.exists() {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read ACME account {}", path.display()))?;
        let credentials: AccountCredentials =
            serde_json::from_str(&raw).context("failed to parse ACME account credentials")?;
        return Account::builder()
            .context("failed to create ACME account builder")?
            .from_credentials(credentials)
            .await
            .context("failed to restore ACME account");
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create ACME account directory {}",
                parent.display()
            )
        })?;
    }
    let email = acme.email.as_deref().unwrap();
    let contact = [format!("mailto:{email}")];
    let contact_refs = contact.iter().map(String::as_str).collect::<Vec<_>>();
    let new_account = NewAccount {
        contact: contact_refs.as_slice(),
        terms_of_service_agreed: acme.terms_agreed,
        only_return_existing: false,
    };
    let (account, credentials) = Account::builder()
        .context("failed to create ACME account builder")?
        .create(&new_account, acme.directory_url.clone(), None)
        .await
        .context("failed to create ACME account")?;
    let raw =
        serde_json::to_vec_pretty(&credentials).context("failed to serialize ACME account")?;
    write_private_file(&path, &raw, 0o600)
        .with_context(|| format!("failed to write ACME account {}", path.display()))?;
    Ok(account)
}

fn cleanup_dns_records(acme: &TlsAcmeConfig, records: &[DnsRecord]) {
    for record in records {
        if let Err(error) = run_dns_action(acme, "cleanup", record) {
            warn!(
                record_name = %record.name,
                error = %error,
                "failed to cleanup ACME DNS record"
            );
        }
    }
}

fn run_dns_action(acme: &TlsAcmeConfig, action: &str, record: &DnsRecord) -> AnyResult<()> {
    let hook = match action {
        "set" => acme.dns_hook_set.as_deref(),
        "cleanup" => acme.dns_hook_cleanup.as_deref(),
        _ => bail!("unsupported ACME DNS action {action}"),
    };
    if let Some(hook) = hook.filter(|value| !value.trim().is_empty()) {
        return run_dns_hook(acme, hook, action, record);
    }
    if acme
        .dns_provider
        .as_deref()
        .is_some_and(|provider| provider.trim().eq_ignore_ascii_case("cloudflare"))
    {
        return run_cloudflare_dns_action(acme, action, record);
    }
    bail!("ACME DNS-01 requires dns hooks or built-in cloudflare provider")
}

fn get_or_start_http01_server<'a>(
    server: &'a mut Option<Http01ChallengeServer>,
    acme: &TlsAcmeConfig,
) -> AnyResult<&'a Http01ChallengeServer> {
    if server.is_none() {
        *server = Some(Http01ChallengeServer::start(&acme.http_challenge_listen)?);
    }
    Ok(server.as_ref().unwrap())
}

fn acme_challenge_type(acme: &TlsAcmeConfig) -> AnyResult<ChallengeType> {
    match acme.challenge.as_str() {
        "dns-01" => Ok(ChallengeType::Dns01),
        "http-01" => Ok(ChallengeType::Http01),
        _ => bail!("unsupported ACME challenge {}", acme.challenge),
    }
}

fn serve_http01_challenges(
    listener: TcpListener,
    responses: Arc<Mutex<BTreeMap<String, String>>>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => handle_http01_connection(stream, &responses),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                warn!(error = %error, "ACME http-01 listener accept failed");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn handle_http01_connection(
    mut stream: TcpStream,
    responses: &Arc<Mutex<BTreeMap<String, String>>>,
) {
    let mut buffer = [0_u8; 4096];
    let Ok(size) = stream.read(&mut buffer) else {
        return;
    };
    let request = String::from_utf8_lossy(&buffer[..size]);
    let token = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|path| path.strip_prefix("/.well-known/acme-challenge/"))
        .and_then(|token| token.split(['?', '#']).next())
        .filter(|token| !token.is_empty());
    let Some(token) = token else {
        let _ = write_http_response(&mut stream, 404, "not found");
        return;
    };
    let response = responses
        .lock()
        .ok()
        .and_then(|responses| responses.get(token).cloned());
    match response {
        Some(response) => {
            let _ = write_http_response(&mut stream, 200, &response);
        }
        None => {
            let _ = write_http_response(&mut stream, 404, "not found");
        }
    }
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = if status == 200 { "OK" } else { "Not Found" };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn run_dns_hook(
    acme: &TlsAcmeConfig,
    path: &str,
    action: &str,
    record: &DnsRecord,
) -> AnyResult<()> {
    let payload_path = dns_hook_payload_path(acme, action, record);
    let payload = DnsHookPayload {
        action,
        provider: acme.dns_provider.as_deref(),
        provider_config: &acme.dns_config,
        domain: &record.domain,
        dns_name: &record.name,
        dns_value: &record.value,
    };
    let raw =
        serde_json::to_vec_pretty(&payload).context("failed to serialize ACME DNS payload")?;
    write_private_file(&payload_path, &raw, 0o600).with_context(|| {
        format!(
            "failed to write ACME DNS hook payload {}",
            payload_path.display()
        )
    })?;

    let output = match Command::new(path).arg(action).arg(&payload_path).output() {
        Ok(output) => output,
        Err(error) => {
            let _ = fs::remove_file(&payload_path);
            return Err(error).with_context(|| format!("failed to execute ACME DNS hook {path}"));
        }
    };
    let _ = fs::remove_file(&payload_path);

    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
        "ACME DNS hook {path} exited with status {}: {}",
        output.status,
        stderr.trim()
    );
}

fn run_cloudflare_dns_action(
    acme: &TlsAcmeConfig,
    action: &str,
    record: &DnsRecord,
) -> AnyResult<()> {
    let api_token = dns_config_value(acme, "api_token")?;
    let zone_id = match acme.dns_config.get("zone_id") {
        Some(zone_id) => zone_id.trim().to_string(),
        None => resolve_cloudflare_zone_id(&api_token, &dns_config_value(acme, "zone_name")?)?,
    };
    let record_name = record.name.trim_end_matches('.');
    match action {
        "set" => {
            ensure_cloudflare_txt_record(acme, &api_token, &zone_id, record_name, &record.value)
        }
        "cleanup" => {
            cleanup_cloudflare_txt_record(&api_token, &zone_id, record_name, &record.value)
        }
        _ => bail!("unsupported Cloudflare DNS action {action}"),
    }
}

/// Reads `tls.acme.dns_config.{key}`. The value may be a plain literal
/// (unchanged pre-#163 behavior) or a `env://`/`vault://` secret reference
/// (issue #163), resolved through `ferrogate-secrets` — letting the ACME DNS
/// provider token come from the same secret backends as provider API keys.
fn dns_config_value(acme: &TlsAcmeConfig, key: &str) -> AnyResult<String> {
    let raw = acme
        .dns_config
        .get(key)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing tls.acme.dns_config.{key}"))?;
    if raw.starts_with("env://") || raw.starts_with("vault://") {
        let registry = ferrogate_secrets::SecretResolverRegistry::from_env();
        return registry
            .resolve(raw)
            .with_context(|| format!("failed to resolve tls.acme.dns_config.{key}"))?
            .ok_or_else(|| anyhow::anyhow!("tls.acme.dns_config.{key} resolved to no value"));
    }
    Ok(raw.to_string())
}

fn resolve_cloudflare_zone_id(api_token: &str, zone_name: &str) -> AnyResult<String> {
    let response = cloudflare_request(
        "GET",
        &format!(
            "/client/v4/zones?name={}&status=active",
            url_encode(zone_name)
        ),
        api_token,
        None,
    )?;
    let zones = response
        .get("result")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("Cloudflare zones response did not include result array"))?;
    if zones.len() != 1 {
        bail!(
            "expected exactly one active Cloudflare zone named {zone_name}, got {}",
            zones.len()
        );
    }
    zones[0]
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("Cloudflare zone {zone_name} did not include id"))
}

fn ensure_cloudflare_txt_record(
    acme: &TlsAcmeConfig,
    api_token: &str,
    zone_id: &str,
    record_name: &str,
    record_value: &str,
) -> AnyResult<()> {
    if !find_cloudflare_txt_records(api_token, zone_id, record_name, record_value)?.is_empty() {
        return Ok(());
    }
    let ttl = acme
        .dns_config
        .get("ttl")
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(120);
    let body = serde_json::json!({
        "type": "TXT",
        "name": record_name,
        "content": record_value,
        "ttl": ttl,
    });
    cloudflare_request(
        "POST",
        &format!("/client/v4/zones/{zone_id}/dns_records"),
        api_token,
        Some(body),
    )?;
    Ok(())
}

fn cleanup_cloudflare_txt_record(
    api_token: &str,
    zone_id: &str,
    record_name: &str,
    record_value: &str,
) -> AnyResult<()> {
    for record in find_cloudflare_txt_records(api_token, zone_id, record_name, record_value)? {
        if let Some(record_id) = record.get("id").and_then(Value::as_str) {
            cloudflare_request(
                "DELETE",
                &format!("/client/v4/zones/{zone_id}/dns_records/{record_id}"),
                api_token,
                None,
            )?;
        }
    }
    Ok(())
}

fn find_cloudflare_txt_records(
    api_token: &str,
    zone_id: &str,
    record_name: &str,
    record_value: &str,
) -> AnyResult<Vec<Value>> {
    let path = format!(
        "/client/v4/zones/{zone_id}/dns_records?type=TXT&name={}&content={}&per_page=100",
        url_encode(record_name),
        url_encode(record_value)
    );
    let response = cloudflare_request("GET", &path, api_token, None)?;
    Ok(response
        .get("result")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

fn cloudflare_request(
    method: &str,
    path_query: &str,
    api_token: &str,
    body: Option<Value>,
) -> AnyResult<Value> {
    let body = match body {
        Some(body) => serde_json::to_vec(&body).context("failed to serialize Cloudflare body")?,
        None => Vec::new(),
    };
    let address = ("api.cloudflare.com", 443)
        .to_socket_addrs()
        .context("failed to resolve api.cloudflare.com")?
        .next()
        .ok_or_else(|| anyhow::anyhow!("api.cloudflare.com resolved no addresses"))?;
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(30))
        .context("failed to connect api.cloudflare.com")?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let server_name =
        ServerName::try_from("api.cloudflare.com").context("invalid Cloudflare TLS server name")?;
    let connection = ClientConnection::new(tls_client_config()?, server_name)
        .context("failed to initialize Cloudflare TLS client")?;
    let mut stream = StreamOwned::new(connection, stream);
    write!(
        stream,
        "{method} {path_query} HTTP/1.1\r\nHost: api.cloudflare.com\r\nAuthorization: Bearer {api_token}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let (status, payload) = parse_cloudflare_response(&raw)?;
    if !status.starts_with('2') {
        bail!("Cloudflare API {method} {path_query} returned HTTP {status}: {payload}");
    }
    let value: Value = serde_json::from_str(&payload).context("failed to parse Cloudflare JSON")?;
    if !value
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!(
            "Cloudflare API {method} {path_query} failed: {}",
            value.get("errors").unwrap_or(&Value::Null)
        );
    }
    Ok(value)
}

fn parse_cloudflare_response(raw: &[u8]) -> AnyResult<(String, String)> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("Cloudflare response missing header terminator"))?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| anyhow::anyhow!("Cloudflare response missing status"))?
        .to_string();
    let body_bytes = &raw[split + 4..];
    let chunked = head.lines().any(|line| {
        let line = line.trim();
        line.to_ascii_lowercase().starts_with("transfer-encoding:")
            && line.to_ascii_lowercase().contains("chunked")
    });
    let body = if chunked {
        String::from_utf8(decode_chunked_body(body_bytes)?)
            .context("Cloudflare chunked response body was not UTF-8")?
    } else {
        String::from_utf8_lossy(body_bytes).to_string()
    };
    Ok((status, body))
}

fn decode_chunked_body(raw: &[u8]) -> AnyResult<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut pos = 0;
    loop {
        let line_end = find_crlf(&raw[pos..])
            .ok_or_else(|| anyhow::anyhow!("chunked response missing chunk size terminator"))?
            + pos;
        let size_line = String::from_utf8_lossy(&raw[pos..line_end]);
        let size_hex = size_line
            .split(';')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("chunked response missing chunk size"))?;
        let size = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("invalid chunk size {size_hex}"))?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        let chunk_end = pos
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("chunk size overflow"))?;
        if raw.len() < chunk_end + 2 {
            bail!("chunked response ended before chunk data completed");
        }
        decoded.extend_from_slice(&raw[pos..chunk_end]);
        if &raw[chunk_end..chunk_end + 2] != b"\r\n" {
            bail!("chunked response chunk missing trailing CRLF");
        }
        pos = chunk_end + 2;
    }
    Ok(decoded)
}

fn find_crlf(raw: &[u8]) -> Option<usize> {
    raw.windows(2).position(|window| window == b"\r\n")
}

/// See the identical helper in `telemetry.rs` for why this is needed:
/// rustls panics if more than one crypto backend is compiled in and no
/// process-wide default has been installed explicitly (issue #163).
fn ensure_rustls_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn tls_client_config() -> AnyResult<Arc<ClientConfig>> {
    static TLS_CLIENT_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(config) = TLS_CLIENT_CONFIG.get() {
        return Ok(Arc::clone(config));
    }
    ensure_rustls_crypto_provider();

    let mut roots = RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    if !native_certs.errors.is_empty() {
        bail!(
            "failed to load platform native certificates: {:?}",
            native_certs.errors
        );
    }
    for cert in native_certs.certs {
        roots
            .add(cert)
            .context("failed to add platform native certificate")?;
    }
    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let _ = TLS_CLIENT_CONFIG.set(Arc::clone(&config));
    Ok(TLS_CLIENT_CONFIG.get().map(Arc::clone).unwrap_or(config))
}

fn url_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn dns_hook_payload_path(acme: &TlsAcmeConfig, action: &str, record: &DnsRecord) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    action.hash(&mut hasher);
    record.domain.hash(&mut hasher);
    record.name.hash(&mut hasher);
    record.value.hash(&mut hasher);
    Path::new(&acme.storage_dir)
        .join("challenges")
        .join(format!("{action}-{:016x}.json", hasher.finish()))
}

pub(crate) fn certificate_paths(acme: &TlsAcmeConfig) -> AcmeCertificatePaths {
    let dir = certificate_storage_dir(acme);
    AcmeCertificatePaths {
        cert_path: dir.join("fullchain.pem").to_string_lossy().into_owned(),
        key_path: dir.join("privkey.pem").to_string_lossy().into_owned(),
    }
}

pub(crate) fn certificate_expires_at_unix(paths: &AcmeCertificatePaths) -> AnyResult<Option<u64>> {
    let raw = fs::read_to_string(&paths.cert_path)
        .with_context(|| format!("failed to read certificate {}", paths.cert_path))?;
    Ok(first_pem_certificate_not_after_unix(&raw))
}

fn initial_renewal_status(acme: &TlsAcmeConfig, paths: &AcmeCertificatePaths) -> AcmeRenewalStatus {
    let now = system_time_unix_seconds();
    let expires_at = certificate_expires_at_unix(paths).ok().flatten();
    let decision = renewal_decision(
        now,
        expires_at,
        acme.renewal_window_secs,
        acme.renewal_check_interval_secs,
    );
    AcmeRenewalStatus {
        enabled: true,
        domains: acme.domains.clone(),
        cert_path: paths.cert_path.clone(),
        key_path: paths.key_path.clone(),
        certificate_expires_at_unix: expires_at,
        renewal_window_secs: acme.renewal_window_secs,
        renewal_due: matches!(decision, AcmeRenewalDecision::RenewNow),
        last_renewal_status: "never",
        last_renewal_at_unix: None,
        last_renewal_error: None,
        next_check_at_unix: match decision {
            AcmeRenewalDecision::RenewNow => Some(now),
            AcmeRenewalDecision::WaitUntil(next_check) => Some(next_check),
        },
        reload_required: false,
        reload_mode: "listener-level-required",
    }
}

pub(crate) fn renewal_decision(
    now: u64,
    expires_at: Option<u64>,
    renewal_window_secs: u64,
    check_interval_secs: u64,
) -> AcmeRenewalDecision {
    let Some(expires_at) = expires_at else {
        return AcmeRenewalDecision::RenewNow;
    };
    let renew_at = expires_at.saturating_sub(renewal_window_secs);
    if now >= renew_at {
        AcmeRenewalDecision::RenewNow
    } else {
        AcmeRenewalDecision::WaitUntil(now.saturating_add(check_interval_secs).min(renew_at))
    }
}

fn next_successful_check_at(
    now: u64,
    expires_at: Option<u64>,
    renewal_window_secs: u64,
    check_interval_secs: u64,
) -> u64 {
    match renewal_decision(now, expires_at, renewal_window_secs, check_interval_secs) {
        AcmeRenewalDecision::RenewNow => now.saturating_add(check_interval_secs),
        AcmeRenewalDecision::WaitUntil(next_check) => next_check,
    }
}

fn system_time_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn first_pem_certificate_not_after_unix(pem: &str) -> Option<u64> {
    let mut in_certificate = false;
    let mut b64 = String::new();
    for line in pem.lines().map(str::trim) {
        match line {
            "-----BEGIN CERTIFICATE-----" => {
                in_certificate = true;
                b64.clear();
            }
            "-----END CERTIFICATE-----" if in_certificate => {
                let der = decode_base64_der(&b64).ok()?;
                return certificate_not_after_unix_from_der(&der);
            }
            _ if in_certificate => b64.push_str(line),
            _ => {}
        }
    }
    None
}

fn certificate_not_after_unix_from_der(der: &[u8]) -> Option<u64> {
    let (cert, _) = der_read_sequence(der, 0)?;
    let (tbs, _) = der_read_sequence(cert, 0)?;
    let mut offset = 0;
    if tbs.get(offset) == Some(&0xa0) {
        let (_, _, consumed) = der_read_tlv(tbs, offset)?;
        offset = offset.checked_add(consumed)?;
    }
    for _ in 0..3 {
        let (_, _, consumed) = der_read_tlv(tbs, offset)?;
        offset = offset.checked_add(consumed)?;
    }
    let (validity, _) = der_read_sequence(tbs, offset)?;
    let (not_before, consumed) = der_read_time(validity, 0)?;
    let _ = not_before;
    let (not_after, _) = der_read_time(validity, consumed)?;
    Some(not_after)
}

fn der_read_sequence(input: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let (tag, content, consumed) = der_read_tlv(input, offset)?;
    (tag == 0x30).then_some((content, consumed))
}

fn der_read_time(input: &[u8], offset: usize) -> Option<(u64, usize)> {
    let (tag, content, consumed) = der_read_tlv(input, offset)?;
    let value = std::str::from_utf8(content).ok()?;
    let unix = match tag {
        0x17 => parse_utc_time_unix(value)?,
        0x18 => parse_generalized_time_unix(value)?,
        _ => return None,
    };
    Some((unix, consumed))
}

fn der_read_tlv(input: &[u8], offset: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *input.get(offset)?;
    let length_first = *input.get(offset + 1)?;
    let (length, length_bytes) = if length_first & 0x80 == 0 {
        (length_first as usize, 1)
    } else {
        let count = (length_first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for byte in input.get(offset + 2..offset + 2 + count)? {
            length = length.checked_mul(256)?.checked_add(*byte as usize)?;
        }
        (length, 1 + count)
    };
    let content_start = offset.checked_add(1 + length_bytes)?;
    let content_end = content_start.checked_add(length)?;
    let content = input.get(content_start..content_end)?;
    Some((tag, content, content_end - offset))
}

fn parse_utc_time_unix(value: &str) -> Option<u64> {
    if value.len() != 13 || !value.ends_with('Z') {
        return None;
    }
    let year = value.get(0..2)?.parse::<i32>().ok()?;
    let full_year = if year >= 50 { 1900 + year } else { 2000 + year };
    parse_ymdhms_unix(
        full_year,
        value.get(2..4)?.parse().ok()?,
        value.get(4..6)?.parse().ok()?,
        value.get(6..8)?.parse().ok()?,
        value.get(8..10)?.parse().ok()?,
        value.get(10..12)?.parse().ok()?,
    )
}

fn parse_generalized_time_unix(value: &str) -> Option<u64> {
    if value.len() != 15 || !value.ends_with('Z') {
        return None;
    }
    parse_ymdhms_unix(
        value.get(0..4)?.parse().ok()?,
        value.get(4..6)?.parse().ok()?,
        value.get(6..8)?.parse().ok()?,
        value.get(8..10)?.parse().ok()?,
        value.get(10..12)?.parse().ok()?,
        value.get(12..14)?.parse().ok()?,
    )
}

fn parse_ymdhms_unix(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<u64> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour as i64 * 3_600 + minute as i64 * 60 + second as i64)?;
    u64::try_from(seconds).ok()
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = month as i32;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146_097 + doe - 719_468) as i64)
}

fn decode_base64_der(value: &str) -> AnyResult<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len() * 3 / 4);
    let mut chunk = [0u8; 4];
    let mut chunk_len = 0usize;
    for byte in value.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        chunk[chunk_len] = byte;
        chunk_len += 1;
        if chunk_len == 4 {
            decode_base64_chunk(&chunk, &mut out)?;
            chunk_len = 0;
        }
    }
    if chunk_len != 0 {
        bail!("base64 certificate body has incomplete final quantum");
    }
    Ok(out)
}

fn decode_base64_chunk(chunk: &[u8; 4], out: &mut Vec<u8>) -> AnyResult<()> {
    let mut values = [0u8; 4];
    let mut padding = 0usize;
    for (index, byte) in chunk.iter().copied().enumerate() {
        values[index] = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding += 1;
                0
            }
            _ => bail!("invalid base64 byte in certificate"),
        };
    }
    out.push((values[0] << 2) | (values[1] >> 4));
    if padding < 2 {
        out.push((values[1] << 4) | (values[2] >> 2));
    }
    if padding == 0 {
        out.push((values[2] << 6) | values[3]);
    }
    Ok(())
}

fn certificate_storage_dir(acme: &TlsAcmeConfig) -> PathBuf {
    Path::new(&acme.storage_dir)
        .join("certificates")
        .join(storage_key(acme))
}

fn account_credentials_path(acme: &TlsAcmeConfig) -> PathBuf {
    Path::new(&acme.storage_dir)
        .join("accounts")
        .join(format!("{}.json", storage_key(acme)))
}

fn storage_key(acme: &TlsAcmeConfig) -> String {
    let first_domain = acme
        .domains
        .first()
        .map(|domain| sanitize_storage_component(domain))
        .unwrap_or_else(|| "default".to_string());
    let mut hasher = DefaultHasher::new();
    acme.directory_url.hash(&mut hasher);
    acme.email.hash(&mut hasher);
    acme.domains.hash(&mut hasher);
    format!("{first_domain}-{:016x}", hasher.finish())
}

fn sanitize_storage_component(raw: &str) -> String {
    let mut value = raw
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    while value.contains("..") {
        value = value.replace("..", ".");
    }
    value.trim_matches('.').to_string()
}

fn dns01_record_name(domain: &str) -> String {
    let normalized = domain
        .trim()
        .trim_end_matches('.')
        .strip_prefix("*.")
        .unwrap_or_else(|| domain.trim().trim_end_matches('.'));
    format!("_acme-challenge.{normalized}.")
}

fn write_private_file(path: &Path, bytes: &[u8], mode: u32) -> AnyResult<()> {
    let tmp = path.with_extension("tmp");
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

        // Create the storage directory 0o700 so the private-key files are not
        // even listable by other local users.
        if let Some(parent) = path.parent() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        // Create the temp file with the restrictive mode UP FRONT (O_CREAT |
        // O_EXCL via create_new) rather than write-then-chmod: the previous
        // fs::write created it 0o644 under the default umask and only chmod'd
        // afterwards, leaving a window in which the private key was
        // world-readable, and a crash in that window left a predictable-path
        // 0o644 temp behind. O_EXCL also refuses to follow a pre-planted
        // symlink at the (predictable) temp path.
        let _ = fs::remove_file(&tmp); // clear a stale temp from a prior crash
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        // Normalize to exactly `mode` (the create above is `mode & ~umask`, i.e.
        // only ever more restrictive, so this never widens an intermediate
        // window); harmless belt-and-suspenders.
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
        drop(file);
    }
    #[cfg(not(unix))]
    {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&tmp, bytes)?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TlsAcmeConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn dns01_record_name_strips_wildcard_and_adds_fqdn_dot() {
        assert_eq!(
            dns01_record_name("*.example.com"),
            "_acme-challenge.example.com."
        );
        assert_eq!(
            dns01_record_name("api.example.com."),
            "_acme-challenge.api.example.com."
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_is_owner_only_with_private_dir() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("certificates").join("api.example.com");
        let key_path = nested.join("privkey.pem");
        write_private_file(&key_path, b"test-private-key-material", 0o600).unwrap();

        // The key file is owner read/write only -- never world/group readable.
        let file_mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            file_mode, 0o600,
            "private key must be 0o600, got {file_mode:o}"
        );
        // The created storage directory is not traversable/listable by others.
        let dir_mode = fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "storage dir must be 0o700, got {dir_mode:o}"
        );
        // No world-readable temp is left behind.
        assert!(!key_path.with_extension("tmp").exists());
        assert_eq!(fs::read(&key_path).unwrap(), b"test-private-key-material");
    }

    #[test]
    fn certificate_paths_are_under_storage_dir() {
        let acme = TlsAcmeConfig {
            enabled: true,
            domains: vec!["api.example.com".into()],
            email: Some("ops@example.com".into()),
            storage_dir: "/tmp/ferrogate-acme".into(),
            ..TlsAcmeConfig::default()
        };

        let paths = certificate_paths(&acme);

        assert!(paths
            .cert_path
            .starts_with("/tmp/ferrogate-acme/certificates/"));
        assert!(paths.cert_path.ends_with("/fullchain.pem"));
        assert!(paths.key_path.ends_with("/privkey.pem"));
    }

    #[test]
    fn renewal_decision_renews_inside_window_or_when_expiry_is_unknown() {
        assert_eq!(
            renewal_decision(100, None, 30, 10),
            AcmeRenewalDecision::RenewNow
        );
        assert_eq!(
            renewal_decision(80, Some(100), 30, 10),
            AcmeRenewalDecision::RenewNow
        );
        assert_eq!(
            renewal_decision(50, Some(100), 30, 10),
            AcmeRenewalDecision::WaitUntil(60)
        );
        assert_eq!(
            renewal_decision(50, Some(100), 30, 60),
            AcmeRenewalDecision::WaitUntil(70)
        );
    }

    #[test]
    fn parses_certificate_expiry_from_pem() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        if !write_test_certificate(&cert, &key, "1") {
            return;
        }
        let paths = AcmeCertificatePaths {
            cert_path: cert.to_string_lossy().into_owned(),
            key_path: key.to_string_lossy().into_owned(),
        };

        let expires_at = certificate_expires_at_unix(&paths).unwrap().unwrap();

        assert!(expires_at > system_time_unix_seconds());
        assert!(expires_at < system_time_unix_seconds() + 2 * 24 * 60 * 60);
    }

    #[test]
    fn failed_renewal_updates_retry_status_without_clearing_existing_certificate() {
        struct FailingRenewer {
            calls: AtomicUsize,
        }
        struct TestReloader;
        impl AcmeCertificateRenewer for FailingRenewer {
            fn renew(&self, _acme: &TlsAcmeConfig, _paths: &AcmeCertificatePaths) -> AnyResult<()> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                anyhow::bail!("mock renewal failed")
            }
        }
        impl AcmeCertificateReloader for TestReloader {
            fn reload(&self) -> AnyResult<()> {
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        write_unparseable_certificate(&cert, &key);
        let acme = TlsAcmeConfig {
            enabled: true,
            domains: vec!["api.example.com".into()],
            email: Some("ops@example.com".into()),
            storage_dir: dir.path().to_string_lossy().into_owned(),
            renewal_window_secs: 90 * 24 * 60 * 60,
            renewal_check_interval_secs: 60,
            renewal_retry_interval_secs: 30,
            ..TlsAcmeConfig::default()
        };
        let paths = AcmeCertificatePaths {
            cert_path: cert.to_string_lossy().into_owned(),
            key_path: key.to_string_lossy().into_owned(),
        };
        let state = Arc::new(SharedAcmeRenewalState::new(&acme, &paths));
        let stop = Arc::new(AtomicBool::new(false));
        let renewer = Arc::new(FailingRenewer {
            calls: AtomicUsize::new(0),
        });

        run_renewal_loop(
            acme,
            paths.clone(),
            Arc::clone(&state),
            AcmeRenewalRuntime {
                renewer: renewer.clone(),
                reloader: Arc::new(TestReloader),
                stop: Arc::clone(&stop),
                now: || 1_700_000_000,
                sleep: |_| stop.store(true, Ordering::Relaxed),
            },
        );

        let status = state.snapshot();
        assert_eq!(renewer.calls.load(Ordering::Relaxed), 1);
        assert_eq!(status.last_renewal_status, "failed");
        assert!(status
            .last_renewal_error
            .unwrap()
            .contains("mock renewal failed"));
        assert_eq!(status.next_check_at_unix, Some(1_700_000_030));
        assert!(std::path::Path::new(&paths.cert_path).exists());
    }

    #[test]
    fn successful_renewal_marks_reload_complete_when_reloader_succeeds() {
        struct SuccessfulRenewer;
        struct SuccessfulReloader {
            calls: AtomicUsize,
        }
        impl AcmeCertificateRenewer for SuccessfulRenewer {
            fn renew(&self, _acme: &TlsAcmeConfig, _paths: &AcmeCertificatePaths) -> AnyResult<()> {
                Ok(())
            }
        }
        impl AcmeCertificateReloader for SuccessfulReloader {
            fn reload(&self) -> AnyResult<()> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        write_unparseable_certificate(&cert, &key);
        let acme = TlsAcmeConfig {
            enabled: true,
            domains: vec!["api.example.com".into()],
            email: Some("ops@example.com".into()),
            storage_dir: dir.path().to_string_lossy().into_owned(),
            renewal_window_secs: 90 * 24 * 60 * 60,
            renewal_check_interval_secs: 60,
            renewal_retry_interval_secs: 30,
            auto_graceful_reload: true,
            ..TlsAcmeConfig::default()
        };
        let paths = AcmeCertificatePaths {
            cert_path: cert.to_string_lossy().into_owned(),
            key_path: key.to_string_lossy().into_owned(),
        };
        let state = Arc::new(SharedAcmeRenewalState::new(&acme, &paths));
        let stop = Arc::new(AtomicBool::new(false));
        let reloader = Arc::new(SuccessfulReloader {
            calls: AtomicUsize::new(0),
        });

        run_renewal_loop(
            acme,
            paths,
            Arc::clone(&state),
            AcmeRenewalRuntime {
                renewer: Arc::new(SuccessfulRenewer),
                reloader: reloader.clone(),
                stop: Arc::clone(&stop),
                now: || 1_700_000_000,
                sleep: |_| stop.store(true, Ordering::Relaxed),
            },
        );

        let status = state.snapshot();
        assert_eq!(status.last_renewal_status, "success");
        assert_eq!(reloader.calls.load(Ordering::Relaxed), 1);
        assert!(!status.reload_required);
        assert_eq!(status.reload_mode, "listener-level-graceful-upgrade");
    }

    #[test]
    fn dns_hook_payload_contains_config_file_provider_settings() {
        let mut dns_config = BTreeMap::new();
        dns_config.insert("api_token".to_string(), "cf-token".to_string());
        let acme = TlsAcmeConfig {
            storage_dir: "/tmp/ferrogate-acme".into(),
            dns_provider: Some("cloudflare".into()),
            dns_config,
            ..TlsAcmeConfig::default()
        };
        let record = DnsRecord {
            domain: "api.example.com".into(),
            name: "_acme-challenge.api.example.com.".into(),
            value: "txt-value".into(),
        };
        let payload = DnsHookPayload {
            action: "set",
            provider: acme.dns_provider.as_deref(),
            provider_config: &acme.dns_config,
            domain: &record.domain,
            dns_name: &record.name,
            dns_value: &record.value,
        };

        let raw = serde_json::to_string(&payload).unwrap();

        assert!(raw.contains("\"provider\":\"cloudflare\""));
        assert!(raw.contains("\"api_token\":\"cf-token\""));
        assert!(raw.contains("\"dns_name\":\"_acme-challenge.api.example.com.\""));
        assert!(dns_hook_payload_path(&acme, "set", &record)
            .starts_with("/tmp/ferrogate-acme/challenges"));
    }

    #[test]
    fn http01_challenge_server_serves_token_response() {
        let server = Http01ChallengeServer::start("127.0.0.1:0").unwrap();
        server
            .insert_response("token-123".into(), "key-auth-value".into())
            .unwrap();

        let mut stream = TcpStream::connect(server.listen).unwrap();
        stream
            .write_all(b"GET /.well-known/acme-challenge/token-123 HTTP/1.1\r\nhost: token4aicloud.com\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("key-auth-value"));
    }

    #[test]
    fn parses_chunked_cloudflare_response_body() {
        let raw =
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n8\r\n{\"ok\":1}\r\n0\r\n\r\n";

        let (status, body) = parse_cloudflare_response(raw).unwrap();

        assert_eq!(status, "200");
        assert_eq!(body, "{\"ok\":1}");
    }

    #[test]
    fn dns_config_value_accepts_plain_literal_unchanged() {
        let mut dns_config = BTreeMap::new();
        dns_config.insert("api_token".to_string(), "cf-token".to_string());
        let acme = TlsAcmeConfig {
            dns_config,
            ..TlsAcmeConfig::default()
        };

        assert_eq!(dns_config_value(&acme, "api_token").unwrap(), "cf-token");
    }

    #[test]
    fn dns_config_value_resolves_env_secret_ref() {
        std::env::set_var("FERROGATE_ACME_TEST_CF_TOKEN", "resolved-token");
        let mut dns_config = BTreeMap::new();
        dns_config.insert(
            "api_token".to_string(),
            "env://FERROGATE_ACME_TEST_CF_TOKEN".to_string(),
        );
        let acme = TlsAcmeConfig {
            dns_config,
            ..TlsAcmeConfig::default()
        };

        assert_eq!(
            dns_config_value(&acme, "api_token").unwrap(),
            "resolved-token"
        );
    }

    #[test]
    fn dns_config_value_errors_when_env_secret_ref_is_unset() {
        std::env::remove_var("FERROGATE_ACME_TEST_CF_TOKEN_UNSET");
        let mut dns_config = BTreeMap::new();
        dns_config.insert(
            "api_token".to_string(),
            "env://FERROGATE_ACME_TEST_CF_TOKEN_UNSET".to_string(),
        );
        let acme = TlsAcmeConfig {
            dns_config,
            ..TlsAcmeConfig::default()
        };

        let error = dns_config_value(&acme, "api_token")
            .unwrap_err()
            .to_string();
        assert!(error.contains("resolved to no value"));
    }

    #[test]
    fn dns_config_value_rejects_missing_key() {
        let acme = TlsAcmeConfig {
            dns_config: BTreeMap::new(),
            ..TlsAcmeConfig::default()
        };

        let error = dns_config_value(&acme, "api_token")
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing tls.acme.dns_config.api_token"));
    }

    fn write_test_certificate(cert: &Path, key: &Path, days: &str) -> bool {
        let Ok(status) = Command::new("openssl")
            .env("OPENSSL_CONF", "/dev/null")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                cert.to_str().unwrap(),
                "-days",
                days,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        else {
            return false;
        };
        status.success()
    }

    fn write_unparseable_certificate(cert: &Path, key: &Path) {
        fs::write(cert, "not a pem certificate").unwrap();
        fs::write(key, "not a private key").unwrap();
    }
}
