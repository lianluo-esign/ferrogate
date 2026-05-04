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
    time::Duration,
};
use tracing::{info, warn};

use crate::config::TlsAcmeConfig;

#[derive(Debug, Clone)]
pub(crate) struct AcmeCertificatePaths {
    pub(crate) cert_path: String,
    pub(crate) key_path: String,
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

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start ACME runtime")?;
    runtime.block_on(issue_certificate(acme, &paths))?;
    Ok(paths)
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
        None => resolve_cloudflare_zone_id(api_token, dns_config_value(acme, "zone_name")?)?,
    };
    let record_name = record.name.trim_end_matches('.');
    match action {
        "set" => {
            ensure_cloudflare_txt_record(acme, api_token, &zone_id, record_name, &record.value)
        }
        "cleanup" => cleanup_cloudflare_txt_record(api_token, &zone_id, record_name, &record.value),
        _ => bail!("unsupported Cloudflare DNS action {action}"),
    }
}

fn dns_config_value<'a>(acme: &'a TlsAcmeConfig, key: &str) -> AnyResult<&'a str> {
    acme.dns_config
        .get(key)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing tls.acme.dns_config.{key}"))
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

fn tls_client_config() -> AnyResult<Arc<ClientConfig>> {
    static TLS_CLIENT_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(config) = TLS_CLIENT_CONFIG.get() {
        return Ok(Arc::clone(config));
    }

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
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TlsAcmeConfig;

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
}
