// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Pluggable malware-scan backend for hosted assets (issue #261,
// continues #179). The #179 EICAR check self-documented as a stand-in "does
// the scanning step run" proof, not an AV engine. This introduces a real
// scanner seam: an `AssetScanner` trait with an offline default
// (`EicarScanner`, keeps tests network-free) plus opt-in `ClamAvScanner`
// (clamd INSTREAM over TCP) and `HttpScanner` (hosted-scanner HTTP) adapters.
// Scanner-unavailable is a first-class outcome resolved per a configured
// fail-closed vs quarantine policy, and large objects can defer to an async
// scan (the asset stays `PendingScan`, invisible until proven clean).

use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// The standard EICAR antivirus test file signature
/// (<https://www.eicar.org/>) -- not a real virus, a fixed byte string every
/// AV product recognizes deliberately, used both by the offline
/// [`EicarScanner`] default and as the canonical "malware is detected and
/// rejected" proof a real ClamAV/hosted-scanner integration must also pass.
pub(crate) const EICAR_TEST_SIGNATURE: &[u8] =
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Whether `content` embeds the EICAR test signature anywhere. Shared by the
/// synchronous fast-reject in `asset_security` and the [`EicarScanner`] so the
/// two never diverge.
pub(crate) fn contains_eicar(content: &[u8]) -> bool {
    content.len() >= EICAR_TEST_SIGNATURE.len()
        && content
            .windows(EICAR_TEST_SIGNATURE.len())
            .any(|window| window == EICAR_TEST_SIGNATURE)
}

/// The raw verdict a scanner returns before policy is applied. `Unavailable`
/// (the scanner could not be reached / errored) is deliberately distinct from
/// `Clean` so it is never silently treated as a pass -- the caller decides,
/// per [`ScannerUnavailablePolicy`], whether that fails closed or quarantines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScanVerdict {
    Clean,
    Infected(String),
    Unavailable(String),
}

/// What to do when the scanner itself is unavailable (down, timed out,
/// malformed response). Never "allow": the choice is only between rejecting
/// the push outright or admitting it into quarantine (stored but invisible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScannerUnavailablePolicy {
    /// Reject the push; the asset is never stored.
    FailClosed,
    /// Store the asset in quarantine (invisible) pending a later clean scan.
    Quarantine,
}

/// The durable scan state of a *stored* asset version. Only `Clean` is visible
/// to consumers; `PendingScan`/`Quarantined` are withheld so a still-unproven
/// blob can never be fetched and executed by another tenant's agent. (A scan
/// that outright rejects the content never produces a stored state -- the push
/// itself fails, see [`ScanOutcome::Reject`].)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanState {
    Clean,
    PendingScan,
    Quarantined,
}

impl ScanState {
    /// The stable wire string surfaced in the verification manifest / audit.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ScanState::Clean => "clean",
            ScanState::PendingScan => "pending_scan",
            ScanState::Quarantined => "quarantined",
        }
    }

    /// Whether an asset in this scan state may be listed/pulled. Every
    /// not-yet-proven-clean state fails closed to invisible (#261 slice 1).
    pub(crate) fn is_visible(self) -> bool {
        matches!(self, ScanState::Clean)
    }
}

/// The resolved outcome of a scan once [`ScannerUnavailablePolicy`] has been
/// applied to a [`ScanVerdict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScanOutcome {
    /// Clean -- store and make visible.
    Admit,
    /// Store but withhold from consumers (quarantine) with this reason.
    Quarantine(String),
    /// Reject the push entirely with this reason.
    Reject(String),
}

/// Fold a raw [`ScanVerdict`] into a [`ScanOutcome`] under the configured
/// unavailable policy. `Infected` always rejects; `Unavailable` never passes.
pub(crate) fn resolve_scan_outcome(
    verdict: ScanVerdict,
    policy: ScannerUnavailablePolicy,
) -> ScanOutcome {
    match verdict {
        ScanVerdict::Clean => ScanOutcome::Admit,
        ScanVerdict::Infected(reason) => {
            ScanOutcome::Reject(format!("content failed malware scan: {reason}"))
        }
        ScanVerdict::Unavailable(reason) => match policy {
            ScannerUnavailablePolicy::FailClosed => {
                ScanOutcome::Reject(format!("scanner unavailable (fail-closed): {reason}"))
            }
            ScannerUnavailablePolicy::Quarantine => ScanOutcome::Quarantine(format!(
                "scanner unavailable, admitted to quarantine: {reason}"
            )),
        },
    }
}

/// A pluggable content scanner. Kept behind a trait so the default stays
/// offline/test-friendly and real backends (clamd, hosted HTTP) are opt-in.
#[async_trait]
pub(crate) trait AssetScanner: Send + Sync {
    async fn scan(&self, content: &[u8]) -> ScanVerdict;
    /// Stable identifier for the manifest/audit (`eicar`, `clamav`, `http`).
    fn backend_name(&self) -> &'static str;
}

/// Offline default: the EICAR fixed-string check. No network, deterministic --
/// this is what tests and un-configured deployments use.
pub(crate) struct EicarScanner;

#[async_trait]
impl AssetScanner for EicarScanner {
    async fn scan(&self, content: &[u8]) -> ScanVerdict {
        if contains_eicar(content) {
            ScanVerdict::Infected("EICAR-STANDARD-ANTIVIRUS-TEST-FILE".to_string())
        } else {
            ScanVerdict::Clean
        }
    }

    fn backend_name(&self) -> &'static str {
        "eicar"
    }
}

/// clamd INSTREAM adapter: streams the content to a `clamav-daemon` over TCP
/// and parses its `stream: OK` / `stream: <sig> FOUND` reply. Any I/O failure
/// becomes `Unavailable` (never a silent pass).
pub(crate) struct ClamAvScanner {
    addr: String,
    timeout: Duration,
}

impl ClamAvScanner {
    pub(crate) fn new(addr: impl Into<String>, timeout: Duration) -> Self {
        Self {
            addr: addr.into(),
            timeout,
        }
    }

    async fn scan_inner(&self, content: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect(&self.addr).await?;
        // clamd INSTREAM: `zINSTREAM\0`, then <u32 be length><bytes> chunks,
        // terminated by a zero-length (u32 0) chunk.
        stream.write_all(b"zINSTREAM\0").await?;
        for chunk in content.chunks(64 * 1024) {
            stream
                .write_all(&(chunk.len() as u32).to_be_bytes())
                .await?;
            stream.write_all(chunk).await?;
        }
        stream.write_all(&0u32.to_be_bytes()).await?;
        stream.flush().await?;
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await?;
        Ok(reply)
    }

    pub(crate) async fn scan(&self, content: &[u8]) -> ScanVerdict {
        match tokio::time::timeout(self.timeout, self.scan_inner(content)).await {
            Ok(Ok(reply)) => parse_clamd_response(&reply),
            Ok(Err(error)) => ScanVerdict::Unavailable(format!("clamd I/O error: {error}")),
            Err(_) => ScanVerdict::Unavailable("clamd request timed out".to_string()),
        }
    }
}

#[async_trait]
impl AssetScanner for ClamAvScanner {
    async fn scan(&self, content: &[u8]) -> ScanVerdict {
        ClamAvScanner::scan(self, content).await
    }

    fn backend_name(&self) -> &'static str {
        "clamav"
    }
}

/// Parse a clamd INSTREAM reply (`stream: OK\0`, `stream: Eicar-Test FOUND\0`,
/// or an error) into a [`ScanVerdict`]. Pure so it is unit-testable without a
/// live daemon.
pub(crate) fn parse_clamd_response(reply: &[u8]) -> ScanVerdict {
    let text = String::from_utf8_lossy(reply);
    let text = text.trim_end_matches(['\0', '\n', '\r']).trim();
    if text.is_empty() {
        return ScanVerdict::Unavailable("empty clamd reply".to_string());
    }
    if text.ends_with("OK") && !text.contains("FOUND") {
        return ScanVerdict::Clean;
    }
    if let Some(found) = text.strip_suffix("FOUND") {
        // `stream: <signature> FOUND` -> extract the signature name.
        let signature = found
            .trim()
            .rsplit(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        return ScanVerdict::Infected(if signature.is_empty() {
            "unknown-signature".to_string()
        } else {
            signature
        });
    }
    ScanVerdict::Unavailable(format!("unexpected clamd reply: {text}"))
}

/// Hosted-scanner HTTP adapter: POSTs the raw bytes to a scanning service and
/// reads a `{"verdict":"clean|infected", "signature":"..."}` JSON reply.
pub(crate) struct HttpScanner {
    endpoint: String,
    client: reqwest::Client,
}

impl HttpScanner {
    pub(crate) fn new(endpoint: impl Into<String>, timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();
        Self {
            endpoint: endpoint.into(),
            client,
        }
    }
}

#[async_trait]
impl AssetScanner for HttpScanner {
    async fn scan(&self, content: &[u8]) -> ScanVerdict {
        let response = self
            .client
            .post(&self.endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(content.to_vec())
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => return ScanVerdict::Unavailable(format!("scanner HTTP error: {error}")),
        };
        if !response.status().is_success() {
            return ScanVerdict::Unavailable(format!(
                "scanner returned status {}",
                response.status()
            ));
        }
        match response.bytes().await {
            Ok(body) => parse_http_scan_response(&body),
            Err(error) => ScanVerdict::Unavailable(format!("scanner body error: {error}")),
        }
    }

    fn backend_name(&self) -> &'static str {
        "http"
    }
}

/// Parse a hosted-scanner JSON body into a verdict. Pure/offline-testable.
pub(crate) fn parse_http_scan_response(body: &[u8]) -> ScanVerdict {
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) => return ScanVerdict::Unavailable(format!("scanner reply not JSON: {error}")),
    };
    match value.get("verdict").and_then(|v| v.as_str()) {
        Some("clean") => ScanVerdict::Clean,
        Some("infected") => ScanVerdict::Infected(
            value
                .get("signature")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown-signature")
                .to_string(),
        ),
        other => ScanVerdict::Unavailable(format!(
            "scanner returned unknown verdict {:?}",
            other.unwrap_or("<missing>")
        )),
    }
}

/// Which backend a deployment scans with, plus the unavailable policy and the
/// async-scan threshold. Default = offline EICAR, fail-closed, no deferral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssetScanConfig {
    pub backend: ScanBackend,
    pub unavailable_policy: ScannerUnavailablePolicy,
    /// Content strictly larger than this defers to an async scan (stored
    /// `PendingScan`, invisible until a follow-up scan proves it clean).
    /// `None` = always scan inline.
    pub async_threshold_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScanBackend {
    Eicar,
    ClamAv { addr: String, timeout_secs: u64 },
    Http { endpoint: String, timeout_secs: u64 },
}

impl Default for AssetScanConfig {
    fn default() -> Self {
        Self {
            backend: ScanBackend::Eicar,
            unavailable_policy: ScannerUnavailablePolicy::FailClosed,
            async_threshold_bytes: None,
        }
    }
}

impl AssetScanConfig {
    /// Build config from the environment so real backends are opt-in without a
    /// control-plane config-schema change (keeps this feature's blast radius to
    /// the gateway crate). Unknown/unset => the offline EICAR default.
    pub(crate) fn from_env() -> Self {
        let backend = match std::env::var("FERROGATE_ASSET_SCANNER").ok().as_deref() {
            Some("clamav") => {
                let addr = std::env::var("FERROGATE_ASSET_SCANNER_ADDR")
                    .unwrap_or_else(|_| "127.0.0.1:3310".to_string());
                ScanBackend::ClamAv {
                    addr,
                    timeout_secs: scanner_timeout_secs(),
                }
            }
            Some("http") => match std::env::var("FERROGATE_ASSET_SCANNER_ENDPOINT") {
                Ok(endpoint) => ScanBackend::Http {
                    endpoint,
                    timeout_secs: scanner_timeout_secs(),
                },
                Err(_) => ScanBackend::Eicar,
            },
            _ => ScanBackend::Eicar,
        };
        let unavailable_policy = match std::env::var("FERROGATE_ASSET_SCANNER_UNAVAILABLE")
            .ok()
            .as_deref()
        {
            Some("quarantine") => ScannerUnavailablePolicy::Quarantine,
            _ => ScannerUnavailablePolicy::FailClosed,
        };
        let async_threshold_bytes = std::env::var("FERROGATE_ASSET_SCANNER_ASYNC_THRESHOLD_BYTES")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok());
        Self {
            backend,
            unavailable_policy,
            async_threshold_bytes,
        }
    }

    /// Instantiate the scanner adapter for this backend.
    pub(crate) fn build_scanner(&self) -> Box<dyn AssetScanner> {
        match &self.backend {
            ScanBackend::Eicar => Box::new(EicarScanner),
            ScanBackend::ClamAv { addr, timeout_secs } => Box::new(ClamAvScanner::new(
                addr.clone(),
                Duration::from_secs(*timeout_secs),
            )),
            ScanBackend::Http {
                endpoint,
                timeout_secs,
            } => Box::new(HttpScanner::new(
                endpoint.clone(),
                Duration::from_secs(*timeout_secs),
            )),
        }
    }

    /// Whether a `size`-byte object should defer to an async scan.
    pub(crate) fn should_defer_scan(&self, size: usize) -> bool {
        matches!(self.async_threshold_bytes, Some(limit) if size > limit)
    }
}

fn scanner_timeout_secs() -> u64 {
    std::env::var("FERROGATE_ASSET_SCANNER_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(30)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Install the process-wide rustls crypto provider before any test builds a
    /// `reqwest::Client` (via `HttpScanner::new` / `build_scanner`). The
    /// workspace `reqwest` uses the `rustls-no-provider` feature, so building a
    /// Client panics ("No rustls crypto provider is configured") unless a
    /// provider is installed first. Production installs it in `main.rs`; this
    /// mirrors that (same `ring` provider) so the client-building tests pass
    /// deterministically standalone, not just by parallel-scheduling luck in the
    /// full suite (issue #448). Idempotent: `install_default` is a no-op after
    /// the first success, so every test that reaches a Client build can call it.
    fn ensure_rustls_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// A configurable in-memory scanner so pluggability is tested without a
    /// live clamd / network.
    struct MockScanner(ScanVerdict);

    #[async_trait]
    impl AssetScanner for MockScanner {
        async fn scan(&self, _content: &[u8]) -> ScanVerdict {
            self.0.clone()
        }
        fn backend_name(&self) -> &'static str {
            "mock"
        }
    }

    #[tokio::test]
    async fn mock_clean_scanner_admits() {
        let scanner = MockScanner(ScanVerdict::Clean);
        let verdict = scanner.scan(b"hello").await;
        assert_eq!(
            resolve_scan_outcome(verdict, ScannerUnavailablePolicy::FailClosed),
            ScanOutcome::Admit
        );
    }

    #[tokio::test]
    async fn mock_infected_scanner_rejects() {
        let scanner = MockScanner(ScanVerdict::Infected("Test.Virus".into()));
        let outcome = resolve_scan_outcome(
            scanner.scan(b"x").await,
            ScannerUnavailablePolicy::Quarantine,
        );
        // Infected rejects regardless of the unavailable policy.
        assert!(matches!(outcome, ScanOutcome::Reject(reason) if reason.contains("Test.Virus")));
    }

    #[tokio::test]
    async fn unavailable_fail_closed_rejects() {
        let scanner = MockScanner(ScanVerdict::Unavailable("connection refused".into()));
        let outcome = resolve_scan_outcome(
            scanner.scan(b"x").await,
            ScannerUnavailablePolicy::FailClosed,
        );
        assert!(matches!(outcome, ScanOutcome::Reject(reason) if reason.contains("fail-closed")));
    }

    #[tokio::test]
    async fn unavailable_quarantine_withholds() {
        let scanner = MockScanner(ScanVerdict::Unavailable("timeout".into()));
        let outcome = resolve_scan_outcome(
            scanner.scan(b"x").await,
            ScannerUnavailablePolicy::Quarantine,
        );
        assert!(matches!(outcome, ScanOutcome::Quarantine(_)));
        assert!(!ScanState::Quarantined.is_visible());
    }

    #[tokio::test]
    async fn eicar_scanner_detects_test_file() {
        let scanner = EicarScanner;
        assert_eq!(scanner.scan(b"clean bytes").await, ScanVerdict::Clean);
        let infected = [b"prefix".as_slice(), EICAR_TEST_SIGNATURE].concat();
        assert!(matches!(
            scanner.scan(&infected).await,
            ScanVerdict::Infected(_)
        ));
    }

    #[test]
    fn clamd_response_parsing() {
        assert_eq!(parse_clamd_response(b"stream: OK\0"), ScanVerdict::Clean);
        assert_eq!(
            parse_clamd_response(b"stream: Win.Test.EICAR_HDB-1 FOUND\0"),
            ScanVerdict::Infected("Win.Test.EICAR_HDB-1".to_string())
        );
        assert!(matches!(
            parse_clamd_response(b""),
            ScanVerdict::Unavailable(_)
        ));
        assert!(matches!(
            parse_clamd_response(b"garbage reply"),
            ScanVerdict::Unavailable(_)
        ));
    }

    #[test]
    fn http_response_parsing() {
        assert_eq!(
            parse_http_scan_response(br#"{"verdict":"clean"}"#),
            ScanVerdict::Clean
        );
        assert_eq!(
            parse_http_scan_response(br#"{"verdict":"infected","signature":"Foo.Bar"}"#),
            ScanVerdict::Infected("Foo.Bar".to_string())
        );
        assert!(matches!(
            parse_http_scan_response(b"not json"),
            ScanVerdict::Unavailable(_)
        ));
    }

    #[test]
    fn scan_state_visibility_fails_closed() {
        assert!(ScanState::Clean.is_visible());
        assert!(!ScanState::PendingScan.is_visible());
        assert!(!ScanState::Quarantined.is_visible());
    }

    #[test]
    fn config_selects_backend_and_defers_large_objects() {
        // The `Http` backend below builds a `reqwest::Client`, which panics
        // without a process-installed rustls crypto provider (see the helper).
        ensure_rustls_crypto_provider();

        let default = AssetScanConfig::default();
        assert_eq!(default.backend, ScanBackend::Eicar);
        assert_eq!(default.build_scanner().backend_name(), "eicar");
        assert!(!default.should_defer_scan(usize::MAX));

        let clamav = AssetScanConfig {
            backend: ScanBackend::ClamAv {
                addr: "127.0.0.1:3310".into(),
                timeout_secs: 5,
            },
            unavailable_policy: ScannerUnavailablePolicy::Quarantine,
            async_threshold_bytes: Some(1024),
        };
        assert_eq!(clamav.build_scanner().backend_name(), "clamav");
        assert!(clamav.should_defer_scan(2048));
        assert!(!clamav.should_defer_scan(512));

        let http = AssetScanConfig {
            backend: ScanBackend::Http {
                endpoint: "https://scanner.example/scan".into(),
                timeout_secs: 5,
            },
            unavailable_policy: ScannerUnavailablePolicy::FailClosed,
            async_threshold_bytes: None,
        };
        assert_eq!(http.build_scanner().backend_name(), "http");
    }
}
