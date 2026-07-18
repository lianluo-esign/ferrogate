// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Verified mutual-TLS transport for self-hosted workers (issue #243, Phase 2).
//!
//! This module implements the *verified* side of the self-hosted worker
//! transport described in `docs/security/self-hosted-mtls-transport.md`:
//!
//! * A single, explicitly configured issuing CA is the only trust anchor for the
//!   self-hosted worker ingress. The OS/web trust store is never consulted and a
//!   trust-anchor load failure is fail-closed (T7).
//! * A real mutual-TLS handshake terminates at the gateway. The client cert must
//!   chain to the configured anchor and be unexpired against the **server** clock
//!   (T1, T5). rustls/webpki performs chain + signature + validity verification
//!   during the handshake; this module additionally re-checks `notAfter` against
//!   the caller-supplied server clock so the security decision never trusts
//!   client-reported time.
//! * The leaf cert cryptographically binds to the exact 4-tuple
//!   (`tenant/workspace/worker/token`) via a SPIFFE-style URI SAN, and a request
//!   is only authorized when that binding equals the enclosed identity envelope,
//!   so a cert issued for worker A cannot authenticate worker B (T6).
//! * [`VerifiedMutualTls`] can *only* be constructed from a completed, verified
//!   handshake, making "the channel is encrypted and mutually authenticated" a
//!   type-level fact rather than a header string (closes the marker/AEAD
//!   downgrade, T2).
//! * A short-TTL, cert-bound transport token is issued after the handshake and
//!   supports rotation with atomic invalidation of the prior token (T3, T4).

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    io::{Read, Write},
    sync::Arc,
};

use rustls::{
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    server::WebPkiClientVerifier,
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, Stream,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};

use crate::self_hosted_worker::{generate_transport_token_secret, SelfHostedWorkerIdentity};

/// Canonical SPIFFE-style identity prefix that binds a self-hosted worker leaf
/// certificate to its 4-tuple. The full URI SAN is
/// `spiffe://ferrogate/self-hosted/{tenant_id}/{workspace_id}/{worker_id}/{token_id}`.
pub const SELF_HOSTED_WORKER_SPIFFE_PREFIX: &str = "spiffe://ferrogate/self-hosted/";

/// Default short lifetime for a cert-bound transport token (seconds). The token
/// is a bearer credential on an already-verified channel; a short TTL bounds the
/// blast radius of a stolen token and forces frequent, cert-checked rotation.
pub const DEFAULT_SELF_HOSTED_TRANSPORT_TOKEN_TTL_SECS: u64 = 300;

/// Upper bound on a transport-token TTL. Anything longer defeats the point of a
/// short-lived, rotate-often bearer credential and is rejected fail-closed.
pub const MAX_SELF_HOSTED_TRANSPORT_TOKEN_TTL_SECS: u64 = 3600;

/// Errors from the verified mutual-TLS transport path. Every variant is a
/// fail-closed refusal: the ingress admits nothing it cannot positively verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfHostedMtlsError {
    /// The configured trust anchor could not be loaded/parsed. The ingress must
    /// not start or must reject every request (fail closed, T7).
    TrustAnchorLoad(String),
    /// Building the rustls verifier/server configuration failed.
    Config(String),
    /// The mutual-TLS handshake did not complete or the client presented no
    /// certificate chaining to the configured anchor.
    Handshake(String),
    /// The presented leaf certificate could not be parsed.
    CertificateParse(String),
    /// The leaf certificate is expired against the server clock (T5).
    Expired(String),
    /// The certificate's 4-tuple binding is missing/malformed, or does not equal
    /// the enclosed request identity (cross-worker reuse, T6).
    IdentityBinding(String),
    /// A transport token was rejected (unknown, expired, wrong secret, or bound
    /// to a different certificate).
    TokenRejected(String),
}

impl fmt::Display for SelfHostedMtlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TrustAnchorLoad(message) => {
                write!(
                    formatter,
                    "self-hosted worker mTLS trust anchor load failed: {message}"
                )
            }
            Self::Config(message) => {
                write!(
                    formatter,
                    "self-hosted worker mTLS configuration failed: {message}"
                )
            }
            Self::Handshake(message) => {
                write!(
                    formatter,
                    "self-hosted worker mTLS handshake rejected: {message}"
                )
            }
            Self::CertificateParse(message) => {
                write!(
                    formatter,
                    "self-hosted worker client certificate parse failed: {message}"
                )
            }
            Self::Expired(message) => {
                write!(
                    formatter,
                    "self-hosted worker client certificate expired: {message}"
                )
            }
            Self::IdentityBinding(message) => {
                write!(
                    formatter,
                    "self-hosted worker certificate identity binding rejected: {message}"
                )
            }
            Self::TokenRejected(message) => {
                write!(
                    formatter,
                    "self-hosted worker transport token rejected: {message}"
                )
            }
        }
    }
}

impl Error for SelfHostedMtlsError {}

/// The self-hosted worker identity 4-tuple, cryptographically bound into a leaf
/// certificate's SPIFFE URI SAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedWorkerCertBinding {
    pub tenant_id: String,
    pub workspace_id: String,
    pub worker_id: String,
    pub token_id: String,
}

impl SelfHostedWorkerCertBinding {
    /// The canonical SPIFFE URI SAN that encodes this binding.
    pub fn spiffe_uri(&self) -> String {
        format!(
            "{SELF_HOSTED_WORKER_SPIFFE_PREFIX}{}/{}/{}/{}",
            self.tenant_id, self.workspace_id, self.worker_id, self.token_id
        )
    }

    /// Parse the binding out of a SPIFFE URI SAN. Requires the exact prefix and
    /// exactly four non-empty path segments; anything else is rejected so a
    /// malformed or ambiguous identity can never be admitted.
    pub fn from_spiffe_uri(uri: &str) -> Result<Self, SelfHostedMtlsError> {
        let rest = uri
            .strip_prefix(SELF_HOSTED_WORKER_SPIFFE_PREFIX)
            .ok_or_else(|| {
                SelfHostedMtlsError::IdentityBinding(format!(
                    "certificate URI SAN {uri} is not a self-hosted worker SPIFFE identity"
                ))
            })?;
        let segments: Vec<&str> = rest.split('/').collect();
        if segments.len() != 4 || segments.iter().any(|segment| segment.is_empty()) {
            return Err(SelfHostedMtlsError::IdentityBinding(format!(
                "certificate SPIFFE identity {uri} must carry a tenant/workspace/worker/token 4-tuple"
            )));
        }
        Ok(Self {
            tenant_id: segments[0].to_string(),
            workspace_id: segments[1].to_string(),
            worker_id: segments[2].to_string(),
            token_id: segments[3].to_string(),
        })
    }

    /// Whether this binding exactly equals an enclosed request identity envelope.
    pub fn matches_identity(&self, identity: &SelfHostedWorkerIdentity) -> bool {
        self.tenant_id == identity.tenant_id
            && self.workspace_id == identity.workspace_id
            && self.worker_id == identity.worker_id
            && self.token_id == identity.token_id
    }
}

/// The single configured issuing CA for the self-hosted worker ingress.
///
/// This is the *only* trust anchor the mTLS verifier consults; it never falls
/// back to the OS or web PKI. Construction validates the anchor and is
/// fail-closed on any parse/load error.
#[derive(Debug, Clone)]
pub struct SelfHostedMtlsTrustAnchor {
    roots: Arc<RootCertStore>,
}

impl SelfHostedMtlsTrustAnchor {
    /// Load the trust anchor from a single DER-encoded CA certificate.
    pub fn from_der(der: impl Into<Vec<u8>>) -> Result<Self, SelfHostedMtlsError> {
        let der = CertificateDer::from(der.into());
        // Parse the anchor up front so a malformed CA fails closed at load time
        // rather than surfacing as an opaque handshake failure later.
        X509Certificate::from_der(der.as_ref()).map_err(|error| {
            SelfHostedMtlsError::TrustAnchorLoad(format!(
                "configured CA is not a valid X.509 certificate: {error:?}"
            ))
        })?;
        let mut roots = RootCertStore::empty();
        roots.add(der).map_err(|error| {
            SelfHostedMtlsError::TrustAnchorLoad(format!(
                "configured CA could not be added to the trust store: {error}"
            ))
        })?;
        Ok(Self {
            roots: Arc::new(roots),
        })
    }

    /// Load the trust anchor from a PEM document containing exactly one CA
    /// certificate. Zero or more-than-one certificate is rejected fail-closed so
    /// the ingress cannot silently trust an unexpected extra anchor.
    pub fn from_pem(pem: &str) -> Result<Self, SelfHostedMtlsError> {
        let mut reader = std::io::BufReader::new(pem.as_bytes());
        let mut anchors = Vec::new();
        for entry in rustls_pemfile::certs(&mut reader) {
            let cert = entry.map_err(|error| {
                SelfHostedMtlsError::TrustAnchorLoad(format!(
                    "trust anchor PEM is not valid: {error}"
                ))
            })?;
            anchors.push(cert);
        }
        if anchors.len() != 1 {
            return Err(SelfHostedMtlsError::TrustAnchorLoad(format!(
                "self-hosted worker ingress requires exactly one configured issuing CA; found {}",
                anchors.len()
            )));
        }
        Self::from_der(anchors.remove(0).to_vec())
    }

    fn roots(&self) -> Arc<RootCertStore> {
        self.roots.clone()
    }
}

/// Proof that a self-hosted worker request arrived on a completed, verified
/// mutual-TLS channel: the peer cert chained to the configured anchor, was
/// unexpired against the server clock, and carried a SPIFFE 4-tuple binding.
///
/// There is intentionally **no public constructor**. The only way to obtain a
/// value is [`SelfHostedMtlsServer::accept`] completing a real handshake and
/// verifying the peer certificate, which makes verified mutual TLS a type-level
/// fact instead of a claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMutualTls {
    binding: SelfHostedWorkerCertBinding,
    cert_fingerprint: String,
    not_after_unix: u64,
    verified_at_unix: u64,
}

impl VerifiedMutualTls {
    /// The 4-tuple the peer certificate binds to.
    pub fn binding(&self) -> &SelfHostedWorkerCertBinding {
        &self.binding
    }

    /// SHA-256 fingerprint (lowercase hex) of the verified leaf certificate.
    pub fn cert_fingerprint(&self) -> &str {
        &self.cert_fingerprint
    }

    /// Server-clock `notAfter` (unix seconds) of the verified leaf certificate.
    pub fn not_after_unix(&self) -> u64 {
        self.not_after_unix
    }

    /// Server-clock instant the handshake was verified at.
    pub fn verified_at_unix(&self) -> u64 {
        self.verified_at_unix
    }

    /// Authorize an enclosed request identity envelope against the cert binding.
    /// Rejects cross-worker/cross-tenant certificate reuse (T6).
    pub fn authorize_identity(
        &self,
        identity: &SelfHostedWorkerIdentity,
    ) -> Result<(), SelfHostedMtlsError> {
        if self.binding.matches_identity(identity) {
            return Ok(());
        }
        Err(SelfHostedMtlsError::IdentityBinding(format!(
            "certificate is bound to {} but the request identity is {}/{}/{}/{}",
            self.binding.spiffe_uri(),
            identity.tenant_id,
            identity.workspace_id,
            identity.worker_id,
            identity.token_id
        )))
    }
}

/// A verified mutual-TLS server terminating self-hosted worker client certs.
///
/// The server requires client authentication against the single configured trust
/// anchor. The rustls `ServerConfig` is built with an explicit crypto provider so
/// no ambient/process-default provider is relied upon.
#[derive(Clone)]
pub struct SelfHostedMtlsServer {
    server_config: Arc<ServerConfig>,
}

impl SelfHostedMtlsServer {
    /// Build a server that requires + verifies client certs against `anchor`,
    /// presenting `server_cert_chain_der` (leaf-first) with `server_key_pkcs8_der`.
    pub fn new(
        anchor: &SelfHostedMtlsTrustAnchor,
        server_cert_chain_der: Vec<Vec<u8>>,
        server_key_pkcs8_der: Vec<u8>,
    ) -> Result<Self, SelfHostedMtlsError> {
        let provider = ring_provider();
        let verifier =
            WebPkiClientVerifier::builder_with_provider(anchor.roots(), provider.clone())
                .build()
                .map_err(|error| {
                    SelfHostedMtlsError::Config(format!(
                        "client certificate verifier build failed: {error}"
                    ))
                })?;
        let chain: Vec<CertificateDer<'static>> = server_cert_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_pkcs8_der));
        let server_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| {
                SelfHostedMtlsError::Config(format!("protocol version selection failed: {error}"))
            })?
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .map_err(|error| {
                SelfHostedMtlsError::Config(format!("server certificate/key rejected: {error}"))
            })?;
        Ok(Self {
            server_config: Arc::new(server_config),
        })
    }

    /// Terminate a mutual-TLS handshake on an accepted byte stream and verify the
    /// peer certificate. Returns a live [`SelfHostedMtlsConnection`] whose
    /// [`VerifiedMutualTls`] proof gates admission, and over which the enclosed
    /// request/response can be exchanged as encrypted application data.
    ///
    /// `now_unix` is the authoritative server clock used for the `notAfter`
    /// re-check; client-reported time is never consulted.
    pub fn accept<S>(
        &self,
        mut io: S,
        now_unix: u64,
    ) -> Result<SelfHostedMtlsConnection<S>, SelfHostedMtlsError>
    where
        S: Read + Write,
    {
        let mut conn = ServerConnection::new(self.server_config.clone()).map_err(|error| {
            SelfHostedMtlsError::Handshake(format!("server connection init failed: {error}"))
        })?;
        // Drive the blocking handshake to completion. rustls/webpki verifies the
        // client chain against the configured anchor and rejects an expired or
        // untrusted cert here (T1, T5, T7).
        let mut progressed_without_data = 0_u8;
        while conn.is_handshaking() {
            let (read, written) = conn.complete_io(&mut io).map_err(|error| {
                SelfHostedMtlsError::Handshake(format!("handshake i/o failed: {error}"))
            })?;
            if read == 0 && written == 0 {
                progressed_without_data += 1;
                if progressed_without_data > 1 {
                    return Err(SelfHostedMtlsError::Handshake(
                        "handshake stalled before completion".to_string(),
                    ));
                }
            } else {
                progressed_without_data = 0;
            }
        }
        let peer_chain = conn.peer_certificates().ok_or_else(|| {
            SelfHostedMtlsError::Handshake(
                "client presented no certificate on the mutual-TLS channel".to_string(),
            )
        })?;
        let leaf = peer_chain.first().ok_or_else(|| {
            SelfHostedMtlsError::Handshake("client certificate chain was empty".to_string())
        })?;
        let verified = verify_leaf_certificate(leaf, now_unix)?;
        Ok(SelfHostedMtlsConnection { conn, io, verified })
    }
}

/// A live, verified mutual-TLS connection to a self-hosted worker. Reads/writes
/// are the encrypted application stream; [`verified`](Self::verified) is the
/// admission proof.
pub struct SelfHostedMtlsConnection<S: Read + Write> {
    conn: ServerConnection,
    io: S,
    verified: VerifiedMutualTls,
}

impl<S: Read + Write> SelfHostedMtlsConnection<S> {
    /// The verified-mutual-TLS proof for this connection.
    pub fn verified(&self) -> &VerifiedMutualTls {
        &self.verified
    }

    /// Consume the connection, returning the admission proof.
    pub fn into_verified(self) -> VerifiedMutualTls {
        self.verified
    }
}

impl<S: Read + Write> Read for SelfHostedMtlsConnection<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Stream::new(&mut self.conn, &mut self.io).read(buf)
    }
}

impl<S: Read + Write> Write for SelfHostedMtlsConnection<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Stream::new(&mut self.conn, &mut self.io).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Stream::new(&mut self.conn, &mut self.io).flush()
    }
}

/// Verify a peer leaf certificate: re-check `notAfter` against the server clock
/// and extract the SPIFFE 4-tuple binding. The chain/signature was already
/// validated by rustls/webpki during the handshake; this is the server-clock and
/// identity-binding layer the design requires on top of it.
fn verify_leaf_certificate(
    leaf: &CertificateDer<'_>,
    now_unix: u64,
) -> Result<VerifiedMutualTls, SelfHostedMtlsError> {
    let (_, parsed) = X509Certificate::from_der(leaf.as_ref()).map_err(|error| {
        SelfHostedMtlsError::CertificateParse(format!(
            "leaf certificate is not valid X.509: {error:?}"
        ))
    })?;

    // Server-clock authoritative expiry (T5): never trust client-reported time.
    let not_after = parsed.validity().not_after.timestamp();
    if not_after < 0 {
        return Err(SelfHostedMtlsError::Expired(
            "leaf certificate notAfter predates the unix epoch".to_string(),
        ));
    }
    let not_after_unix = not_after as u64;
    if now_unix >= not_after_unix {
        return Err(SelfHostedMtlsError::Expired(format!(
            "leaf certificate expired at {not_after_unix} (server clock {now_unix})"
        )));
    }

    let binding = extract_spiffe_binding(&parsed)?;
    let cert_fingerprint = sha256_hex(leaf.as_ref());
    Ok(VerifiedMutualTls {
        binding,
        cert_fingerprint,
        not_after_unix,
        verified_at_unix: now_unix,
    })
}

/// Extract the single self-hosted worker SPIFFE URI SAN and parse its 4-tuple.
fn extract_spiffe_binding(
    parsed: &X509Certificate<'_>,
) -> Result<SelfHostedWorkerCertBinding, SelfHostedMtlsError> {
    let mut spiffe_uri: Option<String> = None;
    for extension in parsed.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name {
                    if uri.starts_with(SELF_HOSTED_WORKER_SPIFFE_PREFIX) {
                        if spiffe_uri.is_some() {
                            return Err(SelfHostedMtlsError::IdentityBinding(
                                "leaf certificate carries multiple self-hosted worker SPIFFE identities"
                                    .to_string(),
                            ));
                        }
                        spiffe_uri = Some((*uri).to_string());
                    }
                }
            }
        }
    }
    let uri = spiffe_uri.ok_or_else(|| {
        SelfHostedMtlsError::IdentityBinding(
            "leaf certificate has no self-hosted worker SPIFFE URI SAN".to_string(),
        )
    })?;
    SelfHostedWorkerCertBinding::from_spiffe_uri(&uri)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn ring_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A short-lived, cert-bound bearer credential issued after a verified handshake.
///
/// The secret is kept private and compared in constant time; the token is bound
/// to the presenting certificate's fingerprint and 4-tuple so it cannot be
/// replayed on a different channel/worker. Expiry is stamped by the server clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfHostedTransportToken {
    token_id: String,
    secret: String,
    binding: SelfHostedWorkerCertBinding,
    cert_fingerprint: String,
    issued_at_unix: u64,
    expires_at_unix: u64,
}

impl SelfHostedTransportToken {
    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    /// The bearer secret the worker presents on subsequent requests. Exposed so
    /// the issuing side can hand it to the worker exactly once; it is never
    /// compared except in constant time via [`matches_secret`](Self::matches_secret).
    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn binding(&self) -> &SelfHostedWorkerCertBinding {
        &self.binding
    }

    pub fn cert_fingerprint(&self) -> &str {
        &self.cert_fingerprint
    }

    pub fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    /// Whether the token is expired against the server clock.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at_unix
    }

    /// Constant-time comparison of a presented secret against this token.
    pub fn matches_secret(&self, presented_secret: &str) -> bool {
        let (a, b) = (self.secret.as_bytes(), presented_secret.as_bytes());
        a.len() == b.len() && a.ct_eq(b).into()
    }
}

/// Mints cert-bound transport tokens with a short, bounded TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfHostedTransportTokenIssuer {
    ttl_secs: u64,
}

impl Default for SelfHostedTransportTokenIssuer {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_SELF_HOSTED_TRANSPORT_TOKEN_TTL_SECS,
        }
    }
}

impl SelfHostedTransportTokenIssuer {
    /// Construct an issuer with an explicit TTL (seconds). Rejects a zero or
    /// over-long TTL fail-closed.
    pub fn new(ttl_secs: u64) -> Result<Self, SelfHostedMtlsError> {
        if ttl_secs == 0 {
            return Err(SelfHostedMtlsError::TokenRejected(
                "transport token TTL must be greater than zero".to_string(),
            ));
        }
        if ttl_secs > MAX_SELF_HOSTED_TRANSPORT_TOKEN_TTL_SECS {
            return Err(SelfHostedMtlsError::TokenRejected(format!(
                "transport token TTL {ttl_secs}s exceeds the maximum {MAX_SELF_HOSTED_TRANSPORT_TOKEN_TTL_SECS}s"
            )));
        }
        Ok(Self { ttl_secs })
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// Mint a fresh transport token bound to a verified handshake. The token
    /// never outlives the certificate: its expiry is the earlier of `now + TTL`
    /// and the cert `notAfter` (both server-clock).
    pub fn issue(&self, verified: &VerifiedMutualTls, now_unix: u64) -> SelfHostedTransportToken {
        let ttl_expiry = now_unix.saturating_add(self.ttl_secs);
        let expires_at_unix = ttl_expiry.min(verified.not_after_unix());
        SelfHostedTransportToken {
            token_id: generate_transport_token_secret(),
            secret: generate_transport_token_secret(),
            binding: verified.binding().clone(),
            cert_fingerprint: verified.cert_fingerprint().to_string(),
            issued_at_unix: now_unix,
            expires_at_unix,
        }
    }
}

/// In-memory registry of live transport tokens with rotation + revocation.
///
/// Rotation mirrors the invariants of the long-lived worker token rotation
/// (`SelfHostedWorkerRegistry::rotate_token`): the caller must present a valid
/// current token before a new one is minted, the new material is always non-empty
/// (CSPRNG), and the old token is invalidated atomically with the new one taking
/// its place. Transport tokens additionally require the rotation to be presented
/// on the *same* certificate they were bound to.
#[derive(Debug, Default, Clone)]
pub struct SelfHostedTransportTokenStore {
    tokens: BTreeMap<String, SelfHostedTransportToken>,
}

impl SelfHostedTransportTokenStore {
    /// Issue and store a fresh token for a verified handshake.
    pub fn issue(
        &mut self,
        issuer: &SelfHostedTransportTokenIssuer,
        verified: &VerifiedMutualTls,
        now_unix: u64,
    ) -> SelfHostedTransportToken {
        let token = issuer.issue(verified, now_unix);
        self.tokens.insert(token.token_id.clone(), token.clone());
        token
    }

    /// Validate a presented token id + secret against the store and the server
    /// clock. Returns the live token on success.
    pub fn validate(
        &self,
        token_id: &str,
        presented_secret: &str,
        now_unix: u64,
    ) -> Result<&SelfHostedTransportToken, SelfHostedMtlsError> {
        let token = self.tokens.get(token_id).ok_or_else(|| {
            SelfHostedMtlsError::TokenRejected("unknown transport token".to_string())
        })?;
        if token.is_expired(now_unix) {
            return Err(SelfHostedMtlsError::TokenRejected(
                "transport token has expired".to_string(),
            ));
        }
        if !token.matches_secret(presented_secret) {
            return Err(SelfHostedMtlsError::TokenRejected(
                "transport token secret does not match".to_string(),
            ));
        }
        Ok(token)
    }

    /// Rotate a still-valid token, atomically invalidating the old one. The
    /// rotation must be authorized by a fresh verified handshake on the same
    /// certificate the current token was bound to.
    pub fn rotate(
        &mut self,
        issuer: &SelfHostedTransportTokenIssuer,
        current_token_id: &str,
        presented_secret: &str,
        verified: &VerifiedMutualTls,
        now_unix: u64,
    ) -> Result<SelfHostedTransportToken, SelfHostedMtlsError> {
        // Validate-before-rotate: the current token must still be valid.
        {
            let current = self.validate(current_token_id, presented_secret, now_unix)?;
            // The new material must be bound to the same certificate that the
            // rotating token was bound to (cert-bound rotation, T4).
            if current.cert_fingerprint != verified.cert_fingerprint() {
                return Err(SelfHostedMtlsError::TokenRejected(
                    "transport token rotation presented a different client certificate".to_string(),
                ));
            }
            if &current.binding != verified.binding() {
                return Err(SelfHostedMtlsError::TokenRejected(
                    "transport token rotation presented a different worker identity".to_string(),
                ));
            }
        }
        let rotated = issuer.issue(verified, now_unix);
        // Atomic swap: remove the old token and insert the new one.
        self.tokens.remove(current_token_id);
        self.tokens
            .insert(rotated.token_id.clone(), rotated.clone());
        Ok(rotated)
    }

    /// Immediately invalidate a token (cert revoke / worker deactivate).
    pub fn revoke(&mut self, token_id: &str) -> bool {
        self.tokens.remove(token_id).is_some()
    }

    /// Drop every expired token from the store (housekeeping).
    pub fn purge_expired(&mut self, now_unix: u64) {
        self.tokens.retain(|_, token| !token.is_expired(now_unix));
    }

    /// Number of live (stored) tokens.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

/// Build a rustls client configuration for a self-hosted worker node: trust only
/// the configured gateway anchor and present the node's client certificate.
///
/// This is the node-side counterpart to [`SelfHostedMtlsServer`]. It is exposed
/// so the worker transport client (and the conformance tests) can drive a real
/// mutual-TLS handshake without an external PKI.
pub fn build_self_hosted_worker_client_config(
    anchor: &SelfHostedMtlsTrustAnchor,
    client_cert_chain_der: Vec<Vec<u8>>,
    client_key_pkcs8_der: Vec<u8>,
) -> Result<ClientConfig, SelfHostedMtlsError> {
    let provider = ring_provider();
    let chain: Vec<CertificateDer<'static>> = client_cert_chain_der
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key_pkcs8_der));
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| {
            SelfHostedMtlsError::Config(format!("protocol version selection failed: {error}"))
        })?
        .with_root_certificates((*anchor.roots()).clone())
        .with_client_auth_cert(chain, key)
        .map_err(|error| {
            SelfHostedMtlsError::Config(format!("client certificate/key rejected: {error}"))
        })
}

/// Convenience constructor for a rustls client-side connection to the gateway.
pub fn connect_self_hosted_worker_client(
    config: Arc<ClientConfig>,
    server_name: &str,
) -> Result<ClientConnection, SelfHostedMtlsError> {
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|error| SelfHostedMtlsError::Config(format!("invalid server name: {error}")))?;
    ClientConnection::new(config, name).map_err(|error| {
        SelfHostedMtlsError::Handshake(format!("client connection init failed: {error}"))
    })
}

#[cfg(test)]
#[path = "self_hosted_mtls_conformance_test.rs"]
mod self_hosted_mtls_conformance_test;
