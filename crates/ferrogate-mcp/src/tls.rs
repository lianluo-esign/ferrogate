// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! rustls client configuration for `https://` MCP endpoints: CA-cert
//! validation, crypto-provider selection, and the opt-in insecure verifier.

use std::sync::Arc;

use anyhow::{bail, Context, Result as AnyResult};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use rustls_pki_types::pem::PemObject;

use crate::config::McpTlsConfig;

/// Validates that `tls.ca_cert_path`, if set, points at a file that exists
/// and parses as at least one PEM certificate (issue #167). Called from
/// `validate_mcp_server_config` so a bad path fails config validation
/// instead of failing silently at first connection attempt.
pub(crate) fn validate_mcp_tls_config(tls: &McpTlsConfig) -> AnyResult<()> {
    if let Some(path) = tls.ca_cert_path.as_deref() {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read tls.ca_cert_path {path}"))?;
        let certs = CertificateDer::pem_reader_iter(&mut bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("failed to parse tls.ca_cert_path {path} as PEM"))?;
        if certs.is_empty() {
            bail!("tls.ca_cert_path {path} contains no PEM certificates");
        }
    }
    Ok(())
}

/// Builds (and does not cache, since each `McpTlsConfig` can differ per
/// server) the rustls client config used to dial `https://` MCP endpoints.
/// rustls 0.23 requires selecting a process-wide default `CryptoProvider`
/// once more than one crypto backend is compiled into the binary — which
/// happens here because `ferrogate-auth-service` depends on `rustls` with the
/// `ring` feature while this crate uses the default `aws-lc-rs` backend.
/// Installing the default explicitly and idempotently avoids the "Could not
/// automatically determine the process-level CryptoProvider" panic in any
/// binary/test that links both (issue #163/#167).
pub(crate) fn ensure_rustls_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

pub(crate) fn mcp_tls_client_config(tls: &McpTlsConfig) -> AnyResult<Arc<ClientConfig>> {
    ensure_rustls_crypto_provider();
    if tls.insecure_skip_verify {
        tracing::warn!(
            "MCP server configured with tls.insecure_skip_verify=true; certificate validation is disabled"
        );
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoServerCertVerification))
            .with_no_client_auth();
        return Ok(Arc::new(config));
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
        let _ = roots.add(cert);
    }
    if let Some(path) = tls.ca_cert_path.as_deref() {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read tls.ca_cert_path {path}"))?;
        let certs = CertificateDer::pem_reader_iter(&mut bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("failed to parse tls.ca_cert_path {path} as PEM"))?;
        for cert in certs {
            roots
                .add(cert)
                .with_context(|| format!("failed to trust certificate from {path}"))?;
        }
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// A `rustls` server-certificate verifier that accepts everything, used only
/// when an operator explicitly sets `tls.insecure_skip_verify = true`.
#[derive(Debug)]
struct NoServerCertVerification;

impl ServerCertVerifier for NoServerCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
#[path = "tls_test.rs"]
mod tests;
