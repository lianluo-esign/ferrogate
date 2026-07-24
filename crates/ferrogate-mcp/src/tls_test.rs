// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.

use super::*;
use rcgen::CertifiedKey;

// -- issue #167: MCP TLS/HTTPS/SSE support -----------------------------

#[test]
fn validate_mcp_tls_config_accepts_missing_ca_cert_path() {
    validate_mcp_tls_config(&McpTlsConfig::default()).unwrap();
}

#[test]
fn validate_mcp_tls_config_rejects_missing_ca_cert_file() {
    let tls = McpTlsConfig {
        insecure_skip_verify: false,
        ca_cert_path: Some("/nonexistent/ferrogate-mcp-test-ca.pem".into()),
    };
    let error = validate_mcp_tls_config(&tls).unwrap_err().to_string();
    assert!(error.contains("ca_cert_path"));
}

#[test]
fn validate_mcp_tls_config_rejects_non_pem_ca_cert_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-a-cert.pem");
    std::fs::write(&path, b"this is not PEM data").unwrap();
    let tls = McpTlsConfig {
        insecure_skip_verify: false,
        ca_cert_path: Some(path.to_string_lossy().into_owned()),
    };
    let error = validate_mcp_tls_config(&tls).unwrap_err().to_string();
    assert!(error.contains("ca_cert_path") || error.contains("no PEM certificates"));
}

#[test]
fn validate_mcp_tls_config_accepts_valid_pem_ca_cert() {
    let CertifiedKey { cert, .. } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.pem");
    std::fs::write(&path, cert.pem()).unwrap();
    let tls = McpTlsConfig {
        insecure_skip_verify: false,
        ca_cert_path: Some(path.to_string_lossy().into_owned()),
    };
    validate_mcp_tls_config(&tls).unwrap();
}

#[test]
fn mcp_tls_client_config_builds_with_insecure_skip_verify() {
    let tls = McpTlsConfig {
        insecure_skip_verify: true,
        ca_cert_path: None,
    };
    mcp_tls_client_config(&tls).unwrap();
}

#[test]
fn mcp_tls_client_config_builds_with_native_roots_only() {
    let tls = McpTlsConfig::default();
    mcp_tls_client_config(&tls).unwrap();
}
