// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! SAML redirect-binding signature + assertion validation coverage (#283).
//!
//! The RSA key/certificate and the detached signature are produced by the
//! `openssl` CLI (already relied on by the OIDC admin-console tests), so the
//! verification path is exercised against a real certificate + real signature,
//! never a self-consistent stub.

use super::*;
use std::process::Command;

fn base64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn deflate(xml: &str) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(xml.as_bytes()).unwrap();
    encoder.finish().unwrap()
}

/// Generates an RSA private key (PEM) and a self-signed X.509 certificate (PEM)
/// via openssl.
fn key_and_certificate() -> (std::path::PathBuf, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key.pem");
    let cert_path = dir.path().join("cert.pem");

    let genrsa = Command::new("openssl")
        .args(["genrsa", "-out"])
        .arg(&key_path)
        .arg("2048")
        .output()
        .expect("openssl must be available");
    assert!(genrsa.status.success(), "openssl genrsa failed");

    let req = Command::new("openssl")
        .args(["req", "-x509", "-new", "-key"])
        .arg(&key_path)
        .args(["-days", "1", "-subj", "/CN=test-idp", "-out"])
        .arg(&cert_path)
        .output()
        .expect("openssl req must run");
    assert!(
        req.status.success(),
        "openssl req failed: {}",
        String::from_utf8_lossy(&req.stderr)
    );

    let cert_pem = std::fs::read_to_string(&cert_path).unwrap();
    (key_path, cert_pem, dir)
}

/// RSA-SHA256 signs `data` with the private key, returning the raw signature.
fn sign_sha256(key_path: &std::path::Path, data: &[u8]) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let data_path = dir.path().join("data.bin");
    let sig_path = dir.path().join("sig.bin");
    std::fs::write(&data_path, data).unwrap();

    let sign = Command::new("openssl")
        .args(["dgst", "-sha256", "-sign"])
        .arg(key_path)
        .arg("-out")
        .arg(&sig_path)
        .arg(&data_path)
        .output()
        .expect("openssl dgst must run");
    assert!(
        sign.status.success(),
        "openssl dgst -sign failed: {}",
        String::from_utf8_lossy(&sign.stderr)
    );
    std::fs::read(&sig_path).unwrap()
}

fn sample_response_xml(not_before: &str, not_on_or_after: &str) -> String {
    let success = STATUS_SUCCESS;
    format!(
        "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" InResponseTo=\"_req-123\">\
         <saml:Issuer>https://idp.example/entity</saml:Issuer>\
         <samlp:Status><samlp:StatusCode Value=\"{success}\"/></samlp:Status>\
         <saml:Assertion><saml:Issuer>https://idp.example/entity</saml:Issuer>\
         <saml:Subject><saml:NameID>subject@example.com</saml:NameID></saml:Subject>\
         <saml:Conditions NotBefore=\"{not_before}\" NotOnOrAfter=\"{not_on_or_after}\">\
         <saml:AudienceRestriction><saml:Audience>sp-entity-id</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions>\
         <saml:AttributeStatement>\
         <saml:Attribute Name=\"email\"><saml:AttributeValue>User@Example.com</saml:AttributeValue></saml:Attribute>\
         <saml:Attribute Name=\"displayName\"><saml:AttributeValue>Ada Lovelace</saml:AttributeValue></saml:Attribute>\
         <saml:Attribute Name=\"groups\">\
         <saml:AttributeValue>Engineering</saml:AttributeValue>\
         <saml:AttributeValue>Admins</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement></saml:Assertion></samlp:Response>",
    )
}

fn signed_query(cert_key: &std::path::Path, saml_response_b64: &str, relay_state: &str) -> String {
    let saml_response_enc = crate::urlencode(saml_response_b64);
    let relay_state_enc = crate::urlencode(relay_state);
    let sig_alg_enc = crate::urlencode(SIG_ALG_RSA_SHA256);
    let octet = format!(
        "SAMLResponse={saml_response_enc}&RelayState={relay_state_enc}&SigAlg={sig_alg_enc}"
    );
    let signature = sign_sha256(cert_key, octet.as_bytes());
    let signature_enc = crate::urlencode(&base64_encode(&signature));
    format!(
        "SAMLResponse={saml_response_enc}&RelayState={relay_state_enc}&SigAlg={sig_alg_enc}&Signature={signature_enc}"
    )
}

#[test]
fn redirect_signature_verifies_against_the_idp_certificate() {
    let (key_path, cert_pem, _dir) = key_and_certificate();
    let response = sample_response_xml("2020-01-01T00:00:00Z", "2999-01-01T00:00:00Z");
    let saml_response_b64 = base64_encode(&deflate(&response));
    let query = signed_query(&key_path, &saml_response_b64, "opaque-state-token");

    let params = RedirectBindingParams::parse(&query);
    assert!(
        verify_redirect_signature(&params, &cert_pem).is_ok(),
        "a correctly signed redirect must verify"
    );
}

#[test]
fn redirect_signature_rejects_a_tampered_payload() {
    let (key_path, cert_pem, _dir) = key_and_certificate();
    let response = sample_response_xml("2020-01-01T00:00:00Z", "2999-01-01T00:00:00Z");
    let saml_response_b64 = base64_encode(&deflate(&response));
    let query = signed_query(&key_path, &saml_response_b64, "opaque-state-token");

    // Flip the RelayState after signing: the reconstructed octet string no
    // longer matches what was signed, so verification must fail closed.
    let tampered = query.replace("RelayState=opaque-state-token", "RelayState=attacker-state");
    let params = RedirectBindingParams::parse(&tampered);
    assert!(
        verify_redirect_signature(&params, &cert_pem).is_err(),
        "a tampered redirect must be rejected"
    );
}

#[test]
fn redirect_signature_rejects_a_wrong_signing_key() {
    let (key_path, _cert_pem, _dir) = key_and_certificate();
    // A DIFFERENT certificate than the one whose key signed the request.
    let (_other_key, other_cert_pem, _other_dir) = key_and_certificate();
    let response = sample_response_xml("2020-01-01T00:00:00Z", "2999-01-01T00:00:00Z");
    let saml_response_b64 = base64_encode(&deflate(&response));
    let query = signed_query(&key_path, &saml_response_b64, "opaque-state-token");

    let params = RedirectBindingParams::parse(&query);
    assert!(
        verify_redirect_signature(&params, &other_cert_pem).is_err(),
        "a signature from a different key must be rejected"
    );
}

#[test]
fn redirect_signature_rejects_when_unsigned() {
    let (_key_path, cert_pem, _dir) = key_and_certificate();
    let params = RedirectBindingParams::parse("SAMLResponse=abc&SigAlg=def");
    assert!(verify_redirect_signature(&params, &cert_pem).is_err());
}

fn expectations<'a>(now_unix: i64) -> AssertionExpectations<'a> {
    AssertionExpectations {
        sp_entity_id: "sp-entity-id",
        idp_entity_id: Some("https://idp.example/entity"),
        in_response_to: Some("_req-123"),
        email_attribute: Some("email"),
        name_attribute: Some("displayName"),
        groups_attribute: Some("groups"),
        now_unix,
        clock_skew_secs: 300,
    }
}

#[test]
fn valid_assertion_extracts_identity_and_groups() {
    let response = sample_response_xml("2020-01-01T00:00:00Z", "2999-01-01T00:00:00Z");
    let saml_response_b64 = base64_encode(&deflate(&response));
    let now = parse_saml_instant("2024-01-01T00:00:00Z").unwrap();

    let assertion =
        parse_and_validate_response(&saml_response_b64, &expectations(now)).expect("valid");
    assert_eq!(assertion.email, "user@example.com");
    assert_eq!(assertion.display_name, "Ada Lovelace");
    assert_eq!(assertion.groups, vec!["Engineering", "Admins"]);
}

#[test]
fn assertion_with_wrong_audience_is_rejected() {
    let response = sample_response_xml("2020-01-01T00:00:00Z", "2999-01-01T00:00:00Z");
    let saml_response_b64 = base64_encode(&deflate(&response));
    let now = parse_saml_instant("2024-01-01T00:00:00Z").unwrap();
    let mut expectations = expectations(now);
    expectations.sp_entity_id = "some-other-sp";

    let error = parse_and_validate_response(&saml_response_b64, &expectations).unwrap_err();
    assert!(error.contains("audience"), "unexpected error: {error}");
}

#[test]
fn expired_assertion_is_rejected() {
    let response = sample_response_xml("2020-01-01T00:00:00Z", "2020-01-01T01:00:00Z");
    let saml_response_b64 = base64_encode(&deflate(&response));
    let now = parse_saml_instant("2024-01-01T00:00:00Z").unwrap();

    let error = parse_and_validate_response(&saml_response_b64, &expectations(now)).unwrap_err();
    assert!(error.contains("expired"), "unexpected error: {error}");
}

#[test]
fn assertion_with_mismatched_in_response_to_is_rejected() {
    let response = sample_response_xml("2020-01-01T00:00:00Z", "2999-01-01T00:00:00Z");
    let saml_response_b64 = base64_encode(&deflate(&response));
    let now = parse_saml_instant("2024-01-01T00:00:00Z").unwrap();
    let mut expectations = expectations(now);
    expectations.in_response_to = Some("_a-different-request");

    let error = parse_and_validate_response(&saml_response_b64, &expectations).unwrap_err();
    assert!(error.contains("InResponseTo"), "unexpected error: {error}");
}

#[test]
fn non_success_status_is_rejected() {
    let response = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">\
         <saml:Issuer>https://idp.example/entity</saml:Issuer>\
         <samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Requester\"/>\
         </samlp:Status></samlp:Response>";
    let saml_response_b64 = base64_encode(&deflate(response));
    let now = parse_saml_instant("2024-01-01T00:00:00Z").unwrap();
    let error = parse_and_validate_response(&saml_response_b64, &expectations(now)).unwrap_err();
    assert!(error.contains("Success"), "unexpected error: {error}");
}

#[test]
fn authn_request_round_trips_through_deflate() {
    let url = build_authn_request_redirect(
        "https://idp.example/sso",
        "https://sp.example/acs",
        "sp-entity-id",
        "_req-1",
        "state-token",
    )
    .unwrap();
    assert!(url.starts_with("https://idp.example/sso?SAMLRequest="));
    assert!(url.contains("&RelayState=state-token"));

    // Extract and inflate the SAMLRequest to confirm it is well-formed.
    let params = url.split_once('?').unwrap().1;
    let saml_request_enc = params
        .split('&')
        .find_map(|pair| pair.strip_prefix("SAMLRequest="))
        .unwrap();
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(crate::urldecode(saml_request_enc).as_bytes())
        .unwrap();
    let mut xml = Vec::new();
    DeflateDecoder::new(&compressed[..])
        .read_to_end(&mut xml)
        .unwrap();
    let xml = String::from_utf8(xml).unwrap();
    assert!(xml.contains("AuthnRequest"));
    assert!(xml.contains("sp-entity-id"));
}

#[test]
fn saml_instant_parsing_requires_utc() {
    assert!(parse_saml_instant("2024-01-01T00:00:00Z").is_ok());
    assert!(parse_saml_instant("2024-01-01T00:00:00.123Z").is_ok());
    // No trailing Z -> ambiguous local time -> fail closed.
    assert!(parse_saml_instant("2024-01-01T00:00:00").is_err());
    assert!(parse_saml_instant("not-a-timestamp").is_err());
}
