// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Conformance tests for the verified mutual-TLS self-hosted worker transport
//! (issue #243, Phase 2). Every test drives a *real* rustls mutual-TLS handshake
//! over a localhost socket pair using certificates generated at test time with
//! rcgen — there is no external PKI and the tests are deterministic.

use std::{
    io::Write,
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rcgen::{
    date_time_ymd, string::Ia5String, BasicConstraints, CertificateParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};

use super::{
    build_self_hosted_worker_client_config, connect_self_hosted_worker_client, SelfHostedMtlsError,
    SelfHostedMtlsServer, SelfHostedMtlsTrustAnchor, SelfHostedTransportTokenIssuer,
    SelfHostedTransportTokenStore, SelfHostedWorkerCertBinding, VerifiedMutualTls,
};
use crate::self_hosted_worker::{
    SelfHostedTransportChannel, SelfHostedTransportPolicy, SelfHostedWorkerIdentity,
};

/// A self-signed test CA plus the ability to mint leaf certs signed by it.
struct TestCa {
    ca_der: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
}

impl TestCa {
    fn new(common_name: &str) -> Self {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let ca_cert = params.self_signed(&ca_key).expect("self-signed ca");
        let ca_der = ca_cert.der().to_vec();
        Self {
            ca_der,
            issuer: Issuer::new(params, ca_key),
        }
    }

    fn anchor(&self) -> SelfHostedMtlsTrustAnchor {
        SelfHostedMtlsTrustAnchor::from_der(self.ca_der.clone()).expect("trust anchor loads")
    }

    /// Mint a server leaf (DNS SAN `localhost`, EKU serverAuth).
    fn server_leaf(&self) -> (Vec<u8>, Vec<u8>) {
        let key = KeyPair::generate().expect("server key");
        let mut params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2100, 1, 1);
        params
            .distinguished_name
            .push(DnType::CommonName, "ferrogate-self-hosted-gateway");
        let cert = params.signed_by(&key, &self.issuer).expect("server cert");
        (cert.der().to_vec(), key.serialize_der())
    }

    /// Mint a client leaf carrying a SPIFFE URI SAN 4-tuple and EKU clientAuth.
    fn client_leaf(
        &self,
        binding: &SelfHostedWorkerCertBinding,
        not_after_ymd: (i32, u8, u8),
    ) -> (Vec<u8>, Vec<u8>) {
        let key = KeyPair::generate().expect("client key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("client params");
        params.subject_alt_names.push(SanType::URI(
            Ia5String::try_from(binding.spiffe_uri()).expect("spiffe uri is ia5"),
        ));
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.not_before = date_time_ymd(2020, 1, 1);
        let (year, month, day) = not_after_ymd;
        params.not_after = date_time_ymd(year, month, day);
        params
            .distinguished_name
            .push(DnType::CommonName, &binding.worker_id);
        let cert = params.signed_by(&key, &self.issuer).expect("client cert");
        (cert.der().to_vec(), key.serialize_der())
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn test_binding() -> SelfHostedWorkerCertBinding {
    SelfHostedWorkerCertBinding {
        tenant_id: "tenant-1".to_string(),
        workspace_id: "workspace-1".to_string(),
        worker_id: "worker-a".to_string(),
        token_id: "token-1".to_string(),
    }
}

fn identity_for(binding: &SelfHostedWorkerCertBinding) -> SelfHostedWorkerIdentity {
    SelfHostedWorkerIdentity {
        tenant_id: binding.tenant_id.clone(),
        workspace_id: binding.workspace_id.clone(),
        worker_id: binding.worker_id.clone(),
        token_id: binding.token_id.clone(),
        token_secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_string(),
        observed_at_unix: None,
    }
}

/// Drive a real mutual-TLS handshake between a rustls client (presenting
/// `client_cert`/`client_key`, trusting `trust_ca`) and a
/// [`SelfHostedMtlsServer`] built from `server_ca`. Returns the server-side
/// verification result.
fn run_handshake(
    server_ca: &TestCa,
    server_leaf: &(Vec<u8>, Vec<u8>),
    client_trust_ca: &TestCa,
    client_cert: Vec<u8>,
    client_key: Vec<u8>,
    now: u64,
) -> Result<VerifiedMutualTls, SelfHostedMtlsError> {
    let server = SelfHostedMtlsServer::new(
        &server_ca.anchor(),
        vec![server_leaf.0.clone()],
        server_leaf.1.clone(),
    )
    .expect("server config builds");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("server read timeout");
        server
            .accept(stream, now)
            .map(|connection| connection.into_verified())
    });

    // Client side: trust the gateway server cert via the client's configured CA.
    let client_config = build_self_hosted_worker_client_config(
        &client_trust_ca.anchor(),
        vec![client_cert],
        client_key,
    )
    .expect("client config builds");
    let mut client_conn = connect_self_hosted_worker_client(Arc::new(client_config), "localhost")
        .expect("client connection");
    let mut tcp = TcpStream::connect(addr).expect("client connect");
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("client read timeout");

    // Best-effort: drive the client handshake. On a rejection the server aborts
    // and the client may see an error here; the authoritative result is the
    // server's verification outcome.
    let mut guard = 0;
    while client_conn.is_handshaking() && guard < 16 {
        if client_conn.complete_io(&mut tcp).is_err() {
            break;
        }
        guard += 1;
    }
    let _ = client_conn.write_all_of_handshake(&mut tcp);

    server_handle.join().expect("server thread joins")
}

// A tiny extension so the client flushes any pending handshake bytes without the
// test caring about the exact rustls IO danceit is best-effort only.
trait FlushHandshake {
    fn write_all_of_handshake(&mut self, tcp: &mut TcpStream) -> std::io::Result<()>;
}

impl FlushHandshake for rustls::ClientConnection {
    fn write_all_of_handshake(&mut self, tcp: &mut TcpStream) -> std::io::Result<()> {
        if self.wants_write() {
            self.write_tls(tcp)?;
        }
        tcp.flush()
    }
}

#[test]
fn cert_valid_request_is_admitted_in_production() {
    let ca = TestCa::new("valid-ca");
    let server_leaf = ca.server_leaf();
    let binding = test_binding();
    let (client_cert, client_key) = ca.client_leaf(&binding, (2100, 1, 1));

    let verified = run_handshake(&ca, &server_leaf, &ca, client_cert, client_key, now_unix())
        .expect("valid client cert must complete a verified handshake");

    assert_eq!(verified.binding(), &binding);
    assert!(!verified.cert_fingerprint().is_empty());
    // The verified channel is admitted under the production posture.
    let policy = SelfHostedTransportPolicy::from_require_production_mtls(true);
    assert_eq!(
        policy.admit(SelfHostedTransportChannel::VerifiedMutualTls(
            verified.clone()
        )),
        Ok(())
    );
    // And it authorizes the matching enclosed request identity.
    assert!(verified.authorize_identity(&identity_for(&binding)).is_ok());
}

#[test]
fn cert_from_untrusted_ca_is_rejected() {
    let gateway_ca = TestCa::new("gateway-ca");
    let server_leaf = gateway_ca.server_leaf();
    let rogue_ca = TestCa::new("rogue-ca");
    let binding = test_binding();
    // Client cert is signed by the rogue CA, which the gateway does not trust.
    let (client_cert, client_key) = rogue_ca.client_leaf(&binding, (2100, 1, 1));

    // The client still trusts the gateway server cert (so the server side is the
    // one that must reject), but presents an untrusted client certificate.
    let result = run_handshake(
        &gateway_ca,
        &server_leaf,
        &gateway_ca,
        client_cert,
        client_key,
        now_unix(),
    );
    assert!(
        matches!(result, Err(SelfHostedMtlsError::Handshake(_))),
        "untrusted client CA must be rejected at the handshake, got {result:?}"
    );
}

#[test]
fn expired_cert_is_rejected() {
    let ca = TestCa::new("expired-ca");
    let server_leaf = ca.server_leaf();
    let binding = test_binding();
    // notAfter in the past relative to any real server clock.
    let (client_cert, client_key) = ca.client_leaf(&binding, (2021, 1, 1));

    let result = run_handshake(&ca, &server_leaf, &ca, client_cert, client_key, now_unix());
    assert!(
        result.is_err(),
        "expired client cert must be rejected, got {result:?}"
    );
}

#[test]
fn cross_worker_cert_is_rejected_for_mismatched_identity() {
    let ca = TestCa::new("binding-ca");
    let server_leaf = ca.server_leaf();
    // Cert is bound to worker-a.
    let worker_a = test_binding();
    let (client_cert, client_key) = ca.client_leaf(&worker_a, (2100, 1, 1));

    let verified = run_handshake(&ca, &server_leaf, &ca, client_cert, client_key, now_unix())
        .expect("valid cert completes handshake");

    // Attempting to authorize a request claiming to be worker-b must fail: the
    // cert issued for worker A cannot authenticate worker B (T6).
    let mut worker_b_identity = identity_for(&worker_a);
    worker_b_identity.worker_id = "worker-b".to_string();
    let error = verified
        .authorize_identity(&worker_b_identity)
        .expect_err("cross-worker cert reuse must be rejected");
    assert!(matches!(error, SelfHostedMtlsError::IdentityBinding(_)));
}

#[test]
fn production_posture_rejects_marker_and_aead_downgrade() {
    let policy = SelfHostedTransportPolicy::from_require_production_mtls(true);
    assert!(policy
        .admit(SelfHostedTransportChannel::SymmetricAead)
        .is_err());
    assert!(policy
        .admit(SelfHostedTransportChannel::UnverifiedMutualTlsMarker)
        .is_err());
}

#[test]
fn trust_anchor_load_is_fail_closed_on_garbage() {
    let error = SelfHostedMtlsTrustAnchor::from_der(vec![0x00, 0x01, 0x02, 0x03])
        .expect_err("a non-certificate must not load as a trust anchor");
    assert!(matches!(error, SelfHostedMtlsError::TrustAnchorLoad(_)));

    let pem_error = SelfHostedMtlsTrustAnchor::from_pem("not a pem document")
        .expect_err("garbage PEM must fail closed");
    assert!(matches!(pem_error, SelfHostedMtlsError::TrustAnchorLoad(_)));
}

/// Obtain a genuine `VerifiedMutualTls` from a real handshake for the token
/// lifecycle tests (the type has no public constructor).
fn verified_channel(now: u64) -> (VerifiedMutualTls, SelfHostedWorkerCertBinding) {
    let ca = TestCa::new("token-ca");
    let server_leaf = ca.server_leaf();
    let binding = test_binding();
    let (client_cert, client_key) = ca.client_leaf(&binding, (2100, 1, 1));
    let verified = run_handshake(&ca, &server_leaf, &ca, client_cert, client_key, now)
        .expect("valid handshake for token tests");
    (verified, binding)
}

#[test]
fn transport_token_issuance_binds_to_cert_and_expires() {
    let now = now_unix();
    let (verified, binding) = verified_channel(now);
    let issuer = SelfHostedTransportTokenIssuer::new(300).expect("issuer");
    let token = issuer.issue(&verified, now);

    assert_eq!(token.binding(), &binding);
    assert_eq!(token.cert_fingerprint(), verified.cert_fingerprint());
    assert_eq!(token.expires_at_unix(), now + 300);
    assert!(!token.is_expired(now));
    assert!(!token.is_expired(now + 299));
    // Server-clock expiry: past the TTL the token is refused.
    assert!(token.is_expired(now + 300));
    // Constant-time secret check.
    assert!(token.matches_secret(token.secret()));
    assert!(!token.matches_secret("wrong-secret"));
}

#[test]
fn transport_token_rotation_invalidates_the_old_token() {
    let now = now_unix();
    let (verified, _binding) = verified_channel(now);
    let issuer = SelfHostedTransportTokenIssuer::new(300).expect("issuer");
    let mut store = SelfHostedTransportTokenStore::default();

    let original = store.issue(&issuer, &verified, now);
    assert!(store
        .validate(original.token_id(), original.secret(), now)
        .is_ok());

    // Rotate before expiry, re-presenting the same certificate.
    let rotated = store
        .rotate(
            &issuer,
            original.token_id(),
            original.secret(),
            &verified,
            now + 10,
        )
        .expect("rotation succeeds with the bound cert");

    // Old token is invalidated atomically; new token is accepted.
    assert!(store
        .validate(original.token_id(), original.secret(), now + 10)
        .is_err());
    assert!(store
        .validate(rotated.token_id(), rotated.secret(), now + 10)
        .is_ok());
    assert_eq!(store.len(), 1);
    assert_ne!(original.token_id(), rotated.token_id());
    assert_ne!(original.secret(), rotated.secret());
}

#[test]
fn transport_token_rotation_rejects_a_different_certificate() {
    let now = now_unix();
    let (verified_a, _binding) = verified_channel(now);
    let (verified_b, _binding_b) = verified_channel(now);
    let issuer = SelfHostedTransportTokenIssuer::new(300).expect("issuer");
    let mut store = SelfHostedTransportTokenStore::default();

    let token = store.issue(&issuer, &verified_a, now);
    // A different handshake (different cert fingerprint) may not rotate the token.
    let error = store
        .rotate(
            &issuer,
            token.token_id(),
            token.secret(),
            &verified_b,
            now + 5,
        )
        .expect_err("rotation with a different cert must be rejected");
    assert!(matches!(error, SelfHostedMtlsError::TokenRejected(_)));
    // The original token remains valid and un-rotated.
    assert!(store
        .validate(token.token_id(), token.secret(), now + 5)
        .is_ok());
}

#[test]
fn expired_transport_token_is_rejected_and_rotation_refused() {
    let now = now_unix();
    let (verified, _binding) = verified_channel(now);
    let issuer = SelfHostedTransportTokenIssuer::new(300).expect("issuer");
    let mut store = SelfHostedTransportTokenStore::default();
    let token = store.issue(&issuer, &verified, now);

    // Past the TTL the token no longer validates, ignoring any client time.
    let error = store
        .validate(token.token_id(), token.secret(), now + 300)
        .expect_err("expired token must be rejected");
    assert!(matches!(error, SelfHostedMtlsError::TokenRejected(_)));

    // And an expired token cannot be rotated (validate-before-rotate).
    let rotate_error = store
        .rotate(
            &issuer,
            token.token_id(),
            token.secret(),
            &verified,
            now + 300,
        )
        .expect_err("expired token cannot be rotated");
    assert!(matches!(
        rotate_error,
        SelfHostedMtlsError::TokenRejected(_)
    ));
}

#[test]
fn transport_token_ttl_is_bounded_and_capped_by_cert_notafter() {
    // Zero TTL is refused.
    assert!(SelfHostedTransportTokenIssuer::new(0).is_err());
    // Over-long TTL is refused.
    assert!(SelfHostedTransportTokenIssuer::new(u64::MAX).is_err());

    // The token never outlives the certificate notAfter.
    let now = now_unix();
    let (verified, _binding) = verified_channel(now);
    let issuer = SelfHostedTransportTokenIssuer::new(3600).expect("issuer");
    let token = issuer.issue(&verified, now);
    assert!(token.expires_at_unix() <= verified.not_after_unix());
}
