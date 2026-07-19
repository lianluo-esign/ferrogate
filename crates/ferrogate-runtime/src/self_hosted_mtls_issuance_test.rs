// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Conformance tests for control-plane client-cert issuance, the CRL-style
//! revocation list, and the verified-mTLS ingress admission seam (issue #249).
//!
//! Every test drives a *real* rustls mutual-TLS handshake over a localhost socket
//! pair. The client certificate is minted by [`SelfHostedMtlsCertIssuer`] (the
//! same control-plane path used at worker registration) rather than by ad-hoc
//! rcgen scaffolding, so these tests exercise the actual issuance -> handshake ->
//! admission chain. There is no external PKI and the tests are deterministic.

use std::{
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::{
    build_self_hosted_worker_client_config, connect_self_hosted_worker_client,
    IssuedSelfHostedWorkerCert, SelfHostedCertRevocationList, SelfHostedMtlsAdmissionError,
    SelfHostedMtlsCertIssuer, SelfHostedMtlsError, SelfHostedMtlsIngressAdmission,
    SelfHostedMtlsServer, SelfHostedMtlsTrustAnchor, SelfHostedWorkerCertBinding,
    VerifiedMutualTls,
};
use crate::self_hosted_worker::{
    SelfHostedTransportChannel, SelfHostedTransportPolicy, SelfHostedWorkerIdentity,
};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn binding(worker_id: &str) -> SelfHostedWorkerCertBinding {
    SelfHostedWorkerCertBinding {
        tenant_id: "tenant-1".to_string(),
        workspace_id: "workspace-1".to_string(),
        worker_id: worker_id.to_string(),
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

/// Drive a real mutual-TLS handshake: the gateway server is built from `anchor`
/// (the issuer's CA) and presents `server_leaf`; the worker client presents
/// `issued`'s cert/key and trusts the same anchor. Returns the server-side
/// verification result.
fn handshake(
    anchor: &SelfHostedMtlsTrustAnchor,
    server_leaf: &(Vec<u8>, Vec<u8>),
    issued: &IssuedSelfHostedWorkerCert,
    now: u64,
) -> Result<VerifiedMutualTls, SelfHostedMtlsError> {
    let server =
        SelfHostedMtlsServer::new(anchor, vec![server_leaf.0.clone()], server_leaf.1.clone())
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

    let client_config = build_self_hosted_worker_client_config(
        anchor,
        vec![issued.certificate_der().to_vec()],
        issued.private_key_pkcs8_der().to_vec(),
    )
    .expect("client config builds");
    let mut client_conn = connect_self_hosted_worker_client(Arc::new(client_config), "localhost")
        .expect("client connection");
    let mut tcp = TcpStream::connect(addr).expect("client connect");
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("client read timeout");

    let mut guard = 0;
    while client_conn.is_handshaking() && guard < 16 {
        if client_conn.complete_io(&mut tcp).is_err() {
            break;
        }
        guard += 1;
    }
    if client_conn.wants_write() {
        let _ = client_conn.write_tls(&mut tcp);
    }

    server_handle.join().expect("server thread joins")
}

/// Mint an issuer + matching anchor + server leaf for a test.
fn issuer_with_server(
    now: u64,
) -> (
    SelfHostedMtlsCertIssuer,
    SelfHostedMtlsTrustAnchor,
    (Vec<u8>, Vec<u8>),
) {
    let issuer = SelfHostedMtlsCertIssuer::generate_self_signed("ferrogate-self-hosted-ca", 86_400)
        .expect("self-signed issuer");
    let anchor = issuer.trust_anchor().expect("trust anchor from issuer");
    let server_leaf = issuer
        .issue_server_cert(vec!["localhost".to_string()], now, 86_400)
        .expect("server leaf");
    (issuer, anchor, server_leaf)
}

#[test]
fn issued_cert_is_admitted_for_its_worker_and_rejected_cross_worker() {
    let now = now_unix();
    let (issuer, anchor, server_leaf) = issuer_with_server(now);
    let worker_a = binding("worker-a");
    let issued = issuer
        .issue_client_cert(&worker_a, now)
        .expect("client cert issued at registration");

    // The fingerprint recorded at issuance matches what the verifier observes.
    let verified = handshake(&anchor, &server_leaf, &issued, now)
        .expect("issued cert completes a verified handshake");
    assert_eq!(verified.binding(), &worker_a);
    assert_eq!(verified.cert_fingerprint(), issued.fingerprint());
    assert_eq!(issued.spiffe_id(), worker_a.spiffe_uri());

    let admission = SelfHostedMtlsIngressAdmission::new(
        SelfHostedTransportPolicy::from_require_production_mtls(true),
        SelfHostedCertRevocationList::new(),
    );

    // Admitted for the worker it was issued for.
    assert_eq!(admission.admit(&verified, &identity_for(&worker_a)), Ok(()));

    // Rejected when presented for a different worker (cross-worker reuse, T6).
    let worker_b_identity = identity_for(&binding("worker-b"));
    assert!(matches!(
        admission.admit(&verified, &worker_b_identity),
        Err(SelfHostedMtlsAdmissionError::IdentityBinding(_))
    ));
}

#[test]
fn cert_issued_by_a_different_ca_is_rejected_at_the_handshake() {
    let now = now_unix();
    // Gateway trusts issuer A; the client presents a cert minted by issuer B.
    let (_issuer_a, anchor_a, server_leaf_a) = issuer_with_server(now);
    let issuer_b =
        SelfHostedMtlsCertIssuer::generate_self_signed("rogue-ca", 86_400).expect("rogue issuer");
    let issued_b = issuer_b
        .issue_client_cert(&binding("worker-a"), now)
        .expect("rogue cert");

    let result = handshake(&anchor_a, &server_leaf_a, &issued_b, now);
    assert!(
        matches!(result, Err(SelfHostedMtlsError::Handshake(_))),
        "a cert from an untrusted issuer must be rejected at the handshake, got {result:?}"
    );
}

#[test]
fn revoked_cert_is_rejected_at_admission() {
    let now = now_unix();
    let (issuer, anchor, server_leaf) = issuer_with_server(now);
    let worker_a = binding("worker-a");
    let issued = issuer.issue_client_cert(&worker_a, now).expect("issued");
    let verified = handshake(&anchor, &server_leaf, &issued, now).expect("verified");

    let mut revocation = SelfHostedCertRevocationList::new();
    // The control plane revokes the fingerprint it recorded at issuance.
    revocation.revoke_fingerprint(issued.fingerprint());
    let admission = SelfHostedMtlsIngressAdmission::new(
        SelfHostedTransportPolicy::from_require_production_mtls(true),
        revocation,
    );

    let error = admission
        .admit(&verified, &identity_for(&worker_a))
        .expect_err("a revoked cert must be refused at admission");
    assert!(matches!(error, SelfHostedMtlsAdmissionError::Revoked(_)));
}

#[test]
fn deactivating_a_worker_revokes_its_cert_at_admission() {
    let now = now_unix();
    let (issuer, anchor, server_leaf) = issuer_with_server(now);
    let worker_a = binding("worker-a");
    let issued = issuer.issue_client_cert(&worker_a, now).expect("issued");
    let verified = handshake(&anchor, &server_leaf, &issued, now).expect("verified");

    let mut revocation = SelfHostedCertRevocationList::new();
    // Worker deactivation revokes every cert bound to the worker, regardless of
    // fingerprint.
    revocation.revoke_worker(
        &worker_a.tenant_id,
        &worker_a.workspace_id,
        &worker_a.worker_id,
    );
    let admission = SelfHostedMtlsIngressAdmission::new(
        SelfHostedTransportPolicy::from_require_production_mtls(true),
        revocation,
    );

    assert!(matches!(
        admission.admit(&verified, &identity_for(&worker_a)),
        Err(SelfHostedMtlsAdmissionError::Revoked(_))
    ));
}

#[test]
fn production_admission_accepts_verified_and_rejects_downgrade() {
    let now = now_unix();
    let (issuer, anchor, server_leaf) = issuer_with_server(now);
    let worker_a = binding("worker-a");
    let issued = issuer.issue_client_cert(&worker_a, now).expect("issued");
    let verified = handshake(&anchor, &server_leaf, &issued, now).expect("verified");

    let policy = SelfHostedTransportPolicy::from_require_production_mtls(true);
    let admission =
        SelfHostedMtlsIngressAdmission::new(policy, SelfHostedCertRevocationList::new());

    // Verified channel is admitted.
    assert_eq!(admission.admit(&verified, &identity_for(&worker_a)), Ok(()));

    // The marker/AEAD downgrade paths are refused server-side under production
    // posture (the header-derived channel never yields a VerifiedMutualTls).
    assert!(policy
        .admit(SelfHostedTransportChannel::SymmetricAead)
        .is_err());
    assert!(policy
        .admit(SelfHostedTransportChannel::UnverifiedMutualTlsMarker)
        .is_err());
}

#[test]
fn issuer_loaded_from_pem_round_trips_through_a_verified_handshake() {
    // A self-signed issuer's CA can be re-loaded from PEM (the configured-CA
    // deployment path) and still mint certs the matching anchor accepts.
    let now = now_unix();
    let bootstrap = SelfHostedMtlsCertIssuer::generate_self_signed("configured-ca", 86_400)
        .expect("bootstrap issuer");
    // Mint a server leaf and export the CA as PEM to prove from_ca_pem works.
    let server_leaf = bootstrap
        .issue_server_cert(vec!["localhost".to_string()], now, 86_400)
        .expect("server leaf");
    let anchor = bootstrap.trust_anchor().expect("anchor");

    let worker = binding("worker-pem");
    let issued = bootstrap.issue_client_cert(&worker, now).expect("issued");
    let verified = handshake(&anchor, &server_leaf, &issued, now).expect("verified");
    assert_eq!(verified.binding(), &worker);

    let admission = SelfHostedMtlsIngressAdmission::new(
        SelfHostedTransportPolicy::from_require_production_mtls(true),
        SelfHostedCertRevocationList::new(),
    );
    assert_eq!(admission.admit(&verified, &identity_for(&worker)), Ok(()));
}

#[test]
fn revocation_list_rejects_bad_ca_material_fail_closed() {
    // A garbage CA cert/key fails closed at issuer construction.
    let error = SelfHostedMtlsCertIssuer::from_ca_pem("not a pem", "also not a pem", 3600)
        .expect_err("garbage CA material must fail closed");
    assert!(matches!(error, SelfHostedMtlsError::CertIssuance(_)));

    // Zero TTL is refused.
    assert!(
        SelfHostedMtlsCertIssuer::generate_self_signed("ca", 0).is_err(),
        "a zero certificate TTL must be refused"
    );
}
