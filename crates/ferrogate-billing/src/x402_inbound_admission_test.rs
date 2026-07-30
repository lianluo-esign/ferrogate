// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Unit tests for inbound x402 sidecar admission (issue #356):
// bypass refusal, mTLS pinning, constant-time credential matching with rotation,
// reserved-attribution-header spoof refusal, and duplicate-header ambiguity.

use ferrogate_core::TenantContext;

use super::*;

const ACTIVE: &str = "active-sidecar-secret-0123456789abcdef";
const ROTATING: &str = "retiring-sidecar-secret-0123456789abcdef";

fn tenant() -> TenantContext {
    TenantContext {
        organization_id: Some("tenant-monetized".to_string()),
        project_id: Some("project-public-api".to_string()),
        ..TenantContext::default()
    }
}

fn credential() -> SidecarCredential {
    SidecarCredential::new(ACTIVE, None).expect("active credential is long enough")
}

fn rotating_credential() -> SidecarCredential {
    SidecarCredential::new(ACTIVE, Some(ROTATING.to_string())).expect("rotation pair is valid")
}

fn policy() -> SidecarAdmissionPolicy {
    SidecarAdmissionPolicy::new(credential(), false, Vec::new(), tenant())
        .expect("private-network policy is consistent")
}

fn mtls_policy() -> SidecarAdmissionPolicy {
    SidecarAdmissionPolicy::new(
        credential(),
        true,
        vec!["CN=pay-sidecar".to_string()],
        tenant(),
    )
    .expect("mTLS policy with a pinned subject is consistent")
}

fn request<'a>(
    transport: SidecarTransport,
    headers: &'a [(&'a str, &'a str)],
) -> ForwardedRequest<'a> {
    ForwardedRequest {
        transport,
        method: "POST",
        path: "/v1/priced/echo",
        headers,
    }
}

fn base_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (HEADER_SIDECAR_CREDENTIAL, ACTIVE),
        (HEADER_SIDECAR_REQUEST_ID, "sidecar-req-1"),
    ]
}

// -------------------------------------------------------------------------
// Bypass: the whole point of the private upstream
// -------------------------------------------------------------------------

#[test]
fn untrusted_transport_is_refused_even_with_a_valid_credential() {
    let headers = base_headers();
    let error = policy()
        .admit(&request(SidecarTransport::Untrusted, &headers))
        .expect_err("a direct hit on the upstream must never be admitted");
    assert_eq!(error, InboundX402AdmissionError::UntrustedTransport);
    assert_eq!(error.http_status(), 403);
    assert_eq!(error.code(), "x402_inbound_untrusted_transport");
}

#[test]
fn private_network_transport_is_refused_when_the_policy_requires_mtls() {
    let headers = base_headers();
    let error = mtls_policy()
        .admit(&request(SidecarTransport::PrivateNetwork, &headers))
        .expect_err("mTLS-required policy must refuse a plain private-network hop");
    assert_eq!(error, InboundX402AdmissionError::MutualTlsRequired);
}

#[test]
fn mtls_subject_must_be_pinned() {
    let headers = base_headers();
    let transport = SidecarTransport::MutualTls {
        subject: "CN=some-other-workload".to_string(),
    };
    let error = mtls_policy()
        .admit(&request(transport, &headers))
        .expect_err("an unpinned client certificate must not be admitted");
    assert_eq!(
        error,
        InboundX402AdmissionError::UnpinnedMutualTlsSubject {
            subject: "CN=some-other-workload".to_string(),
        }
    );
}

#[test]
fn pinned_mtls_subject_is_admitted_and_recorded_in_evidence() {
    let headers = base_headers();
    let transport = SidecarTransport::MutualTls {
        subject: "CN=pay-sidecar".to_string(),
    };
    let admitted = mtls_policy()
        .admit(&request(transport, &headers))
        .expect("a pinned subject is admitted");
    assert_eq!(admitted.transport.as_str(), "mutual_tls");
    let evidence = admitted.evidence_fields();
    assert!(evidence.contains(&("sidecar_mtls_subject", "CN=pay-sidecar".to_string())));
}

// -------------------------------------------------------------------------
// Policy construction: neither half of the mTLS rule is meaningful alone
// -------------------------------------------------------------------------

#[test]
fn mtls_without_a_pinned_subject_is_rejected_at_construction() {
    let error = SidecarAdmissionPolicy::new(credential(), true, Vec::new(), tenant())
        .expect_err("mTLS with no pin would accept any chaining certificate");
    assert_eq!(error, SidecarPolicyError::MutualTlsWithoutPinnedSubject);
}

#[test]
fn a_pin_without_mtls_is_rejected_at_construction() {
    let error =
        SidecarAdmissionPolicy::new(credential(), false, vec!["CN=pay-sidecar".into()], tenant())
            .expect_err("a pin that is never consulted reads as protection that is not there");
    assert_eq!(error, SidecarPolicyError::PinnedSubjectWithoutMutualTls);
}

#[test]
fn an_empty_pinned_subject_is_rejected() {
    let error = SidecarAdmissionPolicy::new(credential(), true, vec![String::new()], tenant())
        .expect_err("an empty pin matches nothing and hides the misconfiguration");
    assert_eq!(error, SidecarPolicyError::EmptyPinnedSubject);
}

// -------------------------------------------------------------------------
// Credentials
// -------------------------------------------------------------------------

#[test]
fn credential_shorter_than_the_floor_is_rejected() {
    let error = SidecarCredential::new("short", None).expect_err("below the minimum length");
    assert_eq!(
        error,
        SidecarCredentialError::TooShort {
            field: "active",
            len: 5,
        }
    );
}

#[test]
fn rotating_out_secret_equal_to_the_active_one_is_rejected() {
    let error = SidecarCredential::new(ACTIVE, Some(ACTIVE.to_string()))
        .expect_err("an identity rotation looks in-progress but changes nothing");
    assert_eq!(error, SidecarCredentialError::RotationIsIdentity);
}

#[test]
fn credential_matching_reports_which_secret_matched() {
    let credential = rotating_credential();
    assert_eq!(
        credential.matches(ACTIVE),
        Some(SidecarCredentialMatch::Active)
    );
    assert_eq!(
        credential.matches(ROTATING),
        Some(SidecarCredentialMatch::RotatingOut)
    );
    assert_eq!(
        credential.matches("neither-of-the-two-secrets-abcdef"),
        None
    );
    assert!(credential.is_rotating());
}

#[test]
fn a_rotating_out_secret_is_not_accepted_once_rotation_is_finished() {
    assert_eq!(credential().matches(ROTATING), None);
}

#[test]
fn credential_debug_never_prints_either_secret() {
    let rendered = format!("{:?}", rotating_credential());
    assert!(
        !rendered.contains(ACTIVE),
        "active secret leaked: {rendered}"
    );
    assert!(
        !rendered.contains(ROTATING),
        "rotating-out secret leaked: {rendered}"
    );
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn policy_debug_never_prints_the_secret() {
    let rendered = format!("{:?}", policy());
    assert!(!rendered.contains(ACTIVE), "secret leaked: {rendered}");
}

#[test]
fn constant_time_eq_agrees_with_ordinary_equality() {
    assert!(constant_time_eq(b"abcdef", b"abcdef"));
    assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
    assert!(!constant_time_eq(b"abcdef", b"abcde"));
    assert!(constant_time_eq(b"", b""));
}

#[test]
fn a_wrong_credential_is_refused() {
    let headers = vec![
        (
            HEADER_SIDECAR_CREDENTIAL,
            "wrong-secret-but-long-enough-0123456789",
        ),
        (HEADER_SIDECAR_REQUEST_ID, "sidecar-req-1"),
    ];
    let error = policy()
        .admit(&request(SidecarTransport::PrivateNetwork, &headers))
        .expect_err("a mismatched credential must be refused");
    assert_eq!(error, InboundX402AdmissionError::CredentialMismatch);
}

#[test]
fn a_missing_credential_is_refused() {
    let headers = vec![(HEADER_SIDECAR_REQUEST_ID, "sidecar-req-1")];
    let error = policy()
        .admit(&request(SidecarTransport::PrivateNetwork, &headers))
        .expect_err("no credential means no admission");
    assert_eq!(error, InboundX402AdmissionError::MissingCredential);
}

#[test]
fn rotation_is_visible_on_the_admitted_request() {
    let policy = SidecarAdmissionPolicy::new(rotating_credential(), false, Vec::new(), tenant())
        .expect("rotating policy is consistent");
    let headers = vec![
        (HEADER_SIDECAR_CREDENTIAL, ROTATING),
        (HEADER_SIDECAR_REQUEST_ID, "sidecar-req-1"),
    ];
    let admitted = policy
        .admit(&request(SidecarTransport::PrivateNetwork, &headers))
        .expect("the retiring secret is still accepted during rotation");
    assert!(admitted.used_rotating_out_credential());
    assert!(admitted
        .evidence_fields()
        .contains(&("sidecar_credential", "rotating_out".to_string())));
}

// -------------------------------------------------------------------------
// Spoofed attribution
// -------------------------------------------------------------------------

#[test]
fn every_reserved_attribution_header_is_refused() {
    for reserved in RESERVED_ATTRIBUTION_HEADERS {
        let headers = vec![
            (HEADER_SIDECAR_CREDENTIAL, ACTIVE),
            (HEADER_SIDECAR_REQUEST_ID, "sidecar-req-1"),
            (*reserved, "attacker-chosen"),
        ];
        let error = policy()
            .admit(&request(SidecarTransport::PrivateNetwork, &headers))
            .expect_err("a reserved attribution header must be refused");
        assert_eq!(
            error,
            InboundX402AdmissionError::ReservedHeaderPresent { header: reserved }
        );
    }
}

#[test]
fn a_reserved_header_is_refused_rather_than_silently_stripped() {
    let headers = vec![
        (HEADER_SIDECAR_CREDENTIAL, ACTIVE),
        (HEADER_SIDECAR_REQUEST_ID, "sidecar-req-1"),
        ("x-ferrogate-tenant", "some-other-tenant"),
    ];
    let error = policy()
        .admit(&request(SidecarTransport::PrivateNetwork, &headers))
        .expect_err("caller-asserted FerroGate identity must be refused");
    assert_eq!(
        error,
        InboundX402AdmissionError::ReservedHeaderPresent {
            header: "x-ferrogate-tenant",
        }
    );
}

#[test]
fn reserved_header_matching_is_case_insensitive() {
    let headers = vec![
        (HEADER_SIDECAR_CREDENTIAL, ACTIVE),
        (HEADER_SIDECAR_REQUEST_ID, "sidecar-req-1"),
        ("X-FerroGate-Payer", "attacker-wallet"),
    ];
    let error = policy()
        .admit(&request(SidecarTransport::PrivateNetwork, &headers))
        .expect_err("header names are case-insensitive on the wire");
    assert_eq!(
        error,
        InboundX402AdmissionError::ReservedHeaderPresent {
            header: "x-ferrogate-payer",
        }
    );
}

#[test]
fn the_tenant_comes_from_config_not_from_the_request() {
    let headers = base_headers();
    let admitted = policy()
        .admit(&request(SidecarTransport::PrivateNetwork, &headers))
        .expect("a clean sidecar request is admitted");
    assert_eq!(admitted.tenant, tenant());
}

// -------------------------------------------------------------------------
// Duplicate headers: never first-one-wins
// -------------------------------------------------------------------------

#[test]
fn a_duplicated_credential_header_is_ambiguous_not_first_one_wins() {
    let headers = vec![
        (HEADER_SIDECAR_CREDENTIAL, ACTIVE),
        (
            HEADER_SIDECAR_CREDENTIAL,
            "second-value-that-is-long-enough-01",
        ),
        (HEADER_SIDECAR_REQUEST_ID, "sidecar-req-1"),
    ];
    let error = policy()
        .admit(&request(SidecarTransport::PrivateNetwork, &headers))
        .expect_err("a proxy chain that disagrees with itself must not be resolved by order");
    assert_eq!(
        error,
        InboundX402AdmissionError::AmbiguousHeader {
            header: HEADER_SIDECAR_CREDENTIAL.to_string(),
        }
    );
}

#[test]
fn a_duplicated_sidecar_request_id_is_ambiguous() {
    let headers = vec![
        (HEADER_SIDECAR_CREDENTIAL, ACTIVE),
        (HEADER_SIDECAR_REQUEST_ID, "sidecar-req-1"),
        (HEADER_SIDECAR_REQUEST_ID, "sidecar-req-2"),
    ];
    let error = policy()
        .admit(&request(SidecarTransport::PrivateNetwork, &headers))
        .expect_err("the claim owner must not be chosen by header order");
    assert_eq!(
        error,
        InboundX402AdmissionError::AmbiguousHeader {
            header: HEADER_SIDECAR_REQUEST_ID.to_string(),
        }
    );
}

#[test]
fn single_returns_none_for_an_absent_header_and_the_value_for_one_occurrence() {
    let headers = base_headers();
    let request = request(SidecarTransport::PrivateNetwork, &headers);
    assert_eq!(request.single("x-absent").expect("no duplicate"), None);
    assert_eq!(
        request
            .single(HEADER_SIDECAR_REQUEST_ID)
            .expect("no duplicate"),
        Some("sidecar-req-1")
    );
}

// -------------------------------------------------------------------------
// Sidecar request id bounds
// -------------------------------------------------------------------------

#[test]
fn a_missing_sidecar_request_id_is_refused() {
    let headers = vec![(HEADER_SIDECAR_CREDENTIAL, ACTIVE)];
    let error = policy()
        .admit(&request(SidecarTransport::PrivateNetwork, &headers))
        .expect_err("the claim owner identity is mandatory");
    assert_eq!(error, InboundX402AdmissionError::MissingSidecarRequestId);
}

#[test]
fn an_oversized_sidecar_request_id_is_refused() {
    let oversized = "x".repeat(MAX_SIDECAR_REQUEST_ID_BYTES + 1);
    let headers = vec![
        (HEADER_SIDECAR_CREDENTIAL, ACTIVE),
        (HEADER_SIDECAR_REQUEST_ID, oversized.as_str()),
    ];
    let error = policy()
        .admit(&request(SidecarTransport::PrivateNetwork, &headers))
        .expect_err("an unbounded id would be copied into every downstream log line");
    assert_eq!(
        error,
        InboundX402AdmissionError::InvalidSidecarRequestId {
            len: MAX_SIDECAR_REQUEST_ID_BYTES + 1,
        }
    );
}

#[test]
fn an_empty_sidecar_request_id_is_refused() {
    let headers = vec![
        (HEADER_SIDECAR_CREDENTIAL, ACTIVE),
        (HEADER_SIDECAR_REQUEST_ID, ""),
    ];
    let error = policy()
        .admit(&request(SidecarTransport::PrivateNetwork, &headers))
        .expect_err("an empty claim owner would collide across requests");
    assert_eq!(
        error,
        InboundX402AdmissionError::InvalidSidecarRequestId { len: 0 }
    );
}

// -------------------------------------------------------------------------
// Strip list and evidence hygiene
// -------------------------------------------------------------------------

#[test]
fn headers_to_strip_covers_the_credential_and_every_reserved_header() {
    let strip = policy().headers_to_strip();
    assert!(strip.contains(&HEADER_SIDECAR_CREDENTIAL));
    // Every piece of spend-once material must stop at the gate. `PAYMENT-RESPONSE`
    // is the settlement proof a replay attempt needs, and the sidecar request id
    // is the forward-once claim owner; leaking either into the handler's request
    // logs (or into whatever the handler forwards to) hands out replay material.
    assert!(
        strip.contains(&HEADER_PAYMENT_RESPONSE),
        "the settlement proof must not reach the protected handler"
    );
    assert!(
        strip.contains(&HEADER_SIDECAR_REQUEST_ID),
        "the claim owner must not reach the protected handler"
    );
    for reserved in RESERVED_ATTRIBUTION_HEADERS {
        assert!(strip.contains(reserved), "{reserved} is not stripped");
    }
}

/// Whatever a request legitimately carries past admission must be on the strip
/// list. Pins the relationship rather than the list's current contents, so a
/// future header added to the admitted set cannot silently travel downstream.
#[test]
fn every_header_admission_consumes_is_stripped_before_the_handler() {
    let strip = policy().headers_to_strip();
    for consumed in [
        HEADER_SIDECAR_CREDENTIAL,
        HEADER_SIDECAR_REQUEST_ID,
        HEADER_PAYMENT_RESPONSE,
    ] {
        assert!(
            strip.contains(&consumed),
            "{consumed} is read by the gate but not stripped"
        );
    }
}

#[test]
fn evidence_fields_never_carry_the_credential_value() {
    let headers = base_headers();
    let admitted = policy()
        .admit(&request(SidecarTransport::PrivateNetwork, &headers))
        .expect("clean request");
    for (name, value) in admitted.evidence_fields() {
        assert_ne!(value, ACTIVE, "credential leaked through field {name}");
    }
}
