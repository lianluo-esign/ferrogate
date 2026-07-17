// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-17
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Tests for the signed policy-snapshot sign/verify primitives (issue #206).

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

use super::super::types::{ApiKey, PolicyRule};
use super::{
    canonical_signing_bytes, sign_snapshot, verify_snapshot, OfflineStatus, RejectReason,
    SignedSnapshotEnvelope, SignedSnapshotPayload, SignedSnapshotStore, SnapshotIngestOutcome,
    SIGNED_SNAPSHOT_SCHEMA_VERSION,
};

const TENANT: &str = "tenant-alpha";
const DEPLOYMENT: &str = "deploy-primary";
const KEY_ID: &str = "control-plane-2026-07";
const NOT_AFTER: u64 = 2_000_000_000;

/// Deterministic signing key from a fixed 32-byte seed. No RNG needed, so the
/// tests are fully reproducible and require no `rand` feature.
fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sample_api_key(id: &str) -> ApiKey {
    ApiKey {
        id: id.to_string(),
        name: format!("key-{id}"),
        key_env: Some("FERRO_KEY".to_string()),
        key: None,
        key_hash: Some("deadbeef".to_string()),
        enabled: true,
        scopes: vec!["chat".to_string(), "embeddings".to_string()],
        allowed_models: vec!["gpt-4o".to_string()],
        denied_models: vec![],
        allowed_providers: vec!["openai".to_string()],
        denied_providers: vec![],
        region_allowlist: vec!["eu-west-1".to_string()],
        organization_id: Some("org-1".to_string()),
        team_id: None,
        project_id: Some("proj-1".to_string()),
        workspace_id: None,
        user_id: None,
        monthly_token_budget: Some(1_000_000),
        request_limit_per_minute: Some(60),
        expires_at_unix: None,
        log_bodies: Some(false),
        cache_enabled: Some(true),
    }
}

fn sample_policy(name: &str) -> PolicyRule {
    PolicyRule {
        name: name.to_string(),
        effect: "deny".to_string(),
        organization_ids: vec!["org-1".to_string()],
        project_ids: vec![],
        api_key_ids: vec!["key-a".to_string()],
        models: vec!["gpt-4o".to_string()],
        providers: vec!["openai".to_string()],
        code: "policy.blocked".to_string(),
        message: "blocked by policy".to_string(),
        enabled: true,
    }
}

fn sample_payload() -> SignedSnapshotPayload {
    SignedSnapshotPayload {
        version: 1,
        api_keys: vec![sample_api_key("a"), sample_api_key("b")],
        policies: vec![sample_policy("block-openai")],
    }
}

/// Trust map containing the verifying key for `key_id`.
fn trust_map(entries: &[(&str, &VerifyingKey)]) -> BTreeMap<String, VerifyingKey> {
    entries
        .iter()
        .map(|(id, vk)| ((*id).to_string(), **vk))
        .collect()
}

/// Sign `sample_payload()` with a fresh key and return (envelope, trust map).
fn signed_fixture() -> (SignedSnapshotEnvelope, BTreeMap<String, VerifyingKey>) {
    let key = signing_key(7);
    let verifying = key.verifying_key();
    let envelope = sign_snapshot(
        sample_payload(),
        TENANT,
        DEPLOYMENT,
        5,
        NOT_AFTER,
        &key,
        KEY_ID,
    )
    .expect("sign should succeed for well-formed input");
    (envelope, trust_map(&[(KEY_ID, &verifying)]))
}

#[test]
fn sign_then_verify_round_trips() {
    let (envelope, keys) = signed_fixture();

    let verified = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 4, NOT_AFTER)
        .expect("valid snapshot must verify");

    assert_eq!(verified.key_id, KEY_ID);
    assert_eq!(verified.tenant_id, TENANT);
    assert_eq!(verified.deployment_id, DEPLOYMENT);
    assert_eq!(verified.revision, 5);
    // ApiKey/PolicyRule don't implement PartialEq; compare their serialized form.
    assert_eq!(
        serde_json::to_value(&verified.payload).expect("serialize verified"),
        serde_json::to_value(sample_payload()).expect("serialize expected"),
    );
}

#[test]
fn verify_accepts_now_equal_to_not_after() {
    // Boundary: now == not_after_unix is still valid (rejection is now > not_after).
    let (envelope, keys) = signed_fixture();

    let verified = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 4, NOT_AFTER)
        .expect("now == not_after must be accepted");
    assert_eq!(verified.revision, 5);
}

#[test]
fn ed25519_signature_is_deterministic() {
    // Same key + same payload => identical signature (RFC 8032). Guards against
    // an accidental change to the canonical encoding between two signs.
    let key = signing_key(9);
    let first = sign_snapshot(
        sample_payload(),
        TENANT,
        DEPLOYMENT,
        1,
        NOT_AFTER,
        &key,
        KEY_ID,
    )
    .expect("sign");
    let second = sign_snapshot(
        sample_payload(),
        TENANT,
        DEPLOYMENT,
        1,
        NOT_AFTER,
        &key,
        KEY_ID,
    )
    .expect("sign");
    assert_eq!(first.signature, second.signature);
}

#[test]
fn one_byte_payload_mutation_after_signing_is_rejected() {
    let (mut envelope, keys) = signed_fixture();

    // Flip one byte of a signed field: the first character of an api key name.
    let name = &mut envelope.payload.api_keys[0].name;
    let mut bytes = name.clone().into_bytes();
    bytes[0] ^= 0x01;
    *name = String::from_utf8(bytes).expect("still valid utf8");

    let result = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 4, NOT_AFTER);
    assert_eq!(result.unwrap_err(), RejectReason::BadSignature);
}

#[test]
fn signature_reused_from_a_different_payload_is_rejected() {
    let key = signing_key(7);
    let verifying = key.verifying_key();
    let keys = trust_map(&[(KEY_ID, &verifying)]);

    let mut target = sign_snapshot(
        sample_payload(),
        TENANT,
        DEPLOYMENT,
        5,
        NOT_AFTER,
        &key,
        KEY_ID,
    )
    .expect("sign target");

    // A validly-signed but DIFFERENT snapshot (extra policy, same key).
    let mut other_payload = sample_payload();
    other_payload
        .policies
        .push(sample_policy("block-anthropic"));
    let other = sign_snapshot(
        other_payload,
        TENANT,
        DEPLOYMENT,
        5,
        NOT_AFTER,
        &key,
        KEY_ID,
    )
    .expect("sign other");

    // Splice the other snapshot's (real, key-valid) signature onto our target.
    target.signature = other.signature;

    let result = verify_snapshot(&target, &keys, TENANT, DEPLOYMENT, 4, NOT_AFTER);
    assert_eq!(result.unwrap_err(), RejectReason::BadSignature);
}

#[test]
fn unknown_key_id_is_rejected() {
    let (envelope, _keys) = signed_fixture();
    // Trust map does not contain KEY_ID.
    let other = signing_key(11).verifying_key();
    let keys = trust_map(&[("some-other-key", &other)]);

    let result = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 4, NOT_AFTER);
    assert_eq!(result.unwrap_err(), RejectReason::UnknownKeyId);
}

#[test]
fn rotated_away_key_id_is_rejected() {
    // Snapshot signed under an old key_id; trust map only has the new one.
    let old_key = signing_key(1);
    let envelope = sign_snapshot(
        sample_payload(),
        TENANT,
        DEPLOYMENT,
        5,
        NOT_AFTER,
        &old_key,
        "key-old",
    )
    .expect("sign");

    let new_key = signing_key(2).verifying_key();
    let keys = trust_map(&[("key-new", &new_key)]);

    let result = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 4, NOT_AFTER);
    assert_eq!(result.unwrap_err(), RejectReason::UnknownKeyId);
}

#[test]
fn rotation_verifies_with_the_correct_new_key() {
    // Two keys live in the trust map; the snapshot is signed with the new one.
    let old_key = signing_key(1);
    let new_key = signing_key(2);
    let keys = trust_map(&[
        ("key-old", &old_key.verifying_key()),
        ("key-new", &new_key.verifying_key()),
    ]);

    let envelope = sign_snapshot(
        sample_payload(),
        TENANT,
        DEPLOYMENT,
        6,
        NOT_AFTER,
        &new_key,
        "key-new",
    )
    .expect("sign with rotated key");

    let verified = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 5, NOT_AFTER)
        .expect("rotated key must verify");
    assert_eq!(verified.key_id, "key-new");

    // And a snapshot signed by the retired key still verifies while it remains
    // in the trust map (rotation overlap), proving key_id selects the key.
    let old_env = sign_snapshot(
        sample_payload(),
        TENANT,
        DEPLOYMENT,
        6,
        NOT_AFTER,
        &old_key,
        "key-old",
    )
    .expect("sign with old key");
    assert!(verify_snapshot(&old_env, &keys, TENANT, DEPLOYMENT, 5, NOT_AFTER).is_ok());
}

#[test]
fn wrong_tenant_is_identity_mismatch() {
    let (envelope, keys) = signed_fixture();
    let result = verify_snapshot(&envelope, &keys, "tenant-other", DEPLOYMENT, 4, NOT_AFTER);
    assert_eq!(result.unwrap_err(), RejectReason::IdentityMismatch);
}

#[test]
fn wrong_deployment_is_identity_mismatch() {
    let (envelope, keys) = signed_fixture();
    let result = verify_snapshot(&envelope, &keys, TENANT, "deploy-other", 4, NOT_AFTER);
    assert_eq!(result.unwrap_err(), RejectReason::IdentityMismatch);
}

#[test]
fn revision_equal_to_active_is_stale() {
    let (envelope, keys) = signed_fixture(); // revision == 5
    let result = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 5, NOT_AFTER);
    assert_eq!(result.unwrap_err(), RejectReason::StaleOrReplayedRevision);
}

#[test]
fn revision_below_active_is_stale() {
    let (envelope, keys) = signed_fixture(); // revision == 5
    let result = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 9, NOT_AFTER);
    assert_eq!(result.unwrap_err(), RejectReason::StaleOrReplayedRevision);
}

#[test]
fn expired_snapshot_is_rejected() {
    let (envelope, keys) = signed_fixture();
    let result = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 4, NOT_AFTER + 1);
    assert_eq!(result.unwrap_err(), RejectReason::Expired);
}

#[test]
fn empty_signature_is_missing_signature() {
    let (mut envelope, keys) = signed_fixture();
    envelope.signature = String::new();
    let result = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 4, NOT_AFTER);
    assert_eq!(result.unwrap_err(), RejectReason::MissingSignature);
}

#[test]
fn whitespace_only_signature_is_missing_signature() {
    let (mut envelope, keys) = signed_fixture();
    envelope.signature = "   ".to_string();
    let result = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 4, NOT_AFTER);
    assert_eq!(result.unwrap_err(), RejectReason::MissingSignature);
}

#[test]
fn empty_key_id_is_unknown_key_id() {
    let (mut envelope, keys) = signed_fixture();
    envelope.key_id = String::new();
    let result = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 4, NOT_AFTER);
    assert_eq!(result.unwrap_err(), RejectReason::UnknownKeyId);
}

#[test]
fn malformed_base64_signature_does_not_panic_and_is_malformed_field() {
    let (mut envelope, keys) = signed_fixture();
    // Not valid base64 at all.
    envelope.signature = "!!! this is not base64 @@@".to_string();
    let result = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 4, NOT_AFTER);
    assert_eq!(result.unwrap_err(), RejectReason::MalformedField);
}

#[test]
fn wrong_length_signature_is_malformed_field() {
    let (mut envelope, keys) = signed_fixture();
    // Valid base64 but decodes to 10 bytes, not the 64 an Ed25519 signature needs.
    envelope.signature = BASE64_STANDARD.encode([0u8; 10]);
    let result = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 4, NOT_AFTER);
    assert_eq!(result.unwrap_err(), RejectReason::MalformedField);
}

#[test]
fn unsupported_schema_version_is_rejected() {
    // Forge a VALID signature over schema_version = 99 so verification reaches
    // the schema check (which runs after signature verification). Uses the
    // module-private canonical encoder so the bytes match verify's exactly.
    let key = signing_key(3);
    let verifying = key.verifying_key();
    let keys = trust_map(&[(KEY_ID, &verifying)]);

    let payload = sample_payload();
    let bad_schema = SIGNED_SNAPSHOT_SCHEMA_VERSION + 98;
    let canonical = canonical_signing_bytes(
        bad_schema, TENANT, DEPLOYMENT, KEY_ID, 5, NOT_AFTER, &payload,
    )
    .expect("canonical");
    let signature = key.sign(&canonical);

    let envelope = SignedSnapshotEnvelope {
        schema_version: bad_schema,
        tenant_id: TENANT.to_string(),
        deployment_id: DEPLOYMENT.to_string(),
        key_id: KEY_ID.to_string(),
        revision: 5,
        not_after_unix: NOT_AFTER,
        payload,
        signature: BASE64_STANDARD.encode(signature.to_bytes()),
    };

    let result = verify_snapshot(&envelope, &keys, TENANT, DEPLOYMENT, 4, NOT_AFTER);
    assert_eq!(result.unwrap_err(), RejectReason::SchemaUnsupported);
}

// --- SignedSnapshotStore: the offline policy loop (issue #206 acceptance #3) ---

/// A store trusting KEY_ID for TENANT/DEPLOYMENT, plus the signing key.
fn store_fixture() -> (SignedSnapshotStore, SigningKey) {
    let key = signing_key(7);
    let store = SignedSnapshotStore::new(
        trust_map(&[(KEY_ID, &key.verifying_key())]),
        TENANT,
        DEPLOYMENT,
    );
    (store, key)
}

fn envelope_at(key: &SigningKey, revision: u64, not_after: u64) -> SignedSnapshotEnvelope {
    sign_snapshot(
        sample_payload(),
        TENANT,
        DEPLOYMENT,
        revision,
        not_after,
        key,
        KEY_ID,
    )
    .expect("sign")
}

#[test]
fn new_store_fails_closed_with_no_snapshot() {
    let (store, _key) = store_fixture();
    assert_eq!(store.active_revision(), 0);
    assert_eq!(store.status(1_000), OfflineStatus::NoSnapshot);
    // Nothing to serve -> security-critical controls must deny.
    assert!(store.active_payload(1_000).is_none());
}

#[test]
fn store_activates_a_valid_snapshot_then_serves_it_until_expiry_then_fails_closed() {
    let (mut store, key) = store_fixture();
    let envelope = envelope_at(&key, 5, NOT_AFTER);

    assert_eq!(
        store.ingest(&envelope, NOT_AFTER - 100),
        SnapshotIngestOutcome::Activated { revision: 5 }
    );
    assert_eq!(store.active_revision(), 5);

    // Within validity: served, status Active.
    assert!(store.active_payload(NOT_AFTER - 100).is_some());
    assert_eq!(
        store.status(NOT_AFTER - 100),
        OfflineStatus::Active {
            revision: 5,
            not_after_unix: NOT_AFTER,
            seconds_until_expiry: 100,
        }
    );

    // Boundary now == not_after: still valid.
    assert!(store.active_payload(NOT_AFTER).is_some());

    // Past expiry with no fresh snapshot (control-plane outage): fail closed.
    assert_eq!(
        store.status(NOT_AFTER + 1),
        OfflineStatus::ExpiredFailClosed {
            revision: 5,
            not_after_unix: NOT_AFTER,
        }
    );
    assert!(
        store.active_payload(NOT_AFTER + 1).is_none(),
        "expired policy must not be served (no silent operation on expired policy)"
    );
}

#[test]
fn store_rejects_a_forged_snapshot_without_replacing_last_known_good() {
    let (mut store, key) = store_fixture();
    store.ingest(&envelope_at(&key, 5, NOT_AFTER), 1_000);

    // A newer-revision but forged (payload mutated after signing) envelope.
    let mut forged = envelope_at(&key, 6, NOT_AFTER);
    let name = &mut forged.payload.api_keys[0].name;
    let mut bytes = name.clone().into_bytes();
    bytes[0] ^= 0x01;
    *name = String::from_utf8(bytes).expect("utf8");

    assert_eq!(
        store.ingest(&forged, 1_000),
        SnapshotIngestOutcome::Rejected(RejectReason::BadSignature)
    );
    // Last-known-good is untouched: still rev 5, still serving.
    assert_eq!(store.active_revision(), 5);
    assert!(store.active_payload(1_000).is_some());
}

#[test]
fn store_rejects_replay_and_downgrade_against_the_active_revision() {
    let (mut store, key) = store_fixture();
    store.ingest(&envelope_at(&key, 5, NOT_AFTER), 1_000);

    // Replay the same revision.
    assert_eq!(
        store.ingest(&envelope_at(&key, 5, NOT_AFTER), 1_000),
        SnapshotIngestOutcome::Rejected(RejectReason::StaleOrReplayedRevision)
    );
    // Downgrade to an older revision.
    assert_eq!(
        store.ingest(&envelope_at(&key, 3, NOT_AFTER), 1_000),
        SnapshotIngestOutcome::Rejected(RejectReason::StaleOrReplayedRevision)
    );
    assert_eq!(store.active_revision(), 5);

    // A strictly-newer authentic snapshot IS adopted.
    assert_eq!(
        store.ingest(&envelope_at(&key, 6, NOT_AFTER), 1_000),
        SnapshotIngestOutcome::Activated { revision: 6 }
    );
    assert_eq!(store.active_revision(), 6);
}

#[test]
fn store_rejects_cross_tenant_and_expired_without_replacing_good_state() {
    let (mut store, key) = store_fixture();
    store.ingest(&envelope_at(&key, 5, NOT_AFTER), 1_000);

    // Cross-tenant: signed for a different tenant identity.
    let cross_tenant = sign_snapshot(
        sample_payload(),
        "tenant-evil",
        DEPLOYMENT,
        6,
        NOT_AFTER,
        &key,
        KEY_ID,
    )
    .expect("sign");
    assert_eq!(
        store.ingest(&cross_tenant, 1_000),
        SnapshotIngestOutcome::Rejected(RejectReason::IdentityMismatch)
    );

    // Expired-on-arrival: a newer revision that is already past its expiry.
    let already_expired = envelope_at(&key, 6, NOT_AFTER);
    assert_eq!(
        store.ingest(&already_expired, NOT_AFTER + 1),
        SnapshotIngestOutcome::Rejected(RejectReason::Expired)
    );

    // Neither rejection replaced the rev-5 last-known-good.
    assert_eq!(store.active_revision(), 5);
    assert!(store.active_payload(1_000).is_some());
}

#[test]
fn canonical_encoding_is_identical_for_sign_and_verify_inputs() {
    // The exact bytes signed by the producer must equal the bytes verify feeds
    // to Ed25519. Recompute both independently and compare.
    let payload = sample_payload();
    let a = canonical_signing_bytes(1, TENANT, DEPLOYMENT, KEY_ID, 5, NOT_AFTER, &payload)
        .expect("canonical a");
    let b = canonical_signing_bytes(1, TENANT, DEPLOYMENT, KEY_ID, 5, NOT_AFTER, &payload)
        .expect("canonical b");
    assert_eq!(a, b);

    // Object keys must be emitted sorted at the top level: deployment_id < key_id
    // < not_after_unix < payload < revision < schema_version < tenant_id.
    let text = String::from_utf8(a).expect("utf8");
    let dep = text.find("deployment_id").expect("deployment_id present");
    let key = text.find("\"key_id\"").expect("key_id present");
    let schema = text.find("schema_version").expect("schema_version present");
    assert!(dep < key, "keys must be lexicographically sorted");
    assert!(key < schema, "keys must be lexicographically sorted");
}
