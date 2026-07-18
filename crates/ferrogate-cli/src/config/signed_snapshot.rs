// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-17
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Signed policy-snapshot sign/verify primitives (issue #206).
//!
//! This module provides the cryptographic core for authenticating a policy
//! snapshot as it travels from the control plane to the data plane, plus the
//! config-driven [`build_snapshot_crypto`] builder and the [`SnapshotSigner`] /
//! [`SnapshotVerifier`] holders that wire it into the file-backed control plane.
//!
//! Wiring (opt-in, backward compatible): when a node configures
//! `cluster.snapshot_signing_key`, `SharedFileControlPlane::publish_from_config`
//! embeds a signed envelope in the published snapshot; when a node configures
//! `cluster.snapshot_trusted_keys`, `SharedAppState::sync_shared_control_plane`
//! verifies that envelope (identity + strictly-newer revision + unexpired)
//! BEFORE activating, and activates the cryptographically authenticated payload
//! — a rejected snapshot leaves the running config (last known good) untouched.
//! With neither configured, snapshots stay unsigned and the fnv1a64
//! change-detection (`state::shared_control_plane_revision`) behaves exactly as
//! before. The pure-offline [`SignedSnapshotStore`] decision core (last-known-
//! good buffering / expiry) remains available for the offline data-plane loop
//! but is not itself on the sync path.
//!
//! ## Why asymmetric (Ed25519)
//!
//! The control plane signs a snapshot with a private [`SigningKey`] that the data
//! plane never holds; the data plane verifies with a public [`VerifyingKey`]
//! looked up by `key_id`. A shared secret would let any holder (including a
//! compromised data plane) forge snapshots. Asymmetric keys also make rotation a
//! matter of publishing a new public key under a new `key_id` while retiring the
//! old one from the trust map.
//!
//! ## Canonical encoding
//!
//! The signature covers every envelope field EXCEPT `signature`, encoded by
//! [`canonical_signing_bytes`]. That function serialises the fields to a JSON
//! value and re-emits it with object keys sorted lexicographically at every
//! nesting level (arrays keep their order). The SAME function is used on the
//! producer (sign) and consumer (verify) sides, so the bytes are byte-for-byte
//! identical for identical logical content, and the encoding is independent of
//! struct field order or the `serde_json` `preserve_order` feature.
//!
//! ## Fail-closed verification
//!
//! [`verify_snapshot`] rejects on any missing/empty/unparseable field with a
//! typed [`RejectReason`]; a verification error is NEVER swallowed into `Ok`.

// The sign/verify path and config builder are now referenced by production code
// (state.rs), but some of the offline-loop surface (SignedSnapshotStore,
// OfflineStatus, active_payload/status) is not yet on a live path, so keep the
// module-level allow to avoid dead-code churn until the offline loop is wired.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::types::{ApiKey, PolicyRule};

/// Schema version this build knows how to verify. Bump only alongside a
/// documented change to the envelope/canonical-encoding shape.
pub(crate) const SIGNED_SNAPSHOT_SCHEMA_VERSION: u32 = 1;

/// The signable payload: a serializable clone of `state::SharedFileSnapshot`'s
/// `version` + `api_keys` + `policies` fields. Kept structurally identical so a
/// snapshot produced from a `SharedFileSnapshot` can round-trip through here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SignedSnapshotPayload {
    pub(crate) version: u32,
    pub(crate) api_keys: Vec<ApiKey>,
    pub(crate) policies: Vec<PolicyRule>,
}

/// A signed, self-describing snapshot envelope.
///
/// `signature` is the base64 (standard alphabet, with padding) encoding of the
/// 64-byte Ed25519 signature over [`canonical_signing_bytes`] of every OTHER
/// field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SignedSnapshotEnvelope {
    pub(crate) schema_version: u32,
    pub(crate) tenant_id: String,
    pub(crate) deployment_id: String,
    pub(crate) key_id: String,
    /// Monotonic revision counter; verification requires it to strictly exceed
    /// the currently active revision to block replay/downgrade.
    pub(crate) revision: u64,
    /// Unix seconds after which the snapshot must be rejected as expired.
    pub(crate) not_after_unix: u64,
    pub(crate) payload: SignedSnapshotPayload,
    pub(crate) signature: String,
}

/// A snapshot whose signature and metadata have passed every check in
/// [`verify_snapshot`]. Ownership of this type is proof of verification.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedSnapshot {
    pub(crate) key_id: String,
    pub(crate) tenant_id: String,
    pub(crate) deployment_id: String,
    pub(crate) revision: u64,
    pub(crate) not_after_unix: u64,
    pub(crate) payload: SignedSnapshotPayload,
}

/// Typed, exhaustive reasons [`verify_snapshot`] can reject an envelope. Every
/// verification failure maps to one of these; none is ever turned into `Ok`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectReason {
    /// The signature field is empty/whitespace.
    MissingSignature,
    /// No trusted verifying key is registered under the envelope's `key_id`
    /// (also covers an empty `key_id`, which can never be trusted).
    UnknownKeyId,
    /// The Ed25519 signature did not verify against the canonical bytes.
    BadSignature,
    /// `tenant_id`/`deployment_id` did not match the expected identity.
    IdentityMismatch,
    /// `schema_version` is not supported by this build.
    SchemaUnsupported,
    /// `revision` did not strictly exceed the active revision (replay/downgrade).
    StaleOrReplayedRevision,
    /// `now_unix` is past `not_after_unix`.
    Expired,
    /// A field could not be parsed/encoded (e.g. non-base64 or wrong-length
    /// signature bytes, or a value that failed canonical serialization).
    MalformedField,
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            RejectReason::MissingSignature => "signature is missing or empty",
            RejectReason::UnknownKeyId => "no trusted key for the supplied key_id",
            RejectReason::BadSignature => "signature failed verification",
            RejectReason::IdentityMismatch => "tenant/deployment identity mismatch",
            RejectReason::SchemaUnsupported => "unsupported schema_version",
            RejectReason::StaleOrReplayedRevision => "revision is stale or replayed",
            RejectReason::Expired => "snapshot has expired",
            RejectReason::MalformedField => "a field was malformed or unparseable",
        };
        f.write_str(text)
    }
}

impl std::error::Error for RejectReason {}

/// Error returned by [`sign_snapshot`]. Signing is infallible for well-formed,
/// producer-controlled input; this variant only guards the (unreachable in
/// practice) case of a canonical-serialization failure so the producer path
/// never `unwrap`/`expect`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignError {
    Canonicalization,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::Canonicalization => f.write_str("failed to canonically encode snapshot"),
        }
    }
}

impl std::error::Error for SignError {}

/// Produce a signed envelope for `payload`. Producer side (control plane).
///
/// The envelope's `schema_version` is fixed to [`SIGNED_SNAPSHOT_SCHEMA_VERSION`]
/// and the signature is computed over [`canonical_signing_bytes`] of all fields
/// except the signature itself.
pub(crate) fn sign_snapshot(
    payload: SignedSnapshotPayload,
    tenant_id: &str,
    deployment_id: &str,
    revision: u64,
    not_after_unix: u64,
    signing_key: &SigningKey,
    key_id: &str,
) -> Result<SignedSnapshotEnvelope, SignError> {
    let schema_version = SIGNED_SNAPSHOT_SCHEMA_VERSION;
    let canonical = canonical_signing_bytes(
        schema_version,
        tenant_id,
        deployment_id,
        key_id,
        revision,
        not_after_unix,
        &payload,
    )
    .map_err(|_| SignError::Canonicalization)?;

    let signature: Signature = signing_key.sign(&canonical);
    let signature_b64 = BASE64_STANDARD.encode(signature.to_bytes());

    Ok(SignedSnapshotEnvelope {
        schema_version,
        tenant_id: tenant_id.to_string(),
        deployment_id: deployment_id.to_string(),
        key_id: key_id.to_string(),
        revision,
        not_after_unix,
        payload,
        signature: signature_b64,
    })
}

/// Verify a signed envelope against a trust map, in this fail-closed order:
///
/// 1. non-empty signature/key_id guard,
/// 2. (a) re-serialize payload+meta canonically,
/// 3. (b) look up the [`VerifyingKey`] by `key_id` (`UnknownKeyId` if absent),
/// 4. (c) verify the Ed25519 signature (`BadSignature` on failure — never
///    swallowed into `Ok`),
/// 5. (d) `tenant_id`/`deployment_id` match (`IdentityMismatch`),
/// 6. (e) `schema_version` supported (`SchemaUnsupported`),
/// 7. (f) `revision > active_revision` (`StaleOrReplayedRevision`),
/// 8. (g) `now_unix <= not_after_unix` (`Expired`).
///
/// The signature covers the identity, schema, revision and expiry fields, so
/// they are only inspected AFTER the signature has authenticated them.
pub(crate) fn verify_snapshot(
    envelope: &SignedSnapshotEnvelope,
    trusted_keys: &BTreeMap<String, VerifyingKey>,
    expected_tenant: &str,
    expected_deployment: &str,
    active_revision: u64,
    now_unix: u64,
) -> Result<VerifiedSnapshot, RejectReason> {
    // Fail-closed guards: an empty/missing signature or key_id is never
    // acceptable and must not reach signature verification.
    if envelope.signature.trim().is_empty() {
        return Err(RejectReason::MissingSignature);
    }
    if envelope.key_id.is_empty() {
        // An empty key_id can never be present in a legitimate trust map.
        return Err(RejectReason::UnknownKeyId);
    }

    // (a) Canonical bytes over every field except the signature.
    let canonical = canonical_signing_bytes(
        envelope.schema_version,
        &envelope.tenant_id,
        &envelope.deployment_id,
        &envelope.key_id,
        envelope.revision,
        envelope.not_after_unix,
        &envelope.payload,
    )?;

    // (b) Look up the verifying key by key_id.
    let verifying_key = trusted_keys
        .get(&envelope.key_id)
        .ok_or(RejectReason::UnknownKeyId)?;

    // (c) Decode + verify the signature. Malformed base64 or wrong-length bytes
    // are MalformedField (never a panic); a cryptographic failure is
    // BadSignature. Neither is ever turned into Ok.
    let signature_bytes = BASE64_STANDARD
        .decode(envelope.signature.as_bytes())
        .map_err(|_| RejectReason::MalformedField)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| RejectReason::MalformedField)?;
    verifying_key
        .verify_strict(&canonical, &signature)
        .map_err(|_| RejectReason::BadSignature)?;

    // (d) Identity: tenant + deployment must match exactly.
    if envelope.tenant_id != expected_tenant || envelope.deployment_id != expected_deployment {
        return Err(RejectReason::IdentityMismatch);
    }

    // (e) Schema must be one this build understands.
    if envelope.schema_version != SIGNED_SNAPSHOT_SCHEMA_VERSION {
        return Err(RejectReason::SchemaUnsupported);
    }

    // (f) Revision must strictly advance to block replay/downgrade.
    if envelope.revision <= active_revision {
        return Err(RejectReason::StaleOrReplayedRevision);
    }

    // (g) Expiry: reject once we are past not_after_unix.
    if now_unix > envelope.not_after_unix {
        return Err(RejectReason::Expired);
    }

    Ok(VerifiedSnapshot {
        key_id: envelope.key_id.clone(),
        tenant_id: envelope.tenant_id.clone(),
        deployment_id: envelope.deployment_id.clone(),
        revision: envelope.revision,
        not_after_unix: envelope.not_after_unix,
        payload: envelope.payload.clone(),
    })
}

/// Ed25519 key material is 32 bytes (both the signing seed and the public key).
const ED25519_KEY_LEN: usize = 32;

/// Reasons a configured snapshot key or identity is unusable. Surfaced both at
/// config-validation time and at runtime construction (they share
/// [`build_snapshot_crypto`], so validation and the live gate never diverge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SnapshotConfigError {
    /// A base64 key field did not decode.
    InvalidBase64 { field: &'static str },
    /// A key decoded but was not 32 bytes.
    WrongKeyLength { field: &'static str, len: usize },
    /// A signing/verification identity field was required but missing/empty.
    MissingIdentity { field: &'static str },
    /// `snapshot_signing_key` was set without a `snapshot_signing_key_id`.
    MissingSigningKeyId,
    /// A trusted key entry had an empty `key_id`.
    EmptyTrustedKeyId,
    /// Two trusted key entries shared a `key_id`.
    DuplicateTrustedKeyId { key_id: String },
    /// `snapshot_max_age_secs` was zero while signing was enabled.
    ZeroMaxAge,
}

impl fmt::Display for SnapshotConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotConfigError::InvalidBase64 { field } => {
                write!(f, "field {field}: must be valid base64")
            }
            SnapshotConfigError::WrongKeyLength { field, len } => {
                write!(f, "field {field}: expected a 32-byte ed25519 key, got {len} bytes")
            }
            SnapshotConfigError::MissingIdentity { field } => {
                write!(f, "field {field}: required when snapshot signing or verification is enabled")
            }
            SnapshotConfigError::MissingSigningKeyId => f.write_str(
                "field cluster.snapshot_signing_key_id: required when cluster.snapshot_signing_key is set",
            ),
            SnapshotConfigError::EmptyTrustedKeyId => {
                f.write_str("field cluster.snapshot_trusted_keys: key_id cannot be empty")
            }
            SnapshotConfigError::DuplicateTrustedKeyId { key_id } => {
                write!(f, "field cluster.snapshot_trusted_keys: duplicate key_id {key_id:?}")
            }
            SnapshotConfigError::ZeroMaxAge => f.write_str(
                "field cluster.snapshot_max_age_secs: must be greater than zero when signing is enabled",
            ),
        }
    }
}

impl std::error::Error for SnapshotConfigError {}

fn decode_ed25519_bytes(
    b64: &str,
    field: &'static str,
) -> Result<[u8; ED25519_KEY_LEN], SnapshotConfigError> {
    let bytes = BASE64_STANDARD
        .decode(b64.trim().as_bytes())
        .map_err(|_| SnapshotConfigError::InvalidBase64 { field })?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| SnapshotConfigError::WrongKeyLength {
            field,
            len: bytes.len(),
        })
}

/// Parse a base64 (standard) 32-byte Ed25519 seed into a [`SigningKey`].
pub(crate) fn parse_signing_key(
    b64_seed: &str,
    field: &'static str,
) -> Result<SigningKey, SnapshotConfigError> {
    Ok(SigningKey::from_bytes(&decode_ed25519_bytes(
        b64_seed, field,
    )?))
}

/// Parse a base64 (standard) 32-byte Ed25519 public key into a [`VerifyingKey`].
pub(crate) fn parse_verifying_key(
    b64_public: &str,
    field: &'static str,
) -> Result<VerifyingKey, SnapshotConfigError> {
    VerifyingKey::from_bytes(&decode_ed25519_bytes(b64_public, field)?).map_err(|_| {
        SnapshotConfigError::WrongKeyLength {
            field,
            len: ED25519_KEY_LEN,
        }
    })
}

/// Producer-side signing material for file-backed control-plane snapshots (#206).
pub(crate) struct SnapshotSigner {
    signing_key: SigningKey,
    key_id: String,
    tenant_id: String,
    deployment_id: String,
    max_age_secs: u64,
}

// Redacting Debug impls: the signing seed and trust map must never reach logs.
impl fmt::Debug for SnapshotSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotSigner")
            .field("key_id", &self.key_id)
            .field("tenant_id", &self.tenant_id)
            .field("deployment_id", &self.deployment_id)
            .field("max_age_secs", &self.max_age_secs)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl SnapshotSigner {
    /// Sign `payload` for `revision`, stamping expiry `now_unix + max_age_secs`.
    pub(crate) fn sign(
        &self,
        payload: SignedSnapshotPayload,
        revision: u64,
        now_unix: u64,
    ) -> Result<SignedSnapshotEnvelope, SignError> {
        let not_after_unix = now_unix.saturating_add(self.max_age_secs);
        sign_snapshot(
            payload,
            &self.tenant_id,
            &self.deployment_id,
            revision,
            not_after_unix,
            &self.signing_key,
            &self.key_id,
        )
    }
}

/// Consumer-side verification material for file-backed control-plane snapshots.
pub(crate) struct SnapshotVerifier {
    trusted_keys: BTreeMap<String, VerifyingKey>,
    expected_tenant: String,
    expected_deployment: String,
}

impl fmt::Debug for SnapshotVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotVerifier")
            .field("expected_tenant", &self.expected_tenant)
            .field("expected_deployment", &self.expected_deployment)
            .field(
                "trusted_key_ids",
                &self.trusted_keys.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl SnapshotVerifier {
    /// Verify `envelope` against the configured trust map/identity, requiring
    /// `revision > active_revision` and an unexpired `not_after_unix`.
    pub(crate) fn verify(
        &self,
        envelope: &SignedSnapshotEnvelope,
        active_revision: u64,
        now_unix: u64,
    ) -> Result<VerifiedSnapshot, RejectReason> {
        verify_snapshot(
            envelope,
            &self.trusted_keys,
            &self.expected_tenant,
            &self.expected_deployment,
            active_revision,
            now_unix,
        )
    }
}

/// The signing/verification material derived from a node's cluster config.
/// `signer` is `Some` when this node publishes signed snapshots; `verifier` is
/// `Some` when this node must verify snapshots before activating them. Either,
/// both, or neither may be enabled.
#[derive(Debug)]
pub(crate) struct SnapshotCrypto {
    pub(crate) signer: Option<SnapshotSigner>,
    pub(crate) verifier: Option<SnapshotVerifier>,
}

impl SnapshotCrypto {
    /// The `(tenant_id, deployment_id)` identity this node signs/verifies
    /// snapshots for, or `None` when neither signing nor verification is
    /// configured. Signer and verifier always share the identity (both are
    /// built from the same `cluster.snapshot_tenant_id`/`_deployment_id`
    /// fields), so either side is authoritative. Used as the durable
    /// replay-floor key (#206).
    pub(crate) fn identity(&self) -> Option<(&str, &str)> {
        if let Some(verifier) = &self.verifier {
            return Some((
                verifier.expected_tenant.as_str(),
                verifier.expected_deployment.as_str(),
            ));
        }
        self.signer
            .as_ref()
            .map(|signer| (signer.tenant_id.as_str(), signer.deployment_id.as_str()))
    }
}

/// Build the snapshot signing/verification material from cluster config, or
/// return the first configuration error. Called BOTH by `Config::validate`
/// (result discarded) and at runtime construction, so a config that validates
/// is guaranteed to build. When neither signing nor verification is configured,
/// returns a crypto with both fields `None` (legacy unsigned behavior).
pub(crate) fn build_snapshot_crypto(
    cluster: &super::types::ClusterConfig,
) -> Result<SnapshotCrypto, SnapshotConfigError> {
    let signing_enabled = cluster
        .snapshot_signing_key
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let verification_enabled = !cluster.snapshot_trusted_keys.is_empty();

    if !signing_enabled && !verification_enabled {
        return Ok(SnapshotCrypto {
            signer: None,
            verifier: None,
        });
    }

    let tenant_id = cluster
        .snapshot_tenant_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(SnapshotConfigError::MissingIdentity {
            field: "cluster.snapshot_tenant_id",
        })?
        .to_string();
    let deployment_id = cluster
        .snapshot_deployment_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(SnapshotConfigError::MissingIdentity {
            field: "cluster.snapshot_deployment_id",
        })?
        .to_string();

    let signer = if signing_enabled {
        if cluster.snapshot_max_age_secs == 0 {
            return Err(SnapshotConfigError::ZeroMaxAge);
        }
        let key_id = cluster
            .snapshot_signing_key_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(SnapshotConfigError::MissingSigningKeyId)?
            .to_string();
        let signing_key = parse_signing_key(
            cluster.snapshot_signing_key.as_deref().unwrap_or_default(),
            "cluster.snapshot_signing_key",
        )?;
        Some(SnapshotSigner {
            signing_key,
            key_id,
            tenant_id: tenant_id.clone(),
            deployment_id: deployment_id.clone(),
            max_age_secs: cluster.snapshot_max_age_secs,
        })
    } else {
        None
    };

    let verifier = if verification_enabled {
        let mut trusted_keys = BTreeMap::new();
        for entry in &cluster.snapshot_trusted_keys {
            let key_id = entry.key_id.trim();
            if key_id.is_empty() {
                return Err(SnapshotConfigError::EmptyTrustedKeyId);
            }
            let verifying_key = parse_verifying_key(
                &entry.public_key,
                "cluster.snapshot_trusted_keys.public_key",
            )?;
            if trusted_keys
                .insert(key_id.to_string(), verifying_key)
                .is_some()
            {
                return Err(SnapshotConfigError::DuplicateTrustedKeyId {
                    key_id: key_id.to_string(),
                });
            }
        }
        Some(SnapshotVerifier {
            trusted_keys,
            expected_tenant: tenant_id,
            expected_deployment: deployment_id,
        })
    } else {
        None
    };

    Ok(SnapshotCrypto { signer, verifier })
}

/// Deterministic canonical byte encoding of every envelope field except the
/// signature. Both sign and verify call THIS function with the same arguments,
/// guaranteeing identical bytes for identical logical content.
///
/// The fields are serialized to a JSON value and re-emitted with object keys
/// sorted lexicographically at every level; arrays preserve their order. Scalar
/// and string encoding is delegated to `serde_json` (correct escaping); only key
/// ordering is overridden, making the output independent of struct field order
/// or the `preserve_order` feature.
fn canonical_signing_bytes(
    schema_version: u32,
    tenant_id: &str,
    deployment_id: &str,
    key_id: &str,
    revision: u64,
    not_after_unix: u64,
    payload: &SignedSnapshotPayload,
) -> Result<Vec<u8>, RejectReason> {
    #[derive(Serialize)]
    struct CanonicalSigningInput<'a> {
        schema_version: u32,
        tenant_id: &'a str,
        deployment_id: &'a str,
        key_id: &'a str,
        revision: u64,
        not_after_unix: u64,
        payload: &'a SignedSnapshotPayload,
    }

    let input = CanonicalSigningInput {
        schema_version,
        tenant_id,
        deployment_id,
        key_id,
        revision,
        not_after_unix,
        payload,
    };

    let value = serde_json::to_value(&input).map_err(|_| RejectReason::MalformedField)?;
    let mut out = Vec::new();
    write_canonical(&value, &mut out)?;
    Ok(out)
}

/// Recursively write `value` as canonical JSON: object keys sorted, arrays in
/// order, scalars/strings via `serde_json` for correct escaping.
fn write_canonical(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<(), RejectReason> {
    match value {
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
            out.push(b'{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                let key_json = serde_json::to_vec(key).map_err(|_| RejectReason::MalformedField)?;
                out.extend_from_slice(&key_json);
                out.push(b':');
                write_canonical(item, out)?;
            }
            out.push(b'}');
        }
        scalar => {
            let scalar_json =
                serde_json::to_vec(scalar).map_err(|_| RejectReason::MalformedField)?;
            out.extend_from_slice(&scalar_json);
        }
    }
    Ok(())
}

/// Outcome of feeding an envelope to a [`SignedSnapshotStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SnapshotIngestOutcome {
    /// The envelope verified and became the new last-known-good at `revision`.
    Activated { revision: u64 },
    /// The envelope failed verification; the prior last-known-good is retained
    /// unchanged (acceptance #206: a forged/replayed/expired/... snapshot must
    /// never replace good state).
    Rejected(RejectReason),
}

/// The data plane's offline serving status, derived from the last-known-good
/// snapshot and the current clock (issue #206 acceptance: continue on the last
/// valid snapshot until expiry, then fail closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OfflineStatus {
    /// No snapshot has ever been accepted -- the data plane has no policy to
    /// serve and must fail closed for security-critical controls.
    NoSnapshot,
    /// Serving the last-known-good snapshot; it is still within its validity
    /// window.
    Active {
        revision: u64,
        not_after_unix: u64,
        seconds_until_expiry: u64,
    },
    /// The last-known-good snapshot has passed its `not_after_unix`. Security
    /// policy must NOT be served on an expired snapshot (no silent indefinite
    /// operation on expired policy -- issue #206 non-goal); the data plane fails
    /// closed until a fresh snapshot arrives.
    ExpiredFailClosed { revision: u64, not_after_unix: u64 },
}

/// The data-plane side of the offline policy loop (issue #206): holds the last
/// verified snapshot, accepts only strictly-newer authentic snapshots (via
/// [`verify_snapshot`], keyed off the currently-active revision so replays and
/// downgrades are rejected), and decides what may be served during a
/// control-plane outage — continue on the last-known-good until its expiry,
/// then fail closed.
///
/// This is the pure decision core; the outbound-only sync transport that feeds
/// it envelopes and the activation wiring are separate (network/infra) steps.
pub(crate) struct SignedSnapshotStore {
    trusted_keys: BTreeMap<String, VerifyingKey>,
    expected_tenant: String,
    expected_deployment: String,
    last_known_good: Option<VerifiedSnapshot>,
}

impl SignedSnapshotStore {
    /// A store trusting `trusted_keys`, bound to a single tenant/deployment
    /// identity, with no snapshot yet (so it fails closed until one arrives).
    pub(crate) fn new(
        trusted_keys: BTreeMap<String, VerifyingKey>,
        expected_tenant: impl Into<String>,
        expected_deployment: impl Into<String>,
    ) -> Self {
        Self {
            trusted_keys,
            expected_tenant: expected_tenant.into(),
            expected_deployment: expected_deployment.into(),
            last_known_good: None,
        }
    }

    /// The currently-active revision (0 when no snapshot has been accepted),
    /// used as the replay/downgrade floor for the next envelope.
    pub(crate) fn active_revision(&self) -> u64 {
        self.last_known_good
            .as_ref()
            .map(|snapshot| snapshot.revision)
            .unwrap_or(0)
    }

    /// Verify `envelope` against the current active revision and, only if it
    /// passes every check, adopt it as the new last-known-good. A rejected
    /// envelope leaves the prior last-known-good untouched.
    pub(crate) fn ingest(
        &mut self,
        envelope: &SignedSnapshotEnvelope,
        now_unix: u64,
    ) -> SnapshotIngestOutcome {
        match verify_snapshot(
            envelope,
            &self.trusted_keys,
            &self.expected_tenant,
            &self.expected_deployment,
            self.active_revision(),
            now_unix,
        ) {
            Ok(verified) => {
                let revision = verified.revision;
                self.last_known_good = Some(verified);
                SnapshotIngestOutcome::Activated { revision }
            }
            Err(reason) => SnapshotIngestOutcome::Rejected(reason),
        }
    }

    /// The offline serving status at `now_unix`.
    pub(crate) fn status(&self, now_unix: u64) -> OfflineStatus {
        match &self.last_known_good {
            None => OfflineStatus::NoSnapshot,
            Some(snapshot) if now_unix <= snapshot.not_after_unix => OfflineStatus::Active {
                revision: snapshot.revision,
                not_after_unix: snapshot.not_after_unix,
                seconds_until_expiry: snapshot.not_after_unix - now_unix,
            },
            Some(snapshot) => OfflineStatus::ExpiredFailClosed {
                revision: snapshot.revision,
                not_after_unix: snapshot.not_after_unix,
            },
        }
    }

    /// The payload safe to serve at `now_unix`: the last-known-good snapshot's
    /// payload while it is unexpired, or `None` once expired (fail closed) or if
    /// none has ever been accepted. Security-critical controls must treat `None`
    /// as deny.
    pub(crate) fn active_payload(&self, now_unix: u64) -> Option<&SignedSnapshotPayload> {
        match &self.last_known_good {
            Some(snapshot) if now_unix <= snapshot.not_after_unix => Some(&snapshot.payload),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "signed_snapshot_test.rs"]
mod tests;
