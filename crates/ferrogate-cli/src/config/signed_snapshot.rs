// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-17
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Signed policy-snapshot sign/verify primitives (issue #206).
//!
//! This module provides the *isolated* cryptographic core for authenticating a
//! policy snapshot as it travels from the control plane to the data plane. It is
//! intentionally NOT wired into the live control-plane activation path
//! (`SharedFileControlPlane::load` / `sync_shared_control_plane`) in this pass;
//! wiring changes runtime behaviour and is a separate, reviewed step. The
//! existing fnv1a64 change-detection (`config::snapshot::config_snapshot_id` and
//! `state::shared_control_plane_revision`) is left untouched.
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

// This module is deliberately not referenced by production code yet (see the
// module docs: wiring into the activation path is a separate reviewed step), so
// its public surface is dead code in a bin-only build. The tests exercise it.
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

#[cfg(test)]
#[path = "signed_snapshot_test.rs"]
mod tests;
