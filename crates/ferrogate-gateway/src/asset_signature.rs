// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Detached-signature verification for hosted assets (issue #261,
// slice 2). FerroGate already runs an Ed25519 signing chain for its own
// control-plane snapshots (`config/signed_snapshot.rs`) and an SBOM/cosign
// chain for releases (#189); this reuses the same ed25519-dalek verify
// primitives -- no new crypto, no new dependency -- for tenant-published
// assets. A publisher registers an Ed25519 public key (minisign format or a
// bare base64 key); a detached signature pushed alongside a blob is verified
// against it and the result is surfaced in a verification manifest so a
// consuming agent can verify before executing. Two formats are accepted:
//   * minisign (`Ed` legacy / `ED` BLAKE2b-512-prehashed), and
//   * a bare detached Ed25519 signature over the raw blob (which is what
//     `cosign sign-blob` emits when configured with an Ed25519 key).
// ECDSA-keyed cosign is intentionally out of scope: it would need a P-256
// dependency, and the acceptance bar is met with the Ed25519 path.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use blake2::{Blake2b512, Digest};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;

/// Which detached-signature encoding a push carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFormat {
    /// A minisign signature file (`untrusted comment:` header + base64 body).
    Minisign,
    /// A bare base64 Ed25519 signature over the raw blob bytes.
    Ed25519,
}

impl SignatureFormat {
    /// Parse the `X-Asset-Signature-Format` header value; defaults to minisign.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "minisign" => Some(Self::Minisign),
            "ed25519" | "cosign" => Some(Self::Ed25519),
            _ => None,
        }
    }
}

/// The detached signature material presented at push time.
#[derive(Debug, Clone)]
pub struct AssetSignatureInput {
    pub format: SignatureFormat,
    /// The signature file text (minisign) or bare base64 signature (ed25519).
    pub material: String,
    /// Optional publisher key-id hint (for the bare-Ed25519 path).
    pub key_id: Option<String>,
}

/// Publisher-registered verification keys. Minisign keys are indexed by their
/// embedded 8-byte key id; bare Ed25519 keys are indexed by a caller-supplied
/// label.
#[derive(Debug, Default, Clone)]
pub struct PublisherKeyRegistry {
    minisign: BTreeMap<[u8; 8], VerifyingKey>,
    ed25519: BTreeMap<String, VerifyingKey>,
}

impl PublisherKeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a minisign public key (`RW...` base64, optionally preceded by
    /// an `untrusted comment:` line).
    pub(crate) fn register_minisign(&mut self, public_key: &str) -> Result<[u8; 8], String> {
        let (key_id, verifying_key) = parse_minisign_public_key(public_key)?;
        self.minisign.insert(key_id, verifying_key);
        Ok(key_id)
    }

    /// Register a bare base64 32-byte Ed25519 public key under `key_id`.
    pub fn register_ed25519(&mut self, key_id: &str, public_key_b64: &str) -> Result<(), String> {
        let bytes = BASE64_STANDARD
            .decode(public_key_b64.trim())
            .map_err(|error| format!("public key is not valid base64: {error}"))?;
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("expected a 32-byte ed25519 key, got {} bytes", bytes.len()))?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|error| format!("not a valid ed25519 key: {error}"))?;
        self.ed25519.insert(key_id.to_string(), verifying_key);
        Ok(())
    }

    /// Build a registry from newline/comma-separated env config. Bare keys use
    /// `label=base64`; minisign keys are the full public-key string.
    pub fn from_env() -> Self {
        let mut registry = Self::new();
        if let Ok(raw) = std::env::var("FERROGATE_ASSET_PUBLISHER_ED25519_KEYS") {
            for entry in raw
                .split([',', '\n'])
                .map(str::trim)
                .filter(|e| !e.is_empty())
            {
                if let Some((label, key)) = entry.split_once('=') {
                    let _ = registry.register_ed25519(label.trim(), key.trim());
                }
            }
        }
        if let Ok(raw) = std::env::var("FERROGATE_ASSET_PUBLISHER_MINISIGN_KEYS") {
            for entry in raw.split('\n').map(str::trim).filter(|e| !e.is_empty()) {
                let _ = registry.register_minisign(entry);
            }
        }
        registry
    }
}

/// The result of verifying (or not) an asset's detached signature. Serialized
/// into the verification manifest so agents can decide whether to trust a blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SignatureStatus {
    /// No signature was presented (allowed per policy, but labeled).
    Unsigned,
    /// Signature verified against a registered publisher key.
    Verified {
        key_id: String,
        format: &'static str,
    },
    /// A signature was presented but its key is not registered / trusted.
    Unverified { reason: String },
    /// A signature was presented and is cryptographically invalid or malformed.
    Invalid { reason: String },
}

impl SignatureStatus {
    pub fn is_verified(&self) -> bool {
        matches!(self, SignatureStatus::Verified { .. })
    }

    pub fn label(&self) -> &'static str {
        match self {
            SignatureStatus::Unsigned => "unsigned",
            SignatureStatus::Verified { .. } => "verified",
            SignatureStatus::Unverified { .. } => "unverified",
            SignatureStatus::Invalid { .. } => "invalid",
        }
    }
}

/// Verify a detached signature over `content` against the publisher registry.
pub fn verify_asset_signature(
    content: &[u8],
    signature: &AssetSignatureInput,
    keys: &PublisherKeyRegistry,
) -> SignatureStatus {
    match signature.format {
        SignatureFormat::Minisign => verify_minisign(content, &signature.material, keys),
        SignatureFormat::Ed25519 => verify_bare_ed25519(
            content,
            &signature.material,
            signature.key_id.as_deref(),
            keys,
        ),
    }
}

fn verify_minisign(content: &[u8], text: &str, keys: &PublisherKeyRegistry) -> SignatureStatus {
    let parsed = match parse_minisign_signature(text) {
        Ok(parsed) => parsed,
        Err(reason) => return SignatureStatus::Invalid { reason },
    };
    let Some(verifying_key) = keys.minisign.get(&parsed.key_id) else {
        return SignatureStatus::Unverified {
            reason: format!(
                "no registered minisign key for id {}",
                hex_lower(&parsed.key_id)
            ),
        };
    };
    // minisign signs the raw file (`Ed`) or its BLAKE2b-512 hash (`ED`,
    // prehashed) as an ordinary Ed25519 message.
    let message = match &parsed.algorithm {
        b"ED" => {
            let mut hasher = Blake2b512::new();
            hasher.update(content);
            hasher.finalize().to_vec()
        }
        b"Ed" => content.to_vec(),
        other => {
            return SignatureStatus::Invalid {
                reason: format!(
                    "unsupported minisign algorithm {:?}",
                    String::from_utf8_lossy(other)
                ),
            }
        }
    };
    match verifying_key.verify_strict(&message, &parsed.signature) {
        Ok(()) => SignatureStatus::Verified {
            key_id: hex_lower(&parsed.key_id),
            format: "minisign",
        },
        Err(_) => SignatureStatus::Invalid {
            reason: "minisign signature did not verify against the registered key".to_string(),
        },
    }
}

fn verify_bare_ed25519(
    content: &[u8],
    material: &str,
    key_id_hint: Option<&str>,
    keys: &PublisherKeyRegistry,
) -> SignatureStatus {
    let signature_bytes = match BASE64_STANDARD.decode(material.trim()) {
        Ok(bytes) => bytes,
        Err(error) => {
            return SignatureStatus::Invalid {
                reason: format!("signature is not valid base64: {error}"),
            }
        }
    };
    let signature = match Signature::from_slice(&signature_bytes) {
        Ok(signature) => signature,
        Err(_) => {
            return SignatureStatus::Invalid {
                reason: format!(
                    "expected a 64-byte ed25519 signature, got {} bytes",
                    signature_bytes.len()
                ),
            }
        }
    };
    if let Some(key_id) = key_id_hint {
        return match keys.ed25519.get(key_id) {
            Some(verifying_key) => match verifying_key.verify_strict(content, &signature) {
                Ok(()) => SignatureStatus::Verified {
                    key_id: key_id.to_string(),
                    format: "ed25519",
                },
                Err(_) => SignatureStatus::Invalid {
                    reason: "ed25519 signature did not verify against the named key".to_string(),
                },
            },
            None => SignatureStatus::Unverified {
                reason: format!("no registered ed25519 key with id {key_id}"),
            },
        };
    }
    // No hint: accept if any registered key verifies it.
    for (key_id, verifying_key) in &keys.ed25519 {
        if verifying_key.verify_strict(content, &signature).is_ok() {
            return SignatureStatus::Verified {
                key_id: key_id.clone(),
                format: "ed25519",
            };
        }
    }
    if keys.ed25519.is_empty() {
        SignatureStatus::Unverified {
            reason: "no publisher ed25519 keys are registered".to_string(),
        }
    } else {
        SignatureStatus::Invalid {
            reason: "ed25519 signature did not verify against any registered key".to_string(),
        }
    }
}

struct MinisignSignature {
    algorithm: [u8; 2],
    key_id: [u8; 8],
    signature: Signature,
}

/// Parse a minisign public key: base64 of `algo(2) || key_id(8) || pubkey(32)`.
fn parse_minisign_public_key(text: &str) -> Result<([u8; 8], VerifyingKey), String> {
    let line = text
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty() && !line.starts_with("untrusted comment:"))
        .ok_or_else(|| "minisign public key is empty".to_string())?;
    let bytes = BASE64_STANDARD
        .decode(line)
        .map_err(|error| format!("minisign public key is not valid base64: {error}"))?;
    if bytes.len() != 42 {
        return Err(format!(
            "expected a 42-byte minisign public key, got {} bytes",
            bytes.len()
        ));
    }
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&bytes[2..10]);
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&bytes[10..42]);
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("minisign public key is not a valid ed25519 key: {error}"))?;
    Ok((key_id, verifying_key))
}

/// Parse a minisign signature file, returning the first base64 line that
/// decodes to `algo(2) || key_id(8) || signature(64)` = 74 bytes.
fn parse_minisign_signature(text: &str) -> Result<MinisignSignature, String> {
    for line in text.lines().map(str::trim) {
        if line.is_empty()
            || line.starts_with("untrusted comment:")
            || line.starts_with("trusted comment:")
        {
            continue;
        }
        let Ok(bytes) = BASE64_STANDARD.decode(line) else {
            continue;
        };
        if bytes.len() != 74 {
            continue;
        }
        let mut algorithm = [0u8; 2];
        algorithm.copy_from_slice(&bytes[0..2]);
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&bytes[2..10]);
        let signature = Signature::from_slice(&bytes[10..74])
            .map_err(|error| format!("minisign signature bytes are invalid: {error}"))?;
        return Ok(MinisignSignature {
            algorithm,
            key_id,
            signature,
        });
    }
    Err("no 74-byte minisign signature line found".to_string())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The verification manifest an agent fetches to verify an asset before
/// executing it: the content digest to compare against the bytes it fetched,
/// plus scan/signature/approval state. Tampering with a stored blob is
/// detectable because the fetched bytes will not hash to `content_sha256`.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationManifest {
    pub object: &'static str,
    pub asset_id: String,
    pub content_sha256: String,
    pub size_bytes: u64,
    pub scan_state: &'static str,
    pub scan_backend: &'static str,
    pub signature: SignatureStatus,
    pub publish_visibility: &'static str,
    pub approval_state: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn signing_key(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }

    fn minisign_public_key(key_id: [u8; 8], key: &SigningKey) -> String {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"Ed");
        raw.extend_from_slice(&key_id);
        raw.extend_from_slice(key.verifying_key().as_bytes());
        format!("untrusted comment: test\n{}", BASE64.encode(raw))
    }

    fn minisign_signature(
        key_id: [u8; 8],
        key: &SigningKey,
        content: &[u8],
        prehash: bool,
    ) -> String {
        let (algo, message): (&[u8; 2], Vec<u8>) = if prehash {
            let mut hasher = Blake2b512::new();
            hasher.update(content);
            (b"ED", hasher.finalize().to_vec())
        } else {
            (b"Ed", content.to_vec())
        };
        let signature = key.sign(&message);
        let mut raw = Vec::new();
        raw.extend_from_slice(algo);
        raw.extend_from_slice(&key_id);
        raw.extend_from_slice(&signature.to_bytes());
        format!(
            "untrusted comment: signature\n{}\ntrusted comment: ts\nAAAA",
            BASE64.encode(raw)
        )
    }

    #[test]
    fn minisign_legacy_signature_verifies() {
        let key = signing_key(7);
        let key_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let content = b"#!/bin/sh\necho hello\n";
        let mut registry = PublisherKeyRegistry::new();
        registry
            .register_minisign(&minisign_public_key(key_id, &key))
            .expect("register");
        let input = AssetSignatureInput {
            format: SignatureFormat::Minisign,
            material: minisign_signature(key_id, &key, content, false),
            key_id: None,
        };
        assert!(verify_asset_signature(content, &input, &registry).is_verified());
    }

    #[test]
    fn minisign_prehashed_signature_verifies() {
        let key = signing_key(9);
        let key_id = [9, 9, 9, 9, 9, 9, 9, 9];
        let content = b"large binary payload";
        let mut registry = PublisherKeyRegistry::new();
        registry
            .register_minisign(&minisign_public_key(key_id, &key))
            .expect("register");
        let input = AssetSignatureInput {
            format: SignatureFormat::Minisign,
            material: minisign_signature(key_id, &key, content, true),
            key_id: None,
        };
        assert!(verify_asset_signature(content, &input, &registry).is_verified());
    }

    #[test]
    fn minisign_tampered_content_rejected() {
        let key = signing_key(3);
        let key_id = [4; 8];
        let mut registry = PublisherKeyRegistry::new();
        registry
            .register_minisign(&minisign_public_key(key_id, &key))
            .expect("register");
        let signature = minisign_signature(key_id, &key, b"original", false);
        let input = AssetSignatureInput {
            format: SignatureFormat::Minisign,
            material: signature,
            key_id: None,
        };
        // Verifying the same signature against different bytes must not pass.
        let status = verify_asset_signature(b"tampered", &input, &registry);
        assert!(
            matches!(status, SignatureStatus::Invalid { .. }),
            "{status:?}"
        );
    }

    #[test]
    fn minisign_unknown_key_is_unverified() {
        let key = signing_key(3);
        let key_id = [4; 8];
        let registry = PublisherKeyRegistry::new(); // nothing registered
        let input = AssetSignatureInput {
            format: SignatureFormat::Minisign,
            material: minisign_signature(key_id, &key, b"content", false),
            key_id: None,
        };
        assert!(matches!(
            verify_asset_signature(b"content", &input, &registry),
            SignatureStatus::Unverified { .. }
        ));
    }

    #[test]
    fn bare_ed25519_signature_verifies_and_rejects_tamper() {
        let key = signing_key(11);
        let content = b"cosign-signed blob";
        let signature = key.sign(content);
        let mut registry = PublisherKeyRegistry::new();
        registry
            .register_ed25519("pub-1", &BASE64.encode(key.verifying_key().as_bytes()))
            .expect("register");
        let good = AssetSignatureInput {
            format: SignatureFormat::Ed25519,
            material: BASE64.encode(signature.to_bytes()),
            key_id: Some("pub-1".to_string()),
        };
        assert!(verify_asset_signature(content, &good, &registry).is_verified());
        // Same signature over tampered bytes fails.
        assert!(matches!(
            verify_asset_signature(b"tampered", &good, &registry),
            SignatureStatus::Invalid { .. }
        ));
    }

    #[test]
    fn bare_ed25519_matches_without_hint() {
        let key = signing_key(21);
        let content = b"unhinted blob";
        let signature = key.sign(content);
        let mut registry = PublisherKeyRegistry::new();
        registry
            .register_ed25519("pub-x", &BASE64.encode(key.verifying_key().as_bytes()))
            .expect("register");
        let input = AssetSignatureInput {
            format: SignatureFormat::Ed25519,
            material: BASE64.encode(signature.to_bytes()),
            key_id: None,
        };
        assert!(verify_asset_signature(content, &input, &registry).is_verified());
    }

    #[test]
    fn signature_format_parsing() {
        assert_eq!(
            SignatureFormat::parse("minisign"),
            Some(SignatureFormat::Minisign)
        );
        assert_eq!(
            SignatureFormat::parse("COSIGN"),
            Some(SignatureFormat::Ed25519)
        );
        assert_eq!(
            SignatureFormat::parse("ed25519"),
            Some(SignatureFormat::Ed25519)
        );
        assert_eq!(SignatureFormat::parse("pgp"), None);
    }

    #[test]
    fn status_labels_are_stable() {
        assert_eq!(SignatureStatus::Unsigned.label(), "unsigned");
        assert_eq!(
            SignatureStatus::Invalid { reason: "x".into() }.label(),
            "invalid"
        );
    }
}
