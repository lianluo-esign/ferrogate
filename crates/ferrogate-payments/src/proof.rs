// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Proof construction for the SVM `exact` scheme (client role).
//!
//! The adapter never touches key material: transaction construction and
//! signing happen behind the injected [`SvmTransferSigner`] trait
//! (implemented later by a wallet, an HSM bridge, or — once it clears MSRV
//! qualification — the `solana-pay-kit` SDK). This module only turns the
//! signer's partially-signed transaction bytes into the x402 V2
//! `PAYMENT-SIGNATURE` wire artifact.

use std::fmt;

use serde_json::{json, Value};

use crate::error::PaymentError;
use crate::wire::{
    encode_header_bytes, SelectedPayment, SolanaNetwork, MAX_SVM_TRANSACTION_BYTES, X402_VERSION,
};

/// Opaque signer secret material. Debug and serde output never contain the
/// underlying bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap secret bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Expose the secret to a signer implementation. Deliberately explicit
    /// and narrowly scoped — never used by this crate's own wire code.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length of the secret, safe to log.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED; {} bytes])", self.0.len())
    }
}

impl serde::Serialize for SecretBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Secrets must never round-trip through serde output.
        serializer.serialize_str("[REDACTED]")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Best-effort scrub; not a hardened zeroize, but keeps plain drops
        // from leaving key bytes in freed memory.
        for b in self.0.iter_mut() {
            *b = 0;
        }
    }
}

/// Everything a signer needs to build and partially sign the SVM `exact`
/// transfer transaction. Derived from a validated [`SelectedPayment`]; the
/// adapter itself never constructs Solana instructions.
#[derive(Debug, Clone, PartialEq)]
pub struct SvmTransferIntent {
    /// Target network.
    pub network: SolanaNetwork,
    /// SPL token mint (base58).
    pub mint: String,
    /// Exact atomic amount to transfer.
    pub atomic_amount: u64,
    /// Recipient wallet owner (base58); the on-chain destination is the
    /// recipient's associated token account for `mint`.
    pub recipient: String,
    /// Facilitator fee payer that will co-sign and submit (base58).
    pub fee_payer: String,
    /// Memo instruction data mandated by the requirement, if any.
    pub memo: Option<String>,
    /// Server-supplied transaction lifetime (base58 blockhash), if any.
    /// When `Some`, the signer SHOULD build against this blockhash instead
    /// of fetching its own; when `None` the signer MUST fetch one.
    pub recent_blockhash: Option<String>,
    /// Bound on [`Self::recent_blockhash`], if the server supplied one.
    pub last_valid_block_height: Option<u64>,
    /// Deterministic challenge hash of the underlying requirement.
    pub challenge_hash: [u8; 32],
}

impl SvmTransferIntent {
    /// Build the signer-facing intent from a validated selection.
    pub fn from_selected(selected: &SelectedPayment) -> Self {
        Self {
            network: selected.network,
            mint: selected.mint.clone(),
            atomic_amount: selected.atomic_amount,
            recipient: selected.recipient.clone(),
            fee_payer: selected.fee_payer.clone(),
            memo: selected.memo.clone(),
            recent_blockhash: selected.recent_blockhash.clone(),
            last_valid_block_height: selected.last_valid_block_height,
            challenge_hash: selected.challenge_hash,
        }
    }
}

/// Injected signing boundary. Implementations hold the wallet/key material
/// and return the serialized, partially-signed versioned Solana transaction
/// for the given transfer intent.
///
/// Contract: the returned bytes are a complete wire-format transaction in
/// which the client's signature is present and the fee payer's slot is
/// unsigned; they must not exceed [`MAX_SVM_TRANSACTION_BYTES`].
pub trait SvmTransferSigner {
    /// The signer's public key (base58), i.e. the paying wallet.
    fn payer_address(&self) -> String;

    /// Build and partially sign the transfer. A refusal (policy veto, user
    /// denial, locked key) should be reported via `Err` with a reason; the
    /// adapter maps it to [`PaymentError::SignerRejected`].
    fn sign_transfer(&self, intent: &SvmTransferIntent) -> Result<Vec<u8>, String>;
}

/// Build the `PAYMENT-SIGNATURE` header value for a selected requirement,
/// routing all signing through the injected `signer`.
///
/// Returns the base64 header value; the decoded JSON is the x402 V2
/// `PaymentPayload` with the original requirement echoed in `accepted` and
/// the partially-signed transaction in `payload.transaction`.
pub fn build_payment_signature(
    selected: &SelectedPayment,
    signer: &dyn SvmTransferSigner,
) -> Result<String, PaymentError> {
    let intent = SvmTransferIntent::from_selected(selected);
    let tx_bytes = signer
        .sign_transfer(&intent)
        .map_err(|reason| PaymentError::SignerRejected { reason })?;
    if tx_bytes.is_empty() {
        return Err(PaymentError::ProofBuildFailed {
            reason: "signer returned an empty transaction".to_string(),
        });
    }
    if tx_bytes.len() > MAX_SVM_TRANSACTION_BYTES {
        return Err(PaymentError::ProofBuildFailed {
            reason: format!(
                "signer returned {} bytes, exceeding the {}-byte Solana packet limit",
                tx_bytes.len(),
                MAX_SVM_TRANSACTION_BYTES
            ),
        });
    }

    let mut payload: Value = json!({
        "x402Version": X402_VERSION,
        "resource": { "url": selected.resource_url },
        "accepted": selected.raw_requirement,
        "payload": { "transaction": encode_header_bytes(&tx_bytes) },
    });
    // x402 V2 §5.1.2: "clients echo them in `PaymentPayload`. The client must
    // include at least the info received". Echo the server's extensions
    // verbatim — never delete or overwrite what the server advertised.
    if let (Some(obj), Some(extensions)) = (payload.as_object_mut(), selected.extensions.as_ref()) {
        obj.insert("extensions".to_string(), extensions.clone());
    }
    let bytes = serde_json::to_vec(&payload).map_err(|e| PaymentError::ProofBuildFailed {
        reason: format!("payload serialization failed: {e}"),
    })?;
    Ok(encode_header_bytes(&bytes))
}
