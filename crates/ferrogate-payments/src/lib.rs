// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! FerroGate x402 V2 / Solana SVM payment wire contract (issue #350).
//!
//! A narrow, protocol-neutral client-side boundary for agent payments:
//! **x402 version 2, HTTP transport, Solana SVM networks, `exact` scheme,
//! client role**. Everything else — HTTP transport plumbing, payment
//! policy/budgets, wallet key loading, RPC submission — deliberately lives
//! OUTSIDE this crate.
//!
//! The adapter surface is four steps:
//!
//! 1. [`parse_payment_required`] — decode + validate a `PAYMENT-REQUIRED`
//!    challenge header.
//! 2. [`select_requirement`] — pick exactly one supported requirement
//!    (scheme `exact`, recognised Solana CAIP-2 network, valid mint /
//!    amount / recipient / timeout) into a structured [`SelectedPayment`]
//!    with a deterministic challenge hash.
//! 3. [`build_payment_signature`] — build the `PAYMENT-SIGNATURE` proof,
//!    with all transaction construction and signing behind the injected
//!    [`SvmTransferSigner`] trait. Server-advertised `extensions` are echoed
//!    verbatim, as the spec requires of clients.
//! 4. [`parse_payment_response`] — decode settlement evidence from the
//!    `PAYMENT-RESPONSE` header.
//!
//! # SDK qualification (issue #350)
//!
//! `solana-pay-kit 0.2.0` was qualified for this role and the verdict is
//! **not usable yet** on the workspace MSRV (Rust 1.88): its mandatory
//! dependency tree requires rustc >= 1.89 with no compatible pin, and the
//! minimal feature set still drags the full Solana RPC client stack (553
//! locked packages). Wire parsing here is therefore hand-rolled against the
//! upstream x402 V2 specification, with checked-in golden fixtures and a
//! negative corpus freezing the contract. The machine-readable verdict
//! lives in [`sdk`] behind the non-default `sdk-solana-pay-kit` feature;
//! the full evidence chain is in this crate's `README.md`.
//!
//! This crate performs no network I/O, opens no wallet, and loads no keys.

mod attempt_state;
mod error;
mod intent;
mod proof;
mod wire;

#[cfg(feature = "sdk-solana-pay-kit")]
pub mod sdk;

pub use attempt_state::PaymentAttemptState;
pub use error::PaymentError;
pub use intent::{
    PaymentIntent, PaymentIntentDraft, PaymentIntentError, PaymentIntentIdentity, RequestBodyHash,
    PAYMENT_INTENT_HASH_DOMAIN,
};
pub use proof::{build_payment_signature, SecretBytes, SvmTransferIntent, SvmTransferSigner};
pub use wire::{
    base58_decode, parse_atomic_amount, parse_payment_required, parse_payment_response,
    select_requirement, validate_solana_address, PaymentRequired, RequirementFilter,
    SelectedPayment, SettlementEvidence, SolanaNetwork, CAIP2_SOLANA_DEVNET, CAIP2_SOLANA_MAINNET,
    CHALLENGE_HASH_DOMAIN, HEADER_PAYMENT_REQUIRED, HEADER_PAYMENT_RESPONSE,
    HEADER_PAYMENT_SIGNATURE, MAX_ACCEPTS_ENTRIES, MAX_HEADER_BYTES, MAX_MEMO_BYTES,
    MAX_SVM_TRANSACTION_BYTES, MAX_TIMEOUT_SECONDS, SCHEME_EXACT, X402_VERSION,
};
