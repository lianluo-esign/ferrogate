/**
 * x402 / Solana SVM wire primitives the spend policy binds against.
 *
 * SINGLE SOURCE OF TRUTH — this module owns NONE of these types. It re-exports
 * the frozen wire contract from `@ferrogate/payments`, mirroring the Rust
 * dependency edge exactly:
 *
 * ```toml
 * # crates/ferrogate-policy/Cargo.toml
 * ferrogate-payments = { path = "../ferrogate-payments" }
 * ```
 * ```rust
 * // crates/ferrogate-policy/src/x402_spend.rs
 * use ferrogate_payments::{validate_solana_address, PaymentIntent, SelectedPayment, SolanaNetwork};
 * ```
 *
 * Rust has exactly ONE `PaymentIntent` and ONE `intent_hash_hex`; the policy
 * layer consumes them. Anything re-declared here would be a SECOND definition
 * of a security seal: `authorize_x402_payment` binds a decision to
 * `intent.intent_hash_hex()`, and if the policy's copy of that hash ever
 * diverged from the one `@ferrogate/payments` produces at proof-construction
 * time, the gateway would authorize one payment and sign another with both
 * suites still green. `test/x402.test.ts` pins the re-export by object identity
 * so a re-divergence fails rather than drifts.
 *
 * Only two thin ADAPTERS live here, both matching how the Rust policy layer
 * calls into the payments crate rather than adding behavior:
 *  - {@link isValidSolanaAddress} — the boolean form of the crate's throwing
 *    `validate_solana_address`, i.e. Rust's `validate_solana_address(..).is_err()`.
 *  - {@link requestBodyHashHex} — `RequestBodyHash::of(body).as_hex()`.
 *
 * Money stays integer-only (`bigint` for the u64 atomic amount), never a float.
 */
import { RequestBodyHash, validateSolanaAddress } from "@ferrogate/payments";

export {
  /** x402 protocol version this contract implements. */
  X402_VERSION,
  /** The `exact` payment scheme identifier. */
  SCHEME_EXACT,
  /** Safety cap on `maxTimeoutSeconds`. */
  MAX_TIMEOUT_SECONDS,
  /** CAIP-2 network identifier for Solana mainnet-beta. */
  CAIP2_SOLANA_MAINNET,
  /** CAIP-2 network identifier for Solana devnet. */
  CAIP2_SOLANA_DEVNET,
  /** Domain-separation tag for the payment-intent seal. */
  PAYMENT_INTENT_HASH_DOMAIN,
  /** Recognise a CAIP-2 network identifier (purely local; no RPC). */
  solanaNetworkFromCaip2 as networkFromCaip2,
  /** The CAIP-2 identifier for a network. */
  caip2ForNetwork as networkCaip2,
  /** Base58 decode (Bitcoin alphabet); `undefined` on any invalid character. */
  base58Decode,
  /** Lowercase hex of a {@link SelectedPayment}'s deterministic challenge hash. */
  challengeHashHex,
  /** The immutable payment-intent contract (issue #351), fully validated. */
  PaymentIntent,
  /** SHA-256 of an authorized request body, as a validated value object. */
  RequestBodyHash,
  /** Why a payment-intent draft is not a valid intent (full #351 taxonomy). */
  PaymentIntentError,
} from "@ferrogate/payments";

export type {
  SolanaNetwork,
  SelectedPayment,
  PaymentIntentIdentity,
  PaymentIntentDraft,
  PaymentIntentErrorKind,
} from "@ferrogate/payments";

/**
 * Is `value` a syntactically valid base58 Solana address (32 decoded bytes)?
 *
 * The crate exposes the throwing `validate_solana_address(field, value)`; the
 * Rust policy layer calls it as `validate_solana_address("mint", &m).is_err()`
 * inside `validate_x402_spend_policy`, where the field-level error is discarded
 * in favour of the policy's own `X402PolicyError`. This is that call shape.
 */
export function isValidSolanaAddress(value: string): boolean {
  try {
    validateSolanaAddress("address", value);
    return true;
  } catch {
    return false;
  }
}

/**
 * SHA-256 of an authorized request body as lowercase hex; an empty slice is the
 * canonical "no body". Mirrors Rust `RequestBodyHash::of(body).as_hex()`.
 */
export function requestBodyHashHex(body: Uint8Array): string {
  return RequestBodyHash.of(body).asHex();
}
