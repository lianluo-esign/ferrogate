/**
 * `@ferrogate/payments` — x402 V2 / Solana SVM payment wire contract.
 *
 * Faithful clean-room port of the Rust crate `ferrogate-payments` (issues
 * #350/#351/#352): a narrow, protocol-neutral CLIENT-side boundary for agent
 * payments — x402 version 2, HTTP transport, Solana SVM networks, `exact`
 * scheme. Everything else (HTTP plumbing, payment policy/budgets, wallet key
 * loading, RPC submission) deliberately lives OUTSIDE this package.
 *
 * The adapter surface is four steps:
 *  1. {@link parsePaymentRequired} — decode + validate a `PAYMENT-REQUIRED` challenge.
 *  2. {@link selectRequirement}   — pick one supported requirement into a
 *     {@link SelectedPayment} with a deterministic challenge hash.
 *  3. {@link buildPaymentSignature} — build the `PAYMENT-SIGNATURE` proof, with
 *     all signing behind the injected {@link SvmTransferSigner}.
 *  4. {@link parsePaymentResponse} — decode settlement evidence.
 *
 * Plus the durable {@link PaymentAttemptState} alphabet (#352) and the immutable
 * {@link PaymentIntent} contract (#351). This package performs no network I/O,
 * opens no wallet, and loads no keys. Money is integer-only (`bigint`), never a
 * float.
 *
 * PORT-NOTE(inventory §3.3): x402/Solana work is deprioritized per project
 * directive. This ports the frozen wire contract + pure logic faithfully;
 * live transaction construction/signing stays behind {@link SvmTransferSigner}
 * (a `@solana/web3.js`/WebCrypto implementation is out of scope here).
 */

export { PaymentError, isPaymentError } from "./error.js";
export type { PaymentErrorKind, PaymentErrorData } from "./error.js";

export {
  PAYMENT_ATTEMPT_STATES,
  parsePaymentAttemptState,
  isTerminal,
  isPreSubmission,
  isReconcilable,
  isInitial,
  retainsHoldWhenUnresolved,
} from "./attempt_state.js";
export type { PaymentAttemptState } from "./attempt_state.js";

export { encodeBase64Std, decodeBase64Std } from "./base64.js";
export { sha256, hexLower, Sha256Builder } from "./hash.js";

export {
  X402_VERSION,
  SCHEME_EXACT,
  HEADER_PAYMENT_REQUIRED,
  HEADER_PAYMENT_SIGNATURE,
  HEADER_PAYMENT_RESPONSE,
  MAX_HEADER_BYTES,
  MAX_ACCEPTS_ENTRIES,
  MAX_TIMEOUT_SECONDS,
  MAX_MEMO_BYTES,
  MAX_SVM_TRANSACTION_BYTES,
  CHALLENGE_HASH_DOMAIN,
  CAIP2_SOLANA_MAINNET,
  CAIP2_SOLANA_DEVNET,
  SolanaNetwork,
  solanaNetworkFromCaip2,
  caip2ForNetwork,
  challengeHashHex,
  parsePaymentRequired,
  parseAtomicAmount,
  base58Decode,
  validateSolanaAddress,
  selectRequirement,
  parsePaymentResponse,
  encodeHeaderBytes,
} from "./wire.js";
export type {
  PaymentRequired,
  SelectedPayment,
  RequirementFilter,
  SettlementEvidence,
} from "./wire.js";

export {
  SecretBytes,
  svmTransferIntentFromSelected,
  buildPaymentSignature,
} from "./proof.js";
export type { SvmTransferIntent, SvmTransferSigner } from "./proof.js";

export {
  PAYMENT_INTENT_HASH_DOMAIN,
  PaymentIntent,
  PaymentIntentError,
  RequestBodyHash,
} from "./intent.js";
export type {
  PaymentIntentDraft,
  PaymentIntentIdentity,
  PaymentIntentWire,
  PaymentIntentErrorKind,
} from "./intent.js";

export {
  SdkVerdict,
  SDK_NAME,
  SDK_VERSION,
  SDK_VERDICT,
  SDK_EVIDENCE,
  sdkUnavailable,
} from "./sdk.js";
