/**
 * `@ferrogate/policy` — pure policy decision boundaries.
 *
 * Faithful clean-room port of the Rust crate `ferrogate-policy`: rule-based
 * allow/deny, multi-level quota merge, workflow-graph execution budgets, and the
 * (deprioritized) x402 Solana spend policy. Every function is pure — storage
 * lookups are injected as closures; there is no I/O.
 *
 * Modules:
 *  - `policy-engine`   — `BasicPolicyEngine`, `PolicyRule`, `PolicySubject`, `PolicyDecision`.
 *  - `quota`           — `resolveEffectiveQuota`, `EffectiveQuota`, `QuotaScopeSelector`.
 *  - `workflow-budget` — envelope composition, budget pre-flight, node dispatch.
 *  - `workflow-graph`  — `enforce_ai_workflow_policy`'s thirteen refusals: node
 *                        pinning, edge transitions, iteration/model-call limits,
 *                        the workflow timeout and the token budgets. A DIFFERENT
 *                        control from `workflow-budget`: the graph gate decides
 *                        whether a step is a legal move, the budget decides
 *                        whether the run can afford it.
 *  - `stored-types`    — storage records the layer reads, re-exported from
 *                        `@ferrogate/storage` (the authoritative home, as in Rust).
 *  - `x402/*`          — x402 spend policy + payment-authorization decision. The
 *                        wire contract it binds against (`SelectedPayment`,
 *                        `PaymentIntent`, `SolanaNetwork`, address validation,
 *                        intent hashing) is NOT redefined here: `x402/wire.ts`
 *                        re-exports it from `@ferrogate/payments`, the same edge
 *                        `ferrogate-policy`'s Cargo.toml declares on
 *                        `ferrogate-payments`.
 *  - `schemas`         — Zod wire schemas for the value types.
 */
export * from "./policy-engine.js";
export * from "./quota.js";
export * from "./workflow-budget.js";
export * from "./workflow-graph.js";
export * from "./stored-types.js";
export * from "./schemas.js";

// x402 (deprioritized per inventory §2.1) — spend policy config + decision.
export * from "./x402/config.js";
export * from "./x402/decision.js";
// The wire contract is @ferrogate/payments' (see `x402/wire.ts`); re-exported
// here so a policy caller has one import, never a second definition.
export {
  X402_VERSION,
  SCHEME_EXACT,
  MAX_TIMEOUT_SECONDS,
  CAIP2_SOLANA_MAINNET,
  CAIP2_SOLANA_DEVNET,
  PAYMENT_INTENT_HASH_DOMAIN,
  networkFromCaip2,
  networkCaip2,
  base58Decode,
  isValidSolanaAddress,
  challengeHashHex,
  requestBodyHashHex,
  PaymentIntent,
  PaymentIntentError,
  RequestBodyHash,
  type SolanaNetwork,
  type SelectedPayment,
  type PaymentIntentIdentity,
  type PaymentIntentDraft,
  type PaymentIntentErrorKind,
} from "./x402/wire.js";
export { sha256, hexLower, Sha256Builder } from "./x402/sha256.js";
