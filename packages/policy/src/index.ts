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
 *  - `stored-types`    — storage records the layer reads, re-exported from
 *                        `@ferrogate/storage` (the authoritative home, as in Rust).
 *  - `x402/*`          — x402 spend policy + payment-authorization decision
 *                        (PORT-TODO: `@ferrogate/payments` wire contract, deprioritized).
 *  - `schemas`         — Zod wire schemas for the value types.
 */
export * from "./policy-engine.js";
export * from "./quota.js";
export * from "./workflow-budget.js";
export * from "./stored-types.js";
export * from "./schemas.js";

// x402 (deprioritized per inventory §2.1) — spend policy config + decision.
export * from "./x402/config.js";
export * from "./x402/decision.js";
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
  type SolanaNetwork,
  type SelectedPayment,
  type PaymentIntentIdentity,
} from "./x402/wire.js";
export { sha256, hexLower, Sha256Builder } from "./x402/sha256.js";
