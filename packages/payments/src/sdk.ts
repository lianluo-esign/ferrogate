/**
 * `solana-pay-kit` qualification record (issue #350). Faithful port of the Rust
 * `sdk` module (which is feature-gated `sdk-solana-pay-kit`).
 *
 * The Rust crate hand-rolls its wire parsing because `solana-pay-kit 0.2.0` was
 * qualified NOT USABLE on the workspace MSRV (Rust 1.88). In JS there is no MSRV
 * constraint, so this record is carried purely as machine-readable provenance —
 * the reason the wire contract is hand-rolled here too, per the inventory (x402
 * work is deprioritized and `@solana/web3.js` remains out of scope).
 */

import { PaymentError } from "./error.js";

/** Qualification outcome for an external payment SDK. */
export const SdkVerdict = {
  UsableAsIs: "usable_as_is",
  UsablePinned: "usable_pinned",
  NotUsableYet: "not_usable_yet",
} as const;
export type SdkVerdict = (typeof SdkVerdict)[keyof typeof SdkVerdict];

/** SDK crate name under qualification. */
export const SDK_NAME = "solana-pay-kit";
/** Exact version qualified. */
export const SDK_VERSION = "0.2.0";
/** Verdict for {@link SDK_NAME} {@link SDK_VERSION} against workspace MSRV 1.88. */
export const SDK_VERDICT: SdkVerdict = SdkVerdict.NotUsableYet;
/** One-line evidence summary (full record in the Rust crate README). */
export const SDK_EVIDENCE =
  'solana-pay-kit 0.2.0 (default-features=false, features=["x402"]) ' +
  "fails `cargo +1.88.0 check`: its mandatory transitive tree requires " +
  "rustc >= 1.89 (solana-address, solana-pubkey, solana-message, wincode, " +
  "...; cargo-platform requires 1.91) with no 1.88-compatible pin " +
  "(solana-account-info needs solana-address ^2.2, solana-client needs " +
  "solana-pubkey ^4.2), and the minimal feature set still locks ~555 " +
  "packages including the full Solana RPC client stack (solana-client, " +
  "solana-rpc-client, solana-keychain and tokio are non-optional). " +
  "Re-verified 2026-07-25.";

/** The error any SDK-backed code path returns in this build. */
export function sdkUnavailable(): PaymentError {
  return PaymentError.sdkIncompatible(
    "solana-pay-kit 0.2.0 requires rustc >= 1.89; workspace MSRV is 1.88 " +
      "(see ferrogate-payments README, issue #350)",
  );
}
