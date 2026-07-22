# ferrogate-payments

FerroGate's frozen x402 V2 / Solana SVM payment wire contract (issue #350,
parent epic #349 — Solana x402 agent payments via pay.sh).

Scope: **x402 version 2, HTTP transport, Solana SVM networks, `exact`
scheme, client role** — nothing else. HTTP plumbing, payment policy and
budgets, wallet key loading, and RPC/mainnet calls all live outside this
crate. Signing is injected via the `SvmTransferSigner` trait; this crate
never loads keys, never mutates a wallet, and performs no network I/O.

## Adapter surface

1. `parse_payment_required` — decode + validate the `PAYMENT-REQUIRED`
   challenge header (base64 → JSON → strict field validation).
2. `select_requirement` — pick exactly one supported requirement
   (scheme `exact`, recognised CAIP-2 Solana network, valid base58
   mint/recipient/feePayer, strict atomic amount, safe timeout) into a
   structured `SelectedPayment` with a deterministic SHA-256 challenge hash.
3. `build_payment_signature` — produce the `PAYMENT-SIGNATURE` proof header;
   all transaction construction/signing happens behind the injected signer.
4. `parse_payment_response` — decode `PAYMENT-RESPONSE` settlement evidence,
   pinned to the expected network.

Recognised networks (local recognition only, no RPC):

| Network | CAIP-2 |
| ------- | ------ |
| Solana mainnet-beta | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` |
| Solana devnet | `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` |

Golden fixtures for all three wire artifacts live in `fixtures/` (each
`.header` file is the exact base64 of its `.json` twin; a test enforces
this). A ~35-case negative corpus lives in `fixtures/negative/`, and
property tests feed arbitrary and base64-wrapped garbage through the whole
pipeline asserting typed rejection without panics. Wire shapes follow the
upstream spec: `coinbase/x402` `specs/x402-specification-v2.md`,
`specs/transports-v2/http.md`, `specs/schemes/exact/scheme_exact_svm.md`.

## `solana-pay-kit` qualification (the #350 deliverable)

**VERDICT: not usable yet** (as of 2026-07-23, workspace MSRV Rust 1.88).

Qualified candidate: `solana-pay-kit 0.2.0` (crates.io, published
2026-07-01 by the Solana Foundation pay-kit repo, MIT license, no declared
`rust-version`), with the minimal feature set for our scope:

```toml
solana-pay-kit = { version = "=0.2.0", default-features = false, features = ["x402"] }
```

(no `axum`/`server`, no `mpp`, no `confidential`, no `otel`, no `testkit`,
no `client` — the `client` feature only adds `reqwest`, and HTTP stays
outside this crate.)

### Evidence

1. **MSRV failure (hard blocker).** `cargo +1.88.0 check` on a scratch
   package with the dependency above fails:

   ```text
   error: rustc 1.88.0 is not supported by the following packages:
     solana-address@2.6.1 requires rustc 1.89.0
     solana-address-lookup-table-interface@3.1.0 requires rustc 1.89.0
     solana-hash@4.5.0 requires rustc 1.89.0
     solana-instruction-error@2.4.0 requires rustc 1.89.0
     solana-message@4.4.0 requires rustc 1.89.0
     solana-pubkey@4.2.0 requires rustc 1.89.0
     solana-signature@3.4.1 requires rustc 1.89.0
     solana-signer@3.0.1 requires rustc 1.89.0
     solana-system-interface@3.2.0 requires rustc 1.89.0
     solana-transaction@4.1.5 requires rustc 1.89.0
     solana-transaction-error@3.3.1 requires rustc 1.89.0
     solana-vote-interface@6.0.3 requires rustc 1.89.0
     wincode@0.5.5 requires rustc 1.89.0
     wincode-derive@0.4.6 requires rustc 1.89.0
   ```

   (`cargo-platform@0.3.3` in the same tree requires rustc 1.91.)

2. **No compatible pin exists.** Cargo 1.88's MSRV-aware resolver already
   fell back to incompatible versions (it printed `requires Rust 1.89.0`
   warnings during `cargo generate-lockfile`), and explicit down-pinning
   fails:

   ```text
   cargo update solana-address@2.6.1 --precise 2.0.0
     error: failed to select a version for the requirement `solana-address = "^2.2.0"`
     required by package `solana-account-info v3.1.1` <- `solana-pay-kit v0.2.0`
   cargo update solana-pubkey@4.2.0 --precise 4.0.0
     error: failed to select a version for the requirement `solana-pubkey = "^4.2.0"`
     required by package `solana-client v4.1.2` <- `solana-pay-kit v0.2.0`
   ```

   So "usable pinned" is ruled out, not just "usable as-is".

   For completeness: dependency *resolution* itself succeeds on both
   x86_64 and aarch64 (`cargo +1.88.0 metadata --locked
   --filter-platform aarch64-unknown-linux-gnu` resolves) — the blocker is
   the target-independent `rust-version` requirement, not a platform gap.

3. **Unacceptable dependency drag.** Even the minimal feature set locks
   **553 packages**, because the full Solana RPC client stack
   (`solana-client ^4`, `solana-rpc-client ^4`, `solana-keychain ^1.4`,
   `solana-transaction-status-client-types ^4`, ...) is a *non-optional*
   dependency of the crate. For a client-side wire codec this is a large
   SBOM/audit surface with no benefit to our scope.

Consequences shipped here:

- Wire parsing is hand-rolled against the upstream spec and frozen by the
  golden fixtures + negative corpus.
- The non-default feature `sdk-solana-pay-kit` gates `src/sdk.rs`, which
  carries the machine-readable verdict (`SDK_VERDICT = NotUsableYet`) and
  the `PaymentError::SdkIncompatible` constructor. The dependency itself is
  intentionally **not** declared (a declared optional dep would poison the
  workspace `Cargo.lock` with the 553-package tree and break the
  `--all-features` MSRV gate); the exact dependency line to enable later is
  recorded in `Cargo.toml` next to the feature.

### Re-qualification checklist (upgrade policy)

Re-run qualification when ANY of: the workspace MSRV moves to >= 1.89; a
new `solana-pay-kit` release appears; or upstream splits the wire/proof
types from the RPC client. Steps:

1. Scratch package with the pinned dependency line above;
   `cargo +<MSRV> check` must pass.
2. `cargo tree` must not contain `axum`, `tower`, `reqwest`,
   `opentelemetry*`, or an RPC client unless features explicitly ask for
   them; record the locked package count.
3. Run this crate's golden fixtures through the SDK's parser and compare
   verdicts with `parse_payment_required` / `parse_payment_response` —
   divergence on any fixture or corpus entry is a blocking finding.
4. Only then declare the optional dependency under `sdk-solana-pay-kit`,
   pinned `=x.y.z`, and update `src/sdk.rs` + this README.

## Pinning, MSRV, license, SBOM

- **MSRV**: workspace-pinned Rust 1.88 (`rust-version.workspace = true`).
- **License**: crate is Apache-2.0 (workspace). `solana-pay-kit` is MIT —
  license-compatible if adopted later.
- **Dependencies / SBOM impact**: only `base64`, `serde`, `serde_json`,
  `sha2` — all already resolved in the workspace, so adding this crate
  introduced **zero** new external packages (the workspace `Cargo.lock`
  delta is the 11-line `ferrogate-payments` member entry only).

`cargo +1.88.0 tree -p ferrogate-payments -e normal` (recorded 2026-07-23 —
no axum/server/RPC anywhere):

```text
ferrogate-payments v2026.7.9
├── base64 v0.22.1
├── serde v1.0.228
│   ├── serde_core v1.0.228
│   └── serde_derive v1.0.228 (proc-macro)
│       ├── proc-macro2 v1.0.106
│       │   └── unicode-ident v1.0.24
│       ├── quote v1.0.45
│       │   └── proc-macro2 v1.0.106 (*)
│       └── syn v2.0.117
│           ├── proc-macro2 v1.0.106 (*)
│           ├── quote v1.0.45 (*)
│           └── unicode-ident v1.0.24
├── serde_json v1.0.149
│   ├── itoa v1.0.18
│   ├── memchr v2.8.0
│   ├── serde_core v1.0.228
│   └── zmij v1.0.21
└── sha2 v0.10.9
    ├── cfg-if v1.0.4
    ├── cpufeatures v0.2.17
    └── digest v0.10.7
        ├── block-buffer v0.10.4
        │   └── generic-array v0.14.7
        │       └── typenum v1.20.0
        └── crypto-common v0.1.7
            ├── generic-array v0.14.7 (*)
            └── typenum v1.20.0
```

- **cargo audit status** (2026-07-23): `cargo-audit 0.21.1` is installed
  but currently fails to load the RustSec advisory DB
  (`RUSTSEC-2025-0149.md: unsupported CVSS version: 4.0` — the installed
  binary predates CVSS 4.0 support). Independent of that tooling gap, this
  crate added no packages to the resolved workspace set, so it cannot have
  introduced a new advisory. The existing `.cargo/audit.toml` +
  `audit-exceptions.json` governance applies unchanged.

## Safety properties (tested)

- Invalid atomic amounts (empty, signed, decimal, exponent, leading-zero,
  overflow, zero, non-ASCII digits) are hard errors — never coerced to 0.
- Headers over 16 KiB are rejected before decoding; `accepts` is capped at
  16 entries; memos at 256 bytes; signer transactions at the 1232-byte
  Solana packet limit.
- Duplicate/conflicting `accepts` entries (same scheme/network/asset/payTo)
  are rejected.
- `maxTimeoutSeconds` must be an integer in `1..=86400` (zero = already
  expired, larger = unsafe).
- `SecretBytes` signer material is redacted in both `Debug` and serde
  output and is best-effort scrubbed on drop.
- Property tests drive arbitrary bytes and arbitrary base64 payloads
  through parse → select → settle with no panics.
