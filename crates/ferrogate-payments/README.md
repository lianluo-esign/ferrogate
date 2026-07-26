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
this). A ~40-case negative corpus lives in `fixtures/negative/`, and
property tests feed arbitrary and base64-wrapped garbage through the whole
pipeline asserting typed rejection without panics.

### Spec provenance

Wire shapes were verified field-by-field against the upstream sources on
**2026-07-25** (fetched from `github.com/x402-foundation/x402`, `main`):

- `specs/x402-specification-v2.md` §5.1 `PaymentRequired`, §5.2
  `PaymentPayload`, §5.3 `SettlementResponse`
- `specs/transports-v2/http.md` — header names and directions
- `specs/schemes/exact/scheme_exact_svm.md` — `extra` fields and the
  base64 partially-signed versioned transaction in `payload.transaction`

### Frozen field set

`PaymentRequired` (`PAYMENT-REQUIRED`, server → client):

| Wire field | Spec | Rust | Validation |
| ---------- | ---- | ---- | ---------- |
| `x402Version` | required `number` | — | must be integer `2`, else `UnsupportedVersion` |
| `error` | optional `string` | `PaymentRequired::error` | passthrough |
| `resource.url` | required `string` | `resource_url` | non-empty, <= 2048 bytes |
| `resource.description` / `.mimeType` | optional `string` | `resource_description` / `resource_mime_type` | passthrough |
| `accepts[]` | required `array` | `accepts` | 1..=16 objects, no duplicate `(scheme, network, asset, payTo)` |
| `extensions` | optional `object` | `extensions` | must be an object; echoed verbatim into `PaymentPayload` |

Selected SVM `exact` requirement (`SelectedPayment`):

| Wire field | Rust | Type / encoding | Validation |
| ---------- | ---- | --------------- | ---------- |
| `scheme` | — | `"exact"` | anything else is skipped / `UnsupportedScheme` |
| `network` | `network` | CAIP-2 `string` | mainnet or devnet only, exact match |
| `asset` | `mint` | base58 `string` | decodes to exactly 32 bytes |
| `amount` | `atomic_amount` | decimal `string` → `u64` | ASCII digits, no leading zero, non-zero, fits `u64` — **never coerced** |
| `payTo` | `recipient` | base58 `string` | decodes to exactly 32 bytes |
| `maxTimeoutSeconds` | `max_timeout_seconds` | `number` → `u64` | `1..=86400` |
| `extra.feePayer` | `fee_payer` | base58 `string` | required, 32 bytes |
| `extra.memo` | `memo` | optional `string` | <= 256 bytes |
| `extra.recentBlockhash` | `recent_blockhash` | optional base58 `string` | 32 bytes when present |
| `extra.lastValidBlockHeight` | `last_valid_block_height` | optional decimal `string` → `u64` | non-zero; **ignored when `recentBlockhash` is absent**, per spec |
| — | `challenge_hash` | `[u8; 32]` | FerroGate-local, see below |
| — | `raw_requirement` | `serde_json::Value` | echoed verbatim into `accepted` |

`SettlementResponse` (`PAYMENT-RESPONSE`, server → client): `success`
(required `bool`), `transaction` (required `string`; base58 64-byte
signature when `success`, empty on failure), `network` (required CAIP-2,
pinned to the network actually proposed), `payer` / `errorReason`
(optional `string`), `amount` (optional decimal `string` → `u64`, parsed
with the same never-coerce rule).

### Challenge hash (`CHALLENGE_HASH_DOMAIN = "ferrogate-x402-challenge-v1"`)

Not part of the wire format. SHA-256 over the **payment-terms** tuple, each
element NUL-terminated:

```text
domain ‖ "exact" ‖ caip2 ‖ mint ‖ payTo ‖ feePayer ‖ amount ‖ timeout ‖ resourceUrl
  ‖ (0x01 ‖ memo | 0x00)   ‖ 0x00
```

- `feePayer` and `memo` are **included**: the memo is the seller's invoice
  reference, so two distinct invoices for the same resource/amount/recipient
  must not collide on one idempotency key, and a different sponsor is a
  different transaction. Memo presence is encoded separately from memo
  content so an absent memo and an empty memo differ.
- `recentBlockhash`, `lastValidBlockHeight` and `extensions` are
  **excluded**: a server may refresh them between retries of the same
  logical challenge, and including them would make the key unstable.
- The digest is pinned by a golden test that was cross-checked against an
  independent implementation of the rule above. Any change to the tuple MUST
  bump `CHALLENGE_HASH_DOMAIN`.

### How the downstream slices consume this

These are already implemented against this contract (#351 in
`ferrogate-policy::x402_spend`, #352 in `ferrogate-storage`, #353 in
`agent-worker::x402_client`, #356 in `ferrogate-billing::x402_inbound`), so
changes here must stay additive:

- **#351**'s immutable `PaymentIntent` now lives HERE (`src/intent.rs`), built
  from `SelectedPayment` (`network`, `mint`, `atomic_amount`, `recipient`,
  `resource_url`, `max_timeout_seconds`, `challenge_hash`) plus the
  egress-request binding (HTTP method, `RequestBodyHash`,
  tenant/project/workspace/key/run/worker/request identity). Sealed: private
  fields, validating constructor, `#[serde(try_from = …)]` deserialization, and
  a deterministic `intent_hash_hex()`. `ferrogate-policy` consumes it as the
  binding target of a spend decision, which is what makes "a challenge cannot
  redirect payment to another URL, **body**, recipient, or network"
  enforceable. Every money field is an integer `u64` — there is no `f64`
  anywhere in this crate.
- **#352** persists `challenge_hash` as the attempt/idempotency key and
  `SettlementEvidence` (`success`, `transaction_signature`, `payer`,
  `settled_amount`, `error_reason`) as the settlement leg. Note the
  scheme tolerates overpayment (§1.4: a matching transfer MAY exceed the
  required amount), so reconciliation must compare
  `settled_amount >= atomic_amount`, not `==`.
- **#353** implements `SvmTransferSigner` on the tenant side and feeds
  `SvmTransferIntent` — which carries the `recentBlockhash` /
  `lastValidBlockHeight` hints so the signer never has to re-parse the raw
  challenge — then ships the `build_payment_signature` output as the
  `PAYMENT-SIGNATURE` header. The gateway never sees key material. Because
  it delegates to `build_payment_signature` rather than serializing its own
  `PaymentPayload`, it inherits the `extensions` echo automatically.

## `solana-pay-kit` qualification (the #350 deliverable)

**VERDICT: not usable yet** (recorded 2026-07-23, independently re-verified
2026-07-25 against the workspace MSRV Rust 1.88).

Qualified candidate: `solana-pay-kit 0.2.0` — the crates.io `default_version`
and latest of only 2 published versions (0.1.0 on 2026-06-29, 0.2.0 on
2026-07-01), MIT license, repository
`github.com/solana-foundation/pay-kit`, no declared `rust-version`, 42
total downloads at the time of qualification. Declared features are
`default = ["mpp", "x402"]` plus `axum`, `client`, `confidential`, `fetch`,
`gcp_kms`, `litesvm-tests`, `otel`, `server`, `testkit`, `worker`; `x402`
itself is an empty feature, so the minimal viable line for our scope is:

```toml
solana-pay-kit = { version = "=0.2.0", default-features = false, features = ["x402"] }
```

(no `axum`/`server`, no `mpp`, no `confidential`, no `otel`, no `testkit`,
no `client` — the `client` feature only adds `reqwest`, and HTTP stays
outside this crate.)

### Evidence

1. **MSRV failure (hard blocker).** `cargo +1.88.0 check` on a scratch
   package with the dependency above fails. Re-run 2026-07-25 on aarch64
   (`Locking 555 packages`, 556 lock entries):

   ```text
   error: rustc 1.88.0 is not supported by the following packages:
     solana-address@2.7.0 requires rustc 1.89.0
     solana-address-lookup-table-interface@3.1.0 requires rustc 1.89.0
     solana-hash@4.6.0 requires rustc 1.89.0
     solana-instruction-error@2.5.0 requires rustc 1.89.0
     solana-message@4.4.0 requires rustc 1.89.0
     solana-pubkey@4.2.0 requires rustc 1.89.0
     solana-signature@3.4.1 requires rustc 1.89.0
     solana-signer@3.0.1 requires rustc 1.89.0
     solana-system-interface@3.2.0 requires rustc 1.89.0
     solana-transaction@4.1.5 requires rustc 1.89.0
     solana-transaction-error@3.4.0 requires rustc 1.89.0
     solana-vote-interface@6.0.3 requires rustc 1.89.0
     wincode@0.5.5 requires rustc 1.89.0
     wincode@0.6.0 requires rustc 1.89.0
     wincode-derive@0.4.6 requires rustc 1.89.0
     wincode-derive@0.5.0 requires rustc 1.89.0
   Either upgrade rustc or select compatible dependency versions with
   `cargo update <name>@<current-ver> --precise <compatible-ver>`
   ```

   (`cargo-platform@0.3.3` in the same tree requires rustc 1.91.) The exact
   patch versions drift upward over time — the 2026-07-23 run saw
   `solana-address@2.6.1` / `solana-hash@4.5.0` — but the ≥1.89 floor is
   structural, not a transient resolution accident.

2. **No compatible pin exists.** Cargo 1.88's MSRV-aware resolver already
   fell back to incompatible versions (it printed `requires Rust 1.89.0`
   during locking), and explicit down-pinning fails (verbatim, 2026-07-25):

   ```text
   $ cargo +1.88.0 update solana-address@2.7.0 --precise 2.0.0
   error: failed to select a version for the requirement `solana-address = "^2.2.0"`
   candidate versions found which didn't match: 2.0.0
   required by package `solana-account-info v3.1.1`
       ... which satisfies dependency `solana-account-info = "^3"` of `solana-pay-kit v0.2.0`

   $ cargo +1.88.0 update solana-pubkey@4.2.0 --precise 4.0.0
   error: failed to select a version for the requirement `solana-pubkey = "^4.2.0"`
   candidate versions found which didn't match: 4.0.0
   required by package `solana-client v4.1.2`
       ... which satisfies dependency `solana-client = "^4"` of `solana-pay-kit v0.2.0`
   ```

   So "usable pinned" is ruled out, not just "usable as-is".

   For completeness: dependency *resolution* itself succeeds on both
   x86_64 and aarch64 — the blocker is the target-independent
   `rust-version` requirement, not a platform gap.

3. **Unacceptable dependency drag.** Even the minimal feature set locks
   **555 packages**, because the crate's own crates.io manifest lists the
   full Solana RPC client stack as *non-optional*: `solana-client ^4`,
   `solana-rpc-client ^4`, `solana-keychain ^1.4`,
   `solana-transaction-status-client-types ^4`, plus `tokio ^1` — 38
   non-optional normal dependencies in total. Only `axum`, `reqwest`,
   `opentelemetry*`, `spl-token-2022` and the confidential-transfer crates
   are feature-gated. For a client-side wire codec this is a large
   SBOM/audit surface with no benefit to our scope.

4. **Maturity signal.** 2 published versions over 3 days and 42 total
   downloads at qualification time. Even with the MSRV blocker removed,
   adopting it for a money path warrants a re-check of release cadence and
   API stability rather than an immediate pin.

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

`cargo tree -p ferrogate-payments -e normal` (re-verified 2026-07-25 on
aarch64 — no axum/tower/reqwest/opentelemetry/RPC client anywhere):

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
    │   └── libc v0.2.186
    └── digest v0.10.7
        ├── block-buffer v0.10.4
        │   └── generic-array v0.14.7
        │       └── typenum v1.20.0
        └── crypto-common v0.1.7
            ├── generic-array v0.14.7 (*)
            └── typenum v1.20.0
```

### `cargo deny check` (2026-07-25, cargo-deny 0.20.2, aarch64)

Run on the whole workspace (cargo-deny always resolves the full workspace
graph; there is no per-crate mode):

```text
advisories FAILED, bans ok, licenses ok, sources ok
```

- `licenses ok` / `sources ok` / `bans ok` — this crate introduces no new
  license, no non-crates.io source, and no new duplicate version.
- `advisories FAILED` is **pre-existing and unrelated to this crate**. The
  three findings are:

  | Advisory | Crate | Reached via |
  | -------- | ----- | ----------- |
  | RUSTSEC-2026-0190 (unsound) | `anyhow 1.0.102` | workspace-wide, predates this crate |
  | RUSTSEC-2026-0194 (vuln) | `quick-xml 0.37.5` | `ferrogate-auth` → `ferrogate-cli` |
  | RUSTSEC-2026-0195 (vuln) | `quick-xml 0.37.5` | `ferrogate-auth` → `ferrogate-cli` |

  None of `anyhow` or `quick-xml` appears in `cargo tree -p
  ferrogate-payments` (see the tree above: `base64`, `serde`, `serde_json`,
  `sha2` only), and this crate added **zero** packages to the resolved
  workspace set, so it cannot have introduced or worsened any of them.
  Per the #350 acceptance ("unresolved security or source-availability risk
  blocks runtime wiring"), these are tracked as workspace-level supply-chain
  debt under `.cargo/audit.toml` + `.cargo/audit-exceptions.json`
  (currently `{"exceptions": []}`, validated by
  `scripts/check-audit-exceptions.py`); they do not gate this crate, which
  is not wired into any runtime path.

- **cargo audit status**: `cargo-audit` is not installed in the current
  build environment (`cargo audit` → `no such command`), so no `cargo audit`
  run is claimed here. The 2026-07-23 record noted `cargo-audit 0.21.1`
  failing to load the RustSec advisory DB
  (`RUSTSEC-2025-0149.md: unsupported CVSS version: 4.0`). `cargo deny
  check advisories` above uses the same RustSec database and is the
  authoritative result for this crate.

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
- `extra.recentBlockhash` must be a base58 32-byte value when present, and
  `extra.lastValidBlockHeight` a non-zero decimal string; a malformed
  blockhash fails the payment rather than silently falling back to a
  self-fetched one.
- Server `extensions` are echoed verbatim and never fabricated: a challenge
  without `extensions` produces a `PaymentPayload` without the key.
- `SecretBytes` signer material is redacted in both `Debug` and serde
  output and is best-effort scrubbed on drop.
- Property tests drive arbitrary bytes and arbitrary base64 payloads
  through parse → select → settle with no panics.
