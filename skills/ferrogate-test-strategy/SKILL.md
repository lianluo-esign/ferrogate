---
name: ferrogate-test-strategy
description: Use when working in the FerroGate repo and deciding how to test a change — which test layer a change needs, adding coverage for a feature or bugfix, whether the harness is sufficient, or when a test run surfaces a bug or new feature that needs tracking. For running the harness CLI itself, use the ferrogate-test skill.
---

# FerroGate Test Strategy

The guiding direction for FerroGate's layered test system: which layer a change
needs, how findings feed the issue queue, and how the tooling must grow to keep
up. The binding source of truth is `AGENTS.md` → `## Testing Architecture` and
`docs/testing/testing-architecture.md`; this skill is the on-the-spot pointer,
kept thin so it does not drift from those. To operate the E2E harness CLI, use
the `ferrogate-test` skill.

## Pick the layer for the change

"Unit tests pass" never proves a cross-cutting or runtime-wiring change.

- Pure logic → Static gate + Unit (+ Property if it is a state machine/invariant).
- Unit test implementations live in dedicated sibling `*_test.rs` files (or
  `crates/*/tests/*.rs`), never inline in business-logic files. A production
  module may keep only the minimal `cfg(test)` path declaration needed for
  private-item access.
- Wiring inside a crate → add Crate integration (`crates/*/tests/*.rs`).
- Provider / guardrail / policy scope / quota surface → add Contract/compliance:
  prove what it **writes** is what the runtime **reads**, and that it emits the
  telemetry/audit evidence it claims. A 200 with the runtime ignoring the value
  is a failure, not a pass (the #188 asset-quota-scope failure mode).
- Producer→consumer handoff (billing, evidence, exports) → add Cross-component
  chain (`ferrogate-test gateway-billing-chain` / `guardrail-supabase`).
- Persistence / schema / migration → add Durability (`ferrogate-test *-restart`).
- Any feature → the E2E harness (`ferrogate-test ci`) must close the loop.
- Hot-path performance → run the Performance layer, record the number; never a
  silent PR gate.

Property tests (`proptest`) belong on state machines/invariants (routing
fallback, quota reserve/settle/rollback, streaming stage transitions,
ack/settlement ordering), not ordinary branch logic. Streaming and concurrency
are correctness surfaces — add a focused async test at the lowest layer that can
reproduce the race instead of leaving it to a slow E2E run.

## Feed findings back to the issue queue

A bug or missing capability a test surfaces, and that is not fixed in the same
change, becomes a house-style GitHub issue before the change lands — never a
silent `#[ignore]`, skipped scenario, or inline TODO.

- Real bug, not fixed now → file a bug issue and add a failing regression test
  at the lowest layer that reproduces it; the fix makes it pass.
- Flaky test → confirm against `main`, open or link a tracking issue, record it
  in the affected suite. No blind retries that hide a real race.
- New feature/capability idea → file it and prioritize it in the queue; do not
  scope-creep it into the current change.
- House style: `[area][priority]` title; `Problem` → `Scope` → `Acceptance`
  (checkboxes) → `Non-goals` body; reuse existing labels; link the issue from
  the failing suite and from the commit that acts on it.

## The harness must keep up with the layers

The methodology is fixed; the tooling is not yet complete. `ferrogate-test` does
not yet support every layer above — treat it as a living harness that must be
iterated to satisfy the test system, not a fixed set of scenarios the methodology
bends to.

- If a change needs a layer the harness cannot yet express, grow the harness (new
  subcommand, shared assertion, fixture) and wire it into `ferrogate-test ci` —
  do not skip the layer or downgrade the claim to fit the current tool.
- A missing tool never silently shrinks coverage. A layer you cannot yet automate
  is still owed a manual proof at the affected surface plus a filed tooling issue.
- Current known shortfall: there is no reusable component-compliance assertion —
  provider/guardrail/policy-scope/quota surfaces have only point scenarios, not a
  shared contract every instance is forced through. Tracked in #210. Until it
  lands, prove compliance by hand and do not present that layer as automated.

## Run the narrowest proof

- Local module gate (mirrors CI): `scripts/local-test-modules.sh <module>`
  (`quality`, `core-policy`, `control-plane`, `agentic-gateway`, `ai-proxy`,
  `cli-tooling`, `gateway-runtime`, `e2e-harness`, `supabase-storage`).
- Workspace units: `cargo +1.88.0 test --workspace --all-features`.
- Static: `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `python3 scripts/check-openapi.py`.
- E2E: the `ferrogate-test` harness (see the `ferrogate-test` skill).

Read the output. Do not claim production readiness from unit tests alone when
the change touches runtime wiring, live reload, TLS/ACME, provider streaming, or
billing settlement.

GitHub Actions are release-only (`release: published`) and never a per-commit
fallback. Missing local infrastructure means the proof remains explicitly
unverified; it does not justify adding a push/PR/manual cloud trigger.
