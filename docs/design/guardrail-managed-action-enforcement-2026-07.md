# #200 — Enforce Guardrails on MCP, Tool, and managed Agent actions

P1, part of the #193 enforcement-plane epic. Verified pickable (no docker/gVisor
— isolation is an explicit non-goal here; no external service — local
deterministic detectors exist; no design-partner dependency). The 2026-07-13
issue comment claiming completion in a `feature/issue-200` worktree is **false
for this repo** (no such branch/stash/worktree) — treat as un-started.

## Goal

Today, guardrails evaluate only **model content** (chat request/response, via
`match_guardrail` in `state_quota_and_policy.rs`). Managed **actions** (MCP
tool calls, Tool/CLI/filesystem/network/secret actions, managed Agent actions)
are governed only by the capability layer (#204) + the legacy approval
subsystem — they are **never** run through the guardrail engine. #200 extends
guardrail evaluation + enforcement to those actions, on both their **inputs**
(pre-execution) and **outputs** (post-execution), with fail-closed semantics.

## What already exists (REUSE — do not rebuild)

- **Guardrail engine**: `ferrogate-guardrails` — envelope/segments (`envelope.rs`),
  policy/detector/scope model (`policy.rs`), deterministic detectors
  (`deterministic.rs`); evaluation + evidence + audit in
  `state_quota_and_policy.rs` (`match_guardrail` :280, `record_guardrail_evaluation`
  :815, `evaluate_guardrail_check` :1171). Reference wiring: `gateway/chat.rs`.
- **Capability layer (#204)**: `CapabilityAction`, `CanonicalCapabilityTarget` /
  `BoundCapabilityTarget.fingerprint()`, `SimpleCapabilityAuthorizer`
  (`ApprovalRequired`), canonical MCP/fs/network/secret/CLI target builders
  (`ferrogate-runtime/src/{capability_boundary.rs,target_capability.rs}`),
  consumed at `gateway/external_actions.rs:129`.
- **Managed-action pipeline**: `external_actions.rs:96 authorize` →
  `authorize_managed_external_action`; worker execution + static redaction
  (`agent-worker/src/external_actions.rs`).
- **Approval subsystem**: `approval.rs` (`fingerprint_for` :407, CAS consume +
  fingerprint-mismatch fail-closed :305; MCP wiring `mcp_rpc.rs:275-349`).

## Remaining work (the actual #200 scope) → sliced

### Slice 1 — guardrails model: managed-action target + new action kinds (`ferrogate-guardrails`)
- Introduce a **managed-action guardrail target/selector** (the issue's "extend
  GuardrailTarget" — no `GuardrailTarget` type exists yet; introduce one).
  `PolicyScopeSelector` (`policy.rs:67`) currently scopes only
  tenant/org/project/workspace/key/model/provider. Add a selector dimension for
  managed actions: action class (mcp/tool/cli/filesystem/network/secret/rest),
  server/tool name, and argument-field paths.
- Extend `ActionKind` (`policy.rs:344`, currently Allow/Block/Redact/Record) with
  **`RequireApproval`** and **`Quarantine`** (+ `validate()` :394 + serde +
  enforcement mapping). `quarantine` currently appears nowhere.
- Self-contained + unit-testable in the guardrails crate. **This is the
  foundational slice; everything else builds on it.**

### Slice 2 — managed-action envelope + evaluation entrypoint (`ferrogate-cli`/`ferrogate-guardrails`)
- A managed-action **envelope builder** carrying the action's segments
  (mcp/tool/cli/fs/rest/secret/network) analogous to the model-content envelope
  (`ContentSource`/`ContentSegment` — extend or add a sibling segment type).
- A single **managed-action guardrail entrypoint** in `state_quota_and_policy.rs`
  mirroring `match_guardrail`, callable twice: **input** (pre-exec) and
  **output** (post-exec). Reuses the existing evaluation + evidence + audit path.

### Slice 3 — wire enforcement into the three execution seams (`ferrogate-cli`)
- Insert the entrypoint at the managed-action choke point
  (`external_actions.rs:129`) and the MCP (`mcp_rpc.rs`) + agent-run
  (`agent_runs.rs dispatch_tool :790`) seams, enforcing the order:
  **identity → capability(#204) → input guardrail → approval → execute →
  output guardrail → billing/evidence.**

### Slice 4 — approval re-binding + fail-closed guarantees
- Re-point approval binding from raw arguments (`approval.rs:407 fingerprint_for`)
  to the **post-transformation canonical action fingerprint**
  (`BoundCapabilityTarget.fingerprint()` computed after redaction). Re-check
  capability immediately before execution (revocation-between-approve-and-exec
  fail-closed; partly covered by the CAS/mismatch machinery).
- Cross-cutting invariants: blocked input → **no side effect AND no usage
  charge** (order guardrail before the worker call and before the managed-action
  billing emit); result redaction before model/client consumption and before
  logs; never auto-retry non-idempotent actions; external-detector payload
  minimized and **never** carrying resolved secret values (`ferrogate-secrets`).

### Slice 5 — E2E + regression
- E2E covering MCP + one more managed-action type, asserting audit + billing +
  evaluation evidence and each fail-closed invariant. Use
  `skills/ferrogate-test-strategy` for layered coverage; fine-grained,
  no-blind-spot per the standing test directive.

## Coordination / risks
- #204 (capability contracts) and #199 (evidence schema) are OPEN — build on
  their landed contracts, coordinate rather than fork. Live Supabase validation
  of the durable evidence/billing path is test-infra, not a code blocker.
- Security-sensitive: every new enforcement path must **fail closed** (deny +
  no side effect + no charge) on any error, missing policy resolution, or
  detector timeout.

## Verification (each slice)
`cargo +1.88.0 check/test/fmt/clippy -D warnings` workspace-wide;
`scripts/security-check.sh`; config + Python CI-gate tests; targeted
guardrail/capability/mcp/agentic integration suites; adversarial diff-review
before each commit. Issue kept OPEN until Slice 5 lands, then closed with an
evidence chain ([[issue-closure-evidence-chain]] style).
