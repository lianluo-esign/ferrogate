# Agent Sandbox Security Model

This document describes FerroGate's shipped agent-sandbox architecture —
`isolation.rs`, `capability_boundary.rs`, and `function_egress.rs` in
`crates/ferrogate-runtime/src/` — and the regression evidence backing its
fail-closed claim. It exists because this architecture (6,600+ lines across
`isolation.rs`, `capability_boundary.rs`, `function_egress.rs`,
`managed_worker.rs`, `self_hosted_worker.rs`) shipped without external
documentation or a concrete attack-shaped proof, per issue #190 and
`docs/design/ai-gateway-market-research-2026-07.md` §3/§4.1. This is
engineering documentation, not marketing copy: every claim below is scoped to
what is actually implemented and, where a fail-closed claim is made, to what
an executable regression test actually proves. See "What is proven vs.
architecturally present but untested" for the exact boundary.

## Why this exists: the threat class

The MCP ecosystem has a continuous stream of published RCE and credential-
leak CVEs, not isolated incidents — CVE-2025-53967 (Figma MCP Server, CVSS
8.0: an unauthenticated HTTP POST to the MCP interface could trigger shell
command execution the caller was never entitled to invoke), CVE-2025-47274
(ToolHive, MCP container secret leakage to local config), CVE-2026-56274
(Flowise MCP RCE, with an existing Metasploit module). The common shape:
a tool/agent call reaches a shell, filesystem, or network action that goes
beyond what the caller was actually authorized to do. FerroGate's answer to
that shape is a three-layer model described below, plus two regression tests
that reproduce it directly against FerroGate's own authorization code.

## The three-layer model

### Layer 1: `isolation.rs` — the execution boundary

`isolation.rs` is a multi-backend abstraction for where agent workloads
physically run. `IsolationBackendKind` enumerates four backends —
`FirecrackerMicroVm`, `KataContainers`, `Gvisor`, `RootlessDocker` — each
described by an `IsolationBackendDescriptor` carrying an
`IsolationBackendCapabilities` set (prepare/start/exec/stop/snapshot/collect
logs/collect artifacts/cleanup/governed egress/secret injection).
`select_isolation_backend` picks the highest-preference backend (Firecracker
first, then Kata, then gVisor, then rootless Docker) that satisfies both the
caller's `allowed_kinds` filter and the policy's `required_capabilities`.

The fail-closed detail worth calling out: `IsolationBackendCapabilities::none()`
gives a backend that advertises zero lifecycle capability, so a backend
entry that exists in the type system but has no real host implementation yet
can never satisfy a policy's required capabilities and can therefore never
be selected — selection is fail-closed by construction, independent of any
separate readiness filtering (`crates/ferrogate-runtime/src/isolation.rs`).
`IsolationPolicy::validate` additionally rejects any policy that would allow
direct public egress, disable the gateway control channel, or mount
arbitrary host paths.

### Layer 2: `capability_boundary.rs` — the authorization boundary

The module's own doc comment states the core design principle directly:
"Managed worker adapters must request capabilities through FerroGate before
executing external actions. A sandbox is an execution boundary, not an
authorization boundary." In other words: isolation (layer 1) limits what a
compromised workload can physically reach on the host; it is not, by itself,
what decides whether a given tool call was authorized. That decision is
`capability_boundary.rs`'s job.

`CapabilityAction` defines ten capability classes: `Tool`, `McpTool`, `Cli`,
`Skill`, `Filesystem`, `Browser`, `Rest`, `Secret`, `MemoryRead`,
`MemoryWrite`, `NetworkEgress`. A `CapabilityPolicy` names which classes are
`allowed_actions`, which additionally require approval
(`approval_required_actions`), and whether direct (ungoverned) network
egress is permitted at all (`allow_direct_network_egress`).
`SimpleCapabilityAuthorizer::authorize` evaluates, in order: direct
`NetworkEgress` is denied unless `allow_direct_network_egress` is set (even
if the `NetworkEgress` class is otherwise allowed — a deliberate two-layer
gate); approval-required actions or `high_risk` requests return
`ApprovalRequired`; allowed actions return `Allowed`; everything else
returns `Denied`. Every outcome carries a `CapabilityAuthorizationEvidence`
record (tenant/workspace/worker/session/run id, adapter, isolation backend,
action, target, decision, reason).

`managed_external_action.rs` is the production entry point that maps a real
tool/CLI/filesystem/browser/REST/secret/memory/network request onto a
`CapabilityAction` and calls this authorizer:
`authorize_managed_external_action` is exactly what
`crates/ferrogate-gateway/src/server/external_actions.rs`'s
`GatewayExternalActionAuthorizerService::authorize` calls in the running
gateway, before any worker handler executes an action. Its result is a
`NormalizedFrameworkEvent` whose `timeline_record()` produces a
`FrameworkEventTimelineRecord` (`event_id`, `run_id`, `kind`, `target`,
`outcome`, `message`, `event_json`) — see "Audit trail" below for how that
becomes a persisted, inspectable record.

### Layer 3: `function_egress.rs` — fail-closed edge-function egress

`function_egress.rs` governs a distinct action: gateway-brokered invocation
of Supabase edge functions via `/v1/functions/execute` (issue #117).
`FunctionEgressAllowlist` holds `FunctionEgressRule` entries
(`tenant`, `base_url`, `function_slugs`, or the `"*"` wildcard slug).
`FunctionEgressAllowlist::authorize(tenant, target)` is deny-by-default: it
returns `FunctionEgressDenied::NoRuleForTenant` for a tenant with no rules
at all, and `FunctionEgressDenied::TargetNotAllowed { tenant, base_url,
function_slug }` for a tenant with rules that don't cover the requested
base URL + slug — an empty allowlist or unrecognized tenant is rejected,
never implicitly allowed. `crates/ferrogate-gateway/src/function_egress.rs`'s
`prepare_brokered_invocation` calls this `authorize` step before minting any
scoped token or building the outbound HTTP request, so a denial happens
before any network call is made.

## The regression evidence

Two new test files reproduce the CVE-2025-53967 shape directly against this
code, both added by issue #190:

- [`crates/ferrogate-runtime/src/managed_external_action_red_team_test.rs`](../../crates/ferrogate-runtime/src/managed_external_action_red_team_test.rs) —
  a simulated tool invocation is granted exactly one `CapabilityAction`
  (`McpTool`), then the same simulated call attempts a shell/CLI action, a
  filesystem action, and a raw network-egress action outside that grant. A
  fourth test proves the two-layer `NetworkEgress` gate: even with the
  `NetworkEgress` class granted, direct egress stays denied without
  `allow_direct_network_egress`.
- [`crates/ferrogate-runtime/src/function_egress_red_team_test.rs`](../../crates/ferrogate-runtime/src/function_egress_red_team_test.rs) —
  a tenant legitimately scoped to one function at one project attempts to
  pivot to a different function slug at the same project, and to a
  different (attacker-controlled) project entirely; plus baseline
  unknown-tenant and empty-allowlist fail-closed checks.

Reproduce locally:

```bash
cargo test -p ferrogate-runtime --all-features managed_external_action_red_team_test
cargo test -p ferrogate-runtime --all-features function_egress_red_team_test
```

Both are ordinary `#[test]` functions inside the `ferrogate-runtime` crate,
so they also run as part of `cargo test -p ferrogate-runtime --all-features`
— the exact command `.github/workflows/rust-agentic-gateway-tests.yml`'s
`runtime` slice and `scripts/local-test-modules.sh agentic-gateway` already
run. No separate CI wiring was needed: that workflow slice runs
unconditionally on every CI run today (this repository's `ci.yml` has no
path filters), so any test added anywhere in the crate is automatically
included going forward, including on every future change to `isolation.rs`,
`capability_boundary.rs`, or `function_egress.rs`.

Actual local run, recorded 2026-07-09:

```
$ cargo test -p ferrogate-runtime --all-features
...
test result: ok. 130 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

## Audit trail

Every capability decision — allowed, denied, or approval-required — carries
inspectable evidence, not just a boolean:

- `capability_boundary.rs` / `managed_external_action.rs`: the
  `FrameworkEventTimelineRecord` returned by `NormalizedFrameworkEvent::timeline_record()`
  carries a deterministic `event_id`, `run_id`, `kind` (e.g.
  `"capability.denied"`), `target` (what was actually attempted, e.g. the
  shell command or host:port), `outcome` (`"denied"` / `"allowed"` /
  `"approval_required"`), and the full canonical `event_json`. In the
  running gateway, `GatewayExternalActionAuthorizerService::record_timeline_event`
  (`crates/ferrogate-gateway/src/server/external_actions.rs`) persists this
  record as a `StoredAgentRunEvent`, visible through the admin run-timeline
  surface.
- `function_egress.rs`: a `FunctionEgressDenied` value names the tenant,
  base URL, and function slug that were rejected. In the running gateway,
  `crates/ferrogate-gateway/src/server/local.rs`'s `/v1/functions/execute`
  handler calls `state.record_admin_audit_event(...)` with the denial's
  `Display` output as the audit message and outcome `"denied"` before
  returning the `403 function_denied` response — the audit record is
  written even though no network call was ever made.

## What is proven vs. architecturally present but untested

**Proven by the regression tests above:**

- An `McpTool`-only capability grant cannot be used to execute a `Cli`
  (shell), `Filesystem`, or `NetworkEgress` action.
- A `NetworkEgress`-class grant cannot be used for direct/ungoverned egress
  without the separate `allow_direct_network_egress` flag.
- A tenant scoped to one edge-function target cannot invoke a different
  function slug at the same project, or any function at a different
  project.
- An unknown tenant and an empty allowlist are both denied, not silently
  allowed.
- Every denial in both layers produces a structured, inspectable evidence
  value (`FrameworkEventTimelineRecord` / `FunctionEgressDenied`) rather
  than a bare boolean.

**NOT proven by this test (architecturally present, not independently
red-teamed here):**

- Class-crossing denials for the other seven `CapabilityAction` classes
  (`Tool`, `Skill`, `Browser`, `Rest`, `Secret`, `MemoryRead`,
  `MemoryWrite`) — covered by the same `allowed_actions.contains()` check
  exercised by the red-team tests, and by the pre-existing unit tests in
  `capability_boundary.rs` and `managed_external_action.rs`, but not by an
  attack-shaped scenario.
- `isolation.rs`'s backend-selection fail-closed behavior under a real
  Firecracker/Kata/gVisor/rootless-Docker host process — covered by
  `isolation_test.rs`'s unit tests, not by an attack-shaped scenario, and
  not exercised against a live host process at all.
- Per-path or per-host scoping *within* a single `CapabilityAction` class.
  `SimpleCapabilityAuthorizer` authorizes at the class level only — it does
  not parse or restrict the `target` string itself. Granting the
  `Filesystem` class authorizes every path and both read and write access,
  not just the one path/access mode named in a given
  `ManagedFilesystemAction`; granting `NetworkEgress` (with
  `allow_direct_network_egress: true`) does not itself restrict which host
  can be reached. Any per-target scoping must currently live in a caller's
  own policy construction, not in this authorizer.
- The HTTP/unix-socket transport around `authorize_managed_external_action`
  (`crates/ferrogate-gateway/src/server/external_actions.rs`) end to end, and
  the `/v1/functions/execute` route handler end to end — both require the
  full gateway process; this test exercises the library-level decision
  functions those handlers call, not the running process.

Do not read this document as a claim that all ten `CapabilityAction` classes
or the full request/response transport have been red-teamed. They have not.
This is the specific, reproducible evidence for the specific attack shape
described above, and no more.
