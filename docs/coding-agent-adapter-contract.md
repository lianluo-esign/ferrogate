<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-25
  description: Token4AI Cloud, FerroGate AI Gateway, the coding-agent adapter contract
  (issue #472): the five phases materialize -> bootstrap -> run -> extract -> write-back,
  the invariants carried by types, and what is deliberately left to implementations.
-->

# The coding-agent adapter contract (#472)

**Status: contract defined, no implementation.** This slice ships types, a
trait, and this note. It starts no container, opens no socket, resolves no
secret, and integrates no specific coding agent.

Code: [`crates/ferrogate-runtime/src/coding_agent/`](../crates/ferrogate-runtime/src/coding_agent/mod.rs).
The module docs are normative; this note is the shorter, linkable version.

Read first: [`cloudflare-data-plane-decision.md`](cloudflare-data-plane-decision.md)
(#470 — the governed data plane stays Pingora in a Cloudflare Container),
[`cloudflare-container-isolation.md`](cloudflare-container-isolation.md) (#415 —
the container tier the agent runs in).

## Why it exists

"Fix this bug in my repo" is the product story the Cloudflare stack exists to
serve. Container lifecycle and exec (#415), agent lifecycle (#414), memory
(#427) and cost governance (#428) already exist. Nothing knew how to bootstrap a
repo-aware agent in a container and turn its work into a reviewable change.

## The five phases

| Phase | Seam | Question it settles |
|---|---|---|
| 1. Materialize | `CodingAgentAdapter::materialize_repo` | Which commit, cloned with which credential, revoked where? |
| 2. Bootstrap | `CodingAgentAdapter::bootstrap` | Which agent, given which task, with model traffic pointed where? |
| 3. Run | `CodingAgentAdapter::run` | Long-running, filesystem-mutating execution to a terminal status. |
| 4. Extract | `CodingAgentAdapter::extract` | What did it produce, and to which `run_id` does that belong? |
| 5. Write back | `CodingAgentAdapter::write_back` | Who authorized the outward side effect, and where is the audit event? |

Plus `finalize`, which is not a sixth feature: it discharges phase 1's
credential obligation and is the reason phase 1 is safe.

## The invariants, and why they are types rather than rules

**A branch is not a pin.** `PinnedRef` accepts only a full 40/64-hex commit id;
`main`, `HEAD`, `v1.2.3` and abbreviated ids are rejected.
`MaterializedWorkspace::verify` makes "the clone landed on a different commit" a
hard failure, because the diff base, the work-product id and the review are all
attributed to the pin.

**Credentials are references, never material.** `CredentialReference` carries a
secret-store URI (`cf://`, `vault://`), refuses bare values, and specifically
refuses `env://` — a container running model-authored code can read its own
environment (#475). No type in this contract has a field that can hold a token,
so no implementation can log one, persist one, or bake one into an image by
accident. `CredentialDelivery` has two variants — a per-operation gateway broker
(nothing rests in the container; every use audited) and an ephemeral file
outside the workspace with a mode check. There is **no `EnvVar` variant**, and
adding one would be a contract change, which is the point. TTL is capped at one
hour, and the grant is `#[must_use]` and consumed by value at `finalize`.

**Write capability cannot be self-granted.** A write-capable credential scope is
only constructible from a `WriteBackGrant`
(`RepoCredentialScope::with_write_back` takes it by reference).
`CodingAgentAdapter::write_back` accepts only an `AuthorizedWriteBack`, which has
private fields, no public constructor, no `Default`, and deliberately **no
`Deserialize`** — a capability token that can be parsed from untrusted input is
not a capability token. The only mint is `authorize_write_back`, whose grant
parameter is an `Option`: the absence of a grant is the normal state of a run
and produces a recorded `deny`, never a fallthrough. Every call — allow *and*
deny — returns an `ActionReceipt` carrying the canonical `ActionIdentity`
(`action = "vcs.write_back"`), the `ActionDecision`, and an `AuditOutcome`.
There is no authorization path that produces no evidence.

**The deliverable is a diff, not a chat completion.** `WorkProduct::product_id`
is derived — `sha256(tenant|run|base_commit|diff_digest)` — so
`WorkProduct::attributed_to` is a check, not a convention: relabelling the run
breaks the id. An empty diff is refused, so "the agent changed nothing" surfaces
as *no work product* rather than as an empty patch that reads like a reviewable
change. Agent prose is `WorkProduct::summary` and is explicitly advisory.

**The gateway cannot claim enforcement it does not have.**
`EgressPosture::enforcement()` is *derived* from the posture, not declared
alongside it, so no implementation can record `network_enforced` for an
open-egress run. The only bypassable posture, `OpenWithDetection`, requires a
named approver and a reason, and that weakening lands on the run receipt. This
is #471's problem stated in the type system.

## Two-level fingerprints

Per the `action_identity` contract (#303): the target-level
`ActionIdentity::action_fingerprint` is `sha256` over the canonical
`CanonicalCapabilityTarget::Network` rendering of the repo's git HTTPS remote —
it answers "which repo is being mutated". The operation, branch, work product
and head commit live in `WriteBackRequest::invocation_fingerprint`, the
invocation-level binding an approval is issued against. Neither substitutes for
the other.

The operation is deliberately **not** in the canonical target: encoding it would
require inventing provider-specific API URLs (`/repos/{o}/{r}/pulls` is GitHub's
shape, not GitLab's), which is exactly the vendor-shaped abstraction #472 warns
against.

## Why this is not `FrameworkAdapter`, and why there is no vendor enum

`FrameworkAdapter` models a request/response worker (session → submit → stream →
artifacts). A coding agent is long-running, filesystem-mutating and
VCS-writing, and three of its five phases — materialization, extraction,
write-back authorization — have no counterpart there. Bolting them on would mean
widening every existing adapter with methods it cannot implement, or smuggling
repo state through `artifacts`.

`SupportedFramework` is a closed enum. This contract deliberately does **not**
mirror it: `CodingAgentDescriptor::agent_name` is a free string and nothing
branches on it. A closed vendor list would have to be edited, and every `match`
on it revisited, to admit the second coding agent — the #350 failure mode, where
a wire contract was frozen and already wrong across five merged slices.

## Consistency with #470

The governed data plane stays Pingora in a Cloudflare Container — one Rust
implementation, no second governed path. `GovernedLlmEgress` points at one
tethered governed endpoint reachable from the agent's container; the strongest
posture (`GatewayProxied`) proxies git through it too, keeping public egress off
entirely. Nothing here introduces a second policy implementation or assumes a
Worker can be the governed proxy.

## Deliberately left to implementations and to later slices

- **Any specific coding-agent integration.** No Claude Code, no aider, no
  in-house harness. The contract exists so the second one costs nothing.
- **Transport and lifecycle.** How `materialize_repo` runs `git` is the
  isolation tier's business (#415 `/container/exec`). This contract never
  touches the network.
- **Credential issuance and resolution** — minting a repo-scoped installation
  token, resolving the store reference, running the credential broker: **#475**.
  This contract fixes only the shape.
- **Egress enforcement mechanics** — whether the platform can actually pin an
  allowlist: **#471/#475**. The contract makes the posture declarable,
  derivable and auditable; it cannot make Cloudflare enforce it.
- **Persistence and the control-plane read path.** Storing work products and
  serving them through the admin API is a separate slice. The types are
  serde-ready; no repository trait is frozen on a guess about the query shape.
- **Approval workflow.** `WriteBackGrant::approval_reference` links to the
  existing approval machinery; this contract does not re-implement it.
- **Prompt construction.** `TaskBrief` carries the requester's instruction
  verbatim; how an implementation turns that into its agent's prompt format is
  its own business, and should stay that way.

## Tests

`crates/ferrogate-runtime/src/coding_agent/*_test.rs` — 36 tests at the adapter
seam driven by a mock container and a mock VCS. No live GitHub, no live model,
no network.
