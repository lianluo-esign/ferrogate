<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-25
  description: Token4AI Cloud, FerroGate AI Gateway, the coding-agent adapter contract
  (issue #472): the five phases materialize -> bootstrap -> run -> extract -> write-back,
  the invariants carried by types, the container-backed implementation that drives git
  through /container/exec, and the control-plane read path on #474's job-result verb.
-->

# The coding-agent adapter contract (#472)

**Status: contract defined, container-backed implementation landed, read path
on #474's job-result route.** What is still deliberately absent is any
*vendor-specific* coding-agent integration — no Claude Code, no aider. The
coding agent is argv on `CodingAgentImage::entrypoint`, so the second one is a
different image, not a second adapter.

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

## The implementation

`ContainerCodingAgentAdapter` (`coding_agent/container_adapter.rs`) runs all
five phases against a #415 Cloudflare Container through `/container/exec`:

```
git init --quiet <ws>
git -C <ws> config --local ...        # #475 credential-helper config
git -C <ws> remote add origin https://<host>/<ns>/<name>.git
git -C <ws> fetch --no-tags --quiet [--depth N] origin <commit>
git -C <ws> checkout --quiet --detach FETCH_HEAD
git -C <ws> rev-parse HEAD            # read the pin back, then verify()
```

Every step is `execve`-style argv — nothing interpolates a repo name, a branch
or a task instruction into a shell string. The pin is **read out of the
workspace** and checked with `MaterializedWorkspace::verify`, so "the clone
landed on the pin" is an observation, not an inference from `git fetch` having
exited 0. Extraction runs `add --intent-to-add` (so files the agent *created*
appear), `diff`, `numstat` and `rev-parse`; write-back runs
`git push origin <head>:refs/heads/<branch>`.

Opening a pull request is a provider API call, not a git verb, so the adapter
advertises `pull_request: false` and `preflight`/`write_back` refuse it rather
than pushing a branch and calling it a review request. Credential revocation is
an injected `RepoCredentialRevoker` seam; a failure records
`RevocationOutcome::Failed` and `credential_is_closed()` answers `false`, which
is the incident.

## Retrieval through the control plane

`GET /v1/agent-jobs/{run_id}/result` (#474) returns a `work_products[]` array.
A work product is published as **one `artifact` event on the run timeline**
carrying a `WorkProductArtifact` envelope, and the result handler decodes those
into `WorkProductView`s.

This rides #474 rather than adding `/admin/v1/.../work-products/{id}` on
purpose: a work product has no life outside its run, the run timeline is
already the durable evidence store, and its tenant isolation is already applied
at the storage query layer (`AgentRunFilter.organization_id` pinned by
`enforce_tenant_filter` before the read). A second surface would have meant a
second store, a second isolation implementation, and a second thing to keep
consistent with the run's terminal state.

The reader does **not** trust the payload. A timeline artifact event is
worker-reported evidence, so `attribution_verified` is `true` only when the
derived product id re-checks against the `run_id` in the request path, and
`repo_verified` only when the recorded repo is the one folded into that id. A
relabelled record is returned *marked*, not hidden — hiding it would hide the
tampering. `published.matches_work_product` repeats the finalize cross-check at
read time, because the timeline event and the run row are written
independently. Patch bytes are never inlined into the projection: the digest,
the stats and the artifact reference are, so one poll cannot be turned into a
megabyte of amplification.

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
adding one would be a contract change, which is the point. The brokered
callback URL must be on the **governed gateway host** that
`GovernedLlmEgress.gateway_host` pins — validating it as merely "some https
URL" would let the strongest delivery be aimed at
`https://attacker.example/git-credential`.

TTL is capped at one hour, and the grant is **linear**: `RepoCredentialGrant`
is `#[must_use]`, is **not `Clone`** and **not `Deserialize`**, is lent to
materialization by reference, moved into `RunFinalization` by value, and
*consumed* by `CredentialRevocation::for_grant`. `#[must_use]` plus by-value
passing bought nothing while the type was cloneable (a caller could clone
first, and a `Serialize + Deserialize` pair is a clone by round-trip); now no
usable handle can survive its own close-out record.

**What the revocation record does and does not claim.** It is a *record*. It
proves the grant was surrendered, that a terminal receipt cannot exist without
one (success path and failure path alike), and which `RevocationPoint` the
attempt named. It does **not** attest that the remote honoured the call — no
in-process type can. `RevocationOutcome::Failed` exists because sometimes it did
not, and `credential_is_closed()` is the predicate that surfaces it.

**Write capability cannot be self-granted, and is tenant-bound.** A
write-capable credential scope is only constructible from a `WriteBackGrant`
(`RepoCredentialScope::with_write_back` takes it by reference). A grant binds
`(tenant_id, run_id, repo_id)`, taking its tenant from the *granting principal*
so it cannot be issued into a tenant its issuer does not act in. Two parts would
not be enough: `run_id` is unique only within a tenant, so a `(run, repo)`
binding lets a grant issued in one tenant authorize a same-named run in another
against the same repository. `authorize_write_back` refuses a cross-tenant
grant (`write_back_tenant_mismatch`) and refuses a cross-tenant acting
principal (`write_back_principal_tenant_mismatch`) *before* the grant is
consulted at all.
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
is derived — `sha256(tenant|run|repo|base_commit|diff_digest)` — so
`WorkProduct::attributed_to` and `WorkProduct::extracted_from` are checks, not
conventions: relabelling the run *or the repo* breaks the id. The repo is in the
derivation because "which repository this diff came from" is the one property
this type exists to provide, and a public field nobody re-derives asserts it
rather than making it checkable.

A terminal `CodingRunReceipt` additionally cross-checks the write-back receipt
against the work product: tenant, run, repo, **branch and head commit**, not
just `work_product_id`. Matching the id alone would let a receipt honestly say
"work product X was published" while the commit that reached the remote had
nothing to do with X.

An empty diff is refused, so "the agent changed nothing" surfaces as *no work
product* rather than as an empty patch that reads like a reviewable change.
Agent prose is `WorkProduct::summary` and is explicitly advisory.

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
- **A dedicated work-product store or route.** Retrieval rides #474's job-result
  verb over the existing run timeline (above). No repository trait, no table and
  no `/admin/v1/.../work-products/{id}` route was frozen.
- **Opening a pull request.** A provider API call, not a git verb: advertised
  `false` and refused, never downgraded to a push.
- **Approval workflow.** `WriteBackGrant::approval_reference` links to the
  existing approval machinery; this contract does not re-implement it.
- **Prompt construction.** `TaskBrief` carries the requester's instruction
  verbatim; how an implementation turns that into its agent's prompt format is
  its own business, and should stay that way.

## Tests

`crates/ferrogate-runtime/src/coding_agent/*_test.rs` — tests at the adapter
seam driven by a mock VCS and by a **scripted `/container/exec` transport**, so
`ContainerCodingAgentAdapter` is exercised as production code with the git
commands it actually issues asserted. Plus
`crates/ferrogate-cli/src/gateway/agent_jobs_test.rs` for the read path off the
run timeline. No live GitHub, no live model, no network.
