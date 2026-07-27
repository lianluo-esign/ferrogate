<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-18
  description: Design-partner VPC pilot kit for the FerroGate Secure Agent Gateway wedge.
-->

---
title: Secure Agent Gateway VPC Pilot
description: Design-partner pilot overview, value proposition, and scope (issue #209).
permalink: /pilot/
---

# Secure Agent Gateway — design-partner VPC pilot

This directory is the **pilot deployment kit** for issue #209 (parent epic
#194): everything a technical design partner needs to run a time-boxed pilot
of FerroGate's Secure Agent Gateway inside their own VPC, with real but
scoped Agent/MCP traffic and an agreed security success test.

- [`vpc-pilot-runbook.md`](vpc-pilot-runbook.md) — step-by-step deployment
  and operation runbook.
- [`success-criteria.md`](success-criteria.md) — measurable success criteria
  and the go/no-go framework for the paid-enterprise conversation.
- [`onboarding-demo.md`](onboarding-demo.md) — a scripted, reproducible demo
  a solutions engineer can run without partner infrastructure.

## The wedge: what problem, why now

Enterprises piloting MCP/Agent systems hit the same wall: an agent is no
longer just model traffic. It calls MCP tools, runs CLI commands, touches
the filesystem, makes REST calls, and consumes secrets — and the security
team cannot answer *who did what, under which policy, with what approval,
at what cost* when something goes wrong. Generic AI gateways govern model
calls; they do not govern **actions**.

FerroGate's sellable wedge is one inspectable chain at the customer
boundary, applied uniformly to model traffic and Agent/MCP actions:

```text
Identity -> Policy -> Guardrail -> Approval -> Isolation -> Governed Egress -> Billing -> Evidence
```

**This is a hypothesis under validation, not a proven market claim.** The
pilot exists to falsify or confirm it with real buyer traffic (see the
falsifiable gates in #209). We do not count generic interest or "security
is important" as validation.

## Security value proposition — anchored to evidence the product produces

Every claim below traces to a shipped feature with tests on `main`. Nothing
here is a roadmap promise; roadmap items are explicitly marked.

| Claim | Shipped evidence | Issue |
|---|---|---|
| **Every guardrail verdict is durable, queryable evidence.** One overall evaluation plus per-check records (verdict, action, enforced vs shadow-only, fail vs detector-error, policy revision, detector version, latency), persisted to the customer's Postgres. Raw prompts, PII/secret text, auth headers, and detector credentials are absent by default; inputs are stored only as tenant-domain-separated HMAC-SHA256 fingerprints. | `crates/ferrogate-storage/src/guardrail_evidence.rs`, `/admin/v1/guardrail-evaluations`, sanitizer tests, RBAC/cross-tenant tests, live E2E (`ferrogate-test guardrail-supabase`) | #199 (merged; one human usability check outstanding) |
| **One investigation view joins the whole chain.** Starting from a request id, trace id, or agent-run id, `/admin/v1/investigations` returns Identity, Route, Policy, Guardrail, Approval, Provider/Tool execution, Usage/Cost, and final outcome as one timeline — no raw table queries. | `/admin/v1/investigations` in `docs/openapi/admin-api.openapi.json`; Admin console investigation view | #199 |
| **Guardrails govern actions, not just model content.** Input and output guardrails run on MCP tool calls, CLI, and managed agent actions, fail-closed: blocked input produces no side effect and no usage charge; results can be redacted before model/client consumption; high-risk actions can require approval. | Managed-action selectors and chokepoint enforcement; E2E `crates/ferrogate-cli/tests/guardrail_managed_action_e2e.rs` (MCP + CLI blocked with `guardrail.blocked` timeline events) | #200 (closed) |
| **Least privilege at the target level, not capability classes.** Policies allow one MCP server/tool, filesystem path+operation, network host/port/method, secret destination, or CLI argv shape while denying siblings in the same class. Evaluated against canonical normalized targets with adversarial tests (path traversal, symlink, hardlink, alt-host encodings, DNS rebinding, IDN homoglyphs). A real hardlink workspace-escape was found by this test suite and fixed fail-closed. | `CanonicalCapabilityTarget` in ferrogate-runtime; `crates/ferrogate-cli/tests/target_capability_e2e.rs` | #204 (closed) |
| **"Approve A, execute B" is impossible.** Approval and execution compare the same canonical action fingerprint, derived after guardrail transformations; the worker re-verifies before executing; fingerprint mismatch and revocation fail closed. | `action_fingerprint()` / `verify_authorized_action_fingerprint`; `/admin/v1/tool-approvals` | #204, #200 |
| **Policy distribution is cryptographically signed with replay protection.** Cluster snapshots can be Ed25519-signed; data-plane nodes activate only snapshots that verify (trusted key, tenant/deployment identity, strictly-newer revision, unexpired), keep last-known-good on any rejection, and fail closed on policy expiry. The replay floor is persisted in Postgres and survives restart. | `crates/ferrogate-config/src/config/signed_snapshot.rs` (25+ fail-closed tests, 3 independent adversarial reviews), `control_plane_replay_floors` migration | #206 (in progress — see honesty note below) |
| **Detector accuracy is measured, not asserted.** A conformance suite and a versioned evaluation runner report precision/recall/F1, FP/FN case ids, and latency distribution for any guardrail adapter. Two self-hostable adapters ship today (Presidio for DLP/PII, LLM-Guard for prompt injection) with published per-field data-flow tables and honest fixture-driven accuracy numbers. | `crates/ferrogate-guardrails/src/{conformance,evaluation}.rs`; `docs/guardrails/adapters/` | #201 (adapter selection pending design-partner confirmation) |
| **Data locality by construction.** In the pilot topology every component — gateway, evidence store (Postgres), and detectors — runs inside the partner VPC. Prompt/response/tool-argument content never leaves the boundary; the shipped adapters send content only to self-hosted analyzers and no tenant/model/key metadata at all. | Pilot topology in the runbook; adapter data-flow tables | #206, #201 |

### Honesty notes (read before quoting anything above to a buyer)

- **#206 is partially delivered.** The signed-snapshot verify/activate loop,
  offline fail-closed behavior, and persisted replay floor are shipped and
  adversarially tested — but over the file-backed shared control plane. The
  managed control plane with an **outbound-only network sync transport** and
  the packaged customer-VPC data-plane deployment are still in progress. The
  pilot therefore runs the **fully-in-VPC topology** (which is also the
  strongest data-locality posture); do not sell "hybrid managed control
  plane" yet.
- **Accuracy numbers are contract fixtures, not vendor benchmarks.** The
  published Presidio/LLM-Guard precision/recall figures come from the small
  synthetic reference corpus and prove the measurement pipeline works. Pilot
  accuracy is measured on the partner's own labeled shadow traffic
  (see success criteria).
- **No certification, compliance, or SLA claims.** FerroGate produces
  evidence (signed snapshots, per-check verdicts, investigation timelines,
  audit/billing joins). What that evidence satisfies is the partner's
  auditors' call, not ours. This mirrors the explicit non-goals in #209.

## Pilot scope and duration

- **Duration:** time-boxed, 4–6 weeks from deploy to go/no-go review
  (agreed at kickoff; do not let it run open-ended — an open-ended pilot
  fails the #194 gate that free experimentation does not count).
- **Traffic:** real but scoped — one named agent/MCP workload with a named
  owner, not synthetic load and not the partner's whole estate.
- **Progression:** week 1 deploy + connect; weeks 2–3 shadow-mode
  guardrails on live traffic; weeks 3–4 promote agreed policies to enforce;
  final week: incident-investigation drill, metrics review, go/no-go.
- **In scope:** OpenAI-compatible model traffic, MCP tool traffic with
  per-user identity, managed agent actions (CLI/filesystem/network/secret),
  target-level capability policy, guardrail shadow/enforce, approvals,
  investigation view, usage/billing attribution.
- **Out of scope:** managed control plane (in progress, #206), isolation
  backend adversarial evidence (#205), certifications/SLAs, production
  cutover.

## What closes #209 vs. what this kit provides

This kit closes the **engineering deliverable**: a turnkey, evidence-anchored
pilot a partner can run. The #209 gates that remain inherently external:
qualified buyer interviews, a partner actually running real traffic, and a
concrete paid contract/support/SLA discussion. Record those in the issue as
they happen, keeping facts, approved quotes, assumptions, and FerroGate
preferences separate.
