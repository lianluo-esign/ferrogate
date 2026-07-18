<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-18
  description: Measurable success criteria and go/no-go framework for the Secure Agent Gateway VPC pilot.
-->

---
title: Pilot Success Criteria
description: Measurable success criteria and the go/no-go framework for the design-partner VPC pilot (issue #209).
permalink: /pilot/success-criteria/
---

# Pilot success criteria and go/no-go framework

Agree on these numbers **at kickoff, in writing, with the partner's named
owner**. Values below are proposed defaults — the partner may tighten or
relax them, but every criterion must stay measurable from evidence the
deployment itself produces. Per #209's non-goals: no certification, audit,
or compliance claim is made or implied beyond the evidence artifacts listed;
what that evidence satisfies is the partner's assessors' judgment.

## 1. Traffic reality gate (prerequisite for everything else)

| Criterion | Target | Measured from |
|---|---|---|
| Real workload | The agreed named agent/MCP workload (named owner) runs through the gateway — not synthetic load | Request logs + billing records attribute traffic to the pilot API keys/identities |
| Sustained window | ≥ 2 consecutive weeks of that traffic, ≥ 5 business days in enforce mode for at least one guardrail policy | Guardrail evaluation records (`enforced` flag) over time |
| Chain coverage | Model **and** managed-action traffic (≥ 1 MCP tool) traverse identity → capability policy → guardrail → billing → evidence | Investigation timelines for sampled requests show every stage |

If this gate fails, the pilot result is "not validated", regardless of how
well the software behaved. Free-floating experimentation does not count
(#194 gate).

## 2. Latency budget

The gateway must not make the workload unusable. Overhead is measured as
gateway-added latency (gateway ingress to provider dispatch + response
handling), not provider/model time, using the deployment's own metrics
(Prometheus/OTLP) over the enforce window.

| Criterion | Proposed target | Notes |
|---|---|---|
| Gateway proxy overhead, p95 | ≤ 15 ms without semantic detectors | Baseline for the identity/policy/routing/billing path; calibrate week 1 against the partner's direct-to-provider baseline |
| In-VPC semantic detector overhead, p95 | ≤ 250 ms per guarded request | Presidio/LLM-Guard are self-hosted; per-check latency is recorded in evidence (p50/p95/max come from the evaluation runner and the per-check latency fields) |
| Streaming behavior | Agreed streaming mode per policy (`buffer_and_enforce` / `shadow_after_complete` / `reject_streaming`) documented and observed | Buffering trades time-to-first-token for enforcement; the partner picks per route |
| Error budget | Gateway-caused 5xx ≤ 0.1% of pilot requests | Excludes provider/upstream failures, which are attributed separately in logs |

Honesty note: FerroGate's committed local performance reports
(`docs/performance-reports/`) are maintainer-workstation baselines, not
capacity promises for the partner's environment. Pilot latency is measured
in the pilot, and week-1 calibration may revise the p95 targets by mutual
agreement before the enforce window starts.

## 3. Guardrail quality (tied to the #201 evaluation harness)

Measured with the shipped evaluation runner
(`crates/ferrogate-guardrails/src/evaluation.rs`: precision, recall, F1,
FP/FN case ids, latency distribution) against **partner-labeled samples of
the pilot's own shadow traffic** — not the synthetic reference corpus, and
not vendor marketing numbers.

| Criterion | Proposed target | Measured from |
|---|---|---|
| Shadow window before any enforcement | ≥ 1 week of shadow evidence per check | `enforced = false` evaluation records |
| Labeled sample | ≥ 200 labeled verdicts per check to be promoted (or all verdicts if fewer) | Owner labels exported shadow verdicts |
| Precision at promotion (deny/redact checks) | ≥ 0.95 on the labeled sample | Evaluation runner report |
| Recall on the agreed threat list | ≥ 0.80 on partner-supplied known-bad cases for that check's category | Evaluation runner report; the partner defines the threat list, we do not grade our own homework |
| Detector health | Detector error rate ≤ 1% of evaluations; errors distinguished from fails in evidence (shipped, #199) | Per-check `error` verdicts + detector-health metrics |
| Enforcement correctness | Blocked input → zero provider/tool side effect and zero usage charge; redaction happens before model/client consumption; approval binds to the canonical post-transform action fingerprint | Spot-checked via investigation timelines (behaviors are E2E-tested in-repo: #200, #204) |
| Rollback drill | One deliberate promote → rollback cycle executed via `/admin/v1/guardrail-policies/{id}/rollback` | Admin audit records |

A check that misses precision stays in shadow — that is a scoping outcome,
not a pilot failure. A check that cannot reach the recall target on the
partner's threat list is reported honestly as a detector limitation
(cf. the published known-limitations sections in
`docs/guardrails/adapters/`).

## 4. Incident-investigation time (tied to #199's <10-minute drill)

| Criterion | Target | Measured from |
|---|---|---|
| Investigation drill | A partner security engineer **unfamiliar with the FerroGate implementation**, given one request/trace/agent-run id from a real blocked request, answers **who, why, target, action, and cost** in **< 10 minutes** using only the investigation view / `/admin/v1/investigations` | Timed drill; record participant, start/end, starting id, answers, and any navigation failure |
| No raw-table access | The drill completes without querying database tables directly | Drill observation |
| Evidence durability | The investigated request's evidence survives a gateway restart | Restart during the pilot (covered in-repo by the `guardrail-supabase` E2E) |

This drill doubles as the one outstanding human-gated acceptance item on
#199 — a successful run should be recorded on that issue with the details
above.

## 5. Data locality and policy-integrity guarantees

| Criterion | Target | Measured from |
|---|---|---|
| Content stays in the VPC | No prompt, response, tool argument, or secret material leaves the partner VPC. Detectors are self-hosted; the shipped adapters send exactly the documented fields (content text only, no tenant/model/key metadata — per-field tables in `docs/guardrails/adapters/`) | Deployment topology review + adapter data-flow docs + partner egress monitoring |
| Evidence sanitization | Stored evidence contains no raw matched PII/secret text, prompts, auth headers, or detector credentials — HMAC fingerprints and categories only | Partner inspects their own evidence tables (sanitizer is test-enforced, #199) |
| Signed policy distribution | Replicas activate only Ed25519-verified snapshots (identity-bound, strictly-newer revision, unexpired); rejection keeps last-known-good; replay floor persists across restart | Cluster sync status (active revision, rejection reason) + one deliberate tamper/replay attempt during the pilot |
| Fail-closed offline behavior | On publisher outage, replicas serve last-known-good until policy expiry, then fail closed — verified once, on purpose | Controlled outage drill |
| Evidence store ownership | All evidence lives in partner-controlled Postgres with configurable retention | Deployment review |

Scope honesty: the managed control plane with outbound-only sync is in
progress (#206) and is not evaluated in this pilot; the criteria above
cover the shipped in-VPC signed-snapshot loop only.

## 6. Go/no-go framework for the paid-enterprise conversation

Reviewed at the end-of-pilot meeting with the partner's named owner and an
economic buyer present. Record outcomes on #209, keeping facts, quotes
approved for use, assumptions, and FerroGate preferences separate.

**GO — open a concrete paid discussion (contract/support/SLA)** when all of:

1. Section 1 traffic gate passed (real, sustained, chain-covering traffic).
2. Latency budget met, or misses were accepted in writing by the workload
   owner.
3. At least one guardrail policy ran in **enforce** on real traffic at the
   precision target, and one real block/redact/approval event was
   investigated end-to-end.
4. The <10-minute investigation drill succeeded with an unfamiliar partner
   engineer.
5. Data-locality review passed the partner's own security check.
6. The partner articulates, in their own words, a concrete incident or
   blocked rollout this would have addressed (the #209 pain evidence — we
   record it, we do not script it).

Per #194, only a concrete paid contract/support/SLA discussion satisfies
the commercial gate — continued free usage, stars, or "keep us posted" do
not.

**NO-GO — record and stop** when any of:

- The partner will not run scoped real traffic (validation impossible —
  this is the #209 stop condition, not a deferral).
- Enforcement was never acceptable at the precision target on their
  traffic (detector fit failure — feed the FP/FN case ids back into #201
  adapter selection).
- Investigation drill exceeded 10 minutes or required implementation help
  (evidence UX failure — file the navigation failures against #199).
- The security review found content leaving the boundary (treat as a
  security bug: file, fix, and re-verify before any re-attempt).

**CONDITIONAL** (one bounded blocker, e.g. a missing detector category or
the #206 managed control plane): time-box the fix and a re-test; do not
let "conditional" become an open-ended free pilot.

After the decision, reorder detector/protocol/deployment/UI priorities
from what the pilot evidence showed (#209's final gate) — not from
competitor feature counts.
