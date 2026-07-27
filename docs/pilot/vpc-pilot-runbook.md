<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-18
  description: Step-by-step VPC pilot deployment runbook for the FerroGate Secure Agent Gateway.
-->

---
title: VPC Pilot Runbook
description: Step-by-step deployment and operation of a FerroGate design-partner pilot in a partner VPC.
permalink: /pilot/vpc-runbook/
---

# VPC pilot runbook

Audience: the partner's platform/infra engineer plus a FerroGate solutions
engineer. Expected wall-clock: ~1 day to a serving gateway, ~1 week to live
shadow-mode traffic.

Topology note (honest scoping): the pilot runs **entirely inside the partner
VPC** — gateway replicas, the Postgres evidence store, and any detector
services. Within the VPC, policy distribution uses FerroGate cluster mode
with **Ed25519-signed snapshots**: an admin/publisher node signs, data-plane
replicas verify (trusted key, tenant/deployment identity, strictly-newer
revision, expiry) before activating, keep last-known-good on rejection, and
fail closed on policy expiry with a Postgres-persisted replay floor. The
managed (FerroGate-operated) control plane with an outbound-only sync
transport is in progress under #206 and is **not** part of this pilot.

## 1. Prerequisites

Partner side:

- A VPC with either a Kubernetes cluster (manifests in `deploy/kubernetes/`,
  optional Helm chart in `charts/ferrogate/`) or VMs with systemd/Docker.
  The full scheduler-agnostic contract is `docs/cluster-deployment.md`.
- PostgreSQL 15+ reachable inside the VPC (Supabase self-hosted or plain
  Postgres — both supported via `storage.provider_order = ["supabase",
  "postgres"]`, see `docs/durable-storage.md`). TLS mode `verify_full`
  preferred, `require` minimum.
- Redis, only if running 2+ replicas and cluster-safe rate limits/token
  budgets are in scope (`cluster.counter_backend = "redis"`).
- Optional but recommended for the semantic-guardrail track: self-hosted
  Microsoft Presidio analyzer and/or ProtectAI LLM-Guard API inside the VPC
  (deployment and per-field data-flow docs: `docs/guardrails/adapters/`).
- One named agent/MCP workload with a named owner, and provider API keys
  (or an internal OpenAI-compatible endpoint) for model traffic.
- Prometheus or an OTLP collector for metrics (optional week 1).

FerroGate side:

- A release build of the `ferrogate` binary or container image
  (`Dockerfile` at repo root; Rust 1.88.0 pinned).
- This kit, `docs/cluster-deployment.md`, and the demo script
  (`onboarding-demo.md`) for the kickoff session.

Secrets to provision before boot (never in config files):

| Env var | Purpose |
|---|---|
| `FERROGATE_SUPABASE_DSN` (name set by `storage.supabase_dsn_env`) | Postgres/Supabase DSN for the durable control/evidence store |
| `FERROGATE_GUARDRAIL_EVIDENCE_HMAC_KEY` | Tenant-domain-separated HMAC key for guardrail input fingerprints (required for evidence persistence) |
| Provider/MCP credentials | Referenced by `value_env` in config, e.g. MCP server headers |

## 2. Deploy the gateway in the partner VPC

1. **Start from the example config.** Copy `config/ferrogate.example.toml`
   and set providers, models, routes, MCP servers, and API keys for the
   scoped pilot workload only. Validate with `ferrogate check --config ...`
   before any deploy.

2. **Point the durable store at partner Postgres** (`docs/durable-storage.md`):

   ```yaml
   storage:
     provider: supabase            # or postgres
     required: true                # fail closed if the evidence store is down
     supabase_dsn_env: "FERROGATE_SUPABASE_DSN"
     postgres_tls_mode: verify_full
     migration_mode: auto          # first boot; switch to validate_only after
   ```

   Everything the pilot's evidence story depends on — request/audit/billing
   records, guardrail evaluations, approvals, agent runs, the snapshot
   replay floor — lands in this partner-controlled database.

3. **Enable cluster mode with signed snapshots.** Per
   `docs/cluster-deployment.md`, run 2+ replicas behind the partner's load
   balancer, and add the signed-snapshot fields (all under `[cluster]`):

   ```toml
   [cluster]
   enabled = true
   cluster_id = "pilot"
   node_id = "gateway-a"              # unique per replica
   state_backend = "file"
   file_state_path = "/var/lib/ferrogate/cluster-state.json"
   counter_backend = "redis"          # if 2+ replicas need shared limits
   redis_url = "redis://redis:6379/0"

   # Signed policy snapshots (issue #206 slice, shipped):
   # the publisher node holds the private key; every replica holds only
   # the public trusted keys and rejects forged/replayed/downgraded/
   # expired/cross-tenant snapshots, keeping last-known-good.
   snapshot_signing_key = "..."           # publisher only
   snapshot_signing_key_id = "pilot-2026-07"
   snapshot_trusted_keys = [{ key_id = "pilot-2026-07", public_key = "..." }]
   snapshot_tenant_id = "partner-tenant"
   snapshot_deployment_id = "pilot-vpc"
   snapshot_max_age_secs = 3600           # fail-closed policy expiry
   ```

   Exact field validation lives in
   `crates/ferrogate-config/src/config/signed_snapshot.rs`; a config that
   validates always constructs. Offline behavior: on publisher outage,
   replicas serve the last verified snapshot until `not_after`, then fail
   closed — there is no silent operation on expired security policy.

4. **Wire health/rollout hooks.** `/healthz` for liveness, `/readyz` for
   load-balancer readiness (ready only with a valid state revision and not
   draining), and `POST /admin/v1/drain` before terminating a node.

5. **Verify the deployment.**
   - `/readyz` green on every replica.
   - Admin status shows `provider: supabase`, storage health, and cluster
     sync state (active revision, last success, rejection reason if any).
   - Send one chat completion through the gateway with a pilot API key and
     confirm a request log + billing record exists.

## 3. Connect the real agent/MCP workload

1. **Model traffic:** point the workload's OpenAI-compatible base URL at
   the gateway (`/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`
   are governed paths) using a scoped `[[api_keys]]` entry with explicit
   `scopes`, model/provider allow-lists, token budget, and RPM limit.
2. **MCP traffic:** register the partner's MCP servers under
   `[[mcp_servers]]` (streamable HTTP transport, header auth via
   `value_env`). Per-user MCP OAuth identity is real or rejected at
   validation (#202) — unsupported identity modes fail config validation
   rather than silently degrading.
3. **Target-level capability policy (#204):** grant the agent only the
   concrete targets it needs — specific MCP server/tool, filesystem path
   glob + operation, network host/port/method, secret destination, CLI
   argv shape. Grants are additive; ambiguous target resolution denies.
   Start from a deny-by-default posture and add targets as the workload
   exercises them (denials are visible as decision evidence, so widening
   is data-driven, not guesswork).
4. Confirm end-to-end: one MCP tool call from the real workload appears in
   the request log with identity, capability decision, and billing
   attribution.

## 4. Turn on shadow-mode guardrails

Guardrail policies are versioned resources with revisions
(`draft`/`active`/`archived`) and per-policy `mode = enforce | shadow`
(`crates/ferrogate-guardrails/src/policy.rs`). Shadow mode evaluates and
records evidence but never blocks — that is the promotion safety net.

Admin API surface (all in `docs/openapi/admin-api.openapi.json`):

- `POST /admin/v1/guardrail-policies` — create a policy
- `POST /admin/v1/guardrail-policies/{policy_id}/revisions` — new revision
- `POST /admin/v1/guardrail-policies/{policy_id}/dry-run` — test content
  against a revision before activating anything
- `POST /admin/v1/guardrail-policies/{policy_id}/activate` — activate a
  revision
- `POST /admin/v1/guardrail-policies/{policy_id}/rollback` — return to a
  prior revision

Steps:

1. Author the pilot's initial checks: deterministic secret/PII patterns
   (in-repo, zero external calls) and, if the detector services are
   deployed, `presidio` (DLP/PII, span-redaction capable) and
   `llm_guard_prompt_injection` (detect-only) provider kinds. Scope with
   `PolicyScopeSelector` (tenant/org/project/workspace/api-key/service
   account) so only the pilot workload is affected; managed-action checks
   scope by class and canonical target (e.g. one `mcp:server:tool`).
2. Set `mode = "shadow"` on every semantic check. Streaming responses use
   the policy's streaming mode (`buffer_and_enforce`,
   `shadow_after_complete`, or `reject_streaming`) — start with
   `shadow_after_complete` for latency-sensitive streams.
3. Dry-run known-bad samples from `onboarding-demo.md`, then activate.
4. Let real traffic run 1–2 weeks. Evidence accrues per request in
   `/admin/v1/guardrail-evaluations` — every check records verdict, action,
   shadow-vs-enforced, fail-vs-detector-error, latency, and policy/detector
   versions, with content stored only as HMAC fingerprints and categories.

## 5. Promote to enforce

Promotion is a data decision, not a leap of faith:

1. Export the shadow window's evaluations; have the workload owner label a
   sample (the evaluation runner in
   `crates/ferrogate-guardrails/src/evaluation.rs` computes
   precision/recall/F1, FP/FN case ids, and latency percentiles against
   labels — targets in `success-criteria.md`).
2. For each check meeting its precision target, create a new revision with
   `mode = "enforce"` (scope-by-scope if desired — the selector lets you
   enforce for one project while others stay shadow) and activate it.
3. Keep the rollback path warm: `.../rollback` restores the prior revision
   in one call; verify once during the pilot, on purpose.
4. Enforcement semantics the partner should verify live (all shipped and
   E2E-tested, #200/#199): blocked input produces no provider/tool side
   effect and no usage charge; redaction rewrites arguments/results before
   model/client consumption and before logs; `RequireApproval` routes
   through `/admin/v1/tool-approvals` bound to the canonical post-transform
   action fingerprint; non-idempotent actions are never auto-retried;
   detector outage behavior is explicit per check (fail closed for
   security-critical checks) rather than silent pass.

## 6. Investigation and evidence walkthrough

Run this once as a drill during the final pilot week (it is also the
timed exercise in `success-criteria.md`):

1. Pick a real blocked or redacted request from the enforce window.
2. Start from a single identifier — request id, trace id, or agent-run
   id — in the Admin console investigation view, or
   `GET /admin/v1/investigations?request_id=...`.
3. The unified timeline joins: Identity (who), Route, capability/policy
   decision with policy revision (why, target), Guardrail per-check
   verdicts incl. shadow-vs-enforced and detector versions (what fired),
   Approval records (who allowed), Provider/Tool execution, Usage/Cost
   (what it cost), and final outcome — without touching raw tables.
4. Access to evidence is itself governed: `guardrails.evidence.read` is
   resolved through the permission/role/tenant-binding graph, cross-tenant
   access is deny-tested, and evidence is sanitized by default (no
   prompts, PII/secret text, auth headers, or detector credentials).
5. Note who ran the drill, start/end time, the starting identifier, and
   the answers to who/why/target/action/cost — this feeds both the #199
   usability acceptance and the pilot report.

## 7. Teardown / rollback

- Drain each node (`POST /admin/v1/drain`) before termination.
- The evidence database is the partner's; retention is configurable and
  deletion is their call. Nothing pilot-related lives outside the VPC.
- Rotate any provider keys and the snapshot signing keypair issued for the
  pilot.
