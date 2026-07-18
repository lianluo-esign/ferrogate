# Plan — 2026-07-18 unattended kanban round

Autonomous loop iteration plan. Source: open issues (priority-ordered). Board API currently
lacks `read:project` scope, so status tracking happens on the issues themselves
(progress comments while open, evidence-chain comment on close).

## Issue triage (open issues, 2026-07-18)

| Issue | Prio | Decision |
|---|---|---|
| #193 / #194 / #209 | P0 | Epics / design-partner product validation — not autonomously codeable; skip. |
| #232 | P1 | **PICK** — tenant-scope admin accounts/roles/refresh tokens. Postgres validation is now unblocked (live Supabase reachable). |
| #227 | P1 | **PICK (deliverable subset)** — per-VM rootfs isolation config + test asserting `read_only_rootfs` policy is enforced in drive config. Real-Firecracker boot validation stays open. |
| #205 / #206 | P1 | Infra-blocked in sandbox (Docker/prod isolation backend, customer-VPC signing) — skip this round per sandbox closure policy unless a deliverable subset emerges. |
| #199 | P1 | Previously human-usability-blocked; re-check after this round. |
| #201 | P1 | Autonomous half already landed; remainder vendor/design-partner-gated — keep open, skip. |
| #231 | P2 | **PICK** — bound worker/agent-run stores + push filtering into SQL; Postgres retention now validatable against live Supabase. |
| #233 | P2 | **PICK** — response cache must respect tightened response-stage guardrails on hit. |

## Execution model

Parallel background worktree agents draft; main session reviews diffs, re-runs gates,
lands on `main`, validates the Postgres-touching changes against the live Supabase
(DSN-gated roundtrip tests + MCP schema checks), pushes, and closes issues with
evidence chains.

- Agent A → #232: add `tenant_id` to admin refresh tokens (schema + migration + re-issue
  path), tenant-scoped SCIM deactivate/delete + per-tenant refresh revocation,
  tenant-owned role catalog with owner-gated upsert and tenant-filtered listing.
- Agent B → #231: retention caps for `agent_run_events` + per-worker distinct-id caps for
  artifacts/checkpoints (oldest-eviction, without truncating active run timelines),
  Postgres retention/pruning, SQL-side `worker_id`/`run_id` filters + `LIMIT` for the
  three hot read paths.
- Agent C → #233: include guardrail-policy revision in `ai_response_cache_key` (or
  re-evaluate response-stage guardrails on hit) + regression test.
- Agent D → #227 subset: per-VM writable overlay/CoW rootfs layout in
  `configure_and_start_firecracker` behind config, `is_read_only` honoring the declared
  `IsolationFilesystemPolicy`, test asserting drive config matches policy. Boot
  validation on a real Firecracker host remains the open tail of #227.

## Gates before landing (main session, per change)

1. `cargo +1.88.0 fmt --check`
2. `cargo +1.88.0 clippy` scoped to touched crates, `-D warnings`
3. Scoped tests for touched crates (box currently 24 cores / 30 GB — full links OK)
4. For storage/schema changes: DSN-gated Supabase roundtrip tests + live schema check
5. `security-check` where applicable
6. Commit → push → issue progress/closing comment with evidence chain
