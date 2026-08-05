# Tenant Usage, Evaluation, and Audit Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Follow this plan step by step and verify each change before moving on.

**Goal:** Move tenant-owned usage, evaluation, anomaly, experiment, audit evidence, and derived rollup authority to Tenant Durable Objects while keeping documented, idempotent control-plane projections.

**Architecture:** Tenant Durable Objects are authoritative for tenant-scoped rows and append-only audit chains. Control D1 retains platform-shared state and narrow projections keyed by tenant and source identity. Gateway and control-plane readers resolve a tenant object before reading tenant-owned data; projection writes are retryable and idempotent.

**Tech Stack:** TypeScript, Cloudflare Durable Objects with SQLite, D1-compatible storage facades, Vitest, Bun, Wrangler, GitHub CLI.

---

## 1. Establish the PR baseline

- [ ] Add or update tenant and control SQL migrations for the ownership and projection boundaries described in docs/design/tenant-data-classification-2026-08.md.
- [ ] Regenerate storage schema modules with the repository generator.
- [ ] Run the affected package typechecks and focused Vitest suites before implementation and record unrelated baseline failures.
- [ ] Commit the plan and baseline setup, push feat/issue-852-usage-evaluation-audit, and create a PR linked to #831, #852, and #825.

## 2. Move usage authority and projections

- [ ] Add red tests for usage rollup authority, observed agent presence, agent cost burn, and projection idempotency.
- [ ] Route production metering writes and reads through the request-scoped tenant database accessor.
- [ ] Keep only documented control-plane projections and make retries safe by tenant and source period/event identity.
- [ ] Verify atomic usage writes and cross-tenant isolation with TenantDataObject tests.

## 3. Move evaluation, anomaly, experiment, and audit authority

- [ ] Add red tests for tenant-scoped online evaluation, regression, spend anomaly episode, experiment leg, and audit-chain writes.
- [ ] Route producers and control-plane workflows through the tenant object while retaining platform-shared policies and run claims in control D1.
- [ ] Repair the asset audit writer so pending rows are partitioned by tenant and appended through the tenant audit chain.
- [ ] Project tenant rows to control D1 with explicit tenant fences and retry-safe keys.

## 4. Verify readers and workflows

- [ ] Add or update fleet-read, projection-retry, audit-chain, and cross-tenant SQL-fence tests.
- [ ] Run focused storage, gateway, and control-plane tests, then package typechecks and the relevant Durable Object configuration.
- [ ] Run the repository E2E harness for the affected admin and gateway workflows when the local environment supports it.
- [ ] Record any unrelated pre-existing failures separately from regressions introduced by #852.

## 5. Independent audit and integration

- [ ] Ask an additional agent to perform a read-only audit of tenant authority, projection retries, chain integrity, cross-tenant fences, and fallback paths.
- [ ] Independently inspect every audit finding, fix valid issues, and rerun the affected verification.
- [ ] Commit and push the implementation, request/complete review, then merge the PR with gh pr merge --admin --squash.
- [ ] Confirm the issue and PR state, then delete the PR branch and its worktree while preserving unrelated worktrees.
- [ ] Fast-forward or update local main, verify it is clean, and report the exact merge and test evidence.
