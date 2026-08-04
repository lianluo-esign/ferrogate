# M9 Step 1: Request Logs and Agent Runs in Tenant Objects

> Execution plan for #859. Keep the control-D1 copy only as the explicitly
> labeled derived compatibility projection described in the design spec.

## 1. Establish the schema and runtime red test

- Add one focused real-workerd test to `packages/storage/test/do/tenant-data-object.test.ts` that mutates two tenant objects with request-log, run, and event rows, then asserts object isolation and event ordering.
- Run only that test and record the expected `no such table` failure before adding production code.
- Add tenant migration `0012_request_logs_agent_runs.sql` with tenant-enforced tables, full request-log columns, run/event JSON payloads, and lookup/order indexes.
- Regenerate `packages/storage/src/tenant-schema-sql.ts` and update the real-object table census/version assertions.

## 2. Make writers object-authoritative

- Add a small storage-facing helper for exact tenant evidence database access that rejects non-Durable-Object sources rather than falling back to control D1.
- Update gateway request-log direct and queue paths to partition by tenant, write one batch per tenant object, then write the derived control projection. Preserve queue retry behavior, append throughput, and the current non-fatal sink contract.
- Update `AgentRunState` lifecycle creation, transitions, cancellation, and event append to persist full evidence in the tenant object and update the derived control projection. Keep the live run-state keys for runtime behavior.
- Add required test/runtime bindings without changing the isolated worktree or shared-control authority boundary.

## 3. Replace tenant-scoped investigation reads

- Add exact-tenant read helpers for request logs, agent runs, and events.
- Change admin request-log investigation to discover candidate tenant ids from the labeled projection only, then fetch request/run/event rows from each exact object with an explicit tenant fence.
- Replace the generic agent-run route's evidence reads with exact object reads for tenant scope and keep only the documented projection-backed platform page path.
- Update retention cleanup to delete authoritative object rows first and then delete projection rows.

## 4. Guard and document fleet compatibility readers

- Add source-of-truth comments/guards around control-D1 request-log and agent-evidence access.
- Keep the existing cost, experiment, FinOps, and SIEM fleet joins on the derived projection until #825 supplies their bounded fan-out/rollup contract, with as-of labeling where the surface exposes freshness.
- Update the classification/design documentation with the complete reader disposition and exact cross-tenant path. Mention Analytics Engine only as future work.

## 5. Test and verify

- Add mutation-backed storage, writer, queue, investigation, projection-authority, ordering, and tenant-isolation tests.
- Run focused storage/gateway/agent/control-plane tests, relevant full package suites, typechecks, lint/format checks, and `git diff --check`.
- Commit in reviewable slices, push after every commit, keep the PR body linked to #859/#831/#825, and do not merge or delete the branch/worktree.

