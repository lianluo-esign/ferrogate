<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

# Dynamic Workflow

This workflow defines how an autonomous agent should keep FerroGate development
moving across the live GitHub issue queue. It is inspired by continuous
development modes such as "ultracode", but it is deliberately bounded by
FerroGate's production gateway rules: small E2E slices, explicit verification,
issue-linked commits, and visible issue updates.

## Goal

Keep shipping verified gateway improvements without waiting for a static plan to
be rewritten after every issue. The workflow dynamically selects the next best
slice from the current issue queue, completes it, records the evidence, and then
continues.

## Loop

1. Refresh repository and issue state.
   - Confirm the worktree is clean or understand any local changes.
   - Fetch `origin/main`.
   - Read open issues with `gh issue list`.
   - Inspect candidate issue bodies before choosing work.

2. Select the next slice.
   - Prefer core gateway functionality over decorative work.
   - Prefer issues that unlock later work, reduce operational risk, or close a
     visible product gap.
   - Choose a slice that can close an E2E path in one development cycle.
   - If an issue is an epic, implement only one coherent acceptance-criteria
     slice and keep the issue open.

3. Define the E2E closure before editing.
   - Identify the operator input: config, Admin API, client API, or runtime
     event.
   - Identify the execution path through the gateway.
   - Identify observable evidence: Admin API, logs, metrics, audit, billing, or
     OpenAPI schema.
   - Identify focused regression and runtime tests.

4. Implement narrowly.
   - Read existing code paths first.
   - Reuse existing config, repository, response, telemetry, and test patterns.
   - Avoid new dependencies unless the issue explicitly requires them or the
     dependency removes more complexity than it adds.
   - Keep hot-path work allocation-light and predictable.

5. Verify before claiming progress.
   - Run the narrow focused tests for the slice.
   - Run schema or docs checks when API/documentation changed.
   - Run `cargo fmt --all -- --check`.
   - Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`
     for meaningful Rust changes.
   - Run `cargo test --workspace --all-features` before final commit unless the
     change is documentation-only.
   - Build FerroGate and `ferrogate-test` locally and run the narrowest matching
     harness scenario in the development container. Use a local Docker image
     only when Docker is available and the scenario specifically needs the
     image boundary.
   - GitHub Actions trigger only on `release: published` and are not a
     per-commit fallback. If local infrastructure or credentials block a
     required proof, record it as not tested in the issue instead of waiting for
     a cloud run that is not allowed to start.

6. Commit and push.
   - Commit every completed slice with the related issue in the subject when
     practical.
   - Use Lore trailers for constraints, rejected alternatives, confidence,
     scope risk, directives, tested commands, and known gaps.
   - Push to `origin/main` unless the user asked not to push.
   - If push is rejected because remote moved, fetch, rebase, re-run relevant
     verification, and push normally. Do not force-push.

7. Update GitHub issues.
   - Close an issue only when all acceptance criteria are actually satisfied.
   - For partial epic slices, comment with the commit, completed scope,
     verification evidence, and remaining work.
   - If a slice reveals a new dependency or blocker, record it in the issue
     instead of hiding it in chat.

8. Continue.
   - Re-check the live issue queue.
   - Pick the next highest-value E2E slice.
   - Stop only when the user stops the workflow, a true blocker remains after
     reasonable alternatives, or the queue has no suitable next slice.

## Selection Heuristics

Use this priority order when the user says to continue development without
specifying an issue:

1. P0/P1 issues and issues recently edited by the user.
2. Commercial gateway differentiators: cluster mode, policy/governance,
   provider orchestration, observability, billing/audit, and agentic-lite tool
   boundaries.
3. Work that unlocks multiple future issues, such as typed config, storage
   contracts, Admin API visibility, or OpenAPI coverage.
4. Narrow documentation only when it is required to make a runtime feature
   operable.

Do not choose a broad rewrite when a smaller vertical slice can prove the next
piece of behavior.

## Done Criteria

A dynamic workflow cycle is done only when all of these are true:

- The chosen slice has an issue reference.
- The implementation has an operator-visible E2E path.
- Tests and checks prove the claimed behavior.
- The matching local `ferrogate-test` scenario passed; an image-boundary proof
  is additionally required only for changes whose behavior depends on an image.
- The commit is pushed.
- The related issue is closed or updated with exact remaining work.
- The worktree is clean.

## Non-Goals

- This workflow is not a substitute for product judgment.
- It does not authorize bypassing tests or issue-linked commits.
- It does not turn FerroGate into an agent runtime.
- It does not require finishing a large epic in one cycle.
