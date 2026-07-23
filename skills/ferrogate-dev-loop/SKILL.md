---
name: ferrogate-dev-loop
description: Use when running FerroGate development as an autonomous, continuously-iterating loop that fans work out across parallel subagents against the GitHub Project board (e.g. "keep iterating on the board", "持续迭代开发", a /loop that advances issues). Covers the binding constraints — advance sub-issues only up to "In review & Test" (never Done), Projects GraphQL quota discipline, the max-3 parallel-subagent ceiling, worktree isolation + slice separation, the cherry-pick integration flow, and mandatory worktree cleanup to bound disk. Not for a single named-issue slice (use docs/dynamic-workflow.md).
---

# FerroGate Autonomous Parallel Dev Loop

Full contract: **`docs/autonomous-dev-loop.md`** (read it before driving the
loop). Single-slice serial workflow: `docs/dynamic-workflow.md`. This skill is
the quick operational checklist.

## The invariants (do not violate)

1. **Advance to "In review & Test", never to Done.** A separate test agent owns
   the "In review & Test" lane and runs targeted coverage there. This loop does
   unit/build proof only, never E2E, and never the Done transition.
2. **Projects GraphQL quota is scarce.** Call `gh project ...` only at key nodes
   (initial plan read; each completed slice's status move). Cache the board dump
   + field/option IDs to local files and reuse them. `gh issue view/comment/
   create` are fine (general budget); subagents must never call `gh project`.
3. **≤ 2 code-developing subagents in parallel.** Hard ceiling (lowered from 3, 2026-07-23). If full on a
   loop tick, hold — integrate finished work, don't launch more, don't re-read
   the board.
4. **Delete every worktree the instant its slice is integrated.** Each Rust
   worktree's `target/` is ~13 GB. Only running agents' worktrees may exist.

## Board handles

- Project #4 `PVT_kwHOBQOh784BdpVt` (owner `lianluo-esign`).
- Status field `PVTSSF_lAHOBQOh784BdpVtzhYJbgM`; lanes
  Epic → Backlog → Ready → In progress → In review & Test → Done.
- "In review & Test" option id `df73e18b`.

## Per-slice loop

1. **Plan (key node):** cache board + IDs once; pick up to 3 **maximally
   file-separated** slices (different crates, or `admin-console/` vs Rust, or a
   new crate). Prefer In-progress → Ready → Backlog; P0/P1 first.
2. **Dispatch** each as a worktree-isolated subagent (≤2 at a time). It reads its own issue
   (`gh issue view`), implements narrowly per AGENTS.md, adds sibling
   `*_test.rs` (no inline `mod tests {}`) tests, verifies locally, and **commits
   to its branch only — no push, never touches `main`**.
3. **Integrate (driver, sequential):** `git fetch` → `git cherry-pick <branch>`
   → **re-verify the combined `main`** (narrowest `cargo build`/`test`, or
   `tsc`/`vitest`) → `git push` → comment issue with sha + evidence (incl. what
   was **not** tested) → move board status to **In review & Test** (key node).
4. **Cleanup:** `git worktree remove --force .claude/worktrees/agent-<id>` +
   `git branch -D worktree-agent-<id>`. File follow-up issues the slice
   surfaced (issue-linked, house style).

## Commit gate

Issue-referenced subject `(#<n>) ...` + Lore trailers (`Constraint:`,
`Rejected:`, `Tested:`, `Not-tested:`, `Confidence:`, `Scope-risk:`,
`Refs #<n>`). See AGENTS.md "Commit Requirements".
