<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-23
  description: Token4AI Cloud, FerroGate AI Gateway, autonomous parallel development loop constraints.
-->

# Autonomous Parallel Development Loop

This document defines the binding constraints for running FerroGate development
as an **autonomous, continuously-iterating loop that fans work out across
parallel subagents**. It extends `docs/dynamic-workflow.md` (which governs a
single serial slice) with the rules that make *parallel* multi-agent iteration
safe: board discipline, GraphQL quota budget, a hard concurrency ceiling,
worktree isolation, and mandatory disk cleanup.

It is the contract a driver agent follows when told to "keep iterating on the
board" without naming a single issue.

## Goal and boundary

- Continuously pull sub-issues off the GitHub Project board and advance them,
  through real implementation + local verification, up to the **In review &
  Test** lane — and **stop there**. Never move an issue to **Done**.
- A separate **test agent** owns the "In review & Test" lane: it runs targeted
  coverage/E2E against whatever sits there. The development driver does **not**
  do end-to-end testing; its job ends when a slice is unit/build-verified and
  parked in "In review & Test" for that test agent.
- Do not close epics. Land one coherent slice, keep the epic open with a
  progress comment (per `docs/dynamic-workflow.md`).

## The board

- Project **#4** (`PVT_kwHOBQOh784BdpVt`, owner `lianluo-esign`).
- `Status` field `PVTSSF_lAHOBQOh784BdpVtzhYJbgM`; lane order:
  **Epic → Backlog → Ready → In progress → In review & Test → Done**.
- The development driver moves sub-issues rightward up to and including
  **In review & Test** (option id `df73e18b`). The **Done** transition belongs
  to the test agent / human review, never to the development driver.

## GitHub Projects GraphQL quota discipline

The org has a **limited GitHub Projects GraphQL quota**. Exhausting it makes the
Project board unusable. Therefore:

- **Only touch the Projects API (`gh project ...`) at key nodes**: the initial
  planning read, and each status move of a completed slice. Nothing else.
- **Cache the board once per planning pass.** Dump
  `gh project item-list 4 --owner lianluo-esign --format json --limit 800` and
  the field/option IDs (`gh project field-list 4 ...`) to local files, then
  reuse those item/field/option IDs for the rest of the pass instead of
  re-querying.
- **Reading individual issues is fine.** `gh issue view <n>` / `gh issue
  comment` / `gh issue create` use the general REST/GraphQL budget, which is not
  the constrained Projects quota. Subagents read their own issue this way and
  must **never** call `gh project ...`.

## Concurrency ceiling

- **At most 3 subagents developing code in parallel.** Hard ceiling, never
  exceeded. Fewer is fine; hold a slot as integration margin when the in-flight
  slices touch shared crates.
- On each loop tick, if the cap is already full, **hold** — do not launch more
  and do not re-read the board. Integrate finished work first.

## Worktree isolation and slice selection

- Every subagent runs in its **own git worktree** (isolated copy) on its own
  branch. It implements, unit-tests, and **commits to its branch only — it does
  not push and does not touch `main`.**
- Pick **maximally file-separated slices** so parallel edits cannot collide:
  different crates, or `admin-console/` (TypeScript) vs Rust crates, or a brand
  new crate. Two agents must not edit the same module concurrently. When two
  candidate slices share a crate/file, pick a different pair or serialize them.

## Integration flow (driver, sequential)

For each completed subagent, integrate one at a time on `main`:

1. `git fetch origin main`; confirm fast-forward/clean base.
2. **Cherry-pick** the agent's branch commit(s) onto `main` (keeps linear
   history; avoids merge commits from stale worktree bases).
3. **Re-verify the combined state** — the merged `main` may combine two agents'
   edits to a shared file that neither tested together. Run the narrowest
   credible `cargo build` / `cargo test` (or `tsc`/`vitest` for admin-console)
   that proves the combined result compiles and passes.
4. `git push origin main`.
5. Comment the issue with the commit sha + exact verification evidence
   (what was run, what passed, what was **not** tested and why).
6. Move the board status to **In review & Test** (the one allowed Projects
   mutation).
7. **Delete the worktree immediately** (see below).
8. File any follow-up issues the slice surfaced (house style, issue-linked),
   rather than leaving TODOs in chat.

## Verification gate before "In review & Test"

Local unit/build proof only — this loop does not run E2E:

- `cargo fmt --all -- --check`, then the narrowest `cargo build -p <crate>` and
  `cargo test -p <crate> <filter>` that prove the slice; `clippy -D warnings`
  and `scripts/check-openapi.py` when the change warrants them.
- For `admin-console/`: `tsc -b`, `vitest run`, `lint`, and the bundle-budget
  build.
- Record anything not provable locally (e.g. live-Postgres) as **not tested** in
  the issue. Do not trigger cloud CI (release-only, per AGENTS.md).

## Worktree cleanup is mandatory (disk safety)

Each worktree's `cargo build` creates its own multi-GB `target/` (observed
~13 GB per Rust worktree). Leftover worktrees consume disk without bound.

- **Delete every worktree the moment its task is done and integrated:**
  `git worktree remove --force .claude/worktrees/agent-<id>` and
  `git branch -D worktree-agent-<id>`.
- At any instant, only the **currently-running** agents' worktrees (≤3) may
  exist on disk. Never leave an integrated worktree behind.
- Do **not** remove a worktree of a still-running agent (it is `locked`).
- Periodically confirm with `df -h .` and `du -sh <wt>/target`.

## Commit requirements

Every integrated commit follows AGENTS.md "Commit Requirements": reference the
issue in the subject (e.g. `(#367) ...`), include a closing/related trailer, and
use Lore trailers (`Constraint:`, `Rejected:`, `Tested:`, `Not-tested:`,
`Confidence:`, `Scope-risk:`, `Refs #<n>`) for non-trivial changes.

## Lane-entry contract (test-gate rule, added 2026-07-23)

An issue may move into **In review & Test** only when its acceptance list is
**deliverable as written** — every checkbox either implemented-and-tested or
explicitly re-scoped by editing the issue BEFORE the lane move. The gate
rejects on the first unmet box; a commit's `Not-tested:`/"deferred" note is
treated as an admission, not an excuse.

Hard rules learned from 14 consecutive gate rejections (#340-#360 era):

- **The E2E/operator-facing boxes are part of the issue.** A library-complete
  slice with the harness scenario, Admin API surface, Playwright flow, or
  write-read compliance proof "deferred to later work" fails the gate.
- **Landing incremental slices on main is encouraged; moving the issue to the
  lane is not** until the last acceptance box is closed. Keep the issue in
  "In progress" between slices.
- **If part of the scope must move out, edit the issue** (split a follow-up,
  shrink acceptance) before the lane move, and say so in a comment.
- Rejected issues return to **Ready** carrying the `gate-rejected` label and a
  comment listing exactly which boxes failed; remove nothing from that list
  when re-entering.
