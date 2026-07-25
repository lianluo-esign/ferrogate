---
name: ferrogate-code-review
description: Use when running the FerroGate code-review role of the three-agent board loop — the session that watches the GitHub Project "In review" lane, judges what the dev agent handed off, and either advances the item to "Testing" or bounces it back to "Ready" with findings (e.g. "run the review agent", "work the In review lane", "review what the dev loop landed"). Covers the fixed lane/edges, the board handles, and the shared discipline (GraphQL quota rationing, cached lane tooling, worktree isolation, never build in the main worktree). The review methodology itself is this session's to define. Neighbouring roles: ferrogate-dev-loop (upstream) and ferrogate-test (downstream); all three at once: ferrogate-multi-agent-loop.
---

# FerroGate Code-Review Agent

Full contract: **`docs/autonomous-dev-loop.md`**. All three roles at a glance:
`ferrogate-multi-agent-loop`. Upstream role that fills this lane:
`ferrogate-dev-loop`. Downstream role that consumes this lane's output:
`ferrogate-test` (+ `ferrogate-test-strategy`).

This is the **second** of three autonomous sessions. The dev agent generates
code and stops at **In review**; this session judges it; the test gate then
proves it end-to-end in **Testing**.

## What is fixed (set by the project owner — do not renegotiate)

1. **Watch the `In review` lane only** (`df73e18b`). That lane is this session's
   inbox; nothing else is.
2. **PASS → move the item to `Testing`** (`74839551`). That hands it to the test
   agent, which owns all end-to-end proof.
3. **FAIL → return the item to `Ready`** (`61e4505c`) with the findings in an
   issue comment. Every bounce in this loop lands in Ready — never In progress,
   never one lane back. The dev agent treats a returned item as its next slice
   and works from that comment, so the comment must name exactly what failed.
   (Precedent: #428 and #346 were bounced from the review lane to Ready on
   2026-07-25.)
4. **Never move a card past `Testing`.** Done belongs to the test gate.
5. The shared discipline below applies to this session like any other.

## What is TBD by this session

Everything about the review *method* is undefined and **must not be invented by
another session**. This session defines it and then documents it here:

- **TBD by the code-review session:** what it actually inspects (diff-only vs
  whole feature, which AGENTS.md rules it enforces, security/observability
  checks, acceptance-box verification, …).
- **TBD by the code-review session:** review depth and stop conditions — how
  much it re-verifies of the dev agent's `cargo build`/`cargo test` evidence,
  whether it builds at all.
- **TBD by the code-review session:** whether it may edit product code itself or
  may only report findings and bounce.
- **TBD by the code-review session:** its pass criteria, and whether a FAIL
  carries a label (the test gate uses `gate-rejected`; nothing obliges this
  session to reuse it).
- **TBD by the code-review session:** its lane tooling and cache file.
  `gate-lane "In review"` reads the lane today; that session may want its own
  mover and its own cache path (see the discipline below — do **not** reuse
  `/tmp/board.json` or `/tmp/dev-board.json`).

Until those are decided, say so explicitly in issue comments rather than
implying a bar that was never agreed.

## Board handles

- Project #4 `PVT_kwHOBQOh784BdpVt` (owner `lianluo-esign`), Status field
  `PVTSSF_lAHOBQOh784BdpVtzhYJbgM`.
- Option ids: Epic `190dc6f3`, Backlog `f75ad846`, **Ready `61e4505c`** (bounce
  target), In progress `47fc9ee4`, **In review `df73e18b`** (this lane, the
  renamed "In review & Test"), **Testing `74839551`** (pass target),
  Done `98236657`.
- Lane order: Epic → Backlog → Ready → In progress → In review → Testing → Done.

## Shared discipline (identical for all three sessions)

- **GraphQL quota is critically scarce and shared** (5000 points/hr across the
  dev, review and test sessions under one user id — observed at 16/5000). Both
  `gh project ...` **and** `gh issue view/list/comment/close` burn it; only
  `gh api repos/...` REST and `git` are free.
  - Read an issue: `gh api repos/lianluo-esign/ferrogate/issues/<n> --jq '.title,.body'`.
  - Comment: `gh api repos/lianluo-esign/ferrogate/issues/<n>/comments -f body=…`.
  - `gh api rate_limit` is free — check it before any board read.
- **Use a cached, status-only lane read**, not `gh project item-list --limit 800`
  (~100 points vs ~5). `dev-lane`/`gate-lane` are the existing pattern: one lean
  GraphQL query, cached to a JSON file, plus a stable issue→item-id map in
  `/tmp/item_ids.json` so a status move needs no board read. **Use a cache path
  of this session's own** — the dev session owns `/tmp/dev-board.json` and the
  gate owns `/tmp/board.json`; they clobbered each other when they shared one.
- **A lane move does not bump `updatedAt`,** so a REST `updatedAt` probe cannot
  see items arriving in In review. Read the lane itself once per cycle.
- **Default to zero GraphQL per tick.** When the quota is low, defer board reads
  and moves, keep working via git + REST, and batch the deferred moves after the
  reset rather than retrying into a wall.
- **Worktree isolation + immediate cleanup.** If this session needs to build or
  run anything, do it in its own throwaway git worktree branched from
  `origin/main`, and delete it (`git worktree remove --force …` +
  `git branch -D …`) the moment the item is judged. Each Rust `target/` is
  ~13 GB.
- **Never build in the primary working directory** (`/home/dev/ferrogate`). All
  three sessions share it and the test gate uses it as its test bed; its
  `target/` once reached 86 GB. Check `git status --porcelain` before relying on
  that tree — if it is dirty with someone else's WIP, touch nothing.
