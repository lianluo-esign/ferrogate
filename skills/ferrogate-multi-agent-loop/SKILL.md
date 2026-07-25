---
name: ferrogate-multi-agent-loop
description: Use when running FerroGate development as THREE cooperating autonomous agents — a code-generation-only dev driver that fans slices out across worktree-isolated subagents, a code-review agent, and a test gate — coordinating through the GitHub Project board (e.g. "run the dev loop, the review and the test gate", "keep the board moving with all three agents", setting up the dev/review/test split, or checking what a neighbouring role will do with your output). Covers the choreography, the board handoff (Ready → In progress → In review → Testing → Done, with every failure bouncing back to Ready), the seven Status option IDs, and the shared GraphQL quota discipline. For one role only, use ferrogate-dev-loop (dev), ferrogate-code-review (review), or ferrogate-test / ferrogate-test-strategy (gate).
---

# FerroGate Three-Agent Development Loop

Full contract: **`docs/autonomous-dev-loop.md`** (read it before driving any
role). This skill is the **shared reference**: read it to understand all three
roles — which lane each watches, what it may and may not do, and what the
neighbouring roles will do with your output. Each role also has a focused skill:
`ferrogate-dev-loop` (dev checklist), `ferrogate-code-review` (review), and
`ferrogate-test` + `ferrogate-test-strategy` (gate tooling / layering).

## The three roles

| | Development driver | Code-review agent | Test gate |
| --- | --- | --- | --- |
| Watches | Backlog / **Ready** (incl. bounced items) / In progress | **In review** only | **Testing** only |
| Produces | code on `main`; slices parked in "In review" | Testing (pass) or Ready + findings (fail) | Done (pass) or Ready + `gate-rejected` (fail) |
| Proof it owns | `cargo build` / `cargo test` + the repo's local gates | TBD by the code-review session | full `ferrogate-test` **end-to-end** coverage |
| Never does | self-review; E2E; the Testing/Done transitions | moves cards past Testing; product code (TBD) | writes product code; moves cards left past Ready |
| Skill | `ferrogate-dev-loop` | `ferrogate-code-review` | `ferrogate-test` |

The board is their **only** message bus. No two of them move the same card in
the same direction, so the flow is a forward pipeline with **one shared
fail-back edge: every rejection, from any stage, returns the issue to Ready.**

```
Backlog ─┐
         ├─► In progress ──(dev: code + local gates)──► In review ──(review PASS)──► Testing ──(test PASS)──► Done
Ready ───┘       ▲                                          │                          │            (+ close)
                 │                                          │ FAIL                     │ FAIL
                 └────────────────── Ready ◄────────────────┴──────────────────────────┘
                              (findings in the issue comments)
```

Because a bounce skips back over In progress, an issue can cross the board
several times. **Ready is the dev agent's rework inbox**, not just a queue of
fresh work.

## The handoff contract

- **Dev → review:** a slice enters "In review" only when its acceptance list is
  *deliverable as written* (every box implemented, or re-scoped by editing the
  issue first). A `Not-tested:`/"deferred" note is an admission, not an excuse.
  The dev role writes the E2E-facing surface (harness scenario, Admin API,
  Playwright flow) but never *runs* end-to-end — that is the test agent's job.
- **Review → test:** on pass the code-review agent moves the item to
  **Testing**. Its pass bar is **TBD by the code-review session**.
- **Test → Done:** the gate passes an item only when the `ferrogate-test`
  harness covers the feature end-to-end. If the scenario is missing, the **gate
  writes it** (harness is gate-owned) — it does not bounce the item for that.
- **Anyone → dev:** on FAIL the item goes back to **Ready** with a comment
  listing exactly what failed; the test gate also adds the **`gate-rejected`**
  label. The dev driver treats such a Ready item as the next slice — read the
  comment, fix only what failed, do not redo landed work.

## Shared discipline (all three agents)

- **GraphQL quota is critically scarce and shared** (5000/hr across all three
  sessions). `gh project ...` *and* `gh issue view/list/comment/close` burn it;
  only `gh api repos/...` REST and `git` are safe. Use the lane tools (~5 points
  vs ~100 for `gh project item-list`): `dev-lane` for the dev driver,
  `gate-lane`/`board-test-lane` for the gate (both still default to the old
  `In review & Test` name — point them at **Testing**). Cache to **separate**
  files per session (dev `/tmp/dev-board.json`, gate `/tmp/board.json`; all may
  append the stable item-id map `/tmp/item_ids.json`). Reconcile the board once
  per cycle; a lane move does not bump `updatedAt`, so REST probing alone misses
  arrivals.
- **Shared checkout.** All three share `/home/dev/ferrogate`. The dev driver
  integrates in a throwaway worktree (never the main dir, which may hold another
  session's WIP); the gate runs `git status --porcelain` before every test run
  and refuses to test a tree dirtied by someone else. **Never build in the main
  worktree** — its `target/` is the silent disk killer. Delete every worktree the
  instant its slice is integrated (~13 GB each).

## Board handles

- Project #4 `PVT_kwHOBQOh784BdpVt` (owner `lianluo-esign`), Status field
  `PVTSSF_lAHOBQOh784BdpVtzhYJbgM`. Seven Status options:

  | Lane | Option ID | Owner |
  | --- | --- | --- |
  | Epic | `190dc6f3` | — |
  | Backlog | `f75ad846` | dev |
  | Ready | `61e4505c` | dev (rework inbox) |
  | In progress | `47fc9ee4` | dev agent |
  | In review | `df73e18b` | code-review agent |
  | Testing | `74839551` | test agent |
  | Done | `98236657` | test agent |

- "In review" is the **renamed** "In review & Test" lane (same id `df73e18b`, so
  nothing migrated); "Testing" (`74839551`) is the new lane between review and
  Done.

## Invariants (no agent violates)

1. Dev advances only to **In review**, never further. Review owns → Testing;
   the gate owns → Done.
2. Every failure bounces to **Ready** — never to In progress, never one lane
   back.
3. ≤ 3 code-developing subagents in parallel (user-controlled ceiling).
4. Delete every worktree the instant its slice is integrated (~13 GB each);
   never build in the primary working directory.
5. Default to **zero GraphQL per loop tick**; git + REST keep flowing when the
   Projects quota is exhausted — defer board reads/moves, batch after reset.

## Loop prompts

Each role's cron directive lives in its own skill, so a session can copy the one
it needs without reading the others:

| Role | Watches | Loop prompt |
| --- | --- | --- |
| Dev (code generation only) | `Backlog` + `Ready` | `skills/ferrogate-dev-loop` → "Loop prompt (dev session)" |
| Code review | `In review` | `skills/ferrogate-code-review` → "Loop prompt (code-review session)" |
| Test (E2E) | `Testing` | `skills/ferrogate-test` → "Loop prompt (test session)" |

All three are started with `/loop 5m <directive>` and share one GitHub GraphQL
quota — which is why every directive carries the same rationing clause.
