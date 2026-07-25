---
name: ferrogate-multi-agent-loop
description: Use when running FerroGate development as TWO cooperating autonomous agents — a development driver that fans slices out across worktree-isolated subagents and a separate test gate that verifies them — coordinating through the GitHub Project board (e.g. "run the dev loop and the test gate", "keep the board moving with both agents", setting up the dev-agent/test-agent split). Covers the choreography, the board handoff (Ready → In progress → In review & Test → Done | back to Ready + gate-rejected), and the shared GraphQL quota discipline. For one role only, use the ferrogate-dev-loop skill (driver) or the ferrogate-test / ferrogate-test-strategy skills (gate).
---

# FerroGate Two-Agent Development Loop

Full contract: **`docs/autonomous-dev-loop.md`** (read it before driving either
role). This skill is the collaboration overview — how the **development driver**
and the **test gate** run in parallel and hand off through the board. Each role
also has a focused skill: `ferrogate-dev-loop` (driver checklist) and
`ferrogate-test` + `ferrogate-test-strategy` (gate tooling / layering).

## The two roles

| | Development driver | Test gate |
| --- | --- | --- |
| Watches | Backlog / Ready / In progress | In review & Test **only** |
| Produces | code on `main`; slices parked in "In review & Test" | Done (pass) or Ready + `gate-rejected` (fail) |
| Proof it owns | unit / build / narrow harness | full `ferrogate-test` E2E harness coverage |
| Never does | E2E; the Done transition | writes product code; moves cards left past Ready |

The board is their **only** message bus. They never move the same card in the
same direction, so the flow is a one-way pipeline with a single fail-back edge:

```
Ready ──► In progress ──►(driver: dev + integrate)──► In review & Test
                                                            │
                                    ┌───────(gate: PASS)────┴───(gate: FAIL)────┐
                                    ▼                                            ▼
                                  Done                              Ready + gate-rejected
                                (+ close)                        (+ comment: failed boxes)
```

## The handoff contract

- **Driver → gate:** a slice enters "In review & Test" only when its acceptance
  list is *deliverable as written* (every box done-and-tested, or re-scoped by
  editing the issue first). A `Not-tested:`/"deferred" note is an admission, not
  an excuse. Epics with a Playwright/E2E box are **not** Test-ready on dev-alone
  — keep them In progress; the gate advances them.
- **Gate → driver:** on FAIL the gate moves the item back to **Ready**, adds the
  **`gate-rejected`** label, and comments the exact failed boxes. The driver
  treats a `gate-rejected` Ready item as the next slice — read the comment,
  fix only what failed, do not redo landed work.
- **PASS bar:** the gate passes an item only when the `ferrogate-test` harness
  covers the feature end-to-end. If the scenario is missing, the **gate writes
  it** (harness is gate-owned) — it does not bounce the item for that.

## Shared discipline (both agents)

- **GraphQL quota is critically scarce and shared** (5000/hr across both agents).
  `gh project ...` *and* `gh issue view/list/comment/close` burn it; only
  `gh api repos/...` REST and `git` are safe. Use the lane tools
  (`dev-lane` for the driver, `gate-lane`/`board-test-lane` for the gate) — ~5
  points vs ~100 for `gh project item-list`. Cache to **separate** files
  (driver `/tmp/dev-board.json`, gate `/tmp/board.json`; both may append the
  stable item-id map `/tmp/item_ids.json`). Reconcile the board once per cycle;
  a lane move does not bump `updatedAt`, so REST probing alone misses arrivals.
- **Shared checkout.** Both share `/home/dev/ferrogate`. The driver integrates
  in a throwaway worktree (never the main dir, which may hold gate WIP); the
  gate runs `git status --porcelain` before every test run and refuses to test a
  tree dirtied by someone else. Never build in the main worktree — its `target/`
  is the silent disk killer.

## Board handles

- Project #4 `PVT_kwHOBQOh784BdpVt` (owner `lianluo-esign`), Status field
  `PVTSSF_lAHOBQOh784BdpVtzhYJbgM`. Option IDs: Epic `190dc6f3`,
  Backlog `f75ad846`, Ready `61e4505c`, In progress `47fc9ee4`,
  In review & Test `df73e18b`, Done `98236657`.

## Invariants (neither agent violates)

1. Driver advances only to **In review & Test**, never Done. Gate owns Done.
2. ≤ 3 code-developing subagents in parallel (user-controlled ceiling).
3. Delete every worktree the instant its slice is integrated (~13 GB each).
4. Default to **zero GraphQL per loop tick**; git + REST keep flowing when the
   Projects quota is exhausted — defer board reads/moves, batch after reset.
