---
name: ferrogate-code-review
description: Use when running the FerroGate code-review role of the three-agent board loop — the session that watches the GitHub Project "In review" lane, judges what the dev agent handed off, and either advances the item to "Testing" or bounces it back to "In progress" with findings (e.g. "run the review agent", "work the In review lane", "review what the dev loop landed"). Covers the fixed lane/edges, the board handles, the review methodology (acceptance-box audit first, static verification only, never builds or runs tests, report-never-edit, `review-rejected` on bounce), and the shared discipline (GraphQL quota rationing, cached lane tooling, worktree isolation, never build in the main worktree). Neighbouring roles: ferrogate-dev-loop (upstream) and ferrogate-test (downstream); all three at once: ferrogate-multi-agent-loop.
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
3. **FAIL → return the item to `In progress`** (`47fc9ee4`) with the findings in
   an issue comment. **Owner directive, 2026-07-27: bounces land in `In progress`,
   not `Ready`** — a rejected item is work already in flight, not a fresh slice to
   be picked. (This reverses the earlier rule; every bounce before 2026-07-27 —
   #428, #346, #352, #414, #493, #517, #518 — went to `Ready`, so a rework
   arriving from there is expected, not a protocol violation.) The dev agent
   works from that comment, so the comment must name exactly what failed.
4. **Never move a card past `Testing`.** Done belongs to the test gate.
5. The shared discipline below applies to this session like any other.

## The review method (v1 — defined by this session 2026-07-25)

The method below was previously marked TBD-by-this-session. It is now decided.
Other sessions do not change it; this session may revise it and re-document it
here.

### What it inspects — the acceptance list is the contract

The **acceptance-box audit is primary**, not the diff. For every checkbox in the
issue body (and every `## Scope` bullet, which the dev agent treats as binding),
find the landed artifact on `origin/main` that satisfies it or record it UNMET
with a reason. The diff is read *second*, to check that what landed matches what
was claimed — a diff can look excellent and still not deliver the issue.

Then, in the diff itself, hunt the recurring failure modes this repo actually
produces:

- stubs / TODOs presented as done; a `Not-tested:` trailer covering an
  **acceptance box** (that is an admission of an unmet box, not an excuse);
- tests that assert nothing, assert only a mock, or merely restate the
  implementation's own arithmetic;
- numbers claimed as *measured* or *sourced* that are estimates or invented
  (an acceptance box saying "not an estimate" means exactly that);
- **missing data reported as `0` where it must read as unavailable** — the
  honesty rule from #458/#464;
- swallowed errors, `unwrap()`/panic on a request path, secrets in logs or
  error strings;
- a second implementation of a governed decision path with no conformance proof
  that both sides decide identically (the #188/#397/#383 divergence class).

Plus `AGENTS.md` commit hygiene: issue-referenced subject, Lore trailers.

### What this actually catches — evidence from the first full cycle

42 items reviewed on 2026-07-25 (15 passed, 27 bounced). The bounce rate is high
**by design**: the dev agent runs in speed mode, so the defects those gates would
have caught arrive here intact — and this lane finds them by reading, then hands
the execution to the test gate.

**Speed mode narrowed again on 2026-07-27** (owner directive, recorded in
`ferrogate-dev-loop` / `ferrogate-multi-agent-loop`): the dev lane now keeps only
**`cargo check --all-targets`** — not even `cargo build`. Tests are still
*written*, never *executed*.

**This session does not close that gap, and must not try to.** Owner directive,
2026-07-27: *"你是 codereview agent 只负责 codereview，而不做任何的单元测试或者其他
测试和编译。编译和测试是交给 test agent 来负责的。"* This lane **reads**. It does
not run `cargo build`, `cargo test`, `cargo clippy`, `cargo fmt`, `vitest`, or
any other compiler or test runner — not even in a throwaway worktree, not even
the narrowest filter. Execution belongs to the test gate, which owns the
`Testing` lane. (This reverses the earlier "read, don't rebuild — build only
when a claim cannot be checked by reading" carve-out: there is now no such
exception.)

What that leaves this session, and it is the larger half:

- **The mutation audit is done by reading, and it always was.** "If I broke the
  thing this test names, would this assertion notice?" is answered by reading
  the assertion, the fixture and the code under test. Every finding this method
  has produced — #460's substring-pinned SQL, #517's unpinned cross-tenant
  guard, #526's `ManagedExternalAction`-only exhaustive match — was visible in
  the source. Report the mutation and the reason it survives; the test gate
  confirms it live.
- **A claim about a gate's result is a claim to audit, not to reproduce.** If a
  commit says `Tested: 107 passed`, check the trailer exists and is specific;
  do not re-run it. If a slice touched a spec and not its generated client, that
  is visible in `git diff --stat` without running the generator.
- **State findings as "would" and let the gate say "did".** An unexecutable
  claim is still a legitimate bounce when the *artifact* is missing, stubbed or
  dishonest — that judgement needs no compiler.
- A `Not-tested:` trailer is now *expected* rather than suspicious; what is
  unacceptable is a silent one, or one covering an acceptance box.
- An interrupted verification can leave a **scratch mutation live in the tree at
  commit time** — #493 shipped with two. Grep the diff for edits that look like
  a deliberately broken assertion.

Four failure modes produced most of the bounces. Hunt them by name:

1. **The code asserts a primitive it never calls.** #414's `cancel()` claimed a
   fiber cancel that was a commented-out example; #427 documented a `SQLITE_FULL`
   prune whose target table nothing writes; #409's secrets seam was landed and
   unused. In each case the README, the docs *and* a Rust mapping table all
   asserted the opposite of the code. **Trace every claimed capability to a real
   call site.** The cost of missing one is not cosmetic: #414's no-op `cancel` was
   the route #428's cost governor used to kill a runaway agent.
2. **The test proves the mock, not the contract.** #343's single hand-written
   fixture backed both the vitest and Playwright suites and encoded a payload shape
   the gateway does not emit — both suites green, product broken. **Weight a test
   by what it would fail on.** Ask: if the implementation were wrong, would this
   assertion notice? If the fixture is hand-written, is it derived from the real
   type?
3. **An acceptance box with no artifact at all**, disclosed only in a handoff
   comment. #472 (nothing materializes a repo), #474 (`/result` can never return
   because nothing advances the run status). Disclosure is the right instinct but
   **does not tick the box** — the fix is to edit the issue or file the split, not
   to note it in a comment.
4. **Missing data rendered as a confident value.** #343 showed `0 / 12` for twelve
   healthy workers and a literal `NaN`; #345 printed a cache policy of `default`
   when the manifest was merely unavailable. Grep the diff for `?? 0`, `|| 0` and
   similar coalescing on anything that is a measurement.

**The biggest gap this method had, found by the stage downstream.** The test gate
filed #500 after bouncing six consecutive items from Testing — **four of them
(#460, #461, #471, #489) had passed this review**. In every case the
implementation was correct and the suite was fully green; what failed is that
*deliberately breaking the load-bearing logic left the suite green too*. 14
mutations survived on #460 alone, 7 of 7 on #471's Worker half.

"Tests that assert nothing" was too vague to catch these. **Apply the operational
form instead: if you can break the thing the test names and the test would still
pass, the test does not cover it.** It is cheap by hand and it is what caught all
six.

The shapes it catches — all of which *read* as thorough — are maintained in one
place, `docs/testing/testing-architecture.md`, section **"Assertions must be
able to fail"** (#500, binding from `AGENTS.md`): the one-minute check, an
eight-row anti-pattern table with the case each row is drawn from, and the two
failures mutation reasoning alone cannot find. Read it once. A second copy here
would be the same two-hand-maintained-claim defect the table's own row 7 names.

Two second-order lessons worth carrying:

- **A defect can be invisible to every repo-wide sweep.** #344 embedded two NUL
  bytes in a `.tsx` file, so git classified it binary and `grep`/`ripgrep` skipped
  it silently — quietly shrinking every coverage claim ever made about that file.
  When a sweep returns suspiciously few hits, check whether the file is text
  (`git grep -Il ''`).
- **A bounce can be undone by a commit trailer.** #417 was bounced to Ready with
  findings, then auto-closed by a `Closes #417` trailer on the same issue's commit,
  so the rework was never visible. **After bouncing, it is worth confirming the
  issue is still open.** Tell the dev agent to prefer `Refs #<n>` until an item
  actually passes.

### Depth and stop condition — read, never build

**Static verification only**: read the code and read the tests. This session runs
no compiler and no test runner at all — see the owner directive above. Beyond
being the rule, it is the right instrument: a test that *passes* while asserting
nothing is exactly the defect being hunted, and reading catches it while
re-running does not. A green suite was never the evidence this lane trades in.

When a claim genuinely cannot be settled by reading, that is a finding to
**report**, not a build to run: name the claim, name what would settle it, and
hand it to the test gate. "This assertion cannot fail, here is the mutation that
proves it" needs no compiler; "this passes live against Postgres" is the gate's
sentence to write, not this session's.

Do **not** stop at the first defect. Complete the acceptance sweep so one bounce
carries the whole list — the dev agent reworks from the comment alone, and a
partial list guarantees a second bounce.

### The PASS/FAIL boundary — do not do the test agent's job

The downstream test agent owns **all** end-to-end and live proof.

- **Never FAIL an item merely because a live/E2E run has not been performed.**
  That is the next lane's work, and bouncing for it stalls the pipeline.
- **DO FAIL** when the code, artifact, test, or harness wiring that a box
  requires is **missing, stubbed, or dishonest**.

The line is: *this session proves the artifact exists and is honest; the test
agent proves it works.*

### Product code — report, never edit

This session **does not write or edit product code**, not even a one-line fix.
It reports and bounces. Three sessions share one checkout; a reviewer that
edits both authors and approves its own work, and races the dev agent's tree.

### Pass criteria and the FAIL label

PASS requires all of: every acceptance box has a landed, inspectable artifact;
no defect found that makes the feature wrong; commit hygiene per `AGENTS.md`;
and the dev agent's handoff-comment claims spot-check as true.

A FAIL carries the **`review-rejected`** label — deliberately *not* the test
gate's `gate-rejected`, so the dev agent can tell which stage bounced it and
which comment to work from. Remove it when the item re-enters and passes.

### Lane tooling

`~/.local/bin/review-lane` — this session's own tool and cache.

```bash
review-lane                 # refresh + list "In review" (~5-10 GraphQL pts)
review-lane --cached        # zero GraphQL
review-lane --lanes         # lane histogram only
review-lane pass <issue>    # -> Testing   (one mutation, no board read)
review-lane fail <issue>    # -> In progress (one mutation, no board read)
```

Cache: **`/tmp/review-board.json`** (never `/tmp/board.json`, the gate's, nor
`/tmp/dev-board.json`, the dev session's). It appends to the shared stable
issue→item-id map `/tmp/item_ids.json`, so `pass`/`fail` need no board read.

### Fan-out

Up to **6 review sub-agents in parallel** (owner directive, 2026-07-27, raised
from 3), one issue each. They are read-only, are forbidden from touching the
board, and return a structured verdict (VERDICT / BOXES / DEFECTS / COMMITS /
BOUNCE_COMMENT). The main session — never a sub-agent — posts comments, applies
labels, and moves cards.

6 is affordable here precisely because of the no-compiler directive: these agents
read and grep, so they contend for nothing but tokens — unlike the test gate's
fan-out, which is capped at 3 by disk and by the shared cargo target dir. Prefer
filling the batch: with the lane routinely at 8+ items, a 3-wide batch is what
lets arrivals outpace review.

**Every sub-agent prompt must restate the no-compiler directive explicitly.** The
default instinct is to build, and a prompt that merely says "review this" gets an
agent that runs `cargo test`.

## Board handles

- Project #4 `PVT_kwHOBQOh784BdpVt` (owner `lianluo-esign`), Status field
  `PVTSSF_lAHOBQOh784BdpVtzhYJbgM`.
- Option ids: Epic `190dc6f3`, Backlog `f75ad846`, Ready `61e4505c`,
  **In progress `47fc9ee4`** (bounce target since 2026-07-27),
  **In review `df73e18b`** (this lane, the renamed "In review & Test"),
  **Testing `74839551`** (pass target), Done `98236657`.
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
- **Worktree isolation + immediate cleanup.** This session builds nothing (see
  "read, never build"), so it normally needs no worktree at all — read
  `origin/main` in place with `git show origin/main:<path>`, which costs nothing
  and cannot dirty a shared tree. If a worktree is ever created for a bulk read,
  delete it (`git worktree remove --force …` + `git branch -D …`) the moment the
  item is judged.
- **Never build in the primary working directory** (`/home/dev/ferrogate`) — or
  anywhere else. All three sessions share that tree, the test gate uses it as
  its test bed, and its `target/` once reached 86 GB. Note it is frequently
  behind `origin/main`; check `git rev-parse HEAD origin/main` before reading it,
  and state which ref a finding is against.

## Loop prompt (code-review session)

Start this session's cron with `/loop 5m` and the directive below. Lane and both
edges are fixed by the project owner; the review **methodology** is defined
above ("The review method (v1)") — extend the prompt as that method is revised,
but do not change the lane or the edges.

```
请读取 GitHub Project 看板中 In review 泳道的 issues 持续做代码评审。
评审通过后把 issue 移动到 Testing 泳道；发现任何问题则把 issue 打回 In progress 泳道，
并在 issue 评论中写明具体问题、影响与复现方式，交给 dev agent 返工。
1- 最多 6 个 sub agent 并行评审（本 lane 不编译不跑测试，只读源码，所以并发只受 token 限制）。
2- 不要无限制调用 GitHub GraphQL 读取看板（配额有限，三个 session 共用同一份配额）；
   只在关键节点读看板，其余一律用 REST (gh api) 与本地缓存。
3- 你只负责代码评审：不写产品代码，不做编译，也不跑任何单元测试或端到端测试——
   编译与测试由 test agent 负责；不要把 issue 移到 Done。
```
