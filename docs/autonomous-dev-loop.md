<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-23
  description: Token4AI Cloud, FerroGate AI Gateway, autonomous parallel three-agent development loop (dev driver + code review + test gate) constraints.
-->

# Autonomous Parallel Development Loop

This document defines the binding constraints for running FerroGate development
as an **autonomous, continuously-iterating loop that fans work out across
parallel subagents**. It extends `docs/dynamic-workflow.md` (which governs a
single serial slice) with the rules that make *parallel* multi-agent iteration
safe: board discipline, GraphQL quota budget, a hard concurrency ceiling,
worktree isolation, and mandatory disk cleanup.

It is the contract **three** cooperating sessions follow when told to "keep
iterating on the board" without naming a single issue. Each session owns exactly
one role and watches exactly one lane for incoming work:

- a **development driver** (code generation **only**, 只负责代码生成) that pulls
  slices off the board, fans them out to worktree-isolated subagents, integrates
  the results onto `main`, and parks finished slices in **In review** — where it
  **stops**;
- a **code-review agent** that watches only the **In review** lane and either
  passes an item on to **Testing** or bounces it back to **Ready** with
  findings; and
- a **test gate** that watches only the **Testing** lane, proves each item
  end-to-end, and takes it to **Done** or bounces it back to **Ready**.

No two of them move the same card in the same direction. The board is their only
message bus, so the quota rules below apply to all three.

**Every bounce lands in `Ready`.** A rejection from *any* stage returns the
issue to **Ready** — not to **In progress**, not to the previous lane — carrying
the reviewer's/tester's findings in the issue comments. So the flow is a forward
pipeline with one shared fail-back edge, and an issue may cross the board
several times before it reaches Done; nothing here implies a single
forward-only pass.

```
Backlog ─┐
         ├─► In progress ──(dev: code + local gates)──► In review ──(review: PASS)──► Testing ──(test: PASS)──► Done
Ready ───┘        ▲                                        │                            │              (+ close)
                  │                                        │ FAIL                       │ FAIL
                  └──────────────── Ready ◄────────────────┴────────────────────────────┘
                        (findings in comments; `gate-rejected`-style return)
```

## Roles at a glance

| | Development driver | Code-review agent | Test gate |
| --- | --- | --- | --- |
| Watches | Backlog / Ready (incl. returned items) / In progress | In review only | Testing only |
| Produces | code on `main` + slices parked in "In review" | Testing (pass) or Ready + findings (fail) | Done (pass) or Ready + `gate-rejected` (fail) |
| Proof it owns | `cargo build` / `cargo test` + the repo's local gates | code review of the landed diff (bar: TBD, see below) | full `ferrogate-test` end-to-end harness coverage |
| Never does | self-review, E2E, the Testing/Done transitions | writes product code (TBD), moves cards past Testing | writes product code, moves cards left past Ready |
| Board writes | move slice → In review (one mutation/slice) | move item → Testing or → Ready (one mutation/item) | move item → Done or → Ready (one mutation/item) |

## Goal and boundary

- The development driver continuously pulls sub-issues off the GitHub Project
  board and advances them, through real implementation + local verification, up
  to the **In review** lane — and **stops there**. It never moves an issue to
  **Testing** and never to **Done**.
- **The dev role is code generation only.** It writes the code and proves it
  with `cargo build` / `cargo test` plus the repo's local gates (`cargo fmt`,
  `clippy`, `scripts/check-openapi.py`, `tsc`/`vitest` for `admin-console/`).
  Its proof obligation **stops there**: it does **not** review its own work, and
  **end-to-end testing is the test agent's job in the Testing lane, never the
  dev agent's**.
- A separate **code-review agent** owns the "In review" lane; a separate **test
  agent** owns the "Testing" lane. The dev driver's job ends when a slice is
  build/unit-verified, integrated, and parked in "In review".
- **`Ready` is the dev agent's inbound queue for rework**, alongside `Backlog`
  for new work. Every bounce — from review or from test — lands there, so the
  dev session must watch `Ready` for returned issues instead of only picking
  fresh ones. Read a returned issue's latest comments (the findings live there)
  before touching code, and fix only what was called out.
- Do not close epics. Land one coherent slice, keep the epic open with a
  progress comment (per `docs/dynamic-workflow.md`).

## The board

- Project **#4** (`PVT_kwHOBQOh784BdpVt`, owner `lianluo-esign`).
- `Status` field `PVTSSF_lAHOBQOh784BdpVtzhYJbgM`; lane order:
  **Epic → Backlog → Ready → In progress → In review → Testing → Done**.
- Status option IDs (cache these; never re-query to move a card):

  | Lane | Option ID | Owner |
  | --- | --- | --- |
  | Epic | `190dc6f3` | — |
  | Backlog | `f75ad846` | dev |
  | Ready | `61e4505c` | dev |
  | In progress | `47fc9ee4` | dev agent |
  | In review | `df73e18b` | code-review agent |
  | Testing | `74839551` | test agent |
  | Done | `98236657` | test agent |

- **"In review" is the renamed "In review & Test" lane** — same option id
  `df73e18b`, so nothing had to migrate; whatever already sat there is now in
  the code-review agent's queue. **Testing** (`74839551`) is the new lane
  inserted between review and Done.
- The development driver moves sub-issues rightward up to and including
  **In review**. The **Testing** transition belongs to the code-review agent;
  the **Done** transition belongs to the test agent / human review, never to
  the development driver.
- The only leftward move any agent makes is **→ Ready** (a bounce). No agent
  moves a card left past Ready.

## The board is live — reconcile once per loop cycle

The board changes *under* each agent: the code-review agent moves items from
**In review** to **Testing** (or bounces them back), the test gate moves items to
**Done** or back to **Ready**, and humans re-triage too. So a status you wrote is
never terminal — treat the board as shared mutable state.

- **Read the board exactly once at the start of each loop cycle** to reconcile,
  then diff against the prior snapshot to see what moved. This single read is
  the sanctioned key-node Projects-quota use (see below).
- The **Ready** lane accumulates two things: the driver's own partially-done
  epics whose *next* slice is the work, and issues **bounced back from review or
  test**. Read the issue's latest comments first — they hold the previous
  slice's progress note or the reviewer's/tester's findings — then do only that
  next slice. Do **not** redo the landed one.
- **A lane move does not bump the issue's `updatedAt`.** A cheap REST probe
  (`gh issue list --json updatedAt` + `git fetch`) therefore *cannot* see items
  that silently entered "In review" or "Testing". Each downstream agent must
  read its own lane itself (via the lane tools below) once per iteration; it
  cannot infer arrivals from REST.

## GitHub Projects GraphQL quota discipline

The org has a **critically limited, shared** GitHub Projects/GraphQL quota
(5000 points/hr, shared across the dev driver, the code-review agent *and* the
test gate under the same user id — observed dropping to **16/5000**
mid-session). Exhausting it makes the board unusable for all three. Default to
**zero GraphQL per loop tick**. A third session watching a third lane means a
third recurring board read — the per-tick budget got tighter, not looser.

- **Both `gh project ...` AND `gh issue view/list/comment/close` burn the
  GraphQL pool.** Only `gh api repos/...` REST and `git` are safe.
  - Read issue bodies via REST:
    `gh api repos/lianluo-esign/ferrogate/issues/<n> --jq '.title,.body'`.
  - Comment/close via REST:
    `gh api .../issues/<n>/comments -f body=…`,
    `gh api -X PATCH .../issues/<n> -f state=closed -f state_reason=completed`.
  - `git push`/`fetch`/`cherry-pick` are **not** rate-limited — keep code
    flowing via git even when GraphQL is exhausted, and defer bookkeeping.
- **Use the quota-lean lane tools, not `gh project item-list`.** A full
  `gh project item-list --limit 800` dump costs ~100 points; hand-written
  status-only GraphQL queries cost ~5.
  - Driver: `~/.local/bin/dev-lane` — `--refresh`, `--candidates [--cached]`,
    `--cached "<lane>"`, `--diff`, `--id <n>`, `move <n> "<lane>"` (typo-proof,
    uses cached item + built-in option IDs, already carries all seven lanes).
    Caches to `/tmp/dev-board.json`.
  - Gate: `~/.local/bin/gate-lane` / `board-test-lane` — status-only query of a
    single lane (~5–10 points), self-protects below ~60 points remaining by
    serving the cached snapshot. Caches to `/tmp/board.json`. **Both still
    default to the old `In review & Test` lane name and must be pointed at
    `Testing` now** (`gate-lane "Testing"`; `board-test-lane` hard-codes the
    name and needs editing) — the test gate no longer watches `df73e18b`.
  - Code review: the lane tool it uses is **TBD by the code-review session**.
    `gate-lane "In review"` already works read-only; whether that session gets
    its own cache file and mover is its call.
- **Each agent uses its own cache file.** The gate owns `/tmp/board.json`; the
  driver owns `/tmp/dev-board.json` (they clobbered each other when they shared
  a path) — a code-review session must likewise not reuse either path. All may
  append to `/tmp/item_ids.json` — item IDs are stable, so merging is safe.
  Cache the issue→item-id map so status moves need **no** board read.
- **Exhaustion handling.** `gh api rate_limit` (free) reports remaining GraphQL
  and the reset time. When remaining is low, defer all `gh project`/lane reads
  and moves to a later fire, keep code flowing via git + REST, and batch the
  deferred moves after reset. Skip a round rather than retrying into a wall.
- **Subagents never touch the board.** They get their issue body pasted into
  their prompt, are forbidden from `gh project ...`, and should prefer `gh api`
  over `gh issue view` if they must read an issue at all.

## Concurrency ceiling

- **At most 3 subagents developing code in parallel.** Hard ceiling, never
  exceeded (user-controlled: set 3 → 2 → back to 3 on 2026-07-23; honor the latest directive). Fewer is fine; hold a slot as integration margin when the in-flight
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

For each completed subagent, integrate one at a time — **but not in the primary
working directory**. The other sessions share `/home/dev/ferrogate` (the test
gate uses it as its test bed) and often leave *uncommitted* WIP there; a
cherry-pick needs a clean tree and would clobber it. So integrate in a throwaway
worktree branched from `origin/main`:

1. `git fetch origin main`; confirm a clean base.
2. `git worktree add -b integrate-<n> .claude/worktrees/integrate-tmp <origin/main-sha>`.
3. **Cherry-pick** the agent's branch commit(s) there (keeps linear history;
   avoids merge commits from stale worktree bases).
4. **Re-verify the combined state.** The merged `main` may combine two agents'
   edits to a shared file that neither tested together. Run the narrowest
   credible build/test that proves the combined result — with one hard rule:
   - **When the slice adds an enum variant, changes a trait signature, or
     touches any widely-consumed `pub` type, run `cargo build --workspace`** (or
     explicitly build every consuming crate — grep the type name across crates).
     A subagent's "`cargo build -p X` clean" does **not** prove downstream
     crates still compile. (Learned from the #415 regression: a new
     `IsolationBackendKind` variant left a non-exhaustive `match` in
     `ferrogate-cli` and broke `main` for two integrations.)
   - You may **skip the throwaway rebuild** only when the cherry-picked source
     is byte-identical to the agent's already-green tree (the common case — main
     unchanged in that crate since the agent's base). Rebuild whenever the
     cherry-pick genuinely combines two agents' edits to a shared file.
   - For `admin-console/`: `tsc -b`, `vitest run`, `lint`, bundle-budget build.
5. `git push HEAD:main` (fetch + rebase onto `origin/main` first if it moved —
   another session may push too, e.g. the test gate's harness commits; never
   force-push).
6. Comment the issue with the commit sha + exact verification evidence
   (what was run, what passed, what was **not** tested and why) — via REST.
7. Move the board status to **In review** (the one allowed Projects mutation for
   this slice, and the last lane the dev role ever writes) — via
   `dev-lane move <n> "In review"`.
8. **Delete the throwaway + agent worktrees immediately** (see below).
9. File any follow-up issues the slice surfaced (house style, issue-linked),
   rather than leaving TODOs in chat.

Local `main` will lag `origin/main` after this (you never committed there);
that is fine — always branch the next throwaway from `origin/main`.

### Build-artifact corruption (rustc ICE) at integration

The sandbox toolchain intermittently ICEs on corrupt cached artifacts —
signature `decode error: Expected header tag [79,68,72,84] ("ODHT")` in
`rmeta/def_path_hash_map`, striking *unrelated* crates (openssl-sys build
script, ppv-lite86, …). It is **not** a code bug in the slice. Fix: build with
`CARGO_INCREMENTAL=0`; if it still ICEs, `rm -rf <target>/debug/incremental` or
`cargo clean` and rebuild in a **fresh** throwaway target (a clean target builds
reliably). Do not mistake this for a regression — verify the actual changed
crate builds+tests and a clean-target build of the consumer.

## Verification gate before "In review"

Local build/unit proof only — this is the dev role's **entire** proof
obligation. It does not run E2E; the test agent does that in the **Testing**
lane:

- `cargo fmt --all -- --check`, then the narrowest `cargo build -p <crate>` and
  `cargo test -p <crate> <filter>` that prove the slice; `clippy -D warnings`
  and `scripts/check-openapi.py` when the change warrants them; `--workspace`
  build for cross-cutting changes (above).
- For `admin-console/`: `tsc -b`, `vitest run`, `lint`, and the bundle-budget
  build.
- Record anything not provable locally (e.g. live-Postgres) as **not tested** in
  the issue. Do not trigger cloud CI (release-only, per AGENTS.md).

## Worktree cleanup is mandatory (disk safety)

Each worktree's `cargo build` creates its own multi-GB `target/` (observed
~13 GB per Rust worktree). Leftover worktrees consume disk without bound.

- **Delete every worktree the moment its task is done and integrated:**
  `git worktree remove --force .claude/worktrees/agent-<id>` and
  `git branch -D worktree-agent-<id>` (and the `integrate-tmp` throwaway).
- At any instant, only the **currently-running** agents' worktrees (≤3) plus at
  most one integration throwaway may exist on disk.
- Do **not** remove a worktree of a still-running agent (it is `locked`).
- **Never build in the primary working directory** (`/home/dev/ferrogate`). Its
  `target/` grew to **86 GB** from accumulated per-verification builds early in
  the session and nearly filled the disk. All builds happen in throwaway/agent
  worktrees that get deleted. If `du -sh /home/dev/ferrogate/target` is large,
  `rm -rf` it — it is pure regenerable cache.
- Periodically confirm with `df -h .` and `du -sh <wt>/target`.

## Commit requirements

Every integrated commit follows AGENTS.md "Commit Requirements": reference the
issue in the subject (e.g. `(#367) ...`), include a closing/related trailer, and
use Lore trailers (`Constraint:`, `Rejected:`, `Tested:`, `Not-tested:`,
`Confidence:`, `Scope-risk:`, `Refs #<n>`) for non-trivial changes.

## Lane-entry contracts

Each forward edge has its own bar. Each backward edge lands in **Ready**.

### → In review (dev agent hands off)

An issue may move into **In review** only when its acceptance list is
**deliverable as written** — every checkbox either implemented (and covered by
the proof the dev role owns) or explicitly re-scoped by editing the issue BEFORE
the lane move. A commit's `Not-tested:`/"deferred" note is treated as an
admission, not an excuse.

Hard rules learned from 14 consecutive gate rejections (#340-#360 era) — still
binding, re-pointed at the new lane:

- **The E2E/operator-facing boxes are part of the issue.** A library-complete
  slice whose harness scenario, Admin API surface, Playwright flow, or
  write-read compliance proof is "deferred to later work" is not ready to hand
  off. The dev role must *write* that surface; only its end-to-end **execution**
  belongs downstream, in the Testing lane.
- **An epic whose acceptance explicitly lists Playwright/E2E is not ready to
  hand off until that code exists.** Keep it in **In progress** while the
  E2E-facing code is missing. Once it exists, hand off at **In review** like
  everything else and let the test agent supply the end-to-end proof — the dev
  agent never runs it.
- **Landing incremental slices on main is encouraged; moving the issue to
  In review is not** until the last acceptance box is closed. Keep the issue in
  "In progress" between slices.
- **If part of the scope must move out, edit the issue** (split a follow-up,
  shrink acceptance) before the lane move, and say so in a comment.

### → Testing (code-review agent hands off)

The pass bar for leaving **In review** is **TBD by the code-review session**.
Fixed by the project owner: that session watches In review, moves passing items
to **Testing** (`74839551`), and returns failing ones to **Ready** with its
findings in an issue comment. What it inspects, how deep it goes, and what
counts as a pass are that session's to define and document — no other session
may invent them here.

### → Done (test agent)

Unchanged: a PASS requires end-to-end `ferrogate-test` harness coverage of the
item's feature (see "The test agent" below).

### Bounces (every stage)

- **A rejection from any stage returns the issue to `Ready` (`61e4505c`)** —
  never to In progress, never to the immediately-preceding lane — with a comment
  listing exactly what failed. The test gate additionally applies the
  **`gate-rejected`** label; remove nothing from that list when re-entering.
- The dev agent therefore treats **Ready** as its rework inbox: a returned item
  is the next slice, and its comments are the spec for that slice. Fix only what
  was called out; do not redo landed work.
- An issue may make this round trip more than once. The pipeline is forward-only
  *per pass*, not forward-only overall.

## The code-review agent (review side)

The code-review agent is the second autonomous session. What the project owner
has fixed, and what every other session may rely on:

- It watches **only** the **In review** lane (`df73e18b`) — the lane the dev
  agent hands off into.
- **PASS** → move the item to **Testing** (`74839551`) for the test agent.
- **FAIL** → return the item to **Ready** (`61e4505c`) with its findings in an
  issue comment, exactly like the test gate's fail-back edge (this is how #428
  and #346 were bounced from the review lane on 2026-07-25).
- It obeys the shared discipline below like everyone else: GraphQL rationing,
  worktree isolation + immediate cleanup, never build in the primary working
  directory.

**Everything else is TBD by the code-review session** — what it inspects, how
deep the review goes, whether it may edit code or only report, its lane tooling
and cache file, and what exactly counts as a pass. No other session may invent
that contract; the review session defines it and documents it in
`skills/ferrogate-code-review`.

## The test agent (gate side)

The test gate is the third autonomous session. It watches **only** the
**Testing** lane (`74839551`), completes the **end-to-end** testing each item
needs, and renders one of three verdicts. End-to-end proof is *its* job — no
other role owes it. It never writes product code and never moves a card left
past Ready.

### Gate outcomes

- **PASS** → move the item to **Done** (`98236657`) and close the issue with an
  evidence comment. A PASS requires the **`ferrogate-test` harness to cover the
  item's feature end-to-end** — targeted `cargo` tests + a green generic `ci`
  are **not** sufficient. If no harness scenario exercises the feature itself,
  the item does not pass yet — **the gate writes the missing scenario itself**
  (the harness is gate-owned tooling), wires it into `ferrogate-test ci`, runs
  it, then judges on the result. Do **not** bounce an item to Ready merely for
  missing harness coverage.
- **FAIL** (打回重写: real defects or unmet acceptance the dev must fix) → move
  the item back to **Ready** (`61e4505c`), add the **`gate-rejected`** label
  (`gh issue edit N --add-label gate-rejected`; remove it when the item
  re-enters and passes), and comment listing what failed and what to fix.
- **HOLD** (blocked *only* on a gate-environment gap — missing credentials, no
  docker — with the code itself not at fault) → leave the item in **Testing**
  with a blocker comment. This is the narrow exception; a real defect is a FAIL,
  not a HOLD.

### Gate environment limits

- **No `docker` binary.** `ferrogate-test ci` runs its docker-free prefix, then
  fails when it reaches `supabase-migration` (hard-codes docker); all
  `*-restart` durability scenarios and docker-image container builds are
  unrunnable here. Document these as environment-blocked and HOLD only if an
  acceptance box truly depends on them (per `ferrogate-test-strategy`: missing
  infrastructure means the proof stays explicitly unverified — never claim it,
  never add cloud CI as a workaround).
- **Live Cloudflare and live Supabase work** (credentials in
  `~/.ferrogate-live.env`; source with `set -a`). Supabase DSN must use the
  session pooler host, not the direct `db.<ref>` host.
- **Mandatory live-Cloudflare cleanup.** After *every* live-CF run, delete all
  resources the run created — container/sandbox instances, D1 probe databases,
  R2 objects/buckets, Secrets Store entries, extra test Workers — and verify
  they are gone (lingering resources bill money). Track every created name
  during the run and sweep it before rendering the verdict. Long-lived
  exception: the `ferrogate-agent-gateway` Worker + its containers app stay
  deployed as the gate's validation fixture.

### Shared-checkout hazard

Dev subagents sometimes edit `/home/dev/ferrogate` (the gate's test bed)
directly instead of a worktree, and a third session now shares it too.
**Before every gate test run, check `git status --porcelain`.** If the tree is
dirty with files the gate did not create, the evidence would be polluted — touch
nothing, flag it to the user, and either wait for the tree to clean up or run
the gate from a clean temporary worktree of `origin/main`.

## Non-goals

- These constraints do not authorize bypassing tests or issue-linked commits.
- They do not turn FerroGate into an agent runtime.
- The collaboration is choreographed through the board, not a shared framework;
  the quick operational checklists live in the `skills/ferrogate-multi-agent-loop`
  skill (the shared three-role reference) and the per-role
  `skills/ferrogate-dev-loop`, `skills/ferrogate-code-review`, and
  `skills/ferrogate-test` skills.
