<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-23
  description: Token4AI Cloud, FerroGate AI Gateway, autonomous parallel two-agent development loop (dev driver + test gate) constraints.
-->

# Autonomous Parallel Development Loop

This document defines the binding constraints for running FerroGate development
as an **autonomous, continuously-iterating loop that fans work out across
parallel subagents**. It extends `docs/dynamic-workflow.md` (which governs a
single serial slice) with the rules that make *parallel* multi-agent iteration
safe: board discipline, GraphQL quota budget, a hard concurrency ceiling,
worktree isolation, and mandatory disk cleanup.

It is the contract **two** cooperating agents follow when told to "keep
iterating on the board" without naming a single issue:

- a **development driver** that pulls slices off the board, fans them out to
  worktree-isolated subagents, integrates the results onto `main`, and parks
  finished slices in **In review & Test**; and
- a **test gate** that watches only the **In review & Test** lane, proves each
  item end-to-end, and takes it to **Done** or bounces it back to **Ready**.

The two never move the same card in the same direction. The board is their only
message bus, so the quota rules below apply to both.

## Roles at a glance

| | Development driver | Test gate |
| --- | --- | --- |
| Watches | Backlog / Ready / In progress | In review & Test only |
| Produces | code on `main` + slices parked in "In review & Test" | Done (pass) or Ready + `gate-rejected` (fail) |
| Proof it owns | unit / build / narrow harness | full `ferrogate-test` E2E harness coverage |
| Never does | E2E, the Done transition | writes product code, moves cards left past Ready |
| Board writes | move slice → In review & Test (one mutation/slice) | move item → Done or → Ready (one mutation/item) |

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
- Status option IDs (cache these; never re-query to move a card):

  | Lane | Option ID |
  | --- | --- |
  | Epic | `190dc6f3` |
  | Backlog | `f75ad846` |
  | Ready | `61e4505c` |
  | In progress | `47fc9ee4` |
  | In review & Test | `df73e18b` |
  | Done | `98236657` |

- The development driver moves sub-issues rightward up to and including
  **In review & Test**. The **Done** transition belongs to the test agent /
  human review, never to the development driver.

## The board is live — reconcile once per loop cycle

The board changes *under* each agent: the test gate moves items to **Done** or
back to **Ready**, and humans re-triage too. So a status you wrote is never
terminal — treat the board as shared mutable state.

- **Read the board exactly once at the start of each loop cycle** to reconcile,
  then diff against the prior snapshot to see what moved. This single read is
  the sanctioned key-node Projects-quota use (see below).
- The **Ready** lane accumulates the driver's own partially-done epics whose
  *next* slice is the work. Read the issue's latest progress comments first and
  do the next slice — do **not** redo the landed one.
- **A lane move does not bump the issue's `updatedAt`.** A cheap REST probe
  (`gh issue list --json updatedAt` + `git fetch`) therefore *cannot* see items
  that silently entered "In review & Test". The gate must read the lane itself
  (via `board-test-lane`, below) once per iteration; it cannot infer arrivals
  from REST.

## GitHub Projects GraphQL quota discipline

The org has a **critically limited, shared** GitHub Projects/GraphQL quota
(5000 points/hr, shared across the dev driver *and* the test gate under the same
user id — observed dropping to **16/5000** mid-session). Exhausting it makes the
board unusable for both agents. Default to **zero GraphQL per loop tick**.

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
    uses cached item + built-in option IDs). Caches to `/tmp/dev-board.json`.
  - Gate: `~/.local/bin/gate-lane` / `board-test-lane` — status-only query of
    the "In review & Test" lane (~5–10 points), self-protects below ~60 points
    remaining by serving the cached snapshot. Caches to `/tmp/board.json`.
- **The two agents use separate cache files.** The gate owns `/tmp/board.json`;
  the driver owns `/tmp/dev-board.json` (they clobbered each other when they
  shared a path). Both may append to `/tmp/item_ids.json` — item IDs are stable,
  so merging is safe. Cache the issue→item-id map so status moves need **no**
  board read.
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
working directory**. The test gate shares `/home/dev/ferrogate` as its test bed
and often leaves *uncommitted* WIP there; a cherry-pick needs a clean tree and
would clobber it. So integrate in a throwaway worktree branched from
`origin/main`:

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
   the test gate may push too; never force-push).
6. Comment the issue with the commit sha + exact verification evidence
   (what was run, what passed, what was **not** tested and why) — via REST.
7. Move the board status to **In review & Test** (the one allowed Projects
   mutation for this slice) — via `dev-lane move`.
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

## Verification gate before "In review & Test"

Local unit/build proof only — the driver loop does not run E2E:

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

## Lane-entry contract (test-gate rule)

An issue may move into **In review & Test** only when its acceptance list is
**deliverable as written** — every checkbox either implemented-and-tested or
explicitly re-scoped by editing the issue BEFORE the lane move. The gate
rejects on the first unmet box; a commit's `Not-tested:`/"deferred" note is
treated as an admission, not an excuse.

Hard rules learned from 14 consecutive gate rejections (#340-#360 era):

- **The E2E/operator-facing boxes are part of the issue.** A library-complete
  slice with the harness scenario, Admin API surface, Playwright flow, or
  write-read compliance proof "deferred to later work" fails the gate.
- **An epic whose acceptance explicitly lists Playwright/E2E is not Test-ready
  on dev-alone.** Keep it in **In progress**; the test gate owns advancing it.
  Only issues with no Playwright/E2E box (component tests only) legitimately go
  to the lane on dev completion.
- **Landing incremental slices on main is encouraged; moving the issue to the
  lane is not** until the last acceptance box is closed. Keep the issue in
  "In progress" between slices.
- **If part of the scope must move out, edit the issue** (split a follow-up,
  shrink acceptance) before the lane move, and say so in a comment.
- Rejected issues return to **Ready** carrying the `gate-rejected` label and a
  comment listing exactly which boxes failed; remove nothing from that list
  when re-entering.

## The test agent (gate side)

The test gate is the second autonomous agent. It watches **only** the
"In review & Test" lane, proves each item, and renders one of three verdicts.
It never writes product code and never moves a card left past Ready.

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
  docker — with the code itself not at fault) → leave the item in
  "In review & Test" with a blocker comment. This is the narrow exception; a
  real defect is a FAIL, not a HOLD.

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
directly instead of a worktree. **Before every gate test run, check
`git status --porcelain`.** If the tree is dirty with files the gate did not
create, the evidence would be polluted — touch nothing, flag it to the user, and
either wait for the tree to clean up or run the gate from a clean temporary
worktree of `origin/main`.

## Non-goals

- These constraints do not authorize bypassing tests or issue-linked commits.
- They do not turn FerroGate into an agent runtime.
- The collaboration is choreographed through the board, not a shared framework;
  the quick operational checklists live in the `skills/ferrogate-multi-agent-loop`,
  `skills/ferrogate-dev-loop`, and `skills/ferrogate-test` skills.
