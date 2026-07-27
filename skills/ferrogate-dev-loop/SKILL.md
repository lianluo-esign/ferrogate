---
name: ferrogate-dev-loop
description: Use when running FerroGate development as an autonomous, continuously-iterating code-generation loop that fans work out across parallel subagents against the GitHub Project board (e.g. "keep iterating on the board", "持续迭代开发", a /loop that advances issues). This is the DEV role of the three-agent loop — code generation only. Covers the binding constraints — advance sub-issues only up to "In review" (never Testing, never Done), Ready is also the rework inbox for bounced issues, Projects GraphQL quota discipline, the max-3 parallel-subagent ceiling, worktree isolation + slice separation, the cherry-pick integration flow, and mandatory worktree cleanup to bound disk. For the neighbouring roles see ferrogate-code-review and ferrogate-test; for all three at once see ferrogate-multi-agent-loop. Not for a single named-issue slice (use docs/dynamic-workflow.md).
---

# FerroGate Autonomous Parallel Dev Loop (code generation only)

Full contract: **`docs/autonomous-dev-loop.md`** (read it before driving the
loop). Single-slice serial workflow: `docs/dynamic-workflow.md`. All three roles
at a glance: `ferrogate-multi-agent-loop`. Downstream roles that consume this
loop's output: `ferrogate-code-review` (In review) and `ferrogate-test`
(Testing). This skill is the quick operational checklist for the dev role.

## Candidate order: In progress → Ready → Backlog (user directive, 2026-07-27)

Read the lanes in that order and take the first actionable item, rather than
starting from Backlog:

1. **`In progress`** — slices already opened, often mid-epic. This lane
   silently accumulates: 14 items sat here while the loop pulled fresh work
   from Backlog. Its items carry the most context and the least duplication
   risk.
2. **`Ready`** — the rework inbox (review/gate bounces carry findings in the
   comments) plus groomed work.
3. **`Backlog`** — fresh work, last.

**Caveat that makes this safe:** In-progress items skew *stale-done* — a later
slice landed after the last comment. Before scoping one, `git grep` `origin/main`
for the feature's symbols to confirm the gap is real; if the surface already
exists and its gate is green, say so on the issue and move it on, do not rebuild
it. `dev-lane --cached "In progress"` lists the lane without a board fetch.

## The invariants (do not violate)

1. **This role is code generation only (只负责代码生成).** Write the code, then
   run **`cargo check --all-targets` and nothing else** — that is the *whole*
   proof obligation (user directive, 2026-07-27; see
   `ferrogate-multi-agent-loop` → "Speed mode"). **Do not** run `cargo build`,
   `cargo test`, `clippy`, or a mutation pass; **do not self-review** (a
   separate code-review agent does that); **do not run end-to-end tests** (the
   test agent owns E2E in the Testing lane). Still *write* the tests a slice
   needs — only their execution moves downstream — and state plainly in the
   commit's `Not-tested:` trailer and the handoff comment that nothing was run.
   Checks that are not tests still apply, because `cargo check` cannot see
   them and the code-review agent bounces on them: **`cargo fmt` before every
   commit** (`AGENTS.md:346` lists `cargo fmt --check` in the static gate —
   #493 was bounced for exactly this, and the same pass caught an unrelated
   fmt break already on `main`), `scripts/check-openapi.py` when you edit the
   spec, and `tsc --noEmit` when you edit `workers/**/*.ts`. Read the
   directive as "skip the *tests*", not "skip the static gate".
2. **Advance to "In review", never further.** The code-review agent owns
   In review → Testing; the test gate owns Testing → Done. This loop never
   writes those two transitions.
3. **Ready is the inbound queue for rework, not just new work.** Every bounce
   from review or test lands in **Ready** with the findings in the issue
   comments. Read those comments first and fix exactly what was called out — do
   not redo landed work, and expect an issue to cross the board more than once.
4. **Projects GraphQL quota is scarce** and shared with two other sessions. Call
   `gh project ...` only at key nodes (initial plan read; each completed slice's
   status move); prefer `dev-lane` (~5 points) over `gh project item-list`
   (~100). Cache the board dump + field/option IDs to `/tmp/dev-board.json` and
   reuse them. `gh issue view/comment/create` also burn GraphQL — prefer
   `gh api repos/...` REST. Subagents must never call `gh project`.
5. **≤ 3 code-developing subagents in parallel.** Hard ceiling (user-controlled;
   3→2→3 on 2026-07-23, honor latest). If full on a loop tick, hold — integrate
   finished work, don't launch more, don't re-read the board.
6. **Delete every worktree the instant its slice is integrated.** Each Rust
   worktree's `target/` is ~13 GB. Only running agents' worktrees may exist, and
   **never build in the primary working directory** (`/home/dev/ferrogate`) —
   the other sessions share it.

## Board handles

- Project #4 `PVT_kwHOBQOh784BdpVt` (owner `lianluo-esign`).
- Status field `PVTSSF_lAHOBQOh784BdpVtzhYJbgM`; lanes
  Epic → Backlog → Ready → In progress → In review → Testing → Done.
- Option ids: Epic `190dc6f3`, Backlog `f75ad846`, Ready `61e4505c`,
  In progress `47fc9ee4`, **In review `df73e18b`** (this role's last stop, the
  renamed "In review & Test"), Testing `74839551`, Done `98236657`.
- `dev-lane move <issue> "In review"` already knows all seven lanes.

## Per-slice loop

1. **Plan (key node):** cache board + IDs once; pick up to 3 **maximally
   file-separated** slices (different crates, or `admin-console/` vs Rust, or a
   new crate). Prefer bounced Ready items (they carry reviewer/tester findings)
   and In-progress work, then fresh Ready → Backlog; P0/P1 first.
2. **Dispatch** each as a worktree-isolated subagent (≤3 at a time). It reads its own issue
   (via `gh api repos/...`), implements narrowly per AGENTS.md, adds sibling
   `*_test.rs` (no inline `mod tests {}`) tests, verifies locally, and **commits
   to its branch only — no push, never touches `main`**.
3. **Integrate (driver, sequential):** `git fetch` → `git cherry-pick <branch>`
   → **re-verify the combined `main`** (`cargo check --all-targets`; widen to
   `--workspace` when the slice adds an enum variant / changes a trait or any
   widely-consumed pub type) → `git push` → **verify the push landed** →
   comment the issue with sha + evidence (explicitly: what was **not** executed,
   and which mutations the downstream agent should apply) → move board status to
   **In review** (key node).
4. **Cleanup:** `git worktree remove --force .claude/worktrees/agent-<id>` +
   `git branch -D worktree-agent-<id>`. File follow-up issues the slice
   surfaced (issue-linked, house style).

## Commit gate

Issue-referenced subject `(#<n>) ...` + Lore trailers (`Constraint:`,
`Rejected:`, `Tested:`, `Not-tested:`, `Confidence:`, `Scope-risk:`,
`Refs #<n>`). See AGENTS.md "Commit Requirements".

## Loop prompt (dev session)

Start this session's cron with `/loop 5m` and the directive below. It is the
authoritative wording for the **dev** role — code generation only, stops at
`In review`. Keep it verbatim; the cron re-fires it unchanged every tick.

```
请读取 GitHub Project 看板中 Backlog 与 Ready 两个泳道的 issues 持续迭代开发。
Ready 里含被 code review / test agent 打回的返工项，优先处理（评论里有对方给出的问题）。
开工时先把该 sub issue 移动到 In progress 泳道（让看板反映正在进行的工作），
开发完成后再移动到 In review 泳道为止，不要移到 Testing 或 Done ——
In review 由 code review agent 负责，Testing 与 Done 由 test agent 负责。
1- 最多 3 个 sub agent 并行开发代码。
2- 不要无限制调用 GitHub GraphQL 读取看板（配额有限，超出后整个 Project 不可用）；
   只在关键节点读看板，其余一律用 REST (gh api) 与本地缓存 (dev-lane)。
3- 你只负责代码生成，不做 code review，也不做端到端测试。
   每次代码生成完毕只需 `cargo check --all-targets` 通过即可：不跑 build，不跑
   test，不做变异验证。随后清除 worktree、合并到 main、评论 issue（写明哪些没有
   执行）、把 issue 移到 In review 交给 code review agent。测试代码照写不执行。
```
