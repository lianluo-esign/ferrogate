---
name: ferrogate-test
description: Use when working in the FerroGate repo and the task involves the ferrogate-test Rust CLI itself — running Admin API or gateway API E2E coverage, CI harness verification, Docker-backed cluster scenarios, editing tools/ferrogate-test, or release-grade end-to-end validation. For deciding which test layer a change needs and how findings become issues, use the ferrogate-test-strategy skill.
---

# FerroGate Test Harness

Use this skill in the FerroGate repo when a task touches the `ferrogate-test`
tool or needs end-to-end validation evidence for FerroGate admin and gateway
APIs. To decide *which* test layer a change needs and how test findings feed the
issue queue, use the `ferrogate-test-strategy` skill.

**Role context (three-agent board loop).** This is the tooling of the **test
gate**, the third session of the loop in `docs/autonomous-dev-loop.md`: it
watches the Project board's **Testing** lane (`74839551`), owns *all* end-to-end
proof (no other role runs E2E), and moves each item to **Done** (`98236657`) or
back to **Ready** (`61e4505c`) with the `gate-rejected` label. Upstream roles:
`ferrogate-dev-loop` (code generation, stops at In review) and
`ferrogate-code-review` (In review → Testing). All three at a glance:
`ferrogate-multi-agent-loop`.

## Tool Contract

`ferrogate-test` is the repo-local Rust E2E harness under `tools/ferrogate-test`.

It must:

- Print the Token4AI Cloud attribution banner on every invocation.
- Use `clap` subcommands for all workflows.
- Run real FerroGate gateway processes for local API coverage.
- Exercise Admin API and gateway API paths through HTTP, not just unit tests.
- Keep Docker-backed cluster scenarios sequential because they reuse fixed
  container and network names.
- Be part of the normal GitHub `rust-ci` verification path through
  `ferrogate-test ci`.

## Commands

```bash
# build gateway + harness
cargo build -p ferrogate-cli -p ferrogate-test --locked
# list scenarios
cargo run -p ferrogate-test --locked -- list
# CI-safe local E2E coverage
./target/debug/ferrogate-test ci
# a specific local surface
cargo run -p ferrogate-test --locked -- admin-api
cargo run -p ferrogate-test --locked -- gateway-api
# live Supabase scenarios create and clean a unique schema by default
cargo run -p ferrogate-test --locked -- supabase-live-smoke
cargo run -p ferrogate-test --locked -- component-compliance-supabase
# retain only the exact run schema for explicit debugging
cargo run -p ferrogate-test --locked -- supabase-live-smoke --keep-supabase-schema
# all local API coverage, optionally with Docker scenarios (sequential)
cargo run -p ferrogate-test --locked -- run-all
cargo run -p ferrogate-test --locked -- run-all --include-docker
# Docker-backed scenarios, one at a time
cargo run -p ferrogate-test --locked -- run cluster-drain
cargo run -p ferrogate-test --locked -- run shared-api-key
cargo run -p ferrogate-test --locked -- run shared-state-stale
cargo run -p ferrogate-test --locked -- run shared-state-startup-unavailable
cargo run -p ferrogate-test --locked -- run redis-counters
```

## When Changing the Harness

After editing `tools/ferrogate-test`, run:

```bash
cargo fmt --all -- --check
cargo check -p ferrogate-test
cargo build -p ferrogate-cli -p ferrogate-test --locked
./target/debug/ferrogate-test ci
```

For release-grade validation, also run the Docker scenarios sequentially with
`run-all --include-docker`, then continue with the repo's normal CI gates from
`AGENTS.md`.

When a change needs a layer the harness cannot yet express, grow the harness (new
subcommand, shared assertion, fixture) and wire it into `ferrogate-test ci`
rather than skipping the layer — see "The harness must keep up with the layers"
in the `ferrogate-test-strategy` skill.

## After a Passing Run: Clean Up, Merge, Push

A gate iteration is not finished when the tests go green. On **PASS**, always run
this sequence — in this order:

1. **Verify the test bed is current before trusting any result.** The gate
   checkout has silently drifted 60+ commits behind `origin/main` before, which
   invalidates every verdict rendered on it. Always:
   ```bash
   git fetch origin
   git rev-list --left-right --count HEAD...origin/main   # want 0 behind
   ```
   If behind, re-run the verification on `origin/main` (a detached worktree is
   the safe way when the checkout is dirty) before judging anything.
2. **Clean the scene — delete the large build artifacts.** Rust `target/` output
   and per-item worktrees accumulate fast on a disk-constrained box:
   ```bash
   cargo clean                          # or: cargo clean -p <crate> to keep the shared cache
   git worktree remove <gate-worktree>  # remove every temporary gate worktree
   git worktree prune
   ```
   Remove probe binaries and scratch artifacts the run produced. Do this on
   **FAIL** too — only the merge/push below is PASS-only.
3. **Run the repo gates on anything you are about to commit — `fmt` is not
   enough.** The gate itself has turned `main` red this way: a probe was
   committed after `cargo fmt --all -- --check` passed, but nobody ran clippy,
   and `clippy -D warnings` failed on `main` until the next iteration caught it.
   Before committing gate-authored code run **all** of:
   ```bash
   cargo fmt --all -- --check
   cargo clippy -p <crate> --all-targets -j8 -- -D warnings   # -D warnings, not bare clippy
   cargo test -p <crate> -j8
   python3 scripts/check-module-layout.py                     # lib.rs line caps
   ```
   Holding other people's code to a bar the gate does not meet itself is the
   fastest way to lose the authority to reject anything.
4. **Fast-forward `main` first, then merge the verified work onto it.** Never
   merge onto a stale base. `origin/main` moves under you — three sessions share
   it, so expect to rebase between the last check and the push.
5. **Push to GitHub.** Gate-verified work that stays on a local branch is
   invisible to the rest of the loop and can be lost.

Never merge-and-push on a FAIL: failing items go back to **Ready** with the
`gate-rejected` label and an evidence comment.

## Failure Handling

- If `ferrogate-test ci` fails on a status code, inspect the raw HTTP response
  and align the harness to the real fail-closed behavior only when the runtime
  behavior is correct.
- If a Docker scenario fails or collides, clean stale resources with
  `docker rm -f ferrogate-e2e-gateway-a ferrogate-e2e-gateway-b ferrogate-e2e-provider ferrogate-e2e-redis`
  and `docker network rm ferrogate-e2e-net`, then rerun sequentially.
- Do not weaken secret-redaction assertions unless the response format
  deliberately changed and an equivalent no-secret-leak assertion replaces them.
- Live Supabase scenarios must reuse one schema within a restart scenario, drop
  it on normal and error paths, and verify the exact generated name is absent.
  Never replace this with prefix-wide deletion; another live scenario may own a
  matching schema concurrently.

## Loop prompt (test session)

Start this session's cron with `/loop 5m` and the directive below. Note the lane
changed: this session now watches **Testing**, not the old "In review & Test".

```
请读取 GitHub Project 看板中 Testing 泳道的 issues 持续做针对性端到端覆盖测试。
测试通过后把 issue 移动到 Done；发现任何问题则把 issue 打回 Ready 泳道并加
gate-rejected 标签，在评论中写明未满足的验收项与证据（命令、输出、复现步骤）。
1- 最多 3 个 sub agent 并行测试。
2- 不要无限制调用 GitHub GraphQL 读取看板（配额有限，三个 session 共用同一份配额）；
   只在关键节点读看板，其余一律用 REST (gh api) 与 board-test-lane 缓存。
3- 你负责端到端测试与 ferrogate-test harness，不写产品代码；
   发现产品代码缺陷打回 Ready 交给 dev agent 修复。
```
