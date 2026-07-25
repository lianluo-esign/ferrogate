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
