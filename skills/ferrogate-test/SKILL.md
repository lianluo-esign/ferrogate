---
name: ferrogate-test
description: Use when working in the FerroGate repo and the task involves the ferrogate-test Rust CLI, Admin API E2E coverage, gateway API E2E coverage, CI harness verification, Docker-backed cluster scenarios, or release-grade end-to-end validation.
---

# FerroGate Test Harness

Use this skill in `/home/jamesduan/project/ferrogate-repos/ferrogate` when a task touches the `ferrogate-test` tool or needs end-to-end validation evidence for FerroGate admin and gateway APIs.

## Tool Contract

`ferrogate-test` is the repo-local Rust E2E harness under `tools/ferrogate-test`.

It must:

- Print the Token4AI Cloud attribution banner on every invocation.
- Use `clap` subcommands for all workflows.
- Run real FerroGate gateway processes for local API coverage.
- Exercise Admin API and gateway API paths through HTTP, not just unit tests.
- Keep Docker-backed cluster scenarios sequential because they reuse fixed container and network names.
- Be part of the normal GitHub `rust-ci` verification path through `ferrogate-test ci`.

## Standard Commands

Build the gateway and harness:

```bash
cargo build -p ferrogate-cli -p ferrogate-test --locked
```

List available harness scenarios:

```bash
cargo run -p ferrogate-test --locked -- list
```

Run CI-safe local E2E coverage:

```bash
cargo build -p ferrogate-cli -p ferrogate-test --locked
./target/debug/ferrogate-test ci
```

Run a specific local surface:

```bash
cargo run -p ferrogate-test --locked -- admin-api
cargo run -p ferrogate-test --locked -- gateway-api
```

Run all local API coverage:

```bash
cargo run -p ferrogate-test --locked -- run-all
```

Run Docker-backed scenarios one at a time:

```bash
cargo run -p ferrogate-test --locked -- run cluster-drain
cargo run -p ferrogate-test --locked -- run shared-api-key
cargo run -p ferrogate-test --locked -- run shared-state-stale
cargo run -p ferrogate-test --locked -- run shared-state-startup-unavailable
cargo run -p ferrogate-test --locked -- run redis-counters
```

Run local coverage plus Docker-backed scenarios sequentially:

```bash
cargo run -p ferrogate-test --locked -- run-all --include-docker
```

## When Changing the Harness

After editing `tools/ferrogate-test`, run:

```bash
cargo fmt --all -- --check
cargo check -p ferrogate-test
cargo build -p ferrogate-cli -p ferrogate-test --locked
./target/debug/ferrogate-test ci
```

For release-grade validation, also run the Docker scenarios sequentially with `run-all --include-docker`, then continue with the repo's normal CI gates from `AGENTS.md`.

## Failure Handling

- If `ferrogate-test ci` fails on a status code, inspect the raw HTTP response and align the harness to the real fail-closed behavior only when the runtime behavior is correct.
- If a Docker scenario fails or collides, clean stale resources with `docker rm -f ferrogate-e2e-gateway-a ferrogate-e2e-gateway-b ferrogate-e2e-provider ferrogate-e2e-redis` and `docker network rm ferrogate-e2e-net`, then rerun sequentially.
- Do not weaken secret-redaction assertions unless the response format deliberately changed and an equivalent no-secret-leak assertion replaces them.
