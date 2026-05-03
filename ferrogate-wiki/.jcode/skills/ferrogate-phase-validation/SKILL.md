# FerroGate Phase Validation

Use this skill whenever a FerroGate PRD implementation phase or phase slice is completed and needs the required validation loop.

## Scope

This skill validates changes in the Rust workspace and updates the PRD execution evidence. It covers:

- Formatting
- Static checks
- Unit tests
- Integration tests
- Performance smoke tests
- Latency checks
- RSS memory growth checks
- Concurrency checks
- Wiki task-plan evidence updates

## Standard Commands

Run these from the repository root:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test -p ferrogate-providers -- --nocapture
cargo test -p ferrogate-config -- --nocapture
cargo test -p ferrogate-runtime -- --nocapture
cargo test -p ferrogate-cli --lib -- --nocapture
cargo test -p ferrogate-cli --test check_command -- --nocapture
cargo test -p ferrogate-cli --test proxy_runtime -- --nocapture
cargo test -p ferrogate-cli --test upstream_pool -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_auth -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_dispatch_errors -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_runtime -- --nocapture
cargo test -p ferrogate-cli --test runtime_perf -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_perf -- --nocapture
cargo run -- validate --config Ferrogate/Caddyfile
```

## Test Classification

- Unit tests: crate library tests such as `ferrogate-providers`, `ferrogate-config`, `ferrogate-runtime`, and `ferrogate-cli --lib`.
- Integration tests: `check_command`, `proxy_runtime`, `upstream_pool`, `ai_proxy_auth`, `ai_proxy_dispatch_errors`, and `ai_proxy_runtime`.
- Performance tests: `runtime_perf` and `ai_proxy_perf`.

## Performance Requirements

Every completed phase slice must include at least one relevant performance smoke path.

- Latency: assert total elapsed time and p95 latency for repeated requests.
- Memory growth: compare gateway RSS before and after the repeated request loop.
- Concurrency: when the slice affects request-path shared state, add or run a concurrent request test instead of only sequential loops.

For Linux CI or containers, RSS can be read from `/proc/<pid>/status`. On macOS, RSS checks may report `0`; keep the test tolerant or skip strict RSS assertions only when the platform cannot expose the value.

## Documentation Update

After validation, update `ferrogate-wiki/wiki/03-development/prd-implementation-plan.md`:

1. Mark completed checklist items.
2. Adjust phase progress and progress overview.
3. Add exact validation commands.
4. Record failures separately from successful checks.
5. Note environment blockers such as missing `cmake` when they prevent Rust tests from building.

Do not edit generated Quartz output under `ferrogate-wiki/wiki-site/public/` unless explicitly requested.
