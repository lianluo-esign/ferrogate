# Coverage baseline — full-business-coverage test initiative (epic #112)

Generated with `cargo llvm-cov` on 2026-07-01, domain-logic crates.

| Crate / file | Line cover | Missed regions | Priority |
|---|---|---|---|
| ferrogate-core/src/lib.rs | 0.00% | 5/5 | high (tiny, trivial win) |
| ferrogate-config/src/loader.rs | 0.00% | 25/25 | high |
| ferrogate-auth/src/lib.rs | 36.69% | 281/413 | high (#103) |
| ferrogate-auth/src/main.rs | 0.00% | 15/15 | med (serve entrypoint) |
| ferrogate-mcp/src/lib.rs | 38.92% | 863/1335 | high (#108) |
| ferrogate-config/src/caddyfile/parser.rs | 73.99% | 218/806 | med (#102) |
| ferrogate-config/src/caddyfile/parser_support.rs | 76.82% | 69/280 | med (#102) |
| ferrogate-billing/src/lib.rs | 80.21% | 40/221 | med (#105) |
| ferrogate-observability/src/lib.rs | 84.65% | 142/867 | low (#107) |
| ferrogate-policy/src/lib.rs | 99.19% | 1/159 | low (#104) |

**TOTAL (these crates): 65.07% lines, 60.97% regions, 55.39% functions.**

Not shown (measured separately — larger + integration-heavy): ferrogate-cli, ferrogate-storage, ferrogate-runtime, agent-worker, ferrogate-providers.

## Harness
Build on the existing `ferrogate-test` scenario tool (validated: `admin-api` green against a fresh `target/debug/ferrogate`). New full-link scenarios extend `scenarios.rs`/`storage.rs`, wire through the `Dispatch` struct, and join the `ci` aggregate. Control-plane facets penetrate a real Supabase/Postgres via the existing Docker-Postgres bootstrap.

## Known flake
`ferrogate-cli --test ai_proxy_runtime` passes standalone (34/0) but can fail under the fully-parallel instrumented `--workspace` coverage run — listener/port contention in reload/streaming tests under instrumentation slowdown. Run coverage per-crate or serialized; harden the port-binding tests as part of #106.
