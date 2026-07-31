#!/usr/bin/env bash
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-06-27
# description: Local feature-module test runner for FerroGate issue development.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.88.0}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/local-test-modules.sh list
  scripts/local-test-modules.sh <module> [module...]
  scripts/local-test-modules.sh all

Modules:
  quality
  core-policy
  control-plane
  agentic-gateway
  governed-decisions
  ai-proxy
  cli-tooling
  platform-crates
  gateway-runtime
  e2e-harness
  supabase-storage

Notes:
  - Runs modules sequentially for predictable local behavior.
  - Docker-backed harness scenarios reuse fixed container names; keep them sequential.
  - Set RUSTUP_TOOLCHAIN to override the default 1.88.0 toolchain.
USAGE
}

ensure_toolchain() {
  if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo is required on the local test host" >&2
    exit 1
  fi

  if command -v rustup >/dev/null 2>&1; then
    if rustup toolchain list | awk '{print $1}' | grep -Eq "^${RUSTUP_TOOLCHAIN}($|-)" ; then
      export RUSTUP_TOOLCHAIN
      return
    fi
    echo "Rust toolchain $RUSTUP_TOOLCHAIN is not installed; install it on the local test host before running module tests." >&2
    exit 1
  fi

  echo "rustup is not installed; using the active cargo toolchain." >&2
}

run_quality() {
  ensure_toolchain
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  cargo metadata --locked --format-version=1 >/dev/null
  # These named `-p ferrogate-cli` until #561's rework and had selected zero
  # tests since #553 stage 1 moved the config module into its own crate. A
  # cargo filter that matches nothing exits 0, so both ran nothing, in silence,
  # in this file and in rust-quality.yml alike. 21 and 193 tests now.
  cargo test -p ferrogate-config --all-features config::tests
  cargo test -p ferrogate-config --all-features config::validation_tests
  python3 scripts/check-openapi.py
  # Coverage gate (#561): fails when a workspace member's tests are executed by
  # no CI slice, or by no module in this file. Sub-second, no cargo work.
  python3 -m unittest scripts/test_ci_crate_coverage.py
  python3 scripts/check-ci-crate-coverage.py
  # Greppability gate (#487): a NUL byte makes git/grep/ripgrep treat a source
  # file as binary and skip it silently, so every repo-wide sweep (secret scan,
  # literal audits, dead-code greps) quietly loses coverage.
  python3 scripts/check-binary-source-files.py
  # Secret scan + its own tests (#525): the scan used to hard-code ripgrep, so
  # on a box without it the gate died instead of running. Both are sub-second.
  scripts/check-secret-scan.sh
  scripts/test-check-secret-scan.sh
  # Gate contracts and the module-layout ratchet mirror rust-quality.yml. A
  # workflow-only invocation would catch these only after release (#499).
  scripts/test-check-admin-console.sh
  python3 -m unittest scripts/test_admin_console_workflow.py
  scripts/test-check-workers.sh
  python3 -m unittest scripts/test_module_layout.py
  python3 scripts/check-module-layout.py
  python3 -m unittest scripts/test_check_d1_surface_map.py
  python3 scripts/check-d1-surface-map.py
  scripts/check-kubernetes-examples.sh
}

run_core_policy() {
  ensure_toolchain
  cargo test -p ferrogate-core --all-features
  cargo test -p ferrogate-config --all-features
  cargo test -p ferrogate-policy --all-features
  cargo test -p ferrogate-routing --all-features
}

run_control_plane() {
  ensure_toolchain
  cargo test -p ferrogate-admin --all-features
  cargo test -p ferrogate-auth-service --all-features
  cargo test -p ferrogate-storage --all-features
  cargo test -p ferrogate-billing --all-features
  cargo test -p ferrogate-observability --all-features
}

run_agentic_gateway() {
  ensure_toolchain
  cargo test -p ferrogate-providers --all-features
  cargo test -p ferrogate-mcp --all-features
  cargo test -p ferrogate-runtime --all-features
  # The `guardrails` slice of rust-agentic-gateway-tests.yml. It was missing
  # here (#561), so the crate ran in CI and nowhere locally.
  cargo test -p ferrogate-guardrails --all-features
  cargo test -p ferrogate-cli --all-features --test agentic_lite
}

# Mirrors rust-platform-crate-tests.yml (#561). Until that workflow existed,
# none of these crates -- ferrogate-gateway among them, the largest in the
# workspace -- was executed by any job or any module here.
run_platform_crates() {
  ensure_toolchain
  # The four `--skip` filters that stood here were #563's, and #563 landed --
  # deleting them from rust-platform-crate-tests.yml and not from here, which
  # is the CI/local drift this module exists to end, reappearing inside the
  # commit that closed it. 1067 passed / 0 failed / 0 filtered out.
  cargo test -p ferrogate-gateway --all-features
  # AGENT_WORKER_DOCKER_BIN matches the workflow slice, for the reason spelled
  # out there: three tests in this crate branch on a bare `docker version`
  # probe rather than on the AGENT_WORKER_ENABLE_DOCKER_BACKEND opt-in, so on a
  # host with a daemon they pull and exec a real container and quietly stop
  # asserting the daemon-unreachable fail-closed path. Pinning the probe makes
  # this run the same thing everywhere.
  AGENT_WORKER_DOCKER_BIN=agent-worker-docker-absent \
    cargo test -p agent-worker --all-features
  cargo test -p ferrogate-cloudflare --all-features
  cargo test -p ferrogate-secrets --all-features
  cargo test -p ferrogate-payments --all-features
  cargo test -p ferrogate-sync-bridge --all-features
}

# Mirrors `governed-decision-conformance.yml`'s Runner A (#470, #561 rework).
# That workflow had no line in this file at all, and the crate coverage gate
# could not see the hole because `ferrogate-gateway` is selected by the
# platform-crates module anyway -- selection is not health, and this is what
# that disclaimer costs when nobody reads it.
run_governed_decisions() {
  ensure_toolchain
  cargo test -p ferrogate-gateway --all-features governed_decision
}

run_ai_proxy() {
  ensure_toolchain
  cargo test -p ferrogate-cli --all-features --test ai_proxy_auth
  cargo test -p ferrogate-cli --all-features --test ai_proxy_dispatch_errors
  cargo test -p ferrogate-cli --all-features --test ai_proxy_runtime
  cargo test -p ferrogate-cli --all-features --test proxy_runtime
  cargo test -p ferrogate-cli --all-features --test upstream_pool
}

run_cli_tooling() {
  ensure_toolchain
  cargo test -p ferrogate-cli --all-features --bins
  cargo test -p ferrogate-cli --all-features --test check_command --test workspace_skeleton
  # Mirrors the `cli_e2e` slice of `rust-cli-tooling-tests.yml`, which was the
  # remaining hole in this mirror (#561).
  cargo test -p ferrogate-cli --all-features \
    --test control_cli_e2e --test control_cli_resource_e2e --test ctl_lifecycle_e2e
  # Mirrors the `control_plane_client` slice of `rust-cli-tooling-tests.yml`
  # (renamed from `cli_core` with the crate in #553). It was missing here, so
  # the crate's hermetic client tests had no local invocation at all. 20,961
  # `.rs` lines across 53 files at `4c2ba43`, of which 11,024 across 26
  # `*_test.rs` files are test code and 9,937 across 27 files are not -- the
  # first published figure attached "of hermetic client tests" to the whole-
  # crate count, which is the crate's size, not its suite's. The dedicated test
  # files are therefore 52.6% of the crate by lines (11,024 / 20,961). The other
  # 27 files contain the `#[path = "*_test.rs"] mod ...;` declarations that wire
  # those same files in, not additional inline test bodies: none contains a
  # `#[test]`, so those declaration lines are not counted twice. Reproduce the
  # whole-crate number at the ref rather than in the working tree:
  #   git ls-tree -r --name-only 4c2ba43 -- \
  #     crates/ferrogate-control-plane-client | grep '\.rs$' \
  #     | xargs -I{} git show 4c2ba43:{} | wc -l
  cargo test -p ferrogate-control-plane-client --all-features
  cargo test -p ferrogate-test --all-features
  # Mirrors the `cli_all` slice. #561 measured the unfiltered run as red on
  # arrival (352 passed, 13 failed across 8 targets) and left it out rather
  # than land a check the next person would turn off; #564 fixed all 13, so it
  # is here. 66 targets, 365 passed, 0 failed.
  #
  # In CI this is one more parallel matrix leg. HERE it is not: this file runs
  # everything sequentially on purpose, so this line is 134s added to the end
  # of the module -- 71s of it in target_capability_e2e -- over targets the
  # four filtered lines above have already built and largely already run. That
  # is a real duplication and it is the price of the mirror being a mirror. It
  # comes last so the filtered slices report first.
  cargo test -p ferrogate-cli --all-features
}

run_gateway_runtime() {
  ensure_toolchain
  cargo test -p ferrogate-cli --test runtime_perf -- --nocapture
  cargo test -p ferrogate-cli --test ai_proxy_perf -- --nocapture
}

run_e2e_harness() {
  ensure_toolchain
  cargo build -p ferrogate-cli -p ferrogate-auth-service -p ferrogate-test --locked
  ./target/debug/ferrogate-test ci
}

run_supabase_storage() {
  ensure_toolchain
  cargo build -p ferrogate-cli -p ferrogate-test --locked
  ./target/debug/ferrogate-test supabase-migration
  ./target/debug/ferrogate-test supabase-restart
  if [[ -n "${FERROGATE_SUPABASE_DSN:-}" ]]; then
    args=()
    if [[ -n "${FERROGATE_SUPABASE_TLS_MODE:-}" ]]; then
      args+=(--tls-mode "$FERROGATE_SUPABASE_TLS_MODE")
    fi
    if [[ -n "${FERROGATE_SUPABASE_TLS_CA_CERT_PATH:-}" ]]; then
      args+=(--tls-ca-cert-path "$FERROGATE_SUPABASE_TLS_CA_CERT_PATH")
    fi
    ./target/debug/ferrogate-test component-compliance-supabase "${args[@]}"
    ./target/debug/ferrogate-test supabase-live-smoke "${args[@]}"
    if [[ -n "${FERROGATE_TOKEN4AI_OPENAI_API_KEY:-}" ]]; then
      ./target/debug/ferrogate-test supabase-live-token4ai-provider "${args[@]}"
    else
      echo "FERROGATE_TOKEN4AI_OPENAI_API_KEY is not configured; skipping optional live Token4AI provider billing scenario."
    fi
  else
    echo "FERROGATE_SUPABASE_DSN is not configured; skipping optional live Supabase restart scenario."
  fi
}

run_module() {
  local module="$1"
  echo "==> local module: $module"
  case "$module" in
    quality) run_quality ;;
    core-policy) run_core_policy ;;
    control-plane) run_control_plane ;;
    agentic-gateway) run_agentic_gateway ;;
    governed-decisions) run_governed_decisions ;;
    ai-proxy) run_ai_proxy ;;
    cli-tooling) run_cli_tooling ;;
    platform-crates) run_platform_crates ;;
    gateway-runtime) run_gateway_runtime ;;
    e2e-harness) run_e2e_harness ;;
    supabase-storage) run_supabase_storage ;;
    list) usage ;;
    *)
      echo "unknown module: $module" >&2
      usage >&2
      exit 2
      ;;
  esac
}

if [[ "$#" -eq 0 ]]; then
  usage >&2
  exit 2
fi

if [[ "$1" == "list" ]]; then
  usage
  exit 0
fi

modules=("$@")
if [[ "$1" == "all" ]]; then
  modules=(
    quality
    core-policy
    control-plane
    agentic-gateway
    governed-decisions
    ai-proxy
    cli-tooling
    platform-crates
    gateway-runtime
    e2e-harness
    supabase-storage
  )
fi

for module in "${modules[@]}"; do
  run_module "$module"
done
