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
  ai-proxy
  cli-tooling
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
  cargo test -p ferrogate-cli --all-features config::tests
  cargo test -p ferrogate-cli --all-features config::validation_tests
  python3 scripts/check-openapi.py
  # Greppability gate (#487): a NUL byte makes git/grep/ripgrep treat a source
  # file as binary and skip it silently, so every repo-wide sweep (secret scan,
  # literal audits, dead-code greps) quietly loses coverage.
  python3 scripts/check-binary-source-files.py
  # Secret scan + its own tests (#525): the scan used to hard-code ripgrep, so
  # on a box without it the gate died instead of running. Both are sub-second.
  scripts/check-secret-scan.sh
  scripts/test-check-secret-scan.sh
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
  cargo test -p ferrogate-cli --all-features --test agentic_lite
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
  cargo test -p ferrogate-test --all-features
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
    ai-proxy) run_ai_proxy ;;
    cli-tooling) run_cli_tooling ;;
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
    ai-proxy
    cli-tooling
    gateway-runtime
    e2e-harness
    supabase-storage
  )
fi

for module in "${modules[@]}"; do
  run_module "$module"
done
