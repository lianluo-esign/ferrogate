#!/usr/bin/env bash
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-06-11
# description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

set -euo pipefail

# Bash-native, so a stripped PATH is reported by the tool preflight below
# instead of by a confusing "dirname: command not found" from this line.
SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
[[ "$SCRIPT_DIR" == "${BASH_SOURCE[0]}" ]] && SCRIPT_DIR="."
cd "$SCRIPT_DIR/.."
ROOT_DIR="$PWD"

require_supply_chain_tools="${FERROGATE_SECURITY_REQUIRE_TOOLS:-0}"

# Tool preflight (#525): resolve every non-optional tool up front and name what
# is missing. Without this the script died mid-way with a bare
# "cargo: command not found" style error that reads like an unrelated failure,
# so a gate that never ran looked like noise instead of a red gate.
# cargo deny / cargo audit stay optional and keep their own explicit skip
# notices, gated by FERROGATE_SECURITY_REQUIRE_TOOLS.
missing_tools=()
for required_tool in cargo python3 git bash mktemp sed sort comm rm tr wc; do
  command -v "$required_tool" >/dev/null 2>&1 || missing_tools+=("$required_tool")
done
if [[ "${#missing_tools[@]}" -ne 0 ]]; then
  echo "security check did NOT run: missing required tool(s) on PATH: ${missing_tools[*]}" >&2
  echo "a gate that cannot run must fail loudly instead of skipping itself (#525)" >&2
  exit 1
fi

# Un-suppressable secret scan (#525): the secret scan is the security-critical
# heart of this gate, yet it used to run LAST under `set -e`, so ANY earlier
# fmt/clippy/build hiccup aborted the script before the scan ever executed --
# "the scan silently never runs". We now record each step's failure into
# `overall_status` WITHOUT aborting, ALWAYS run the secret scan, and only then
# exit non-zero if anything (the scan or an earlier step) failed. A future
# fmt/clippy/metadata failure can therefore never again suppress the scan.
overall_status=0

# Run a labelled step, capturing (not propagating) its failure. errexit is
# suspended for the command itself via the `if !` guard, so a red step marks
# `overall_status` and the script keeps going to the secret scan.
run_step() {
  local label="$1"
  shift
  echo "==> $label"
  if ! "$@"; then
    echo "FAILED: $label" >&2
    overall_status=1
  fi
}

cargo_metadata_locked() {
  cargo metadata --locked --format-version=1 >/dev/null
}

run_step "cargo fmt" cargo fmt --check
# Reconciled to the repo's pinned clippy toolchain (see release-local.sh); the
# default (1.97) toolchain surfaced lints nothing else in the repo enforces.
run_step "cargo clippy" cargo +1.88.0 clippy --workspace --all-targets --all-features -- -D warnings
run_step "cargo metadata --locked" cargo_metadata_locked
run_step "vendored Pingora integrity" python3 scripts/check-pingora-vendor.py
run_step "protobuf advisory floor" python3 scripts/check-protobuf-advisory.py

# The security-critical secret scan ALWAYS runs, regardless of any failure
# above. It lives in its own script so it is drivable (and testable) without a
# full cargo build; see scripts/test-check-secret-scan.sh.
echo "==> secret scan"
if ! bash scripts/check-secret-scan.sh; then
  echo "FAILED: secret scan" >&2
  overall_status=1
fi

run_step "cargo-audit exception policy" python3 scripts/check-audit-exceptions.py
run_step "immutable GitHub Actions references" python3 scripts/check-workflow-action-pins.py

if cargo deny --version >/dev/null 2>&1; then
  run_step "cargo deny" cargo deny check licenses bans sources
elif [[ "$require_supply_chain_tools" == "1" ]]; then
  echo "cargo deny is required when FERROGATE_SECURITY_REQUIRE_TOOLS=1" >&2
  overall_status=1
else
  echo "==> cargo deny not installed; skipping"
fi

if cargo audit --version >/dev/null 2>&1; then
  run_step "cargo audit" cargo audit
elif [[ "$require_supply_chain_tools" == "1" ]]; then
  echo "cargo audit is required when FERROGATE_SECURITY_REQUIRE_TOOLS=1" >&2
  overall_status=1
else
  echo "==> cargo audit not installed; skipping"
fi

if [[ "$overall_status" -ne 0 ]]; then
  echo "security check FAILED" >&2
  exit "$overall_status"
fi

echo "security check passed"
