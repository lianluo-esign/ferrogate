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

echo "==> cargo fmt"
cargo fmt --check

echo "==> cargo clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> cargo metadata --locked"
cargo metadata --locked --format-version=1 >/dev/null

echo "==> vendored Pingora integrity"
python3 scripts/check-pingora-vendor.py

echo "==> protobuf advisory floor"
python3 scripts/check-protobuf-advisory.py

# Secret scan lives in its own script so it is drivable (and testable) without
# a full cargo build; see scripts/test-check-secret-scan.sh.
bash scripts/check-secret-scan.sh

echo "==> cargo-audit exception policy"
python3 scripts/check-audit-exceptions.py

echo "==> immutable GitHub Actions references"
python3 scripts/check-workflow-action-pins.py

if cargo deny --version >/dev/null 2>&1; then
  echo "==> cargo deny"
  cargo deny check licenses bans sources
elif [[ "$require_supply_chain_tools" == "1" ]]; then
  echo "cargo deny is required when FERROGATE_SECURITY_REQUIRE_TOOLS=1" >&2
  exit 1
else
  echo "==> cargo deny not installed; skipping"
fi

if cargo audit --version >/dev/null 2>&1; then
  echo "==> cargo audit"
  cargo audit
elif [[ "$require_supply_chain_tools" == "1" ]]; then
  echo "cargo audit is required when FERROGATE_SECURITY_REQUIRE_TOOLS=1" >&2
  exit 1
else
  echo "==> cargo audit not installed; skipping"
fi

echo "security check passed"
