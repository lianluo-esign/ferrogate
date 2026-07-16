#!/usr/bin/env bash
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-06-11
# description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

require_supply_chain_tools="${FERROGATE_SECURITY_REQUIRE_TOOLS:-0}"

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

scan_file="$(mktemp)"
trap 'rm -f "$scan_file"' EXIT

rg_common=(
  --line-number
  --no-heading
)

mapfile -d '' tracked_secret_scan_files < <(git ls-files -z -- ':!:Cargo.lock')
if [[ "${#tracked_secret_scan_files[@]}" -eq 0 ]]; then
  echo "secret scan found no tracked files" >&2
  exit 1
fi

scan_secret_pattern() {
  local label="$1"
  local pattern="$2"
  set +e
  rg "${rg_common[@]}" -- "$pattern" "${tracked_secret_scan_files[@]}" >>"$scan_file"
  local status=$?
  set -e

  if [[ "$status" -eq 0 ]]; then
    echo "secret scan matched: $label" >&2
    return 1
  fi
  if [[ "$status" -eq 1 ]]; then
    return 0
  fi

  echo "secret scan failed while checking: $label" >&2
  return 1
}

echo "==> high-confidence secret scan"
scan_failed=0
scan_secret_pattern "private key material" '-----BEGIN (RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----' || scan_failed=1
scan_secret_pattern "AWS access key id" '(AKIA|ASIA)[0-9A-Z]{16}' || scan_failed=1
scan_secret_pattern "GitHub token" 'gh[pousr]_[A-Za-z0-9_]{20,}' || scan_failed=1
scan_secret_pattern "OpenAI-style API key" 'sk-[A-Za-z0-9]{32,}' || scan_failed=1
scan_secret_pattern "Anthropic API key" 'sk-ant-[A-Za-z0-9_-]{20,}' || scan_failed=1
scan_secret_pattern "Google API key" 'AIza[0-9A-Za-z_-]{35}' || scan_failed=1

if [[ "$scan_failed" -ne 0 ]]; then
  echo "Potential secrets found:" >&2
  sed -n '1,120p' "$scan_file" >&2
  exit 1
fi

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
