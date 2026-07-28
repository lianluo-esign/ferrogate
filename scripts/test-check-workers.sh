#!/usr/bin/env bash
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-28
# description: Behavioral contract tests for the Cloudflare Workers gate (#499).

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gate="$root/scripts/check-workers.sh"
workflow="$root/.github/workflows/workers.yml"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_words_equal() {
  local expected="$1"
  local actual="$2"
  local subject="$3"
  [ "$actual" = "$expected" ] \
    || fail "$subject: expected '$expected', got '${actual:-<empty>}'"
}

EXPECTED_WORKERS="agent-gateway d1-proxy gateway-front mcp-server telemetry-collector"
EXPECTED_E2E="agent-gateway gateway-front telemetry-collector"

# Pin the current repository surface. The product gate derives this list from
# manifests; the test keeps additions/removals intentional and reviewable.
actual_workers="$({
  for manifest in "$root"/workers/*/package.json; do
    [ -f "$manifest" ] || continue
    basename "$(dirname "$manifest")"
  done
} | sort | paste -sd ' ' -)"
assert_words_equal "$EXPECTED_WORKERS" "$actual_workers" \
  "workers/*/package.json set"

actual_e2e="$({
  for config in "$root"/workers/*/vitest.config.ts; do
    [ -f "$config" ] || continue
    basename "$(dirname "$config")"
  done
} | sort | paste -sd ' ' -)"
assert_words_equal "$EXPECTED_E2E" "$actual_e2e" \
  "workerd/Vitest opt-in set"

# Parse only the top-level `on` mapping. The exact trigger set matters here:
# removing push or pull_request recreates the release-only hole from #499.
actual_triggers="$(awk '
  /^on:$/ { in_on = 1; next }
  in_on && /^[^[:space:]#]/ { exit }
  in_on && /^  [a-z_]+:$/ {
    trigger = $0
    sub(/^  /, "", trigger)
    sub(/:$/, "", trigger)
    print trigger
  }
' "$workflow" | paste -sd ' ' -)"
assert_words_equal "workflow_call workflow_dispatch push pull_request" \
  "$actual_triggers" "Workers workflow trigger set"

assert_path_filter() {
  local path="$1"
  local count
  count="$(awk -v expected="      - \"$path\"" '$0 == expected { count++ } END { print count + 0 }' "$workflow")"
  [ "$count" -eq 2 ] \
    || fail "Workers workflow must path-filter push and pull_request on $path (found $count entries)"
}

assert_path_filter "workers/**"
assert_path_filter "scripts/check-workers.sh"
assert_path_filter "scripts/test-check-workers.sh"
assert_path_filter "scripts/node-env.sh"
assert_path_filter ".github/workflows/workers.yml"

# Drive the real gate against a hermetic Worker tree. npm records commands and
# materializes only the binaries an install would supply; no package manager,
# TypeScript compiler, Vitest runner, network, or workerd process is invoked.
fixture="$tmp/repo"
mkdir -p "$fixture/scripts" "$fixture/workers" "$tmp/toolchain" "$tmp/home"
cp "$gate" "$root/scripts/node-env.sh" "$fixture/scripts/"

for worker in $EXPECTED_WORKERS; do
  worker_dir="$fixture/workers/$worker"
  mkdir -p "$worker_dir/node_modules/.bin"
  printf '{}\n' >"$worker_dir/package.json"
  printf '{}\n' >"$worker_dir/package-lock.json"
  printf '#!/bin/sh\nexit 0\n' >"$worker_dir/node_modules/.bin/tsc"
  chmod +x "$worker_dir/node_modules/.bin/tsc"
done
for worker in $EXPECTED_E2E; do
  worker_dir="$fixture/workers/$worker"
  : >"$worker_dir/vitest.config.ts"
  printf '#!/bin/sh\nexit 0\n' >"$worker_dir/node_modules/.bin/vitest"
  chmod +x "$worker_dir/node_modules/.bin/vitest"
done

cat >"$tmp/toolchain/node" <<'SH'
#!/bin/sh
exit 0
SH
cat >"$tmp/toolchain/npm" <<'SH'
#!/bin/sh
set -eu
worker="${PWD##*/}"
printf '%s|%s\n' "$worker" "$*" >>"$NPM_LOG"
case "$1" in
  ci|install)
    [ "${FAKE_NPM_INSTALL_FAIL:-0}" = "0" ] || exit 19
    mkdir -p node_modules/.bin
    printf '#!/bin/sh\nexit 0\n' >node_modules/.bin/tsc
    chmod +x node_modules/.bin/tsc
    if [ -f vitest.config.ts ]; then
      printf '#!/bin/sh\nexit 0\n' >node_modules/.bin/vitest
      chmod +x node_modules/.bin/vitest
    fi
    ;;
esac
exit 0
SH
chmod +x "$tmp/toolchain/node" "$tmp/toolchain/npm"

npm_log="$tmp/npm.log"
gate_out="$tmp/gate.out"
gate_err="$tmp/gate.err"

run_gate() {
  : >"$npm_log"
  env -i \
    HOME="$tmp/home" \
    PATH="$tmp/toolchain:/usr/bin:/bin" \
    FERROGATE_NODE_BIN="$tmp/toolchain" \
    NPM_LOG="$npm_log" \
    "$fixture/scripts/check-workers.sh" >"$gate_out" 2>"$gate_err"
}

logged_workers_for() {
  local command="$1"
  awk -F '|' -v command="$command" '$2 == command { print $1 }' "$npm_log" \
    | sort | paste -sd ' ' -
}

run_gate || fail "usable fixture failed: $(cat "$gate_err")"
assert_words_equal "$EXPECTED_WORKERS" "$(logged_workers_for 'run typecheck')" \
  "manifest-derived typecheck coverage"
assert_words_equal "$EXPECTED_E2E" "$(logged_workers_for 'test')" \
  "pinned workerd/Vitest execution coverage"
if awk -F '|' '$2 ~ /^(ci|install)( |$)/ { found = 1 } END { exit !found }' "$npm_log"; then
  fail "usable node_modules unexpectedly triggered an install"
fi

# Reverting worker_tree_is_usable to `[ -d node_modules ]` makes both of these
# assertions red: missing executables must trigger a clean lockfile install.
rm -f "$fixture/workers/d1-proxy/node_modules/.bin/tsc"
run_gate || fail "missing tsc was not repaired: $(cat "$gate_err")"
assert_words_equal "d1-proxy" "$(logged_workers_for 'ci --no-audit --no-fund')" \
  "missing tsc reinstall"

rm -f "$fixture/workers/agent-gateway/node_modules/.bin/vitest"
run_gate || fail "missing vitest was not repaired: $(cat "$gate_err")"
assert_words_equal "agent-gateway" "$(logged_workers_for 'ci --no-audit --no-fund')" \
  "missing vitest reinstall"

# A future manifest is covered without editing check-workers.sh. This is the
# behavioral assertion that catches a regression back to a literal array.
future="$fixture/workers/future-worker"
mkdir -p "$future/node_modules/.bin"
printf '{}\n' >"$future/package.json"
printf '{}\n' >"$future/package-lock.json"
printf '#!/bin/sh\nexit 0\n' >"$future/node_modules/.bin/tsc"
chmod +x "$future/node_modules/.bin/tsc"
run_gate || fail "gate rejected a manifest-derived future Worker: $(cat "$gate_err")"
assert_words_equal "agent-gateway d1-proxy future-worker gateway-front mcp-server telemetry-collector" \
  "$(logged_workers_for 'run typecheck')" "new Worker auto-discovery"
rm -rf "$future"

# The old file-presence opt-in silently skipped E2E when this file disappeared.
# The expected-set guard must fail before reporting a green gate.
rm -f "$fixture/workers/agent-gateway/vitest.config.ts"
if run_gate; then
  fail "deleting agent-gateway/vitest.config.ts silently dropped its workerd suite"
fi
grep -qF "workerd/Vitest opt-in set changed" "$gate_err" \
  || fail "missing-config failure did not name the opt-in contract: $(cat "$gate_err")"

echo "workers gate contract passed"
