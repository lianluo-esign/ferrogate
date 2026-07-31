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

EXPECTED_WORKERS="agent-gateway d1-proxy ferrogate-poc gateway-front mcp-server telemetry-collector"
EXPECTED_E2E="agent-gateway ferrogate-poc gateway-front telemetry-collector"

# The #424 Containers PoC entrypoint shape the gate greps for. Two runtime
# requirements tsc cannot see; both would turn the shim probe into a false
# negative on the claim it exists to back (#484).
POC_ENTRY_OK='import { Container, ContainerProxy, getContainer } from "@cloudflare/containers";
export { ContainerProxy };
export class FerroGateContainer extends Container {}
FerroGateContainer.outboundByHost = {};
'

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

workers_gate_invocations="$(awk '
  /^jobs:$/ { in_jobs = 1; next }
  in_jobs && /^  [A-Za-z0-9_-]+:$/ {
    in_workers = ($0 == "  workers:")
    next
  }
  in_workers && $0 == "        run: ./scripts/check-workers.sh" {
    count++
  }
  END { print count + 0 }
' "$workflow")"
[ "$workers_gate_invocations" -eq 1 ] \
  || fail "Workers workflow must invoke ./scripts/check-workers.sh exactly once in jobs.workers (found $workers_gate_invocations)"

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

# ferrogate-poc is the one Worker whose suite drives a real process, so the gate
# also checks its entrypoint shape and locates a prebuilt gateway binary.
mkdir -p "$fixture/workers/ferrogate-poc/src" "$fixture/target/debug"
printf '%s' "$POC_ENTRY_OK" >"$fixture/workers/ferrogate-poc/src/index.ts"
printf '#!/bin/sh\nexit 0\n' >"$fixture/target/debug/ferrogate"
chmod +x "$fixture/target/debug/ferrogate"

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
    FAKE_NPM_INSTALL_FAIL="${FAKE_NPM_INSTALL_FAIL:-0}" \
    WORKERS_SKIP_POC_ORIGIN="${WORKERS_SKIP_POC_ORIGIN:-}" \
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

# A broken committed lockfile must stop at npm ci. The pre-#468 fallback retried
# with npm install --legacy-peer-deps and let an unreproducible tree pass.
rm -f "$fixture/workers/d1-proxy/node_modules/.bin/tsc"
if FAKE_NPM_INSTALL_FAIL=1 run_gate; then
  fail "failed npm ci unexpectedly passed the Workers gate"
fi
assert_words_equal "d1-proxy" "$(logged_workers_for 'ci --no-audit --no-fund')" \
  "failed lockfile install"
if awk -F '|' '$2 ~ /^install( |$)/ { found = 1 } END { exit !found }' "$npm_log"; then
  fail "failed npm ci fell back to npm install"
fi
if grep -q -- '--legacy-peer-deps' "$npm_log"; then
  fail "Workers gate invoked npm with --legacy-peer-deps"
fi
if awk -F '|' '$1 == "d1-proxy" && $2 ~ /^(run typecheck|test)( |$)/ { found = 1 } END { exit !found }' "$npm_log"; then
  fail "d1-proxy continued after its npm ci failed"
fi

# A future manifest is covered without editing check-workers.sh. This is the
# behavioral assertion that catches a regression back to a literal array.
future="$fixture/workers/future-worker"
mkdir -p "$future/node_modules/.bin"
printf '{}\n' >"$future/package.json"
printf '{}\n' >"$future/package-lock.json"
printf '#!/bin/sh\nexit 0\n' >"$future/node_modules/.bin/tsc"
chmod +x "$future/node_modules/.bin/tsc"
run_gate || fail "gate rejected a manifest-derived future Worker: $(cat "$gate_err")"
assert_words_equal "agent-gateway d1-proxy ferrogate-poc future-worker gateway-front mcp-server telemetry-collector" \
  "$(logged_workers_for 'run typecheck')" "new Worker auto-discovery"
rm -rf "$future"

# --- #424 ferrogate-poc contract -------------------------------------------
#
# Each assertion below is a real false-negative the gate is there to stop. Break
# the corresponding line in check-workers.sh and exactly one of them goes red.

# 1. A missing `export { ContainerProxy };` installs no outbound interception,
#    so the shim probe fails for a reason unrelated to bindings.
printf 'export class FerroGateContainer extends Container {}\nFerroGateContainer.outboundByHost = {};\n' \
  >"$fixture/workers/ferrogate-poc/src/index.ts"
if run_gate; then
  fail "ferrogate-poc passed without 'export { ContainerProxy };'"
fi
grep -qF "missing 'export { ContainerProxy };'" "$gate_err" \
  || fail "ContainerProxy failure did not name itself: $(cat "$gate_err")"

# 2. A static class field shadows the SDK's inherited static setter, leaving the
#    outbound registry empty while the file still type-checks.
printf 'export { ContainerProxy };\nexport class FerroGateContainer extends Container {\n  static outboundByHost = {};\n}\nFerroGateContainer.outboundByHost = {};\n' \
  >"$fixture/workers/ferrogate-poc/src/index.ts"
if run_gate; then
  fail "ferrogate-poc passed with a static outboundByHost class field"
fi
grep -qF "static outboundByHost class field" "$gate_err" \
  || fail "static-field failure did not name itself: $(cat "$gate_err")"

printf '%s' "$POC_ENTRY_OK" >"$fixture/workers/ferrogate-poc/src/index.ts"
run_gate || fail "restored ferrogate-poc entrypoint was rejected: $(cat "$gate_err")"

# 3. No gateway binary must FAIL, not skip. A PoC that never reached the real
#    Pingora process is unproven, and unproven must not read as OK.
mv "$fixture/target/debug/ferrogate" "$fixture/target/debug/ferrogate.hidden"
if run_gate; then
  fail "ferrogate-poc E2E passed with no ferrogate binary present"
fi
grep -qF "no ferrogate binary found" "$gate_err" \
  || fail "missing-binary failure did not name itself: $(cat "$gate_err")"

# 4. The cargo-free lane opts out explicitly, and says what went unproven. The
#    rest of the gate still runs; only ferrogate-poc's suite is withheld.
if ! WORKERS_SKIP_POC_ORIGIN=1 run_gate; then
  fail "WORKERS_SKIP_POC_ORIGIN=1 did not let the rest of the gate pass: $(cat "$gate_err")"
fi
grep -qF "NOT PROVEN" "$gate_err" \
  || fail "opt-out did not report the withheld proof: $(cat "$gate_err")"
if awk -F '|' '$1 == "ferrogate-poc" && $2 ~ /^test( |$)/ { found = 1 } END { exit !found }' "$npm_log"; then
  fail "WORKERS_SKIP_POC_ORIGIN=1 still ran the origin-backed suite"
fi
assert_words_equal "$EXPECTED_WORKERS" "$(logged_workers_for 'run typecheck')" \
  "typecheck coverage survives the ferrogate-poc opt-out"
mv "$fixture/target/debug/ferrogate.hidden" "$fixture/target/debug/ferrogate"
run_gate || fail "restored ferrogate binary was not picked up: $(cat "$gate_err")"

# The old file-presence opt-in silently skipped E2E when this file disappeared.
# The expected-set guard must fail before reporting a green gate.
rm -f "$fixture/workers/agent-gateway/vitest.config.ts"
if run_gate; then
  fail "deleting agent-gateway/vitest.config.ts silently dropped its workerd suite"
fi
grep -qF "workerd/Vitest opt-in set changed" "$gate_err" \
  || fail "missing-config failure did not name the opt-in contract: $(cat "$gate_err")"

echo "workers gate contract passed"
