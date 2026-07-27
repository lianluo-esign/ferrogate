#!/usr/bin/env bash
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-27
# description: Contract test for the admin-console gate's toolchain handling.
#
# #508: the admin-console gate was runnable but undiscoverable, and could be
# not-run without saying so. Believing it could not run, #351 landed without it
# and regressed the #313 admin-API coverage guard. This test holds the fix:
#
#   1. No Node reachable  -> exit != 0 AND the exact line
#      "admin-console gate did NOT run: node not found on PATH" on stderr.
#      NOT a skip, NOT an OK.
#   2. Node present but npm not -> the analogous npm line, also non-zero.
#   3. Node off PATH but discoverable -> the gate finds it and runs with it.
#   4. Chromium present but unlaunchable -> named failure, not a warning it
#      walks past (`playwright install` exits 0 on a host missing browser libs).
#   5. SKIP_ADMIN_CONSOLE_CHECK=1 -> still an explicit, announced opt-out.
#
# No real build is ever triggered: the gate either refuses before doing any
# work, or runs against stub node/npm/npx binaries in a scrubbed PATH.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gate="$root/scripts/check-admin-console.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# A PATH with the usual system utilities but NO node/npm/npx, plus a $HOME with
# no toolchain in it: the "node is off PATH" state #508 is about, reproduced
# without touching the real environment.
mkdir -p "$tmp/bin" "$tmp/home" "$tmp/empty/bin"
for d in /bin /usr/bin; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    ln -sf "$f" "$tmp/bin/$(basename "$f")" 2>/dev/null || true
  done
done
rm -f "$tmp/bin/node" "$tmp/bin/npm" "$tmp/bin/npx" "$tmp/bin/nodejs"

run_gate() { # run_gate <node-bin-dir-or-empty> [env assignments...]
  local node_bin="$1"; shift
  env -i \
    HOME="$tmp/home" \
    PATH="$tmp/bin" \
    FERROGATE_NODE_BIN="$node_bin" \
    "$@" \
    "$gate" >"$tmp/out" 2>"$tmp/err"
}

# --- 1. node unreachable: loud, named, non-zero ------------------------------
if run_gate "$tmp/empty/bin"; then
  fail "gate exited 0 with no Node reachable (silently skipped -- the #508 defect)"
fi
grep -qxF "admin-console gate did NOT run: node not found on PATH" "$tmp/err" \
  || fail "missing exact loud-failure line on stderr; got: $(cat "$tmp/err")"
grep -qF "env: 'node': No such file or directory" "$tmp/err" \
  || fail "hint does not mention the shebang gotcha"
grep -qF "FERROGATE_NODE_BIN" "$tmp/err" \
  || fail "hint does not tell the operator how to point at an off-PATH toolchain"
if grep -qE "admin-console gate: (OK|skipped)" "$tmp/out"; then
  fail "gate reported OK/skipped while not running"
fi

# --- 2. node present, npm absent: still loud and non-zero -------------------
mkdir -p "$tmp/nodeonly/bin"
printf '#!/bin/sh\necho vFAKE-NODEONLY\n' >"$tmp/nodeonly/bin/node"
chmod +x "$tmp/nodeonly/bin/node"
if run_gate "$tmp/nodeonly/bin"; then
  fail "gate exited 0 with npm unreachable"
fi
grep -qxF "admin-console gate did NOT run: npm not found on PATH" "$tmp/err" \
  || fail "missing exact npm loud-failure line; got: $(cat "$tmp/err")"

# --- 3. off-PATH toolchain is discovered and actually used ------------------
# Stub node/npm so the discovery path is proved without running a real build.
mkdir -p "$tmp/toolchain/bin"
printf '#!/bin/sh\necho vFAKE-DISCOVERED\n' >"$tmp/toolchain/bin/node"
printf '#!/bin/sh\nif [ "$1" = "-v" ]; then echo 0.0.0-FAKE; fi\nexit 0\n' \
  >"$tmp/toolchain/bin/npm"
printf '#!/bin/sh\nexit 0\n' >"$tmp/toolchain/bin/npx"
chmod +x "$tmp/toolchain/bin/node" "$tmp/toolchain/bin/npm" "$tmp/toolchain/bin/npx"
run_gate "$tmp/toolchain/bin" \
  || fail "gate refused a reachable off-PATH toolchain: $(cat "$tmp/err")"
grep -qF "vFAKE-DISCOVERED" "$tmp/out" \
  || fail "gate did not report the off-PATH node it resolved; got: $(cat "$tmp/out")"
if grep -qF "did NOT run" "$tmp/err"; then
  fail "gate claimed it did not run while a toolchain was reachable"
fi

# --- 4. an unlaunchable browser is a failure, not a warning -----------------
# `playwright install` exits 0 while only WARNING that the host lacks chromium's
# shared libraries; the suite then dies a minute later. The gate must promote
# that warning to a named failure instead of marching on.
mkdir -p "$tmp/nodeps/bin"
cp "$tmp/toolchain/bin/node" "$tmp/toolchain/bin/npm" "$tmp/nodeps/bin/"
printf '#!/bin/sh\necho "Host system is missing dependencies to run browsers."\nexit 0\n' \
  >"$tmp/nodeps/bin/npx"
chmod +x "$tmp/nodeps/bin/npx"
if run_gate "$tmp/nodeps/bin"; then
  fail "gate passed with a chromium that cannot launch (browser contract unproven)"
fi
grep -qF "admin-console gate did NOT run: chromium is downloaded but cannot launch" "$tmp/err" \
  || fail "missing actionable chromium-deps failure; got: $(cat "$tmp/err")"
grep -qF "playwright install-deps chromium" "$tmp/err" \
  || fail "chromium-deps failure does not name the fix command"

# --- 5. the explicit opt-out is still explicit ------------------------------
run_gate "$tmp/empty/bin" SKIP_ADMIN_CONSOLE_CHECK=1 \
  || fail "SKIP_ADMIN_CONSOLE_CHECK=1 did not exit 0"
grep -qF "admin-console gate: skipped (SKIP_ADMIN_CONSOLE_CHECK=1)" "$tmp/out" \
  || fail "explicit skip did not announce itself"

echo "admin-console gate toolchain contract passed"
