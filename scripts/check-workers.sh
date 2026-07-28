#!/usr/bin/env bash
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-25
# description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
#
# Cloudflare Workers gate (#465): TypeScript typecheck for every Worker under
# workers/ (agent-gateway, mcp-server, d1-proxy, telemetry-collector).
# Runs standalone for dev use and from scripts/release-local.sh (no GitHub
# Actions per the release directive), mirroring scripts/check-admin-console.sh.
#
#   scripts/check-workers.sh                  # full gate
#   SKIP_WORKERS_CHECK=1 scripts/...          # explicit skip (prints a note)
#
# Every Worker's package.json declares `typecheck: tsc --noEmit`, but until this
# gate nothing ever invoked it: the TypeScript that ships to Cloudflare was
# checked by no gate at all, so a type error surfaced only at `wrangler deploy`.
#
# Dependencies install only when node_modules is missing (same contract as the
# admin-console gate): `npm ci` when the Worker has a committed
# package-lock.json — pinned and reproducible — and `npm install` otherwise.
# Delete node_modules (or run the install yourself) to force a clean install.
set -euo pipefail

if [ "${SKIP_WORKERS_CHECK:-}" = "1" ]; then
  echo "workers gate: skipped (SKIP_WORKERS_CHECK=1)"
  exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Locate Node ourselves and refuse loudly when we cannot (#508): on the dev
# boxes Node lives under $HOME and is not always on a non-login shell's PATH.
# shellcheck source=scripts/node-env.sh
. "$ROOT/scripts/node-env.sh"
ferrogate_require_node "workers gate" || exit 1

# DERIVED, not hand-maintained (#499 review): the list used to be
# `WORKERS=(agent-gateway mcp-server d1-proxy telemetry-collector)`, and
# workers/gateway-front -- a real Worker with its own package.json -- was
# simply not in it. The gate went GREEN while not covering it, which is the
# same silent-skip class this issue is about, one level up: the gate ran, and
# the thing it did not run was invisible.
#
# Every directory under workers/ carrying a package.json is a Worker and is
# gated. Adding a Worker cannot now forget to add it here.
WORKERS=()
for candidate in "$ROOT"/workers/*/; do
  [ -f "${candidate}package.json" ] || continue
  WORKERS+=("$(basename "$candidate")")
done
if [ "${#WORKERS[@]}" -eq 0 ]; then
  echo "ERROR: workers gate found no workers/*/package.json -- refusing to report success" >&2
  echo "       (a gate that silently covers nothing is the defect this guards against)" >&2
  exit 1
fi
echo "-- gating ${#WORKERS[@]} workers: ${WORKERS[*]}"

echo "== workers gate =="
for worker in "${WORKERS[@]}"; do
  echo "== workers/$worker =="
  cd "$ROOT/workers/$worker"

  # #499: "node_modules exists" is NOT "node_modules is usable". Testing the
  # directory let a tree that predates a dependency being added satisfy the
  # check: workers/agent-gateway had a node_modules with no `vitest` and no
  # @cloudflare/vitest-pool-workers, so `npm test` died with `vitest: not
  # found` while the script silently skipped the reinstall that would have
  # fixed it -- the gate quietly degraded to typecheck-only, which is exactly
  # the silent-skip class this issue is about.
  #
  # So ask for what the gate is about to RUN, not for a directory: `tsc` for
  # the typecheck every Worker gets, and `vitest` for the Workers that opt
  # into the workerd E2E by committing a vitest.config.ts. `npm ci` on a clean
  # checkout is the lockfile-reproducibility proof; this local fast path only
  # avoids reinstalling an already usable tree.
  worker_tree_is_usable() {
    [ -d node_modules ] || return 1
    [ -x node_modules/.bin/tsc ] || return 1
    if [ -f vitest.config.ts ]; then
      [ -x node_modules/.bin/vitest ] || return 1
    fi
    return 0
  }

  if ! worker_tree_is_usable; then
    if [ -d node_modules ]; then
      echo "-- reinstalling: node_modules is present but does not satisfy the gate" >&2
    fi
    if [ -f package-lock.json ]; then
      echo "-- npm ci (node_modules missing or unusable)"
      npm ci --no-audit --no-fund \
        || { echo "ERROR: workers/$worker: npm ci failed; the committed lockfile must reproduce exactly" >&2; exit 1; }
    else
      echo "-- npm install (node_modules missing, no package-lock.json)"
      npm install --no-audit --no-fund \
        || { echo "ERROR: workers/$worker: npm install failed" >&2; exit 1; }
    fi
  fi

  echo "-- typecheck (tsc --noEmit)"
  npm run typecheck \
    || { echo "ERROR: workers/$worker: typecheck failed" >&2; exit 1; }

  # Docker-free Worker E2E: a Worker that ships a vitest.config.ts is booted in
  # workerd via @cloudflare/vitest-pool-workers (miniflare) — NO Docker, NO live
  # Cloudflare account. agent-gateway (#413) proves its control routes' auth gate
  # + name-addressed DO RPC round-trip this way. Only runs for workers that opt in
  # by committing a vitest.config.ts, so mcp-server / d1-proxy stay typecheck-only.
  if [ -f vitest.config.ts ]; then
    echo "-- worker E2E (vitest run, workerd/miniflare — no docker)"
    # WALL CLOCK, because the failure this gate met in #559 was not a red suite but
    # NO suite: a Durable Object aborted mid-request wedged vitest-pool-workers, and
    # `npm test` sat there with workerd alive, ignoring SIGTERM, producing nothing.
    # An unbounded call in a gate turns that into a job that never returns, which
    # reads as "still running" rather than as a failure -- strictly worse than red,
    # because nobody is paged for it. So bound it and report the bound explicitly.
    # The cause is fixed (workers/agent-gateway/vitest.config.ts,
    # `disableConsoleIntercept`); this is the class of failure being made visible,
    # not that instance of it. Whole-suite wall time today is ~5s.
    if command -v timeout >/dev/null 2>&1; then
      # SIGKILL, not SIGTERM: in #559 workerd stayed alive through SIGTERM and only
      # died on SIGKILL. coreutils `timeout` signals the whole process group it made
      # for the command, so npm, node and workerd all go together and the gate box is
      # not left with orphans.
      test_status=0
      timeout --signal=KILL "${WORKERS_TEST_TIMEOUT:-600}" npm test || test_status=$?
      if [ "$test_status" -ne 0 ]; then
        if [ "$test_status" -eq 137 ]; then
          echo "ERROR: workers/$worker: worker E2E did not finish within ${WORKERS_TEST_TIMEOUT:-600}s and was killed." >&2
          echo "ERROR: workers/$worker: a hanging runner is a FAILURE here, not a slow one -- see #559." >&2
        else
          echo "ERROR: workers/$worker: worker E2E failed" >&2
        fi
        exit 1
      fi
    else
      # No coreutils `timeout` (e.g. a bare macOS shell). Run anyway rather than
      # skip the E2E, but say out loud that the hang guard is not in place.
      echo "WARNING: workers/$worker: no 'timeout' binary -- running the E2E UNBOUNDED (#559)." >&2
      npm test \
        || { echo "ERROR: workers/$worker: worker E2E failed" >&2; exit 1; }
    fi
  fi

  echo "workers/$worker: OK"
done

echo "workers gate: OK"
