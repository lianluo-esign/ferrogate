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
  # into the workerd E2E by committing a vitest.config.ts. Deliberately not
  # `npm ls`, which reports non-zero on agent-gateway's known-broken peer
  # graph (#468) and would reinstall on every single run.
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
      echo "-- npm ci (node_modules missing)"
      # A committed lockfile that is out of sync with package.json makes `npm ci`
      # refuse (EUSAGE). That is drift worth SEEING, but it must not make the
      # typecheck gate unrunnable -- the point of this script is to compile the
      # TypeScript we deploy. So fall back to `npm install` and shout about it.
      # workers/agent-gateway is in exactly this state today (see #468): 127 of
      # its 220 lockfile entries carry no resolved/integrity, and wrangler's
      # floating range pulls a peer that conflicts with the pinned
      # @cloudflare/workers-types, so the lockfile cannot be regenerated without
      # a dependency decision.
      if ! npm ci --no-audit --no-fund; then
        echo "WARNING: workers/$worker: npm ci refused (lockfile out of sync with package.json)." >&2
        echo "WARNING: workers/$worker: falling back to 'npm install' so the typecheck still runs." >&2
        echo "WARNING: workers/$worker: the committed lockfile is NOT reproducible -- fix it (see #468)." >&2
        if ! npm install --no-audit --no-fund; then
          # Last resort: an unsatisfiable peer graph. agent-gateway hits this
          # today -- wrangler's floating ^4.114.0 resolves to a build whose
          # peerOptional wants @cloudflare/workers-types ^5, while the pinned v4
          # and partyserver's peer both require v4 (#468). --legacy-peer-deps
          # yields a tree that compiles; it does NOT make the deps correct.
          echo "WARNING: workers/$worker: npm install failed on an unsatisfiable peer graph." >&2
          echo "WARNING: workers/$worker: retrying with --legacy-peer-deps purely to keep the" >&2
          echo "WARNING: workers/$worker: typecheck running. THE DEPENDENCY SET IS BROKEN (#468)." >&2
          npm install --no-audit --no-fund --legacy-peer-deps \
            || { echo "ERROR: workers/$worker: install failed even with --legacy-peer-deps" >&2; exit 1; }
        fi
      fi
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
    npm test \
      || { echo "ERROR: workers/$worker: worker E2E failed" >&2; exit 1; }
  fi

  echo "workers/$worker: OK"
done

echo "workers gate: OK"
