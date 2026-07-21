#!/usr/bin/env bash
# Admin-console gate (#314, #331): lint + Vitest + production build + browser
# contract for admin-console/.
# Runs standalone for dev use and from scripts/release-local.sh (no GitHub
# Actions per the release directive). Node 22+ per admin-console/Dockerfile.
#
#   scripts/check-admin-console.sh            # full gate
#   SKIP_ADMIN_CONSOLE_CHECK=1 scripts/...    # explicit skip (prints a note)
#
# `npm ci` runs only when node_modules is missing; delete node_modules (or run
# `npm ci` yourself) to force a clean install. The typed OpenAPI client types
# (src/lib/api-types.generated.ts) are checked in; contract drift surfaces as
# a type error in the build step. Regenerate with `npm run generate:api`.
set -euo pipefail

if [ "${SKIP_ADMIN_CONSOLE_CHECK:-}" = "1" ]; then
  echo "admin-console gate: skipped (SKIP_ADMIN_CONSOLE_CHECK=1)"
  exit 0
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/admin-console"

command -v npm >/dev/null || { echo "ERROR: npm not found (need Node 22+; see admin-console/Dockerfile)" >&2; exit 1; }

echo "== admin-console gate =="
if [ ! -d node_modules ]; then
  echo "-- npm ci (node_modules missing)"
  npm ci --no-audit --no-fund
fi

echo "-- lint"
npm run lint

echo "-- test (vitest --run)"
npm run test -- --run

echo "-- build (tsc -b && vite build)"
npm run build

echo "-- browser contract (Playwright + axe)"
npm run test:e2e

echo "admin-console gate: OK"
