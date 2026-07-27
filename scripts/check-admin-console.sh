#!/usr/bin/env bash
# Admin-console gate (#314, #331): lint + Vitest + api-types drift + production
# build + browser contract for admin-console/.
# Runs standalone for dev use and from scripts/release-local.sh (no GitHub
# Actions per the release directive). Node 22+ per admin-console/Dockerfile.
#
#   scripts/check-admin-console.sh            # full gate
#   SKIP_ADMIN_CONSOLE_CHECK=1 scripts/...    # explicit skip (prints a note)
#   FERROGATE_NODE_BIN=/path/to/node/bin ...  # point at an off-PATH toolchain
#
# TOOLCHAIN (#508). This gate used to be effectively undiscoverable: Node lives
# under $HOME on the dev boxes but is not always on a non-login shell's PATH,
# and `npm` being a `#!/usr/bin/env node` shebang script turns that into the
# misleading `env: 'node': No such file or directory`. Believing the gate could
# not run at all, #351 landed without it and regressed the #313 admin-API
# coverage guard. So the gate now locates Node itself (scripts/node-env.sh) and,
# when it truly cannot, exits NON-ZERO with
#
#     admin-console gate did NOT run: node not found on PATH
#
# instead of skipping or reporting success. scripts/test-check-admin-console.sh
# asserts that contract; a gate that can be silently not-run is worthless
# (#499/#500).
#
# DEPENDENCIES: admin-console/node_modules is NOT checked in (it is gitignored,
# ~500MB, and platform-specific). `npm ci` from the committed package-lock.json
# is the required first step and this script runs it for you when node_modules
# is missing -- a fresh checkout must not fail obscurely on missing deps.
# Delete node_modules (or run `npm ci` yourself) to force a clean install.
#
# The typed OpenAPI client types (src/lib/api-types.generated.ts) are checked in
# and are regenerated from docs/openapi/admin-api.openapi.json with
# `npm run generate:api`. The `check:api-types` step below FAILS the gate when
# they are stale vs the spec (#392): stale-but-compilable types would otherwise
# slip past the build's `tsc` step, which is exactly how the client drifted
# before #379.
set -euo pipefail

if [ "${SKIP_ADMIN_CONSOLE_CHECK:-}" = "1" ]; then
  echo "admin-console gate: skipped (SKIP_ADMIN_CONSOLE_CHECK=1)"
  exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=scripts/node-env.sh
. "$ROOT/scripts/node-env.sh"
ferrogate_require_node "admin-console gate" || exit 1

cd "$ROOT/admin-console"

echo "== admin-console gate =="
echo "-- node $(node -v) / npm $(npm -v) ($(command -v node))"

if [ ! -d node_modules ]; then
  echo "-- npm ci (node_modules missing; not checked in by design)"
  npm ci --no-audit --no-fund \
    || { echo "admin-console gate did NOT run: npm ci failed (see above)" >&2; exit 1; }
fi

echo "-- lint"
npm run lint

echo "-- test (vitest --run)"
npm run test -- --run

echo "-- api-types drift (generated client vs OpenAPI spec)"
npm run check:api-types

echo "-- build (tsc -b && vite build)"
npm run build

# Playwright browsers are a separate ~150MB download from node_modules, live in
# ~/.cache/ms-playwright, and need a pile of OS shared libraries on top. A fresh
# box has neither, and `playwright test` then dies with a wall of install advice
# a minute into the suite. So do it up front (#508).
#
# `playwright install` is idempotent and a no-op when the pinned revision is
# already present -- but note it exits 0 while merely WARNING that the host is
# missing the shared libraries chromium needs to launch. That warning is fatal in
# practice, so it is promoted to a gate failure here: an unlaunchable browser
# means the #331 browser contract is unproven, and unproven must not read as OK.
echo "-- browser install (playwright chromium; no-op when present)"
PW_LOG="$(mktemp)"
trap 'rm -f "$PW_LOG"' EXIT
if ! npx playwright install chromium >"$PW_LOG" 2>&1; then
  cat "$PW_LOG" >&2
  echo "admin-console gate did NOT run: 'playwright install chromium' failed" >&2
  echo "  needs network; retry with: cd admin-console && npm run test:e2e:install" >&2
  exit 1
fi
cat "$PW_LOG"
if grep -qF "missing dependencies to run browsers" "$PW_LOG"; then
  echo "admin-console gate did NOT run: chromium is downloaded but cannot launch" >&2
  echo "  the host is missing chromium's shared libraries. Install them as root:" >&2
  echo "      sudo npx playwright install-deps chromium    # from admin-console/" >&2
  echo "  then re-run scripts/check-admin-console.sh. This is NOT a skip -- the" >&2
  echo "  browser contract (axe + overflow guards, #331) stays UNPROVEN until it runs." >&2
  exit 1
fi

echo "-- browser contract (Playwright + axe)"
npm run test:e2e

echo "admin-console gate: OK"
