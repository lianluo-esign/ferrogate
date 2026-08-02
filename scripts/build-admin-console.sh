#!/usr/bin/env bash
# Build the admin console INTO the control-plane Worker's static-asset
# directory (#696).
#
#   scripts/build-admin-console.sh
#
# The console is a Vite SPA that must be served from the SAME ORIGIN as the
# control-plane API. `apps/control-plane/wrangler.toml`'s `[assets]` block
# carries the full argument; the short version is that two guards on that Worker
# — `adminCrossSiteRejection` (`sec-fetch-site`) and a CORS preflight surface
# scoped to `/admin/` only — make a cross-origin console unusable in a browser,
# and same-origin dissolves both without widening either.
#
# So `wrangler deploy` for `apps/control-plane` uploads whatever is in
# `apps/control-plane/public/`, and this script is what puts the console there.
# Nothing but `.gitignore`/`.assetsignore` is committed in that directory: a
# checkout that has never run this script deploys a Worker with no assets, which
# serves the API exactly as before and 404s the console — a visibly missing UI,
# never a stale one.
#
# TOOLCHAIN: same discovery as `scripts/check-admin-console.sh`. Node lives
# under $HOME on the dev boxes and is not always on a non-login shell's PATH,
# and `npm` being a `#!/usr/bin/env node` shebang turns that into the misleading
# `env: 'node': No such file or directory`. Fail LOUDLY instead.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
console_dir="$repo_root/admin-console"
asset_dir="$repo_root/apps/control-plane/public"

# shellcheck source=scripts/node-env.sh
if [[ -f "$repo_root/scripts/node-env.sh" ]]; then
  source "$repo_root/scripts/node-env.sh"
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "admin-console build did NOT run: npm not found on PATH" >&2
  exit 1
fi

if [[ ! -d "$console_dir/node_modules" ]]; then
  echo "==> npm ci (admin-console/node_modules missing)"
  (cd "$console_dir" && npm ci --no-audit --no-fund)
fi

echo "==> vite build"
(cd "$console_dir" && npm run build)

# Replace, never merge: a merge leaves last build's hashed chunks behind, and
# `index.html` only ever references the current ones, so the directory grows
# without bound and the extra files are uploaded on every deploy.
echo "==> publishing into apps/control-plane/public"
find "$asset_dir" -mindepth 1 -maxdepth 1 ! -name '.gitignore' ! -name '.assetsignore' -exec rm -rf {} +
cp -R "$console_dir/dist/." "$asset_dir/"

echo "admin console built into $asset_dir"
