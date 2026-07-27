# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-27
# description: Sourceable Node toolchain locator for FerroGate repo tooling.
#
# SOURCE THIS, DO NOT EXECUTE IT:  . "$(dirname "$0")/node-env.sh"
#
# Why this file exists (#508): on the dev boxes the Node toolchain is installed
# under $HOME but is NOT always on a non-login shell's PATH, and nothing in the
# repo said where it lives. Every agent had to rediscover it, and the failure
# mode actively misleads: `npm` and `npx` are `#!/usr/bin/env node` shebang
# scripts, so invoking them by absolute path from a shell without node on PATH
# fails with
#
#     env: 'node': No such file or directory
#
# which reads as "node is not installed" when node is in fact sitting one
# directory away. Believing exactly that, #351 shipped without running the
# admin-console gate and regressed the #313 admin-API coverage guard.
#
# So: repo tooling locates Node itself instead of trusting the ambient PATH,
# and when it genuinely cannot, the caller fails LOUDLY and by name rather than
# skipping (same defect class as #499/#500 -- a gate that can be silently
# not-run is worth nothing).
#
# Override the search with FERROGATE_NODE_BIN=/path/to/node/bin.
# POSIX sh on purpose: sourced by both sh and bash gate scripts.

# Actionable "where is Node" hint. printf-only: it has to survive being run from
# a shell whose PATH has no coreutils on it.
ferrogate_node_hint() {
  printf '%s\n' \
    '  This gate needs Node 22+ (see admin-console/Dockerfile). It was NOT skipped' \
    '  and it did NOT pass -- it did not run at all.' \
    '' \
    '  Node is usually installed under $HOME but missing from a non-login shell'"'"'s' \
    '  PATH. Find it and put its bin/ on PATH, e.g.:' \
    '' \
    '      ls -d "$HOME"/.local/share/node/*/bin "$HOME"/toolchain/node/*/bin' \
    '      export PATH="<that bin dir>:$PATH"' \
    '' \
    '  or point this repo straight at it:' \
    '' \
    '      FERROGATE_NODE_BIN=<that bin dir> scripts/check-admin-console.sh' \
    '' \
    '  GOTCHA: npm/npx are `#!/usr/bin/env node` scripts. Running them by absolute' \
    '  path without node on PATH fails with' \
    '' \
    "      env: 'node': No such file or directory" \
    '' \
    '  That error means "node is off PATH", NOT "node is not installed". Put the' \
    '  bin/ directory on PATH; do not conclude the toolchain is missing (#508).'
}

# Put a usable node+npm on PATH. Returns 0 when node is reachable afterwards.
#
# FERROGATE_NODE_BIN is AUTHORITATIVE when set: only that directory is
# considered, and PATH/heuristic discovery is bypassed entirely. That makes
# "which Node did this gate use" answerable on a weird box, and gives
# scripts/test-check-admin-console.sh a deterministic way to reproduce the
# no-Node state on any host.
ferrogate_node_env() {
  if [ -n "${FERROGATE_NODE_BIN:-}" ]; then
    if [ -x "$FERROGATE_NODE_BIN/node" ]; then
      PATH="$FERROGATE_NODE_BIN:$PATH"
      export PATH
      return 0
    fi
    return 1
  fi

  if command -v node >/dev/null 2>&1; then
    return 0
  fi

  _fg_home="${HOME:-}"
  # Unmatched globs stay literal and are filtered out by the -x test below.
  for _fg_dir in \
    "$_fg_home/.local/bin" \
    "$_fg_home"/.local/share/node/*/bin \
    "$_fg_home"/toolchain/node/*/bin \
    "${NVM_DIR:-$_fg_home/.nvm}"/versions/node/*/bin \
    /usr/local/lib/nodejs/*/bin \
    /opt/node/bin
  do
    if [ -x "$_fg_dir/node" ]; then
      PATH="$_fg_dir:$PATH"
      export PATH
      unset _fg_dir _fg_home
      return 0
    fi
  done

  unset _fg_dir _fg_home
  return 1
}

# Loud, named failure for a gate that needs Node. $1 is the gate name, e.g.
# "admin-console gate". Never returns 0 without node AND npm on PATH.
ferrogate_require_node() {
  _fg_gate="${1:-gate}"

  if ! ferrogate_node_env; then
    echo "$_fg_gate did NOT run: node not found on PATH" >&2
    ferrogate_node_hint >&2
    unset _fg_gate
    return 1
  fi

  if ! command -v npm >/dev/null 2>&1; then
    echo "$_fg_gate did NOT run: npm not found on PATH" >&2
    ferrogate_node_hint >&2
    unset _fg_gate
    return 1
  fi

  unset _fg_gate
  return 0
}
