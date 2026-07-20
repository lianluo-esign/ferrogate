#!/usr/bin/env bash
# `zig ar` wrapper (llvm-ar) — target-independent archiver for the zig cross builds (#325).
set -euo pipefail
ZIG="${ZIG:-$HOME/.local/zig/zig}"
exec "$ZIG" ar "$@"
