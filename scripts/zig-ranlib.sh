#!/usr/bin/env bash
# `zig ranlib` wrapper (llvm-ranlib) for the zig cross builds (#325).
set -euo pipefail
ZIG="${ZIG:-$HOME/.local/zig/zig}"
exec "$ZIG" ranlib "$@"
