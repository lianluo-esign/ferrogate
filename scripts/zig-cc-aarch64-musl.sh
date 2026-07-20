#!/usr/bin/env bash
# zig-as-CC/linker wrapper for the aarch64-unknown-linux-musl Rust target (#325).
# See zig-cc-x86_64-musl.sh for the rationale and the argv filter notes.
set -euo pipefail
ZIG="${ZIG:-$HOME/.local/zig/zig}"
args=()
for a in "$@"; do
  case "$a" in
    --target=*) ;;
    -lgcc_s|-lgcc) args+=("-lunwind");;
    *) args+=("$a");;
  esac
done
exec "$ZIG" cc -target aarch64-linux-musl "${args[@]}"
