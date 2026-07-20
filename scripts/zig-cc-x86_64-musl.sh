#!/usr/bin/env bash
# zig-as-CC/linker wrapper for the x86_64-unknown-linux-musl Rust target (#325).
#
# WHY A WRAPPER: cargo/cc-rs accept CC/linker as a single argv[0] executable; the
# `-target` selection must therefore be baked in here. Runs on any host zig
# supports (this repo's release host is aarch64-linux).
#
# ZIG env overrides the zig binary; default is the userspace install.
set -euo pipefail
ZIG="${ZIG:-$HOME/.local/zig/zig}"

# Filter argv for zig-cc (clang) compatibility. Kept minimal and test-driven:
#   --target=<rust triple> : cc-rs detects zig cc as clang and passes the RUST
#     triple (x86_64-unknown-linux-musl), which zig rejects (zig triples are
#     arch-os-abi). The wrapper bakes the correct -target, so drop it.
#   -lgcc_s / -lgcc : gcc runtime libs that don't exist in zig's world; compiler
#     intrinsics live in zig's bundled compiler-rt (libunwind is the classic
#     substitute if anything still asks).
#   crti.o/crtn.o/etc from rustc's self-contained dir would duplicate zig's own
#     CRT, but the build sets `-C link-self-contained=no` instead of filtering.
args=()
for a in "$@"; do
  case "$a" in
    --target=*) ;;
    -lgcc_s|-lgcc) args+=("-lunwind");;
    *) args+=("$a");;
  esac
done
exec "$ZIG" cc -target x86_64-linux-musl "${args[@]}"
