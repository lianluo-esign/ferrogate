#!/usr/bin/env bash
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-30
# description: Behavioral contract tests for the CLI packaging script (#365).
#
# Runs entirely without cargo: every packaging path is exercised through
# --binary-dir with a stub binary, so this gate is fast and needs no cross
# toolchain. The real build path is covered by running the script for a host
# triple during a release.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/scripts/package-cli.sh"
manifest="$root/scripts/cli-release-targets.json"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[ -x "$script" ] || fail "scripts/package-cli.sh must be executable"
[ -f "$manifest" ] || fail "missing $manifest"

# --- the manifest is the single source of the released set ------------------
released="$(python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
print(" ".join(e["triple"] for e in manifest["targets"] if e["tier"] == "released"))
' "$manifest")"
[ -n "$released" ] || fail "manifest declares no released target"

# --- --check resolves the released set and builds nothing -------------------
check_out="$("$script" --version v2026.07.30 --out "$tmp/check" --check)"
for triple in $released; do
  grep -q -- "- $triple " <<< "$check_out" \
    || fail "--check plan omits released target $triple"
done
grep -q "check only: nothing built" <<< "$check_out" \
  || fail "--check must state that it built nothing"
[ ! -d "$tmp/check" ] || fail "--check must not create the output directory"

# --- version format is enforced --------------------------------------------
if "$script" --version 2026.07.30 --check >/dev/null 2>&1; then
  fail "a version without the v prefix must be rejected"
fi

# --- an undeclared triple is refused, not silently packaged -----------------
if "$script" --version v2026.07.30 --target totally-not-a-triple --check >/dev/null 2>&1; then
  fail "an undeclared target must be rejected"
fi

# --- a declared build-from-source triple is packageable when asked for ------
from_source="$(python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
entries = [e for e in manifest["targets"] if e["tier"] == "build-from-source"]
print(entries[0]["triple"] if entries else "")
' "$manifest")"
[ -n "$from_source" ] || fail "manifest declares no build-from-source target"
"$script" --version v2026.07.30 --target "$from_source" --check >/dev/null \
  || fail "an explicitly requested declared target must be accepted"

# --- packaging produces an archive, a checksum line, and the licence ---------
# One stub binary per released triple, taken from --binary-dir so no build runs.
stub_dir="$tmp/bin"
for triple in $released; do
  binary="$(python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
print(next(e["binary"] for e in manifest["targets"] if e["triple"] == sys.argv[2]))
' "$manifest" "$triple")"
  mkdir -p "$stub_dir/$triple"
  printf '#!/bin/sh\necho stub\n' > "$stub_dir/$triple/$binary"
  chmod 0755 "$stub_dir/$triple/$binary"
done

"$script" --version v2026.07.30 --out "$tmp/dist" --binary-dir "$stub_dir" >/dev/null \
  || fail "packaging from --binary-dir failed"

[ -f "$tmp/dist/SHA256SUMS" ] || fail "no SHA256SUMS produced"
for triple in $released; do
  archive="$tmp/dist/ferrogate-v2026.07.30-$triple.tar.gz"
  [ -f "$archive" ] || fail "missing archive for $triple"
  grep -q "ferrogate-v2026.07.30-$triple.tar.gz" "$tmp/dist/SHA256SUMS" \
    || fail "SHA256SUMS does not cover $triple"
  tar -tzf "$archive" | grep -q "ferrogate-v2026.07.30-$triple/LICENSE" \
    || fail "archive for $triple ships no LICENSE"
  tar -tzf "$archive" | grep -q "ferrogate-v2026.07.30-$triple/COMPATIBILITY.md" \
    || fail "archive for $triple ships no compatibility policy"
done

# The checksum file must actually verify in place — a SHA256SUMS whose paths
# do not resolve from the release directory is worse than none.
( cd "$tmp/dist" && sha256sum -c SHA256SUMS >/dev/null ) \
  || fail "SHA256SUMS does not verify from the output directory"

# --- archives are reproducible ---------------------------------------------
"$script" --version v2026.07.30 --out "$tmp/dist2" --binary-dir "$stub_dir" >/dev/null \
  || fail "second packaging run failed"
for triple in $released; do
  a="$(sha256sum < "$tmp/dist/ferrogate-v2026.07.30-$triple.tar.gz")"
  b="$(sha256sum < "$tmp/dist2/ferrogate-v2026.07.30-$triple.tar.gz")"
  [ "$a" = "$b" ] || fail "archive for $triple is not byte-reproducible"
done

# --- a missing staged binary fails loudly rather than shipping an empty archive
rm -rf "${stub_dir:?}/$(echo "$released" | awk '{print $1}')"
if "$script" --version v2026.07.30 --out "$tmp/dist3" --binary-dir "$stub_dir" >/dev/null 2>&1; then
  fail "a missing binary must abort packaging"
fi

echo "PASS: scripts/package-cli.sh contract"
