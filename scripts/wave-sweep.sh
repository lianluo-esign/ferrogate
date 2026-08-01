#!/usr/bin/env bash
# Wave regression sweep: `bun run test` in EACH packages/* and apps/*, one at a
# time, so the per-package totals are attributable rather than interleaved.
# Not a gate; a reporting aid for the integrate step.
set -u
cd "$(dirname "$0")/.." || exit 1
root="$PWD"
out="${1:-/tmp/wave-sweep}"
mkdir -p "$out"
: >"$out/summary.txt"
for dir in packages/*/ apps/*/ e2e/; do
  [ -f "$dir/package.json" ] || continue
  grep -q '"test"' "$dir/package.json" || { echo "$dir SKIP (no test script)" >>"$out/summary.txt"; continue; }
  name=$(echo "$dir" | tr '/' '_')
  ( cd "$root/$dir" && timeout 1800 bun run test ) >"$out/$name.log" 2>&1
  code=$?
  line=$(sed 's/\x1b\[[0-9;]*m//g' "$out/$name.log" | grep -E "^\s*Tests\s+" | tail -1)
  files=$(sed 's/\x1b\[[0-9;]*m//g' "$out/$name.log" | grep -E "^\s*Test Files\s+" | tail -1)
  echo "$dir exit=$code | $(echo "$files" | xargs) | $(echo "$line" | xargs)" >>"$out/summary.txt"
done
cat "$out/summary.txt"
