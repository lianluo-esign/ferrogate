#!/usr/bin/env bash
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-27
# description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
#
# Tests for scripts/check-secret-scan.sh (#525).
#
# The scan used to hard-code `rg`; on a box without ripgrep the section died
# and nothing said so. These tests drive the real script with tools shadowed
# out of PATH and assert what it does then, plus that the ripgrep and
# `git grep -I` engines produce identical output on the same corpus.
#
#   scripts/test-check-secret-scan.sh
#
# No fake credential is written as a literal anywhere in this file: every one
# is assembled at runtime, so this file does not trip the scan it tests.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${root}/scripts/check-secret-scan.sh"
security_check="${root}/scripts/security-check.sh"

bash_bin="$(command -v bash)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=0
pass() { printf 'ok   - %s\n' "$1"; }
fail() {
  printf 'FAIL - %s\n' "$1" >&2
  [[ "$#" -ge 2 ]] && printf '       %s\n' "$2" >&2
  failures=$((failures + 1))
}

# A PATH holding only the listed tools, so a tool can be genuinely absent
# rather than merely broken (`command -v` still finds a stub that exits 127).
make_shim_path() {
  local dir="$1"
  shift
  rm -rf "$dir"
  mkdir -p "$dir"
  local tool resolved
  for tool in "$@"; do
    resolved="$(command -v "$tool" 2>/dev/null)" || continue
    ln -sf "$resolved" "$dir/$tool"
  done
  printf '%s' "$dir"
}

# Everything check-secret-scan.sh may exec, minus the search tools. sha256sum
# is here because the reviewed-exception allowlist pins each entry to one line
# by digest (#566), so a scan OF THIS REPO needs it; a --root scan does not.
base_tools=(bash mktemp sed sort comm cat rm sha256sum)

# ---------------------------------------------------------------------------
# A corpus with planted fake credentials, in its own git checkout.
# ---------------------------------------------------------------------------
corpus="$work/corpus"
mkdir -p "$corpus"
(
  cd "$corpus"
  git init -q .
  git config user.email scan@test.invalid
  git config user.name 'scan test'

  aws_prefix=AKIA
  sts_prefix=ASIA
  gh_prefix=gh
  sk_prefix=sk
  goog_prefix=AI

  {
    printf 'let a = "%s0123456789ABCDEF";\n' "$aws_prefix"
    printf 'let b = "%s0123456789ABCDEF";\n' "$sts_prefix"
    printf 'let too_short = "%s0123456789ABCDE";\n' "$aws_prefix"
  } >aws.txt
  # Split so this file does not match the PEM pattern it is exercising.
  pem_open="-----BEGIN"
  pem_private="PRIVATE KEY-----"
  {
    printf -- '%s %s\n' "$pem_open" "$pem_private"
    printf -- '%s RSA %s\n' "$pem_open" "$pem_private"
    printf -- '%s EC %s\n' "$pem_open" "$pem_private"
    printf -- '%s OPENSSH %s\n' "$pem_open" "$pem_private"
    printf -- '%s DSA %s\n' "$pem_open" "$pem_private"
    printf -- '%s PUBLIC KEY-----\n' "$pem_open"
    printf -- 'inline %s FOO %s tail\n' "$pem_open" "$pem_private"
  } >keys.txt
  {
    printf '%sp_%s\n' "$gh_prefix" ABCDEFGHIJKLMNOPQRSTUVWXYZ012
    printf '%so_%s\n' "$gh_prefix" abcdefghij0123456789_
    printf '%sx_%s\n' "$gh_prefix" ABCDEFGHIJKLMNOPQRSTUVWXYZ012
    printf '%ss_%s\n' "$gh_prefix" ABCDEFGHIJ
  } >gh.txt
  {
    printf '%s-%s\n' "$sk_prefix" abcdefghijABCDEFGHIJ0123456789XY
    printf '%s-%s\n' "$sk_prefix" abcdefghijABCDEFGHIJ012345
    printf '%s-ant-%s\n' "$sk_prefix" -ABCdef_ghi-jklmnopqrstuvwx
    printf '%sza%s\n' "$goog_prefix" 0123456789012345678901234567890123X
  } >mixed.txt
  printf 'nothing to see here\n' >clean.txt
  # Shapes where a regex-dialect or IO difference between the two engines
  # would show up: multibyte, CRLF, no trailing newline, a 200 KB line, and a
  # filename full of pathspec magic characters.
  printf 'caf\xc3\xa9 %s0123456789ABCDEF \xe4\xb8\xad\xe6\x96\x87\n' "$aws_prefix" >utf8.txt
  printf 'crlf %s0123456789ABCDEF\r\n' "$aws_prefix" >crlf.txt
  printf 'no-newline %s0123456789ABCDEF' "$aws_prefix" >nonewline.txt
  {
    head -c 200000 /dev/zero | tr '\0' 'q'
    printf ' %s0123456789ABCDEF\n' "$aws_prefix"
  } >longline.txt
  printf 'weird %s0123456789ABCDEF\n' "$aws_prefix" >'star*name[a].txt'
  git add -A
  git commit -qm corpus
) >/dev/null

clean_repo="$work/clean"
mkdir -p "$clean_repo"
(
  cd "$clean_repo"
  git init -q .
  git config user.email scan@test.invalid
  git config user.name 'scan test'
  printf 'nothing here\n' >a.txt
  git add -A
  git commit -qm clean
) >/dev/null

# ---------------------------------------------------------------------------
# 1. Missing-tool behaviour: the reason this issue exists.
# ---------------------------------------------------------------------------
no_search_path="$(make_shim_path "$work/bin-no-search" "${base_tools[@]}")"
out="$("$script" --root "$corpus" 2>&1)"
status=$?
neither_out="$(PATH="$no_search_path" "$bash_bin" "$script" --root "$corpus" 2>&1)"
neither_status=$?

if [[ "$neither_status" -ne 0 ]]; then
  pass "no search tool on PATH: exits non-zero ($neither_status)"
else
  fail "no search tool on PATH: exits non-zero" "got status 0, output: $neither_out"
fi

if [[ "$neither_out" == *"'rg'"* ]]; then
  pass "no search tool on PATH: message names rg"
else
  fail "no search tool on PATH: message names rg" "output: $neither_out"
fi

if [[ "$neither_out" == *"'git'"* || "$neither_out" == *"git grep"* ]]; then
  pass "no search tool on PATH: message names git / git grep"
else
  fail "no search tool on PATH: message names git / git grep" "output: $neither_out"
fi

# The script must not pretend it found something when it could not look.
if [[ "$neither_out" != *"Potential secrets found"* ]]; then
  pass "no search tool on PATH: does not report a bogus finding"
else
  fail "no search tool on PATH: does not report a bogus finding" "output: $neither_out"
fi

# ripgrep alone is not enough: the tracked-file list comes from `git ls-files`.
if command -v rg >/dev/null 2>&1; then
  rg_only_path="$(make_shim_path "$work/bin-rg-only" "${base_tools[@]}" rg)"
  no_git_out="$(PATH="$rg_only_path" "$bash_bin" "$script" --root "$corpus" 2>&1)"
  no_git_status=$?
  if [[ "$no_git_status" -ne 0 && "$no_git_out" == *"git"* ]]; then
    pass "git absent but rg present: exits non-zero naming git"
  else
    fail "git absent but rg present: exits non-zero naming git" "status $no_git_status, output: $no_git_out"
  fi
else
  printf 'skip - rg-without-git assertion (rg is not installed here)\n'
fi

# security-check.sh itself must name a missing tool instead of dying mid-way.
stripped_out="$(PATH=/nonexistent "$bash_bin" "$security_check" 2>&1)"
stripped_status=$?
if [[ "$stripped_status" -ne 0 ]]; then
  pass "security-check.sh with an empty PATH: exits non-zero ($stripped_status)"
else
  fail "security-check.sh with an empty PATH: exits non-zero" "output: $stripped_out"
fi
for tool in cargo python3 git; do
  if [[ "$stripped_out" == *"missing required tool"*"$tool"* ]]; then
    pass "security-check.sh with an empty PATH: message names $tool"
  else
    fail "security-check.sh with an empty PATH: message names $tool" "output: $stripped_out"
  fi
done

# ---------------------------------------------------------------------------
# 2. The git grep fallback runs the scan for real when ripgrep is absent.
# ---------------------------------------------------------------------------
git_only_path="$(make_shim_path "$work/bin-git-only" "${base_tools[@]}" git)"
fallback_out="$(PATH="$git_only_path" "$bash_bin" "$script" --root "$clean_repo" 2>&1)"
fallback_status=$?
if [[ "$fallback_status" -eq 0 ]]; then
  pass "ripgrep absent, git present: clean repo still scans and passes"
else
  fail "ripgrep absent, git present: clean repo still scans and passes" "status $fallback_status, output: $fallback_out"
fi
if [[ "$fallback_out" == *"engine: git-grep"* ]]; then
  pass "ripgrep absent: announces the git-grep engine"
else
  fail "ripgrep absent: announces the git-grep engine" "output: $fallback_out"
fi

# No match is the *success* case and both engines exit 1 for it; a `set -e`
# slip here would turn a clean repo into a failing gate.
if [[ "$fallback_out" == *"secret scan passed"* ]]; then
  pass "no-match exit status 1 is not mistaken for a failure"
else
  fail "no-match exit status 1 is not mistaken for a failure" "output: $fallback_out"
fi

if command -v rg >/dev/null 2>&1; then
  rg_clean_out="$("$bash_bin" "$script" --root "$clean_repo" 2>&1)"
  rg_clean_status=$?
  if [[ "$rg_clean_status" -eq 0 && "$rg_clean_out" == *"engine: rg"* ]]; then
    pass "ripgrep present: rg engine selected and clean repo passes"
  else
    fail "ripgrep present: rg engine selected and clean repo passes" "status $rg_clean_status, output: $rg_clean_out"
  fi
else
  printf 'skip - ripgrep engine assertions (rg is not installed here)\n'
fi

# ---------------------------------------------------------------------------
# 3. The fallback still catches planted credentials, per pattern.
# ---------------------------------------------------------------------------
planted_out="$(PATH="$git_only_path" "$bash_bin" "$script" --root "$corpus" 2>&1)"
planted_status=$?
if [[ "$planted_status" -ne 0 ]]; then
  pass "git grep fallback: planted credentials fail the scan"
else
  fail "git grep fallback: planted credentials fail the scan" "output: $planted_out"
fi
for label in "private key material" "AWS access key id" "GitHub token" \
  "OpenAI-style API key" "Anthropic API key" "Google API key"; do
  if [[ "$planted_out" == *"secret scan matched: $label"* ]]; then
    pass "git grep fallback: detects $label"
  else
    fail "git grep fallback: detects $label" "output: $planted_out"
  fi
done
if [[ "$planted_out" == *"Potential secrets found"* ]]; then
  pass "git grep fallback: prints the matching lines"
else
  fail "git grep fallback: prints the matching lines" "output: $planted_out"
fi

# The reported lines are what a reviewer reads, so hold their shape:
# <path>:<line-number>:<content>, one finding per line.
findings_block() { sed -n '/^Potential secrets found:$/,$p' | tail -n +2; }
printf '%s\n' "$planted_out" | findings_block >"$work/gg.findings"
if [[ -s "$work/gg.findings" ]] &&
  ! grep -qvE '^[^:]+:[0-9]+:' "$work/gg.findings"; then
  pass "git grep fallback: every finding keeps the path:line:content shape"
else
  fail "git grep fallback: every finding keeps the path:line:content shape" \
    "$(head -5 "$work/gg.findings")"
fi

# ---------------------------------------------------------------------------
# 3b. An engine that is present but broken must not be mistaken for a clean
#     scan, and must not invent a finding it never saw. (`command -v` still
#     resolves a stub, so this is a different path from "tool absent".)
# ---------------------------------------------------------------------------
broken_path="$(make_shim_path "$work/bin-broken-rg" "${base_tools[@]}" git)"
printf '#!/bin/sh\nexit 127\n' >"$broken_path/rg"
chmod +x "$broken_path/rg"
broken_out="$(PATH="$broken_path" "$bash_bin" "$script" --root "$clean_repo" 2>&1)"
broken_status=$?
if [[ "$broken_status" -ne 0 ]]; then
  pass "broken search tool: exits non-zero ($broken_status)"
else
  fail "broken search tool: exits non-zero" "output: $broken_out"
fi
if [[ "$broken_out" != *"Potential secrets found"* ]]; then
  pass "broken search tool: does not claim a finding it never saw"
else
  fail "broken search tool: does not claim a finding it never saw" "output: $broken_out"
fi
if [[ "$broken_out" == *"treat this repository as unscanned"* ]]; then
  pass "broken search tool: says the repository is unscanned"
else
  fail "broken search tool: says the repository is unscanned" "output: $broken_out"
fi

# ---------------------------------------------------------------------------
# 4. Engine equivalence, through the script itself: the two engines must
#    report the same findings, byte for byte, from the same corpus. This
#    drives the real flag arrays, so any drift in either invocation shows up.
# ---------------------------------------------------------------------------
if command -v rg >/dev/null 2>&1; then
  rg_planted_out="$("$bash_bin" "$script" --root "$corpus" 2>&1)"
  printf '%s\n' "$rg_planted_out" | findings_block | LC_ALL=C sort >"$work/rg.script"
  printf '%s\n' "$planted_out" | findings_block | LC_ALL=C sort >"$work/gg.script"
  if [[ -s "$work/rg.script" ]] && diff -q "$work/rg.script" "$work/gg.script" >/dev/null; then
    pass "both engines report identical findings through the script"
  else
    fail "both engines report identical findings through the script" \
      "$(diff "$work/rg.script" "$work/gg.script" | cut -c1-200 | head -10)"
  fi
else
  printf 'skip - script-level engine equivalence (rg is not installed here)\n'
fi

# ---------------------------------------------------------------------------
# 4b. Engine equivalence at the raw-invocation level, over shapes the corpus
#     would not otherwise reach (regex dialect, encodings, IO edges).
# ---------------------------------------------------------------------------
if command -v rg >/dev/null 2>&1; then
  patterns=(
    '-----BEGIN (RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----'
    '(AKIA|ASIA)[0-9A-Z]{16}'
    'gh[pousr]_[A-Za-z0-9_]{20,}'
    'sk-[A-Za-z0-9]{32,}'
    'sk-ant-[A-Za-z0-9_-]{20,}'
    'AIza[0-9A-Za-z_-]{35}'
  )
  mapfile -d '' corpus_files < <(cd "$corpus" && git ls-files -z -- ':!:Cargo.lock')
  for pattern in "${patterns[@]}"; do
    (
      cd "$corpus"
      rg --line-number --no-heading --with-filename -e "$pattern" -- "${corpus_files[@]}" \
        2>/dev/null | LC_ALL=C sort >"$work/rg.out"
      git --literal-pathspecs grep -I --no-color --full-name --line-number \
        --extended-regexp -e "$pattern" -- "${corpus_files[@]}" \
        2>/dev/null | LC_ALL=C sort >"$work/gg.out"
    )
    if diff -q "$work/rg.out" "$work/gg.out" >/dev/null; then
      pass "engines agree byte-for-byte on: $pattern"
    else
      fail "engines agree byte-for-byte on: $pattern" "$(diff "$work/rg.out" "$work/gg.out" | cut -c1-200 | head -10)"
    fi
    if [[ ! -s "$work/gg.out" ]]; then
      fail "corpus exercises: $pattern" "neither engine matched anything, so the comparison is vacuous"
    fi
  done
else
  printf 'skip - engine equivalence diff (rg is not installed here)\n'
fi

# ---------------------------------------------------------------------------
# 5. Coverage: #344's assets.tsx carried two NUL bytes, which made git and
#    every grep-based tool skip it silently. Assert the scan reaches it now.
# ---------------------------------------------------------------------------
reachability_target="admin-console/src/pages/assets.tsx"
scan_list="$("$script" --list-files 2>/dev/null)"
if grep -qxF "$reachability_target" <<<"$scan_list"; then
  pass "scan file list includes $reachability_target"
else
  fail "scan file list includes $reachability_target" "not in the list the script itself resolves"
fi
if [[ -f "$root/$reachability_target" ]]; then
  pass "$reachability_target exists in the checkout"
else
  fail "$reachability_target exists in the checkout"
fi
# Being listed is not enough: a NUL byte would still make both engines skip it.
if (cd "$root" && git --literal-pathspecs grep -I -l -e '' -- "$reachability_target" >/dev/null 2>&1); then
  pass "$reachability_target is line-scannable, not skipped as binary"
else
  fail "$reachability_target is line-scannable, not skipped as binary" "git classifies it as binary; the scan would skip it silently"
fi
# Command substitution eats NUL bytes, so compare byte counts instead.
target_bytes="$(wc -c <"$root/$reachability_target")"
target_bytes_without_nul="$(tr -d '\000' <"$root/$reachability_target" | wc -c)"
if [[ "$target_bytes" -eq "$target_bytes_without_nul" ]]; then
  pass "$reachability_target carries no NUL byte (#344 stayed fixed)"
else
  fail "$reachability_target carries no NUL byte (#344 stayed fixed)"
fi

# ---------------------------------------------------------------------------
# 6. This repository passes its own scan, with both engines.
# ---------------------------------------------------------------------------
self_out="$("$script" 2>&1)"
self_status=$?
if [[ "$self_status" -eq 0 ]]; then
  pass "this checkout passes the secret scan (default engine)"
else
  fail "this checkout passes the secret scan (default engine)" "$self_out"
fi
self_fallback_out="$(PATH="$git_only_path" "$bash_bin" "$script" 2>&1)"
self_fallback_status=$?
if [[ "$self_fallback_status" -eq 0 ]]; then
  pass "this checkout passes the secret scan (git grep fallback)"
else
  fail "this checkout passes the secret scan (git grep fallback)" "$self_fallback_out"
fi
# #525 review: this used to be
#   [[ "$self_out" == *"1492"* || "$self_out" == *"tracked files are line-scannable"* ]]
# and the second branch is always true, because the scan always prints that
# sentence. So the assertion could never notice the scan SHRINKING -- which,
# for a secret scan, is the only failure that matters. Coverage IS the product.
#
# Assert the reported count against the tree instead of against a literal: a
# hard-coded 1492 rots on the next commit, and a substring of the sentence
# asserts that the sentence exists.
reported_scanned="$(printf '%s' "$self_out" | grep -oE '[0-9]+ tracked files are line-scannable' | grep -oE '^[0-9]+' | head -1)"
tracked_total="$(git -C "$root" ls-files | wc -l | tr -d ' ')"
if [[ -z "$reported_scanned" ]]; then
  fail "scan reports its coverage instead of staying silent" "$self_out"
elif [[ "$reported_scanned" -lt $(( tracked_total * 9 / 10 )) ]]; then
  # A scan that silently stops covering a tenth of the tree is the regression
  # this file exists to catch. The floor is deliberately a ratio, not a
  # literal, so it survives the tree growing.
  fail "the scan covers at least 90% of tracked files" \
    "reported ${reported_scanned} of ${tracked_total} tracked files"
else
  pass "scan reports its coverage and covers ${reported_scanned}/${tracked_total} tracked files"
fi

# ---------------------------------------------------------------------------
# 7. The reviewed-exception allowlist (#566).
#
#    The allowlist is the only way a match can be dropped, so it is the only
#    place a real key could hide. It used to be scoped to <label, file>, which
#    means a real key pasted ANYWHERE in an allowlisted file scanned clean --
#    and both allowlisted files are credential tests, the likeliest place for
#    someone to paste a live value while debugging. It is now scoped to one
#    line, pinned by SHA-256 of that line's content.
#
#    These cases drive the real script over a fixture checkout built from the
#    real allowlisted files, so the exemptions are the production ones. The
#    allowlist only applies when the script scans its OWN repo, so the fixture
#    puts a copy of the script at <fixture>/scripts/ and runs it with no
#    --root.
# ---------------------------------------------------------------------------

# Assembled at runtime, like every other fake credential in this file: a
# realistic PKCS#1 line, ~400 characters of base64 body, of the shape a real
# leak has and the reviewed placeholders do not.
pem_open="-----BEGIN"
pem_private="PRIVATE KEY-----"
realistic_der="MIIEpAIBAAKCAQEA"
for _ in 1 2 3 4 5 6; do
  realistic_der+="7bQvXk2LmN9pRs0aZbYcJhGfEeDdCcBbAa9876543210QwErTyUiOpAsDfGhJkL"
done
realistic_key_line="  KEY: \"${pem_open} RSA ${pem_private}\\n${realistic_der}\\n\","

# The table itself, from the script rather than restated here: a copy in the
# test is a copy that stops matching the thing it claims to cover.
mapfile -t allowlist_rows < <("$script" --list-allowlist)
if [[ "${#allowlist_rows[@]}" -ge 1 ]]; then
  pass "the script publishes its allowlist (${#allowlist_rows[@]} reviewed exception(s))"
else
  fail "the script publishes its allowlist" "--list-allowlist printed nothing"
fi

allowlist_paths=()
allowlist_pem_path=""
for row in "${allowlist_rows[@]}"; do
  IFS=$'\t' read -r row_label row_path row_digest row_reason <<<"$row"
  if [[ ! "$row_digest" =~ ^[0-9a-f]{64}$ ]]; then
    fail "every allowlist entry pins a line by SHA-256" "$row_label | $row_path | digest: ${row_digest:0:20}"
  fi
  if [[ "${#row_reason}" -lt 20 ]]; then
    fail "every allowlist entry carries a written reason" "$row_label | $row_path"
  fi
  if [[ ! -f "$root/$row_path" ]]; then
    fail "every allowlist entry names a file that exists" "$row_path"
  fi
  allowlist_paths+=("$row_path")
  [[ "$row_label" == "private key material" ]] && allowlist_pem_path="$row_path"
done
if [[ -n "$allowlist_pem_path" ]]; then
  pass "allowlist entries carry a 64-hex digest, a reason, and an existing path"
else
  fail "the allowlist still holds a private-key exception to test against" \
    "no 'private key material' entry; if that is deliberate, delete section 7's plant cases with it"
fi

# A fixture checkout carrying the script and every allowlisted file, so the
# production exemptions are the ones under test.
self_fixture="$work/self"
build_self_fixture() {
  rm -rf "$self_fixture"
  mkdir -p "$self_fixture/scripts"
  cp "$script" "$self_fixture/scripts/check-secret-scan.sh"
  local path
  for path in "${allowlist_paths[@]}"; do
    mkdir -p "$self_fixture/${path%/*}"
    cp "$root/$path" "$self_fixture/$path"
  done
  (
    cd "$self_fixture"
    git init -q .
    git config user.email scan@test.invalid
    git config user.name 'scan test'
    git add -A
    git commit -qm fixture
  ) >/dev/null
}
run_self_fixture() { "$bash_bin" "$self_fixture/scripts/check-secret-scan.sh" 2>&1; }

# 7a. The control. Without this, every plant below could pass because the
#     fixture never scans clean in the first place.
build_self_fixture
fixture_out="$(run_self_fixture)"
fixture_status=$?
if [[ "$fixture_status" -eq 0 && "$fixture_out" == *"secret scan passed"* ]]; then
  pass "allowlist: the reviewed lines are exempted and the fixture scans clean"
else
  fail "allowlist: the reviewed lines are exempted and the fixture scans clean" \
    "status $fixture_status, output: $fixture_out"
fi

# 7b. THE GUARD. A real-shaped key added to an allowlisted file is reported.
#     Under the old <label, file> scoping this case passed the scan.
build_self_fixture
printf '%s\n' "$realistic_key_line" >>"$self_fixture/$allowlist_pem_path"
(cd "$self_fixture" && git commit -qam planted) >/dev/null
planted_self_out="$(run_self_fixture)"
planted_self_status=$?
if [[ "$planted_self_status" -ne 0 ]]; then
  pass "allowlist: a real-shaped key elsewhere in an allowlisted file fails the scan"
else
  fail "allowlist: a real-shaped key elsewhere in an allowlisted file fails the scan" \
    "the exemption swallowed it; output: $planted_self_out"
fi
if [[ "$planted_self_out" == *"$realistic_der"* && "$planted_self_out" == *"$allowlist_pem_path"* ]]; then
  pass "allowlist: the planted key is printed, with its path"
else
  fail "allowlist: the planted key is printed, with its path" "output: $planted_self_out"
fi

# 7c. The same key ON the reviewed line, which a <label, file, line-number>
#     exception would still have exempted. The digest is what refuses it.
build_self_fixture
printf '%s\n' "$realistic_key_line" >"$self_fixture/$allowlist_pem_path"
(cd "$self_fixture" && git commit -qam replaced) >/dev/null
replaced_self_out="$(run_self_fixture)"
replaced_self_status=$?
if [[ "$replaced_self_status" -ne 0 && "$replaced_self_out" == *"$realistic_der"* ]]; then
  pass "allowlist: a real-shaped key replacing the reviewed line fails the scan"
else
  fail "allowlist: a real-shaped key replacing the reviewed line fails the scan" \
    "status $replaced_self_status, output: $replaced_self_out"
fi
# "an allowlisted file changed" and "a credential leaked" have opposite fixes,
# so the report must distinguish them rather than leave the reader guessing.
if [[ "$replaced_self_out" == *"the allowlist does not cover"* ]]; then
  pass "allowlist: a changed reviewed line is reported as drift, not just as a hit"
else
  fail "allowlist: a changed reviewed line is reported as drift, not just as a hit" \
    "output: $replaced_self_out"
fi

# 7d. An entry that stops matching is a failure, so the table cannot rot into a
#     permanent exemption for a file nobody reviews any more.
build_self_fixture
(cd "$self_fixture" && git rm -q "$allowlist_pem_path" && git commit -qm dropped) >/dev/null
stale_self_out="$(run_self_fixture)"
stale_self_status=$?
if [[ "$stale_self_status" -ne 0 && "$stale_self_out" == *"no longer match anything"* ]]; then
  pass "allowlist: an entry that matches nothing fails the scan as stale"
else
  fail "allowlist: an entry that matches nothing fails the scan as stale" \
    "status $stale_self_status, output: $stale_self_out"
fi

# 7e. No digest tool means the exemptions cannot be checked. Granting them
#     unchecked is the silent skip #525 exists to refuse.
no_digest_path="$(make_shim_path "$work/bin-no-digest" bash mktemp sed sort comm cat rm git)"
build_self_fixture
no_digest_out="$(PATH="$no_digest_path" "$bash_bin" "$self_fixture/scripts/check-secret-scan.sh" 2>&1)"
no_digest_status=$?
if [[ "$no_digest_status" -ne 0 && "$no_digest_out" == *"sha256sum"* ]]; then
  pass "allowlist: no digest tool on PATH exits non-zero naming sha256sum"
else
  fail "allowlist: no digest tool on PATH exits non-zero naming sha256sum" \
    "status $no_digest_status, output: $no_digest_out"
fi
if [[ "$no_digest_out" != *"secret scan passed"* ]]; then
  pass "allowlist: no digest tool on PATH never reports a pass"
else
  fail "allowlist: no digest tool on PATH never reports a pass" "output: $no_digest_out"
fi

# Unused status from the very first probe; keep shellcheck and readers honest.
: "$out" "$status"

if [[ "$failures" -ne 0 ]]; then
  printf '\n%d assertion(s) failed\n' "$failures" >&2
  exit 1
fi
printf '\nall secret-scan assertions passed\n'
