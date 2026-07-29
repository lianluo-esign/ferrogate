#!/usr/bin/env bash
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-27
# description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
#
# High-confidence secret scan over every tracked authored file (#525).
#
# Extracted from scripts/security-check.sh, which hard-coded `rg` (ripgrep).
# ripgrep is not part of any baseline install, so on a box without it the scan
# section died with a bare `rg: command not found` and the script reported
# "Potential secrets found:" over an empty list -- a gate everyone believed was
# running, that was not. Silence is the failure mode #499, #506, #508, #513 and
# #533 all shared; this script refuses it.
#
#   rg present   -> ripgrep, unchanged behaviour.
#   rg absent    -> `git grep -I`, which ships wherever the repo does.
#   neither      -> exit non-zero naming both tools. Never a silent skip.
#
#   scripts/check-secret-scan.sh                 # scan this checkout
#   scripts/check-secret-scan.sh --root DIR      # scan another git checkout
#   scripts/check-secret-scan.sh --list-files    # print tracked authored inputs
#   scripts/check-secret-scan.sh --list-scannable-files  # print scanner inputs
#   scripts/check-secret-scan.sh --list-allowlist  # print the reviewed exceptions
#
# Engine equivalence: rg is invoked with --line-number --no-heading and no
# other regex flags, so every pattern below is plain (non-PCRE) regex matched
# per line, and only *whether a line matches* can affect the output -- the
# whole line is printed either way. All six patterns are POSIX-ERE clean, so
# `git grep -E` is a faithful translation; scripts/test-check-secret-scan.sh
# diffs both engines over a corpus (UTF-8, CRLF, no-trailing-newline, 200 KB
# lines, pathspec-magic filenames) and asserts byte equality after sorting.
#
# Known engine differences, both handled here rather than left implicit:
#   * Files git calls binary are skipped outright by `git grep -I`, while rg
#     can print "binary file matches" without the line. This script rejects an
#     unreviewed binary before either engine runs, so engine choice cannot
#     change the verdict. A reviewed exception is content-pinned and stale-checked.
#   * `git grep` ignores a tracked path missing from the worktree and still
#     exits 0, where rg fails loudly. The readability guard below closes that.
#   * rg emits matches in nondeterministic (parallel) order; git grep follows
#     the file list. Nothing downstream depends on order.
set -euo pipefail

root_dir=""
list_files_only=0
list_scannable_files_only=0
list_allowlist_only=0
scanning_this_repo=1

print_help() {
  printf '%s\n' \
    'High-confidence secret scan over tracked authored files.' \
    '' \
    'Usage:' \
    '  scripts/check-secret-scan.sh' \
    '  scripts/check-secret-scan.sh --root DIR' \
    '  scripts/check-secret-scan.sh --list-files' \
    '  scripts/check-secret-scan.sh --list-scannable-files' \
    '  scripts/check-secret-scan.sh --list-allowlist'
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --root)
      [[ "$#" -ge 2 ]] || { echo "--root requires a directory" >&2; exit 2; }
      root_dir="$2"
      scanning_this_repo=0
      shift 2
      ;;
    --list-files)
      list_files_only=1
      shift
      ;;
    --list-scannable-files)
      list_scannable_files_only=1
      shift
      ;;
    --list-allowlist)
      # The reviewed-exception table, one TAB-separated row per entry, so
      # scripts/test-check-secret-scan.sh can drive the real table instead of
      # restating it -- a copy in the test is a copy that stops matching.
      list_allowlist_only=1
      shift
      ;;
    -h | --help)
      # Keep help available even on the stripped PATH whose failure behaviour
      # this gate exists to diagnose.
      print_help
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$root_dir" ]]; then
  # Bash-native, so the tool preflight below is what reports a stripped PATH
  # rather than a confusing "dirname: command not found" from this line.
  script_dir="${BASH_SOURCE[0]%/*}"
  [[ "$script_dir" == "${BASH_SOURCE[0]}" ]] && script_dir="."
  root_dir="$script_dir/.."
fi
cd "$root_dir"
root_dir="$PWD"

# Reviewed non-secret matches: "<label>\t<path>\t<sha256>\t<reason>".
#
# An entry exempts ONE LINE, pinned by the SHA-256 of the matched line's own
# content -- not the file (#566). A file-scoped exemption means a real key
# pasted anywhere in an allowlisted file scans clean, and the two files here are
# credential tests, exactly where a real value is most likely to be pasted by
# mistake. The digest is over the line's text only, so the entry survives the
# line moving and dies the moment its content changes.
#
# Two ways an entry fails rather than rots. One that matches nothing at all is
# reported as stale below (same discipline as REVIEWED_BINARY_FILES in
# scripts/check-binary-source-files.py). One whose file and label still match
# but whose line has CHANGED grants nothing: the match is reported as a finding,
# with a note naming the entry so the reader knows to re-review the line and
# update the digest rather than to hunt a breach.
#
# Never put the literal value here -- the allowlist file is itself scanned, and
# a digest is not the value. Recompute one with:
#
#   scripts/check-secret-scan.sh 2>&1 | sed -n 's/^[^:]*:[0-9]*://p' |
#     while IFS= read -r l; do printf '%s' "$l" | sha256sum; done
secret_scan_allowlist=(
  $'GitHub token\tcrates/ferrogate-runtime/src/coding_agent/materialize_test.rs\t316f47ed71425cec4cab1629059b6d69d36ec7e20e291f6d4be41073f3650e00\tsynthetic bare-token literal asserting CredentialReference::parse rejects inline credentials'
  $'GitHub token\tworkers/agent-gateway/test/git-credential-leak.test.ts\t0196265512882027f8b3308963f78177c1ea15c154b0eab71a3cf5c29622b816\tsynthetic token the leak test asserts never reaches an upstream request'
  $'private key material\tworkers/agent-gateway/vitest.config.ts\t4bfc0a278b803710d04c8af4b9949dd730d00088d60f0e3104995fbf7e4315c0\tPEM header of the test-only signing key whose body reads "not-a-real-key-tests-never-sign"'
)
allowlist_hits=()
for _ in "${secret_scan_allowlist[@]}"; do allowlist_hits+=(0); done
allowlist_drift=()

# Binary files cannot be line-scanned. A genuinely necessary binary therefore
# needs an explicit, owned, content-pinned decision rather than a path-only hole:
# "<path>\t<sha256>\t<owner>\t<reason>". Entries that do not match a current
# binary are stale and fail. Empty on purpose: every tracked file currently
# admitted to the secret scan is text to git.
reviewed_binary_scan_files=()
reviewed_binary_scan_hits=()
for _ in "${reviewed_binary_scan_files[@]}"; do reviewed_binary_scan_hits+=(0); done

if [[ "$list_allowlist_only" -eq 1 ]]; then
  printf '%s\n' "${secret_scan_allowlist[@]}"
  exit 0
fi

# --- tool preflight -----------------------------------------------------
# Resolve the search engine before any work happens, and name what is missing.
secret_scan_engine=""
if command -v rg >/dev/null 2>&1; then
  secret_scan_engine="rg"
elif command -v git >/dev/null 2>&1; then
  secret_scan_engine="git-grep"
else
  echo "secret scan did NOT run: ripgrep not found on PATH and git grep fallback unavailable" >&2
  echo "a gate that cannot run must fail loudly instead of skipping itself (#525)" >&2
  exit 1
fi

missing_runtime_tools=()
for required_tool in git mktemp sed sort comm rm; do
  command -v "$required_tool" >/dev/null 2>&1 || missing_runtime_tools+=("$required_tool")
done
if [[ "${#missing_runtime_tools[@]}" -ne 0 ]]; then
  echo "secret scan did NOT run: missing required tool(s) on PATH: ${missing_runtime_tools[*]}" >&2
  exit 1
fi

if ! git rev-parse --show-toplevel >/dev/null 2>&1; then
  echo "secret scan did NOT run: $root_dir is not a git checkout" >&2
  exit 1
fi

# --- file list ----------------------------------------------------------
# Cargo.lock is generated dependency inventory rather than authored source. Its
# integrity and advisory surfaces are checked by `cargo metadata --locked`, the
# protobuf floor, cargo-audit, cargo-deny and release attestation gates. Exclude
# only the root lockfile so dependency strings cannot masquerade as application
# credentials while nested authored lock fixtures remain covered.
mapfile -d '' tracked_secret_scan_files < <(git ls-files -z -- ':!:Cargo.lock')
if [[ "${#tracked_secret_scan_files[@]}" -eq 0 ]]; then
  echo "secret scan found no tracked files" >&2
  exit 1
fi

if [[ "$list_files_only" -eq 1 ]]; then
  printf '%s\n' "${tracked_secret_scan_files[@]}"
  exit 0
fi

# The allowlist pins each reviewed exemption to one line by SHA-256 (#566), so
# without a digest tool the scan could only choose between granting every
# exemption unchecked and reporting three known-good lines as findings. Both are
# wrong. `--list-files` exits above because listing tracked inputs does not read
# or grant an allowlist entry and therefore does not require a digest backend.
secret_scan_digest_cmd=()
if [[ "$scanning_this_repo" -eq 1 ]]; then
  if command -v sha256sum >/dev/null 2>&1; then
    secret_scan_digest_cmd=(sha256sum)
  elif command -v shasum >/dev/null 2>&1; then
    secret_scan_digest_cmd=(shasum -a 256)
  else
    echo "secret scan did NOT run: neither sha256sum nor shasum found on PATH" >&2
    echo "a gate that cannot verify its own exemptions must fail loudly instead of granting them (#525, #566)" >&2
    exit 1
  fi
fi

# A tracked path missing from the worktree is skipped by `git grep` with exit
# status 0 -- coverage silently lost. Refuse to scan a list we cannot read.
unreadable_scan_files=()
for scan_path in "${tracked_secret_scan_files[@]}"; do
  [[ -r "$scan_path" ]] || unreadable_scan_files+=("$scan_path")
done
if [[ "${#unreadable_scan_files[@]}" -ne 0 ]]; then
  echo "secret scan cannot read ${#unreadable_scan_files[@]} tracked file(s); the scan would skip them silently:" >&2
  printf '  %s\n' "${unreadable_scan_files[@]:0:20}" >&2
  exit 1
fi

# Files git classifies as binary are not line-scanned by either engine. Empty
# files are text with no lines, not binary, so compare only non-empty files.
binary_scan_files=()
nonempty_scan_files=()
for scan_path in "${tracked_secret_scan_files[@]}"; do
  [[ -s "$scan_path" ]] && nonempty_scan_files+=("$scan_path")
done
mapfile -t git_text_scan_files < <(
  git --literal-pathspecs grep -I -l -e '' -- "${nonempty_scan_files[@]}" || true
)
if [[ "${#git_text_scan_files[@]}" -ne "${#nonempty_scan_files[@]}" ]]; then
  mapfile -t binary_scan_files < <(
    comm -23 \
      <(printf '%s\n' "${nonempty_scan_files[@]}" | LC_ALL=C sort) \
      <(printf '%s\n' "${git_text_scan_files[@]}" | LC_ALL=C sort)
  )
fi

secret_scan_file_digest() {
  local rendered
  rendered="$("${secret_scan_digest_cmd[@]}" -- "$1")" || return 1
  printf '%s' "${rendered%% *}"
}

binary_scan_failures=()
reviewed_binary_paths=()
for binary_path in "${binary_scan_files[@]}"; do
  binary_reviewed=0
  if [[ "$scanning_this_repo" -eq 1 ]]; then
    binary_index=0
    for entry in "${reviewed_binary_scan_files[@]}"; do
      IFS=$'\t' read -r entry_path entry_digest entry_owner entry_reason <<<"$entry"
      if [[ "$binary_path" == "$entry_path" ]]; then
        # The path is current even when its content or metadata has drifted;
        # report that defect once rather than also mislabelling it stale.
        reviewed_binary_scan_hits[binary_index]=1
        actual_digest="$(secret_scan_file_digest "$binary_path")"
        if [[ "$entry_digest" =~ ^[0-9a-f]{64}$ && -n "$entry_owner" &&
          "${#entry_reason}" -ge 20 && "$actual_digest" == "$entry_digest" ]]; then
          reviewed_binary_paths+=("$binary_path")
          binary_reviewed=1
        else
          binary_scan_failures+=("$binary_path: reviewed binary entry is malformed or its SHA-256 changed")
          binary_reviewed=1
        fi
      fi
      binary_index=$((binary_index + 1))
    done
  fi
  if [[ "$binary_reviewed" -eq 0 ]]; then
    binary_scan_failures+=("$binary_path: binary to git and not present in reviewed_binary_scan_files")
  fi
done

if [[ "$scanning_this_repo" -eq 1 ]]; then
  binary_index=0
  for entry in "${reviewed_binary_scan_files[@]}"; do
    if [[ "${reviewed_binary_scan_hits[binary_index]}" -eq 0 ]]; then
      entry_path="${entry%%$'\t'*}"
      binary_scan_failures+=("$entry_path: stale reviewed_binary_scan_files entry")
    fi
    binary_index=$((binary_index + 1))
  done
fi

if [[ "${#binary_scan_failures[@]}" -ne 0 ]]; then
  echo "secret scan did NOT run: ${#binary_scan_failures[@]} binary coverage failure(s)" >&2
  printf '  %s\n' "${binary_scan_failures[@]}" >&2
  echo "fix the file, or add a SHA-256-pinned entry with an owner and reason after explicit review" >&2
  exit 1
fi

# Reviewed binaries are deliberately outside both engine invocations. This is
# what makes the rg and git-grep verdict identical for the binary case.
scannable_scan_files=()
for scan_path in "${tracked_secret_scan_files[@]}"; do
  scan_path_is_reviewed_binary=0
  for binary_path in "${reviewed_binary_paths[@]}"; do
    [[ "$scan_path" == "$binary_path" ]] && scan_path_is_reviewed_binary=1
  done
  [[ "$scan_path_is_reviewed_binary" -eq 0 ]] && scannable_scan_files+=("$scan_path")
done

if [[ "$list_scannable_files_only" -eq 1 ]]; then
  printf '%s\n' "${scannable_scan_files[@]}"
  exit 0
fi

echo "==> high-confidence secret scan (engine: $secret_scan_engine)"
echo "secret scan coverage: ${#scannable_scan_files[@]}/${#tracked_secret_scan_files[@]} tracked files are line-scannable"
if [[ "${#reviewed_binary_paths[@]}" -ne 0 ]]; then
  echo "secret scan reviewed binary exception(s): ${#reviewed_binary_paths[@]}" >&2
  printf '  %s\n' "${reviewed_binary_paths[@]}" >&2
fi

# --- scan ---------------------------------------------------------------
scan_file="$(mktemp)"
match_file="$(mktemp)"
trap 'rm -f "$scan_file" "$match_file"' EXIT

rg_common=(
  --line-number
  --no-heading
  --with-filename
)

git_grep_common=(
  --literal-pathspecs
  grep
  -I
  --no-color
  --full-name
  --line-number
  --extended-regexp
)

# Both engines exit 1 when nothing matched -- the success case here -- so the
# call must never run under `set -e`.
run_secret_scan_engine() {
  local pattern="$1"
  local status=0
  set +e
  case "$secret_scan_engine" in
    rg)
      rg "${rg_common[@]}" -e "$pattern" -- "${scannable_scan_files[@]}" >"$match_file"
      status=$?
      ;;
    git-grep)
      git "${git_grep_common[@]}" -e "$pattern" -- "${scannable_scan_files[@]}" >"$match_file"
      status=$?
      ;;
  esac
  set -e
  return "$status"
}

# SHA-256 of a single line's content, with no trailing newline. `sha256sum` and
# `shasum -a 256` print "<digest>  <name>"; keep the first field in bash so the
# scan needs no extra process on PATH.
secret_scan_line_digest() {
  local rendered
  rendered="$(printf '%s' "$1" | "${secret_scan_digest_cmd[@]}")" || return 1
  printf '%s' "${rendered%% *}"
}

secret_scan_allowlisted() {
  local label="$1"
  local path="$2"
  local content="$3"
  local index=0
  local digest="" entry rest entry_label entry_path entry_digest
  for entry in "${secret_scan_allowlist[@]}"; do
    rest="$entry"
    entry_label="${rest%%$'\t'*}"
    rest="${rest#*$'\t'}"
    entry_path="${rest%%$'\t'*}"
    rest="${rest#*$'\t'}"
    entry_digest="${rest%%$'\t'*}"
    if [[ "$label" == "$entry_label" && "$path" == "$entry_path" ]]; then
      [[ -n "$digest" ]] || digest="$(secret_scan_line_digest "$content")"
      if [[ "$digest" == "$entry_digest" ]]; then
        allowlist_hits[index]=1
        return 0
      fi
      # Same file, same pattern, different line. Say so: "an allowlisted file
      # changed" and "a credential leaked" have opposite fixes.
      allowlist_drift+=("$label | $path | reviewed digest ${entry_digest:0:12}..., this line ${digest:0:12}...")
    fi
    index=$((index + 1))
  done
  return 1
}

scan_secret_pattern() {
  local label="$1"
  local pattern="$2"
  local status=0
  run_secret_scan_engine "$pattern" || status=$?

  if [[ "$status" -eq 1 ]]; then
    return 0
  fi
  if [[ "$status" -ne 0 ]]; then
    echo "secret scan failed while checking: $label (engine $secret_scan_engine exited $status)" >&2
    return 1
  fi

  # Engine output is "<path>:<line-number>:<content>"; the allowlist is pinned
  # to the content, so the entry survives the line moving within its file.
  local line path rest content kept=0
  while IFS= read -r line; do
    path="${line%%:*}"
    rest="${line#*:}"
    content="${rest#*:}"
    if [[ "$scanning_this_repo" -eq 1 ]] && secret_scan_allowlisted "$label" "$path" "$content"; then
      continue
    fi
    printf '%s\n' "$line" >>"$scan_file"
    kept=1
  done <"$match_file"

  if [[ "$kept" -eq 1 ]]; then
    echo "secret scan matched: $label" >&2
    return 1
  fi
  return 0
}

scan_failed=0
scan_secret_pattern "private key material" '-----BEGIN (RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----' || scan_failed=1
scan_secret_pattern "AWS access key id" '(AKIA|ASIA)[0-9A-Z]{16}' || scan_failed=1
scan_secret_pattern "GitHub token" 'gh[pousr]_[A-Za-z0-9_]{20,}' || scan_failed=1
scan_secret_pattern "OpenAI-style API key" 'sk-[A-Za-z0-9]{32,}' || scan_failed=1
scan_secret_pattern "Anthropic API key" 'sk-ant-[A-Za-z0-9_-]{20,}' || scan_failed=1
scan_secret_pattern "Google API key" 'AIza[0-9A-Za-z_-]{35}' || scan_failed=1

if [[ "$scan_failed" -ne 0 ]]; then
  # Only claim a finding when there is one: a broken engine used to print
  # "Potential secrets found:" over an empty list, which reads like noise.
  if [[ -s "$scan_file" ]]; then
    echo "Potential secrets found:" >&2
    sed -n '1,120p' "$scan_file" >&2
    if [[ "${#allowlist_drift[@]}" -ne 0 ]]; then
      echo "note: an allowlisted file matched on a line the allowlist does not cover:" >&2
      printf '  %s\n' "${allowlist_drift[@]}" >&2
      echo "re-review the line; if it is still not a secret, update the entry's digest in ${BASH_SOURCE[0]}" >&2
    fi
  else
    echo "secret scan did not complete; treat this repository as unscanned" >&2
  fi
  exit 1
fi

if [[ "$scanning_this_repo" -eq 1 ]]; then
  stale_allowlist=()
  index=0
  for entry in "${secret_scan_allowlist[@]}"; do
    if [[ "${allowlist_hits[index]}" -eq 0 ]]; then
      stale_allowlist+=("${entry//$'\t'/ | }")
    fi
    index=$((index + 1))
  done
  if [[ "${#stale_allowlist[@]}" -ne 0 ]]; then
    echo "secret scan allowlist entries no longer match anything; delete them:" >&2
    printf '  %s\n' "${stale_allowlist[@]}" >&2
    exit 1
  fi
fi

echo "secret scan passed"
