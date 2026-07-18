#!/usr/bin/env bash
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-18
# description: Offline release-verification dry-run matrix for issue #208.
# Produces a locally signed release-evidence bundle for the current commit and
# runs the REAL consumer verifier (scripts/verify-image-supply-chain.sh)
# against it: PASS on the good bundle, FAIL on every negative case.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
dryrun_dir="$root/scripts/release-dryrun"
verifier="$root/scripts/verify-image-supply-chain.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

source_digest="$(git -C "$root" rev-parse HEAD)"
# Release-shaped ref derived from the commit date; no tag is created or pushed.
release_ref="refs/tags/v$(git -C "$root" log -1 --format=%cd --date=format:%Y.%m.%d HEAD)"

export FERROGATE_COSIGN_BIN="$dryrun_dir/shims/cosign"
export FERROGATE_GH_BIN="$dryrun_dir/shims/gh"

echo "== producing locally signed release-evidence bundle (ephemeral key) =="
good_bundle="$tmp/bundle-good"
image="$(python3 "$dryrun_dir/produce_bundle.py" --out "$good_bundle" --workflow-ref "$release_ref")"
digest="${image##*@sha256:}"
echo "   image (dry-run digest stand-in): $image"
echo "   source: $source_digest"
echo "   signing identity ref: $release_ref"

rogue_issuer_bundle="$tmp/bundle-rogue-issuer"
python3 "$dryrun_dir/produce_bundle.py" \
  --out "$rogue_issuer_bundle" --workflow-ref "$release_ref" \
  --issuer "https://rogue-issuer.example.invalid" >/dev/null

unsigned_bundle="$tmp/bundle-unsigned"
python3 "$dryrun_dir/produce_bundle.py" \
  --out "$unsigned_bundle" --workflow-ref "$release_ref" --unsigned >/dev/null

tampered_attestation_bundle="$tmp/bundle-tampered-attestation"
cp -r "$good_bundle" "$tampered_attestation_bundle"
python3 - "$tampered_attestation_bundle/attestations/build-inputs.dsse.json" <<'PY'
import base64
import json
import sys

path = sys.argv[1]
envelope = json.loads(open(path).read())
statement = json.loads(base64.b64decode(envelope["payload"]))
# Tamper with a signed build input AFTER signing; the old DSSE signature stays.
statement["predicate"]["cargo_lock_sha256"] = "e" * 64
envelope["payload"] = base64.b64encode(
    json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
).decode()
open(path, "w").write(json.dumps(envelope, indent=2) + "\n")
PY

tampered_digest="ghcr.io/lianluo-esign/ferrogate@sha256:$(printf 'e%.0s' {1..64})"
if [[ "$tampered_digest" == "$image" ]]; then
  echo "tampered digest collided with the real digest" >&2
  exit 1
fi

declare -a case_names=() case_expectations=() case_results=()
failures=0

run_case() {
  local name="$1" expectation="$2" bundle="$3"
  shift 3
  local outcome
  if FERROGATE_DRYRUN_BUNDLE="$bundle" "$verifier" "$@" \
    >"$tmp/${name}.log" 2>&1; then
    outcome=PASS
  else
    outcome=FAIL
  fi
  local status="as-expected"
  if [[ "$outcome" != "$expectation" ]]; then
    status="UNEXPECTED"
    failures=$((failures + 1))
    sed "s/^/   [$name] /" "$tmp/${name}.log" >&2
  fi
  case_names+=("$name")
  case_expectations+=("$expectation")
  case_results+=("$outcome ($status)")
}

echo "== running the real consumer verifier against the local bundle =="
run_case good PASS "$good_bundle" \
  --mode release --image "$image" \
  --workflow-ref "$release_ref" --source-digest "$source_digest"

run_case tampered-digest FAIL "$good_bundle" \
  --mode release --image "$tampered_digest" \
  --workflow-ref "$release_ref" --source-digest "$source_digest"

run_case wrong-identity FAIL "$good_bundle" \
  --mode release --image "$image" \
  --workflow-ref refs/heads/forged-release --source-digest "$source_digest"

run_case wrong-issuer FAIL "$rogue_issuer_bundle" \
  --mode release --image "$image" \
  --workflow-ref "$release_ref" --source-digest "$source_digest"

run_case unsigned FAIL "$unsigned_bundle" \
  --mode release --image "$image" \
  --workflow-ref "$release_ref" --source-digest "$source_digest"

run_case tampered-attestation FAIL "$tampered_attestation_bundle" \
  --mode release --image "$image" \
  --workflow-ref "$release_ref" --source-digest "$source_digest"

echo
echo "== release-verification dry-run matrix =="
printf '%-24s %-10s %s\n' CASE EXPECTED RESULT
for index in "${!case_names[@]}"; do
  printf '%-24s %-10s %s\n' \
    "${case_names[$index]}" "${case_expectations[$index]}" "${case_results[$index]}"
done

if [[ "$failures" -ne 0 ]]; then
  echo "release-verification dry-run matrix FAILED ($failures unexpected outcome(s))" >&2
  exit 1
fi
echo "release-verification dry-run matrix passed (digest sha256:$digest)"
