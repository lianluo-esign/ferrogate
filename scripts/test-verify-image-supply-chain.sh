#!/usr/bin/env bash
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-11
# description: Local contract tests for the digest-pinned supply-chain verifier.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
log="$tmp/calls.log"

cat >"$tmp/cosign" <<'EOF'
#!/usr/bin/env bash
printf 'cosign %s\n' "$*" >>"$MOCK_LOG"
if [[ "${MOCK_CRYPTOGRAPHIC_FAILURE:-0}" == "1" ]]; then
  exit 1
fi
if [[ -n "${MOCK_EXPECTED_IDENTITY:-}" && "$*" != *"--certificate-identity ${MOCK_EXPECTED_IDENTITY}"* ]]; then
  exit 1
fi
if [[ "$*" == *"verify-attestation"*"https://token4ai.cloud/ferrogate/build-inputs/v1"* ]]; then
  printf '{"payload":"%s"}\n' "$MOCK_BUILD_INPUT_PAYLOAD"
fi
EOF
cat >"$tmp/gh" <<'EOF'
#!/usr/bin/env bash
printf 'gh %s\n' "$*" >>"$MOCK_LOG"
[[ "${MOCK_CRYPTOGRAPHIC_FAILURE:-0}" != "1" ]]
EOF
chmod +x "$tmp/cosign" "$tmp/gh"

export MOCK_LOG="$log"
export FERROGATE_COSIGN_BIN="$tmp/cosign"
export FERROGATE_GH_BIN="$tmp/gh"
export MOCK_EXPECTED_IDENTITY="https://github.com/lianluo-esign/ferrogate/.github/workflows/ci-image.yml@refs/heads/main"
digest="ghcr.io/lianluo-esign/ferrogate@sha256:$(printf 'a%.0s' {1..64})"
export SOURCE_DIGEST="$(git -C "$root" rev-parse HEAD)"
export CARGO_LOCK_DIGEST="$(git -C "$root" show "${SOURCE_DIGEST}:Cargo.lock" | sha256sum | awk '{print $1}')"
export DOCKERFILE_DIGEST="$(git -C "$root" show "${SOURCE_DIGEST}:Dockerfile" | sha256sum | awk '{print $1}')"
export MOCK_BUILD_INPUT_PAYLOAD="$(python3 - <<'PY'
import base64
import json
import os

statement = {
    "_type": "https://in-toto.io/Statement/v1",
    "predicateType": "https://token4ai.cloud/ferrogate/build-inputs/v1",
    "subject": [{
        "name": "ghcr.io/lianluo-esign/ferrogate",
        "digest": {"sha256": "a" * 64},
    }],
    "predicate": {
        "repository": "lianluo-esign/ferrogate",
        "workflow_ref": "lianluo-esign/ferrogate/.github/workflows/ci-image.yml@refs/heads/main",
        "commit_sha": os.environ["SOURCE_DIGEST"],
        "image": "ghcr.io/lianluo-esign/ferrogate",
        "digest": "sha256:" + "a" * 64,
        "cargo_lock_sha256": os.environ["CARGO_LOCK_DIGEST"],
        "dockerfile_sha256": os.environ["DOCKERFILE_DIGEST"],
    },
}
print(base64.b64encode(json.dumps(statement).encode()).decode())
PY
)"

"$root/scripts/verify-image-supply-chain.sh" \
  --mode release \
  --image "$digest" \
  --workflow-ref refs/heads/main \
  --source-digest "$SOURCE_DIGEST" >/dev/null

grep -F "cosign verify --certificate-identity https://github.com/lianluo-esign/ferrogate/.github/workflows/ci-image.yml@refs/heads/main" "$log" >/dev/null
grep -F -- "--type spdxjson" "$log" >/dev/null
grep -F -- "--type https://token4ai.cloud/ferrogate/build-inputs/v1" "$log" >/dev/null
grep -F "gh attestation verify oci://$digest" "$log" >/dev/null

valid_build_input_payload="$MOCK_BUILD_INPUT_PAYLOAD"
export MOCK_BUILD_INPUT_PAYLOAD="$(python3 - <<'PY'
import base64
import json
import os

statement = json.loads(base64.b64decode(os.environ["MOCK_BUILD_INPUT_PAYLOAD"]))
statement["predicate"]["cargo_lock_sha256"] = "e" * 64
print(base64.b64encode(json.dumps(statement).encode()).decode())
PY
)"
if "$root/scripts/verify-image-supply-chain.sh" \
  --mode release --image "$digest" --workflow-ref refs/heads/main \
  --source-digest "$SOURCE_DIGEST" >/dev/null 2>&1; then
  echo "mismatched Cargo.lock digest unexpectedly passed" >&2
  exit 1
fi
export MOCK_BUILD_INPUT_PAYLOAD="$valid_build_input_payload"

if "$root/scripts/verify-image-supply-chain.sh" \
  --mode release --image ghcr.io/other/ferrogate@sha256:$(printf 'a%.0s' {1..64}) \
  --workflow-ref refs/heads/main --source-digest "$SOURCE_DIGEST" >/dev/null 2>&1; then
  echo "wrong repository identity unexpectedly passed" >&2
  exit 1
fi

if "$root/scripts/verify-image-supply-chain.sh" \
  --mode release --image ghcr.io/lianluo-esign/ferrogate:latest \
  --workflow-ref refs/heads/main --source-digest "$SOURCE_DIGEST" >/dev/null 2>&1; then
  echo "mutable tag unexpectedly passed" >&2
  exit 1
fi

if "$root/scripts/verify-image-supply-chain.sh" \
  --mode release --image "$digest" --workflow-ref refs/heads/forged \
  --source-digest "$SOURCE_DIGEST" \
  >/dev/null 2>&1; then
  echo "wrong workflow identity unexpectedly passed" >&2
  exit 1
fi

tampered_digest="ghcr.io/lianluo-esign/ferrogate@sha256:$(printf 'e%.0s' {1..64})"
if "$root/scripts/verify-image-supply-chain.sh" \
  --mode release --image "$tampered_digest" --workflow-ref refs/heads/main \
  --source-digest "$SOURCE_DIGEST" \
  >/dev/null 2>&1; then
  echo "tampered digest unexpectedly matched the signed predicate" >&2
  exit 1
fi

if "$root/scripts/verify-image-supply-chain.sh" \
  --mode release --image "$digest" --workflow-ref refs/heads/main \
  --source-digest "$(printf 'e%.0s' {1..40})" >/dev/null 2>&1; then
  echo "mismatched signed build-input predicate unexpectedly passed" >&2
  exit 1
fi

export MOCK_CRYPTOGRAPHIC_FAILURE=1
if "$root/scripts/verify-image-supply-chain.sh" \
  --mode release --image "$digest" --workflow-ref refs/heads/main \
  --source-digest "$SOURCE_DIGEST" >/dev/null 2>&1; then
  echo "cryptographic verification failure unexpectedly passed" >&2
  exit 1
fi

if "$root/scripts/verify-image-supply-chain.sh" \
  --mode release --image "$digest" --workflow-ref refs/heads/main \
  >/dev/null 2>&1; then
  echo "missing exact source digest unexpectedly passed" >&2
  exit 1
fi

echo "supply-chain verifier contract passed"
