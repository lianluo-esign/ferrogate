#!/usr/bin/env bash
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-11
# description: Verify a FerroGate image signature, provenance, SBOM, and build-input attestations.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: verify-image-supply-chain.sh --mode <release|ci> --image <ghcr digest> \
  --workflow-ref <git ref> --source-digest <git sha>

The image must be ghcr.io/lianluo-esign/ferrogate@sha256:<64 lowercase hex>.
EOF
}

mode=""
image=""
workflow_ref=""
source_digest=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) mode="${2:-}"; shift 2 ;;
    --image) image="${2:-}"; shift 2 ;;
    --workflow-ref) workflow_ref="${2:-}"; shift 2 ;;
    --source-digest) source_digest="${2:-}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$mode" in
  release|ci) workflow="ci-image.yml" ;;
  *) echo "--mode must be release or ci" >&2; exit 2 ;;
esac

if [[ ! "$image" =~ ^ghcr\.io/lianluo-esign/ferrogate@sha256:[0-9a-f]{64}$ ]]; then
  echo "--image must be the immutable FerroGate GHCR sha256 digest" >&2
  exit 2
fi
if [[ ! "$workflow_ref" =~ ^refs/(heads/[A-Za-z0-9._/-]+|tags/v[0-9]{4}\.[0-9]{2}\.[0-9]{2})$ ]]; then
  echo "--workflow-ref must be an explicit branch ref or FerroGate release tag ref" >&2
  exit 2
fi
if [[ ! "$source_digest" =~ ^[0-9a-f]{40}$ ]]; then
  echo "--source-digest must be a full lowercase Git commit SHA" >&2
  exit 2
fi

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! git -C "$source_root" cat-file -e "${source_digest}^{commit}" 2>/dev/null; then
  echo "--source-digest is not present in the verifier source checkout" >&2
  exit 2
fi
if [[ "$(git -C "$source_root" rev-parse HEAD)" != "$source_digest" ]]; then
  echo "verifier checkout HEAD must match --source-digest" >&2
  exit 2
fi
cargo_lock_digest="$(git -C "$source_root" show "${source_digest}:Cargo.lock" | sha256sum | awk '{print $1}')"
dockerfile_digest="$(git -C "$source_root" show "${source_digest}:Dockerfile" | sha256sum | awk '{print $1}')"

repo="lianluo-esign/ferrogate"
identity="https://github.com/${repo}/.github/workflows/${workflow}@${workflow_ref}"
issuer="https://token.actions.githubusercontent.com"
build_inputs_type="https://token4ai.cloud/ferrogate/build-inputs/v1"
cosign_bin="${FERROGATE_COSIGN_BIN:-cosign}"
gh_bin="${FERROGATE_GH_BIN:-gh}"

"$cosign_bin" verify \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  "$image"

"$cosign_bin" verify-attestation \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  --type spdxjson \
  "$image"

build_inputs_attestation="$("$cosign_bin" verify-attestation \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  --type "$build_inputs_type" \
  "$image")"
predicate_args=(
  --image "$image"
  --workflow-ref "${repo}/.github/workflows/${workflow}@${workflow_ref}"
  --source-digest "$source_digest"
  --cargo-lock-digest "$cargo_lock_digest"
  --dockerfile-digest "$dockerfile_digest"
)
printf '%s\n' "$build_inputs_attestation" | \
  python3 "$(dirname "${BASH_SOURCE[0]}")/verify-build-input-attestation.py" \
    "${predicate_args[@]}"

gh_args=(
  attestation verify "oci://${image}"
  --repo "$repo"
  --cert-identity "$identity"
  --cert-oidc-issuer "$issuer"
)
gh_args+=(--source-digest "$source_digest")
"$gh_bin" "${gh_args[@]}"

echo "verified FerroGate signature, provenance, SBOM, and build-input attestations for ${image}"
