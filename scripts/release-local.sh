#!/usr/bin/env bash
# Local release: build the image in Docker, run the gate, sign + SBOM, push to GHCR —
# WITHOUT consuming GitHub Actions minutes.
#
# REQUIREMENTS (on the host running this — NOT available in the dev sandbox):
#   docker (or podman aliased), cosign, syft, gh (or a GHCR PAT), rustup 1.88.0
#
# SIGNING TRADE-OFF (read before using for a "verifiable signed release", #208):
#   The GitHub Actions pipeline signs KEYLESSLY with the CI workflow's OIDC identity
#   (signer-workflow-ref = .../ci-image.yml@<ref>). scripts/verify-image-supply-chain.sh
#   in --mode release pins to THAT identity. A LOCAL signature cannot reproduce the
#   GitHub-workflow provenance — it is signed by YOUR key/identity, so the release-mode
#   verifier will reject it. Use:
#     --sign local-key   : cosign key-pair you control (fast; local trust root, NOT GH provenance)
#     --sign none        : just build + test + push the image (no signature/SBOM)
#   For a release that keeps the GitHub-workflow provenance while not queuing on GitHub-
#   hosted runners, register a SELF-HOSTED runner and run the existing ci.yml there —
#   that keeps keyless OIDC + provenance and runs on your hardware. See docs.
#
# USAGE:
#   scripts/release-local.sh --tag v2026.07.18 [--owner lianluo-esign] [--sign local-key|none] [--skip-tests] [--push]
set -euo pipefail

OWNER="lianluo-esign"
TAG=""
SIGN="local-key"
DO_PUSH="false"
SKIP_TESTS="false"
COSIGN_KEY="${COSIGN_KEY:-cosign.key}"   # for --sign local-key

while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG="$2"; shift 2;;
    --owner) OWNER="$2"; shift 2;;
    --sign) SIGN="$2"; shift 2;;
    --push) DO_PUSH="true"; shift;;
    --skip-tests) SKIP_TESTS="true"; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$TAG" ] || { echo "ERROR: --tag <vYYYY.MM.DD> required" >&2; exit 2; }

IMAGE="ghcr.io/${OWNER}/ferrogate"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Engine selection: prefer a real container daemon (reference Dockerfile, glibc);
# on a no-sudo/no-daemon host fall back to the musl-static + crane path, which
# needs neither root nor a runtime. See scripts/build-image-crane.sh.
ENGINE="docker"
if ! command -v docker >/dev/null; then
  ENGINE="crane"
  echo "NOTE: docker not found -> using no-daemon musl+crane image path (scripts/build-image-crane.sh)."
fi

echo "== 1/5 local gate =="
if [ "$SKIP_TESTS" = "true" ]; then
  echo "   (skipped --skip-tests)"
else
  # The same gate the release pipeline enforces before an image is trusted.
  cargo +1.88.0 fmt --check
  cargo +1.88.0 clippy --workspace --all-targets --all-features -- -D warnings
  cargo +1.88.0 test --workspace
  # Release gate (user directive 2026-07-19): the local ferrogate-test suite must
  # pass with no errors before an image is built/pushed. Replaces the slow GitHub
  # Actions release pipeline.
  cargo +1.88.0 build --release -p ferrogate-test
  if [ "$ENGINE" = "docker" ]; then
    # Full gate incl. Docker-backed cluster/shared-state/Redis scenarios.
    ./target/release/ferrogate-test ci
  else
    # No-daemon host: run the docker-free harness (run-all without --include-docker).
    # `ci` would abort on the first Docker-backed scenario. run-all needs the two
    # debug binaries it drives.
    cargo +1.88.0 build -p ferrogate-cli -p ferrogate-auth
    ./target/release/ferrogate-test run-all \
      --ferrogate-bin target/debug/ferrogate \
      --ferrogate-auth-bin target/debug/ferrogate-auth
    echo "   NOTE: Docker-backed cluster scenarios skipped (no daemon); run 'ferrogate-test ci' on a docker host for full coverage."
  fi
  # Dependency vulnerability gate (#208): RUSTSEC advisories over the locked graph.
  # git-fetch of the advisory DB may be blocked; set CARGO_AUDIT_DB to a pre-fetched
  # checkout to run offline. Missing tool/DB is a soft-skip (warns, doesn't block).
  if command -v cargo-audit >/dev/null; then
    if [ -n "${CARGO_AUDIT_DB:-}" ]; then
      cargo-audit audit --no-fetch --db "$CARGO_AUDIT_DB" --file Cargo.lock \
        || echo "   WARNING: cargo-audit reported findings (review above)."
    else
      cargo-audit audit --file Cargo.lock \
        || echo "   WARNING: cargo-audit reported findings (review above)."
    fi
  else
    echo "   (cargo-audit absent: dependency vuln gate skipped)"
  fi
  # Admin-console gate (#314): lint + Vitest + build for the SPA that ships in
  # the image. Soft-skips only when Node/npm isn't installed on this host.
  if command -v node >/dev/null && command -v npm >/dev/null; then
    "$ROOT/scripts/check-admin-console.sh"
  else
    echo "   (node/npm absent: admin-console gate skipped — run scripts/check-admin-console.sh on a Node 22+ host)"
  fi
fi

if [ "$ENGINE" = "crane" ]; then
  # No-daemon path: musl-static build + crane assemble + push. Handles its own
  # build/stage/push (and GHCR_TOKEN / write:packages requirement).
  echo "== 2-3/5 musl+crane image build =="
  CRANE_ARGS=(--tag "$TAG" --owner "$OWNER")
  [ "$DO_PUSH" = "true" ] && CRANE_ARGS+=(--push)
  "$ROOT/scripts/build-image-crane.sh" "${CRANE_ARGS[@]}"
  if [ "$DO_PUSH" = "true" ]; then
    DIGEST="$(crane digest "${IMAGE}:${TAG}" 2>/dev/null || echo "sha256:UNKNOWN")"
  else
    DIGEST="sha256:LOCAL-DRY-RUN"
  fi
else
  echo "== 2/5 docker build =="
  # --provenance / --sbom off here; SBOM is produced explicitly in step 4.
  docker build -t "${IMAGE}:${TAG}" -t "${IMAGE}:latest" .

  echo "== 3/5 push to GHCR =="
  if [ "$DO_PUSH" = "true" ]; then
    # gh auth token -> GHCR login (or set CR_PAT and: echo "$CR_PAT" | docker login ghcr.io -u <user> --password-stdin)
    gh auth token | docker login ghcr.io -u "${OWNER}" --password-stdin
    docker push "${IMAGE}:${TAG}"
    docker push "${IMAGE}:latest"
    DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "${IMAGE}:${TAG}" | sed 's/.*@//')"
    echo "   published digest: ${DIGEST}"
  else
    echo "   (dry-run: pass --push to actually push to GHCR)"
    DIGEST="sha256:LOCAL-DRY-RUN"
  fi
fi

echo "== 4/5 SBOM + sign =="
case "$SIGN" in
  none) echo "   (--sign none: no signature/SBOM)";;
  local-key)
    command -v syft >/dev/null && syft "${IMAGE}@${DIGEST}" -o spdx-json > "sbom-${TAG}.spdx.json" || echo "   (syft absent: skipping SBOM)"
    if [ "$DO_PUSH" = "true" ] && command -v cosign >/dev/null; then
      [ -f "$COSIGN_KEY" ] || { echo "ERROR: --sign local-key needs \$COSIGN_KEY ($COSIGN_KEY); make one with 'cosign generate-key-pair'" >&2; exit 1; }
      cosign sign --key "$COSIGN_KEY" --yes "${IMAGE}@${DIGEST}"
      [ -f "sbom-${TAG}.spdx.json" ] && cosign attest --key "$COSIGN_KEY" --predicate "sbom-${TAG}.spdx.json" --type spdxjson --yes "${IMAGE}@${DIGEST}"
      echo "   signed with LOCAL key ($COSIGN_KEY) — NOT the GitHub-workflow OIDC identity (see header trade-off)."
    else
      echo "   (no push or cosign absent: skipping sign)"
    fi
    ;;
  *) echo "ERROR: --sign must be local-key or none" >&2; exit 2;;
esac

echo "== 5/5 verify =="
if [ "$DO_PUSH" = "true" ] && [ "$SIGN" = "local-key" ] && command -v cosign >/dev/null && [ -f "${COSIGN_KEY}.pub" ]; then
  cosign verify --key "${COSIGN_KEY}.pub" "${IMAGE}@${DIGEST}" && echo "   local-key signature verifies."
  echo "   NOTE: the release-mode GitHub-provenance verifier (scripts/verify-image-supply-chain.sh --mode release) will NOT pass on a local-key signature by design."
else
  echo "   (skipped)"
fi
echo "done: ${IMAGE}:${TAG}${DIGEST:+ @ }${DIGEST:-}"
