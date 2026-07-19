#!/usr/bin/env bash
# Build + push the FerroGate GHCR image WITHOUT a container runtime and WITHOUT sudo.
#
# WHY THIS EXISTS
#   The reference Dockerfile compiles inside `rust:bookworm` and packages a glibc
#   binary. That needs a container engine. On a locked-down host (no sudo, no
#   Docker/Podman, and no setuid `newuidmap`/`newgidmap` so rootless engines can't
#   map subuids) there is no way to run a daemon or a rootless multi-uid build.
#
#   This script sidesteps the daemon entirely:
#     1. Cross-compile a FULLY STATIC musl binary on the host (no glibc-version
#        coupling to any base image — runs on scratch/distroless/anything).
#     2. Assemble the OCI image with `crane` (google/go-containerregistry) — a
#        static Go binary that talks to the registry directly. No daemon, no
#        namespaces, no privileges.
#
# TOOLCHAIN (userspace, no sudo — set up once; see docs/release/local-image-build.md)
#   - rustup target x86_64-unknown-linux-musl
#   - musl cross gcc:      $HOME/.local/musl/x86_64-linux-musl-cross/bin
#   - musl OpenSSL (static): $HOME/.local/musl-openssl   (native-tls -> postgres TLS)
#   - crane binary:        $HOME/.local/bin/crane  (or ./crane / on PATH)
#
# PUSH CREDENTIALS
#   GHCR push needs a token with `write:packages`. The default `gh` login here has
#   only repo/workflow/project scopes, so provide ONE of:
#     - env GHCR_TOKEN=<PAT with write:packages>
#     - `gh auth refresh -s write:packages` then re-run (token then covers it)
#   Username defaults to the repo owner.
#
# USAGE
#   scripts/build-image-crane.sh --tag v2026.07.19 [--owner lianluo-esign] [--push]
#   (no --push => assemble to a local OCI tarball and print the config; never touches GHCR)
set -euo pipefail

OWNER="lianluo-esign"
TAG=""
DO_PUSH="false"
BASE="gcr.io/distroless/static-debian12:latest"
TARGET="x86_64-unknown-linux-musl"

while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG="$2"; shift 2;;
    --owner) OWNER="$2"; shift 2;;
    --base) BASE="$2"; shift 2;;
    --push) DO_PUSH="true"; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$TAG" ] || { echo "ERROR: --tag <vYYYY.MM.DD> required" >&2; exit 2; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
IMAGE="ghcr.io/${OWNER}/ferrogate"

# --- resolve crane ---
CRANE="$(command -v crane || true)"
[ -z "$CRANE" ] && [ -x "$HOME/.local/bin/crane" ] && CRANE="$HOME/.local/bin/crane"
[ -z "$CRANE" ] && [ -x "$ROOT/crane" ] && CRANE="$ROOT/crane"
[ -n "$CRANE" ] || { echo "ERROR: crane not found (get github.com/google/go-containerregistry)" >&2; exit 1; }

# --- musl toolchain env ---
source "$HOME/.local/tcbin/rust-env.sh" 2>/dev/null || true
MUSL_BIN="$HOME/.local/musl/x86_64-linux-musl-cross/bin"
[ -d "$MUSL_BIN" ] || { echo "ERROR: musl cross toolchain missing at $MUSL_BIN" >&2; exit 1; }
export PATH="$MUSL_BIN:$PATH"
export CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc
export CXX_x86_64_unknown_linux_musl=x86_64-linux-musl-g++
export AR_x86_64_unknown_linux_musl=x86_64-linux-musl-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static"
# musl OpenSSL for native-tls (postgres TLS). Target-specific vars beat the host
# gnu OPENSSL_INCLUDE_DIR/LIB_DIR that rust-env.sh exports.
unset OPENSSL_INCLUDE_DIR OPENSSL_LIB_DIR OPENSSL_DIR OPENSSL_STATIC 2>/dev/null || true
export X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_INCLUDE_DIR="$HOME/.local/musl-openssl/include"
export X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR="$HOME/.local/musl-openssl/lib64"
export X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_STATIC=1

echo "== 1/4 cross-compile static musl binaries =="
cargo +1.88.0 build --release -p ferrogate-cli -p ferrogate-auth --target "$TARGET"
D="target/${TARGET}/release"
file "$D/ferrogate" | grep -q "static" || { echo "ERROR: ferrogate is not static" >&2; exit 1; }

echo "== 2/4 stage rootfs layer =="
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/usr/local/bin" "$STAGE/etc/ferrogate" "$STAGE/etc/ssl/certs"
install -m 0755 "$D/ferrogate" "$STAGE/usr/local/bin/ferrogate"
install -m 0755 "$D/ferrogate-auth" "$STAGE/usr/local/bin/ferrogate-auth"
"$MUSL_BIN/x86_64-linux-musl-strip" "$STAGE/usr/local/bin/ferrogate" "$STAGE/usr/local/bin/ferrogate-auth"
install -m 0644 Ferrogate/Caddyfile "$STAGE/etc/ferrogate/Caddyfile"
# CA bundle so a scratch/distroless base can still do outbound TLS.
[ -f /etc/ssl/certs/ca-certificates.crt ] && \
  install -m 0644 /etc/ssl/certs/ca-certificates.crt "$STAGE/etc/ssl/certs/ca-certificates.crt"
LAYER="$STAGE/layer.tar"
( cd "$STAGE" && tar --numeric-owner --owner=0 --group=0 --mtime='2026-07-19 00:00:00' \
    -cf "$LAYER" usr etc )

echo "== 3/4 assemble OCI image with crane =="
OUT_TARBALL="$STAGE/ferrogate-${TAG}.oci.tar"
"$CRANE" mutate "$BASE" \
  --append "$LAYER" \
  --entrypoint /usr/local/bin/ferrogate \
  --cmd run \
  --env FERROGATE_CONFIG=/etc/ferrogate/Caddyfile \
  --exposed-ports 8080 \
  --workdir / \
  -l org.opencontainers.image.vendor="Token4AI Cloud" \
  -l org.opencontainers.image.source="https://github.com/${OWNER}/ferrogate" \
  -l org.opencontainers.image.version="${TAG}" \
  -l cloud.token4ai.build="musl-static-crane-local" \
  -o "$OUT_TARBALL"
echo "   assembled: $OUT_TARBALL ($(stat -c%s "$OUT_TARBALL") bytes)"
"$CRANE" config "$OUT_TARBALL" 2>/dev/null | \
  python3 -c "import json,sys;c=json.load(sys.stdin)['config'];print('   entrypoint',c['Entrypoint'],c.get('Cmd'));print('   ports',c.get('ExposedPorts'))" 2>/dev/null || true

echo "== 4/4 push to GHCR =="
if [ "$DO_PUSH" != "true" ]; then
  KEEP="${TMPDIR:-/tmp}/ferrogate-${TAG}.oci.tar"
  cp "$OUT_TARBALL" "$KEEP"
  echo "   (dry-run: pass --push to push ${IMAGE}:${TAG}); kept $KEEP"
  exit 0
fi
TOKEN="${GHCR_TOKEN:-$(gh auth token 2>/dev/null || true)}"
[ -n "$TOKEN" ] || { echo "ERROR: no GHCR token (set GHCR_TOKEN with write:packages)" >&2; exit 1; }
echo "$TOKEN" | "$CRANE" auth login ghcr.io -u "$OWNER" --password-stdin
"$CRANE" push "$OUT_TARBALL" "${IMAGE}:${TAG}"
"$CRANE" push "$OUT_TARBALL" "${IMAGE}:latest"
DIGEST="$("$CRANE" digest "${IMAGE}:${TAG}")"
echo "   published ${IMAGE}:${TAG} @ ${DIGEST}"
