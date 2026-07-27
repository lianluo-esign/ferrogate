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
#     1. Cross-compile FULLY STATIC musl binaries on the host (no glibc-version
#        coupling to any base image — runs on scratch/distroless/anything).
#     2. Assemble the OCI image with `crane` (google/go-containerregistry) — a
#        static Go binary that talks to the registry directly. No daemon, no
#        namespaces, no privileges.
#
# TOOLCHAINS (userspace, no sudo — set up once; see docs/release/local-image-build.md)
#   Primary — zig cc (host-arch independent; the dev host is aarch64 since 2026-07-18):
#     - zig static tarball:        $HOME/.local/zig/zig          (or env ZIG=<path>)
#     - wrappers:                  scripts/zig-cc-{x86_64,aarch64}-musl.sh (+ zig-ar/ranlib)
#     - musl OpenSSL (static):     $HOME/.local/musl-openssl-zig/{x86_64,aarch64}
#     - rustup targets:            {x86_64,aarch64}-unknown-linux-musl for 1.88.0
#   Legacy fallback — musl.cc prebuilt gcc (x86_64 hosts only, amd64 target only):
#     - $HOME/.local/musl/x86_64-linux-musl-cross + $HOME/.local/musl-openssl
#   - crane binary: $HOME/.local/bin/crane (or ./crane / on PATH)
#
# PUSH CREDENTIALS
#   GHCR push needs a token with `write:packages`. The default `gh` login here has
#   only repo/workflow/project scopes, so provide ONE of:
#     - env GHCR_TOKEN=<PAT with write:packages>
#     - `gh auth refresh -s write:packages` then re-run (token then covers it)
#   Username defaults to the repo owner.
#
# USAGE
#   scripts/build-image-crane.sh --tag v2026.07.20 [--arch amd64|arm64|both] \
#       [--owner lianluo-esign] [--push]
#   (no --push => assemble to local OCI tarball(s) ferrogate-<tag>-<arch>.oci.tar
#    and print the config; never touches GHCR)
#   --arch both + --push: pushes <tag>-amd64 / <tag>-arm64 then assembles the
#   multi-arch index for <tag> and latest via `crane index append`.
set -euo pipefail

OWNER="lianluo-esign"
TAG=""
ARCHES="amd64"                 # amd64 | arm64 | both (amd64 = prior single-arch releases)
DO_PUSH="false"
BASE="gcr.io/distroless/static-debian12:latest"
DO_SBOM="true"                 # syft SPDX (source dep graph + image)
SIGN="none"                    # none | local-key
COSIGN_KEY="${COSIGN_KEY:-}"   # for --sign local-key
ARTIFACT_DIR="${ARTIFACT_DIR:-${TMPDIR:-/tmp}}"

while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG="$2"; shift 2;;
    --arch) ARCHES="$2"; shift 2;;
    --owner) OWNER="$2"; shift 2;;
    --base) BASE="$2"; shift 2;;
    --push) DO_PUSH="true"; shift;;
    --sbom) DO_SBOM="true"; shift;;
    --no-sbom) DO_SBOM="false"; shift;;
    --sign) SIGN="$2"; shift 2;;
    --cosign-key) COSIGN_KEY="$2"; shift 2;;
    --artifact-dir) ARTIFACT_DIR="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$TAG" ] || { echo "ERROR: --tag <vYYYY.MM.DD> required" >&2; exit 2; }
case "$ARCHES" in
  amd64|arm64) ARCH_LIST="$ARCHES";;
  both) ARCH_LIST="amd64 arm64";;
  *) echo "ERROR: --arch must be amd64|arm64|both" >&2; exit 2;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
IMAGE="ghcr.io/${OWNER}/ferrogate"
ZIG="${ZIG:-$HOME/.local/zig/zig}"

# Reproducible layer mtime: derive from a vYYYY.MM.DD tag, else epoch.
if [[ "$TAG" =~ ^v([0-9]{4})\.([0-9]{2})\.([0-9]{2})$ ]]; then
  LAYER_MTIME="${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]} 00:00:00"
else
  LAYER_MTIME="1970-01-01 00:00:00"
fi

# --- resolve crane ---
CRANE="$(command -v crane || true)"
[ -z "$CRANE" ] && [ -x "$HOME/.local/bin/crane" ] && CRANE="$HOME/.local/bin/crane"
[ -z "$CRANE" ] && [ -x "$ROOT/crane" ] && CRANE="$ROOT/crane"
[ -n "$CRANE" ] || { echo "ERROR: crane not found (get github.com/google/go-containerregistry)" >&2; exit 1; }

source "$HOME/.local/tcbin/rust-env.sh" 2>/dev/null || true
# Host-gnu OPENSSL vars (rust-env.sh) must not leak into the cross builds; the
# target-specific vars set below win for openssl-sys.
unset OPENSSL_INCLUDE_DIR OPENSSL_LIB_DIR OPENSSL_DIR OPENSSL_STATIC 2>/dev/null || true

# readelf-based static verification (the dev host has no `file`):
# fully static = correct machine + no PT_INTERP + no dynamic section.
verify_static() { # <binary> <expected readelf machine substring>
  local bin="$1" mach="$2"
  readelf -h "$bin" | grep -q "Machine:.*${mach}" \
    || { echo "ERROR: $bin is not ${mach}" >&2; return 1; }
  if readelf -l "$bin" | grep -q INTERP; then
    echo "ERROR: $bin requests an interpreter (dynamically linked)" >&2; return 1
  fi
  if readelf -d "$bin" 2>/dev/null | grep -q NEEDED; then
    echo "ERROR: $bin has NEEDED shared libs" >&2; return 1
  fi
  echo "   static ok: $bin ($(readelf -h "$bin" | sed -n 's/.*Machine:[[:space:]]*//p'))"
}

# Per-arch toolchain env + cargo build, run in a subshell so arch envs don't mix.
build_arch() { # <amd64|arm64>
  local arch="$1"
  case "$arch" in
    amd64) local rust_target=x86_64-unknown-linux-musl  zig_wrap="$ROOT/scripts/zig-cc-x86_64-musl.sh"  ossl="$HOME/.local/musl-openssl-zig/x86_64" mach="X86-64";;
    arm64) local rust_target=aarch64-unknown-linux-musl zig_wrap="$ROOT/scripts/zig-cc-aarch64-musl.sh" ossl="$HOME/.local/musl-openssl-zig/aarch64" mach="AArch64";;
  esac
  local tvar; tvar="$(echo "$rust_target" | tr 'a-z-' 'A-Z_')"

  if [ -x "$ZIG" ] && [ -d "$ossl" ]; then
    echo "   toolchain: zig cc ($("$ZIG" version)) -> $rust_target"
    local ossl_lib="$ossl/lib64"; [ -d "$ossl_lib" ] || ossl_lib="$ossl/lib"
    export "CC_${rust_target//-/_}=$zig_wrap"
    export "CXX_${rust_target//-/_}=$zig_wrap"
    export "AR_${rust_target//-/_}=$ROOT/scripts/zig-ar.sh"
    export "RANLIB_${rust_target//-/_}=$ROOT/scripts/zig-ranlib.sh"
    export "CARGO_TARGET_${tvar}_LINKER=$zig_wrap"
    # link-self-contained=no: zig supplies CRT + musl libc; rustc's bundled CRT
    # objects would collide (duplicate _start). strip=symbols replaces the
    # external musl-strip of the legacy path.
    export "CARGO_TARGET_${tvar}_RUSTFLAGS=-C target-feature=+crt-static -C link-self-contained=no -C strip=symbols"
    export "${tvar}_OPENSSL_INCLUDE_DIR=$ossl/include"
    export "${tvar}_OPENSSL_LIB_DIR=$ossl_lib"
    export "${tvar}_OPENSSL_STATIC=1"
  elif [ "$arch" = "amd64" ] && [ -d "$HOME/.local/musl/x86_64-linux-musl-cross/bin" ]; then
    echo "   toolchain: legacy musl.cc gcc (x86_64 host fallback)"
    local MUSL_BIN="$HOME/.local/musl/x86_64-linux-musl-cross/bin"
    export PATH="$MUSL_BIN:$PATH"
    export CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc
    export CXX_x86_64_unknown_linux_musl=x86_64-linux-musl-g++
    export AR_x86_64_unknown_linux_musl=x86_64-linux-musl-ar
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C strip=symbols"
    export X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_INCLUDE_DIR="$HOME/.local/musl-openssl/include"
    export X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR="$HOME/.local/musl-openssl/lib64"
    export X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_STATIC=1
  else
    echo "ERROR: no toolchain for $arch. Install zig ($ZIG) + static OpenSSL ($ossl)" >&2
    echo "       (see docs/release/local-image-build.md, 'One-time userspace toolchain setup')" >&2
    return 1
  fi

  rustup +1.88.0 target list --installed | grep -q "^${rust_target}$" \
    || rustup +1.88.0 target add "$rust_target"
  cargo +1.88.0 build --release -p ferrogate-cli -p ferrogate-auth-service --target "$rust_target"
  local D="target/${rust_target}/release"
  verify_static "$D/ferrogate" "$mach"
  verify_static "$D/ferrogate-auth" "$mach"
  # Native-arch smoke: prove the binary actually runs (cross arch: readelf only).
  case "$(uname -m):$arch" in
    x86_64:amd64|aarch64:arm64) echo "   smoke: $("$D/ferrogate" --version)";;
  esac
}

stage_and_assemble() { # <amd64|arm64> -> writes $STAGE/ferrogate-<tag>-<arch>.oci.tar
  local arch="$1"
  local rust_target; case "$arch" in
    amd64) rust_target=x86_64-unknown-linux-musl;;
    arm64) rust_target=aarch64-unknown-linux-musl;;
  esac
  local D="target/${rust_target}/release"
  local S="$STAGE/$arch"
  mkdir -p "$S/usr/local/bin" "$S/etc/ferrogate" "$S/etc/ssl/certs"
  install -m 0755 "$D/ferrogate" "$S/usr/local/bin/ferrogate"
  install -m 0755 "$D/ferrogate-auth" "$S/usr/local/bin/ferrogate-auth"
  install -m 0644 Ferrogate/Caddyfile "$S/etc/ferrogate/Caddyfile"
  # CA bundle so a scratch/distroless base can still do outbound TLS.
  [ -f /etc/ssl/certs/ca-certificates.crt ] && \
    install -m 0644 /etc/ssl/certs/ca-certificates.crt "$S/etc/ssl/certs/ca-certificates.crt"
  local LAYER="$S/layer.tar"
  ( cd "$S" && tar --numeric-owner --owner=0 --group=0 --mtime="$LAYER_MTIME" \
      -cf "$LAYER" usr etc )

  local OUT="$STAGE/ferrogate-${TAG}-${arch}.oci.tar"
  "$CRANE" mutate "$BASE" \
    --platform "linux/${arch}" \
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
    -o "$OUT"
  echo "   assembled: $OUT ($(stat -c%s "$OUT") bytes)"
  # (`crane config` only reads registry refs, not tarballs — read the embedded config.)
  tar xOf "$OUT" "$(tar xOf "$OUT" manifest.json | python3 -c "import json,sys;print(json.load(sys.stdin)[0]['Config'])")" | \
    python3 -c "import json,sys;j=json.load(sys.stdin);c=j['config'];print('   platform',j.get('os','?')+'/'+j.get('architecture','?'));print('   entrypoint',c['Entrypoint'],c.get('Cmd'));print('   ports',c.get('ExposedPorts'))" 2>/dev/null || true
}

echo "== 1/4 cross-compile static musl binaries (${ARCH_LIST}) =="
for A in $ARCH_LIST; do
  echo "-- arch: $A"
  ( build_arch "$A" )
done

echo "== 2/4 stage rootfs + 3/4 assemble OCI image(s) with crane =="
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
for A in $ARCH_LIST; do
  echo "-- arch: $A"
  stage_and_assemble "$A"
done

echo "== 3.5/4 SBOM + sign (evidence, #208) =="
mkdir -p "$ARTIFACT_DIR"
SBOM_SRC="$ARTIFACT_DIR/sbom-${TAG}.src.spdx.json"
if [ "$DO_SBOM" = "true" ] && command -v syft >/dev/null; then
  # source graph = the real supply-chain inventory for a static Rust binary;
  # image scan = base + embedded binary (per arch).
  syft scan "dir:$ROOT" -o spdx-json 2>/dev/null > "$SBOM_SRC" \
    && echo "   SBOM(src): $SBOM_SRC ($(python3 -c "import json;print(len(json.load(open('$SBOM_SRC'))['packages']))" 2>/dev/null) pkgs)"
  for A in $ARCH_LIST; do
    SBOM_IMG="$ARTIFACT_DIR/sbom-${TAG}-${A}.image.spdx.json"
    syft scan "docker-archive:$STAGE/ferrogate-${TAG}-${A}.oci.tar" -o spdx-json 2>/dev/null > "$SBOM_IMG" \
      && echo "   SBOM(img,$A): $SBOM_IMG"
  done
else
  echo "   (SBOM skipped: --no-sbom or syft absent)"
fi
if [ "$SIGN" = "local-key" ]; then
  command -v cosign >/dev/null || { echo "ERROR: --sign local-key needs cosign" >&2; exit 1; }
  [ -f "$COSIGN_KEY" ] || { echo "ERROR: --sign local-key needs --cosign-key <key> (COSIGN_PASSWORD env for its passphrase)" >&2; exit 1; }
  for A in $ARCH_LIST; do
    SIG="$ARTIFACT_DIR/ferrogate-${TAG}-${A}.oci.tar.sig"
    # Offline detached signature over the exact OCI artifact; verify with
    # scripts/verify-image-crane.sh. NOT GitHub-workflow keyless provenance (see docs).
    cosign sign-blob --key "$COSIGN_KEY" --yes "$STAGE/ferrogate-${TAG}-${A}.oci.tar" \
      --output-signature "$SIG" --tlog-upload=false 2>/dev/null \
      && echo "   signed(local-key,$A): $SIG"
  done
fi

echo "== 4/4 push to GHCR =="
if [ "$DO_PUSH" != "true" ]; then
  for A in $ARCH_LIST; do
    KEEP="$ARTIFACT_DIR/ferrogate-${TAG}-${A}.oci.tar"
    cp "$STAGE/ferrogate-${TAG}-${A}.oci.tar" "$KEEP"
    echo "   kept $KEEP"
  done
  echo "   (dry-run: pass --push to push ${IMAGE}:${TAG})"
  exit 0
fi
TOKEN="${GHCR_TOKEN:-$(gh auth token 2>/dev/null || true)}"
[ -n "$TOKEN" ] || { echo "ERROR: no GHCR token (set GHCR_TOKEN with write:packages)" >&2; exit 1; }
echo "$TOKEN" | "$CRANE" auth login ghcr.io -u "$OWNER" --password-stdin
if [ "$ARCHES" = "both" ]; then
  # Per-arch tags first, then a multi-arch index for <tag> and latest.
  for A in $ARCH_LIST; do
    "$CRANE" push "$STAGE/ferrogate-${TAG}-${A}.oci.tar" "${IMAGE}:${TAG}-${A}"
  done
  "$CRANE" index append -t "${IMAGE}:${TAG}" \
    -m "${IMAGE}:${TAG}-amd64" -m "${IMAGE}:${TAG}-arm64"
  "$CRANE" index append -t "${IMAGE}:latest" \
    -m "${IMAGE}:${TAG}-amd64" -m "${IMAGE}:${TAG}-arm64"
else
  "$CRANE" push "$STAGE/ferrogate-${TAG}-${ARCHES}.oci.tar" "${IMAGE}:${TAG}"
  "$CRANE" push "$STAGE/ferrogate-${TAG}-${ARCHES}.oci.tar" "${IMAGE}:latest"
fi
DIGEST="$("$CRANE" digest "${IMAGE}:${TAG}")"
echo "   published ${IMAGE}:${TAG} @ ${DIGEST}"
