#!/usr/bin/env bash
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-30
# description: Package the `ferrogate` CLI as a released artifact with checksums,
# SBOM and signature evidence (issue #365).
#
# SCOPE — this script PACKAGES; it does not own cross-toolchain setup.
#   Cross-compiling the musl triples needs the zig cc + static musl OpenSSL
#   environment documented at the top of scripts/build-image-crane.sh. That
#   setup lives there and is deliberately not duplicated here: two copies of it
#   would drift. Either export that environment before running this script, or
#   pass --binary-dir with binaries an earlier build already produced.
#
# The target policy is NOT defined here either. scripts/cli-release-targets.json
# is generated from crates/ferrogate-cli/src/release.rs and drift-checked by
# `cargo test -p ferrogate-cli release`, so this script cannot package a triple
# the policy does not declare.
#
# USAGE:
#   scripts/package-cli.sh --version vYYYY.MM.DD [--out DIR] [--target TRIPLE]...
#                          [--binary-dir DIR] [--sign local-key|none] [--sbom] [--check]
#
#   --check        resolve and print the plan, then exit; builds nothing.
#   --target       package this triple instead of the default `released` set.
#                  May be repeated. Must be declared in the manifest.
#   --binary-dir   take the binary from DIR/<triple>/<binary> instead of
#                  invoking cargo.
#   --sign         local-key uses cosign with $COSIGN_KEY (default cosign.key).
#                  See the SIGNING TRADE-OFF note in scripts/release-local.sh:
#                  a local signature is NOT the GitHub-workflow provenance the
#                  release-mode verifier pins to.
#   --sbom         emit a CycloneDX SBOM per archive with syft.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/scripts/cli-release-targets.json"
TOOLCHAIN="${FERROGATE_CLI_TOOLCHAIN:-1.88.0}"

VERSION=""
OUT="$ROOT/dist/cli"
BINARY_DIR=""
SIGN="none"
WANT_SBOM="false"
CHECK_ONLY="false"
REQUESTED_TARGETS=()

die() { echo "ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version)     VERSION="${2:-}"; shift 2;;
    --out)         OUT="${2:-}"; shift 2;;
    --target)      REQUESTED_TARGETS+=("${2:-}"); shift 2;;
    --binary-dir)  BINARY_DIR="${2:-}"; shift 2;;
    --sign)        SIGN="${2:-}"; shift 2;;
    --sbom)        WANT_SBOM="true"; shift;;
    --check)       CHECK_ONLY="true"; shift;;
    -h|--help)     sed -n '2,34p' "${BASH_SOURCE[0]}"; exit 0;;
    *)             die "unknown arg: $1";;
  esac
done

[ -n "$VERSION" ] || die "--version <vYYYY.MM.DD> required"
[[ "$VERSION" =~ ^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}$ ]] \
  || die "version must match vYYYY.MM.DD (got '$VERSION')"
[ -f "$MANIFEST" ] || die "missing $MANIFEST — regenerate with \
FERROGATE_REGENERATE_DOCS=1 cargo test -p ferrogate-cli release"
case "$SIGN" in local-key|none) ;; *) die "--sign must be local-key or none";; esac
command -v python3 >/dev/null || die "python3 is required to read $MANIFEST"

# Resolve the plan from the manifest. Emits one `triple<TAB>archive<TAB>binary`
# row per target to package. Filtering happens here, in one place, so --check
# and the real run can never disagree about what would be built.
plan() {
  python3 - "$MANIFEST" "${REQUESTED_TARGETS[@]+"${REQUESTED_TARGETS[@]}"}" <<'PY'
import json
import sys

manifest_path, requested = sys.argv[1], sys.argv[2:]
with open(manifest_path, encoding="utf-8") as handle:
    manifest = json.load(handle)

targets = {entry["triple"]: entry for entry in manifest["targets"]}

if requested:
    unknown = [triple for triple in requested if triple not in targets]
    if unknown:
        print(
            "undeclared target(s): %s\ndeclared: %s"
            % (", ".join(unknown), ", ".join(sorted(targets))),
            file=sys.stderr,
        )
        raise SystemExit(1)
    selected = [targets[triple] for triple in requested]
else:
    selected = [e for e in manifest["targets"] if e["tier"] == "released"]
    if not selected:
        print("manifest declares no `released` target", file=sys.stderr)
        raise SystemExit(1)

for entry in selected:
    print("\t".join((entry["triple"], entry["archive"], entry["binary"])))
PY
}

PLAN="$(plan)" || die "could not resolve a packaging plan from $MANIFEST"

echo "== ferrogate CLI packaging =="
echo "   version:   $VERSION"
echo "   manifest:  ${MANIFEST#"$ROOT/"}"
echo "   out:       $OUT"
echo "   source:    ${BINARY_DIR:-cargo +$TOOLCHAIN build --release --locked}"
echo "   sign:      $SIGN   sbom: $WANT_SBOM"
echo "   targets:"
while IFS=$'\t' read -r triple archive binary; do
  echo "     - $triple ($archive, $binary)"
done <<< "$PLAN"

if [ "$CHECK_ONLY" = "true" ]; then
  echo "== check only: nothing built =="
  exit 0
fi

if [ "$SIGN" = "local-key" ]; then
  command -v cosign >/dev/null || die "--sign local-key needs cosign on PATH"
  [ -f "${COSIGN_KEY:-cosign.key}" ] || die "--sign local-key needs \$COSIGN_KEY (default cosign.key)"
fi
[ "$WANT_SBOM" = "false" ] || command -v syft >/dev/null || die "--sbom needs syft on PATH"
[ -n "$BINARY_DIR" ] || command -v cargo >/dev/null || die "cargo is required unless --binary-dir is given"

mkdir -p "$OUT"

# Locate the binary for a triple: either an already-built one under
# --binary-dir, or a fresh `cargo build --target` (which needs the caller's
# cross environment for a non-host triple).
#
# The built path is read from cargo's own JSON artifact message rather than
# assembled from `target/<triple>/release/`: `build.target-dir` in any
# .cargo/config.toml (or CARGO_TARGET_DIR) relocates that directory, and this
# repository is routinely built on hosts that set it. Asking cargo is the only
# answer that survives that.
resolve_binary() {
  local triple="$1" binary="$2"
  if [ -n "$BINARY_DIR" ]; then
    local candidate="$BINARY_DIR/$triple/$binary"
    [ -f "$candidate" ] || die "no binary at $candidate"
    printf '%s' "$candidate"
    return
  fi

  local messages="$OUT/.cargo-build-$triple.json"
  cargo "+$TOOLCHAIN" build --release --locked \
    -p ferrogate-cli --bin ferrogate --target "$triple" \
    --message-format=json-render-diagnostics > "$messages" \
    || die "cargo build failed for $triple. For a musl triple, export the zig cc + \
static musl OpenSSL environment documented in scripts/build-image-crane.sh, or pass --binary-dir."

  local built
  built="$(python3 - "$messages" <<'PY'
import json
import sys

executable = ""
with open(sys.argv[1], encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target") or {}
        if target.get("name") == "ferrogate" and "bin" in (target.get("kind") or []):
            executable = message.get("executable") or executable
print(executable)
PY
  )"
  rm -f "$messages"
  [ -n "$built" ] && [ -f "$built" ] \
    || die "cargo reported success but emitted no ferrogate binary for $triple"
  printf '%s' "$built"
}

ARCHIVES=()
while IFS=$'\t' read -r triple archive binary; do
  echo "== packaging $triple =="
  source_binary="$(resolve_binary "$triple" "$binary")"

  stage_name="ferrogate-$VERSION-$triple"
  stage="$OUT/$stage_name"
  rm -rf "$stage"
  mkdir -p "$stage"
  install -m 0755 "$source_binary" "$stage/$binary"
  install -m 0644 "$ROOT/LICENSE" "$stage/LICENSE"
  install -m 0644 "$ROOT/README.md" "$stage/README.md"
  install -m 0644 "$ROOT/docs/cli-compatibility.md" "$stage/COMPATIBILITY.md"

  case "$archive" in
    tar.gz)
      artifact="$OUT/$stage_name.tar.gz"
      # Deterministic: fixed owner/mode metadata and sorted entries, so two
      # builds of the same binary produce the same archive bytes.
      tar --sort=name --owner=0 --group=0 --numeric-owner \
          --mtime="UTC 2020-01-01" \
          -czf "$artifact" -C "$OUT" "$stage_name"
      ;;
    zip)
      command -v zip >/dev/null || die "packaging $triple needs zip on PATH"
      artifact="$OUT/$stage_name.zip"
      rm -f "$artifact"
      ( cd "$OUT" && zip -qrX "$(basename "$artifact")" "$stage_name" )
      ;;
    *) die "unsupported archive format '$archive' for $triple";;
  esac
  rm -rf "$stage"
  ARCHIVES+=("$(basename "$artifact")")
  echo "   -> ${artifact#"$ROOT/"}"

  if [ "$WANT_SBOM" = "true" ]; then
    syft "file:$artifact" -o cyclonedx-json > "$artifact.sbom.json"
    echo "   -> ${artifact#"$ROOT/"}.sbom.json"
  fi
  if [ "$SIGN" = "local-key" ]; then
    COSIGN_PASSWORD="${COSIGN_PASSWORD:-}" cosign sign-blob --yes \
      --key "${COSIGN_KEY:-cosign.key}" \
      --output-signature "$artifact.sig" "$artifact" >/dev/null
    echo "   -> ${artifact#"$ROOT/"}.sig"
  fi
done <<< "$PLAN"

# One checksum file over every archive, sorted, so `sha256sum -c` in the
# release directory verifies the whole set in one command.
( cd "$OUT" && printf '%s\n' "${ARCHIVES[@]}" | sort | xargs sha256sum > SHA256SUMS )
echo "== SHA256SUMS =="
cat "$OUT/SHA256SUMS"
echo "== done: ${OUT#"$ROOT/"} =="
