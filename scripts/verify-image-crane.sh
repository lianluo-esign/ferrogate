#!/usr/bin/env bash
# Consumer-side verification for the no-daemon musl+crane release artifact (#208).
#
# Verifies an OCI image tarball against a LOCAL-KEY cosign signature — offline, no
# transparency log, no registry. This is the verifier for the local release path
# (scripts/build-image-crane.sh --sign local-key). It pins to the public key you
# were given out-of-band and, optionally, to an expected artifact digest.
#
# NOTE ON PROVENANCE: this checks "signed by the holder of THIS key + not tampered".
# It is NOT the GitHub-workflow keyless provenance that
# scripts/verify-image-supply-chain.sh --mode release enforces. Use that one for
# CI-published images; use this one for locally-built images.
#
# USAGE:
#   scripts/verify-image-crane.sh \
#     --tarball ferrogate-v2026.07.19.oci.tar \
#     --signature ferrogate-v2026.07.19.oci.tar.sig \
#     --pubkey cosign.pub \
#     [--digest sha256:<expected sha256 of the tarball>] \
#     [--sbom sbom-v2026.07.19.src.spdx.json]
set -euo pipefail

TARBALL="" SIG="" PUBKEY="" EXPECT_DIGEST="" SBOM=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tarball) TARBALL="$2"; shift 2;;
    --signature) SIG="$2"; shift 2;;
    --pubkey) PUBKEY="$2"; shift 2;;
    --digest) EXPECT_DIGEST="$2"; shift 2;;
    --sbom) SBOM="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
for req in TARBALL SIG PUBKEY; do
  eval "v=\$$req"; [ -n "$v" ] || { echo "ERROR: --${req,,} required" >&2; exit 2; }
done
command -v cosign >/dev/null || { echo "ERROR: cosign required" >&2; exit 1; }

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "== 1/3 artifact digest =="
GOT="sha256:$(sha256sum "$TARBALL" | cut -d' ' -f1)"
echo "   $TARBALL = $GOT"
if [ -n "$EXPECT_DIGEST" ]; then
  [ "$GOT" = "$EXPECT_DIGEST" ] || fail "digest mismatch (expected $EXPECT_DIGEST)"
  echo "   digest matches pin."
fi

echo "== 2/3 signature (local key, offline) =="
cosign verify-blob --key "$PUBKEY" --signature "$SIG" \
  --insecure-ignore-tlog=true "$TARBALL" >/dev/null 2>&1 \
  || fail "signature does not verify against $PUBKEY (tampered, wrong key, or unsigned)"
echo "   signature verifies against $PUBKEY."

echo "== 3/3 SBOM association (optional) =="
if [ -n "$SBOM" ]; then
  [ -f "$SBOM" ] || fail "SBOM $SBOM not found"
  python3 - "$SBOM" <<'PY' || fail "SBOM is not valid SPDX-json"
import json,sys
d=json.load(open(sys.argv[1]))
assert str(d.get("spdxVersion","")).startswith("SPDX-"), "not SPDX"
print(f"   SBOM ok: {d['spdxVersion']}, {len(d.get('packages',[]))} packages")
PY
else
  echo "   (no --sbom given: skipped)"
fi

echo "OK: artifact verified."
