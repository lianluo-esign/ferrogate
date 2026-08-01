#!/usr/bin/env bash
# Mutation sweep for @ferrogate/sso.
#
# For each row: back up the file, apply the mutation, GREP THE FILE BACK OFF
# DISK to confirm the edit landed (a mutation that never landed looks exactly
# like a vacuous test), run `bun run test`, require RED in the named test,
# restore, and verify the checksum. A final GREEN run closes the sweep.
#
# Substitution is done with python3 and literal strings passed through the
# environment — perl's s{}{} chokes on the braces that every one of these
# mutations contains.
set -uo pipefail
cd "$(dirname "$0")"

PASS=0
FAIL=0
NOTES=()

apply() {
  MUT_FILE="$1" MUT_FROM="$2" MUT_TO="$3" python3 - <<'PY'
import os, sys
path, frm, to = os.environ["MUT_FILE"], os.environ["MUT_FROM"], os.environ["MUT_TO"]
src = open(path).read()
if src.count(frm) != 1:
    sys.stderr.write(f"anchor appears {src.count(frm)} times, expected exactly 1\n")
    sys.exit(2)
open(path, "w").write(src.replace(frm, to))
PY
}

mutate() {
  local id="$1" file="$2" from="$3" to="$4" confirm="$5" expect="$6"
  cp "$file" /tmp/sso-seam.bak
  sha256sum "$file" > /tmp/sso-seam.sha
  if ! apply "$file" "$from" "$to"; then
    echo "[$id] ANCHOR NOT UNIQUE/ABSENT — sweep row is stale"
    cp /tmp/sso-seam.bak "$file"
    FAIL=$((FAIL + 1))
    return
  fi
  # CONFIRM off disk. Not optional.
  if ! grep -qF -- "$confirm" "$file"; then
    echo "[$id] MUTATION DID NOT LAND (confirm grep found nothing)"
    cp /tmp/sso-seam.bak "$file"
    FAIL=$((FAIL + 1))
    return
  fi
  local out
  out="$(bun run test 2>&1)"
  if echo "$out" | grep -qF -- "FAIL" && echo "$out" | grep -qF -- "$expect"; then
    echo "[$id] RED as required -> $expect"
    PASS=$((PASS + 1))
  else
    echo "[$id] *** STILL GREEN — no assertion holds this seam ***"
    echo "$out" | tail -5
    FAIL=$((FAIL + 1))
    NOTES+=("$id")
  fi
  cp /tmp/sso-seam.bak "$file"
  sha256sum -c /tmp/sso-seam.sha >/dev/null || { echo "[$id] RESTORE FAILED"; exit 1; }
}

FALSE='if (false as boolean) {'

# ---------------------------------------------------------------- signature --
# M1: verify over a RE-SERIALISED query instead of the raw octets — the classic
#     signature bypass. Must make a signature the IdP never made over the wire
#     form ACCEPTABLE.
mutate M1 src/redirect-binding.ts \
'    let signed = `SAMLResponse=${this.samlResponseRaw}`;
    if (this.relayStateRaw !== null) {
      signed += `&RelayState=${this.relayStateRaw}`;
    }
    signed += `&SigAlg=${this.sigAlgRaw}`;' \
'    let signed = `SAMLResponse=${encodeURIComponent(urldecode(this.samlResponseRaw))}`;
    if (this.relayStateRaw !== null) {
      signed += `&RelayState=${encodeURIComponent(urldecode(this.relayStateRaw))}`;
    }
    signed += `&SigAlg=${encodeURIComponent(urldecode(this.sigAlgRaw))}`;' \
'encodeURIComponent(urldecode(this.samlResponseRaw))' \
'a signature valid over a RE-SERIALISED form but not the raw octets is refused'

# M2: never refuse, whatever WebCrypto says.
mutate M2 src/redirect-binding.ts '  if (!verified) {' "  $FALSE" "$FALSE" \
'a tampered RelayState is refused'

# M3: the ACS stops verifying the signature at all.
mutate M3 src/flow.ts \
'    await verifyRedirectSignature(params, certificate);' \
'    void certificate;' \
'void certificate;' \
"an assertion signed by an UNKNOWN issuer's key is refused with 401"

# ------------------------------------------------------------------- replay --
# M4: `take` stops consuming — the ONLY replay defence.
mutate M4 src/memory-store.ts '        flows.delete(state);' '        void state;' 'void state;' \
'a REPLAYED assertion is refused'

# ------------------------------------------------------ assertion validation --
mutate M5 src/response.ts '  if (parsed.statusCode !== STATUS_SUCCESS) {' "  $FALSE" "$FALSE" \
'a non-Success status is refused'

mutate M6 src/response.ts \
'  if (expectedInResponseTo !== null && parsed.responseInResponseTo !== expectedInResponseTo) {' \
"  $FALSE" "$FALSE" \
'an InResponseTo that does not match the pending AuthnRequest is refused'

mutate M7 src/response.ts '  if (expectedIssuer !== null && parsed.issuer !== expectedIssuer) {' \
"  $FALSE" "$FALSE" 'an UNKNOWN ISSUER is refused'

mutate M8 src/response.ts '  if (!parsed.audiences.includes(expectations.spEntityId)) {' \
"  $FALSE" "$FALSE" 'a wrong audience (this SP is not the intended recipient) is refused'

mutate M9 src/response.ts '    if (expectations.nowUnix - expectations.clockSkewSecs >= notOnOrAfter) {' \
"    $FALSE" "$FALSE" 'an EXPIRED assertion is refused'

mutate M10 src/response.ts '    if (expectations.nowUnix + expectations.clockSkewSecs < notBefore) {' \
"    $FALSE" "$FALSE" 'a NOT-YET-VALID assertion is refused'

mutate M11 src/response.ts '  if (email === null || !isValidEmail(email)) {' \
"  $FALSE" "$FALSE" 'an assertion with no usable email is refused'

# ------------------------------------------------------- decoding / parsing --
mutate M12 src/deflate.ts '  if (inflated.byteLength > limit) {' "  $FALSE" "$FALSE" \
'a DECOMPRESSION BOMB is refused without hanging or reaching the XML scanner'

mutate M13 src/response.ts '  if (samlResponseB64.length > MAX_SAML_RESPONSE_B64_CHARS) {' \
"  $FALSE" "$FALSE" 'an OVERSIZED encoded payload is refused before it is even decoded'

mutate M14 src/xml.ts \
'    if (text.startsWith("<!DOCTYPE", index) || text.startsWith("<!doctype", index)) {' \
"    $FALSE" "$FALSE" 'a DOCTYPE is refused outright'

mutate M15 src/xml.ts \
'          throw new XmlError(`unknown entity reference &${entity};`);' \
'          out += `&${entity};`;' \
'out += `&${entity};`;' \
'an unknown entity reference is refused rather than passed through'

mutate M16 src/xml.ts \
'      if (open !== name) fail(`end tag </${name}> does not close <${open}>`);' \
'      void open;' \
'void open;' \
'MIS-NESTED elements are refused even when the tag counts balance'

# ------------------------------------------------------------------- X.509 ---
mutate M17 src/x509.ts '  if (oid !== OID_RSA_ENCRYPTION) {' "  $FALSE" "$FALSE" \
'a NON-RSA (EC) certificate is refused rather than mis-imported'

mutate M18 src/x509.ts '  if (bitString.content.length === 0) {' "  $FALSE" "$FALSE" \
'a certificate whose public-key BIT STRING is empty is refused'

mutate M19 src/der.ts '  if (first === 0x80) {' "  $FALSE" "$FALSE" \
'an indefinite-length (BER, not DER) encoding is refused'

# ----------------------------------------------------------------- instants --
mutate M20 src/instant.ts '  if (!trimmed.endsWith("Z")) {' "  $FALSE" "$FALSE" \
'a NON-UTC instant is refused rather than assumed local'

# --------------------------------------------------------- config admission --
mutate M21 src/config.ts '    parseIdpPublicKey(idpCertificate);' '    void idpCertificate;' \
'void idpCertificate;' 'an UNPARSEABLE certificate is refused AT CONFIG TIME'

mutate M22 src/config.ts \
'  if (
    idpSsoUrl.length === 0 ||' \
'  if (
    (false as boolean) ||' \
'(false as boolean) ||' 'a missing idpSsoUrl is refused'

# ------------------------------------------------------------ flow refusals --
mutate M23 src/flow.ts \
'  if (stored.providerKind !== "saml") {
    throw samlFlowError(
      "not_saml_tenant",' \
"  $FALSE
    throw samlFlowError(
      \"not_saml_tenant\"," \
"$FALSE" 'an OIDC tenant is refused at the SAML authorize endpoint'

mutate M24 src/flow.ts \
'  if (flow.providerKind !== "saml") {' "  $FALSE" "$FALSE" \
'a pending flow belonging to the OIDC flow kind is refused'

mutate M25 src/flow.ts \
'  if (!certificate) {' "  $FALSE" "$FALSE" \
'a config with no certificate refuses rather than skipping verification'

echo
echo "=================================================="
echo "mutations RED (seam proven): $PASS"
echo "mutations STILL GREEN / not landed: $FAIL ${NOTES[*]:-}"
echo "=================================================="
echo "final restore check (must be GREEN):"
bun run test 2>&1 | tail -5
