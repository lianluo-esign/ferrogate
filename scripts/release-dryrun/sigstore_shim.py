#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-18
"""Offline stand-in for the `cosign` and `gh attestation` CLIs.

Shimmed boundary (clearly marked): registry/Rekor/Fulcio network lookups are
replaced by reading the local bundle in $FERROGATE_DRYRUN_BUNDLE, and the
keyless Fulcio certificate is replaced by the bundle's signed
"dry-run certificate" (identity + issuer bound to the payload digest).

NOT shimmed — verified for real, exactly as cosign/gh would:
  * ECDSA P-256 / SHA-256 signature verification of every payload against the
    bundle public key (image signature, DSSE PAE for every attestation, and
    the certificate binding itself);
  * subject digest matching (the requested image digest must equal the digest
    inside the signed payload / in-toto subject);
  * --certificate-identity / --certificate-oidc-issuer matching against the
    cryptographically bound signing identity.

Any failure exits non-zero, so the real verifier
(scripts/verify-image-supply-chain.sh) observes the same pass/fail semantics
it would against a real release.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

COSIGN_TYPE_ALIASES = {"spdxjson": "https://spdx.dev/Document"}
PROVENANCE_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"


def fail(message: str) -> None:
    print(f"release-dryrun shim: verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    return b" ".join(
        [
            b"DSSEv1",
            str(len(payload_type)).encode(),
            payload_type.encode(),
            str(len(payload)).encode(),
            payload,
        ]
    )


def bundle_dir() -> Path:
    value = os.environ.get("FERROGATE_DRYRUN_BUNDLE", "")
    if not value:
        fail("FERROGATE_DRYRUN_BUNDLE is not set")
    path = Path(value)
    if not path.is_dir():
        fail(f"bundle directory {path} does not exist")
    return path


def load_pubkey(bundle: Path):
    try:
        return serialization.load_pem_public_key((bundle / "pubkey.pem").read_bytes())
    except (OSError, ValueError) as error:
        fail(f"cannot load bundle public key: {error}")


def verify_raw(pubkey, signature_b64: str, message: bytes, what: str) -> None:
    if not signature_b64:
        fail(f"{what} is unsigned")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        pubkey.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except (ValueError, InvalidSignature):
        fail(f"{what} signature does not verify")


def verify_certificate(pubkey, record: dict, payload: bytes, identity: str, issuer: str, what: str) -> None:
    certificate = record.get("dryrunCertificate")
    if not isinstance(certificate, dict):
        fail(f"{what} has no signing certificate")
    verify_raw(
        pubkey,
        record.get("dryrunCertificateSignature", ""),
        canonical(certificate),
        f"{what} certificate",
    )
    if certificate.get("payloadSha256") != hashlib.sha256(payload).hexdigest():
        fail(f"{what} certificate is not bound to this payload")
    if certificate.get("identity") != identity:
        fail(
            f"{what} certificate identity {certificate.get('identity')!r} "
            f"does not match requested identity {identity!r}"
        )
    if certificate.get("issuer") != issuer:
        fail(
            f"{what} certificate issuer {certificate.get('issuer')!r} "
            f"does not match requested issuer {issuer!r}"
        )


def parse_image(image: str) -> tuple[str, str]:
    if "@sha256:" not in image:
        fail(f"image reference {image!r} is not digest-pinned")
    name, _, digest = image.partition("@sha256:")
    return name, digest


def load_envelope(bundle: Path, filename: str) -> dict:
    path = bundle / "attestations" / filename
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as error:
        fail(f"cannot load attestation {path.name}: {error}")


def verify_envelope(pubkey, envelope: dict, identity: str, issuer: str, image: str, what: str) -> dict:
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
    except (KeyError, ValueError) as error:
        fail(f"{what} envelope payload is invalid: {error}")
    payload_type = envelope.get("payloadType", "")
    signatures = envelope.get("signatures") or []
    if not signatures or not signatures[0].get("sig"):
        fail(f"{what} attestation is unsigned")
    verify_raw(pubkey, signatures[0]["sig"], dsse_pae(payload_type, payload), what)
    verify_certificate(pubkey, envelope, payload, identity, issuer, what)
    try:
        statement = json.loads(payload)
    except ValueError as error:
        fail(f"{what} payload is not JSON: {error}")
    name, digest = parse_image(image)
    subjects = statement.get("subject", [])
    if not any(
        isinstance(subject, dict)
        and subject.get("name") == name
        and subject.get("digest", {}).get("sha256") == digest
        for subject in subjects
    ):
        fail(f"{what} subject does not match image digest sha256:{digest}")
    return statement


def take_flag(args: list[str], flag: str) -> str:
    if flag not in args:
        fail(f"required flag {flag} missing")
    index = args.index(flag)
    if index + 1 >= len(args):
        fail(f"flag {flag} has no value")
    value = args[index + 1]
    del args[index : index + 2]
    return value


def cosign_main(args: list[str]) -> None:
    if not args:
        fail("cosign shim invoked without a subcommand")
    subcommand = args.pop(0)
    bundle = bundle_dir()
    pubkey = load_pubkey(bundle)
    identity = take_flag(args, "--certificate-identity")
    issuer = take_flag(args, "--certificate-oidc-issuer")

    if subcommand == "verify":
        image = args[-1] if args else fail("no image reference given")
        _, digest = parse_image(image)
        try:
            record = json.loads((bundle / "signature.json").read_text())
            payload = base64.b64decode(record["payload"], validate=True)
        except (OSError, KeyError, ValueError) as error:
            fail(f"cannot load image signature: {error}")
        verify_raw(pubkey, record.get("signature", ""), payload, "image")
        verify_certificate(pubkey, record, payload, identity, issuer, "image")
        try:
            signed_digest = json.loads(payload)["critical"]["image"]["docker-manifest-digest"]
        except (KeyError, ValueError) as error:
            fail(f"image signing payload is malformed: {error}")
        if signed_digest != f"sha256:{digest}":
            fail(
                f"no signature exists for sha256:{digest}; "
                f"signed digest is {signed_digest}"
            )
        print(f"release-dryrun shim: verified image signature for {image}")
        return

    if subcommand == "verify-attestation":
        predicate_type = take_flag(args, "--type")
        predicate_type = COSIGN_TYPE_ALIASES.get(predicate_type, predicate_type)
        image = args[-1] if args else fail("no image reference given")
        filenames = {
            "https://spdx.dev/Document": "spdx.dsse.json",
            "https://token4ai.cloud/ferrogate/build-inputs/v1": "build-inputs.dsse.json",
            PROVENANCE_PREDICATE_TYPE: "provenance.dsse.json",
        }
        filename = filenames.get(predicate_type)
        if filename is None:
            fail(f"no attestation of type {predicate_type} in the bundle")
        envelope = load_envelope(bundle, filename)
        statement = verify_envelope(
            pubkey, envelope, identity, issuer, image, predicate_type
        )
        if statement.get("predicateType") != predicate_type:
            fail(
                f"attestation predicateType {statement.get('predicateType')!r} "
                f"does not match requested {predicate_type!r}"
            )
        # Match real cosign output: one JSON envelope per line on stdout.
        print(
            json.dumps(
                {
                    "payloadType": envelope.get("payloadType"),
                    "payload": envelope.get("payload"),
                    "signatures": envelope.get("signatures"),
                }
            )
        )
        return

    fail(f"cosign shim does not support subcommand {subcommand!r}")


def gh_main(args: list[str]) -> None:
    if len(args) < 3 or args[0] != "attestation" or args[1] != "verify":
        fail(f"gh shim only supports 'attestation verify', got {args!r}")
    args = args[2:]
    subject = args.pop(0)
    if not subject.startswith("oci://"):
        fail(f"gh attestation subject must be oci://..., got {subject!r}")
    image = subject[len("oci://") :]
    repo = take_flag(args, "--repo")
    identity = take_flag(args, "--cert-identity")
    issuer = take_flag(args, "--cert-oidc-issuer")
    source_digest = take_flag(args, "--source-digest")

    bundle = bundle_dir()
    pubkey = load_pubkey(bundle)
    envelope = load_envelope(bundle, "provenance.dsse.json")
    statement = verify_envelope(
        pubkey, envelope, identity, issuer, image, "provenance"
    )
    if statement.get("predicateType") != PROVENANCE_PREDICATE_TYPE:
        fail("provenance attestation has the wrong predicateType")
    predicate = statement.get("predicate", {})
    build_definition = predicate.get("buildDefinition", {})
    workflow = build_definition.get("externalParameters", {}).get("workflow", {})
    if workflow.get("repository") != f"https://github.com/{repo}":
        fail("provenance workflow repository does not match --repo")
    dependencies = build_definition.get("resolvedDependencies", [])
    if not any(
        isinstance(dependency, dict)
        and dependency.get("digest", {}).get("gitCommit") == source_digest
        for dependency in dependencies
    ):
        fail("provenance source commit does not match --source-digest")
    print(f"release-dryrun shim: verified build provenance for {image}")


def main() -> None:
    if len(sys.argv) < 2:
        fail("usage: sigstore_shim.py <cosign|gh> [args...]")
    tool, args = sys.argv[1], sys.argv[2:]
    if tool == "cosign":
        cosign_main(args)
    elif tool == "gh":
        gh_main(args)
    else:
        fail(f"unknown shimmed tool {tool!r}")


if __name__ == "__main__":
    main()
