#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-18
"""Produce an offline FerroGate release-evidence bundle for the current commit.

This is the local, hermetic stand-in for what `.github/workflows/ci-image.yml`
plus `.github/actions/image-supply-chain` publish for a real release:

  * an immutable image digest (here: a deterministic digest computed from the
    exact Dockerfile build inputs of the checked-out commit, because no Docker
    daemon or registry is available offline);
  * an SPDX 2.3 SBOM derived from Cargo.lock (stand-in for syft/anchore
    sbom-action output);
  * the `https://token4ai.cloud/ferrogate/build-inputs/v1` predicate with the
    exact same field shape the composite action emits via jq;
  * a build-provenance statement bound to the subject digest and source SHA
    (stand-in for actions/attest-build-provenance);
  * a cosign-style image signature and DSSE attestation envelopes, all signed
    with an EPHEMERAL in-memory ECDSA P-256 key (real cryptography), plus a
    "dry-run certificate" that binds the signing identity + issuer to each
    signed payload (stand-in for the keyless Fulcio certificate chain).

The private key never touches disk and is discarded after signing, so the
bundle cannot be re-signed: tampering with any payload afterwards is
detectable by real signature verification.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

REPO = "lianluo-esign/ferrogate"
IMAGE_NAME = "ghcr.io/lianluo-esign/ferrogate"
DEFAULT_ISSUER = "https://token.actions.githubusercontent.com"
BUILD_INPUTS_TYPE = "https://token4ai.cloud/ferrogate/build-inputs/v1"
SPDX_PREDICATE_TYPE = "https://spdx.dev/Document"
PROVENANCE_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
DIGEST_DOMAIN = "ferrogate-release-dryrun-image/v1"


def run_git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def git_blob_sha256(root: Path, commit: str, path: str) -> str:
    blob = subprocess.run(
        ["git", "-C", str(root), "show", f"{commit}:{path}"],
        check=True,
        capture_output=True,
    ).stdout
    return hashlib.sha256(blob).hexdigest()


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


def spdx_from_cargo_lock(root: Path, commit: str, source_sha: str) -> dict:
    """Deterministic SPDX 2.3 document from the committed Cargo.lock."""
    text = subprocess.run(
        ["git", "-C", str(root), "show", f"{commit}:Cargo.lock"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    packages = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if current.get("name"):
                packages.append(current)
            current = {}
        else:
            match = re.fullmatch(r'(name|version|checksum) = "([^"]+)"', line)
            if match:
                current[match.group(1)] = match.group(2)
    if current.get("name"):
        packages.append(current)
    commit_time = run_git(
        root, "log", "-1", "--format=%cI", commit
    ).strip()
    spdx_packages = []
    for index, package in enumerate(sorted(packages, key=lambda p: (p["name"], p.get("version", "")))):
        entry = {
            "SPDXID": f"SPDXRef-Package-{index}",
            "name": package["name"],
            "versionInfo": package.get("version", "NOASSERTION"),
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
        }
        if package.get("checksum"):
            entry["checksums"] = [
                {"algorithm": "SHA256", "checksumValue": package["checksum"]}
            ]
        spdx_packages.append(entry)
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"ferrogate-image-{source_sha}",
        "documentNamespace": f"https://token4ai.cloud/ferrogate/spdx/{source_sha}",
        "creationInfo": {
            "created": commit_time,
            "creators": [
                "Tool: ferrogate-release-dryrun (offline stand-in for syft)"
            ],
        },
        "packages": spdx_packages,
    }


class Signer:
    """Ephemeral P-256 signer; the private key lives only in process memory."""

    def __init__(self, identity: str, issuer: str, unsigned: bool) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.identity = identity
        self.issuer = issuer
        self.unsigned = unsigned

    def public_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, message: bytes) -> str:
        if self.unsigned:
            return ""
        signature = self._key.sign(message, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(signature).decode()

    def certificate_for(self, payload: bytes) -> dict:
        """Dry-run stand-in for the keyless Fulcio certificate: binds the
        signing identity + issuer to the exact payload digest, and is itself
        signed by the same ephemeral key."""
        certificate = {
            "identity": self.identity,
            "issuer": self.issuer,
            "payloadSha256": hashlib.sha256(payload).hexdigest(),
        }
        return {
            "dryrunCertificate": certificate,
            "dryrunCertificateSignature": self.sign(canonical(certificate)),
        }

    def envelope(self, statement: dict) -> dict:
        payload = canonical(statement)
        payload_type = "application/vnd.in-toto+json"
        envelope = {
            "payloadType": payload_type,
            "payload": base64.b64encode(payload).decode(),
            "signatures": (
                []
                if self.unsigned
                else [{"keyid": "", "sig": self.sign(dsse_pae(payload_type, payload))}]
            ),
        }
        envelope.update(self.certificate_for(payload))
        return envelope


def statement(predicate_type: str, digest: str, predicate: dict) -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": predicate_type,
        "subject": [{"name": IMAGE_NAME, "digest": {"sha256": digest}}],
        "predicate": predicate,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="bundle output directory")
    parser.add_argument(
        "--workflow-ref",
        required=True,
        help="git ref the signing workflow would run on, e.g. refs/tags/v2026.07.18",
    )
    parser.add_argument(
        "--issuer",
        default=DEFAULT_ISSUER,
        help="OIDC issuer recorded in the dry-run certificate (override to model a rogue issuer)",
    )
    parser.add_argument(
        "--identity-repo",
        default=REPO,
        help="repository recorded in the signing identity (override to model a rogue signer)",
    )
    parser.add_argument(
        "--unsigned",
        action="store_true",
        help="emit the bundle without any signatures (negative-case input)",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    source_sha = run_git(root, "rev-parse", "HEAD").strip()
    cargo_lock_sha = git_blob_sha256(root, source_sha, "Cargo.lock")
    dockerfile_sha = git_blob_sha256(root, source_sha, "Dockerfile")

    # Deterministic stand-in for the GHCR manifest digest: bound to the exact
    # Dockerfile build inputs of this commit. A real release replaces this
    # with the digest reported by docker/build-push-action.
    digest = hashlib.sha256(
        "\0".join([DIGEST_DOMAIN, source_sha, dockerfile_sha, cargo_lock_sha]).encode()
    ).hexdigest()

    identity = (
        f"https://github.com/{args.identity_repo}"
        f"/.github/workflows/ci-image.yml@{args.workflow_ref}"
    )
    signer = Signer(identity, args.issuer, args.unsigned)

    out = Path(args.out)
    (out / "attestations").mkdir(parents=True, exist_ok=True)
    (out / "image-digest").write_text(f"sha256:{digest}\n")
    (out / "pubkey.pem").write_bytes(signer.public_pem())

    # cosign-style simple-signing image signature over the digest subject.
    signing_payload = canonical(
        {
            "critical": {
                "identity": {"docker-reference": IMAGE_NAME},
                "image": {"docker-manifest-digest": f"sha256:{digest}"},
                "type": "cosign container image signature",
            },
            "optional": None,
        }
    )
    signature_record = {
        "payload": base64.b64encode(signing_payload).decode(),
        "signature": signer.sign(signing_payload),
    }
    signature_record.update(signer.certificate_for(signing_payload))
    (out / "signature.json").write_text(json.dumps(signature_record, indent=2) + "\n")

    sbom = spdx_from_cargo_lock(root, source_sha, source_sha)
    (out / "sbom.spdx.json").write_text(json.dumps(sbom, indent=2) + "\n")
    (out / "attestations" / "spdx.dsse.json").write_text(
        json.dumps(signer.envelope(statement(SPDX_PREDICATE_TYPE, digest, sbom)), indent=2)
        + "\n"
    )

    # Exact field shape emitted by .github/actions/image-supply-chain (jq -n).
    build_inputs = {
        "repository": REPO,
        "workflow_ref": f"{REPO}/.github/workflows/ci-image.yml@{args.workflow_ref}",
        "commit_sha": source_sha,
        "image": IMAGE_NAME,
        "digest": f"sha256:{digest}",
        "cargo_lock_sha256": cargo_lock_sha,
        "dockerfile_sha256": dockerfile_sha,
    }
    (out / "attestations" / "build-inputs.dsse.json").write_text(
        json.dumps(
            signer.envelope(statement(BUILD_INPUTS_TYPE, digest, build_inputs)), indent=2
        )
        + "\n"
    )

    provenance = {
        "buildDefinition": {
            "buildType": "https://actions.github.io/buildtypes/workflow/v1",
            "externalParameters": {
                "workflow": {
                    "ref": args.workflow_ref,
                    "repository": f"https://github.com/{REPO}",
                    "path": ".github/workflows/ci-image.yml",
                }
            },
            "resolvedDependencies": [
                {
                    "uri": f"git+https://github.com/{REPO}@{args.workflow_ref}",
                    "digest": {"gitCommit": source_sha},
                }
            ],
        },
        "runDetails": {
            "builder": {
                "id": f"https://github.com/{args.identity_repo}"
                f"/.github/workflows/ci-image.yml@{args.workflow_ref}"
            }
        },
    }
    (out / "attestations" / "provenance.dsse.json").write_text(
        json.dumps(
            signer.envelope(statement(PROVENANCE_PREDICATE_TYPE, digest, provenance)),
            indent=2,
        )
        + "\n"
    )

    manifest = {
        "image": f"{IMAGE_NAME}@sha256:{digest}",
        "source_sha": source_sha,
        "workflow_ref": args.workflow_ref,
        "identity": identity,
        "issuer": args.issuer,
        "unsigned": args.unsigned,
        "digest_stand_in": DIGEST_DOMAIN,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"{IMAGE_NAME}@sha256:{digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
