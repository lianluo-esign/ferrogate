#!/usr/bin/env python3
"""Validate the signed FerroGate build-input predicate emitted by cosign."""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys


PREDICATE_TYPE = "https://token4ai.cloud/ferrogate/build-inputs/v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--source-digest", required=True)
    parser.add_argument("--cargo-lock-digest", required=True)
    parser.add_argument("--dockerfile-digest", required=True)
    return parser.parse_args()


def fail(message: str) -> None:
    print(f"build-input attestation verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    args = parse_args()
    image_name, digest = args.image.rsplit("@sha256:", 1)
    envelopes = [line for line in sys.stdin.read().splitlines() if line.strip()]
    for raw in envelopes:
        try:
            envelope = json.loads(raw)
            statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
        except (KeyError, ValueError, json.JSONDecodeError) as error:
            fail(f"invalid cosign envelope: {error}")
        if statement.get("predicateType") != PREDICATE_TYPE:
            continue
        subjects = statement.get("subject", [])
        if not any(
            subject.get("name") == image_name
            and subject.get("digest", {}).get("sha256") == digest
            for subject in subjects
            if isinstance(subject, dict)
        ):
            fail("predicate subject does not match the requested image digest")
        predicate = statement.get("predicate")
        if not isinstance(predicate, dict):
            fail("predicate is not an object")
        expected = {
            "repository": "lianluo-esign/ferrogate",
            "workflow_ref": args.workflow_ref,
            "image": image_name,
            "digest": f"sha256:{digest}",
        }
        for key, value in expected.items():
            if predicate.get(key) != value:
                fail(f"predicate {key} does not match expected value")
        if not re.fullmatch(r"[0-9a-f]{40}", str(predicate.get("commit_sha", ""))):
            fail("predicate commit_sha is not a full Git commit SHA")
        if predicate.get("commit_sha") != args.source_digest:
            fail("predicate commit_sha does not match --source-digest")
        expected_source_files = {
            "cargo_lock_sha256": args.cargo_lock_digest,
            "dockerfile_sha256": args.dockerfile_digest,
        }
        for key, expected_digest in expected_source_files.items():
            if not re.fullmatch(r"[0-9a-f]{64}", str(predicate.get(key, ""))):
                fail(f"predicate {key} is not a SHA-256 digest")
            if predicate.get(key) != expected_digest:
                fail(f"predicate {key} does not match the verified source commit")
        print("verified signed FerroGate build-input predicate contents")
        return
    fail(f"no {PREDICATE_TYPE} predicate found")


if __name__ == "__main__":
    main()
