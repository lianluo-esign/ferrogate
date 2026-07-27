#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-27
# description: Fail when a workspace member's tests are executed by no CI slice
# and no local module (issue #561).
"""Reject workspace members that no `cargo test` invocation ever selects.

Issue #561: `ferrogate-gateway` -- 136k lines, 1,069 tests, the largest crate in
the workspace -- was compiled by CI and executed by no job, for as long as it
had existed. Nothing noticed, because nothing was looking. `ferrogate-secrets`,
`ferrogate-payments` and `ferrogate-cloudflare` were in the same state, and
`scripts/local-test-modules.sh` had drifted away from the workflow matrices on
top of that, so a contributor could not reproduce CI even where CI was right.

This gate is the part that stops it recurring: carving out a new crate now fails
here until someone points a slice at it. It checks two independent surfaces --

  1. the workflows reachable from `ci.yml`, i.e. what actually runs on a
     release, not every `.yml` in the directory (a crate named only by the
     manually-dispatched, KVM-only Firecracker workflow is not covered);
  2. `scripts/local-test-modules.sh`, so the local mirror cannot drift from CI
     silently again -- that drift is how the gap survived review.

It proves selection, not health: a slice that selects a crate and skips half its
tests still passes here. It is a floor, not a ceiling.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]

# `cargo test ... -p name` / `-p "name"`. `--package` is spelled `-p` everywhere
# in this repo; both are accepted so a future rewrite does not slip past.
PACKAGE_FLAG = re.compile(r"(?:-p|--package)[= ]+['\"]?([A-Za-z0-9_-]+)['\"]?")
# A matrix key: `- package: ferrogate-admin`.
MATRIX_PACKAGE = re.compile(r"^\s*-?\s*package:\s*['\"]?([A-Za-z0-9_-]+)['\"]?\s*$")
# A reusable-workflow call: `uses: ./.github/workflows/rust-quality.yml`.
WORKFLOW_CALL = re.compile(r"uses:\s*\./(\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml)")
# A workspace member path in the root Cargo.toml's `members = [...]`.
MEMBER = re.compile(r"^\s*['\"]([^'\"]+)['\"]\s*,?\s*$")
PACKAGE_NAME = re.compile(r"^\s*name\s*=\s*['\"]([^'\"]+)['\"]", re.MULTILINE)


def workspace_members(root: pathlib.Path) -> dict[str, str]:
    """Map every workspace member's package name to its manifest directory."""
    manifest = (root / "Cargo.toml").read_text(encoding="utf-8")
    inside = False
    directories: list[str] = []
    for line in manifest.splitlines():
        stripped = line.strip()
        if stripped.startswith("members"):
            inside = True
            continue
        if inside:
            if stripped.startswith("]"):
                break
            match = MEMBER.match(line)
            if match is not None:
                directories.append(match.group(1))
    if not directories:
        raise SystemExit("could not parse [workspace] members from Cargo.toml")

    packages: dict[str, str] = {}
    for directory in directories:
        member_manifest = root / directory / "Cargo.toml"
        name = PACKAGE_NAME.search(member_manifest.read_text(encoding="utf-8"))
        if name is None:
            raise SystemExit(f"{member_manifest}: no [package] name")
        packages[name.group(1)] = directory
    return packages


def reachable_workflows(root: pathlib.Path, entry: str) -> list[pathlib.Path]:
    """The entry workflow plus every reusable workflow it transitively calls."""
    pending = [entry]
    seen: list[str] = []
    while pending:
        relative = pending.pop()
        if relative in seen:
            continue
        path = root / relative
        if not path.exists():
            continue
        seen.append(relative)
        for called in WORKFLOW_CALL.findall(path.read_text(encoding="utf-8")):
            pending.append(called)
    return [root / relative for relative in sorted(seen)]


def selected_by_cargo_test(text: str) -> set[str]:
    """Crates a `cargo test` in `text` selects, resolving matrix indirection.

    Only `cargo test` lines count. `cargo build -p ferrogate-cli` in the e2e
    harness proves the crate compiles, which is exactly the thing #561 was
    already getting for free and exactly the thing that was not enough.
    """
    selected: set[str] = set()
    templated = False
    for line in text.splitlines():
        if "cargo test" not in line:
            continue
        for name in PACKAGE_FLAG.findall(line):
            selected.add(name)
        # `cargo test -p "${{ matrix.package }}"` -- the crate names live in the
        # matrix, so credit that file's `package:` keys.
        if "${{" in line:
            templated = True
    if templated:
        for line in text.splitlines():
            match = MATRIX_PACKAGE.match(line)
            if match is not None:
                selected.add(match.group(1))
    return selected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    parser.add_argument("--entry-workflow", default=".github/workflows/ci.yml")
    parser.add_argument("--local-runner", default="scripts/local-test-modules.sh")
    arguments = parser.parse_args(argv)
    root: pathlib.Path = arguments.root

    packages = workspace_members(root)

    workflows = reachable_workflows(root, arguments.entry_workflow)
    if not workflows:
        print(
            f"no workflow reachable from {arguments.entry_workflow}; the gate would "
            "pass vacuously",
            file=sys.stderr,
        )
        return 1
    in_ci: set[str] = set()
    for workflow in workflows:
        in_ci |= selected_by_cargo_test(workflow.read_text(encoding="utf-8"))

    runner = root / arguments.local_runner
    in_local = selected_by_cargo_test(runner.read_text(encoding="utf-8"))

    missing_ci = sorted(name for name in packages if name not in in_ci)
    missing_local = sorted(name for name in packages if name not in in_local)

    if missing_ci or missing_local:
        print("workspace members whose tests nothing executes:", file=sys.stderr)
        for name in missing_ci:
            print(
                f"  {name} ({packages[name]}): no `cargo test -p {name}` in any "
                f"workflow reachable from {arguments.entry_workflow}",
                file=sys.stderr,
            )
        for name in missing_local:
            print(
                f"  {name} ({packages[name]}): no `cargo test -p {name}` in "
                f"{arguments.local_runner}",
                file=sys.stderr,
            )
        print(
            "\nAdd a slice that runs the crate's tests, in both CI and the local "
            "runner. If the crate genuinely cannot be tested on a hosted runner, "
            "say so in a slice comment and select it with the filters that can "
            "run -- an absent slice is indistinguishable from an oversight, "
            "which is what issue #561 was.",
            file=sys.stderr,
        )
        return 1

    print(
        f"validated {len(packages)} workspace members against "
        f"{len(workflows)} CI workflows and {arguments.local_runner}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
