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

Carving out a new crate now fails here until someone points a slice at it. The
gate checks two independent surfaces --

  1. the workflows reachable from `ci.yml`, i.e. what actually runs on a
     release, not every `.yml` in the directory (a crate named only by the
     manually-dispatched, KVM-only Firecracker workflow is not covered);
  2. `scripts/local-test-modules.sh`, so the local mirror cannot drift from CI
     silently again -- that drift is how the gap survived review.

Where it runs, and therefore how much it is worth. `ci.yml` triggers only on a
published release (`AGENTS.md:478-481` makes that project policy), and
`rust-quality.yml` is reachable from nowhere else, so on an ordinary commit the
only thing that runs this gate is a developer invoking
`scripts/local-test-modules.sh quality`. It is a release-time backstop plus a
local habit, not a per-commit check, and the first round of #561 overstated it
as "the part that stops this recurring".

WHAT IT PROVES IS SELECTION, NOT HEALTH. A slice that selects a crate and skips
half its tests passes here. It is a floor, not a ceiling.

Two things it deliberately does NOT credit, because the first round of review
found both live in this tree:

  * a `cargo test` inside a comment, in either YAML or bash. The line
    `# This still does not run `cargo test -p ferrogate-cli` unfiltered` -- a
    comment SAYING the crate was under-covered -- was what credited that crate
    as covered locally;
  * a `cargo test` inside a bash function that `run_module` never dispatches.
    Deleting `platform-crates) run_platform_crates ;;` orphaned six crates'
    only local invocation and the gate did not notice, because it modelled
    workflow reachability via `uses:` and the script's reachability not at all.
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
# `cargo test -p "${{ matrix.package }}"`: the crate name is not on this line,
# it is in the matrix, and the CAPTURED KEY says which key holds it. Binding to
# the key matters -- `rust-gateway-runtime.yml` templates its run line through
# `${{ matrix.args }}` while naming its crate literally, so treating any `${{`
# as "consult the matrix" would credit a `package:` key added to that file for
# some other purpose entirely.
TEMPLATED_PACKAGE_FLAG = re.compile(
    r"(?:-p|--package)[= ]+['\"]?\$\{\{\s*(?:matrix|inputs|env)\.([A-Za-z0-9_-]+)\s*\}\}"
)
# A reusable-workflow call: `uses: ./.github/workflows/rust-quality.yml`.
WORKFLOW_CALL = re.compile(r"uses:\s*\./(\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml)")
# A workspace member path in the root Cargo.toml's `members = [...]`.
MEMBER = re.compile(r"^\s*['\"]([^'\"]+)['\"]\s*,?\s*$")
PACKAGE_NAME = re.compile(r"^\s*name\s*=\s*['\"]([^'\"]+)['\"]", re.MULTILINE)
# `jobs:` at column zero, then each job key at whatever indent the first one
# uses. Enough YAML to tell one job from the next; no more.
JOBS_BLOCK = re.compile(r"^jobs:\s*$")
JOB_KEY = re.compile(r"^(\s+)[A-Za-z0-9_.-]+:\s*$")
# `run_platform_crates() {` ... a matching `}` at column zero. This repo writes
# every bash function that way; a definition indented or brace-styled otherwise
# is not recognized as a function and its body stays top-level, which credits
# more rather than less.
SHELL_FUNCTION = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{\s*$")
SHELL_FUNCTION_END = re.compile(r"^\}\s*$")


def matrix_key(key: str) -> re.Pattern[str]:
    """`- package: ferrogate-admin` for the key a run line interpolated."""
    return re.compile(
        rf"^\s*-?\s*{re.escape(key)}:\s*['\"]?([A-Za-z0-9_-]+)['\"]?\s*$"
    )


def strip_comment(line: str) -> str:
    """Drop a trailing `#` comment. One rule serves both YAML and bash.

    In each language a `#` opens a comment when it begins a line or follows
    whitespace, and never inside a quoted string. That shared rule is all this
    gate needs, and it is the difference between reading a script and matching
    bytes in one: at `60cdc14` a COMMENT explaining that `ferrogate-cli` was
    under-covered locally was the thing crediting `ferrogate-cli` as covered
    locally, so the real invocations could all have been deleted in silence.
    """
    quote = ""
    for index, character in enumerate(line):
        if quote:
            if character == quote:
                quote = ""
            continue
        if character in "'\"":
            quote = character
            continue
        if character == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def strip_comments(text: str) -> str:
    return "\n".join(strip_comment(line) for line in text.splitlines())


def workspace_members(root: pathlib.Path) -> dict[str, str]:
    """Map every workspace member's package name to its manifest directory."""
    manifest = (root / "Cargo.toml").read_text(encoding="utf-8")
    inside = False
    directories: list[str] = []
    for raw in manifest.splitlines():
        line = strip_comment(raw)
        stripped = line.strip()
        if not inside:
            if stripped.startswith("members"):
                inside = True
            continue
        if stripped.startswith("]"):
            break
        if not stripped:
            continue
        match = MEMBER.match(line)
        if match is None:
            # A member this parser cannot read used to be dropped in silence,
            # which is the gate's own failure mode one level up: a new crate
            # written `"crates/foo", # experimental` would exempt itself while
            # the gate reported success over the members it did understand.
            raise SystemExit(
                f"{root / 'Cargo.toml'}: cannot read a workspace member from "
                f"{raw.strip()!r}. A member this gate cannot parse is a crate "
                "that exempts itself from it, so this is an error rather than "
                "a skip."
            )
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


def selected_in_region(text: str) -> set[str]:
    """Crates a `cargo test` in one region selects, resolving matrix keys.

    A region is one workflow job, or one bash script -- never a whole file with
    several jobs in it, because matrix credit must not leak between them.

    Only `cargo test` lines count. `cargo build -p ferrogate-cli` in the e2e
    harness proves the crate compiles, which is exactly the thing #561 was
    already getting for free and exactly the thing that was not enough.

    `text` must already have had its comments stripped.
    """
    selected: set[str] = set()
    keys: set[str] = set()
    for line in text.splitlines():
        if "cargo test" not in line:
            continue
        for name in PACKAGE_FLAG.findall(line):
            selected.add(name)
        keys.update(TEMPLATED_PACKAGE_FLAG.findall(line))
    for key in keys:
        pattern = matrix_key(key)
        for line in text.splitlines():
            match = pattern.match(line)
            if match is not None:
                selected.add(match.group(1))
    return selected


def workflow_job_regions(text: str) -> list[str]:
    """Split a workflow into one region per job, plus everything around them.

    Matrix credit is scoped to the job that interpolated the key. Without this,
    `rust-gateway-runtime.yml` -- whose run line reads
    `cargo test -p ferrogate-cli ${{ matrix.args }}` -- would hand a `package:`
    key belonging to some unrelated `clippy` or `build` job in the same file a
    testedness it never earned.
    """
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if JOBS_BLOCK.match(line):
            start = index + 1
            break
    if start is None:
        return [text]

    outside = lines[:start]
    jobs: list[list[str]] = []
    indent: str | None = None
    for line in lines[start:]:
        if line.strip() and not line[0].isspace():
            # Back to column zero: the `jobs:` mapping has ended.
            outside.append(line)
            indent = None
            jobs.append([])
            continue
        match = JOB_KEY.match(line)
        if match is not None and (indent is None or match.group(1) == indent):
            indent = match.group(1)
            jobs.append([])
        if jobs:
            jobs[-1].append(line)
        else:
            outside.append(line)
    return ["\n".join(outside)] + ["\n".join(job) for job in jobs]


def selected_by_workflow(text: str) -> set[str]:
    selected: set[str] = set()
    for region in workflow_job_regions(strip_comments(text)):
        selected |= selected_in_region(region)
    return selected


def shell_reachable_text(text: str, label: str) -> str:
    """The part of a bash script that running it can actually reach.

    A `cargo test` inside a function nothing dispatches runs for nobody. Delete
    `platform-crates) run_platform_crates ;;` from `run_module` and the six
    crates in that function -- `ferrogate-gateway` among them -- have no local
    invocation left, which is #561 exactly. The gate followed `uses:` through
    the workflows and read the script as a flat pile of lines.

    Functions are recognized only in this repo's style (`name() {` on its own
    line, closing `}` at column zero). Anything else stays top-level, so an
    unrecognized definition over-credits rather than failing the script's
    author for a formatting choice.
    """
    bodies: dict[str, list[str]] = {}
    toplevel: list[str] = []
    current: str | None = None
    for line in text.splitlines():
        if current is None:
            match = SHELL_FUNCTION.match(line)
            if match is not None:
                current = match.group(1)
                bodies.setdefault(current, [])
                continue
            toplevel.append(line)
            continue
        if SHELL_FUNCTION_END.match(line):
            current = None
            continue
        bodies[current].append(line)

    if not bodies:
        return text

    def calls(region: list[str]) -> set[str]:
        body = "\n".join(region)
        return {
            name
            for name in bodies
            if re.search(rf"(?<![A-Za-z0-9_-]){re.escape(name)}(?![A-Za-z0-9_-])", body)
        }

    reachable: set[str] = set()
    pending = sorted(calls(toplevel))
    while pending:
        name = pending.pop()
        if name in reachable:
            continue
        reachable.add(name)
        pending.extend(sorted(calls(bodies[name]) - reachable))

    if not reachable:
        raise SystemExit(
            f"{label}: it defines {len(bodies)} functions and top-level code "
            "calls none of them, so this gate can see no invocation at all. "
            "Either the script stopped dispatching or this reachability model "
            "has broken; both must be looked at, neither may pass quietly."
        )
    return "\n".join(toplevel + [line for name in sorted(reachable) for line in bodies[name]])


def selected_by_local_runner(text: str, label: str) -> set[str]:
    return selected_in_region(shell_reachable_text(strip_comments(text), label))


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
        in_ci |= selected_by_workflow(workflow.read_text(encoding="utf-8"))

    runner = root / arguments.local_runner
    in_local = selected_by_local_runner(
        runner.read_text(encoding="utf-8"), arguments.local_runner
    )

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
