#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-25
# description: Reject tracked source files that git classifies as binary (issue #487).
"""Fail when a tracked source file is one git treats as binary.

A single NUL byte inside a file makes git -- and therefore `git grep`, GNU
`grep` and ripgrep without `-a` -- classify it as binary. The damage is not a
broken build, it is a *silent* one:

* Every repo-wide sweep quietly skips the file. The secret scan in
  `scripts/security-check.sh`, i18n literal audits, `?? 0` honesty sweeps,
  dead-code greps and "does anything read this field?" investigations all
  return fewer hits and still look clean.
* No diff of the file is reviewable -- `git show --stat` renders
  `Bin N -> M bytes`, so neither a human nor an agent ever sees the change.

A loud failure is strictly better than a coverage hole nobody notices, so this
gate makes the classification an error. See issue #487 (found while reviewing
#344).

Mechanism -- git's own notion of binary, not a guess at encodings:

    tracked source files   := git ls-files -- <SOURCE_GLOBS>   (regular files)
    text to git            := git grep -I -l -e '' -- <SOURCE_GLOBS>
    offenders              := tracked - text - allowlist - .gitattributes-binary

`git grep -I` applies exactly the rule git applies everywhere else (including
any `binary` / `-text` attribute declared in `.gitattributes`), so the gate
cannot drift from git's behaviour.

Genuinely-binary tracked files (images, fixtures, test corpora) are excluded
two ways: the scan is scoped to source-ish extensions in the first place, and
`REVIEWED_BINARY_FILES` carries an explicit, owned, reasoned allowlist for the
rest -- mirroring the `REVIEWED_EXCLUSIONS` discipline of the CLI parity gate
(`crates/ferrogate-control-plane-client/src/parity.rs`). Like that gate, an allowlist entry
that no longer applies is itself a failure, so the table cannot rot into a
silent permanent exemption.

    python3 scripts/check-binary-source-files.py
    python3 scripts/check-binary-source-files.py --root /path/to/checkout
"""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys
from typing import NamedTuple


ROOT = pathlib.Path(__file__).resolve().parents[1]

# Source-ish pathspecs. Everything here is expected to be plain text; anything
# NOT listed (`.png`, `.pdf`, binary fixtures, ...) is outside the gate, which
# is the first and cheapest way genuinely-binary files stay green. Add an
# extension here only when files with it are meant to be greppable.
SOURCE_GLOBS = (
    "*.rs",
    "*.ts",
    "*.tsx",
    "*.js",
    "*.jsx",
    "*.mjs",
    "*.cjs",
    "*.json",
    "*.jsonc",
    "*.py",
    "*.sh",
    "*.bash",
    "*.md",
    "*.toml",
    "*.yaml",
    "*.yml",
    "*.sql",
    "*.html",
    "*.css",
    "*.scss",
    "*.svg",
    "*.txt",
    "*.csv",
    "*.conf",
    "*.tpl",
    "*.proto",
    "*.graphql",
    "*.header",
    "*.pem",
    "*.lock",
    "*.gitignore",
    "*.dockerignore",
    "Dockerfile*",
    "*/Dockerfile*",
    "Makefile",
    "*.mk",
)

# Blob modes `git ls-files -s` reports for regular files. Symlinks (120000) and
# gitlinks (160000) have no working-tree content for `git grep` to scan, so
# including them would manufacture false failures.
REGULAR_FILE_MODES = frozenset({"100644", "100755"})


class ReviewedBinaryFile(NamedTuple):
    """One tracked source file that is knowingly binary to git.

    An entry is a reviewed, owned decision -- never a way to make a new failure
    go away quietly. `owner` says who is accountable for closing or keeping it
    and `reason` says why the coverage hole is tolerable, both in the same
    spirit as `ReviewedExclusion` in the CLI parity gate.
    """

    path: str
    owner: str
    reason: str


# Empty on purpose. The gate's only entry -- `admin-console/src/pages/assets.tsx`,
# frozen here when #487 landed so the gate could ship without hijacking a file
# #344 owned -- was removed by #344 when it replaced the NUL-byte composite map
# key with a JSON-encoded one. The stale-entry check below is what forced that
# removal, and is what keeps this table from rotting into a permanent exemption.
REVIEWED_BINARY_FILES: tuple[ReviewedBinaryFile, ...] = ()


def git(root: pathlib.Path, *args: str, tolerate_no_match: bool = False) -> bytes:
    """Run git in `root` and return raw stdout (paths may not be UTF-8)."""
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        check=False,
    )
    if result.returncode == 0:
        return result.stdout
    # `git grep` exits 1 with no output when nothing matched -- not an error.
    if tolerate_no_match and result.returncode == 1 and not result.stdout:
        return b""
    message = result.stderr.decode("utf-8", "replace").strip()
    raise SystemExit(f"git {' '.join(args)} failed: {message or result.returncode}")


def tracked_source_files(root: pathlib.Path) -> list[str]:
    """Tracked regular files matching SOURCE_GLOBS, as repo-relative paths."""
    raw = git(root, "ls-files", "-s", "-z", "--", *SOURCE_GLOBS)
    paths: list[str] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        # `<mode> <object> <stage>\t<path>`
        meta, _, path = record.partition(b"\t")
        if not path:
            continue
        if meta.split(b" ", 1)[0].decode("ascii", "replace") not in REGULAR_FILE_MODES:
            continue
        paths.append(path.decode("utf-8", "surrogateescape"))
    return paths


def text_to_git(root: pathlib.Path) -> set[str]:
    """Tracked source files `git grep` is willing to treat as text.

    `-e ''` matches every line, `-I` drops files git considers binary, `-l`
    lists names. A file with zero bytes has no lines to match and so is absent
    from this set; callers must not read that as "binary".
    """
    raw = git(
        root,
        "grep",
        "-z",
        "-I",
        "-l",
        "-e",
        "",
        "--",
        *SOURCE_GLOBS,
        tolerate_no_match=True,
    )
    return {
        path.decode("utf-8", "surrogateescape")
        for path in raw.split(b"\0")
        if path
    }


def declared_binary(root: pathlib.Path, paths: list[str]) -> set[str]:
    """Paths whose `.gitattributes` deliberately declare them non-text.

    `binary` set (a macro for `-diff -merge -text`) or `text` unset means the
    repository has already made the call; the gate defers to it rather than
    second-guessing a deliberate declaration.
    """
    if not paths:
        return set()
    raw = git(root, "check-attr", "-z", "binary", "text", "--", *paths)
    fields = raw.split(b"\0")
    declared: set[str] = set()
    # `check-attr -z` emits a flat <path>\0<attr>\0<value>\0 stream.
    for index in range(0, len(fields) - 2, 3):
        path = fields[index].decode("utf-8", "surrogateescape")
        attribute = fields[index + 1].decode("ascii", "replace")
        value = fields[index + 2].decode("ascii", "replace")
        if (attribute == "binary" and value == "set") or (
            attribute == "text" and value == "unset"
        ):
            declared.add(path)
    return declared


def describe(root: pathlib.Path, relative: str) -> str:
    """Point at the first NUL byte so the offender is fixable, not just named."""
    path = root / relative
    try:
        data = path.read_bytes()
    except OSError as error:  # pragma: no cover - unreadable working-tree file
        return f"unreadable ({error})"
    index = data.find(b"\0")
    if index < 0:
        return (
            "git classifies it as binary but it holds no NUL byte; check its "
            "encoding (UTF-16?) or an attribute in .gitattributes"
        )
    line = data[:index].count(b"\n") + 1
    total = data.count(b"\0")
    plural = "" if total == 1 else "s"
    return (
        f"{total} NUL byte{plural}, first at byte {index} (line {line}); "
        "git and every grep treat this file as binary and silently skip it"
    )


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reject binary-to-git source files.")
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=ROOT,
        help="repository root to scan (default: this repository)",
    )
    parser.add_argument(
        "--no-allowlist",
        action="store_true",
        help="ignore REVIEWED_BINARY_FILES (used by the gate's own tests)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()

    allowlist: dict[str, ReviewedBinaryFile] = (
        {} if args.no_allowlist else {entry.path: entry for entry in REVIEWED_BINARY_FILES}
    )

    tracked = tracked_source_files(root)
    text = text_to_git(root)

    binary: list[str] = []
    for relative in tracked:
        if relative in text:
            continue
        path = root / relative
        # A zero-byte file has no line for `git grep -e ''` to match, and a
        # path staged but deleted from the working tree has no content at all.
        # Neither is binary.
        try:
            if not path.is_file() or path.stat().st_size == 0:
                continue
        except OSError:
            continue
        binary.append(relative)

    deliberate = declared_binary(root, binary)

    failures: list[str] = []
    notes: list[str] = []
    for relative in binary:
        if relative in deliberate:
            notes.append(f"{relative}: declared binary in .gitattributes; skipped")
            continue
        entry = allowlist.get(relative)
        if entry is not None:
            notes.append(
                f"{relative}: KNOWN binary source file, allowlisted "
                f"(owner: {entry.owner}) -- {entry.reason}"
            )
            continue
        failures.append(f"{relative}: {describe(root, relative)}")

    # A reviewed entry whose file is now text (or gone) is stale. Leaving it in
    # place would silently re-permit a future NUL byte in that path, so -- like
    # the CLI parity gate's stale-exclusion check -- it fails.
    offenders = set(binary)
    for entry in allowlist.values():
        if entry.path not in offenders:
            failures.append(
                f"{entry.path}: stale REVIEWED_BINARY_FILES entry -- this file is "
                "no longer binary to git (or no longer tracked). Delete the entry "
                "so the path is gated again."
            )

    for note in notes:
        print(f"note: {note}")
    sys.stdout.flush()

    if failures:
        print(
            "Tracked source files must be text to git; a NUL byte silently "
            "removes a file from every repo-wide grep (issue #487):",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(
            "  fix the file (escape the NUL, e.g. \\u0000 / \\0 in a string "
            "literal), or add a reviewed entry to REVIEWED_BINARY_FILES in "
            "scripts/check-binary-source-files.py with an owner and a reason.",
            file=sys.stderr,
        )
        return 1

    print(f"validated {len(tracked)} tracked source files are text to git")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
