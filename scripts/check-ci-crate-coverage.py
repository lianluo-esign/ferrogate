#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-27
# description: Fail when a workspace member's tests are executed by no CI slice
# and no local module (issue #561), and when a `cargo test` name filter selects
# no test at all (issue #553).
"""Reject `cargo test` invocations that execute nothing.

Two ways an invocation runs nothing, and this gate refuses both.

**No slice names the crate (#561).** `ferrogate-gateway` -- 136,681 lines, 1,070
test attributes, the largest crate in the workspace -- was compiled by CI and
executed by no job, for as long as it had existed. Nothing noticed, because
nothing was looking. `ferrogate-secrets`, `ferrogate-payments` and
`ferrogate-cloudflare` were in the same state, and `scripts/local-test-modules.sh`
had drifted away from the workflow matrices on top of that, so a contributor
could not reproduce CI even where CI was right.

**A slice names the crate, and its name filter matches nothing (#553).** This is
the failure the first check cannot see, and it is the one #553 shipped.
`governed-decision-conformance.yml` ran

    cargo test -p ferrogate-cli --bin ferrogate governed_decision

after #553 stage 3b moved `governed_decision_conformance_test.rs` into
`ferrogate-gateway`. `ferrogate-cli` *is* named by that line, so the crate-level
check above is satisfied and stays satisfied; libtest exits 0 when a filter
matches no test, so Runner A of the #470 conformance suite -- the corpus-vs-
authority gate `ci.yml` describes as failing CI on divergence -- passed having
run zero tests, and `rust-ci` kept listing it in `needs:`. Two more filters in
`rust-quality.yml` were in the same state for the same reason: `config::tests`
and `config::validation_tests` against `ferrogate-cli`, whose `config` module
had moved to `ferrogate-config` in stage 3a. Three instances of one mistake, all
introduced by file moves, none visible to anything.

So every literal `cargo test` invocation's positional name filters are resolved
against the test paths its `-p` crates actually contain, and a filter that
matches none of them is an error. A test path here means a `#[test]` function's
full `module::path::fn_name` and nothing else: a filter naming a MODULE resolves
through the tests beneath it (`config::tests` through
`config::tests::rejects_an_unknown_key`), because libtest matches substrings and
a module with tests under it is a prefix of each of their paths. Module paths
are deliberately not candidates in their own right -- admitting them let a
filter resolve against a module whose only test file had been moved away, which
is this gate's own failure mode surviving this gate. See `crate_test_paths`.

Resolution is CRATE-wide, not target-wide, and this matters for the line that
shipped the defect. `-p ferrogate-cli --bin ferrogate governed_decision` is
accepted by this gate as soon as any test anywhere in `ferrogate-cli` matches
`governed_decision`, including one in a `tests/` target that `--bin` excludes.
Pairing filters with the targets a selector leaves live would need cargo's own
target resolution; what is here is a floor. `--test`/`--bin`/`--bench` selectors
are NOT themselves checked: cargo already fails loudly on a target name that
does not exist, which is why the same three moves did not break those.

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
    Deleting `platform-crates) run_platform_crates ;;` orphans the only local
    invocation of five of that function's six crates -- `agent-worker`,
    `ferrogate-cloudflare`, `ferrogate-payments`, `ferrogate-secrets`,
    `ferrogate-sync-bridge` -- and the gate did not notice, because it modelled
    workflow reachability via `uses:` and the script's reachability not at all.
    Five, not six: `ferrogate-gateway`, the crate #561 is named after, is the
    one that SURVIVES that deletion, because `run_governed_decisions` selects
    it too. Selection is not health, and a crate selected twice hides the loss
    of either selector.

  * a function name that appears in a reachable line without being RUN by it.
    `platform-crates) echo "run_platform_crates is disabled" ;;` left all
    twenty-two members credited and the gate green, because reachability was a
    mention graph. It is a command-position graph now: quoted strings and
    heredoc bodies are data, and a name only counts where a shell would execute
    it (line start, or after `;`, `&&`, `||`, `|`, a `case` arm's `)`, `(`,
    `{`, a backtick, `!`, `then`, `else` or `do`).

And one thing the filter check deliberately does not attempt, stated so its
scope is not overread: a run line whose arguments come from a matrix
(`cargo test -p "${{ matrix.package }}" ${{ matrix.args }}`) is skipped, because
pairing an `args:` value with the `package:` in the same matrix ENTRY needs a
real YAML parse and this gate has none. That is a hole with a shape: a
positional filter written into a matrix `args:` value is invisible here, and a
printed count is not an assertion. Both halves are pinned in
`scripts/test_ci_crate_coverage.py` instead -- one test recounts the skipped
invocations off the reachable workflows a second way and requires the printed
number to match, and another reads every templated matrix's value lists and
fails if any of them grows a positional filter. At `77c921e` there are seven
skipped invocations and none of the value lists carries one; all six positional
filters -- three in the workflows, three in the local runner -- are on literal
lines and are checked.

Filters are matched as substrings of a reconstructed `module::path::fn_name`,
the same way libtest matches them. The reconstruction reads rustfmt indentation
rather than counting braces, so a stray `{` in data -- the JSON these tests are
full of -- cannot shift a module boundary. What it does NOT survive is a line
that literally reads `mod name {` inside a raw string or a `/* */` block: that
is read as a module and opens one. Zero instances across the 706 `.rs` files
under `crates/` at `4c2ba43`, `cargo fmt --all -- --check` is a gate so the
indentation it depends on holds, and the failure direction is a wrong module
prefix rather than a missed test -- but it is a parser, not a compiler, and the
claim is that narrow.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import shlex
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
# every bash function that way; `function name {` and `function name() {` are
# accepted too, because a definition this parser does not recognize leaves its
# body top-level, i.e. credits more rather than less, and that is the direction
# a false credit travels in.
SHELL_FUNCTION = re.compile(
    r"^(?:function\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\s*\))?"
    r"|([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\))\s*\{\s*$"
)
# Column zero, and only column zero. An indented `}` closes a `{ ...; }` group,
# a `case` arm's brace or a nested block INSIDE a function body; treating it as
# the end of the function spills the rest of that body into top-level code,
# where it is credited without any dispatch at all.
SHELL_FUNCTION_END = re.compile(r"^\}\s*$")
# `cat <<'USAGE'` / `<<-EOF` / `<<EOF`, but not the `<<<` here-string. A heredoc
# body is data handed to a command, not commands: this repo's own `usage`
# heredoc lists module names, and the day one of those lists a function name the
# gate must not read that as a dispatch.
HEREDOC_OPEN = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")

# --- name-filter resolution (#553) -------------------------------------------
#
# Cargo flags that consume the NEXT token. Anything not listed is treated as a
# boolean flag, so an unknown value-taking flag makes its value look like a name
# filter -- which fails loudly rather than passing quietly, the direction this
# gate wants to err in.
CARGO_VALUE_FLAGS = frozenset(
    {
        "-p",
        "--package",
        "--exclude",
        "--test",
        "--bench",
        "--example",
        "--bin",
        "--features",
        "-F",
        "--manifest-path",
        "--target",
        "--target-dir",
        "--profile",
        "--config",
        "--color",
        "--message-format",
        "--out-dir",
        "-j",
        "--jobs",
        "-Z",
        # libtest's own value-taking flags, reachable after `--`.
        "--skip",
        "--test-threads",
        "--logfile",
        "--format",
    }
)
# `#[test]`, `#[tokio::test]`, `#[tokio::test(flavor = "...")]`, `#[rstest]`.
TEST_ATTRIBUTE = re.compile(r"^\s*#\[(?:[a-z_]+::)*(?:test|rstest)[\]\(]")
# `mod name {` -- an inline module. A `mod name;` declaration adds no nesting to
# the file it appears in; the declared file supplies its own prefix from its
# path, so only the braced form is tracked.
INLINE_MODULE = re.compile(r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*\{")
# `#[path = "signed_snapshot_test.rs"]` immediately above `mod tests;`: the file
# on disk is not where its module path says it is, and `config::tests` is
# exactly the kind of filter that depends on getting this right.
PATH_ATTRIBUTE = re.compile(r"^\s*#\[path\s*=\s*\"([^\"]+)\"\s*\]")
MODULE_DECLARATION = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]+)\s*;"
)
FUNCTION_DECLARATION = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z0-9_]+)"
)


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


def strip_heredoc_bodies(text: str) -> str:
    """Drop every heredoc body, keeping the line that opened it.

    A heredoc is an argument, not a command list. `usage()` in this repo prints
    its module menu from one, and a `cargo test` written inside such a block
    would be a string being echoed, not a suite being run.
    """
    kept: list[str] = []
    terminator: str | None = None
    dashed = False
    for line in text.splitlines():
        if terminator is not None:
            if (line.strip() if dashed else line.rstrip()) == terminator:
                terminator = None
            continue
        kept.append(line)
        if "<<<" in line:
            continue
        opened = HEREDOC_OPEN.search(line)
        if opened is not None:
            terminator = opened.group(2)
            dashed = "<<-" in line
    return "\n".join(kept)


def strip_quoted(text: str) -> str:
    """Replace every quoted span with a space. A name in a string is data.

    `echo "run_platform_crates is disabled"` mentions a function and runs
    nothing. Substituting a space rather than deleting the span keeps two
    tokens from being welded into a third that neither line contains.
    """
    stripped: list[str] = []
    for line in text.splitlines():
        buffer: list[str] = []
        quote = ""
        for character in line:
            if quote:
                if character == quote:
                    quote = ""
                    buffer.append(" ")
                continue
            if character in "'\"":
                quote = character
                continue
            buffer.append(character)
        if quote:
            buffer.append(" ")
        stripped.append("".join(buffer))
    return "\n".join(stripped)


def command_position(name: str) -> re.Pattern[str]:
    """`name` where a shell would RUN it, not merely where it is written.

    The separators are every place a bash command can begin: the start of a
    line, `;` (which covers a `case` arm's `;;`), `&`/`&&`, `|`/`||`, the `)`
    that closes a `case` pattern, `(`, `{`, a backtick, `!`, and the `then`,
    `else` and `do` keywords.
    """
    return re.compile(
        r"(?:^|[;&|(){}`!]|\bthen\b|\belse\b|\bdo\b)\s*"
        + re.escape(name)
        + r"(?![A-Za-z0-9_-])",
        re.MULTILINE,
    )


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
    `platform-crates) run_platform_crates ;;` from `run_module` and five of the
    six crates in that function have no local invocation left -- not
    `ferrogate-gateway`, which `run_governed_decisions` also selects. The gate
    followed `uses:` through the workflows and read the script as a flat pile
    of lines.

    Functions are recognized in this repo's style (`name() {` on its own line,
    closing `}` at column zero) and in the `function name {` spelling. Anything
    else stays top-level, so an unrecognized definition over-credits rather
    than failing the script's author for a formatting choice.

    A name counts as dispatched only where a shell would run it. The first
    version of this model asked whether the name appeared at all, which is not
    the same question: `platform-crates) echo "run_platform_crates is
    disabled" ;;` kept every crate in that function credited, on the real
    script, with the gate green.

    What it still over-credits, said here rather than left to be found: a
    function DEFINED inside another function's body is not seen as a
    definition (the closing `}` at column zero belongs to the outer one), so
    its lines are read whenever the outer function is reachable, whether or not
    anything calls the inner one. And a name reached through `eval`, a variable
    (`"$module"`), or any indirection is invisible either way -- in the
    crediting direction for the first and the failing direction for the
    second. This is a reachability approximation, not a bash interpreter; what
    it must never do is call something reachable that is not, and the three
    constructs above are why "must never" is "does not, for the constructs
    this repository writes".
    """
    text = strip_heredoc_bodies(text)
    bodies: dict[str, list[str]] = {}
    toplevel: list[str] = []
    current: str | None = None
    for line in text.splitlines():
        if current is None:
            match = SHELL_FUNCTION.match(line)
            if match is not None:
                current = match.group(1) or match.group(2)
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

    patterns = {name: command_position(name) for name in bodies}

    def calls(region: list[str]) -> set[str]:
        body = strip_quoted("\n".join(region))
        return {name for name, pattern in patterns.items() if pattern.search(body)}

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


def command_lines(text: str) -> list[str]:
    """One shell/YAML command per string, `\\`-continuations folded in.

    `scripts/local-test-modules.sh` writes its longest `cargo test` over two
    lines with a trailing backslash. Reading it line-at-a-time would drop the
    half carrying the filters, and a filter this gate cannot see is a filter it
    silently exempts -- the gate's own version of the defect it checks for.
    """
    folded: list[str] = []
    pending = ""
    for line in text.splitlines():
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1] + " "
            continue
        folded.append(pending + line)
        pending = ""
    if pending:
        folded.append(pending)
    return folded


def cargo_test_name_filters(command: str) -> tuple[set[str], set[str]]:
    """`(packages, positional name filters)` for one literal `cargo test`.

    Tokenized with `shlex`, not `str.split`, because `-- --skip 'issue #563
    fixture'` is ONE argument to libtest and splitting it on whitespace turns
    three words into three name filters that must each match a test. The gate's
    own test suite already contained that line.
    """
    index = command.find("cargo test")
    remainder = command[index + len("cargo test") :]
    try:
        tokens = shlex.split(remainder, comments=False)
    except ValueError:
        # Unbalanced quoting: the arguments cannot be read, so neither can what
        # this command runs. Reported as a filter that resolves to nothing
        # rather than skipped, because "the gate could not parse it" and "the
        # gate approved it" must not look the same.
        return set(), {remainder.strip()}
    packages: set[str] = set()
    filters: set[str] = set()
    skip_next = False
    for position, token in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue
        flag, _, inline = token.partition("=")
        if flag in CARGO_VALUE_FLAGS:
            if inline:
                if flag in ("-p", "--package"):
                    packages.add(inline)
                continue
            skip_next = True
            if flag in ("-p", "--package") and position + 1 < len(tokens):
                packages.add(tokens[position + 1])
            continue
        if token.startswith("-"):
            # `--` itself, and every boolean flag on either side of it.
            continue
        filters.add(token)
    return packages, filters


def module_prefix(relative: pathlib.PurePosixPath) -> list[str] | None:
    """The module path a file contributes, or `None` if it is not a test root.

    `src/lib.rs` and `src/main.rs` are crate roots and contribute nothing;
    `src/a/b.rs` and `src/a/b/mod.rs` both contribute `a::b`. An integration
    target `tests/foo.rs` is its own crate root, so it contributes nothing
    either, while `tests/support/mod.rs` contributes `support` -- the name the
    targets that `mod support;` it will see.
    """
    parts = list(relative.parts)
    if not parts or parts[-1].endswith(".rs") is False:
        return None
    if parts[0] not in ("src", "tests"):
        return None
    inner = parts[1:]
    if not inner:
        return None
    if inner[0] == "bin" and parts[0] == "src":
        # A `src/bin/*.rs` binary is its own target with its own root.
        inner = inner[1:]
        if len(inner) == 1:
            return []
    stem = inner[-1][: -len(".rs")]
    if stem == "mod":
        return inner[:-1]
    if parts[0] == "src" and len(inner) == 1 and stem in ("lib", "main"):
        return []
    if parts[0] == "tests" and len(inner) == 1:
        return []
    return inner[:-1] + [stem]


def crate_test_paths(directory: pathlib.Path) -> set[str]:
    """Every `module::path::test_name` libtest could print for this crate.

    A TEST path, and only a test path. The first version of this function also
    returned the module paths it walked through -- every file's own prefix and
    every inline `mod` it opened -- so that a filter naming a module rather
    than a test still resolved. That admitted a module path with no test under
    it, which is the exact failure this gate exists to refuse, surviving the
    gate. Delete `server/governed_decision_test.rs` and
    `server/governed_decision_conformance_test.rs` and leave the production
    `server/governed_decision.rs` (763 lines at `4c2ba43`, zero `#[test]`) in
    place -- a file move, the same edit class that caused #553 -- and the
    filter `governed_decision` resolved against the surviving
    `server::governed_decision` module path while `cargo test -p
    ferrogate-gateway governed_decision` ran nothing. At `77c921e`, 184 of
    `ferrogate-gateway`'s 1,271 candidates were proper prefixes of another,
    i.e. module paths standing in for tests that might or might not exist.

    Dropping them loses nothing, because libtest matches a filter as a
    SUBSTRING of the full path: a module that does have tests beneath it is a
    prefix -- therefore a substring -- of each of their paths, so `config::tests`
    still resolves through `config::tests::rejects_an_unknown_key`. Rejecting
    the module path when no test lies beneath it and admitting it when one does
    are the same rule as simply not admitting module paths at all, and the
    second is the one that cannot be got wrong. All three filters live at
    `77c921e` keep many candidates under this rule: `governed_decision` 18,
    `config::tests` 27, `config::validation_tests` 193.

    Nesting is read from rustfmt indentation, not from brace counting: `cargo
    fmt --all -- --check` is a gate in this repo, so indentation is reliable,
    while a `{` inside one of the JSON fixtures these tests are full of would
    walk a brace counter straight off the end.
    """
    files = sorted(path for path in directory.rglob("*.rs") if path.is_file())
    relatives = {path: pathlib.PurePosixPath(path.relative_to(directory).as_posix()) for path in files}
    prefixes: dict[pathlib.Path, list[str]] = {}
    for path in files:
        prefix = module_prefix(relatives[path])
        if prefix is not None:
            prefixes[path] = prefix

    # `#[path = "x_test.rs"] mod tests;` overrides what the file name implies.
    # Applied to a fixpoint so a remapped file can itself remap another.
    for _ in range(4):
        changed = False
        for path in files:
            if path not in prefixes:
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            pending_path: str | None = None
            for line in lines:
                attribute = PATH_ATTRIBUTE.match(line)
                if attribute is not None:
                    pending_path = attribute.group(1)
                    continue
                declaration = MODULE_DECLARATION.match(line)
                if declaration is not None and pending_path is not None:
                    target = (path.parent / pending_path).resolve()
                    resolved = prefixes[path] + [declaration.group(1)]
                    if target in prefixes and prefixes[target] != resolved:
                        prefixes[target] = resolved
                        changed = True
                if line.strip():
                    pending_path = None
        if not changed:
            break

    paths: set[str] = set()
    for path, prefix in prefixes.items():
        stack: list[tuple[int, str]] = []
        is_test = False
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            while stack and indent <= stack[-1][0]:
                stack.pop()
            module = INLINE_MODULE.match(line)
            if module is not None:
                stack.append((len(module.group(1)), module.group(2)))
                continue
            if TEST_ATTRIBUTE.match(line):
                is_test = True
                continue
            function = FUNCTION_DECLARATION.match(line)
            if function is not None:
                if is_test:
                    paths.add(
                        "::".join(prefix + [name for _, name in stack] + [function.group(1)])
                    )
                is_test = False
                continue
            if not line.lstrip().startswith(("#", "//")):
                is_test = False
    return paths


def unmatched_name_filters(
    regions: list[tuple[str, str]],
    packages: dict[str, str],
    root: pathlib.Path,
) -> tuple[list[str], int, int, int]:
    """Filters selecting no test, filters checked, templated lines skipped, and
    the number of test paths those filters were resolved against.

    The last two numbers exist because this half of the gate is invisible when
    it finds nothing, in two independent ways, and neither shows up in the exit
    code. A refactor that stopped recognizing `cargo test` lines at all would
    print the same success line as a clean tree -- `checked` makes "checked
    nothing" and "checked everything" different outputs. And a `crate_test_paths`
    that stopped RECONSTRUCTING tests would leave the filters checked against an
    empty set; the fourth number is the floor under that, pinned in the suite
    against the real tree so it cannot silently collapse.

    A crate that reconstructs to zero test paths is called out by name rather
    than left to surface as "matches no test", because the two have opposite
    fixes: the first means this parser broke, the second means the filter is
    pointed at the wrong crate. #553 was the second and was read as neither.
    """
    known: dict[str, set[str]] = {}
    failures: list[str] = []
    checked = 0
    skipped = 0
    for label, text in regions:
        for command in command_lines(text):
            if "cargo test" not in command:
                continue
            if "${{" in command:
                skipped += 1
                continue
            selected, filters = cargo_test_name_filters(command)
            if not filters:
                continue
            named = [name for name in selected if name in packages]
            if not named:
                failures.append(
                    f"  {label}: `{command.strip()}` filters on "
                    f"{', '.join(sorted(filters))} but names no workspace member, "
                    "so what it runs cannot be resolved"
                )
                continue
            reachable: set[str] = set()
            for name in named:
                if name not in known:
                    known[name] = crate_test_paths(root / packages[name])
                    if not known[name]:
                        failures.append(
                            f"  {label}: `{command.strip()}` filters on "
                            f"{', '.join(sorted(filters))} against {name} "
                            f"({packages[name]}), in which this gate reconstructed "
                            "ZERO test paths -- so every filter naming it would be "
                            "reported as matching nothing, whether or not it does. "
                            "Either the crate has no tests and no filter should "
                            "name it, or the reconstruction in `crate_test_paths` "
                            "has broken and this gate is checking an empty set."
                        )
                reachable |= known[name]
            for name_filter in sorted(filters):
                checked += 1
                if not any(name_filter in candidate for candidate in reachable):
                    failures.append(
                        f"  {label}: `cargo test {' '.join('-p ' + n for n in sorted(named))} "
                        f"{name_filter}` matches no test in "
                        f"{', '.join(sorted(named))}"
                    )
    return failures, checked, skipped, sum(len(paths) for paths in known.values())


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
    runner_text = runner.read_text(encoding="utf-8")
    in_local = selected_by_local_runner(runner_text, arguments.local_runner)

    # The same two surfaces, read a second time for the other failure: a slice
    # that names its crate and then filters every test in it away (#553).
    regions: list[tuple[str, str]] = [
        (str(workflow.relative_to(root)), strip_comments(workflow.read_text(encoding="utf-8")))
        for workflow in workflows
    ]
    regions.append(
        (
            arguments.local_runner,
            shell_reachable_text(strip_comments(runner_text), arguments.local_runner),
        )
    )
    empty_filters, checked_filters, templated, discovered = unmatched_name_filters(
        regions, packages, root
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

    if empty_filters:
        print("`cargo test` name filters that select no test:", file=sys.stderr)
        for failure in empty_filters:
            print(failure, file=sys.stderr)
        print(
            "\nlibtest exits 0 when a filter matches nothing, so each of these is a "
            "step that passes having run no test. Repoint the filter at the crate "
            "the code now lives in, or delete it. This is #553's own regression: "
            "moving a file out of a crate leaves every filter that named it green "
            "and empty.",
            file=sys.stderr,
        )
        return 1

    print(
        f"validated {len(packages)} workspace members against "
        f"{len(workflows)} CI workflows and {arguments.local_runner}"
    )
    print(
        f"resolved {checked_filters} name filter(s) on literal `cargo test` lines "
        f"against {discovered} reconstructed test path(s); "
        f"{templated} matrix-templated line(s) skipped"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
