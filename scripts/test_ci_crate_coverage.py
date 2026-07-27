#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-27
# description: Tests for the workspace-member CI coverage gate (issue #561) and
# its empty-name-filter half (issue #553).
"""Tests for `scripts/check-ci-crate-coverage.py`.

The gate exists because nothing noticed that a 136k-line crate ran nowhere, so
the one thing these tests must rule out is the gate itself being the next thing
that notices nothing. Every case below is built as a throwaway workspace on
disk and run through the real script, and each negative case is paired with the
positive that differs only in the fact under test.

The second block of cases covers the filter half (#553): a slice that names its
crate and then selects no test inside it. The crate-level cases above are all
blind to it by construction -- every one of those invocations names its crate
correctly -- which is why it survived four review rounds in
`governed-decision-conformance.yml`.
"""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-ci-crate-coverage.py"


class CiCrateCoverageTests(unittest.TestCase):
    def build_workspace(
        self,
        root: pathlib.Path,
        members: list[str],
        ci_workflow: str | None,
        called_workflows: dict[str, str] | None = None,
        local_runner: str = "",
        member_lines: str | None = None,
        sources: dict[str, dict[str, str]] | None = None,
    ) -> None:
        quoted = member_lines or "".join(
            f'    "crates/{member}",\n' for member in members
        )
        (root / "Cargo.toml").write_text(
            f"[workspace]\nmembers = [\n{quoted}]\n", encoding="utf-8"
        )
        for member in members:
            directory = root / "crates" / member
            directory.mkdir(parents=True)
            (directory / "Cargo.toml").write_text(
                f'[package]\nname = "{member}"\nversion = "0.0.0"\n', encoding="utf-8"
            )
            for relative, body in (sources or {}).get(member, {}).items():
                target = directory / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(textwrap.dedent(body), encoding="utf-8")
        workflows = root / ".github" / "workflows"
        workflows.mkdir(parents=True)
        if ci_workflow is not None:
            (workflows / "ci.yml").write_text(ci_workflow, encoding="utf-8")
        for name, body in (called_workflows or {}).items():
            (workflows / name).write_text(body, encoding="utf-8")
        scripts = root / "scripts"
        scripts.mkdir()
        (scripts / "local-test-modules.sh").write_text(local_runner, encoding="utf-8")

    def run_checker(self, **kwargs) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.build_workspace(root, **kwargs)
            return subprocess.run(
                ["python3", str(CHECKER), "--root", str(root)],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_accepts_a_member_selected_in_both_ci_and_the_local_runner(self) -> None:
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="cargo test -p ferrogate-gateway --all-features\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("validated 1 workspace members", result.stdout)

    def test_rejects_the_member_that_no_workflow_selects(self) -> None:
        """The literal #561 shape: compiled everywhere, executed nowhere."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-cli\n",
            local_runner="cargo test -p ferrogate-gateway\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertIn("in any workflow", result.stderr)

    def test_rejects_the_member_the_local_runner_dropped(self) -> None:
        """CI-only coverage is the drift half of #561, and also fails."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="cargo test -p ferrogate-cli\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("local-test-modules.sh", result.stderr)
        # Naming the crate is the point: a local branch that reported the
        # wrong member would still say "local-test-modules.sh".
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertNotIn("ferrogate-cli", result.stderr)

    def test_compiling_a_crate_is_not_testing_it(self) -> None:
        """`cargo build -p X` is exactly what #561's crates already had."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo build -p ferrogate-gateway --locked\n",
            local_runner="cargo build -p ferrogate-gateway\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)

    def test_resolves_a_matrix_package_key_through_the_templated_run_line(self) -> None:
        """Every real slice in this repo names its crate in the matrix, not the

        run line, so a gate that only reads the run line would pass everything
        vacuously."""
        result = self.run_checker(
            members=["ferrogate-secrets"],
            ci_workflow=textwrap.dedent(
                """
                jobs:
                  t:
                    strategy:
                      matrix:
                        include:
                          - slice: secrets
                            package: ferrogate-secrets
                    steps:
                      - run: cargo test -p "${{ matrix.package }}" --all-features
                """
            ),
            local_runner="cargo test -p ferrogate-secrets\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_matrix_package_key_alone_does_not_count(self) -> None:
        """The counterpart of the case above: a `package:` key in a workflow

        that never runs `cargo test` must not be credited."""
        result = self.run_checker(
            members=["ferrogate-secrets"],
            ci_workflow=textwrap.dedent(
                """
                jobs:
                  t:
                    strategy:
                      matrix:
                        include:
                          - package: ferrogate-secrets
                    steps:
                      - run: cargo build -p "${{ matrix.package }}"
                """
            ),
            local_runner="cargo test -p ferrogate-secrets\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-secrets", result.stderr)

    def test_follows_reusable_workflow_calls_from_the_entry_point(self) -> None:
        result = self.run_checker(
            members=["ferrogate-payments"],
            ci_workflow="jobs:\n  p:\n    uses: ./.github/workflows/rust-x.yml\n",
            called_workflows={
                "rust-x.yml": "jobs:\n  t:\n    run: cargo test -p ferrogate-payments\n"
            },
            local_runner="cargo test -p ferrogate-payments\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ignores_a_workflow_the_entry_point_never_calls(self) -> None:
        """`firecracker-boot-validation.yml` is `workflow_dispatch`-only and

        needs a KVM runner, so the `cargo test -p agent-worker` inside it is not
        coverage. Reading every `.yml` in the directory -- which is how #561's
        own survey was done -- would have called that crate covered."""
        result = self.run_checker(
            members=["agent-worker"],
            ci_workflow="jobs:\n  q:\n    run: cargo test -p ferrogate-cli\n",
            called_workflows={
                "manual.yml": "on:\n  workflow_dispatch:\njobs:\n  t:\n"
                "    run: cargo test -p agent-worker\n"
            },
            local_runner="cargo test -p agent-worker\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("agent-worker", result.stderr)

    # ---- a comment is not an invocation -------------------------------------
    #
    # The live instance, found by review at `60cdc14`: the line
    # `# This still does not run \`cargo test -p ferrogate-cli\` unfiltered`
    # -- a comment SAYING the crate was under-covered -- was what credited it
    # as covered. Every real invocation could have been deleted in silence.

    def test_a_commented_out_run_line_is_not_coverage(self) -> None:
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    steps:\n"
            "      # - run: cargo test -p ferrogate-gateway\n"
            "      - run: cargo build -p ferrogate-gateway\n",
            local_runner="cargo test -p ferrogate-gateway\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertIn("in any workflow", result.stderr)

    def test_a_comment_about_a_crate_does_not_run_the_crate(self) -> None:
        """The shell half, in the shape the repository actually had it."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="run_x() {\n"
            "  # This still does not run `cargo test -p ferrogate-gateway`\n"
            "  # unfiltered; the suite is red on arrival.\n"
            "  cargo test -p ferrogate-cli\n"
            "}\n"
            "run_x\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertIn("local-test-modules.sh", result.stderr)

    def test_a_trailing_comment_is_not_part_of_the_command(self) -> None:
        result = self.run_checker(
            members=["ferrogate-core", "ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: |\n"
            "      cargo test -p ferrogate-core\n"
            "      cargo test -p ferrogate-gateway\n",
            local_runner="cargo test -p ferrogate-core  # one day: -p ferrogate-gateway\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertNotIn("ferrogate-core", result.stderr)

    def test_a_hash_inside_a_quoted_argument_is_not_a_comment(self) -> None:
        """The counterpart: comment stripping must not truncate a real command,

        which is how a "skip a comment" fix turns into a coverage hole of its
        own. The `#` sits BEFORE the `-p` flag, which is the only position that
        discriminates: with the trailing `-- --skip 'issue #563 fixture'` shape
        this file shipped first, deleting the quote-tracking branch from
        `strip_comment` still left `-p ferrogate-gateway` intact, the crate
        credited and all twenty-one tests of the day green."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="cargo test --features 'unstable #563' -p ferrogate-gateway"
            " -- --skip 'issue #563 fixture'\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_quoted_hash_before_the_command_does_not_erase_the_command(self) -> None:
        """And the same rule where nothing but crate credit can catch it.

        An environment prefix is how this repo pins `AGENT_WORKER_DOCKER_BIN`
        for the `platform-crates` module. Put a quoted `#` in one and
        over-stripping deletes the whole invocation -- `cargo test` included --
        so the filter half of this gate never even looks at the line and the
        crate is simply reported as run by nothing."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="FERROGATE_TEST_TAG='issue #563' "
            "cargo test -p ferrogate-gateway --all-features\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    # ---- a function nothing dispatches runs for nobody -----------------------

    def test_a_cargo_test_in_an_undispatched_function_is_not_coverage(self) -> None:
        """Review's second dead-code hole: drop the `case` arm and FIVE of the

        six crates in `run_platform_crates` have no local invocation left,
        while the function -- and its `cargo test` lines -- sit there looking
        like coverage. Five, measured on the real script:
        `ferrogate-gateway` survives, because `run_governed_decisions` selects
        it as well. The crate #561 is named after is the one that does not drop
        out, which is what "selection is not health" costs when a crate is
        selected twice and one selector dies."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="run_platform_crates() {\n"
            "  cargo test -p ferrogate-gateway --all-features\n"
            "}\n"
            "run_module() {\n"
            "  case \"$1\" in\n"
            "    quality) run_quality ;;\n"
            "  esac\n"
            "}\n"
            "run_quality() {\n"
            "  cargo fmt --all -- --check\n"
            "}\n"
            'run_module "$1"\n',
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertIn("local-test-modules.sh", result.stderr)

    def test_the_same_function_counts_once_something_dispatches_it(self) -> None:
        """The positive that differs from the case above in exactly one line."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="run_platform_crates() {\n"
            "  cargo test -p ferrogate-gateway --all-features\n"
            "}\n"
            "run_module() {\n"
            "  case \"$1\" in\n"
            "    platform-crates) run_platform_crates ;;\n"
            "  esac\n"
            "}\n"
            'run_module "$1"\n',
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_function_named_only_inside_a_string_is_not_dispatched(self) -> None:
        """Reachability was a MENTION graph, and review broke it on the real

        script in one edit: `platform-crates) echo "run_platform_crates is
        disabled" ;;` left all twenty-two members credited and the gate green,
        because the name still appeared inside `run_module`. A name in a string
        is data. This differs from the positive above in exactly the two words
        that stop it being a call.

        This exact shape is caught twice over -- the quote stripping and the
        command-position rule each suffice for it -- so the two tests below
        exist to hold each of those mechanisms on its own."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="run_platform_crates() {\n"
            "  cargo test -p ferrogate-gateway --all-features\n"
            "}\n"
            "run_module() {\n"
            "  case \"$1\" in\n"
            '    platform-crates) echo "run_platform_crates is disabled" ;;\n'
            "  esac\n"
            "}\n"
            'run_module "$1"\n',
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertIn("local-test-modules.sh", result.stderr)

    def test_a_function_named_as_a_bare_argument_is_not_dispatched(self) -> None:
        """Holds `command_position` alone: no quotes anywhere, so stripping

        them changes nothing, and only "is this where a shell would START a
        command?" separates `echo run_platform_crates` from running it."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="run_platform_crates() {\n"
            "  cargo test -p ferrogate-gateway --all-features\n"
            "}\n"
            "run_module() {\n"
            "  case \"$1\" in\n"
            "    platform-crates) echo run_platform_crates is disabled ;;\n"
            "  esac\n"
            "}\n"
            'run_module "$1"\n',
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertIn("local-test-modules.sh", result.stderr)

    def test_a_string_that_looks_like_a_command_list_is_not_one(self) -> None:
        """And holds `strip_quoted` alone: the `;` inside the message puts the

        name in command position by the letter of the rule, so the only thing
        left to notice that it is a message and not a command is that it is
        quoted."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="run_platform_crates() {\n"
            "  cargo test -p ferrogate-gateway --all-features\n"
            "}\n"
            "run_module() {\n"
            "  case \"$1\" in\n"
            '    platform-crates) echo "disabled; run_platform_crates was retired" ;;\n'
            "  esac\n"
            "}\n"
            'run_module "$1"\n',
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertIn("local-test-modules.sh", result.stderr)

    def test_a_function_named_only_in_a_heredoc_is_not_dispatched(self) -> None:
        """The same, one construct over. This script prints its module menu

        from a heredoc; the day that menu lists a function name rather than a
        module name, a mention graph reads the help text as a dispatch."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="run_platform_crates() {\n"
            "  cargo test -p ferrogate-gateway --all-features\n"
            "}\n"
            "usage() {\n"
            "  cat <<'USAGE'\n"
            "Modules:\n"
            "  run_platform_crates\n"
            "USAGE\n"
            "}\n"
            "usage\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertIn("local-test-modules.sh", result.stderr)

    def test_the_function_keyword_spelling_is_a_definition_too(self) -> None:
        """`function name {` is a definition, so its body needs a dispatch like

        any other. Unrecognized, the body falls through to top-level code and
        is credited unconditionally -- which is the one direction a
        reachability model must not fail in silently."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="function run_platform_crates {\n"
            "  cargo test -p ferrogate-gateway --all-features\n"
            "}\n"
            "run_quality() {\n"
            "  cargo fmt --all -- --check\n"
            "}\n"
            "run_quality\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertIn("local-test-modules.sh", result.stderr)

    def test_an_indented_brace_does_not_end_a_function_body(self) -> None:
        """`SHELL_FUNCTION_END` anchors at column zero, and loosening it to

        `^\\s*\\}` survived every test this file had: the `}` closing a `{ ...;
        }` group inside a body ends the function early, and everything after it
        -- the `cargo test` included -- becomes top-level code, credited with
        no dispatch at all. The function below is deliberately never
        dispatched, so the only way this passes is by ending it early."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="run_platform_crates() {\n"
            "  if true; then\n"
            "    {\n"
            "      echo grouped\n"
            "    }\n"
            "  fi\n"
            "  cargo test -p ferrogate-gateway --all-features\n"
            "}\n"
            "run_quality() {\n"
            "  cargo fmt --all -- --check\n"
            "}\n"
            "run_quality\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertIn("local-test-modules.sh", result.stderr)

    # ---- matrix credit stays inside the job that asked for it ---------------

    def test_matrix_credit_does_not_cross_from_one_job_to_the_next(self) -> None:
        """The job scoping itself, which nothing held.

        The two tests below both template `${{ matrix.args }}` while naming
        their crate literally, so `TEMPLATED_PACKAGE_FLAG` collects no key in
        either and `workflow_job_regions` never runs: reverting it to a single
        file-wide region -- `return [text]` -- left all thirty tests green.
        Here job `a` DOES interpolate `${{ matrix.package }}`, and job `b`
        carries a different crate's `package:` key for a step that only builds.
        File-wide, `a`'s key finds `b`'s value and marks it tested."""
        result = self.run_checker(
            members=["ferrogate-cli", "ferrogate-storage"],
            ci_workflow=textwrap.dedent(
                """
                jobs:
                  a:
                    strategy:
                      matrix:
                        include:
                          - package: ferrogate-cli
                    steps:
                      - run: cargo test -p "${{ matrix.package }}" --all-features
                  b:
                    strategy:
                      matrix:
                        include:
                          - package: ferrogate-storage
                    steps:
                      - run: cargo build -p "${{ matrix.package }}" --locked
                """
            ),
            local_runner="cargo test -p ferrogate-cli\ncargo test -p ferrogate-storage\n",
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("ferrogate-storage", result.stderr)
        self.assertNotIn("ferrogate-cli", result.stderr)

    def test_the_long_package_spelling_is_read_too(self) -> None:
        """`--package` is documented in `PACKAGE_FLAG` as accepted "so a future

        rewrite does not slip past", and no fixture used it: dropping the
        alternative left all thirty tests green while every `--package` slice
        in a rewritten workflow silently stopped counting."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test --package ferrogate-gateway\n",
            local_runner="cargo test --package=ferrogate-gateway --all-features\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_package_key_in_another_job_is_not_credited(self) -> None:
        """`rust-gateway-runtime.yml` templates its run line through

        `${{ matrix.args }}` while naming its crate literally. Treating any
        `${{` as "consult this file's matrix" would let a `package:` key added
        to an unrelated build job mark that crate tested."""
        result = self.run_checker(
            members=["ferrogate-cli", "ferrogate-storage"],
            ci_workflow=textwrap.dedent(
                """
                jobs:
                  perf:
                    strategy:
                      matrix:
                        include:
                          - slice: runtime_perf
                            args: --test runtime_perf
                    steps:
                      - run: cargo test -p ferrogate-cli ${{ matrix.args }}
                  build:
                    strategy:
                      matrix:
                        include:
                          - package: ferrogate-storage
                    steps:
                      - run: cargo build -p "${{ matrix.package }}"
                """
            ),
            local_runner="cargo test -p ferrogate-cli\ncargo test -p ferrogate-storage\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-storage", result.stderr)
        self.assertNotIn("ferrogate-cli", result.stderr)

    def test_a_package_key_the_run_line_never_interpolates_is_not_credited(
        self,
    ) -> None:
        """The same leak inside ONE job, where scoping cannot be what catches

        it. The run line names its crate literally and templates only
        `${{ matrix.args }}`, so the `package:` key beside it is some other
        step's input -- credit follows the key the `-p` flag actually
        interpolated, or it is not credit at all."""
        result = self.run_checker(
            members=["ferrogate-cli", "ferrogate-storage"],
            ci_workflow=textwrap.dedent(
                """
                jobs:
                  perf:
                    strategy:
                      matrix:
                        include:
                          - slice: runtime_perf
                            package: ferrogate-storage
                            args: --test runtime_perf
                    steps:
                      - run: cargo build -p "${{ matrix.package }}" --locked
                      - run: cargo test -p ferrogate-cli ${{ matrix.args }}
                """
            ),
            local_runner="cargo test -p ferrogate-cli\ncargo test -p ferrogate-storage\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-storage", result.stderr)
        self.assertNotIn("ferrogate-cli", result.stderr)

    # ---- the gate's own vacuity floors --------------------------------------

    def test_an_unreachable_entry_workflow_is_a_failure_of_its_own(self) -> None:
        """`:141`'s backstop. Asserting only the exit code would not hold it:

        with no workflow read, every member is uncovered too, so the run fails
        either way. What discriminates is that the gate must stop THERE and
        say the entry point is missing, rather than blaming the crates."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow=None,
            local_runner="cargo test -p ferrogate-gateway\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("pass vacuously", result.stderr)
        self.assertNotIn("workspace members whose tests nothing executes", result.stderr)

    def test_a_manifest_with_no_readable_members_is_an_error(self) -> None:
        """The `if not directories:` floor, which nothing held.

        Deleting it is the shortest route to a vacuous pass in this whole
        script: no members means no missing members, so the gate prints
        `validated 0 workspace members` and exits 0 having checked nothing.
        Asserting the exit code alone would not hold it either -- both stdout
        assertions below are the discriminator."""
        result = self.run_checker(
            members=[],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="cargo test -p ferrogate-gateway\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not parse [workspace] members", result.stderr)
        self.assertNotIn("validated 0 workspace members", result.stdout)
        self.assertNotIn("validated", result.stdout)

    def test_a_runner_that_dispatches_nothing_is_an_error(self) -> None:
        """The `if not reachable:` floor, which nothing held either.

        Replacing that raise with `return text` restores exactly the flat read
        the dispatch model was added to remove, and does it for the whole file
        at once: every `cargo test` in every function is credited again. The
        message is the assertion, because a stricter mutation
        (`if False:`) also exits 1 -- by blaming the crates instead of saying
        the script dispatches nothing."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="run_platform_crates() {\n"
            "  cargo test -p ferrogate-gateway --all-features\n"
            "}\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("calls none of them", result.stderr)

    def test_a_member_line_this_parser_cannot_read_is_an_error(self) -> None:
        """A dropped member is a crate that exempts itself from the gate while

        the gate reports success over the ones it did understand -- #561's own
        recurrence, one level up."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            member_lines='    "crates/ferrogate-gateway",\n    crates/ferrogate-new\n',
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="cargo test -p ferrogate-gateway\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("crates/ferrogate-new", result.stderr)

    def test_a_member_line_with_a_trailing_comment_is_still_a_member(self) -> None:
        """And the counterpart, so the strictness above does not become a ban

        on commenting the manifest: `"crates/foo", # experimental` is a member
        that must be checked, not an error and not a silent drop."""
        result = self.run_checker(
            members=["ferrogate-core", "ferrogate-gateway"],
            member_lines='    "crates/ferrogate-core",\n'
            '    "crates/ferrogate-gateway", # experimental\n',
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-core\n",
            local_runner="cargo test -p ferrogate-core\n"
            "cargo test -p ferrogate-gateway\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertNotIn("ferrogate-core", result.stderr)

    def test_it_names_the_uncovered_member_beside_a_covered_one(self) -> None:
        """Every other negative here declares ONE member, so truncating the

        member scan to its first entry (`if match is not None and not
        directories:`) left all nine tests green while the gate checked a
        single crate and exited 0."""
        result = self.run_checker(
            members=["ferrogate-core", "ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-core\n",
            local_runner="cargo test -p ferrogate-core\n"
            "cargo test -p ferrogate-gateway\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ferrogate-gateway", result.stderr)
        self.assertNotIn("ferrogate-core", result.stderr)

    # --- name filters that select nothing (#553) ----------------------------
    #
    # The crate-level half above is blind to all of these: every one of them
    # names its crate correctly, which is what made the #470 conformance gate
    # survive four rounds of review as a green no-op.

    GATEWAY_SOURCES = {
        "src/server/governed_decision_conformance_test.rs": """
            #[test]
            fn every_fixture_matches_its_golden() {}
        """
    }
    CLI_SOURCES = {
        "src/main.rs": """
            #[test]
            fn parses_the_root_command() {}
        """
    }

    def test_rejects_a_name_filter_that_matches_no_test(self) -> None:
        """The literal #553 shape, and the one this gate was added for.

        Pins the `any(name_filter in candidate ...)` arm of
        `unmatched_name_filters`. Mutating it to `if False` -- or dropping the
        `empty_filters` branch from `main` -- turns this green, which is
        precisely the state `governed-decision-conformance.yml` shipped in:
        `-p ferrogate-cli ... governed_decision` after the test file moved to
        `ferrogate-gateway`, exiting 0 having run nothing."""
        result = self.run_checker(
            members=["ferrogate-cli", "ferrogate-gateway"],
            sources={
                "ferrogate-gateway": self.GATEWAY_SOURCES,
                "ferrogate-cli": self.CLI_SOURCES,
            },
            ci_workflow="jobs:\n  t:\n    run: |\n"
            "        cargo test -p ferrogate-gateway\n"
            "        cargo test -p ferrogate-cli --bin ferrogate governed_decision\n",
            local_runner="cargo test -p ferrogate-cli\ncargo test -p ferrogate-gateway\n",
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("governed_decision", result.stderr)
        self.assertIn("matches no test in ferrogate-cli", result.stderr)

    def test_accepts_the_same_filter_pointed_at_the_crate_that_holds_it(self) -> None:
        """The positive twin: identical workspace, identical filter, only the

        `-p` differs. Without it, a gate that rejected every filter outright
        would pass the case above and prove nothing."""
        result = self.run_checker(
            members=["ferrogate-cli", "ferrogate-gateway"],
            sources={
                "ferrogate-gateway": self.GATEWAY_SOURCES,
                "ferrogate-cli": self.CLI_SOURCES,
            },
            ci_workflow="jobs:\n  t:\n    run: |\n"
            "        cargo test -p ferrogate-cli\n"
            "        cargo test -p ferrogate-gateway --all-features governed_decision\n",
            local_runner="cargo test -p ferrogate-cli\ncargo test -p ferrogate-gateway\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("resolved 1 name filter(s)", result.stdout)

    def test_a_module_path_filter_resolves_without_naming_a_test(self) -> None:
        """`config::tests` names a MODULE, not a test, and is the second live

        instance of this defect (`rust-quality.yml`, against a `ferrogate-cli`
        whose `config` module had moved to `ferrogate-config`). Pins the
        `paths.add("::".join(prefix))` line and the `INLINE_MODULE` branch in
        `crate_test_paths`: delete either and a filter naming only a module
        stops resolving, and the two `rust-quality.yml` lines red on a tree
        where they are correct."""
        sources = {
            "src/config/mod.rs": """
                mod tests;
            """,
            "src/config/tests.rs": """
                #[test]
                fn rejects_an_unknown_key() {}
            """,
        }
        result = self.run_checker(
            members=["ferrogate-config"],
            sources={"ferrogate-config": sources},
            ci_workflow="jobs:\n  t:\n    run: "
            "cargo test -p ferrogate-config --all-features config::tests\n",
            local_runner="cargo test -p ferrogate-config --all-features config::tests\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_path_attribute_moves_the_module_a_filter_must_match(self) -> None:
        """`#[path = "x_test.rs"] mod tests;` is how half this workspace wires

        its test files, and the module path libtest prints follows the
        DECLARATION, not the file name. Pins the `PATH_ATTRIBUTE` fixpoint
        loop: remove it and `signed_snapshot::tests` -- a real path in
        `ferrogate-config` -- is reported as matching nothing."""
        sources = {
            "src/config/signed_snapshot.rs": """
                #[cfg(test)]
                #[path = "signed_snapshot_test.rs"]
                mod tests;
            """,
            "src/config/signed_snapshot_test.rs": """
                #[test]
                fn verifies_a_snapshot_signature() {}
            """,
        }
        result = self.run_checker(
            members=["ferrogate-config"],
            sources={"ferrogate-config": sources},
            ci_workflow="jobs:\n  t:\n    run: "
            "cargo test -p ferrogate-config signed_snapshot::tests\n",
            local_runner="cargo test -p ferrogate-config signed_snapshot::tests\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_test_target_selector_is_not_a_name_filter(self) -> None:
        """`--test agentic_lite` is a TARGET, and cargo already errors on a

        target that does not exist. Pins `--test` in `CARGO_VALUE_FLAGS`: drop
        it and every `--test <name>` in the workflows becomes a name filter
        this gate demands a match for, reddening thirteen correct slices."""
        result = self.run_checker(
            members=["ferrogate-cli"],
            sources={"ferrogate-cli": self.CLI_SOURCES},
            ci_workflow="jobs:\n  t:\n    run: "
            "cargo test -p ferrogate-cli --all-features --test agentic_lite\n",
            local_runner="cargo test -p ferrogate-cli --test agentic_lite\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_harness_flags_after_the_double_dash_are_not_name_filters(self) -> None:
        """`-- --nocapture` and `-- --skip foo` are libtest's own flags. Pins

        the `token.startswith("-")` skip and `--skip` in `CARGO_VALUE_FLAGS`:
        without the second, `foo` reads as a filter that must match, and
        `--skip` exists precisely to name something you are NOT running."""
        result = self.run_checker(
            members=["ferrogate-cli"],
            sources={"ferrogate-cli": self.CLI_SOURCES},
            ci_workflow="jobs:\n  t:\n    run: "
            "cargo test -p ferrogate-cli --test perf -- --nocapture --skip slow_case\n",
            local_runner="cargo test -p ferrogate-cli\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_backslash_continued_command_is_read_as_one_command(self) -> None:
        """`scripts/local-test-modules.sh` splits its longest invocation across

        two lines. Pins `command_lines`: read line-at-a-time, the `-p` and the
        filter land in different strings, the filter half names no member, and
        the gate would report a false failure -- or, with the continuation
        carrying the `-p`, silently exempt the filter."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            sources={"ferrogate-gateway": self.GATEWAY_SOURCES},
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="cargo test -p ferrogate-gateway --all-features \\\n"
            "  governed_decision\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("resolved 1 name filter(s)", result.stdout)

    def test_a_filter_on_a_crate_outside_the_workspace_is_an_error(self) -> None:
        """A filtered `cargo test` naming no member cannot be resolved at all,

        and the honest answer is to fail rather than skip. Pins the `if not
        named` branch: turning it into a `continue` is the shape that let the
        whole class through -- an invocation the gate cannot model, exempted in
        silence."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            sources={"ferrogate-gateway": self.GATEWAY_SOURCES},
            ci_workflow="jobs:\n  t:\n    run: |\n"
            "        cargo test -p ferrogate-gateway\n"
            "        cargo test -p ferrogate-retired governed_decision\n",
            local_runner="cargo test -p ferrogate-gateway\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("names no workspace member", result.stderr)

    def test_the_real_repository_passes_its_own_gate(self) -> None:
        result = subprocess.run(
            ["python3", str(CHECKER)], text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        # ...and passes it over EVERY member, not over however many its own
        # parser happened to read. The count comes from a second, deliberately
        # cruder reading of the same manifest, so a truncation in one is not
        # copied by the other; the floor keeps that second reader from
        # collapsing to a small number in sympathy.
        manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        block = manifest.split("members = [", 1)[1].split("]", 1)[0]
        declared = [line for line in block.splitlines() if '"' in line]
        self.assertGreaterEqual(len(declared), 22, block)
        self.assertIn(
            f"validated {len(declared)} workspace members", result.stdout
        )

    def test_the_real_repository_has_filters_for_the_filter_half_to_check(self) -> None:
        """The filter half is silent when it finds nothing, and "found nothing"

        is indistinguishable from "there is nothing" in the exit code. This
        counts the literal name filters in the tree a second way -- straight
        off the two files that carry them -- and requires the gate to report
        the same number. Break `command_lines`, `cargo_test_name_filters` or
        the `cargo test` scan and the reported count drops while the gate still
        exits 0; that is the shape #553 shipped, one level up."""
        takes_a_value = {"-p", "--test", "--bin", "--bench", "--example", "--features"}
        expected = 0
        for relative in (
            ".github/workflows/governed-decision-conformance.yml",
            ".github/workflows/rust-quality.yml",
            "scripts/local-test-modules.sh",
        ):
            for line in (ROOT / relative).read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped.startswith("cargo test") or "${{" in stripped:
                    continue
                skip = False
                for token in stripped.split()[2:]:
                    if skip:
                        skip = False
                    elif token == "--":
                        break  # everything after belongs to libtest
                    elif token in takes_a_value:
                        skip = True
                    elif not token.startswith("-"):
                        expected += 1
        self.assertEqual(expected, 6, "the filters this repository actually carries")
        result = subprocess.run(
            ["python3", str(CHECKER)], text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"resolved {expected} name filter(s)", result.stdout)


if __name__ == "__main__":
    unittest.main()
