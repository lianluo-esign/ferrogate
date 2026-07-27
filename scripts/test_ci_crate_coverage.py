#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-27
# description: Tests for the workspace-member CI coverage gate (issue #561).
"""Tests for `scripts/check-ci-crate-coverage.py`.

The gate exists because nothing noticed that a 136k-line crate ran nowhere, so
the one thing these tests must rule out is the gate itself being the next thing
that notices nothing. Every case below is built as a throwaway workspace on
disk and run through the real script, and each negative case is paired with the
positive that differs only in the fact under test.
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
        own."""
        result = self.run_checker(
            members=["ferrogate-gateway"],
            ci_workflow="jobs:\n  t:\n    run: cargo test -p ferrogate-gateway\n",
            local_runner="cargo test -p ferrogate-gateway -- --skip 'issue #563 fixture'\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    # ---- a function nothing dispatches runs for nobody -----------------------

    def test_a_cargo_test_in_an_undispatched_function_is_not_coverage(self) -> None:
        """Review's second dead-code hole: drop the `case` arm and the six

        crates in `run_platform_crates` have no local invocation left, while
        the function -- and its `cargo test` lines -- sit there looking like
        coverage."""
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

    # ---- matrix credit stays inside the job that asked for it ---------------

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


if __name__ == "__main__":
    unittest.main()
