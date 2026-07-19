---
name: ferrogate-release
description: Use when cutting a FerroGate release — building the container image and publishing it to GHCR. Covers the standing directive to NOT use GitHub Actions (too slow) and instead gate on the local ferrogate-test suite then push locally, including the no-sudo/no-Docker host path (musl-static + crane). Use for "release", "publish image", "push to GHCR", "cut a version".
---

# FerroGate Release

**Standing directive (2026-07-19): do NOT release through GitHub Actions.** The
GitHub-hosted `ci.yml` / `ci-image.yml` release pipeline is too slow (15+ min,
one serial failure per run) and blocks dev velocity. Instead:

> local `ferrogate-test` full suite green → build image locally → push straight to GHCR.

## Gate first (non-negotiable)

Never build/push an image until the local gate is green:

```bash
source $HOME/.local/tcbin/rust-env.sh
cargo +1.88.0 fmt --check
cargo +1.88.0 clippy --workspace --all-targets --all-features -- -D warnings
cargo +1.88.0 test --workspace
cargo +1.88.0 build --release -p ferrogate-test && ./target/release/ferrogate-test ci
```

On the ~6 GB dev box a full-workspace test/clippy link can OOM — scope to the
crates you touched (`-p ...`) when iterating; run the full suite for the actual
release gate. See the `ferrogate-test` / `ferrogate-test-strategy` skills.

## Build + push

One entry point, auto-detects the engine:

```bash
scripts/release-local.sh --tag vYYYY.MM.DD --push          # full gate + build + push
scripts/release-local.sh --tag vYYYY.MM.DD                 # dry-run (no push)
scripts/release-local.sh --tag vYYYY.MM.DD --skip-tests --push   # image only (gate already run)
```

- **Host has Docker** → uses the reference `Dockerfile` (glibc, builds in `rust:bookworm`).
- **No Docker / no sudo** → falls back to `scripts/build-image-crane.sh`: a fully
  static **musl** binary packaged into an OCI image with **crane** — no daemon, no
  root, no namespaces. This is the path on the locked-down dev host. Full setup and
  rationale: `docs/release/local-image-build.md`.

## The credential gate

GHCR push needs a token with **`write:packages`**. The dev-host `gh` login lacks
it (only `repo/workflow/project/read:org/gist`). Supply one of:

- `export GHCR_TOKEN=<classic PAT with write:packages>`, or
- `gh auth refresh -s write:packages` (interactive) then re-run.

Without it, `--push` fails fast; the dry-run still fully validates build + assembly.

## Supply-chain trade-off (#208)

Local signing uses your **own key**, not the GitHub-workflow keyless OIDC identity,
so `scripts/verify-image-supply-chain.sh --mode release` (pinned to the CI workflow
identity) will reject a locally-built image *by design*. That is the accepted price
of skipping GitHub CI. If keyless workflow provenance is ever mandatory, run
`ci-image.yml` on a **self-hosted runner** — never fabricate provenance.

## Checklist

1. Local gate green (fmt + clippy + workspace tests + `ferrogate-test ci`).
2. Pick `--tag vYYYY.MM.DD` (date-based).
3. Dry-run first; confirm image config (entrypoint `/usr/local/bin/ferrogate run`,
   `EXPOSE 8080`, `FERROGATE_CONFIG`).
4. Ensure a `write:packages` token; `--push`.
5. Verify the published digest (`crane digest ghcr.io/<owner>/ferrogate:<tag>`).
6. Do NOT cut a GitHub Release for routine releases.
