# Local image build + GHCR push (no GitHub CI, no sudo, no Docker daemon)

Standing release directive: **do not queue on GitHub Actions**. When the local
`ferrogate-test` full suite is green, build the image locally and push it straight
to GHCR. This doc covers the *no-daemon* path used on the locked-down dev host
(no `sudo`, no Docker/Podman, no setuid `newuidmap`/`newgidmap`).

## Why not Docker / rootless Podman here

The reference `Dockerfile` compiles inside `rust:bookworm` and ships a **glibc**
binary. That requires a container engine:

- Docker Engine / Docker Desktop — needs root (daemon) → no `sudo`, unavailable.
- Rootless Podman/Docker/nerdctl — need `newuidmap`/`newgidmap` (setuid-root) to
  map the `/etc/subuid` range. Those bits can only be set by root, so a userspace
  install can't enable multi-uid rootless. Single-uid mode can't extract the
  `rust` builder image (apt chowns to other uids).

Also: the host glibc is newer than any stable base image (bookworm = 2.36),
so a **native** glibc build here won't run on a standard base anyway.

Since the machine migration (2026-07-18) the dev host is **aarch64**, which rules
out the original musl.cc prebuilt cross-gcc (x86_64-hosted binaries, and musl.cc
ships no aarch64-hosted x86_64 cross). The cross C compiler/linker is now
**zig cc** — a static, host-arch-independent clang driver that targets both
`x86_64-linux-musl` and `aarch64-linux-musl` from any host (#325).

## The path that works: zig-cc musl-static + crane

1. **Cross-compile fully static musl binaries** with `zig cc` as CC/linker. No
   glibc coupling — runs on `scratch`, `distroless`, anything. Both amd64 and
   arm64 build from the aarch64 host.
2. **Assemble the OCI image with `crane`** (google/go-containerregistry) — a static
   Go binary that talks to the registry directly. No daemon, no namespaces, no root.

Run it:

```bash
# dry-run (assemble local OCI tarball(s) ferrogate-<tag>-<arch>.oci.tar, never touch GHCR)
scripts/build-image-crane.sh --tag v2026.07.20 --arch amd64    # default arch
scripts/build-image-crane.sh --tag v2026.07.20 --arch both     # amd64 + arm64

# real push (needs a write:packages token — see below)
GHCR_TOKEN=<PAT> scripts/build-image-crane.sh --tag v2026.07.20 --arch both --push
```

`--arch both --push` pushes `:<tag>-amd64` and `:<tag>-arm64`, then assembles the
multi-arch index for `:<tag>` and `:latest` via `crane index append` (crane cannot
build an index from local tarballs, so the index is created at push time). A
single-arch `--push` pushes `:<tag>`/`:latest` directly, as before.

`scripts/release-local.sh` auto-detects: if `docker` is on PATH it uses the
Dockerfile; otherwise it delegates the image step to `build-image-crane.sh`.

## One-time userspace toolchain setup (no sudo)

All under `$HOME/.local`, no root:

| Piece | How |
|---|---|
| musl std | `rustup +1.88.0 target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl` |
| zig (cross CC/linker) | static tarball from ziglang.org (aarch64-linux, 0.16.0) → `$HOME/.local/zig/zig-aarch64-linux-0.16.0/`, symlinked at `$HOME/.local/zig/zig` (override with env `ZIG`) |
| musl OpenSSL (static, per arch) | OpenSSL 3.5.x source, `CC=scripts/zig-cc-<arch>-musl.sh AR=scripts/zig-ar.sh RANLIB=scripts/zig-ranlib.sh ./Configure linux-<x86_64\|aarch64> no-shared no-tests no-docs --prefix=$HOME/.local/musl-openssl-zig/<x86_64\|aarch64>` then `make -j4 install_sw` (needed by `native-tls` → postgres TLS) |
| crane | `go-containerregistry` release binary → `$HOME/.local/bin/crane` |

The zig invocation goes through the repo wrappers `scripts/zig-cc-x86_64-musl.sh`
/ `scripts/zig-cc-aarch64-musl.sh` (plus `zig-ar.sh`/`zig-ranlib.sh`) because
cargo/cc-rs need CC/linker as a single argv[0] executable with the `-target`
baked in. The wrappers also absorb two clang/zig quirks (test-driven, keep them
minimal): they drop cc-rs's rust-style `--target=` (zig rejects that triple
spelling — hit compiling aws-lc-sys asm), and map `-lgcc_s`/`-lgcc` to
`-lunwind`. On the rustc side the build script passes
`-C link-self-contained=no` so zig supplies CRT + musl libc (rustc's bundled CRT
objects otherwise collide with zig's — duplicate `_start`), and
`-C strip=symbols` (replaces the external musl-strip of the legacy path).

The OpenSSL step matters: `native-tls` (postgres TLS) pulls `openssl-sys`. The
cross env must point the **target-specific** vars at the per-arch musl OpenSSL,
because any host `OPENSSL_INCLUDE_DIR`/`OPENSSL_LIB_DIR` would otherwise win
(`build-image-crane.sh` sets all of this per `--arch`; libdir is `lib64` on
x86_64, `lib` on aarch64 — the script auto-detects):

```
X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_INCLUDE_DIR=$HOME/.local/musl-openssl-zig/x86_64/include
X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR=$HOME/.local/musl-openssl-zig/x86_64/lib64
X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_STATIC=1
AARCH64_UNKNOWN_LINUX_MUSL_OPENSSL_INCLUDE_DIR=$HOME/.local/musl-openssl-zig/aarch64/include
AARCH64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR=$HOME/.local/musl-openssl-zig/aarch64/lib
AARCH64_UNKNOWN_LINUX_MUSL_OPENSSL_STATIC=1
```

Verification is readelf-based (the host has no `file`): correct `Machine`, no
`PT_INTERP`, no dynamic section; plus a native-arch smoke run
(`ferrogate --version`) when the target arch matches the host (arm64 here —
amd64 is verified by ELF inspection only; no qemu on the box).

### Legacy x86_64-host fallback (musl.cc)

The pre-migration path is still auto-detected for `--arch amd64` when
`$HOME/.local/musl/x86_64-linux-musl-cross/` exists (prebuilt musl.cc cross gcc +
static OpenSSL at `$HOME/.local/musl-openssl`). It only works on an x86_64 host
and only for the amd64 image; zig takes precedence when both are installed.

## Push credentials — the only remaining gate

GHCR push requires a token with **`write:packages`**. The dev-host `gh` login has
`repo, workflow, project, read:org, gist` — **not** `write:packages`. Provide one of:

- `export GHCR_TOKEN=<PAT with write:packages>` (classic PAT, `write:packages`), or
- `gh auth refresh -s write:packages` (interactive; opens a browser) then re-run.

Until a `write:packages` token is present, `--push` fails fast and the dry-run
still fully validates the build + image assembly.

## Image contract (parity with the Dockerfile)

- base: `gcr.io/distroless/static-debian12` (ships a CA bundle; we also embed
  `/etc/ssl/certs/ca-certificates.crt` so a `scratch` base would still do TLS)
- `/usr/local/bin/ferrogate`, `/usr/local/bin/ferrogate-auth`
- `/etc/ferrogate/Caddyfile`
- `ENTRYPOINT ["/usr/local/bin/ferrogate"]`, `CMD ["run"]`
- `ENV FERROGATE_CONFIG=/etc/ferrogate/Caddyfile`, `EXPOSE 8080`
- labels: `org.opencontainers.image.{vendor,source,version}`, `cloud.token4ai.build`

## Supply-chain evidence (SBOM + signature + vuln gate, #208)

The local path produces the same *classes* of evidence the CI path did, minus the
GitHub-workflow provenance (see trade-off below):

- **SBOM (SPDX-2.3, syft).** `--sbom` emits `sbom-<tag>.src.spdx.json` (the full
  ~2150-package Rust dependency graph from `Cargo.lock` — the real inventory for a
  static binary) plus a per-arch `sbom-<tag>-<arch>.image.spdx.json` (base +
  embedded binary). Requires `syft` on PATH (not yet reinstalled on the aarch64
  host — the step self-skips until it is).
- **Signature (cosign, local key).** `--sign local-key --cosign-key <key>` produces
  an offline detached signature over each exact OCI artifact
  (`ferrogate-<tag>-<arch>.oci.tar.sig`), no transparency log, no registry.
- **Consumer verification.** `scripts/verify-image-crane.sh` pins to the public key
  and (optionally) the expected artifact digest, checks the SBOM is valid SPDX, and
  **fails on a tampered artifact, wrong key, or missing signature**:
  ```bash
  scripts/verify-image-crane.sh \
    --tarball ferrogate-v2026.07.20-amd64.oci.tar \
    --signature ferrogate-v2026.07.20-amd64.oci.tar.sig \
    --pubkey cosign.pub \
    --digest sha256:<tarball sha256> \
    --sbom sbom-v2026.07.20.src.spdx.json
  ```
- **Dependency vulnerability gate (cargo-audit / RUSTSEC).** Part of the
  `release-local.sh` gate. Where the advisory DB can't be git-fetched, point it at a
  pre-fetched checkout: `CARGO_AUDIT_DB=/path/to/advisory-db`. Current status: **0
  vulnerabilities** over 527 deps; 4 `unmaintained` warnings (transitive via
  `pingora 0.8.0`: e.g. `rustls-pemfile` RUSTSEC-2025-0134).

Build with full evidence in one shot:
```bash
scripts/build-image-crane.sh --tag v2026.07.20 --arch both \
  --sbom --sign local-key --cosign-key cosign.key \
  --artifact-dir ./release-artifacts        # add --push once a write:packages token exists
```

## Key rotation, revocation, exceptions (#208 release governance)

- **Signing key custody.** The local-key path uses a cosign key pair held by the
  release owner. Private key stays off the repo and out of images (never `git add`
  a `*.key`; `COSIGN_PASSWORD` supplies its passphrase). Rotate by
  `cosign generate-key-pair` and distributing the new `cosign.pub` out-of-band;
  consumers pin the new pubkey in `verify-image-crane.sh --pubkey`.
- **Revocation.** To revoke a published tag, delete/yank the GHCR package version
  and publish a superseding digest; announce the bad digest so consumers reject it
  via `--digest`. For the `write:packages` token, revoke the PAT in GitHub settings.
- **Vulnerability exceptions.** A `cargo-audit` finding blocks release by default.
  A time-boxed exception (e.g. an `unmaintained` transitive dep with no fix) is
  recorded in `deny.toml`/`audit.toml` `[advisories] ignore = ["RUSTSEC-YYYY-NNNN"]`
  with an owner + expiry date in a comment; expired ignores must be re-reviewed.
  Current standing exceptions: the 4 `unmaintained` warnings via `pingora 0.8.0`
  (tracked; no upstream fix — revisit on the next pingora bump).
- **Ownership.** Release owner = whoever holds the signing key + `write:packages`
  token; they own rotation cadence and exception expiry review.

## Supply-chain trade-off (see #208)

This path signs (if you opt in) with a **local key**, not the GitHub-workflow
keyless OIDC identity. `scripts/verify-image-supply-chain.sh --mode release` pins
to the CI workflow identity and will therefore reject a locally-built image by
design. That provenance-to-GitHub-workflow guarantee is the price of skipping
GitHub CI. If keyless workflow provenance is ever mandatory, run the existing
`ci-image.yml` on a **self-hosted runner** instead of GitHub-hosted.
