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

Also: the host glibc (2.43) is newer than any stable base image (bookworm = 2.36),
so a **native** glibc build here won't run on a standard base anyway.

## The path that works: musl-static + crane

1. **Cross-compile a fully static musl binary.** No glibc coupling — runs on
   `scratch`, `distroless`, anything.
2. **Assemble the OCI image with `crane`** (google/go-containerregistry) — a static
   Go binary that talks to the registry directly. No daemon, no namespaces, no root.

Run it:

```bash
# dry-run (assemble to a local OCI tarball, never touch GHCR)
scripts/build-image-crane.sh --tag v2026.07.19

# real push (needs a write:packages token — see below)
GHCR_TOKEN=<PAT with write:packages> scripts/build-image-crane.sh --tag v2026.07.19 --push
```

`scripts/release-local.sh` auto-detects: if `docker` is on PATH it uses the
Dockerfile; otherwise it delegates the image step to `build-image-crane.sh`.

## One-time userspace toolchain setup (no sudo)

All under `$HOME/.local`, no root:

| Piece | How |
|---|---|
| musl std | `rustup +1.88.0 target add x86_64-unknown-linux-musl` |
| musl cross gcc | prebuilt `x86_64-linux-musl-cross.tgz` (musl.cc) → `$HOME/.local/musl/` |
| musl OpenSSL (static) | build `openssl` with `--cross-compile-prefix=x86_64-linux-musl-` `no-shared` → `$HOME/.local/musl-openssl` (needed by `native-tls` → postgres TLS) |
| crane | `go-containerregistry` release binary → `$HOME/.local/bin/crane` |

The OpenSSL step matters: `native-tls` (postgres TLS) pulls `openssl-sys`. The
cross env must point the **target-specific** vars at the musl OpenSSL, because
`rust-env.sh` exports host-gnu `OPENSSL_INCLUDE_DIR`/`OPENSSL_LIB_DIR` that would
otherwise win:

```
X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_INCLUDE_DIR=$HOME/.local/musl-openssl/include
X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_LIB_DIR=$HOME/.local/musl-openssl/lib64
X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_STATIC=1
```

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

## Supply-chain trade-off (see #208)

This path signs (if you opt in) with a **local key**, not the GitHub-workflow
keyless OIDC identity. `scripts/verify-image-supply-chain.sh --mode release` pins
to the CI workflow identity and will therefore reject a locally-built image by
design. That provenance-to-GitHub-workflow guarantee is the price of skipping
GitHub CI. If keyless workflow provenance is ever mandatory, run the existing
`ci-image.yml` on a **self-hosted runner** instead of GitHub-hosted.
