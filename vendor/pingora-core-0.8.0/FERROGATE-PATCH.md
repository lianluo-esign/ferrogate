# FerroGate Pingora Core Patch

This directory is the unmodified source of crates.io `pingora-core` 0.8.0,
except for one dependency constraint in `Cargo.toml` and `Cargo.toml.orig`:

```toml
prometheus = "0.14"
```

The source crate archive has SHA-256
`08973c4853cef4c682f7a592907e81a32dcad69476c4846e5de079f16448b177`
and records upstream Git commit `faac65b0c2a0bfdbfdc5f13a1591f53f3c15321a`.
All files below `src/` are byte-identical to that archive. The following
non-runtime files are intentionally omitted:

- `Cargo.lock`: the upstream crate's standalone development lockfile; the
  FerroGate workspace lockfile is authoritative.
- `examples/keys/client-ca/key.pem`
- `examples/keys/clients/invalid-key.pem`
- `examples/keys/clients/key-1.pem`
- `examples/keys/clients/key-2.pem`
- `examples/keys/server/key.pem`

The five PEM files are private-key fixtures used only when manually running the
upstream `client_cert` example. FerroGate does not build or run that example,
and vendoring private-key material would violate the repository secret-scan
control. Certificates and example source remain for upstream provenance.

`scripts/check-pingora-vendor.py` verifies the crate archive checksum, complete
file set, byte-identical runtime source, the exact removals above, and that the
two manifests contain no change beyond the Prometheus version constraint.

The published crate requires Prometheus 0.13, which pulls `protobuf` 2.28.0
and RUSTSEC-2024-0437 into FerroGate's shipped dependency graph. Prometheus
0.14 uses `protobuf` 3.7.2 or newer. Cloudflare made the same dependency change
upstream in commit `5e7034460f8fb04bccaa1f636d7070ac8b897e90`, but has not
published it in Pingora 0.8.1.

The local path patch avoids running unreleased Pingora runtime changes and
keeps `cargo-deny`'s unknown-Git-source rejection intact. Remove this directory,
the `[patch.crates-io]` entry, and the exact Pingora pin when a released Pingora
version removes `protobuf` 2.x from its production dependency graph.

Tracking: https://github.com/lianluo-esign/ferrogate/issues/218
Upstream: https://github.com/cloudflare/pingora/issues/875
RustSec: https://rustsec.org/advisories/RUSTSEC-2024-0437.html
