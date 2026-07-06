# Security Policy

## Supported Versions

FerroGate ships date-based releases from the `main` branch. Only the latest
released version and `main` receive security fixes. There is no long-term
support branch today; operators should track releases and upgrade promptly
when a security fix lands.

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately — do not open a
public GitHub issue.

- Preferred: use [GitHub's private vulnerability reporting](https://github.com/lianluo-esign/ferrogate/security/advisories/new)
  for this repository ("Security" tab → "Report a vulnerability").
- Alternative: email `security@token4ai.cloud` with a description of the
  issue, affected version/commit, and reproduction steps.

We will acknowledge new reports within 3 business days and aim to provide a
remediation timeline within 10 business days of confirming the issue.
Coordinated disclosure is preferred — please allow us to ship and release a
fix before public disclosure.

## Scope

In scope:

- The `ferrogate` binary and all workspace crates under `crates/`.
- The admin console (`admin-console/`).
- Deployment manifests under `deploy/` and `charts/`.

Out of scope:

- Vulnerabilities in third-party upstream AI providers, Supabase, or other
  operator-supplied infrastructure.
- Findings that require an operator to have already misconfigured a
  documented security control (e.g. running with `insecure_skip_verify: true`
  intentionally set).

## Supply-Chain Controls

Every change is gated by `scripts/security-check.sh`, which runs `cargo fmt`,
`cargo clippy -D warnings`, a locked-metadata check, a high-confidence secret
scan, `cargo deny check licenses bans sources`, and `cargo audit`. CI enforces
the full strict gate (`FERROGATE_SECURITY_REQUIRE_TOOLS=1`) on every change —
see [`.github/workflows/rust-quality.yml`](.github/workflows/rust-quality.yml).

See [`docs/security-controls.md`](docs/security-controls.md) for a mapping of
shipped capabilities to common security-review control families.
