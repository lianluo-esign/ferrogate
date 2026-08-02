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

- The deployable Workers and the `ferrogate` CLI under `apps/`.
- The shared libraries under `packages/`.
- The D1 migrations under `sql/d1-ts/`.
- The route contract and admin OpenAPI documents under `docs/openapi/`.
- The admin console (`admin-console/`).

Out of scope:

- Vulnerabilities in third-party upstream AI providers, in Cloudflare platform
  services, or in other operator-supplied infrastructure.
- Findings that require an operator to have already misconfigured a documented
  security control — in particular, deploying with a dev-posture variable that
  [`docs/rewrite/CLOUD-VERIFICATION.md`](docs/rewrite/CLOUD-VERIFICATION.md)
  §0 requires be overridden (for example `GATEWAY_DEV_AUTH`,
  `FG_DEV_IN_MEMORY_PORTS`, or `FG_REQUIRE_PRODUCTION_MTLS`).

## Supply-Chain Controls

Dependencies are resolved by Bun from the committed `bun.lock`. The repository
ships a high-confidence secret scan over every tracked authored file,
`scripts/check-secret-scan.sh`, which fails loudly rather than skipping when
neither `rg` nor `git grep` is available. Alongside it, `bun run typecheck`
(`tsc --noEmit`), `bun run lint` (Biome) and `bun run test` run offline against
the real local `workerd`.

No account id, database uuid, bucket name or secret is committed: every such
value in `apps/*/wrangler.toml` is a placeholder supplied at deploy time, and
per-tenant IdP credentials are stored as `env://` references rather than as
values.

[`docs/security-controls.md`](docs/security-controls.md) maps shipped
capabilities to common security-review control families. It predates the
TypeScript implementation and describes the earlier system, so treat
[`docs/rewrite/`](docs/rewrite/) and the contracts under
[`docs/openapi/`](docs/openapi/) as authoritative where they disagree.
