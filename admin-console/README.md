# FerroGate Admin Console

A standalone Vite + React + TypeScript + Tailwind + shadcn/ui single-page app
that covers FerroGate's control plane: tenant/project/workspace hierarchy,
API/virtual keys, quota policies, gateway configuration (providers, models,
agent upstreams/workflows, skill packages, prompt templates, plugins, MCP
servers), infrastructure (self-hosted/managed workers), and observability
(request logs, audit events, usage reports, billing events).

The TypeScript control plane serves the console and the admin/session API from
one origin. The console also calls the gateway for data-plane resources such
as assets, agent jobs, MCP identity and published sites:

- The control plane's session endpoints (`/v1/admin/register|login|refresh|logout|me`)
  and Admin API (`/admin/v1/*`).
- The gateway's data-plane endpoints (`/v1/*` and `/sites/*`) when a page needs
  assets, jobs, MCP identity or published site content.

## Toolchain (#508)

Node 22+ (see [`Dockerfile`](./Dockerfile)). On the dev boxes Node is installed
under `$HOME` and is **not** always on a non-login shell's `PATH`:

```bash
command -v node || ls -d "$HOME"/.local/share/node/*/bin "$HOME"/toolchain/node/*/bin
export PATH="<that bin dir>:$PATH"
```

`npm`/`npx` are `#!/usr/bin/env node` shebang scripts, so calling them by
absolute path from a shell without `node` on `PATH` fails with
`env: 'node': No such file or directory`. That means *node is off `PATH`*, not
*node is missing* — do not conclude the toolchain is broken.

`node_modules` is **not** checked in (gitignored, ~500MB, platform-specific), so
`npm ci` from the committed `package-lock.json` is the required first step on a
fresh checkout. `scripts/check-admin-console.sh` runs it for you when
`node_modules` is absent, finds Node itself via `scripts/node-env.sh` (override
with `FERROGATE_NODE_BIN=<bin dir>`), and exits non-zero with
`admin-console gate did NOT run: node not found on PATH` rather than skipping
when it cannot. `scripts/test-check-admin-console.sh` holds that contract.

## Local development

```bash
npm ci                       # required first step on a fresh checkout
cp .env.example .env.local   # point at your local control plane + gateway
npm run dev
```

Run a control-plane Worker and a gateway Worker on the targets configured by
`.env.local`. The Vite proxy keeps browser requests on the console origin.

## Build

```bash
npm run typecheck   # tsc -b on its own, for a fast type-only signal
npm run build       # tsc -b && vite build && check:bundle, output in dist/
```

## OpenAPI client types (drift guard, #392)

`src/lib/api-types.generated.ts` is the typed client, generated from the
committed contract `docs/openapi/admin-api.openapi.json`:

```bash
bun run generate          # PREFERRED, from the repo root: every generated client at once
npm run generate:api      # the same thing for this client only
```

Both go through `tools/generated-clients/`, which since #766 owns the generator
invocation and the banner for every client generated from that document — this
console's and `sdks/typescript`'s. Two private pipelines are what let one be
regenerated and the other forgotten.

Stale-but-still-compilable types slip past `tsc`, so a spec change that lands
without regenerating silently drifts the client (the regression #379 had to
clean up). `npm run check:api-types` guards against that: it renders the
contract into an OS temp file (never touching the committed file) and fails
when the result differs from the checked-in `api-types.generated.ts`:

```bash
npm run check:api-types   # exit 1 + "run `bun run generate` and commit" on drift
```

It runs as a step in `scripts/check-admin-console.sh` (the local/release gate).
It is ALSO run, on the same code, by root `bun run test` via
`tools/generated-clients/test/drift.test.mjs` — because this package is not a
Bun workspace, its own guard was unreachable from the repo root and this client
went stale twice without a report (#736, #737). A guard nothing runs is not a
guard.

## Lint

```bash
npm run lint   # eslint . — CI runs this via scripts/check-admin-console.sh
```

### Authoring i18n copy

Key naming, namespace ownership (and why `bootstrap` vs `rest` is a bundle
boundary), the Simplified Chinese glossary, what must NOT be translated, and the
add-a-locale procedure live in
[`docs/admin-console-i18n.md`](../docs/admin-console-i18n.md). The glossary is
executable — `src/i18n/glossary.ts` + `glossary.test.ts` fail the suite when a
term gains a second Chinese rendering.

### i18n regression guard (`ferrogate/no-untranslated-literal`, #380)

`npm run lint` rejects **newly introduced** hard-coded operator-facing strings
so the surfaces migrated to `@/i18n` (#348) cannot regress to non-localized
literals. The rule (`eslint-rules/no-untranslated-literal.js`) flags JSX text
and operator-facing string props (`placeholder`, `title`, `alt`, `aria-label`,
`label`, `description`, ...) that are bare literals instead of `t("<key>")`.

It is scoped so the gate is green today without a full-console migration:

- It runs on **every `src/**/*.{ts,tsx}` by default**, so any *new* file is
  guarded automatically. Tests and the `src/i18n/` catalogs are excluded.
- Pages/components #348 has **not migrated yet** are listed in the
  `I18N_UNMIGRATED_ALLOWLIST` in [`eslint.config.js`](./eslint.config.js). This
  is a shrinking baseline, not a permanent exemption.

Adding or removing an exception:

- **Migrating a file** — route its copy through `t()` with catalog keys and
  delete its glob from the allowlist so it is guarded again.
- **A single non-copy literal** the heuristic misfires on (a brand mark, an
  illustrative example value) — prefer an inline
  `// eslint-disable-next-line ferrogate/no-untranslated-literal -- <reason>`
  over listing the whole file.
- **A new page that genuinely cannot be localized yet** — add its glob to the
  allowlist *with a one-line justification in review*. New files are guarded by
  default so this stays a conscious, reviewed decision.

## Browser contract

The Playwright suite runs against deterministic browser-side Admin API mocks;
it does not require a local gateway or auth service. Install Chromium once on a
new machine, then run the contract:

```bash
npm ci
npm run test:e2e:install
npm run test:e2e
```

The suite covers Chromium at 390x844, 768x1024, and 1440x900. It fails on
uncaught page/console errors, document-level horizontal overflow, and critical
axe violations, and attaches viewport screenshots plus axe JSON to the local
Playwright report. Known serious accessibility defects are tightened to a
failing threshold by #334 after those defects are fixed.

## Docker / production

### The supported shape: same origin as the control plane

```bash
# Configure the gateway Worker with the exact console origin (no wildcard):
# GATEWAY_CORS_ALLOWED_ORIGIN=https://control-plane.example.com
VITE_GATEWAY_BASE_URL=https://gateway.example.com \
  scripts/build-admin-console.sh        # from the repo root
cd apps/control-plane && wrangler deploy
```

`scripts/build-admin-console.sh` builds this app into
`apps/control-plane/public/`, which that Worker serves as Workers Static
Assets. `VITE_GATEWAY_BASE_URL` is required for this deployment shape because
the control-plane Worker does not serve gateway data-plane paths. The console
still uses the control-plane origin for browser mutations; the gateway URL is
only baked into data-plane request routing.

When the gateway is a separate Worker, set its `GATEWAY_CORS_ALLOWED_ORIGIN`
to the exact origin serving this console. The gateway then answers browser
preflights and data-plane responses for that origin only; leaving it unset is
appropriate for the container image because nginx keeps those requests
same-origin.

That is a **correctness requirement**, not a packaging choice. The control
plane answers `403 cross_site_admin_denied` to any state-changing request
carrying `sec-fetch-site: cross-site`, and its CORS preflight surface covers
`/admin/` only -- so a console on a second origin cannot write, and cannot even
log in (`OPTIONS /v1/admin/login` 404s, so the browser never sends the POST).
`src/lib/config.ts` carries the full write-up.

### The container image

```bash
docker build -t ferrogate-admin-console .
docker run --rm -p 8081:8080 \
  -e CONTROL_PLANE_BASE_URL=https://control-plane.example.com \
  -e GATEWAY_BASE_URL=https://gateway.example.com \
  ferrogate-admin-console
```

The image serves the built SPA from nginx. Set `CONTROL_PLANE_BASE_URL` and
`GATEWAY_BASE_URL` to absolute upstream origins. The entrypoint generates
same-origin nginx proxy locations for `/admin/v1`, `/control/v1`, `/v1/admin`,
`/scim/v2`, `/v1/*` and `/sites/*`, so the browser never sends a control-plane
mutation cross-origin.

`CONTROL_PLANE_BASE_URL` and `GATEWAY_BASE_URL` are available as container env
vars and are used by `render-env-config.sh` at container start
(`docker-entrypoint.d/` hook) to generate the nginx upstreams. The generated
`env-config.js` points both client origins at the console itself.
`ADMIN_API_BASE_URL` and `GATEWAY_ADMIN_BASE_URL` remain renderer fallbacks for
older Kubernetes images.

The old `AUTH_BASE_URL` name is no longer used by the client. The old
`GATEWAY_ADMIN_BASE_URL` name is retained only as a runtime compatibility
fallback; new deployments should use the two explicit variables above.

Kubernetes: [`deploy/kubernetes/admin-console.yaml`](../deploy/kubernetes/admin-console.yaml)
or the optional `adminConsole.*` Helm values in
[`charts/ferrogate`](../charts/ferrogate).
