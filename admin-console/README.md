# FerroGate Admin Console

A standalone Vite + React + TypeScript + Tailwind + shadcn/ui single-page app
that covers the gateway's control plane: tenant/project/workspace hierarchy,
API/virtual keys, quota policies, gateway configuration (providers, models,
agent upstreams/workflows, skill packages, prompt templates, plugins, MCP
servers), infrastructure (self-hosted/managed workers), and observability
(request logs, audit events, usage reports, billing events).

It is deployed as its own service, separate from the gateway and the auth
service, and talks to both over HTTP:

- `ferrogate-auth`'s admin-console endpoints (`/v1/admin/register|login|refresh|logout|me`)
  for human login/registration and session management.
- The gateway's Admin API (`/admin/v1/*`) for everything else, authenticated
  with a virtual API key minted by the auth service on register/login.

## Local development

```bash
npm install
cp .env.example .env.local   # point at your local auth service + gateway
npm run dev
```

Both backends need to be pointed at the **same** Postgres schema (see
`--admin-jwt-secret`'s doc comment on `ferrogate auth serve`) and the gateway
needs `admin.cors_allowed_origin` set to this app's origin (`--cors-allowed-origin`
equivalent is `FERROGATE_AUTH_CORS_ALLOWED_ORIGIN` on the auth service; the
gateway reads `admin.cors_allowed_origin` from its own config file) so the
browser is allowed to call `/admin/v1/*` cross-origin.

## Build

```bash
npm run build   # tsc -b && vite build, output in dist/
```

## OpenAPI client types (drift guard, #392)

`src/lib/api-types.generated.ts` is the typed client, generated from the
committed contract `docs/openapi/admin-api.openapi.json`:

```bash
npm run generate:api      # openapi-typescript + stamp banner -> api-types.generated.ts
```

Stale-but-still-compilable types slip past `tsc`, so a spec change that lands
without regenerating silently drifts the client (the regression #379 had to
clean up). `npm run check:api-types` guards against that: it replays
`generate:api` into an OS temp file (never touching the committed file) and
fails when the result differs from the checked-in `api-types.generated.ts`:

```bash
npm run check:api-types   # exit 1 + "run `npm run generate:api` and commit" on drift
```

It runs as a step in `scripts/check-admin-console.sh` (the local/release gate),
so any contract change must regenerate the client types to pass.

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

```bash
docker build -t ferrogate-admin-console .
docker run --rm -p 8081:8080 \
  -e AUTH_BASE_URL=https://auth.ferrogate.example.com \
  -e GATEWAY_ADMIN_BASE_URL=https://ferrogate.example.com \
  ferrogate-admin-console
```

The dev-server env vars above (`VITE_AUTH_BASE_URL`/`VITE_GATEWAY_ADMIN_BASE_URL`)
are Vite build-time values, baked into the JS bundle by `npm run build` --
they can't be changed without a rebuild. The Docker image instead reads plain
`AUTH_BASE_URL`/`GATEWAY_ADMIN_BASE_URL` container env vars and renders them
into `/env-config.js` at container start (`render-env-config.sh`, installed
as an nginx `docker-entrypoint.d/` hook), which `index.html` loads before the
app bundle and `src/lib/config.ts` prefers over the Vite build-time value.
This lets the same image serve dev/staging/prod with different backend URLs.

Kubernetes: [`deploy/kubernetes/admin-console.yaml`](../deploy/kubernetes/admin-console.yaml)
or the optional `adminConsole.*` Helm values in
[`charts/ferrogate`](../charts/ferrogate).
