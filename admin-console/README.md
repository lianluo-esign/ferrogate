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
