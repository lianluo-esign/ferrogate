# Standalone FerroGate Control Plane API service (`ferrogate control-api serve`)

> **Naming — FerroGate Control Plane API (issue #359).** This service is the
> **FerroGate Control Plane API**: the supported, externally consumable REST
> surface for managing FerroGate resources. *Public* means supported and
> externally consumable — **not** unauthenticated: authentication,
> `admin.read`/`admin.write` scope enforcement, tenant isolation, CSRF rules
> where browser sessions apply, rate limits, request IDs, and audit evidence
> remain mandatory. OpenAPI (`docs/openapi/admin-api.openapi.json`) is the
> machine-readable contract for the service; it is not the service's product
> name.
>
> **Canonical entrypoints:** launch it with `ferrogate control-api serve` and
> configure it under the `[control_api]` section. The `admin-api` name — the
> `ferrogate admin-api serve` command and the `[admin_api]` config section (plus
> the `FERROGATE_ADMIN_*` environment names and the `/admin/v1` path prefix) —
> is retained as a **documented, deprecated compatibility alias** for the
> migration window. `admin-api serve` still works and prints an actionable
> deprecation notice; `[admin_api]` still loads (with a deprecation log) and
> maps 1:1 onto `[control_api]`. **Setting both `[control_api]` and `[admin_api]`
> is rejected at load** with a clear error rather than silently picking one. The
> stable `/admin/v1` paths are unchanged, so existing admin clients keep working
> byte-for-byte.
>
> **Stability contract.** Operations promoted into the versioned public-stable
> surface carry `x-ferrogate-stability: "stable"` in the OpenAPI document and
> are enumerated in the top-level `x-ferrogate-control-plane` block. The typed
> source of truth is `ferrogate_admin::control_plane` (crate
> `crates/ferrogate-admin`), pinned against the OpenAPI document by
> `crates/ferrogate-admin/src/control_plane_test.rs`. A promoted operation's
> path, method, `operationId`, auth scope, and request/response schema may only
> change in backward-compatible ways; the compatibility baseline gate
> (`scripts/check-openapi.py` against
> `docs/openapi/admin-api.compatibility-baseline.json`) enforces this.
>
> **Promoted this slice:** the full `guardrail-policies` lifecycle (list, read,
> revision history, create-revision, activate, rollback, dry-run, archive — 10
> operations). Promotion is *additive*: these keep their `/admin/v1` paths and
> their `admin` runtime visibility / admin-scope enforcement; the stability
> marker is an external supportability promise, not a relaxation of auth.
>
> **Delivered in this slice of #359** (additive, non-breaking): the canonical
> `ferrogate control-api serve` command; the `admin-api serve` deprecation
> notice; the non-breaking `[admin_api]` → `[control_api]` config migration with
> explicit rejection of a conflicting old+new configuration; and the
> Control Plane API product naming across CLI help, startup logs, and the
> service's own `/healthz` evidence.
>
> **Deferred to later slices of #359** (tracked on the open issue): a second URI
> namespace alias such as `/control/v1` (only allowed once both paths are
> generated from one route contract with tested behavior parity); promotion of
> the remaining admin resource families; and the end-to-end acceptance flow
> (Admin Console login + resource CRUD + CLI read/mutation) proven through the
> canonical service, which is the test gate's box.

Issue #315. The admin console used to call the gateway's `/admin/v1/*`
surface directly, which meant admin control-plane traffic rode the same
process, listener, and route table as the AI data plane. `ferrogate
admin-api serve` is a dedicated admin-console API service following the
same decomposition pattern as `ferrogate auth serve` and `ferrogate
billing serve`: the same binary, its own HTTP(S) listener, its own config
section, sharing the durable Supabase/Postgres control plane.

## What it is

An **authenticated reverse proxy** in front of the gateway's admin
surface:

- Path-compatible: `/admin/v1/*` (plus `/admin/status`) and the console's
  asset page surface `/v1/assets*` are forwarded verbatim to the gateway
  configured in `admin_api.gateway_url`; responses stream back untouched,
  so the console only changes its base URL.
- Fail-closed auth **before** any forwarding: every request must present a
  virtual API key (`Authorization: Bearer` or `x-api-key`) that resolves
  against the same sources the gateway itself uses — the shared durable
  storage backend (`[storage]`), the static `[[api_keys]]` list, or the
  external auth service (`[auth_service]`) — and hold the same scope the
  gateway would demand (`admin.read` for GET/HEAD, `admin.write` for
  mutations; `assets.read`/`assets.write` on the asset surface). The scope
  semantics are shared code with the gateway (`scope_set_allows`), not a
  re-implementation.
- The AI data plane is **not** served: `/v1/chat/completions` and every
  other non-admin path answer 404 at this listener.
- The service refuses to start with no credential source at all — it can
  never be an open proxy.
- Request bodies are capped per path family from the shared `[limits]`
  section (#312) using the loosest cap the gateway applies for that
  family, and are never logged.

Why a proxy and not re-mounted handlers: the gateway's admin handlers are
written directly against the Pingora `Session` (request I/O and response
writing), so re-mounting them on a second transport requires extracting a
response-writing seam across every admin handler module. The proxy slice
ships the process/listener separation now with identical behavior; the
gateway remains the single enforcement authority for per-resource tenant
scoping (#185/#186), quotas, and budgets on the forwarded request —
defense in depth rather than a second implementation that could drift.
In-process handler mounting remains a follow-up that would not change
this service's config or URL contract.

## Configuration

The service loads the **same config file as the gateway** (shared
`[[api_keys]]`, `[storage]`, `[limits]`) plus its own section:

```toml
[control_api]
listen = "127.0.0.1:8095"              # default
gateway_url = "http://127.0.0.1:8080"  # internal gateway base URL (http:// only)
upstream_timeout_millis = 30000
# cors_allowed_origin = "https://admin.example.com"
# tls_cert_path = "./certs/control-api.crt"  # optional listener TLS,
# tls_key_path  = "./certs/control-api.key"  # both paths together
```

The deprecated `[admin_api]` section is still accepted for the migration window
and maps field-for-field onto `[control_api]`; using it logs a deprecation
notice. Setting **both** `[control_api]` and `[admin_api]` is rejected at load
with a clear error (never silently resolved) — keep only one, and prefer
`[control_api]`.

Run it (canonical):

```sh
ferrogate control-api serve --config Ferrogate/ferrogate.toml
```

`ferrogate admin-api serve` remains a deprecated alias that behaves identically
and prints a deprecation notice pointing at `control-api serve`.

`GET /healthz` answers locally (`{"service":"ferrogate-control-plane-api"}`) and
is intentionally not part of the gateway's OpenAPI contract.

`gateway_url` is `http://` only, mirroring `auth_service.endpoint`: the
proxied hop is an internal service-to-service call. Terminate public TLS
on the listener (`tls_cert_path`/`tls_key_path`) or at an Ingress.

CORS: the OPTIONS preflight is answered locally (a preflight carries no
Authorization header, so it never hits the auth gate); real responses
carry the gateway's own CORS headers, so set the gateway's
`admin.cors_allowed_origin` and `control_api.cors_allowed_origin` (or the
deprecated `admin_api.cors_allowed_origin`) to the same console origin.

Note on memory-only storage: with `storage.provider = "memory"` there is
no shared durable backend, so virtual keys minted at runtime inside the
gateway process are not visible to this service (static `[[api_keys]]`
still are). A production admin-console deployment always uses the shared
Supabase/Postgres backend, where durable keys resolve identically in both
processes.

## Console wiring

The console reads `ADMIN_API_BASE_URL` (rendered into `env-config.js` by
`admin-console/render-env-config.sh`) and prefers it over the legacy
`GATEWAY_ADMIN_BASE_URL`, which remains a backward-compatible fallback.
Kubernetes manifests: `deploy/kubernetes/admin-api.yaml` runs the service
against the shared `ferrogate-config` ConfigMap; the admin-console
Deployment (and the Helm chart's `adminConsole.env.adminApiBaseUrl`
value) points the console at it.

## Tests

- `crates/ferrogate-cli/src/admin_api_test.rs` — route classification
  (data plane refused), scope mapping, `[limits]` cap resolution, and the
  fail-closed auth gate (401/403 codes identical to the gateway).
- `crates/ferrogate-cli/tests/admin_api_service_e2e.rs` — gateway +
  Control Plane API as real processes: console-shaped create/list with
  byte-equal parity vs the gateway, cross-tenant denial through the proxy
  (#185), data-plane 404, and a dead-upstream proof that 401/403/413 are
  produced by the Control Plane API layer itself before any forwarding. Also
  covers the canonical `control-api serve` + `[control_api]` startup/gate path
  (`control_api_command_and_config_section_start_and_gate`), the deprecated
  `admin-api serve` fail-closed path, and the conflicting-`[control_api]`+
  `[admin_api]` startup rejection.
- `crates/ferrogate-cli/src/config/validation_tests.rs` — `[control_api]`
  (new-only), `[admin_api]` alias (old-only, maps identically), the
  both-present conflict rejection, and migration idempotency.
- `crates/ferrogate-cli/src/cli.rs` (`cli_parse_tests`) — the canonical
  `control-api serve` command and the deprecated `admin-api serve` alias both
  parse; the clap command tree is valid.
