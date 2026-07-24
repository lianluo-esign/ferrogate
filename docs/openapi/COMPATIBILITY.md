# API Contract And Compatibility

This document is the machine-readable contract for the **FerroGate Control
Plane API** (issue #359) — the supported, externally consumable REST surface.
*Public* means supported and externally consumable, not unauthenticated. The
`admin-api` command/config/`/admin/v1` names are a documented, deprecated
compatibility alias for the migration window; the OpenAPI `info.title` is
"FerroGate Control Plane API" while the artifact file name stays
`admin-api.openapi.json` for path compatibility.

Operations promoted into the versioned public-stable surface carry
`x-ferrogate-stability: "stable"` and are enumerated in the document's
top-level `x-ferrogate-control-plane` block. Their typed source of truth lives
in the `ferrogate_admin::control_plane` module and is pinned against this
document by `crates/ferrogate-admin/src/control_plane_test.rs`. Stable
operations may only change in backward-compatible ways, enforced by the
compatibility baseline below.

## URI aliases (`/control/v1`)

The stable surface is served under two URI prefixes: the compatibility prefix
`/admin/v1` and the canonical alias `/control/v1` (issue #453). A request under
`/control/v1` is normalized onto the identical `/admin/v1` operation at request
ingress — before routing, authentication, `admin.read`/`admin.write` scope
enforcement, tenant isolation, CSRF, rate limits, request-id assignment, audit
evidence, error handling, and pagination — so both prefixes dispatch through one
route contract with no duplicated handlers and byte-identical behavior. The
single normalization is `ferrogate_admin::control_plane::canonicalize_alias_path`
(one source of truth), applied by both the in-process gateway ingress and the
standalone Control Plane API reverse proxy. `/admin/v1` stays stable and
unchanged for the compatibility window.

Because normalization happens before contract matching, the alias adds **no**
new operations to `runtime-api-contract.json` or `admin-api.openapi.json`: the
runtime/OpenAPI operation contract stays 1:1. The alias is documented in the
OpenAPI `x-ferrogate-control-plane.uri_aliases` block and proven by dual-path
parity tests (`crates/ferrogate-cli/tests/control_plane_uri_alias_e2e.rs`) that
assert identical behavior across both prefixes.

FerroGate's fixed HTTP API has three checked-in contract surfaces:

- `runtime-api-contract.json` is embedded into `ferrogate-cli`. It owns fixed
  route-group dispatch, allowed methods, stable operation IDs, visibility,
  authentication scope, and optional database permission action keys.
- `admin-api.openapi.json` owns public request and response schemas. Every
  operation repeats the runtime classification in `x-ferrogate-contract` so
  drift is visible to tooling and generated clients.
- `admin-api.compatibility-baseline.json` is the last reviewed compatible
  contract. Removing operations or schemas, changing operation IDs, narrowing
  enums, or changing existing request/response shapes fails validation.

`python3 scripts/check-openapi.py` compares runtime and OpenAPI operations in
both directions. A fixed route cannot execute unless its path and method are in
the embedded registry. Operator-configured reverse-proxy routes remain data and
are explicitly listed under `dynamic_surfaces`; they are not part of the stable
FerroGate API.

## Change Process

1. Add or change the runtime operation and OpenAPI schema together.
2. Keep `operationId` stable after publication.
3. Classify the operation as `public`, `admin`, or `internal`; document the
   actual auth scope. `rbac_action` may contain a database permission action
   key, never a role name. Roles and tenant bindings remain database data.
   Runtime **data-plane** operations (OpenAI-compatible inference, MCP/tool
   execution, and agent-runtime invoke/messaging — `invokeAgent`,
   `sendAgentMessage`, `streamAgentMessage`) stay `public` — they are publicly
   reachable — but additionally carry the operation-level
   `x-ferrogate-data-plane: true` marker. This is an
   orthogonal axis to `visibility`: it moves the operation off the Control-Plane
   CLI parity surface (they move AI traffic, not configuration), so the
   OpenAPI-to-CLI parity gate does not require a management verb for them
   (issue #390). The marker lives only in `admin-api.openapi.json`; it does not
   change the runtime `visibility` recorded in `runtime-api-contract.json`.
4. Run the Python contract tests and generated TypeScript client smoke.
5. For an intentional breaking change, document migration impact in the issue
   and commit, then replace the compatibility baseline with the reviewed
   OpenAPI document in the same change.

Updating the baseline only silences the mechanical compatibility alarm. It is
not evidence that a breaking change was reviewed.
