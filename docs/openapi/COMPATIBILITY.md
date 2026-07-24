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
