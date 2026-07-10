# API Contract And Compatibility

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
4. Run the Python contract tests and generated TypeScript client smoke.
5. For an intentional breaking change, document migration impact in the issue
   and commit, then replace the compatibility baseline with the reviewed
   OpenAPI document in the same change.

Updating the baseline only silences the mechanical compatibility alarm. It is
not evidence that a breaking change was reviewed.
