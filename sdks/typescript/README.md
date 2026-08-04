# @ferrogate/admin-sdk

Thin TypeScript client for the FerroGate admin API.

The request and response types are generated from
docs/openapi/admin-api.openapi.json. The runtime client accepts an explicit
base URL and either a bearer token or an x-api-key; it has no ambient
credential or process-state dependency.

Build the vendored package with:

    npm run build
    npm pack --dry-run

The source contract and generated types stay in the repository so a package
consumer can audit the exact API surface used for a build.
