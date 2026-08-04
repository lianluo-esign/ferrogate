# ferrogate-admin

Thin, standard-library-only Python client for the FerroGate admin API.

The generated operation catalog is derived from
docs/openapi/admin-api.openapi.json. Use AdminClient.request_operation with
an OpenAPI operationId, or use the lower-level verb methods when an endpoint
needs a custom call shape.

Build a vendored wheel and source archive from this directory with:

    python -m build --wheel --sdist

The package does not publish to PyPI as part of repository CI.
