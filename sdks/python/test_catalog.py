"""The generated Python operation catalog is load-bearing for the thin client."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ferrogate_admin import AdminClient, HttpResponse  # noqa: E402
from ferrogate_admin.api.generated import (  # noqa: E402
    OPENAPI_OPERATION_COUNT,
    OPERATIONS,
)


REQUIRED_ADMIN_OPERATIONS = {
    "listProjects",
    "createProject",
    "getProject",
    "replaceProject",
    "updateProject",
    "deleteProject",
    "listAdminApiKeys",
    "createAdminApiKey",
    "getAdminApiKey",
    "putAdminApiKey",
    "patchAdminApiKey",
    "deleteAdminApiKey",
    "listVirtualKeys",
    "createVirtualKey",
    "getVirtualKey",
    "revokeVirtualKey",
    "listQuotaPolicies",
    "createQuotaPolicy",
    "getQuotaPolicy",
    "replaceQuotaPolicy",
    "updateQuotaPolicy",
    "deleteQuotaPolicy",
    "listWallets",
    "createWallet",
    "getWallet",
    "updateWallet",
    "adjustWallet",
    "chargeWallet",
    "listWalletLedger",
    "listGuardrailPolicyRevisions",
    "createGuardrailPolicyRevision",
    "listGuardrailPolicyRevisionsByPolicy",
    "listGuardrailPolicyRevisionHistory",
    "createNextGuardrailPolicyRevision",
    "getGuardrailPolicyRevision",
    "archiveGuardrailPolicyRevision",
    "activateGuardrailPolicyRevision",
    "rollbackGuardrailPolicyRevision",
    "dryRunGuardrailPolicyRevision",
}


class GeneratedCatalogTests(unittest.TestCase):
    def test_catalog_matches_the_openapi_surface_and_required_admin_groups(self) -> None:
        self.assertEqual(len(OPERATIONS), OPENAPI_OPERATION_COUNT)
        self.assertTrue(REQUIRED_ADMIN_OPERATIONS <= set(OPERATIONS))
        self.assertEqual(OPERATIONS["listProjects"]["security"], ("bearerAuth",))

    def test_catalog_preserves_openapi_security_alternatives_and_metadata(self) -> None:
        with (Path(__file__).resolve().parents[2] / "docs/openapi/admin-api.openapi.json").open() as stream:
            document = json.load(stream)

        expected = {}
        for path, path_item in document["paths"].items():
            for method in ("get", "post", "put", "patch", "delete"):
                operation = path_item.get(method)
                if operation is None:
                    continue
                requirements = operation.get("security", document.get("security", []))
                security = tuple(
                    tuple((scheme, tuple(scopes)) for scheme, scopes in requirement.items())
                    for requirement in requirements
                )
                expected[operation["operationId"]] = {
                    "method": method.upper(),
                    "path": path,
                    "security": security,
                }

        self.assertEqual(set(OPERATIONS), set(expected))
        for operation_id, metadata in expected.items():
            with self.subTest(operation_id=operation_id):
                self.assertEqual(OPERATIONS[operation_id]["method"], metadata["method"])
                self.assertEqual(OPERATIONS[operation_id]["path"], metadata["path"])
                self.assertEqual(OPERATIONS[operation_id]["security"], metadata["security"])

    def test_request_operation_dispatches_a_generated_operation(self) -> None:
        seen = []

        def transport(request):
            seen.append(request)
            return HttpResponse(201, {}, '{"id":"project-1"}')

        client = AdminClient("https://gateway.example.com", token="token", transport=transport)
        result = client.request_operation(
            "createProject",
            body={"tenant_id": "tenant-1", "name": "Example", "slug": "example"},
        )

        self.assertEqual(result, {"id": "project-1"})
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].method, "POST")
        self.assertEqual(seen[0].url, "https://gateway.example.com/admin/v1/projects")
        self.assertEqual(json.loads(seen[0].body), {"tenant_id": "tenant-1", "name": "Example", "slug": "example"})

    def test_request_operation_rejects_unknown_metadata(self) -> None:
        client = AdminClient("https://gateway.example.com", token="token")

        with self.assertRaises(ValueError):
            client.request_operation("notAnOpenApiOperation")


if __name__ == "__main__":
    unittest.main()
