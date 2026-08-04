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


if __name__ == "__main__":
    unittest.main()
