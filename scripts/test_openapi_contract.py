#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-10
# description: Regression tests for bidirectional runtime drift and compatibility rules.

from __future__ import annotations

import copy
import unittest

from openapi_contract import (
    OPENAPI_PATH,
    load_json,
    validate_bidirectional_drift,
    validate_compatibility,
    validate_openapi,
    validate_runtime_contract,
)


def operation(operation_id: str) -> dict:
    return {
        "operationId": operation_id,
        "x-ferrogate-contract": {
            "visibility": "public",
            "auth": {"kind": "bearer", "scope": "things.read"},
            "rbac_action": None,
        },
        "responses": {
            "200": {
                "description": "ok",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Thing"}
                    }
                },
            }
        },
    }


def document() -> dict:
    return {
        "openapi": "3.1.0",
        "info": {},
        "security": [{"bearerAuth": []}],
        "paths": {"/things": {"get": operation("listThings")}},
        "components": {
            "schemas": {
                "Thing": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {"id": {"type": "string"}},
                    "additionalProperties": False,
                }
            }
        },
    }


def contract() -> dict:
    return {
        "version": 1,
        "route_patterns": [{"pattern": "/things", "group": "inference"}],
        "dynamic_surfaces": [{"pattern": "configured", "visibility": "dynamic_proxy"}],
        "operations": [
            {
                "path": "/things",
                "method": "get",
                "operation_id": "listThings",
                "visibility": "public",
                "auth": {"kind": "bearer", "scope": "things.read"},
                "rbac_action": None,
            }
        ],
    }


class ContractTests(unittest.TestCase):
    def test_bidirectional_drift_rejects_runtime_and_openapi_extras(self) -> None:
        runtime_extra = contract()
        runtime_extra["operations"].append(
            {
                "path": "/missing",
                "method": "post",
                "operation_id": "createMissing",
                "visibility": "public",
                "auth": {"kind": "bearer", "scope": "things.write"},
                "rbac_action": None,
            }
        )
        failures = validate_bidirectional_drift(document(), runtime_extra)
        self.assertTrue(any("missing from OpenAPI" in failure for failure in failures))

        stale = document()
        stale["paths"]["/stale"] = {"get": operation("getStale")}
        failures = validate_bidirectional_drift(stale, contract())
        self.assertTrue(any("stale OpenAPI" in failure for failure in failures))

    def test_operation_ids_must_be_unique_in_both_sources(self) -> None:
        duplicate_document = document()
        duplicate_document["paths"]["/other"] = {"get": operation("listThings")}
        self.assertTrue(
            any(
                "duplicate operationId" in failure
                for failure in validate_openapi(__file__, duplicate_document)
            )
        )

        duplicate_contract = contract()
        duplicate_contract["operations"].append(
            {
                **duplicate_contract["operations"][0],
                "path": "/other",
            }
        )
        self.assertTrue(
            any(
                "duplicate operation_id" in failure
                for failure in validate_runtime_contract(__file__, duplicate_contract)
            )
        )

    def test_fixed_role_names_are_rejected(self) -> None:
        invalid = contract()
        invalid["operations"][0]["role_name"] = "forbidden-static-value"
        failures = validate_runtime_contract(__file__, invalid)
        self.assertTrue(any("never fixed role names" in failure for failure in failures))

    def test_method_dependent_auth_requires_a_nonempty_scope_map(self) -> None:
        invalid = contract()
        invalid["operations"][0]["auth"] = {
            "kind": "method_dependent",
            "scope": None,
        }
        failures = validate_runtime_contract(__file__, invalid)
        self.assertTrue(any("scope_discriminator" in failure for failure in failures))

        invalid["operations"][0]["auth"]["scope_discriminator"] = {
            "field": "method",
            "map": {"tools/call": ""},
        }
        failures = validate_runtime_contract(__file__, invalid)
        self.assertTrue(any("scope_discriminator map" in failure for failure in failures))

    def test_operation_must_belong_to_a_route_pattern(self) -> None:
        invalid = contract()
        invalid["route_patterns"] = [{"pattern": "/other", "group": "test"}]
        failures = validate_runtime_contract(__file__, invalid)
        self.assertTrue(any("not owned by a route pattern" in failure for failure in failures))

    def test_compatibility_rejects_removed_field_enum_and_operation_id(self) -> None:
        baseline = document()
        current = copy.deepcopy(baseline)
        current["paths"]["/things"]["get"]["operationId"] = "getThings"
        current["components"]["schemas"]["Thing"]["properties"].pop("id")
        failures = validate_compatibility(baseline, current)
        self.assertTrue(any("operationId changed" in failure for failure in failures))
        self.assertTrue(any("removed schema Thing.id" in failure for failure in failures))

        enum_baseline = document()
        enum_baseline["components"]["schemas"]["Thing"]["properties"]["kind"] = {
            "type": "string",
            "enum": ["a", "b"],
        }
        enum_current = copy.deepcopy(enum_baseline)
        enum_current["components"]["schemas"]["Thing"]["properties"]["kind"]["enum"] = ["a"]
        self.assertTrue(
            any("enum" in failure for failure in validate_compatibility(enum_baseline, enum_current))
        )

    def test_additive_optional_field_is_compatible(self) -> None:
        baseline = document()
        current = copy.deepcopy(baseline)
        current["components"]["schemas"]["Thing"]["properties"]["label"] = {
            "type": "string"
        }
        self.assertEqual(validate_compatibility(baseline, current), [])

    def test_compatibility_rejects_runtime_governance_changes(self) -> None:
        baseline = document()

        changed_visibility = copy.deepcopy(baseline)
        changed_visibility["paths"]["/things"]["get"]["x-ferrogate-contract"][
            "visibility"
        ] = "admin"
        self.assertTrue(
            any(
                "runtime contract metadata changed" in failure
                for failure in validate_compatibility(baseline, changed_visibility)
            )
        )

        changed_kind = copy.deepcopy(baseline)
        changed_kind["paths"]["/things"]["get"]["x-ferrogate-contract"]["auth"][
            "kind"
        ] = "anonymous"
        self.assertTrue(
            any(
                "runtime contract metadata changed" in failure
                for failure in validate_compatibility(baseline, changed_kind)
            )
        )

        changed_scope = copy.deepcopy(baseline)
        changed_scope["paths"]["/things"]["get"]["x-ferrogate-contract"]["auth"][
            "scope"
        ] = "things.write"
        self.assertTrue(
            any(
                "runtime contract metadata changed" in failure
                for failure in validate_compatibility(baseline, changed_scope)
            )
        )

        baseline["paths"]["/things"]["get"]["x-ferrogate-contract"][
            "rbac_action"
        ] = "things.read"
        changed_action = copy.deepcopy(baseline)
        changed_action["paths"]["/things"]["get"]["x-ferrogate-contract"][
            "rbac_action"
        ] = "things.write"
        self.assertTrue(
            any(
                "runtime contract metadata changed" in failure
                for failure in validate_compatibility(baseline, changed_action)
            )
        )

    def test_compatibility_rejects_method_scope_map_changes(self) -> None:
        baseline = document()
        auth = baseline["paths"]["/things"]["get"]["x-ferrogate-contract"]["auth"]
        auth.update(
            {
                "kind": "method_dependent",
                "scope": None,
                "scope_discriminator": {
                    "field": "method",
                    "map": {
                        "tools/list": "tools.read",
                        "tools/call": "tools.execute",
                    },
                },
            }
        )
        current = copy.deepcopy(baseline)
        current["paths"]["/things"]["get"]["x-ferrogate-contract"]["auth"][
            "scope_discriminator"
        ]["map"]["tools/call"] = "tools.read"
        self.assertTrue(
            any(
                "runtime contract metadata changed" in failure
                for failure in validate_compatibility(baseline, current)
            )
        )

    def test_real_spec_mutations_reject_inherited_parameters_and_payload_drift(self) -> None:
        baseline, failures = load_json(OPENAPI_PATH)
        self.assertEqual(failures, [])
        assert baseline is not None

        missing_path_parameter = copy.deepcopy(baseline)
        missing_path_parameter["paths"]["/admin/v1/plugins/{plugin_id}"].pop(
            "parameters"
        )
        self.assertTrue(
            any(
                "removed parameter" in failure and "PluginId" in failure
                for failure in validate_compatibility(baseline, missing_path_parameter)
            )
        )

        required_body = copy.deepcopy(baseline)
        required_body["paths"]["/admin/v1/mcp-servers"]["post"]["requestBody"][
            "required"
        ] = True
        self.assertTrue(
            any(
                "request body required state" in failure
                for failure in validate_compatibility(baseline, required_body)
            )
        )

        changed_request_schema = copy.deepcopy(baseline)
        changed_request_schema["paths"]["/v1/mcp"]["post"]["requestBody"][
            "content"
        ]["application/json"]["schema"]["$ref"] = "#/components/schemas/McpJsonRpcResponse"
        self.assertTrue(
            any(
                "request body application/json reference" in failure
                for failure in validate_compatibility(baseline, changed_request_schema)
            )
        )

        changed_error_envelope = copy.deepcopy(baseline)
        changed_error_envelope["paths"]["/v1/mcp"]["post"]["responses"]["401"][
            "$ref"
        ] = "#/components/responses/Forbidden"
        self.assertTrue(
            any(
                "response 401 reference" in failure
                for failure in validate_compatibility(baseline, changed_error_envelope)
            )
        )

    def test_real_component_target_mutations_are_incompatible(self) -> None:
        baseline, failures = load_json(OPENAPI_PATH)
        self.assertEqual(failures, [])
        assert baseline is not None

        changed_parameter = copy.deepcopy(baseline)
        changed_parameter["components"]["parameters"]["PluginId"]["schema"][
            "minLength"
        ] = 99
        self.assertTrue(
            any(
                "component parameter PluginId minLength" in failure
                for failure in validate_compatibility(baseline, changed_parameter)
            )
        )

        changed_description = copy.deepcopy(baseline)
        changed_description["components"]["responses"]["Unauthorized"][
            "description"
        ] = "Changed authentication envelope."
        self.assertTrue(
            any(
                "component response Unauthorized description" in failure
                for failure in validate_compatibility(baseline, changed_description)
            )
        )

        removed_response_content = copy.deepcopy(baseline)
        removed_response_content["components"]["responses"]["Unauthorized"][
            "content"
        ].pop("application/json")
        self.assertTrue(
            any(
                "component response Unauthorized removed media type" in failure
                for failure in validate_compatibility(baseline, removed_response_content)
            )
        )

        changed_response_schema = copy.deepcopy(baseline)
        changed_response_schema["components"]["responses"]["Unauthorized"][
            "content"
        ]["application/json"]["schema"]["$ref"] = "#/components/schemas/HealthResponse"
        self.assertTrue(
            any(
                "component response Unauthorized application/json reference" in failure
                for failure in validate_compatibility(baseline, changed_response_schema)
            )
        )

        changed_body_required = copy.deepcopy(baseline)
        changed_body_required["components"]["requestBodies"][
            "AdminMcpServerMutation"
        ]["required"] = False
        self.assertTrue(
            any(
                "component request body AdminMcpServerMutation required state" in failure
                for failure in validate_compatibility(baseline, changed_body_required)
            )
        )

        changed_body_schema = copy.deepcopy(baseline)
        changed_body_schema["components"]["requestBodies"][
            "AdminMcpServerMutation"
        ]["content"]["application/json"]["schema"][
            "$ref"
        ] = "#/components/schemas/AdminMcpServerResponse"
        self.assertTrue(
            any(
                "component request body AdminMcpServerMutation application/json reference"
                in failure
                for failure in validate_compatibility(baseline, changed_body_schema)
            )
        )

    def test_contract_classification_drift_is_rejected(self) -> None:
        documented = document()
        documented["paths"]["/things"]["get"]["x-ferrogate-contract"] = {
            "visibility": "public",
            "auth": {"kind": "anonymous", "scope": None},
            "rbac_action": None,
        }
        failures = validate_bidirectional_drift(documented, contract())
        self.assertTrue(any("classification drift" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
