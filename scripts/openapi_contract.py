#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-07-10
# description: Dependency-free OpenAPI/runtime drift and compatibility validation domain.

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OPENAPI_PATH = ROOT / "docs" / "openapi" / "admin-api.openapi.json"
CONTRACT_PATH = ROOT / "docs" / "openapi" / "runtime-api-contract.json"
BASELINE_PATH = ROOT / "docs" / "openapi" / "admin-api.compatibility-baseline.json"
HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
VISIBILITIES = {"public", "admin", "internal"}
AUTH_KINDS = {"anonymous", "bearer", "method_dependent", "internal"}


def load_json(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - return the parser diagnostic.
        return None, [f"{path}: failed to parse JSON: {exc}"]
    if not isinstance(value, dict):
        return None, [f"{path}: root must be an object"]
    return value, []


def operations(document: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for path, path_item in document.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        path_parameters = path_item.get("parameters", [])
        for method, operation in path_item.items():
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            effective = operation.copy()
            effective["parameters"] = merge_parameters(
                path_parameters, operation.get("parameters", [])
            )
            result[(path, method)] = effective
    return result


def merge_parameters(path_parameters: Any, operation_parameters: Any) -> list[Any]:
    """Apply OpenAPI path-item inheritance without erasing referenced parameters."""
    merged: dict[tuple[Any, Any], Any] = {}
    for parameter in parameter_list(path_parameters) + parameter_list(operation_parameters):
        merged[parameter_identity(parameter)] = parameter
    return list(merged.values())


def parameter_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [parameter for parameter in value if isinstance(parameter, dict)]


def parameter_identity(parameter: dict[str, Any]) -> tuple[Any, Any]:
    ref = parameter.get("$ref")
    if isinstance(ref, str):
        return ("$ref", ref)
    return (parameter.get("in"), parameter.get("name"))


def contract_operations(contract: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for operation in contract.get("operations", []):
        if not isinstance(operation, dict):
            continue
        path = operation.get("path")
        method = operation.get("method")
        if isinstance(path, str) and isinstance(method, str):
            result[(path, method.lower())] = operation
    return result


def route_pattern_matches(pattern: str, operation_path: str) -> bool:
    pattern_parts = pattern.split("/")
    path_parts = operation_path.split("/")
    for index, part in enumerate(pattern_parts):
        if part.startswith("{*") and part.endswith("}"):
            return index < len(path_parts)
        if index >= len(path_parts):
            return False
        if part.startswith("{") and part.endswith("}"):
            continue
        if part != path_parts[index]:
            return False
    return len(pattern_parts) == len(path_parts)


def validate_repository_contract() -> list[str]:
    document, failures = load_json(OPENAPI_PATH)
    contract, contract_failures = load_json(CONTRACT_PATH)
    baseline, baseline_failures = load_json(BASELINE_PATH)
    failures.extend(contract_failures)
    failures.extend(baseline_failures)
    if document is None or contract is None or baseline is None:
        return failures
    failures.extend(validate_openapi(OPENAPI_PATH, document))
    failures.extend(validate_runtime_contract(CONTRACT_PATH, contract))
    failures.extend(validate_bidirectional_drift(document, contract))
    failures.extend(validate_compatibility(baseline, document))
    return failures


def validate_openapi(path: Path, document: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if not str(document.get("openapi", "")).startswith("3."):
        failures.append(f"{path}: openapi must start with 3.")
    if not isinstance(document.get("info"), dict):
        failures.append(f"{path}: missing info object")
    if not isinstance(document.get("paths"), dict) or not document["paths"]:
        failures.append(f"{path}: missing non-empty paths object")
    if not isinstance(document.get("components"), dict):
        failures.append(f"{path}: missing components object")
    failures.extend(validate_refs(path, document))

    operation_ids: list[str] = []
    for (route, method), operation in operations(document).items():
        operation_id = operation.get("operationId")
        if not isinstance(operation_id, str) or not operation_id:
            failures.append(f"{path}: {method.upper()} {route} is missing operationId")
        else:
            operation_ids.append(operation_id)
        if not isinstance(operation.get("responses"), dict) or not operation["responses"]:
            failures.append(f"{path}: {method.upper()} {route} is missing responses")
        if not isinstance(operation.get("x-ferrogate-contract"), dict):
            failures.append(
                f"{path}: {method.upper()} {route} is missing x-ferrogate-contract"
            )
    for operation_id, count in Counter(operation_ids).items():
        if count > 1:
            failures.append(f"{path}: duplicate operationId {operation_id}")
    return failures


def validate_runtime_contract(path: Path, contract: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if contract.get("version") != 1:
        failures.append(f"{path}: version must be 1")
    route_patterns = contract.get("route_patterns")
    if not isinstance(route_patterns, list) or not route_patterns:
        failures.append(f"{path}: route_patterns must be a non-empty array")
    else:
        seen_patterns: set[str] = set()
        for route in route_patterns:
            if not isinstance(route, dict):
                failures.append(f"{path}: route pattern must be an object")
                continue
            pattern = route.get("pattern")
            group = route.get("group")
            if not isinstance(pattern, str) or not pattern.startswith("/"):
                failures.append(f"{path}: route pattern requires an absolute pattern")
            elif pattern in seen_patterns:
                failures.append(f"{path}: duplicate route pattern {pattern}")
            else:
                seen_patterns.add(pattern)
            if not isinstance(group, str) or not group:
                failures.append(f"{path}: route pattern {pattern!r} requires a group")

    seen_keys: set[tuple[str, str]] = set()
    operation_ids: list[str] = []
    raw_operations = contract.get("operations")
    if not isinstance(raw_operations, list) or not raw_operations:
        return failures + [f"{path}: operations must be a non-empty array"]
    for operation in raw_operations:
        if not isinstance(operation, dict):
            failures.append(f"{path}: operation must be an object")
            continue
        route = operation.get("path")
        method = operation.get("method")
        operation_id = operation.get("operation_id")
        visibility = operation.get("visibility")
        auth = operation.get("auth")
        if not isinstance(route, str) or not route.startswith("/"):
            failures.append(f"{path}: operation requires an absolute path")
            continue
        if not isinstance(method, str) or method.lower() not in HTTP_METHODS:
            failures.append(f"{path}: operation {route} has invalid method {method!r}")
            continue
        key = (route, method.lower())
        if key in seen_keys:
            failures.append(f"{path}: duplicate operation {method.upper()} {route}")
        seen_keys.add(key)
        if not isinstance(operation_id, str) or not operation_id:
            failures.append(f"{path}: {method.upper()} {route} requires operation_id")
        else:
            operation_ids.append(operation_id)
        if visibility not in VISIBILITIES:
            failures.append(f"{path}: {operation_id} has invalid visibility {visibility!r}")
        if not isinstance(auth, dict) or auth.get("kind") not in AUTH_KINDS:
            failures.append(f"{path}: {operation_id} has invalid auth metadata")
        elif auth["kind"] == "bearer" and not auth.get("scope"):
            failures.append(f"{path}: {operation_id} bearer auth requires a scope")
        elif auth["kind"] == "method_dependent":
            failures.extend(
                validate_scope_discriminator(path, operation_id, auth)
            )
        action = operation.get("rbac_action")
        if action is not None and (not isinstance(action, str) or not action):
            failures.append(f"{path}: {operation_id} has invalid rbac_action")
        if "role" in operation or "role_name" in operation:
            failures.append(
                f"{path}: {operation_id} must declare DB action keys, never fixed role names"
            )
    for operation_id, count in Counter(operation_ids).items():
        if count > 1:
            failures.append(f"{path}: duplicate operation_id {operation_id}")

    dynamic = contract.get("dynamic_surfaces")
    if not isinstance(dynamic, list) or not dynamic:
        failures.append(f"{path}: dynamic_surfaces must classify excluded runtime surfaces")

    patterns = [
        route.get("pattern")
        for route in route_patterns or []
        if isinstance(route, dict) and isinstance(route.get("pattern"), str)
    ]
    operation_paths = {
        operation.get("path")
        for operation in raw_operations
        if isinstance(operation, dict) and isinstance(operation.get("path"), str)
    }
    for operation_path in sorted(operation_paths):
        if not any(route_pattern_matches(pattern, operation_path) for pattern in patterns):
            failures.append(
                f"{path}: operation path {operation_path} is not owned by a route pattern"
            )
    for pattern in patterns:
        if not any(route_pattern_matches(pattern, operation_path) for operation_path in operation_paths):
            failures.append(f"{path}: route pattern {pattern} has no documented operation")
    return failures


def validate_scope_discriminator(
    path: Path, operation_id: Any, auth: dict[str, Any]
) -> list[str]:
    discriminator = auth.get("scope_discriminator")
    if auth.get("scope") is not None or not isinstance(discriminator, dict):
        return [
            f"{path}: {operation_id} method_dependent auth requires a scope_discriminator"
        ]
    field = discriminator.get("field")
    scope_map = discriminator.get("map")
    if not isinstance(field, str) or not field or not isinstance(scope_map, dict) or not scope_map:
        return [f"{path}: {operation_id} has invalid scope_discriminator"]
    if any(
        not isinstance(value, str) or not value
        for key, value in scope_map.items()
        if isinstance(key, str) and key
    ) or any(not isinstance(key, str) or not key for key in scope_map):
        return [f"{path}: {operation_id} has invalid scope_discriminator map"]
    return []


def validate_bidirectional_drift(
    document: dict[str, Any], contract: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    documented = operations(document)
    runtime = contract_operations(contract)
    for route, method in sorted(runtime.keys() - documented.keys()):
        failures.append(f"runtime contract operation missing from OpenAPI: {method.upper()} {route}")
    for route, method in sorted(documented.keys() - runtime.keys()):
        failures.append(f"stale OpenAPI operation missing from runtime contract: {method.upper()} {route}")
    for key in sorted(runtime.keys() & documented.keys()):
        runtime_id = runtime[key].get("operation_id")
        documented_id = documented[key].get("operationId")
        if runtime_id != documented_id:
            failures.append(
                f"operationId drift for {key[1].upper()} {key[0]}: "
                f"runtime={runtime_id!r} openapi={documented_id!r}"
            )
        documented_metadata = documented[key].get("x-ferrogate-contract")
        expected_metadata = {
            "visibility": runtime[key].get("visibility"),
            "auth": runtime[key].get("auth"),
            "rbac_action": runtime[key].get("rbac_action"),
        }
        if documented_metadata != expected_metadata:
            failures.append(
                f"classification drift for {key[1].upper()} {key[0]}: "
                f"runtime={expected_metadata!r} openapi={documented_metadata!r}"
            )
    return failures


def validate_compatibility(
    baseline: dict[str, Any], current: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    old_operations = operations(baseline)
    new_operations = operations(current)
    for key, old in old_operations.items():
        if key not in new_operations:
            failures.append(f"compatibility: removed operation {key[1].upper()} {key[0]}")
            continue
        new = new_operations[key]
        if old.get("operationId") != new.get("operationId"):
            failures.append(
                f"compatibility: operationId changed for {key[1].upper()} {key[0]}"
            )
        if effective_security(baseline, old) != effective_security(current, new):
            failures.append(f"compatibility: security changed for {key[1].upper()} {key[0]}")
        if old.get("x-ferrogate-contract") != new.get("x-ferrogate-contract"):
            failures.append(
                f"compatibility: runtime contract metadata changed for {key[1].upper()} {key[0]}"
            )
        failures.extend(compare_parameters(old, new, key))
        failures.extend(compare_request_body(old, new, key))
        failures.extend(compare_responses(old, new, key))

    old_schemas = baseline.get("components", {}).get("schemas", {})
    new_schemas = current.get("components", {}).get("schemas", {})
    if isinstance(old_schemas, dict) and isinstance(new_schemas, dict):
        for name, old_schema in old_schemas.items():
            if name not in new_schemas:
                failures.append(f"compatibility: removed schema {name}")
            else:
                failures.extend(
                    compare_schema(old_schema, new_schemas[name], f"schema {name}")
                )
    failures.extend(compare_component_parameters(baseline, current))
    failures.extend(compare_component_request_bodies(baseline, current))
    failures.extend(compare_component_responses(baseline, current))
    return failures


def effective_security(document: dict[str, Any], operation: dict[str, Any]) -> Any:
    return operation.get("security", document.get("security", []))


def compare_parameters(
    old: dict[str, Any], new: dict[str, Any], key: tuple[str, str]
) -> list[str]:
    location = f"{key[1].upper()} {key[0]}"
    old_parameters = parameter_map(old.get("parameters", []))
    new_parameters = parameter_map(new.get("parameters", []))
    failures: list[str] = []
    for parameter_key, old_parameter in old_parameters.items():
        if parameter_key not in new_parameters:
            failures.append(f"compatibility: {location} removed parameter {parameter_key}")
            continue
        new_parameter = new_parameters[parameter_key]
        failures.extend(
            compare_parameter(
                old_parameter,
                new_parameter,
                f"{location} parameter {parameter_key}",
            )
        )
    for parameter_key, new_parameter in new_parameters.items():
        if parameter_key not in old_parameters and new_parameter.get("required") is True:
            failures.append(
                f"compatibility: {location} added required parameter {parameter_key}"
            )
    return failures


def compare_parameter(old: Any, new: Any, location: str) -> list[str]:
    if not isinstance(old, dict) or not isinstance(new, dict):
        return [] if old == new else [f"compatibility: changed {location}"]
    failures: list[str] = []
    for key in ("$ref", "name", "in", "required"):
        if old.get(key) != new.get(key):
            failures.append(f"compatibility: changed {location} {key}")
    failures.extend(
        compare_schema(old.get("schema"), new.get("schema"), location)
    )
    return failures


def parameter_map(value: Any) -> dict[tuple[Any, Any], dict[str, Any]]:
    return {
        parameter_identity(parameter): parameter
        for parameter in parameter_list(value)
    }


def compare_request_body(
    old: dict[str, Any], new: dict[str, Any], key: tuple[str, str]
) -> list[str]:
    old_body = old.get("requestBody")
    new_body = new.get("requestBody")
    location = f"{key[1].upper()} {key[0]} request body"
    if old_body is None:
        if isinstance(new_body, dict) and new_body.get("required") is True:
            return [f"compatibility: {location} became required"]
        return []
    if new_body is None:
        return [f"compatibility: removed {location}"]
    return compare_request_body_value(old_body, new_body, location)


def compare_request_body_value(old: Any, new: Any, location: str) -> list[str]:
    failures: list[str] = []
    if isinstance(old, dict) and isinstance(new, dict):
        if old.get("required", False) != new.get("required", False):
            failures.append(f"compatibility: changed {location} required state")
    failures.extend(compare_content(old, new, location))
    return failures


def compare_responses(
    old: dict[str, Any], new: dict[str, Any], key: tuple[str, str]
) -> list[str]:
    failures: list[str] = []
    old_responses = old.get("responses", {})
    new_responses = new.get("responses", {})
    if not isinstance(old_responses, dict) or not isinstance(new_responses, dict):
        return [f"compatibility: invalid responses for {key[1].upper()} {key[0]}"]
    for status, old_response in old_responses.items():
        if status not in new_responses:
            failures.append(
                f"compatibility: {key[1].upper()} {key[0]} removed response {status}"
            )
            continue
        failures.extend(
            compare_response(
                old_response,
                new_responses[status],
                f"{key[1].upper()} {key[0]} response {status}",
            )
        )
    return failures


def compare_response(old: Any, new: Any, location: str) -> list[str]:
    failures = compare_content(old, new, location)
    if isinstance(old, dict) and isinstance(new, dict):
        if old.get("description") != new.get("description"):
            failures.append(f"compatibility: changed {location} description")
    return failures


def component_map(document: dict[str, Any], section: str) -> dict[str, Any]:
    components = document.get("components", {})
    if not isinstance(components, dict):
        return {}
    values = components.get(section, {})
    return values if isinstance(values, dict) else {}


def compare_component_parameters(
    baseline: dict[str, Any], current: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    old_parameters = component_map(baseline, "parameters")
    new_parameters = component_map(current, "parameters")
    for name, old_parameter in old_parameters.items():
        if name not in new_parameters:
            failures.append(f"compatibility: removed component parameter {name}")
        else:
            failures.extend(
                compare_parameter(
                    old_parameter,
                    new_parameters[name],
                    f"component parameter {name}",
                )
            )
    return failures


def compare_component_request_bodies(
    baseline: dict[str, Any], current: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    old_bodies = component_map(baseline, "requestBodies")
    new_bodies = component_map(current, "requestBodies")
    for name, old_body in old_bodies.items():
        if name not in new_bodies:
            failures.append(f"compatibility: removed component request body {name}")
        else:
            failures.extend(
                compare_request_body_value(
                    old_body,
                    new_bodies[name],
                    f"component request body {name}",
                )
            )
    return failures


def compare_component_responses(
    baseline: dict[str, Any], current: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    old_responses = component_map(baseline, "responses")
    new_responses = component_map(current, "responses")
    for name, old_response in old_responses.items():
        if name not in new_responses:
            failures.append(f"compatibility: removed component response {name}")
        else:
            failures.extend(
                compare_response(
                    old_response,
                    new_responses[name],
                    f"component response {name}",
                )
            )
    return failures


def compare_content(old: Any, new: Any, location: str) -> list[str]:
    if not isinstance(old, dict) or not isinstance(new, dict):
        return [] if old == new else [f"compatibility: changed {location}"]
    failures: list[str] = []
    if old.get("$ref") != new.get("$ref"):
        failures.append(f"compatibility: changed {location} reference")
    failures.extend(compare_schema(old.get("schema"), new.get("schema"), location))
    old_content = old.get("content", {})
    new_content = new.get("content", {})
    if not isinstance(old_content, dict) or not isinstance(new_content, dict):
        if old_content != new_content:
            failures.append(f"compatibility: changed {location} content")
        return failures
    for media_type, old_media in old_content.items():
        if media_type not in new_content:
            failures.append(f"compatibility: {location} removed media type {media_type}")
            continue
        old_schema = old_media.get("schema") if isinstance(old_media, dict) else None
        new_media = new_content[media_type]
        new_schema = new_media.get("schema") if isinstance(new_media, dict) else None
        failures.extend(compare_schema(old_schema, new_schema, f"{location} {media_type}"))
    return failures


def compare_schema(old: Any, new: Any, location: str) -> list[str]:
    if old is None and new is None:
        return []
    if not isinstance(old, dict) or not isinstance(new, dict):
        return [] if old == new else [f"compatibility: changed {location}"]
    failures: list[str] = []
    if old.get("$ref") != new.get("$ref"):
        failures.append(f"compatibility: changed {location} reference")
        return failures
    for key in (
        "type",
        "format",
        "nullable",
        "enum",
        "const",
        "pattern",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
    ):
        if old.get(key) != new.get(key):
            failures.append(f"compatibility: changed {location} {key}")
    old_required = set(old.get("required", []))
    new_required = set(new.get("required", []))
    if old_required != new_required:
        failures.append(f"compatibility: changed {location} required fields")
    old_properties = old.get("properties", {})
    new_properties = new.get("properties", {})
    if isinstance(old_properties, dict) and isinstance(new_properties, dict):
        for name, old_property in old_properties.items():
            if name not in new_properties:
                failures.append(f"compatibility: removed {location}.{name}")
            else:
                failures.extend(
                    compare_schema(old_property, new_properties[name], f"{location}.{name}")
                )
    if old.get("additionalProperties", True) is True and new.get("additionalProperties", True) is False:
        failures.append(f"compatibility: closed additional properties for {location}")
    failures.extend(compare_schema(old.get("items"), new.get("items"), f"{location} items"))
    for composition in ("oneOf", "anyOf", "allOf"):
        if old.get(composition) != new.get(composition):
            failures.append(f"compatibility: changed {location} {composition}")
    return failures


def validate_refs(path: Path, document: Any) -> list[str]:
    failures: list[str] = []
    for ref in collect_refs(document):
        if not ref.startswith("#/"):
            continue
        current: Any = document
        for segment in ref[2:].split("/"):
            key = segment.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or key not in current:
                failures.append(f"{path}: unresolved local ref {ref}")
                break
            current = current[key]
    return failures


def collect_refs(value: Any) -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        if isinstance(value.get("$ref"), str):
            refs.append(value["$ref"])
        for child in value.values():
            refs.extend(collect_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.extend(collect_refs(child))
    return refs
