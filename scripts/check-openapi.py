#!/usr/bin/env python3
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-06-11
# description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

"""Validate checked-in OpenAPI documents without external dependencies."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = [
    ROOT / "docs" / "openapi" / "admin-api.openapi.json",
]

EXPECTED_ADMIN_METHODS = {
    "/healthz": {"get"},
    "/admin": {"get"},
    "/admin/status": {"get"},
    "/admin/v1/status": {"get"},
    "/admin/v1/providers": {"get"},
    "/admin/v1/provider-health": {"get"},
    "/admin/v1/provider-models": {"get"},
    "/admin/v1/extensions": {"get"},
    "/admin/v1/tools": {"get"},
    "/admin/v1/mcp-servers": {"get"},
    "/admin/v1/agent-upstreams": {"get", "post"},
    "/admin/v1/agent-upstreams/{id}": {"get", "put", "patch", "delete"},
    "/admin/v1/tool-sessions/{session_id}": {"get"},
    "/v1/mcp": {"post"},
    "/v1/mcp/tool/execute": {"post"},
    "/admin/v1/models": {"get"},
    "/admin/v1/api-keys": {"get", "post"},
    "/admin/v1/api-keys/{id}": {"get", "put", "patch", "delete"},
    "/admin/v1/tenants": {"get"},
    "/admin/v1/policies": {"get", "post"},
    "/admin/v1/policies/{name}": {"get", "put", "patch", "delete"},
    "/admin/v1/guardrail-policies": {"get", "post"},
    "/admin/v1/guardrail-policies/{policy_id}": {"get"},
    "/admin/v1/guardrail-policies/{policy_id}/revisions": {"get", "post"},
    "/admin/v1/guardrail-policies/{policy_id}/revisions/{revision}": {"get", "delete"},
    "/admin/v1/guardrail-policies/{policy_id}/activate": {"post"},
    "/admin/v1/guardrail-policies/{policy_id}/rollback": {"post"},
    "/admin/v1/guardrail-policies/{policy_id}/dry-run": {"post"},
    "/admin/v1/agent-workflows": {"get", "post"},
    "/admin/v1/agent-workflows/{id}": {"get", "put", "patch", "delete"},
    "/admin/v1/skill-packages": {"get", "post"},
    "/admin/v1/skill-packages/{id}": {"get", "put", "patch", "delete"},
    "/v1/skills": {"get"},
    "/v1/skills/{id}": {"get"},
    "/.well-known/agent.json": {"get"},
    "/admin/v1/request-logs": {"get"},
    "/admin/v1/billing-events": {"get"},
    "/admin/v1/usage-aggregates": {"get"},
    "/admin/v1/audit-events": {"get"},
    "/admin/v1/config/validate": {"post"},
    "/admin/v1/config/reload": {"post"},
    "/metrics": {"get"},
}

HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def main() -> int:
    failures: list[str] = []
    for path in DOCUMENTS:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - report parser detail.
            failures.append(f"{path}: failed to parse JSON: {exc}")
            continue

        if not str(document.get("openapi", "")).startswith("3."):
            failures.append(f"{path}: openapi must start with 3.")
        if not isinstance(document.get("info"), dict):
            failures.append(f"{path}: missing info object")
        if not isinstance(document.get("paths"), dict) or not document["paths"]:
            failures.append(f"{path}: missing non-empty paths object")
        if not isinstance(document.get("components"), dict):
            failures.append(f"{path}: missing components object")
        failures.extend(validate_refs(path, document))
        if path.name == "admin-api.openapi.json":
            failures.extend(validate_expected_admin_methods(path, document))

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    for path in DOCUMENTS:
        print(f"validated {path.relative_to(ROOT)}")
    return 0


def validate_refs(path: Path, document: object) -> list[str]:
    failures: list[str] = []
    if not isinstance(document, dict):
        return [f"{path}: document must be an object"]

    for ref in collect_refs(document):
        if not ref.startswith("#/"):
            continue
        current: object = document
        for segment in ref[2:].split("/"):
            key = segment.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or key not in current:
                failures.append(f"{path}: unresolved local ref {ref}")
                break
            current = current[key]
    return failures


def collect_refs(value: object) -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str):
            refs.append(ref)
        for child in value.values():
            refs.extend(collect_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.extend(collect_refs(child))
    return refs


def validate_expected_admin_methods(path: Path, document: object) -> list[str]:
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        return []
    paths = document["paths"]
    failures: list[str] = []
    for route, methods in EXPECTED_ADMIN_METHODS.items():
        path_item = paths.get(route)
        if not isinstance(path_item, dict):
            failures.append(f"{path}: missing path {route}")
            continue
        actual_methods = {key for key in path_item if key in HTTP_METHODS}
        missing = methods - actual_methods
        if missing:
            failures.append(f"{path}: path {route} missing methods {sorted(missing)}")
    return failures


if __name__ == "__main__":
    raise SystemExit(main())
