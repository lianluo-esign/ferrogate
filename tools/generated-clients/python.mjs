import { readFileSync } from "node:fs";

export const PYTHON_BANNER =
  "# GENERATED FILE - DO NOT EDIT.\n" +
  "# Source contract: docs/openapi/admin-api.openapi.json (repo root).\n" +
  "# Regenerate with: bun run generate   (from the repo root).\n";

const HTTP_METHODS = ["delete", "get", "patch", "post", "put"];

function pythonString(value) {
  return JSON.stringify(value);
}

function pythonTuple(values) {
  if (values.length === 0) return "()";
  if (values.length === 1) return "(" + pythonString(values[0]) + ",)";
  return "(" + values.map(pythonString).join(", ") + ")";
}

function operationSecurity(operation, document) {
  const requirements = operation.security ?? document.security ?? [];
  return [...new Set(requirements.flatMap((requirement) => Object.keys(requirement)))].sort();
}

/**
 * Render the operation catalog consumed by the zero-dependency Python client.
 * The catalog intentionally carries paths and transport metadata, not models:
 * the client stays thin while operation IDs remain discoverable and checked
 * against the same OpenAPI document as the TypeScript types.
 *
 * @param {string} specPath absolute path to the OpenAPI document
 */
export function renderPythonOperationCatalog(specPath) {
  const document = JSON.parse(readFileSync(specPath, "utf8"));
  const operations = [];

  for (const [path, pathItem] of Object.entries(document.paths ?? {})) {
    for (const method of HTTP_METHODS) {
      const operation = pathItem?.[method];
      if (!operation) continue;
      operations.push({
        operationId: operation.operationId,
        method: method.toUpperCase(),
        path,
        security: operationSecurity(operation, document),
        tags: [...(operation.tags ?? [])],
      });
    }
  }

  operations.sort((left, right) => left.operationId.localeCompare(right.operationId));
  const adminOperationIds = operations
    .filter((operation) => operation.path.startsWith("/admin/v1/"))
    .map((operation) => operation.operationId);

  const lines = [
    PYTHON_BANNER.trimEnd(),
    "",
    "from __future__ import annotations",
    "",
    "from typing import Final, TypedDict",
    "",
    "",
    "class Operation(TypedDict):",
    "    method: str",
    "    path: str",
    "    security: tuple[str, ...]",
    "    tags: tuple[str, ...]",
    "",
    "OPENAPI_OPERATION_COUNT: Final[int] = " + operations.length,
    "",
    "OPERATIONS: Final[dict[str, Operation]] = {",
  ];

  for (const operation of operations) {
    lines.push("    " + pythonString(operation.operationId) + ": {");
    lines.push("        \"method\": " + pythonString(operation.method) + ",");
    lines.push("        \"path\": " + pythonString(operation.path) + ",");
    lines.push("        \"security\": " + pythonTuple(operation.security) + ",");
    lines.push("        \"tags\": " + pythonTuple(operation.tags) + ",");
    lines.push("    },");
  }

  lines.push("}", "", "ADMIN_OPERATION_IDS: Final[tuple[str, ...]] = (");
  for (const operationId of adminOperationIds) {
    lines.push("    " + pythonString(operationId) + ",");
  }
  lines.push(")", "");
  return lines.join("\n");
}
