// Test-only helper for the wire-contract drift alarms (*.contract.test.ts).
//
// Those tests used to read the SERVER structs straight out of the Rust tree
// (`crates/ferrogate-gateway/...`). The Rust implementation was deleted on
// 2026-08-02; the surviving cross-repo authority is the shared OpenAPI contract
// `docs/openapi/admin-api.openapi.json`, from which both this console's
// `src/lib/api-types.generated.ts` and the TS backend's routing tables are
// derived (with a drift gate on the generated types). The contract tests
// therefore now pin schema shapes out of that document, and this module is the
// one place that knows how to read it.
//
// `fieldShape` renders one property schema as a compact descriptor string —
// the moral equivalent of the Rust `field: Type` pairs the old tests pinned —
// so a rename, retype, un-nulling, enum edit, or `$ref` swap shows up as a
// string diff on the exact field that moved.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

/** The (subset of the) OpenAPI schema-object grammar the pins need. */
export interface OpenApiSchema {
  $ref?: string;
  type?: string | string[];
  format?: string;
  nullable?: boolean;
  const?: unknown;
  enum?: unknown[];
  required?: string[];
  properties?: Record<string, OpenApiSchema>;
  items?: OpenApiSchema;
  additionalProperties?: boolean | OpenApiSchema;
  oneOf?: OpenApiSchema[];
  description?: string;
}

export interface OpenApiOperation {
  operationId?: string;
  summary?: string;
  description?: string;
  responses?: Record<string, { content?: Record<string, { schema?: OpenApiSchema }> }>;
}

interface ContractDocument {
  paths: Record<string, Record<string, OpenApiOperation>>;
  components: { schemas: Record<string, OpenApiSchema> };
}

// Vitest runs with `admin-console/` as its root, so the shared contract sits
// one directory up. Reading it (rather than a checked-in copy) is the whole
// point: there is no second artifact to forget to update.
const CONTRACT_PATH = resolve(process.cwd(), "../docs/openapi/admin-api.openapi.json");

let cached: ContractDocument | undefined;

/** The parsed shared contract, `docs/openapi/admin-api.openapi.json`. */
export function contractDocument(): ContractDocument {
  cached ??= JSON.parse(readFileSync(CONTRACT_PATH, "utf8")) as ContractDocument;
  return cached;
}

/** One named component schema; throws (rather than pinning `undefined` against
 * `undefined`) when the schema was deleted or renamed. */
export function contractSchema(name: string): OpenApiSchema {
  const schema = contractDocument().components.schemas[name];
  if (schema === undefined) {
    throw new Error(`schema ${name} not found in ${CONTRACT_PATH}`);
  }
  return schema;
}

/** One operation object; throws when the path or method is gone. */
export function contractOperation(path: string, method: string): OpenApiOperation {
  const operation = contractDocument().paths[path]?.[method];
  if (operation === undefined) {
    throw new Error(`operation ${method.toUpperCase()} ${path} not found in ${CONTRACT_PATH}`);
  }
  return operation;
}

/** The `$ref` target of an operation's `application/json` response schema. */
export function responseSchemaRef(operation: OpenApiOperation, status: string): string | undefined {
  return operation.responses?.[status]?.content?.["application/json"]?.schema?.$ref;
}

/**
 * A property schema as a compact descriptor: `ref:Name`, `const:value`,
 * `enum:a|b`, `array<...>`, or `type[:format][|null]`.
 */
export function fieldShape(property: OpenApiSchema): string {
  if (property.$ref !== undefined) {
    return `ref:${property.$ref.split("/").pop() ?? property.$ref}`;
  }
  if (property.const !== undefined) return `const:${String(property.const)}`;
  if (property.enum !== undefined) return `enum:${property.enum.map(String).join("|")}`;
  const type = Array.isArray(property.type)
    ? property.type.join("|")
    : (property.type ?? "unknown");
  if (type === "array") {
    const items = property.items === undefined ? "unknown" : fieldShape(property.items);
    return `array<${items}>${property.nullable === true ? "|null" : ""}`;
  }
  let shape = type;
  if (property.format !== undefined) shape += `:${property.format}`;
  if (property.nullable === true) shape += "|null";
  return shape;
}

/** Every property of `schema` as `field -> descriptor`, the pinnable shape. */
export function fieldShapes(schema: OpenApiSchema): Record<string, string> {
  const shapes: Record<string, string> = {};
  for (const [field, property] of Object.entries(schema.properties ?? {})) {
    shapes[field] = fieldShape(property);
  }
  return shapes;
}

/** The schema's `required` list, sorted so pins are order-insensitive. */
export function sortedRequired(schema: OpenApiSchema): string[] {
  return [...(schema.required ?? [])].sort();
}
