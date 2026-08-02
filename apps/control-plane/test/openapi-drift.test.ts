/**
 * THE published-contract anti-drift gate (issue #734).
 *
 * `docs/openapi/admin-api.openapi.json` is a CODE GENERATOR INPUT, not prose:
 * `admin-console/src/lib/api-types.generated.ts` and the TypeScript admin SDK
 * are both emitted from it. An operation that ships in
 * `docs/openapi/runtime-api-contract.json` — routed, authenticated, RBAC'd —
 * but never lands in the OpenAPI is therefore not merely undocumented: it is
 * uncallable and untypeable from every generated client.
 *
 * ## Why this file exists at all, when `scripts/check-openapi.py` already says it
 *
 * Because that script only ran from `.github/workflows/api-contract-drift.yml`,
 * which is disabled at the repository level (CI here is release-only by owner
 * directive). Within hours of it being switched off, three merged PRs drifted
 * twelve operations past it — #682's BYOK registration, #694's prompt
 * deployment labels, #695's semantic-cache policy — and every generated client
 * silently lost all three features. A gate that is switched off is not a gate
 * that is cheap; it is a gate that is absent.
 *
 * So the invariant lives HERE, in a workspace `bun run test` executes on every
 * run, next to `test/contract.test.ts` — which polices the *other* half of the
 * same document (contract operation ⇄ mounted handler). Neither subsumes the
 * other: `contract.test.ts` proves the code implements what the contract
 * declares; this file proves the published artifact DESCRIBES it.
 *
 * The Python script is kept and is still the richer check (it also validates the
 * backward-compatibility baseline). This is the portion that must never be
 * skippable, re-implemented against the same two JSON documents rather than
 * shelling out, because workerd has no subprocess.
 *
 * ## Direction
 *
 * Checked BOTH ways. Runtime → OpenAPI is the defect this issue names. OpenAPI →
 * runtime is the reverse failure: an operation described to SDK consumers that
 * no router serves, i.e. a generated client method that 404s. As of #734 the two
 * documents are exactly 1:1 at 265 operations, so neither direction has an
 * allowance list, and adding one would be the beginning of the same problem.
 */
import { describe, expect, it } from "vitest";
import openapiDocument from "../../../docs/openapi/admin-api.openapi.json";
import contractDocument from "../../../docs/openapi/runtime-api-contract.json";
import { EXPECTED_TOTAL_OPERATION_COUNT } from "../src/contract.js";

/** The OpenAPI path-item keys that are operations rather than metadata. */
const HTTP_METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"] as const;

interface RawContractOperation {
  path: string;
  method: string;
  operation_id: string;
  visibility: string;
  auth: { kind: string; scope: string | null };
  rbac_action: string | null;
}

interface RawOpenApiOperation {
  operationId?: unknown;
  responses?: unknown;
  "x-ferrogate-contract"?: unknown;
}

const CONTRACT = contractDocument as unknown as { operations: RawContractOperation[] };
const OPENAPI = openapiDocument as unknown as {
  paths: Record<string, Record<string, RawOpenApiOperation>>;
};

/** `"GET /admin/v1/provider-credentials"` — the key both documents are compared on. */
function key(method: string, path: string): string {
  return `${method.toUpperCase()} ${path}`;
}

/**
 * Every operation the published OpenAPI describes, keyed by `METHOD path`.
 *
 * Read from the raw document, exactly like `test/contract.test.ts` reads the
 * runtime contract raw: a gate that went through a parser could be satisfied by
 * a bug in that parser.
 */
function openapiOperations(document: typeof OPENAPI): Map<string, RawOpenApiOperation> {
  const found = new Map<string, RawOpenApiOperation>();
  for (const [path, item] of Object.entries(document.paths)) {
    for (const method of HTTP_METHODS) {
      const operation = item[method];
      if (operation === undefined) continue;
      found.set(key(method, path), operation);
    }
  }
  return found;
}

/** What `x-ferrogate-contract` must equal, built from the runtime contract row. */
function expectedClassification(operation: RawContractOperation): unknown {
  return {
    visibility: operation.visibility,
    auth: operation.auth,
    rbac_action: operation.rbac_action,
  };
}

/**
 * The whole gate as one pure function, so the failure path can be DRIVEN below
 * rather than assumed reachable. Returns one human-readable line per drift.
 */
function openapiDrift(
  document: typeof OPENAPI,
  operations: readonly RawContractOperation[],
): string[] {
  const documented = openapiOperations(document);
  const runtime = new Map(
    operations.map((operation) => [key(operation.method, operation.path), operation]),
  );
  const failures: string[] = [];

  for (const name of [...runtime.keys()].sort()) {
    if (!documented.has(name)) {
      failures.push(`runtime contract operation missing from OpenAPI: ${name}`);
    }
  }
  for (const name of [...documented.keys()].sort()) {
    if (!runtime.has(name)) {
      failures.push(`stale OpenAPI operation missing from runtime contract: ${name}`);
    }
  }
  for (const name of [...runtime.keys()].sort()) {
    const operation = documented.get(name);
    const declared = runtime.get(name);
    if (operation === undefined || declared === undefined) continue;
    if (operation.operationId !== declared.operation_id) {
      failures.push(
        `operationId drift for ${name}: runtime=${declared.operation_id} openapi=${String(operation.operationId)}`,
      );
    }
    const classification = JSON.stringify(operation["x-ferrogate-contract"]);
    const expected = JSON.stringify(expectedClassification(declared));
    if (classification !== expected) {
      failures.push(
        `classification drift for ${name}: runtime=${expected} openapi=${classification}`,
      );
    }
  }
  return failures;
}

describe("published OpenAPI ⇄ runtime contract", () => {
  it("describes every routed operation, and describes nothing that is not routed", () => {
    const failures = openapiDrift(OPENAPI, CONTRACT.operations);
    // The listing IS the message: "265 !== 253" tells an engineer nothing.
    expect(failures, failures.join("\n")).toEqual([]);
  });

  it("is 1:1 with the runtime contract, operation for operation", () => {
    expect(openapiOperations(OPENAPI).size).toBe(EXPECTED_TOTAL_OPERATION_COUNT);
    expect(CONTRACT.operations).toHaveLength(EXPECTED_TOTAL_OPERATION_COUNT);
  });

  it("gives every described operation an operationId and at least one response", () => {
    const incomplete = [...openapiOperations(OPENAPI).entries()]
      .filter(
        ([, operation]) =>
          typeof operation.operationId !== "string" ||
          operation.operationId === "" ||
          typeof operation.responses !== "object" ||
          operation.responses === null ||
          Object.keys(operation.responses as object).length === 0,
      )
      .map(([name]) => name);
    expect(incomplete).toEqual([]);
  });

  it("never reuses an operationId", () => {
    const ids = [...openapiOperations(OPENAPI).values()].map((operation) =>
      String(operation.operationId),
    );
    const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index).sort();
    expect(duplicates).toEqual([]);
  });

  /**
   * The proof that the three assertions above are not vacuous.
   *
   * Each drift the real check would report is reproduced against a MUTATED copy
   * of the published document, so the failure path is executed on every run. A
   * gate whose red branch is never taken is indistinguishable from a gate that
   * cannot go red — which is precisely how #734's twelve operations shipped.
   */
  describe("the gate goes RED when the document drifts", () => {
    const REMOVED = "/admin/v1/provider-credentials";

    function withPathRemoved(path: string): typeof OPENAPI {
      const paths = { ...OPENAPI.paths };
      delete paths[path];
      return { paths };
    }

    it("names an operation deleted from the OpenAPI — #734's exact defect", () => {
      const failures = openapiDrift(withPathRemoved(REMOVED), CONTRACT.operations);
      expect(failures).toEqual([`runtime contract operation missing from OpenAPI: GET ${REMOVED}`]);
    });

    it("names an operation described but not routed", () => {
      const routed = CONTRACT.operations.filter(
        (operation) => !(operation.method.toUpperCase() === "GET" && operation.path === REMOVED),
      );
      expect(openapiDrift(OPENAPI, routed)).toEqual([
        `stale OpenAPI operation missing from runtime contract: GET ${REMOVED}`,
      ]);
    });

    it("names a renamed operationId — the generated client method that vanished", () => {
      const renamed = CONTRACT.operations.map((operation) =>
        operation.operation_id === "listProviderCredentials"
          ? { ...operation, operation_id: "listByokCredentials" }
          : operation,
      );
      expect(openapiDrift(OPENAPI, renamed)).toEqual([
        `operationId drift for GET ${REMOVED}: runtime=listByokCredentials openapi=listProviderCredentials`,
      ]);
    });

    it("names a scope the OpenAPI no longer agrees with", () => {
      const widened = CONTRACT.operations.map((operation) =>
        operation.operation_id === "listProviderCredentials"
          ? { ...operation, auth: { kind: "bearer", scope: "admin.write" } }
          : operation,
      );
      const failures = openapiDrift(OPENAPI, widened);
      expect(failures).toHaveLength(1);
      expect(failures[0]).toContain(`classification drift for GET ${REMOVED}`);
      expect(failures[0]).toContain("admin.write");
    });
  });
});

/**
 * The twelve operations #734 restored, named individually.
 *
 * The sweep above already covers them, but it covers them ANONYMOUSLY: a future
 * edit that dropped the whole `provider-credentials` family from BOTH documents
 * at once would keep the sweep green (still 1:1) while silently un-shipping a
 * feature from every generated client. Naming them makes that a deliberate,
 * visible act rather than an accident.
 */
describe("#734: the twelve operations are described, not merely routed", () => {
  const RESTORED = [
    "GET /admin/v1/provider-credentials",
    "PUT /admin/v1/provider-credentials/{alias}",
    "DELETE /admin/v1/provider-credentials/{alias}",
    "GET /admin/v1/prompt-templates/{id}/labels",
    "PUT /admin/v1/prompt-templates/{id}/labels/{label}",
    "DELETE /admin/v1/prompt-templates/{id}/labels/{label}",
    "GET /admin/v1/semantic-cache-policies",
    "POST /admin/v1/semantic-cache-policies",
    "GET /admin/v1/semantic-cache-policies/{scope_type}/{scope_id}",
    "PUT /admin/v1/semantic-cache-policies/{scope_type}/{scope_id}",
    "DELETE /admin/v1/semantic-cache-policies/{scope_type}/{scope_id}",
    "POST /admin/v1/semantic-cache-policies/{scope_type}/{scope_id}/invalidate",
  ];

  it("carries all twelve with a typed 200/201 body", () => {
    const documented = openapiOperations(OPENAPI);
    const missing = RESTORED.filter((name) => !documented.has(name));
    expect(missing, `absent from the OpenAPI: ${missing.join(", ")}`).toEqual([]);

    const untyped = RESTORED.filter((name) => {
      const responses = documented.get(name)?.responses as
        | Record<string, { content?: Record<string, { schema?: unknown }> }>
        | undefined;
      const success = responses?.["200"] ?? responses?.["201"];
      return success?.content?.["application/json"]?.schema === undefined;
    });
    expect(untyped, `no application/json success schema: ${untyped.join(", ")}`).toEqual([]);
  });

  /**
   * #682's operations carry provider secrets. The request schema takes one; NO
   * response may return it, and no example anywhere in the document may contain
   * one. `last4` is the entire disclosure budget.
   */
  it("never describes a response that returns the submitted credential", () => {
    const documented = openapiOperations(OPENAPI);
    for (const name of RESTORED.filter((entry) => entry.includes("provider-credentials"))) {
      const responses = documented.get(name)?.responses as Record<string, unknown>;
      const serialized = JSON.stringify(responses);
      expect(serialized, `${name} response mentions the credential`).not.toContain('"value"');
      expect(serialized).not.toContain("ciphertext");
      expect(serialized).not.toContain('"iv"');
    }
  });

  it("marks the credential field write-only and gives it no example", () => {
    const put = openapiOperations(OPENAPI).get("PUT /admin/v1/provider-credentials/{alias}") as {
      requestBody?: { content: Record<string, { schema: { $ref: string } }> };
    };
    const ref = put.requestBody?.content["application/json"]?.schema.$ref;
    expect(ref).toBe("#/components/schemas/AdminProviderCredentialMutation");

    const schemas = (
      openapiDocument as unknown as {
        components: {
          schemas: Record<
            string,
            { properties: Record<string, Record<string, unknown>> } | undefined
          >;
        };
      }
    ).components.schemas;
    const value = schemas.AdminProviderCredentialMutation?.properties.value;
    expect(value?.writeOnly).toBe(true);
    expect(value?.example).toBeUndefined();
    expect(value?.default).toBeUndefined();
  });
});
