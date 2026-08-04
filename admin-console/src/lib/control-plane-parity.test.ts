// The console's API contract is the shared runtime contract (#696).
//
// WHAT THIS CLOSES
// ----------------
// The console generates `src/lib/api-types.generated.ts` from
// `docs/openapi/admin-api.openapi.json`, and the `api-contract-drift` workflow
// gates that one hop. The hop BEFORE it was ungated: nothing checked that
// `admin-api.openapi.json` still describes the shared runtime surface. The
// TypeScript control plane owns only its admin slice of that document and is
// table-driven off the same source —
// `docs/openapi/runtime-api-contract.json`, which `apps/control-plane/src/
// contract.ts` imports, validates at module load, and turns directly into its
// route table and its auth/RBAC guards.
//
// Two hand-maintained documents describing one surface is exactly the shape
// that rots quietly: the console would keep type-checking against a spec the
// server had moved on from, and the first symptom would be a 404 in a browser.
//
// It holds TODAY — that was the first thing #696's audit checked, and all
// shared operations match on both sides with zero divergence in either
// direction. The backend origin predicate in `config.ts` separately sends
// gateway-owned `/v1/*` and `/sites/*` paths to the data plane; this test does
// not claim that the control-plane Worker serves those paths.
//
// WHY NOT COMPARE THE CONSOLE'S CALL SITES INSTEAD
// ------------------------------------------------
// `admin-api-coverage.test.ts` already walks the console's real call sites
// (the resource registry's `basePath`s and the `/admin/v1/<group>` literals in
// each bespoke page) and requires every contract GROUP to have a surface or a
// reviewed exclusion. That gate answers "does the console cover the contract".
// This one answers the question underneath it — "is that contract the one the
// runtime implements" — and the two together are what make the coverage claim
// mean anything.
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const docsDir = path.resolve(testDir, "..", "..", "..", "docs", "openapi");
// Same relative hop `scripts/check-api-types-drift.mjs` and
// `admin-api-coverage.test.ts` take: <repo-root>/docs/openapi/.
const CONSOLE_SPEC = path.join(docsDir, "admin-api.openapi.json");
const RUNTIME_CONTRACT = path.join(docsDir, "runtime-api-contract.json");

const HTTP_METHODS = ["get", "post", "put", "patch", "delete"] as const;

interface RuntimeOperation {
  path: string;
  method: string;
  operation_id: string;
}

function readJson<T>(file: string): T {
  if (!existsSync(file)) {
    // Loud, never a silent skip: a moved document must fail here, where the
    // cause is named, rather than by making every assertion below vacuous.
    throw new Error(`control-plane parity gate: ${file} not found`);
  }
  return JSON.parse(readFileSync(file, "utf8")) as T;
}

/** `METHOD /path` for every operation the console's OpenAPI document declares. */
function consoleOperations(): Map<string, string> {
  const spec = readJson<{
    paths: Record<string, Record<string, { operationId?: string }>>;
  }>(CONSOLE_SPEC);
  const operations = new Map<string, string>();
  for (const [route, item] of Object.entries(spec.paths)) {
    for (const method of HTTP_METHODS) {
      const operation = item[method];
      if (operation === undefined) continue;
      operations.set(`${method.toUpperCase()} ${route}`, operation.operationId ?? "");
    }
  }
  return operations;
}

/** `METHOD /path` for every operation the shared runtime contract declares. */
function runtimeOperations(): Map<string, string> {
  const document = readJson<{ operations: RuntimeOperation[] }>(RUNTIME_CONTRACT);
  return new Map(
    document.operations.map((operation) => [
      `${operation.method.toUpperCase()} ${operation.path}`,
      operation.operation_id,
    ]),
  );
}

describe("the console's Admin API spec matches the runtime contract", () => {
  it("declares no operation the runtime does not route", () => {
    const runtime = runtimeOperations();
    const orphaned = [...consoleOperations().keys()].filter((key) => !runtime.has(key));
    // An orphan is a console screen that type-checks and 404s: the generated
    // client would carry the path, and no Worker would answer it.
    expect(
      orphaned,
      `in docs/openapi/admin-api.openapi.json but not in docs/openapi/runtime-api-contract.json: ${orphaned.join(", ")}`,
    ).toEqual([]);
  });

  it("is not missing an operation the runtime routes", () => {
    const spec = consoleOperations();
    const unspecified = [...runtimeOperations().keys()].filter((key) => !spec.has(key));
    // The mirror direction: a served operation absent from the console's spec is
    // invisible to `npm run generate:api`, so no console screen can be built
    // against it without hand-writing an untyped call.
    expect(
      unspecified,
      `served by the runtime but absent from docs/openapi/admin-api.openapi.json: ${unspecified.join(", ")}`,
    ).toEqual([]);
  });

  it("agrees on the operationId of every shared operation", () => {
    // The path/method pair is what routes; the `operationId` is what the
    // generated client and `apps/control-plane`'s handler table are BOTH keyed
    // by, so a rename on one side alone silently unhooks a handler from its
    // contract entry.
    const runtime = runtimeOperations();
    const mismatched: string[] = [];
    for (const [key, operationId] of consoleOperations()) {
      const expected = runtime.get(key);
      if (expected !== undefined && expected !== operationId) {
        mismatched.push(`${key}: spec ${operationId} vs contract ${expected}`);
      }
    }
    expect(mismatched, mismatched.join("; ")).toEqual([]);
  });
});
