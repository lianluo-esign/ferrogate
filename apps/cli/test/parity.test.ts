/**
 * The #365 OpenAPI-to-CLI parity gate (port of Rust `parity_test.rs`).
 *
 * Two halves:
 *  - the ENGINE tests, which prove the diff actually detects a synthetic gap,
 *    duplicate, extra mapping and stale exclusion (so a green real gate is not
 *    green because the engine reports nothing);
 *  - the GATE itself, run against the checked-in
 *    `docs/openapi/admin-api.openapi.json` and the live `GROUPS` registry.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import {
  DATA_PLANE_MARKER,
  OPENAPI_DOCUMENT_PATH,
  REVIEWED_EXCLUSIONS,
  type ReviewedExclusion,
  buildReport,
  cliMapping,
  duplicateMappings,
  isClean,
  mappedOperationIds,
  parseOpenApiSurface,
  renderReport,
} from "../src/parity.js";
import { GROUPS, type GroupDescriptor, coverageManifest, read } from "../src/registry.js";

const REPO_ROOT = resolvePath(dirname(fileURLToPath(import.meta.url)), "../../..");

function loadContract(): string {
  return readFileSync(resolvePath(REPO_ROOT, OPENAPI_DOCUMENT_PATH), "utf8");
}

/** A minimal synthetic contract so the engine tests do not depend on the real one. */
function syntheticContract(): string {
  return JSON.stringify({
    paths: {
      "/admin/v1/widgets": {
        get: { operationId: "listWidgets", "x-ferrogate-contract": { visibility: "admin" } },
        post: { operationId: "createWidget", "x-ferrogate-contract": { visibility: "public" } },
      },
      "/admin/v1/internal": {
        get: { operationId: "scrapeMetrics", "x-ferrogate-contract": { visibility: "internal" } },
      },
      "/v1/chat/completions": {
        post: {
          operationId: "createChatCompletion",
          [DATA_PLANE_MARKER]: true,
          "x-ferrogate-contract": { visibility: "public" },
        },
      },
    },
  });
}

function syntheticGroup(
  name: string,
  verbs: readonly { verb: string; operationId: string }[],
): GroupDescriptor {
  return {
    name,
    about: `${name} (synthetic)`,
    verbs: verbs.map((entry) => read(entry.verb, entry.verb, entry.operationId)),
    build: () => ({ method: "GET", path: `/admin/v1/${name}`, query: [] }),
  };
}

describe("parity engine — surface parsing", () => {
  test("splits public/admin, internal and data-plane operations", () => {
    const surface = parseOpenApiSurface(syntheticContract());
    expect(surface.coverable).toEqual(["createWidget", "listWidgets"]);
    expect(surface.internal).toEqual(["scrapeMetrics"]);
    expect(surface.dataPlane).toEqual(["createChatCompletion"]);
  });

  test("a data-plane operation is NOT coverable even though its visibility is public", () => {
    const surface = parseOpenApiSurface(syntheticContract());
    expect(surface.coverable).not.toContain("createChatCompletion");
  });

  test("fails closed on an operation with no operationId", () => {
    const document = JSON.stringify({
      paths: { "/x": { get: { "x-ferrogate-contract": { visibility: "admin" } } } },
    });
    expect(() => parseOpenApiSurface(document)).toThrow(/GET \/x is missing operationId/);
  });

  test("fails closed on an operation with no declared visibility", () => {
    const document = JSON.stringify({ paths: { "/x": { get: { operationId: "getX" } } } });
    expect(() => parseOpenApiSurface(document)).toThrow(/missing x-ferrogate-contract.visibility/);
  });

  test("fails closed on a document with no coverable operations at all", () => {
    const document = JSON.stringify({
      paths: {
        "/x": { get: { operationId: "getX", "x-ferrogate-contract": { visibility: "internal" } } },
      },
    });
    expect(() => parseOpenApiSurface(document)).toThrow(/no coverable/);
  });

  test("rejects a document with no paths object", () => {
    expect(() => parseOpenApiSurface("{}")).toThrow(/no `paths` object/);
  });
});

describe("parity engine — the diff detects real drift", () => {
  const surface = parseOpenApiSurface(syntheticContract());

  test("a fully-mapped surface is clean", () => {
    const mapping = cliMapping([
      syntheticGroup("widgets", [
        { verb: "list", operationId: "listWidgets" },
        { verb: "create", operationId: "createWidget" },
      ]),
    ]);
    const report = buildReport(surface, mapping, []);
    expect(report.missing).toEqual([]);
    expect(report.covered).toEqual(["createWidget", "listWidgets"]);
    expect(isClean(report)).toBe(true);
  });

  test("an unmapped coverable operation is reported as missing", () => {
    const mapping = cliMapping([
      syntheticGroup("widgets", [{ verb: "list", operationId: "listWidgets" }]),
    ]);
    const report = buildReport(surface, mapping, []);
    expect(report.missing).toEqual(["createWidget"]);
    expect(isClean(report)).toBe(false);
    expect(renderReport(report)).toContain("- createWidget");
  });

  test("a reviewed exclusion moves a gap out of missing without hiding it", () => {
    const mapping = cliMapping([
      syntheticGroup("widgets", [{ verb: "list", operationId: "listWidgets" }]),
    ]);
    const excuse: ReviewedExclusion = {
      operationId: "createWidget",
      owner: "tests",
      reason: "synthetic",
    };
    const report = buildReport(surface, mapping, [excuse]);
    expect(report.missing).toEqual([]);
    expect(report.excludedMissing).toEqual(["createWidget"]);
    expect(isClean(report)).toBe(true);
  });

  test("an exclusion for an operation that IS mapped is stale and fails the gate", () => {
    const mapping = cliMapping([
      syntheticGroup("widgets", [
        { verb: "list", operationId: "listWidgets" },
        { verb: "create", operationId: "createWidget" },
      ]),
    ]);
    const report = buildReport(surface, mapping, [
      { operationId: "createWidget", owner: "tests", reason: "synthetic" },
    ]);
    expect(report.staleExclusions).toEqual(["createWidget"]);
    expect(isClean(report)).toBe(false);
  });

  test("an exclusion naming an operation the contract no longer has is stale", () => {
    const mapping = cliMapping([
      syntheticGroup("widgets", [
        { verb: "list", operationId: "listWidgets" },
        { verb: "create", operationId: "createWidget" },
      ]),
    ]);
    const report = buildReport(surface, mapping, [
      { operationId: "deleteWidgetLongGone", owner: "tests", reason: "synthetic" },
    ]);
    expect(report.staleExclusions).toEqual(["deleteWidgetLongGone"]);
    expect(isClean(report)).toBe(false);
  });

  test("a verb bound to a data-plane operation is EXTRA, not covered (#390)", () => {
    const mapping = cliMapping([
      syntheticGroup("widgets", [
        { verb: "list", operationId: "listWidgets" },
        { verb: "create", operationId: "createWidget" },
        { verb: "chat", operationId: "createChatCompletion" },
      ]),
    ]);
    const report = buildReport(surface, mapping, []);
    expect(report.extra).toEqual(["createChatCompletion"]);
    expect(isClean(report)).toBe(false);
  });

  test("a verb bound to an internal operation is EXTRA", () => {
    const mapping = cliMapping([
      syntheticGroup("widgets", [
        { verb: "list", operationId: "listWidgets" },
        { verb: "create", operationId: "createWidget" },
        { verb: "metrics", operationId: "scrapeMetrics" },
      ]),
    ]);
    expect(buildReport(surface, mapping, []).extra).toEqual(["scrapeMetrics"]);
  });

  test("two verbs claiming one operation is a duplicate, naming both sites", () => {
    const mapping = cliMapping([
      syntheticGroup("widgets", [
        { verb: "list", operationId: "listWidgets" },
        { verb: "create", operationId: "createWidget" },
      ]),
      syntheticGroup("gadgets", [{ verb: "list", operationId: "listWidgets" }]),
    ]);
    const duplicates = duplicateMappings(mapping);
    expect(duplicates.get("listWidgets")).toEqual(["gadgets list", "widgets list"]);
    const report = buildReport(surface, mapping, []);
    expect(isClean(report)).toBe(false);
    expect(renderReport(report)).toContain("listWidgets: gadgets list, widgets list");
  });
});

describe("the #365 parity gate (real contract, real registry)", () => {
  const surface = parseOpenApiSurface(loadContract());
  const mapping = cliMapping(GROUPS);
  const report = buildReport(surface, mapping);

  test("the registry covers every coverable Control Plane operation", () => {
    expect(renderReport(report)).toBeTypeOf("string");
    expect(report.missing, renderReport(report)).toEqual([]);
    expect(report.extra, renderReport(report)).toEqual([]);
    expect([...report.duplicates.keys()], renderReport(report)).toEqual([]);
    expect(report.staleExclusions, renderReport(report)).toEqual([]);
    expect(isClean(report)).toBe(true);
  });

  test("the gate is not vacuous: it is diffing a real, non-trivial surface", () => {
    expect(surface.coverable.length).toBeGreaterThan(200);
    expect(report.covered.length).toBeGreaterThan(200);
    expect(surface.dataPlane.length).toBeGreaterThan(0);
  });

  test("every reviewed exclusion is a real, still-open gap in the contract", () => {
    for (const exclusion of REVIEWED_EXCLUSIONS) {
      expect(surface.coverable, exclusion.operationId).toContain(exclusion.operationId);
      expect(mappedOperationIds(mapping), exclusion.operationId).not.toContain(
        exclusion.operationId,
      );
      expect(exclusion.owner.length, exclusion.operationId).toBeGreaterThan(0);
      expect(exclusion.reason.length, exclusion.operationId).toBeGreaterThan(0);
    }
    expect(report.excludedMissing).toEqual(
      [...REVIEWED_EXCLUSIONS.map((entry) => entry.operationId)].sort(),
    );
  });

  test("no registry verb binds a data-plane operation (#390)", () => {
    const claimed = new Set(mappedOperationIds(mapping));
    for (const id of surface.dataPlane) expect(claimed, id).not.toContain(id);
  });

  test("coverageManifest() agrees with the parity mapping", () => {
    expect(coverageManifest()).toEqual(mappedOperationIds(mapping));
  });
});
