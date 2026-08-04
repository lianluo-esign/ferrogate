import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const workflow = readFileSync(
  path.join(repoRoot, ".github/workflows/api-contract-drift.yml"),
  "utf8",
);

describe("API contract drift workflow", () => {
  it("runs the load-bearing generated-client manifest suite", () => {
    expect(workflow).toContain("bun x vitest run tools/generated-clients/test");
  });

  it("runs Python SDK metadata and runtime tests", () => {
    expect(workflow).toContain("python3 -m unittest discover -s sdks/python");
  });
});
