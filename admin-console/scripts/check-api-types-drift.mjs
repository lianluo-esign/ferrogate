// OpenAPI -> generated-client drift guard (#392, surfaced by #379).
//
// `src/lib/api-types.generated.ts` is produced by `npm run generate:api` from
// the committed contract `docs/openapi/admin-api.openapi.json`. Because those
// stale types can still type-check, contract changes that landed WITHOUT
// re-running the generator silently drifted the client from the spec (the exact
// regression #379 had to clean up). The admin-console gate's build step only
// catches drift that happens to break `tsc`; this guard catches ALL drift.
//
// It re-runs the SAME generator (openapi-typescript + the stamp banner, i.e. a
// byte-for-byte replay of `generate:api`) against the committed spec into an
// OS temp file and compares it to the committed generated file. It NEVER writes
// to the committed file — the comparison target is a throwaway temp path that
// is removed on exit. A clean tree passes (exit 0); any difference fails
// (exit 1) with the fix instruction.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const specPath = path.join(projectRoot, "..", "docs", "openapi", "admin-api.openapi.json");
const generatedPath = path.join(projectRoot, "src", "lib", "api-types.generated.ts");
const openapiCli = path.join(
  projectRoot,
  "node_modules",
  "openapi-typescript",
  "bin",
  "cli.js",
);

// Must stay byte-identical to scripts/stamp-generated-api-header.mjs so a clean
// tree produced by `generate:api` compares equal here.
const banner = `// GENERATED FILE — DO NOT EDIT.
// Source contract: docs/openapi/admin-api.openapi.json (repo root).
// Regenerate with: npm run generate:api   (from admin-console/)
`;

const scratch = mkdtempSync(path.join(tmpdir(), "ferrogate-api-types-"));
const tempOut = path.join(scratch, "api-types.generated.ts");

try {
  // Replay `generate:api` into the temp file: openapi-typescript then stamp.
  execFileSync(process.execPath, [openapiCli, specPath, "-o", tempOut], {
    cwd: projectRoot,
    stdio: ["ignore", "ignore", "inherit"],
  });

  const fresh = banner + readFileSync(tempOut, "utf8");
  const committed = readFileSync(generatedPath, "utf8");

  if (fresh !== committed) {
    console.error(
      "api-types drift: src/lib/api-types.generated.ts is stale vs " +
        "docs/openapi/admin-api.openapi.json.\n" +
        "The committed client types no longer match the OpenAPI contract.\n" +
        "Fix: run `npm run generate:api` (from admin-console/) and commit the result.",
    );
    process.exit(1);
  }

  console.log(
    "api-types drift: src/lib/api-types.generated.ts is in sync with admin-api.openapi.json",
  );
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
