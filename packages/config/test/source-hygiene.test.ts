/**
 * One byte, and two of this package's source files were invisible to every
 * audit tool in the repo.
 *
 * `src/validate/plugins.ts` and `src/x402-scope.ts` each embedded a LITERAL NUL
 * (U+0000) in a template literal, as a separator in a composite `Set` key:
 *
 *     const orderKey = `${plugin.kind}<NUL>${plugin.order}`;
 *
 * The value is correct and the runtime does not care. `grep`/`ripgrep` do:
 * a NUL in the first buffer makes a file BINARY, and binary files are skipped
 * silently — no error, no warning, exit code 1 as if nothing matched. So
 * `grep -rn validatePlugins packages/config/src` reported only the import site
 * in `validate.ts` and NOT the 463-line file that defines it, and every
 * "is this ported?" / "does anything call this?" sweep quietly excluded
 * `validatePlugins`, `validateBuiltinPluginShape`, the whole manifest and
 * permission-gate family, and the x402 scope validator.
 *
 * That is the repo's dominant defect with a new delivery mechanism: not code
 * that is missing, but code an audit cannot see and therefore reports as
 * missing — or, worse, code that could be deleted while a marker-sweep says the
 * package is clean. Both were rewritten to the `\u0000` escape, which is the
 * same character at runtime and plain ASCII on disk.
 *
 * This test is the tripwire, over `src/` AND `test/`. Over `test/` because
 * while writing this very file a stray NUL landed in the paragraph above — the
 * mistake is that easy to make, and a scan that skipped the test tree would not
 * have caught its own.
 */
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(full);
    return entry.name.endsWith(".ts") ? [full] : [];
  });
}

const FILES = [
  ...sourceFiles(path.join(packageRoot, "src")),
  ...sourceFiles(path.join(packageRoot, "test")),
];

describe("source hygiene", () => {
  test("the scan actually found this package's sources", () => {
    // Without this, an empty list would make the assertion below vacuously true
    // — which is the same class of bug it is guarding against.
    expect(FILES.length).toBeGreaterThan(30);
    expect(FILES.some((file) => file.endsWith(path.join("validate", "plugins.ts")))).toBe(true);
    expect(FILES.some((file) => file.endsWith("source-hygiene.test.ts"))).toBe(true);
  });

  // The `types: ["node"]` in this package's tsconfig exists ONLY for the test
  // above. It would silently widen the `src` program too, and a `node:*` import
  // that type-checks here would fail at runtime in `workerd` — so the library
  // half is held to the Workers-only surface separately.
  test("no src/ module imports a node: built-in", () => {
    const offenders = FILES.filter(
      (file) =>
        file.includes(`${path.sep}src${path.sep}`) &&
        /from "node:|require\("node:/.test(readFileSync(file, "utf8")),
    ).map((file) => path.relative(packageRoot, file));
    expect(offenders).toEqual([]);
  });

  test.each(FILES.map((file) => [path.relative(packageRoot, file), file]))(
    "%s contains no control bytes that make grep treat it as binary",
    (_label, file) => {
      const bytes = readFileSync(file);
      expect(bytes.includes(0)).toBe(false);
    },
  );
});
