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
import { existsSync, readFileSync, readdirSync } from "node:fs";
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

/**
 * ...and the tripwire only covered ONE package, which is how it got bitten a
 * second time.
 *
 * This file was written after `packages/config` was cleaned, and it scans
 * `packages/config` only. The other twelve libraries were never covered, and a
 * re-scan of the whole tree found the same defect had landed again, unnoticed,
 * in a package with no tripwire:
 *
 *   - `packages/guardrails/src/envelope.ts`     — 1 NUL (`${source}<NUL>${location}`)
 *   - `packages/guardrails/src/deterministic.ts` — 3 NULs (a 4-part composite key)
 *
 * Both files were BINARY to `grep`/`rg` for as long as they existed, so
 * `evaluateDeterministic`, the whole segment/category dedup, and the envelope's
 * per-source location index were invisible to every census run through a
 * line-oriented tool — including the ones that produced the parity audits.
 *
 * A per-package copy of this file would be thirteen copies to keep in step, and
 * the one that matters is always the one nobody wrote. So the scan below is
 * TREE-WIDE over `packages/*`, and it lives here because this is where the
 * tripwire already is. A failure naming another package is not a mislocated
 * test: it is this invariant doing its job in the one place that holds it.
 *
 * (`apps/*` is deliberately out of scope — a `packages/*` library must not
 * assert on a Worker's tree. The apps carry their own composition-root gates.)
 */
const packagesRoot = path.resolve(packageRoot, "..");

const TREE_WIDE_FILES = readdirSync(packagesRoot, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .flatMap((entry) =>
    ["src", "test"]
      .map((sub) => path.join(packagesRoot, entry.name, sub))
      .filter((dir) => existsSync(dir))
      .flatMap((dir) => sourceFiles(dir)),
  );

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

  describe("tree-wide over packages/*", () => {
    test("the tree-wide scan actually reached the other libraries", () => {
      // Same vacuity guard, one level up: an empty or config-only list would
      // make the NUL assertion below pass while covering nothing. Named
      // packages, not just a count, because a count is satisfied by
      // `packages/config` alone.
      const packagesSeen = new Set(
        TREE_WIDE_FILES.map((file) => path.relative(packagesRoot, file).split(path.sep)[0]),
      );
      for (const name of ["config", "guardrails", "storage", "billing", "secrets"]) {
        expect(packagesSeen).toContain(name);
      }
      expect(packagesSeen.size).toBeGreaterThan(10);
      expect(TREE_WIDE_FILES.length).toBeGreaterThan(FILES.length);
      // The two files that were binary until this scan existed.
      for (const relative of ["guardrails/src/envelope.ts", "guardrails/src/deterministic.ts"]) {
        expect(
          TREE_WIDE_FILES.some(
            (file) => path.relative(packagesRoot, file) === path.normalize(relative),
          ),
        ).toBe(true);
      }
    });

    test("no packages/*/{src,test} file contains a NUL byte", () => {
      const offenders = TREE_WIDE_FILES.filter((file) => readFileSync(file).includes(0)).map(
        (file) => path.relative(packagesRoot, file),
      );
      expect(offenders).toEqual([]);
    });
  });
});
