/**
 * The grep-invisibility tripwire, ported from `packages/config/test/source-hygiene.test.ts`.
 *
 * `packages/config` shipped two source files that embedded a LITERAL NUL
 * (U+0000) as a separator inside a composite `Set` key:
 *
 *     const orderKey = `${plugin.kind}<NUL>${plugin.order}`;
 *
 * The runtime does not care. `grep`/`ripgrep` do: a NUL in the first buffer
 * makes a file BINARY, and binary files are skipped SILENTLY — no error, no
 * warning, exit code 1 exactly as if nothing matched. So every "is this
 * ported?" / "does anything import this?" sweep quietly excluded those files,
 * and a marker-count of the package came back short.
 *
 * That failure mode is not specific to `packages/config`, and this package is
 * where it would hurt most: `src/index.ts`'s mount inventory and
 * `test/mount-inventory.test.ts` are BOTH grep-shaped, and this package builds
 * composite keys from `(scope_type, scope_id)` / `(tenant, asset, channel)`
 * tuples in several places — precisely the shape that invites a NUL separator.
 * A NUL landing in `src/d1/wallet-d1.ts` would make the no-oversell reserve
 * invisible to the next audit that tried to find it.
 *
 * So the tripwire is here too, over `src/` AND `test/` — over `test/` because
 * the gate that re-derives the mount split lives there, and a scan that skipped
 * the test tree could not catch its own blinding.
 */
import { readFileSync, readdirSync } from "node:fs";
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
    // Without this, an empty list makes every assertion below vacuously true —
    // the same class of bug the file is guarding against.
    expect(FILES.length).toBeGreaterThan(30);
    // Three files named individually because they are the ones whose
    // disappearance from a grep would be most expensive: the money guard, the
    // mount inventory, and the gate that re-derives it.
    expect(FILES.some((f) => f.endsWith(path.join("d1", "wallet-d1.ts")))).toBe(true);
    expect(FILES.some((f) => f.endsWith(path.join("src", "index.ts")))).toBe(true);
    expect(FILES.some((f) => f.endsWith("mount-inventory.test.ts"))).toBe(true);
  });

  test.each(FILES.map((file) => [path.relative(packageRoot, file), file]))(
    "%s contains no control bytes that make grep treat it as binary",
    (_label, file) => {
      const bytes = readFileSync(file);
      expect(bytes.includes(0)).toBe(false);
    },
  );

  // `src/` must stay runnable inside `workerd`, which has no `node:*` unless
  // `nodejs_compat` is on. The test tree legitimately uses `node:fs` (this file
  // and `mount-inventory.test.ts` read the repo from disk), so the rule is
  // scoped to `src/` rather than being switched off.
  test("no src/ module imports a node: built-in", () => {
    const offenders = FILES.filter(
      (file) =>
        file.includes(`${path.sep}src${path.sep}`) &&
        /from "node:|require\("node:/.test(readFileSync(file, "utf8")),
    ).map((file) => path.relative(packageRoot, file));
    expect(offenders).toEqual([]);
  });
});
