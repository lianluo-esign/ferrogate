/**
 * NO SOURCE FILE MAY CONTAIN A RAW NUL BYTE.
 *
 * This is not style. `grep` classifies a file containing a NUL as BINARY and
 * skips it silently — no warning, no non-zero exit, just a file that is not in
 * the results. `src/middleware/network.ts` carried one for several waves as the
 * separator in `policyCacheKey`'s `join(...)`, typed as a literal instead of
 * the `"\0"` escape. For as long as it did, EVERY `grep -r PORT-TODO src/`
 * audit of this Worker reported on one fewer file than exists and nobody could
 * tell, because the omission looks exactly like a clean file.
 *
 * Two files in this repo have now done it. This test is why a third cannot:
 * `?raw` inlines the file's real bytes at build time, so the assertion runs
 * against what is on disk rather than against a re-encoding.
 *
 * The fix is never to remove the separator — it is to write `"\0"`, which
 * produces the identical one-character string at runtime and leaves the source
 * file text.
 */
import { describe, expect, it } from "vitest";

/**
 * The byte itself, built at RUNTIME.
 *
 * Writing it as a literal here would make THIS file binary to `grep` and the
 * guard would be the third instance of the very thing it exists to prevent.
 * `"\\u0000"` would also be safe; `String.fromCharCode(0)` is used because it
 * cannot be mistaken for one while skimming.
 */
const NUL = String.fromCharCode(0);

/**
 * `import.meta.glob` is a VITE transform, not a runtime call: it is rewritten
 * at build time into a static map of `path → file contents`, which is the only
 * way a workerd test (no filesystem) can inspect source bytes at all.
 *
 * It must be written out in full — Vite refuses an aliased reference, because
 * the transform is textual. The local `ImportMeta` augmentation is because this
 * workspace's `tsconfig` does not pull in `vite/client`, and adding that
 * reference project-wide is a wider change than one test file warrants.
 */
declare global {
  interface ImportMeta {
    glob(pattern: string, options: object): Record<string, string>;
  }
}

const SOURCES = import.meta.glob("../src/**/*.ts", {
  query: "?raw",
  import: "default",
  eager: true,
});

describe("source hygiene", () => {
  it("globbed every source file — an empty scan would assert nothing", () => {
    // Without this the test below would pass vacuously if the glob pattern ever
    // stopped matching (a moved directory, a changed vite root).
    const names = Object.keys(SOURCES);
    expect(names.length).toBeGreaterThan(50);
    expect(names.some((name) => name.endsWith("/middleware/network.ts"))).toBe(true);
    expect(names.some((name) => name.endsWith("/cache/config.ts"))).toBe(true);
  });

  it("contains no raw NUL byte in any src/**/*.ts", () => {
    const offenders = Object.entries(SOURCES)
      .filter(([, text]) => text.includes(NUL))
      .map(([name]) => name);
    expect(offenders).toEqual([]);
  });
});
