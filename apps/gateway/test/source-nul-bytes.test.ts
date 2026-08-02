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

/**
 * Every path under EVERY Worker's `src/`, extension-free — because the second
 * form of this hazard hides in the FILE NAME rather than the file contents, and
 * the `*.ts` glob above is blind to it by construction.
 *
 * Wave 23 found two files in this repo whose NAMES contain literal newlines:
 *
 *     apps/mcp/src/admission/gate.ts\n    code: "quota_scope_disabled",…
 *     apps/agent-runtime/src/admission/admit.ts\n    message: (requestId…
 *
 * both 27,809 bytes, byte-identical to each other, and both a stale snapshot of
 * `apps/agent-runtime/src/middleware/auth.ts` produced by a shell redirect whose
 * target was an unquoted multi-line variable.
 *
 * They are INERT for the build — no name ends in `.ts`, so no glob, no
 * `tsconfig` include and no bundler entry resolves them. They are NOT inert for
 * `grep`, which is this project's primary evidence-gathering instrument: the
 * first line of such a name is indistinguishable from a real path, so
 * `grep -rn tenancy_suspended apps/mcp/src` reported a hit at
 * `apps/mcp/src/admission/gate.ts:114` — text that is not in that file, in a
 * Worker that reaches its suspension gate through an entirely different module.
 * During the wave-23 certification itself, a `grep -rc token_budget_exceeded`
 * run to decide a CLASS A verdict printed these names as though they were
 * matching files.
 *
 * That is one substitution away from a wrong verdict in a certification
 * document, and it is the same class as the NUL-byte incident above: evidence
 * that looks complete and is not.
 */
const ALL_WORKER_PATHS = import.meta.glob("../../*/src/**/*", {
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

  it("scanned every app's src/ — an app-scoped glob would assert nothing", () => {
    // The companion vacuity guard for the cross-app glob. Without it the
    // path-name assertion below would pass trivially the day the relative
    // pattern stops resolving.
    //
    // Vite normalises the CITING package's own matches to `../src/…` and every
    // sibling's to `../../<app>/src/…`, so the owning app is `..`. Deriving the
    // set from the keys rather than asserting a hand-written prefix is what
    // keeps this honest when a sixth app is added.
    const names = Object.keys(ALL_WORKER_PATHS);
    expect(names.length).toBeGreaterThan(200);
    const scanned = new Set(
      names.map((name) => name.split("/src/")[0]?.replace(/^\.\.\/\.\.\//, "") ?? ""),
    );
    // `..` is `apps/gateway` itself.
    expect([...scanned].sort()).toEqual([
      "..",
      "agent-runtime",
      "cli",
      "control-plane",
      "mcp",
      "telemetry",
    ]);
  });

  it("no path under any apps/*/src contains a control character", () => {
    // A newline in a FILE NAME makes `grep -rn` attribute one file's text to
    // another file's path. `\p{Cc}` is the Unicode control class: C0, DEL and
    // C1. A legitimate source path in this repo contains none of them.
    const offenders = Object.keys(ALL_WORKER_PATHS)
      .filter((name) => /\p{Cc}/u.test(name))
      // Report the FIRST line only: printing the whole name re-injects the
      // newline into the failure message and makes the report unreadable.
      .map((name) => `${name.split(/\p{Cc}/u)[0]} …(+${name.split(/\p{Cc}/u).length - 1} lines)`);
    expect(offenders).toEqual([]);
  });
});
