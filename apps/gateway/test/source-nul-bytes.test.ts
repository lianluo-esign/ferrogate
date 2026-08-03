/**
 * NO SOURCE OR TEST FILE MAY CONTAIN A RAW NUL BYTE.
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
 *
 * ## Why this guard scans TEST files too (issue #736)
 *
 * It did not, and that omission cost a whole review. `#736` shipped a raw NUL
 * in `src/assets/ports.ts` — caught here — but ALSO two of them in
 * `test/assets/bundle.test.ts`, in an `"MZ\0\0"` DOS-header fixture, and that
 * one this guard could not see: it globbed `src/` only.
 *
 * The consequence was not cosmetic. Git classifies a file containing a NUL as
 * BINARY, so `git diff --stat` reported that 684-line test file as
 * `Bin 0 -> 24797 bytes` and `gh pr diff` emitted NO HUNK for it at all. A
 * reviewer checking whether the PR had server-side security tests saw only the
 * CLI packing tests and concluded the server-side ones were missing. They were
 * not missing; they were invisible. A test file is evidence, and evidence that
 * cannot be diffed or grepped is worse than absent, because absent is obvious.
 *
 * So the scan below is the union of every app's `src/` AND every app's
 * `test/`, at any extension — and note that widening it to `test/` is also what
 * finally brought the OTHER apps' `src/` under the NUL scan, which `SOURCES`
 * (this Worker's own TypeScript, and nobody else's) never covered either.
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

/**
 * The same sweep over every app's `test/` tree, at any extension.
 *
 * This is the half of the guard that was missing until issue #736 (see the file
 * header). It must be a SEPARATE literal glob rather than a `{src,test}` brace
 * or a variable: `import.meta.glob` is a build-time textual transform, so the
 * pattern has to be written out where Vite can read it.
 *
 * Test dirs carry no binary fixtures in this repo — every file under every
 * app's test tree is text — so inlining them with `?raw` is safe. If a real
 * binary fixture is ever added, it belongs in a `fixtures/` dir excluded here
 * rather than being a reason to narrow the scan back to source.
 */
const ALL_WORKER_TEST_PATHS = import.meta.glob("../../*/test/**/*", {
  query: "?raw",
  import: "default",
  eager: true,
});

// packages/*/src/ — the shared library source tree
const ALL_PACKAGE_SOURCES = import.meta.glob("../../packages/*/src/**/*", {
  query: "?raw",
  import: "default",
  eager: true,
});

// packages/*/test/ — the shared library test tree
const ALL_PACKAGE_TESTS = import.meta.glob("../../packages/*/test/**/*", {
  query: "?raw",
  import: "default",
  eager: true,
});

// tools/*/test/ — the tooling test tree (no src/ dirs in tools)
const ALL_TOOL_TESTS = import.meta.glob("../../tools/*/test/**/*", {
  query: "?raw",
  import: "default",
  eager: true,
});

// sdks/*/src/ and sdks/*/test/ — the published SDK trees
const ALL_SDK_SOURCES = import.meta.glob("../../sdks/*/src/**/*", {
  query: "?raw",
  import: "default",
  eager: true,
});

const ALL_SDK_TESTS = import.meta.glob("../../sdks/*/test/**/*", {
  query: "?raw",
  import: "default",
  eager: true,
});

// admin-console/src/ and admin-console/e2e/ — separate Vite SPA project
const ALL_ADMIN_CONSOLE_SOURCES = import.meta.glob("../../admin-console/src/**/*", {
  query: "?raw",
  import: "default",
  eager: true,
});

const ALL_ADMIN_CONSOLE_E2E = import.meta.glob("../../admin-console/e2e/**/*", {
  query: "?raw",
  import: "default",
  eager: true,
});

// Everything this guard is responsible for: apps, packages, tools, sdks, admin-console
const ALL_SCANNED_PATHS = {
  ...ALL_WORKER_PATHS,
  ...ALL_WORKER_TEST_PATHS,
  ...ALL_PACKAGE_SOURCES,
  ...ALL_PACKAGE_TESTS,
  ...ALL_TOOL_TESTS,
  ...ALL_SDK_SOURCES,
  ...ALL_SDK_TESTS,
  ...ALL_ADMIN_CONSOLE_SOURCES,
  ...ALL_ADMIN_CONSOLE_E2E,
};

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

  it("scanned every app's test/ — a src-only glob would assert nothing", () => {
    // The vacuity guard for the widened half. Written to fail LOUDLY if the
    // `test/` glob ever stops resolving, because the day it silently returns
    // `{}` is the day the NUL scan below goes back to being src-only without
    // anyone noticing — which is exactly how issue #736 happened.
    const names = Object.keys(ALL_WORKER_TEST_PATHS);
    expect(names.length).toBeGreaterThan(200);

    // Vite resolves the citing package's OWN matches against this file's
    // directory, so the gateway's tests arrive as `./…` while every sibling's
    // arrive as `../../<app>/test/…`. (Vite omits the importing module itself
    // from its own glob, so this file is not among them — anchor on a peer.)
    expect(names).toContain("./contract.test.ts");
    // A sibling app's test file, so a gateway-only glob cannot pass this.
    expect(names.some((name) => name.startsWith("../../telemetry/test/"))).toBe(true);
    // And a nested one, so a single-level glob cannot pass it either.
    expect(names.some((name) => name.startsWith("./assets/"))).toBe(true);

    const scanned = new Set(
      names.map((name) =>
        // `..` for the gateway's own tests, to match the `src/` census above.
        name.startsWith("./")
          ? ".."
          : (name.split("/test/")[0]?.replace(/^\.\.\/\.\.\//, "") ?? ""),
      ),
    );
    // `..` is `apps/gateway` itself, exactly as in the `src/` census above.
    expect([...scanned].sort()).toEqual([
      "..",
      "agent-runtime",
      "cli",
      "control-plane",
      "mcp",
      "telemetry",
    ]);
  });

  it("contains no raw NUL byte under any apps/*/src or apps/*/test", () => {
    // The scan that issue #736 needed and did not have. `SOURCES` above covers
    // only THIS Worker's `src/**/*.ts`; this covers every app's source and every
    // app's tests, at any extension.
    const offenders = Object.entries(ALL_SCANNED_PATHS)
      .filter(([, text]) => text.includes(NUL))
      .map(([name]) => name);
    expect(offenders).toEqual([]);
  });

  it("no path under any apps/*/src or apps/*/test contains a control character", () => {
    // A newline in a FILE NAME makes `grep -rn` attribute one file's text to
    // another file's path. `\p{Cc}` is the Unicode control class: C0, DEL and
    // C1. A legitimate source path in this repo contains none of them.
    const offenders = Object.keys(ALL_SCANNED_PATHS)
      .filter((name) => /\p{Cc}/u.test(name))
      // Report the FIRST line only: printing the whole name re-injects the
      // newline into the failure message and makes the report unreadable.
      .map((name) => `${name.split(/\p{Cc}/u)[0]} …(+${name.split(/\p{Cc}/u).length - 1} lines)`);
    expect(offenders).toEqual([]);
  });

  // -----------------------------------------------------------------------
  // Vacuity assertions for packages/, tools/, sdks/ and admin-console/
  // -----------------------------------------------------------------------

  it("scanned every package's src/ — a packages glob that matched nothing would assert nothing", () => {
    const names = Object.keys(ALL_PACKAGE_SOURCES);
    expect(names.length).toBeGreaterThan(50);
    // Anchor on a known package source file.
    expect(names.some((name) => name.includes("/packages/providers/src/caching.ts"))).toBe(true);
    expect(names.some((name) => name.includes("/packages/core/src/"))).toBe(true);
  });

  it("scanned every package's test/ — a packages test glob that matched nothing would assert nothing", () => {
    const names = Object.keys(ALL_PACKAGE_TESTS);
    expect(names.length).toBeGreaterThan(50);
    expect(names.some((name) => name.includes("/packages/providers/test/"))).toBe(true);
    expect(names.some((name) => name.includes("/packages/core/test/"))).toBe(true);
  });

  it("scanned every tool's test/ — a tools glob that matched nothing would assert nothing", () => {
    const names = Object.keys(ALL_TOOL_TESTS);
    expect(names.length).toBeGreaterThan(5);
    expect(names.some((name) => name.includes("/tools/sdk-conformance/test/"))).toBe(true);
  });

  it("scanned every SDK's src/ and test/ — an SDK glob that matched nothing would assert nothing", () => {
    const srcNames = Object.keys(ALL_SDK_SOURCES);
    expect(srcNames.length).toBeGreaterThan(5);
    expect(srcNames.some((name) => name.includes("/sdks/typescript/src/"))).toBe(true);

    const testNames = Object.keys(ALL_SDK_TESTS);
    expect(testNames.length).toBeGreaterThan(5);
    expect(testNames.some((name) => name.includes("/sdks/typescript/test/"))).toBe(true);
  });

  it("scanned admin-console's src/ and e2e/ — an admin-console glob that matched nothing would assert nothing", () => {
    const srcNames = Object.keys(ALL_ADMIN_CONSOLE_SOURCES);
    expect(srcNames.length).toBeGreaterThan(50);
    expect(srcNames.some((name) => name.includes("/admin-console/src/"))).toBe(true);

    const e2eNames = Object.keys(ALL_ADMIN_CONSOLE_E2E);
    expect(e2eNames.length).toBeGreaterThan(5);
    expect(e2eNames.some((name) => name.includes("/admin-console/e2e/"))).toBe(true);
  });
});
