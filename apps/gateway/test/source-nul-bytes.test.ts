/**
 * NO FILE UNDER THE SEVEN SCANNED SOURCE AND TEST TREES MAY CONTAIN A RAW NUL BYTE.
 *
 * This is not style. `grep` classifies a file containing a NUL as BINARY and
 * skips it silently — no warning, no non-zero exit, just a file that is not in
 * the results. `src/middleware/network.ts` carried one for several waves as the
 * separator in `policyCacheKey`'s `join(...)`, typed as a literal instead of
 * the `"\0"` escape. For as long as it did, EVERY `grep -r PORT-TODO src/`
 * audit of this Worker reported on one fewer file than exists and nobody could
 * tell, because the omission looks exactly like a clean file.
 *
 * Two files in this repo have now done it. This test is why a third cannot land
 * in the scanned trees: `?raw` inlines the file's real bytes at build time, so
 * the assertion runs against what is on disk rather than a re-encoding.
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
 * So the scan below sweeps seven trees whole: `apps/`, `packages/`, `tools/`,
 * `sdks/`, `admin-console/`, `tests/` and `e2e/`. Each uses a whole-tree glob
 * (star-star-slash-star) rather than guessing internal src/test layout, because
 * sdks/python/ has no src/ dir, tools/sdk-packaging/ is a single root-level
 * check.mjs with no src/ or test/ dir at all,
 * and admin-console/ has scripts/, eslint-rules/ and root-level config files
 * outside src/. Dotfile companions (star-star-slash-dot-star) are added per
 * tree because Vite's import.meta.glob skips them by default. Build and cache
 * directories are excluded so local artefacts cannot make the guard depend on
 * machine state. The `apps/` tree was the last application tree to be widened —
 * it was previously limited to `src/` and `test/` only, missing 27 tracked files
 * (package.json, tsconfig.json, vitest.config.ts, wrangler.toml, spec/ scripts
 * and README).
 *
 * This is not a repo-wide guard. Tracked files under docs/, scripts/, sql/,
 * charts/, deploy/, skills/, .github/ and config/, plus repository-root files,
 * remain outside its scope because they are neither source trees nor test trees.
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
    glob(pattern: string | string[], options: object): Record<string, string>;
  }
}

const SOURCES = import.meta.glob("../src/**/*.ts", {
  query: "?raw",
  import: "default",
  eager: true,
});

/**
 * Every path under all seven scanned trees, at any extension — because the
 * second form of this hazard hides in the FILE NAME rather than the file
 * contents, and the `*.ts` glob above is blind to it by construction.
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
// apps/ — the Worker tree, now scanned whole like the other six trees.
// Previously limited to src/ and test/ only, which missed 27 tracked files
// (package.json, tsconfig.json, vitest.config.ts, wrangler.toml, spec/
// scripts and README). Dotfile companion included for the same reason as
// the other trees, though apps/ currently has no tracked dotfiles.
const ALL_APPS_PATHS = import.meta.glob(
  [
    "../../../apps/**/*",
    "../../../apps/**/.*",
    "!**/node_modules/**",
    "!**/dist/**",
    "!**/build/**",
    "!**/.next/**",
    "!**/__pycache__/**",
  ],
  { query: "?raw", import: "default", eager: true },
);

// packages/ — the shared library tree, scanned whole rather than guessing
// internal src/test layout. Exclusions are defensive: these directories are
// gitignored but may exist on disk after a local build.
const ALL_PACKAGE_PATHS = import.meta.glob(
  [
    "../../../packages/**/*",
    "../../../packages/**/.*",
    "!**/node_modules/**",
    "!**/dist/**",
    "!**/build/**",
    "!**/.next/**",
    "!**/__pycache__/**",
  ],
  { query: "?raw", import: "default", eager: true },
);

// tools/ — the tooling tree, scanned whole. tools/sdk-packaging/ is a single
// root-level check.mjs and tools/generated-clients/ has root-level .mjs
// scripts, so a src/test-guessing glob would miss them.
const ALL_TOOL_PATHS = import.meta.glob(
  [
    "../../../tools/**/*",
    "../../../tools/**/.*",
    "!**/node_modules/**",
    "!**/dist/**",
    "!**/build/**",
    "!**/.next/**",
    "!**/__pycache__/**",
  ],
  { query: "?raw", import: "default", eager: true },
);

// sdks/ — the published SDK tree, scanned whole. sdks/python/ has no src/
// dir (its package is at sdks/python/ferrogate_admin/) and test_client.py
// lives at the root, so a src/test-guessing glob would miss it.
const ALL_SDK_PATHS = import.meta.glob(
  [
    "../../../sdks/**/*",
    "../../../sdks/**/.*",
    "!**/node_modules/**",
    "!**/dist/**",
    "!**/build/**",
    "!**/.next/**",
    "!**/__pycache__/**",
  ],
  { query: "?raw", import: "default", eager: true },
);

// admin-console/ — separate Vite SPA project, scanned whole. It has no
// standardised src/test layout: scripts/, eslint-rules/, e2e/ and root-level
// config files all live outside src/.
const ALL_ADMIN_CONSOLE_PATHS = import.meta.glob(
  [
    "../../../admin-console/**/*",
    "../../../admin-console/**/.*",
    "!**/node_modules/**",
    "!**/dist/**",
    "!**/build/**",
    "!**/.next/**",
    "!**/__pycache__/**",
  ],
  { query: "?raw", import: "default", eager: true },
);

// tests/ — shared repository-level fixtures and test evidence.
const ALL_TEST_PATHS = import.meta.glob(
  [
    "../../../tests/**/*",
    "../../../tests/**/.*",
    "!**/node_modules/**",
    "!**/dist/**",
    "!**/build/**",
    "!**/.next/**",
    "!**/__pycache__/**",
  ],
  { query: "?raw", import: "default", eager: true },
);

// e2e/ — repository-level Playwright tests, fixtures and configuration.
const ALL_E2E_PATHS = import.meta.glob(
  [
    "../../../e2e/**/*",
    "../../../e2e/**/.*",
    "!**/node_modules/**",
    "!**/dist/**",
    "!**/build/**",
    "!**/.next/**",
    "!**/__pycache__/**",
  ],
  { query: "?raw", import: "default", eager: true },
);

// Everything this guard is responsible for: seven source and test trees.
const ALL_SCANNED_PATHS = {
  ...ALL_APPS_PATHS,
  ...ALL_PACKAGE_PATHS,
  ...ALL_TOOL_PATHS,
  ...ALL_SDK_PATHS,
  ...ALL_ADMIN_CONSOLE_PATHS,
  ...ALL_TEST_PATHS,
  ...ALL_E2E_PATHS,
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

  it("scanned every app — an apps glob that matched nothing would assert nothing", () => {
    const names = Object.keys(ALL_APPS_PATHS);
    // ~95% of 814 tracked files: tight enough to catch a partial glob loss,
    // loose enough to not churn on every new file added to an app.
    expect(names.length).toBeGreaterThan(773);
    // Vite resolves the glob relative to the project root (apps/gateway/), so
    // apps paths arrive as `../../<member>/...` rather than `../../../apps/<member>/...`
    // like the other trees. Gateway's own files arrive as `../...` or `./...`.
    const members = [
      ...new Set(
        names.map((k) => {
          if (k.startsWith("../../")) return k.split("/")[2];
          return "..";
        }),
      ),
    ].sort();
    expect(members).toEqual(["..", "agent-runtime", "cli", "control-plane", "mcp", "telemetry"]);
  });

  it("contains no raw NUL byte anywhere in the seven scanned source and test trees", () => {
    // The scan that issue #736 needed and did not have. `SOURCES` above covers
    // only THIS Worker's `src/**/*.ts`; this covers the whole of apps/,
    // packages/, tools/, sdks/, admin-console/, tests/ and e2e/.
    const offenders = Object.entries(ALL_SCANNED_PATHS)
      .filter(([, text]) => text.includes(NUL))
      .map(([name]) => name);
    expect(offenders).toEqual([]);
  });

  it("no path in the seven scanned source and test trees contains a control character", () => {
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
  // Per-member census for all seven scanned source and test trees
  //
  // Each test derives the set of top-level member names from the scanned
  // keys and asserts it equals an explicit sorted literal list. A count
  // threshold plus one .includes() anchor passes green when an individual
  // package drops out of the scan — that is the very failure mode this
  // issue exists to prevent. The per-member census fails LOUDLY, naming
  // the missing member, the day any single sub-package or area is lost.
  //
  // Every key emitted by these globs contains `/<tree>/<member>`, so the regex
  // always has a member. A tree-root file such as packages/README.md yields
  // README.md; the equality assertion reports it as an unexpected member.
  // -----------------------------------------------------------------------

  function extractMember(path: string, tree: string): string {
    return path.match(new RegExp(`/${tree}/([^/]+)`))![1] as string;
  }

  it("scanned every package — a packages glob that matched nothing would assert nothing", () => {
    const names = Object.keys(ALL_PACKAGE_PATHS);
    // ~95% of 447 tracked files: tight enough to catch a partial glob loss,
    // loose enough to not churn on every new file added to a package.
    expect(names.length).toBeGreaterThan(425);
    const members = [...new Set(names.map((k) => extractMember(k, "packages")))].sort();
    expect(members).toEqual([
      "billing",
      "cloudflare",
      "config",
      "core",
      "guardrails",
      "identity",
      "observability",
      "payments",
      "policy",
      "provider-types",
      "providers",
      "routing",
      "schemas",
      "secrets",
      "sso",
      "storage",
    ]);
  });

  it("scanned every tool — a tools glob that matched nothing would assert nothing", () => {
    const names = Object.keys(ALL_TOOL_PATHS);
    // ~95% of 23 tracked files: tight enough to catch a partial glob loss,
    // loose enough to not churn on every new file added to a tool.
    expect(names.length).toBeGreaterThan(21);
    const members = [...new Set(names.map((k) => extractMember(k, "tools")))].sort();
    // `openapi-client-smoke` was retired and `sdk-packaging` (a single
    // root-level check.mjs) took its place in the tree — re-derived from the
    // committed tools/ directory, which today holds exactly these three
    // members across 23 tracked files.
    expect(members).toEqual(["generated-clients", "sdk-conformance", "sdk-packaging"]);
  });

  it("scanned every SDK — an SDK glob that matched nothing would assert nothing", () => {
    const names = Object.keys(ALL_SDK_PATHS);
    // ~93% of 14 tracked files: close to the shared ~95% floor while remaining
    // loose enough to not churn on every new file added to an SDK.
    expect(names.length).toBeGreaterThan(12);
    const members = [...new Set(names.map((k) => extractMember(k, "sdks")))].sort();
    expect(members).toEqual(["python", "typescript"]);
  });

  it("scanned every admin-console area — an admin-console glob that matched nothing would assert nothing", () => {
    const names = Object.keys(ALL_ADMIN_CONSOLE_PATHS);
    // ~95% of 288 tracked files: tight enough to catch a partial glob loss,
    // loose enough to not churn on every new file added to admin-console.
    expect(names.length).toBeGreaterThan(273);
    const topLevel = [...new Set(names.map((k) => extractMember(k, "admin-console")))].sort();
    expect(topLevel).toEqual([
      ".dockerignore",
      ".env.example",
      ".gitignore",
      "Dockerfile",
      "README.md",
      "bun.lock",
      "components.json",
      "e2e",
      "eslint-rules",
      "eslint.config.js",
      "index.html",
      "nginx.conf",
      "package-lock.json",
      "package.json",
      "playwright.config.ts",
      "postcss.config.js",
      "public",
      "render-env-config.sh",
      "scripts",
      "src",
      "tailwind.config.js",
      "tsconfig.app.json",
      "tsconfig.e2e.json",
      "tsconfig.json",
      "tsconfig.node.json",
      "vite.config.ts",
    ]);
  });

  it("scanned every tests area — a tests glob that matched nothing would assert nothing", () => {
    const names = Object.keys(ALL_TEST_PATHS);
    // ~95% of 39 tracked files: tight enough to catch a partial glob loss,
    // loose enough to not churn on every new repository-level test fixture.
    expect(names.length).toBeGreaterThan(37);
    const members = [...new Set(names.map((k) => extractMember(k, "tests")))].sort();
    expect(members).toEqual(["fixtures"]);
  });

  it("scanned every e2e area — an e2e glob that matched nothing would assert nothing", () => {
    const names = Object.keys(ALL_E2E_PATHS);
    // All 7 tracked files are required because this tree is too small for a
    // useful ~95% floor; its explicit census makes additions readable.
    expect(names.length).toBeGreaterThan(6);
    const members = [...new Set(names.map((k) => extractMember(k, "e2e")))].sort();
    expect(members).toEqual([
      "README.md",
      "fixtures.ts",
      "package.json",
      "playwright.config.ts",
      "tests",
      "tsconfig.json",
    ]);
  });
});
