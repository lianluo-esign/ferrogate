import { defineConfig } from "vitest/config";

// Plain Node/Bun environment: this package spawns the generator off disk and
// compares bytes. No Worker, no bindings, no network — the gate has to be
// runnable by anyone, on any checkout, with nothing configured.
//
// Sources here are `.mjs` on purpose. admin-console runs the same modules under
// plain `node` from its npm scripts (its CI job installs no Bun and no TypeScript
// runner), so the shared pipeline must be executable JavaScript, not TypeScript.
export default defineConfig({
  test: {
    include: ["test/**/*.test.mjs"],
    // The drift gate launches openapi-typescript twice and renders the complete
    // 2 MiB client: once through checkArtifact(), once through the standalone
    // CLI. That work exceeded Vitest's 5s default under CPU contention, and
    // sampling artifacts would weaken the tree-wide drift proof. 30s keeps the
    // complete gate viable while still failing a real hang.
    testTimeout: 30_000,
  },
});
