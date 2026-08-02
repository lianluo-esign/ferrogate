# FerroGate TS/CF — testing strategy

Three layers. All must run **offline, docker-free** (proven for the existing Workers).

## 1. Unit + integration — Vitest + `@cloudflare/vitest-pool-workers`

The tests run in the **real local `workerd`** (miniflare) — the same runtime as
`wrangler dev --local`. `c.env.DB` (D1), `c.env.KV`, R2, DO bindings are **really
in effect**, no mocking.

- **Worker apps (`apps/*`)** use the `cloudflareTest` Vite plugin (this repo's
  vitest-4 line; NOT the old `defineWorkersConfig`). Mirror `workers/gateway-front`:

  ```ts
  import { defineConfig } from "vitest/config";
  import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
  export default defineConfig({
    plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.toml" } })],
    test: { include: ["test/**/*.test.ts"] },
  });
  ```

  Integration tests drive the Worker via `SELF` from `cloudflare:test`:

  ```ts
  import { SELF } from "cloudflare:test";
  import { describe, expect, test } from "vitest";

  describe("gateway routing + auth", () => {
    test("missing Authorization → 401", async () => {
      const res = await SELF.fetch("https://x.test/v1/chat/completions", {
        method: "POST", body: JSON.stringify({ model: "gpt-4o", messages: [] }),
      });
      expect(res.status).toBe(401);
    });
    test("Zod: non-array messages → 400", async () => {
      const res = await SELF.fetch("https://x.test/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: "Bearer valid_key" },
        body: JSON.stringify({ model: "gpt-4o", messages: "not-an-array" }),
      });
      expect(res.status).toBe(400);
    });
  });
  ```

- **Pure library packages (`packages/*` with no CF binding)** use plain `vitest`
  unit tests (no `cloudflare:test` needed) — fast, direct function assertions.
- **Binding-dependent packages** (e.g. `storage` → D1/KV/R2) use the pool-workers
  config with miniflare bindings so the real D1 SQLite executes.

## 2. LLM mocking — MSW (Mock Service Worker)

Never call OpenAI/Anthropic for real (cost, latency, nondeterminism). Use `msw`
to intercept the gateway's **outbound** `fetch()` to provider hosts and return a
canned **SSE stream**, so token counting, SSE normalization, and MCP forwarding
are exercised against a deterministic typewriter stream.

## 3. E2E — Playwright + `wrangler dev`

Black-box the Worker as a real service:
1. Start `wrangler dev --port 8787` in the background before the suite.
2. Playwright `request.post("http://localhost:8787/...")` with real HTTP.
3. Kill the wrangler process after.

Assert real end-to-end behavior (e.g. gateway wraps a remote MCP JSON-RPC
response correctly). Keep E2E in `apps/*/e2e/` with a `playwright.config.ts`.

## Convention
- Every ported package/app ships tests in the SAME slice as its logic.
- No silently-skipped behavior: if a Rust behavior isn't yet ported, mark it
  `// PORT-TODO(<inventory §>):` and add a `test.todo(...)` so it's visible.
