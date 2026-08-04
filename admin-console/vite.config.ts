/// <reference types="vitest/config" />
import path from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const controlPlaneProxyTarget = env.VITE_CONTROL_PLANE_PROXY_TARGET ?? "http://127.0.0.1:8787";
  const gatewayProxyTarget = env.VITE_GATEWAY_PROXY_TARGET ?? "http://127.0.0.1:8788";

  return {
    plugins: [react()],
    build: {
      manifest: true,
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (!id.includes("node_modules")) return undefined;
            if (
              id.includes("/react/") ||
              id.includes("/react-dom/") ||
              id.includes("/react-router/") ||
              id.includes("/react-router-dom/") ||
              id.includes("/@remix-run/router/") ||
              id.includes("/scheduler/")
            ) {
              return "react-runtime";
            }
            if (id.includes("/@tanstack/react-query/") || id.includes("/@tanstack/query-core/")) {
              return "query-runtime";
            }
            if (id.includes("/@radix-ui/")) return "radix-runtime";
            return undefined;
          },
        },
      },
    },
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },
    server: {
      port: 5173,
      /**
       * The dev server is the browser origin. Control-plane prefixes are
       * checked before the broad `/v1` gateway prefix so session requests do
       * not accidentally go to the data plane.
       */
      proxy: Object.fromEntries([
        ...["/admin/v1", "/control/v1", "/v1/admin", "/scim/v2"].map((prefix) => [
          prefix,
          {
            target: controlPlaneProxyTarget,
            changeOrigin: false,
          },
        ]),
        ...["/v1", "/sites"].map((prefix) => [
          prefix,
          {
            target: gatewayProxyTarget,
            changeOrigin: false,
          },
        ]),
      ]),
    },
    test: {
      // `e2e/support/*.test.ts` are NOT browser specs: they are unit tests over the
      // pure support modules the Playwright specs are built from (the #348
      // registered-route inventory), and they belong next to the module they
      // check. `playwright.config.ts` pins `testMatch` to `*.spec.ts` so the two
      // runners do not collide over them.
      include: ["src/**/*.test.{ts,tsx}", "e2e/support/*.test.ts"],
      environment: "jsdom",
      setupFiles: ["./src/test/setup.ts"],
      restoreMocks: true,
      // Tests import vitest APIs explicitly (no injected globals) so the
      // type-checker sees exactly what runs.
      globals: false,
    },
  };
});
