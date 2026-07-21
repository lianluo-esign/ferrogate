/// <reference types="vitest/config" />
import path from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
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
  },
  test: {
    include: ["src/**/*.test.{ts,tsx}"],
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    restoreMocks: true,
    // Tests import vitest APIs explicitly (no injected globals) so the
    // type-checker sees exactly what runs.
    globals: false,
  },
});
