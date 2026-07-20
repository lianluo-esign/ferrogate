// ESLint 9 flat config (#314). The `lint` script predates this file and used
// to fail with "no configuration found" — this makes `npm run lint` a real
// gate (scripts/check-admin-console.sh runs it before test + build).
import js from "@eslint/js";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import reactHooks from "eslint-plugin-react-hooks";

export default [
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      // Generated from docs/openapi/admin-api.openapi.json (`npm run generate:api`).
      "src/lib/api-types.generated.ts",
    ],
  },
  {
    files: ["**/*.{js,mjs}"],
    ...js.configs.recommended,
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: { console: "readonly", process: "readonly", URL: "readonly" },
    },
  },
  {
    // Served as-is to the browser (overwritten by the Docker entrypoint).
    files: ["public/**/*.js"],
    languageOptions: { globals: { window: "readonly" } },
  },
  {
    // Loaded by Tailwind via jiti, which provides CommonJS `require`.
    files: ["tailwind.config.js", "postcss.config.js"],
    languageOptions: { globals: { require: "readonly", module: "writable" } },
  },
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      parser: tsParser,
      ecmaVersion: 2022,
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
      "react-hooks": reactHooks,
    },
    rules: {
      ...js.configs.recommended.rules,
      ...tsPlugin.configs.recommended.rules,
      ...reactHooks.configs.recommended.rules,
      // TypeScript itself checks undefined identifiers (incl. DOM globals);
      // core no-undef false-positives on types and browser globals.
      "no-undef": "off",
      // Superseded by @typescript-eslint/no-unused-vars from `recommended`.
      "no-unused-vars": "off",
    },
  },
];
