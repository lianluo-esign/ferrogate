// ESLint 9 flat config (#314). The `lint` script predates this file and used
// to fail with "no configuration found" — this makes `npm run lint` a real
// gate (scripts/check-admin-console.sh runs it before test + build).
import js from "@eslint/js";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import reactHooks from "eslint-plugin-react-hooks";
import ferrogate from "./eslint-rules/no-untranslated-literal.js";

// i18n regression guard (#380). `ferrogate/no-untranslated-literal` rejects
// NEWLY introduced hard-coded operator-facing strings so the surfaces #348
// migrated to `@/i18n` cannot silently regress to non-localized literals.
//
// KEEPING THE GATE GREEN WITHOUT MIGRATING THE WHOLE CONSOLE
// ----------------------------------------------------------
// The rule applies to every `src/**/*.{ts,tsx}` source file BY DEFAULT, so any
// NEW file is guarded automatically. Files below are surfaces #348 has not
// migrated yet; they are exempted here so the gate enforces "no NEW violations"
// today instead of demanding a full-console migration first. This is a
// shrinking baseline, not a permanent carve-out.
//
// HOW A CONTRIBUTOR ADDS / REMOVES AN EXCEPTION
// ---------------------------------------------
//   * Migrating a file: route its copy through `t()` and DELETE its glob here.
//     (Leaving a migrated file listed is harmless but defeats the guard.)
//   * A single non-copy literal the heuristic misfires on: prefer an inline
//     `// eslint-disable-next-line ferrogate/no-untranslated-literal -- <reason>`
//     over listing the whole file.
//   * A brand-new page that legitimately cannot be localized yet: add its glob
//     below WITH a one-line justification in review. New files are guarded by
//     default precisely so this stays a conscious, reviewed decision.
const I18N_UNMIGRATED_ALLOWLIST = [
  // Bespoke pages/components #348 has not migrated to `@/i18n` yet. Baselined
  // 2026-07-23 by running the rule with an empty allowlist and recording the
  // files that failed. Remove a glob when its copy is migrated.
  "src/components/route-load-boundary.tsx",
  "src/components/theme-switcher.tsx",
  "src/components/tools/tools-table.tsx",
  // shadcn/ui primitives carry a few vendored sr-only labels; migrate with the
  // component library, not piecemeal.
  "src/components/ui/breadcrumb.tsx",
  "src/components/ui/dialog.tsx",
  "src/components/ui/sheet.tsx",
  "src/components/ui/sidebar.tsx",
  "src/components/worker-ops/worker-ops-primitives.tsx",
  "src/pages/assets.tsx",
  "src/pages/investigations.tsx",
  "src/pages/managed-worker-sessions.tsx",
  "src/pages/mcp-identities.tsx",
  "src/pages/ops-config.tsx",
  "src/pages/ops-drain.tsx",
  "src/pages/ops-gateway-configs.tsx",
  "src/pages/ops-observability.tsx",
  "src/pages/ops-provider-health.tsx",
  "src/pages/plugin-tools.tsx",
  "src/pages/self-hosted-runs.tsx",
  "src/pages/self-hosted-worker-detail.tsx",
  "src/pages/self-hosted-workers-ops.tsx",
  "src/pages/tenant-roles.tsx",
  "src/pages/tool-approvals.tsx",
  "src/pages/tool-sessions.tsx",
  "src/pages/tools-catalog.tsx",
];

export default [
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "playwright-report/**",
      "test-results/**",
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
  {
    // i18n regression guard (#380). Scoped to app source only: test files assert
    // on literal copy, and the i18n catalogs/locale files ARE the string source
    // of truth, so both are excluded rather than allowlisted.
    files: ["src/**/*.{ts,tsx}"],
    ignores: [
      "**/*.test.{ts,tsx}",
      "src/i18n/**",
      "src/test/**",
      "src/lib/api-types.generated.ts",
      ...I18N_UNMIGRATED_ALLOWLIST,
    ],
    plugins: { ferrogate },
    rules: {
      "ferrogate/no-untranslated-literal": "error",
    },
  },
];
