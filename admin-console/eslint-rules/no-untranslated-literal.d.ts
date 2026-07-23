// Types for the JS-authored lint rule so the vitest coverage in
// `src/i18n/no-untranslated-literal.test.ts` type-checks (#380). The rule is
// authored in plain JS because `eslint.config.js` imports it at config-load
// time, before any TS transform runs.
import type { Rule } from "eslint";

declare const plugin: {
  rules: Record<string, Rule.RuleModule>;
};

export default plugin;
