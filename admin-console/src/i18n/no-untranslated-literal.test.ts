// Regression coverage for the i18n lint gate (#380).
//
// Locks the behavior of `ferrogate/no-untranslated-literal`: it must flag new
// hard-coded operator copy (JSX text + operator-facing props) while leaving the
// migrated `t("...")` idiom and genuinely-technical literals alone. The rule
// itself lives outside `src/` (eslint-rules/) so it is never bundled.
import { afterAll, describe, it } from "vitest";
import { RuleTester } from "eslint";
import plugin from "../../eslint-rules/no-untranslated-literal.js";

const rule = plugin.rules["no-untranslated-literal"];

// RuleTester drives an external test runner; wire it to vitest (globals: false).
// The `@types/eslint` surface does not declare these static hooks as writable.
const hooks = RuleTester as unknown as {
  afterAll: typeof afterAll;
  describe: typeof describe;
  it: typeof it;
  itOnly: typeof it.only;
};
hooks.afterAll = afterAll;
hooks.describe = describe;
hooks.it = it;
hooks.itOnly = it.only;

const ruleTester = new RuleTester({
  languageOptions: {
    ecmaVersion: 2022,
    sourceType: "module",
    parserOptions: { ecmaFeatures: { jsx: true } },
  },
});

ruleTester.run("no-untranslated-literal", rule, {
  valid: [
    // The migrated idiom: copy comes from the catalog, not a literal.
    { code: "const x = <button>{t('common.save')}</button>;" },
    { code: "const x = <input placeholder={t('search.placeholder')} />;" },
    // Whitespace / punctuation / single symbols are not copy.
    { code: "const x = <span> · </span>;" },
    { code: "const x = <span>{count}</span>;" },
    // No 2+ letter run -> identifiers, units, numbers are ignored.
    { code: "const x = <span>%</span>;" },
    { code: "const x = <div id=\"main\" className=\"flex gap-2\" />;" },
    // Technical props are not checked.
    { code: "const x = <a href=\"/agents\" data-testid=\"go\" />;" },
    // Technical elements: code/pre/kbd hold literals, not copy.
    { code: "const x = <code>SELECT * FROM t</code>;" },
    { code: "const x = <pre>const y = 1;</pre>;" },
  ],
  invalid: [
    {
      code: "const x = <button>Save changes</button>;",
      errors: [{ messageId: "jsxText" }],
    },
    {
      code: "const x = <input placeholder=\"Search agents\" />;",
      errors: [{ messageId: "prop" }],
    },
    {
      code: "const x = <img alt=\"Company logo\" />;",
      errors: [{ messageId: "prop" }],
    },
    {
      code: "const x = <div aria-label=\"Close dialog\" />;",
      errors: [{ messageId: "prop" }],
    },
    {
      // Static template literal (no interpolation) is still a hard-coded string.
      code: "const x = <div title={`Danger zone`} />;",
      errors: [{ messageId: "prop" }],
    },
  ],
});
