// Custom ESLint rule: ferrogate/no-untranslated-literal (#380).
//
// WHY THIS EXISTS
// ---------------
// #348 migrates operator-facing copy into the typed `@/i18n` catalogs so the
// console renders in English and Simplified Chinese. Nothing statically stops a
// future edit from re-introducing a hard-coded literal on an already-migrated
// surface (e.g. `placeholder="Enter name"` instead of `placeholder={t(...)}`),
// silently regressing localization. This rule is that static guard.
//
// WHY A CUSTOM RULE (not a community plugin)
// ------------------------------------------
// `react/jsx-no-literals` and `i18next/no-literal-string` both require pulling
// a new eslint plugin into devDependencies, and neither ships the file-level
// allowlist we need to stay green on the ~90 not-yet-migrated surfaces without
// migrating the whole console first (AGENTS.md: "Do not introduce new
// dependencies without a concrete reason"). This rule is ~1 file, dev-only,
// and does exactly the scoping #380 asks for.
//
// WHAT IT FLAGS
// -------------
//   * JSX text that is human copy:  <Button>Save changes</Button>
//   * Operator-facing string props: placeholder / title / alt / aria-label /
//     aria-description / label / description  set to a bare string literal.
// It does NOT flag `{t("...")}` (that is an expression, not a literal), so the
// migrated idiom always passes.
//
// WHAT IT INTENTIONALLY IGNORES (not operator copy)
// -------------------------------------------------
//   * whitespace / punctuation / symbol-only text (icons, separators);
//   * strings without a 2+ letter run (identifiers like "id", units, "%");
//   * text inside <code>/<pre>/<kbd>/<samp>/<script>/<style>;
//   * technical props (className, id, type, name, href, ...) — only the prop
//     names in OPERATOR_FACING_PROPS are checked.
//
// ESCAPE HATCH
// ------------
// A genuinely non-copy literal the heuristic misfires on can be silenced with a
// justified inline disable, e.g.:
//   {/* eslint-disable-next-line ferrogate/no-untranslated-literal -- brand mark, never translated */}
// File-level exceptions (whole unmigrated pages) live in the allowlist in
// `eslint.config.js`; see the header comment there for the contributor
// procedure. Fixing the violation = wrap the string in `t()` with a catalog key.

/** Props that carry operator-facing copy and must go through the catalog. */
const OPERATOR_FACING_PROPS = new Set([
  "placeholder",
  "title",
  "alt",
  "label",
  "description",
  "aria-label",
  "aria-description",
  "aria-placeholder",
  "aria-roledescription",
  "aria-valuetext",
]);

/** JSX elements whose text content is technical, not copy. */
const TECHNICAL_ELEMENTS = new Set(["code", "pre", "kbd", "samp", "script", "style"]);

/**
 * Heuristic: does `text` read as human, operator-facing copy? We require a run
 * of at least two letters so bare symbols, single-letter markers, numbers, and
 * units ("%", "·", "3", "px") do not trip the gate.
 */
function looksLikeCopy(text) {
  const trimmed = text.trim();
  if (trimmed.length === 0) return false;
  return /\p{L}{2,}/u.test(trimmed);
}

/** Resolve a JSXText's nearest enclosing element name, if any. */
function enclosingElementName(node) {
  let parent = node.parent;
  while (parent) {
    if (parent.type === "JSXElement" && parent.openingElement) {
      const nameNode = parent.openingElement.name;
      return nameNode && nameNode.type === "JSXIdentifier" ? nameNode.name : null;
    }
    parent = parent.parent;
  }
  return null;
}

/** Extract a static string from a Literal or a no-substitution template. */
function staticStringValue(node) {
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "TemplateLiteral" && node.expressions.length === 0) {
    return node.quasis.map((q) => q.value.cooked ?? "").join("");
  }
  return null;
}

/** @type {import("eslint").Rule.RuleModule} */
const rule = {
  meta: {
    type: "problem",
    docs: {
      description:
        "Reject hard-coded operator-facing strings; route copy through the @/i18n catalog.",
    },
    messages: {
      jsxText:
        'Hard-coded operator-facing text "{{ text }}". Move it into the @/i18n catalog and render with t("<key>"). See eslint-rules/no-untranslated-literal.js.',
      prop:
        'Hard-coded operator-facing string on `{{ prop }}`. Use `{{ prop }}={t("<key>")}` from @/i18n. See eslint-rules/no-untranslated-literal.js.',
    },
    schema: [],
  },
  create(context) {
    return {
      JSXText(node) {
        if (!looksLikeCopy(node.value)) return;
        const element = enclosingElementName(node);
        if (element && TECHNICAL_ELEMENTS.has(element)) return;
        context.report({
          node,
          messageId: "jsxText",
          data: { text: node.value.trim().slice(0, 40) },
        });
      },
      JSXAttribute(node) {
        const name =
          node.name.type === "JSXIdentifier"
            ? node.name.name
            : node.name.type === "JSXNamespacedName"
              ? `${node.name.namespace.name}:${node.name.name.name}`
              : null;
        if (!name || !OPERATOR_FACING_PROPS.has(name)) return;
        if (!node.value) return;
        // `placeholder="..."` -> Literal; `placeholder={"..."}` / `{`..`}` -> container.
        let valueNode = node.value;
        if (valueNode.type === "JSXExpressionContainer") valueNode = valueNode.expression;
        const text = staticStringValue(valueNode);
        if (text === null || !looksLikeCopy(text)) return;
        context.report({ node, messageId: "prop", data: { prop: name } });
      },
    };
  },
};

export default {
  rules: {
    "no-untranslated-literal": rule,
  },
};
