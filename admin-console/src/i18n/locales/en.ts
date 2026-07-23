// English message catalog — the SOURCE OF TRUTH for the console's i18n.
//
// Why this file is special:
//   * `en` is declared `as const`, so its keys become a compile-time string
//     union (`TranslationKey` in `../catalog.ts`). `t("typo.key")` then fails
//     `tsc`, not at runtime.
//   * Every other locale (see `./zh-CN.ts`) is typed `Messages`, i.e.
//     `Record<TranslationKey, string>`, so a missing OR misspelled key in a
//     translation is a type error — the "reject missing Chinese keys / key
//     drift" contract from #346 is enforced by the compiler, then re-checked
//     at runtime in `../catalog.test.ts`.
//
// Keys are flat, dot-namespaced strings (`"<namespace>.<name>"`). This keeps
// the union cheap for the type-checker and lets #348 grow route-level
// namespaces (`agents.*`, `billing.*`, ...) incrementally without re-shaping
// the catalog. Interpolation placeholders use `{name}` (see `../format.ts`).
//
// Scope note (#346): this foundation ships only the keys the i18n runtime and
// its language selector need. Page copy is migrated by #348.

export const en = {
  // Language selector (used by `../language-switcher.tsx`).
  "language.label": "Language",
  "language.change": "Change language",
  "language.current": "Language: {name}. Change language",

  // A couple of genuinely shared strings, to seed the `common.*` namespace and
  // prove interpolation/pluralization end to end.
  "common.appName": "FerroGate Admin Console",
  "common.selected": "{count} selected",
} as const;
