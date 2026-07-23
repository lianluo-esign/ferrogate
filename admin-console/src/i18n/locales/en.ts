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
// Keys are flat, dot-namespaced strings (`"<namespace>.<name>"`).
//
// CODE-SPLIT (#394): the RUNTIME values are split across two modules so the bulk
// of the EN copy stays OUT of the entry chunk. `./en/bootstrap` holds the small
// always-visible chrome subset (eagerly bundled); `./en/rest` holds everything
// else (dashboard/resource/page.*) and is loaded via a dynamic `import()` in
// `../catalog.ts`. This aggregator re-composes them into the single `en` object
// purely so `TranslationKey` stays the union of ALL keys — `../catalog.ts`
// imports `en` TYPE-ONLY (fully erased at runtime), so re-composing here adds
// NOTHING to any runtime chunk; it exists only to keep the type whole while the
// values load in two chunks. Add new keys to `./en/bootstrap` (chrome) or
// `./en/rest` (route/page copy), never here.
import { enBootstrap } from "./en/bootstrap";
import { enRest } from "./en/rest";

export const en = { ...enBootstrap, ...enRest } as const;
