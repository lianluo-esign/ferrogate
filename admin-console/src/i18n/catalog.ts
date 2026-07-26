// Catalog types + registry — the typed core of the console i18n runtime (#346).
//
// DEVIATION from #346's Decision ("use i18next + react-i18next … do not build a
// custom translation map/provider"), on MEASURED evidence rather than taste.
// The mandated runtime was actually built and benchmarked before this deviation
// was accepted. It was NOT landed (it fails the budget gate below), so there is
// no commit to check out; reproduce it with i18next 26.3.6 + react-i18next
// 17.0.11 as: a real `createInstance()` + `initReactI18next`
// + `I18nextProvider` + `useTranslation` + `getFixedT`, keeping this module's
// flat dot-namespaced keys (`keySeparator: false`, `nsSeparator: false`), the
// `{name}` placeholder syntax, and the #393/#394 code-split catalog chunks fed
// to `addResourceBundle`. It is functionally EQUIVALENT: `npx vitest run` came
// back byte-identical at 553 passed / 7 failed (560 — the 7 are the pre-existing
// #510 failures), `tsc -b` and `npm run lint` clean. Only the size differs:
//
//   metric (npx vite build + npm run check:bundle, same tree, 2026-07-26)
//                        hand-rolled (this)   i18next 26.3.6 +      delta
//                                             react-i18next 17.0.11
//   entry index-*.js      125.97 KiB min       176.23 KiB min       +50.26 KiB (+39.9%)
//                          36.86 KiB gzip       53.18 KiB gzip      +16.32 KiB (+44.3%)
//   initial static graph  456.01 KiB min       506.28 KiB min       +50.27 KiB (+11.0%)
//                         142.01 KiB gzip      158.34 KiB gzip      +16.33 KiB (+11.5%)
//   check:bundle          PASS (1.96 KiB       FAIL — 48.30 KiB     —
//                         under the ceiling)   over the 127.93 KiB ceiling
//
// Isolating the libraries into their own manual chunk prices them exactly:
// i18next + react-i18next + html-parse-stringify = 50.89 kB min / 16.90 kB gzip.
// That is the ENTIRE delta — nothing else regressed. It is also ~27% of the
// 190_723 B that #393 and #394 spent two slices removing from this entry chunk,
// bought back as machinery carrying zero operator copy.
//
// NOT a reason (an earlier version of this note claimed it; it is wrong):
// compile-time key safety is NOT lost under i18next. A `CustomTypeOptions`
// augmentation binding `resources: { translation: Messages }` with both
// separators disabled makes i18next's own `t` reject a bad key — verified by a
// probe whose `@ts-expect-error` on `i18n.t("totally.made.up")` and
// `i18n.t("language.lable")` type-checked clean, i.e. both ARE `tsc` errors.
// Deriving `TranslationKey` from the English catalog (below) is equivalent on
// that axis, not superior. The bundle number is the whole argument.
//
// Also rejected: hiding i18next in a sibling manual chunk. It measures at entry
// 126.70 KiB, so `check:bundle` goes green — but the chunk is STATICALLY
// imported by the entry, so all 50.89 kB still download before first paint
// (initial static graph 506.44 KiB). The budget's stated purpose is to guard
// against an unintended heavy dependency; routing around it defeats exactly that.
//
// This module stays structurally compatible with a later i18next migration:
// flat dot-namespaced keys map 1:1 onto i18next keys, and the `t` / formatter
// surface is the same shape react-i18next exposes — which is what made the
// measured port above a ~150-line change.
//
// Code-split — locales (#393) AND the default catalog (#394):
//   * Non-default locales (zh-CN) were already lazy: fetched with a dynamic
//     `import()` so Vite emits each as its OWN chunk outside the entry.
//   * #394 splits the DEFAULT locale (English) too. Only a SMALL bootstrap
//     subset (`./locales/en/bootstrap` — the always-visible chrome: language
//     selector, `common.*`, app-shell `nav.*`/`shell.*`, the `auth.*` login copy,
//     worker reveal warnings, the theme switcher + route-load-boundary "Loading
//     page…" + sidebar a11y) is eagerly bundled into the entry, so chrome still
//     paints SYNCHRONOUSLY with no async hop. The bulk of the EN copy
//     (`./locales/en/rest` — dashboard/resource/every `page.<route>.*`) is pulled
//     in by a dynamic `import()` (see `catalogLoaders.en`) and merged over the
//     bootstrap subset, so it lands in its own chunk OUTSIDE the entry.
//
// The compile-time completeness guarantee is preserved WITHOUT bundling the full
// EN or the zh-CN runtime value into the entry: both `./locales/en` (the whole-
// catalog aggregator) and `./locales/zh-CN` are imported here TYPE-ONLY (fully
// erased by the bundler; contribute nothing to the entry chunk). `TranslationKey`
// is still `keyof typeof en` — the union of EVERY key across bootstrap + rest —
// and `_ZhCatalogIsComplete` still fails `tsc` if zh-CN drops or misspells a key.
import { enBootstrap } from "./locales/en/bootstrap";
import type { en } from "./locales/en";
import type { zhCN } from "./locales/zh-CN";

/** Every valid translation key, derived from the (whole) English source catalog. */
export type TranslationKey = keyof typeof en;

/** The shape every locale catalog must satisfy: all keys, string values. */
export type Messages = Record<TranslationKey, string>;

// --- Compile-time completeness gate (runtime value loads lazily) ---
// `AssertCovers<Base, Sub extends Base>` is a plain type alias whose ONLY effect
// is the `extends` constraint: instantiating it with a `Sub` that is NOT
// assignable to `Base` is a `tsc` error. Applied to the TYPE of the lazily
// imported zh-CN catalog, it fails `tsc -b` the instant zh-CN drops or misspells
// a `TranslationKey` — the exact "reject missing Chinese keys / key drift"
// contract from #346/#348, now enforced at the registry through a type-only
// import instead of an eager runtime import. `zh-CN.ts` additionally pins its
// own value with `satisfies Messages`, so drift fails at BOTH sites.
type AssertCovers<Base, Sub extends Base> = Sub;
export type _ZhCatalogIsComplete = AssertCovers<Messages, typeof zhCN>;

/** Canonical initial locales for the console (#346). */
export const LOCALES = ["en", "zh-CN"] as const;
export type Locale = (typeof LOCALES)[number];

/** Source/fallback locale — the ONLY locale with any copy eager in the entry. */
export const DEFAULT_LOCALE = "en" satisfies Locale;

/**
 * Per-locale display metadata. `nativeName` is the autonym (the language's own
 * name), so the selector is legible whatever the active locale is. `htmlLang`
 * is the value written to `<html lang>` / passed to `Intl`.
 */
export const LOCALE_META: Record<Locale, { nativeName: string; htmlLang: string }> = {
  en: { nativeName: "English", htmlLang: "en" },
  "zh-CN": { nativeName: "简体中文", htmlLang: "zh-CN" },
};

/**
 * The bootstrap catalog: the SMALL chrome subset of EN eagerly bundled with the
 * entry chunk so the default-locale chrome (and the synchronous EN fallback for
 * any pending/not-yet-loaded key) resolves WITHOUT async — no flash of
 * untranslated content on the always-visible shell. It is a PARTIAL catalog by
 * design: the rest of EN (dashboard/resource/page.*) is code-split into its own
 * chunk (`./locales/en/rest`) and merged in by `loadCatalog("en")`. A key that
 * is not in the bootstrap subset resolves once its route's copy has loaded; until
 * then `t()` falls back to the key (rare — the EN rest loads at provider mount).
 */
export const BOOTSTRAP_CATALOG: Partial<Messages> = enBootstrap;

/**
 * Catalogs FULLY resolved so far. Empty until first load: even the default
 * locale's complete catalog is assembled lazily (bootstrap subset + the
 * dynamically imported rest). Each locale populates on its first `loadCatalog`.
 * Read synchronously via `getLoadedCatalog` on the render path.
 */
const loadedCatalogs: Partial<Record<Locale, Messages>> = {};

/**
 * Dynamic importers for EVERY locale's FULL catalog. Each `import()` makes Vite
 * emit that locale's copy as a SEPARATE chunk outside the entry — including the
 * default locale, whose bulk (`./locales/en/rest`) is merged over the eager
 * bootstrap subset. Typed `Record<Locale, ...>`, so adding a new `Locale` is a
 * COMPILE error until its lazy loader is registered here.
 */
const catalogLoaders: Record<Locale, () => Promise<Messages>> = {
  en: () =>
    import("./locales/en/rest").then((module) => ({ ...enBootstrap, ...module.enRest })),
  "zh-CN": () => import("./locales/zh-CN").then((module) => module.zhCN),
};

/** The FULLY resolved catalog for `locale` if already loaded, else `undefined`. */
export function getLoadedCatalog(locale: Locale): Messages | undefined {
  return loadedCatalogs[locale];
}

/**
 * Resolve `locale`'s FULL catalog, dynamically importing (and caching) its
 * code-split chunk on first use. Every locale — the default included — awaits its
 * own chunk the first time; the always-visible chrome renders synchronously in
 * the meantime from `BOOTSTRAP_CATALOG`. Idempotent: repeat calls return the cache.
 */
export async function loadCatalog(locale: Locale): Promise<Messages> {
  const cached = loadedCatalogs[locale];
  if (cached) return cached;
  const messages = await catalogLoaders[locale]();
  loadedCatalogs[locale] = messages;
  return messages;
}

/** Runtime type guard for an untrusted locale code (storage, navigator, URL). */
export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && (LOCALES as readonly string[]).includes(value);
}
