// Catalog types + registry — the typed core of the console i18n runtime (#346).
//
// Design (why hand-rolled instead of i18next):
//   * The console has no i18n dependency today and leans on small, typed,
//     context-based providers (see `theme-provider`, `use-auth`). A ~40 KiB
//     i18next + react-i18next runtime would land near the app entry chunk,
//     which is governed by a hard bundle budget (`scripts/check-bundle-budget`).
//   * #346 asks for COMPILE-TIME key safety ("a mistyped key must fail
//     typecheck, not silently fall through"). i18next resolves keys as runtime
//     strings and, by default, silently falls back to the key. Deriving the key
//     union from the English catalog gives a stronger, zero-runtime guarantee.
//   * This module is structurally compatible with a later i18next migration:
//     flat dot-namespaced keys map 1:1 onto i18next namespaces/keys, and the
//     `t` / formatter surface is the same shape react-i18next exposes.
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
