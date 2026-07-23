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
// Code-split (#393): only the DEFAULT locale (English) is eagerly bundled into
// the entry chunk. Every non-default locale (currently zh-CN) is fetched with a
// dynamic `import()` (see `catalogLoaders`), so Vite emits its copy as its OWN
// chunk OUTSIDE the entry — an operator only downloads Chinese strings if they
// actually switch to Chinese. The compile-time completeness guarantee is
// preserved WITHOUT bundling zh-CN's runtime value: `zh-CN.ts` is imported here
// TYPE-ONLY (fully erased by the bundler; contributes nothing to the entry
// chunk) purely to assert, at `tsc` time, that it still covers every
// `TranslationKey` (see `_ZhCatalogIsComplete`).
import { en } from "./locales/en";
import type { zhCN } from "./locales/zh-CN";

/** Every valid translation key, derived from the English source catalog. */
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

/** Source/fallback locale — the ONLY catalog eagerly in the entry chunk. */
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
 * The default catalog: eagerly bundled with the entry chunk so the default
 * locale (and the EN fallback for any pending non-default locale) resolves
 * SYNCHRONOUSLY — no async on first paint, no flash of untranslated content.
 */
export const DEFAULT_CATALOG: Messages = en;

/**
 * Catalogs resolved so far. Seeded with the eager default; each non-default
 * locale populates on its first `loadCatalog(...)`. Read synchronously via
 * `getLoadedCatalog` on the render path.
 */
const loadedCatalogs: Partial<Record<Locale, Messages>> = { en };

/**
 * Dynamic importers for the non-default locales. Each `import()` makes Vite emit
 * that locale's copy as a SEPARATE chunk outside the entry. Typed
 * `Record<Exclude<Locale, typeof DEFAULT_LOCALE>, ...>`, so adding a new
 * `Locale` is a COMPILE error until its lazy loader is registered here.
 */
const catalogLoaders: Record<Exclude<Locale, typeof DEFAULT_LOCALE>, () => Promise<Messages>> = {
  "zh-CN": () => import("./locales/zh-CN").then((module) => module.zhCN),
};

/** The catalog for `locale` if already resolved, else `undefined`. */
export function getLoadedCatalog(locale: Locale): Messages | undefined {
  return loadedCatalogs[locale];
}

/**
 * Resolve `locale`'s catalog, dynamically importing (and caching) it on first
 * use. The default locale resolves synchronously from the eager bundle; every
 * other locale awaits its own chunk. Idempotent: repeat calls return the cache.
 */
export async function loadCatalog(locale: Locale): Promise<Messages> {
  const cached = loadedCatalogs[locale];
  if (cached) return cached;
  const messages = await catalogLoaders[locale as Exclude<Locale, typeof DEFAULT_LOCALE>]();
  loadedCatalogs[locale] = messages;
  return messages;
}

/** Runtime type guard for an untrusted locale code (storage, navigator, URL). */
export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && (LOCALES as readonly string[]).includes(value);
}
