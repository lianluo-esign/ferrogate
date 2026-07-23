// Public entry point for the console i18n runtime (#346).
//
// Import from `@/i18n` rather than reaching into submodules so #348 can move
// internals (e.g. swap in lazy namespace loading) without churning call sites.
export {
  BOOTSTRAP_CATALOG,
  DEFAULT_LOCALE,
  LOCALE_META,
  LOCALES,
  getLoadedCatalog,
  isLocale,
  loadCatalog,
  type Locale,
  type Messages,
  type TranslationKey,
} from "./catalog";
export {
  LOCALE_STORAGE_KEY,
  readStoredLocale,
  resolveInitialLocale,
  writeStoredLocale,
} from "./detect";
export {
  I18nProvider,
  translate,
  useI18n,
  type BoundFormatters,
  type I18nContextValue,
} from "./i18n-provider";
export { LanguageSwitcher } from "./language-switcher";
export type { InterpolationValues } from "./format";
