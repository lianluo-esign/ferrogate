// App-level i18n provider + `useI18n()` hook (#346).
//
// Mirrors the console's existing provider idiom (see `theme-provider`): a React
// context, a versioned localStorage preference, and a document-side effect —
// here `<html lang>`. Switching locale updates React state only: it never
// reloads the document and never resets route/form/sidebar state.
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  DEFAULT_CATALOG,
  getLoadedCatalog,
  loadCatalog,
  LOCALE_META,
  type Locale,
  type Messages,
  type TranslationKey,
} from "./catalog";
import { resolveInitialLocale, writeStoredLocale } from "./detect";
import {
  formatBytes,
  formatCurrency,
  formatDate,
  formatNumber,
  formatPercent,
  formatRelativeTime,
  formatTime,
  formatTokens,
  interpolate,
  selectPlural,
  type InterpolationValues,
} from "./format";

/**
 * Translate a typed key for `locale`, interpolating `{name}` placeholders.
 *
 * Resolves against the locale's catalog IF it has already been lazily loaded
 * (`getLoadedCatalog`), else against the eager default catalog. The default
 * locale is always available synchronously; a non-default locale whose chunk
 * has not resolved yet gracefully yields the English string. For a live,
 * re-rendering surface prefer the context `t` (below), which tracks the active
 * catalog as it loads; this free function is for one-shot/synchronous callers.
 */
export function translate(
  locale: Locale,
  key: TranslationKey,
  values?: InterpolationValues,
): string {
  const catalog = getLoadedCatalog(locale) ?? DEFAULT_CATALOG;
  // Typed catalogs guarantee the key exists; the `?? DEFAULT` chain only guards
  // against a locale catalog being hand-edited out of sync at runtime.
  const template = catalog[key] ?? DEFAULT_CATALOG[key] ?? key;
  return interpolate(template, values);
}

/** Formatters bound to a single locale (see `./format`). */
export interface BoundFormatters {
  number: (value: number, options?: Intl.NumberFormatOptions) => string;
  tokens: (tokens: number) => string;
  percent: (ratio: number, fractionDigits?: number) => string;
  currency: (amount: number, currency: string, options?: Intl.NumberFormatOptions) => string;
  bytes: (bytes: number, fractionDigits?: number) => string;
  date: (value: Date | number | string, options?: Intl.DateTimeFormatOptions) => string;
  time: (value: Date | number | string, options?: Intl.DateTimeFormatOptions) => string;
  relativeTime: (value: Date | number, now?: Date | number) => string;
  plural: (
    count: number,
    forms: Partial<Record<Intl.LDMLPluralRule, string>> & { other: string },
  ) => string;
}

export interface I18nContextValue {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: (key: TranslationKey, values?: InterpolationValues) => string;
  format: BoundFormatters;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export interface I18nProviderProps {
  children: ReactNode;
  /** Force an initial locale (tests / storybook); otherwise resolved at mount. */
  initialLocale?: Locale;
}

export function I18nProvider({ children, initialLocale }: I18nProviderProps) {
  const [locale, setLocaleState] = useState<Locale>(
    () => initialLocale ?? resolveInitialLocale(),
  );

  // The active message catalog. The default locale — and any non-default locale
  // whose chunk is already cached — resolves SYNCHRONOUSLY here, so the common
  // case (and every default-locale render, including the test suite's) paints
  // with no async hop. A not-yet-loaded non-default locale seeds with the eager
  // default catalog (graceful English pending state) and swaps in once its
  // dynamically imported chunk resolves via the effect below.
  const [catalog, setCatalog] = useState<Messages>(
    () => getLoadedCatalog(locale) ?? DEFAULT_CATALOG,
  );

  // Reflect the active locale on the document element for a11y + `:lang()` CSS.
  useEffect(() => {
    document.documentElement.lang = LOCALE_META[locale].htmlLang;
  }, [locale]);

  // Keep `catalog` in sync with `locale`, lazily importing non-default locales.
  useEffect(() => {
    const alreadyLoaded = getLoadedCatalog(locale);
    if (alreadyLoaded) {
      setCatalog(alreadyLoaded);
      return;
    }
    // Non-default locale not yet resolved: show the default copy while its chunk
    // downloads, then re-render with the real catalog. `cancelled` guards a
    // locale change (or unmount) that lands before the import settles.
    let cancelled = false;
    setCatalog(DEFAULT_CATALOG);
    void loadCatalog(locale).then((messages) => {
      if (!cancelled) setCatalog(messages);
    });
    return () => {
      cancelled = true;
    };
  }, [locale]);

  const setLocale = useCallback((next: Locale) => {
    writeStoredLocale(next);
    // Kick the lazy chunk fetch off at click time so the switch feels immediate;
    // the effect above also awaits it and commits the swap when it lands.
    void loadCatalog(next);
    setLocaleState(next);
  }, []);

  const value = useMemo<I18nContextValue>(() => {
    const format: BoundFormatters = {
      number: (v, o) => formatNumber(locale, v, o),
      tokens: (t) => formatTokens(locale, t),
      percent: (r, d) => formatPercent(locale, r, d),
      currency: (a, c, o) => formatCurrency(locale, a, c, o),
      bytes: (b, d) => formatBytes(locale, b, d),
      date: (v, o) => formatDate(locale, v, o),
      time: (v, o) => formatTime(locale, v, o),
      relativeTime: (v, now) => formatRelativeTime(locale, v, now),
      plural: (count, forms) => selectPlural(locale, count, forms),
    };
    return {
      locale,
      setLocale,
      // Resolve from the active (possibly lazily loaded) catalog, falling back
      // to the eager default so a pending non-default locale renders English.
      t: (key, values) => interpolate(catalog[key] ?? DEFAULT_CATALOG[key] ?? key, values),
      format,
    };
  }, [locale, catalog, setLocale]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

/** Access the active locale, `t`, `setLocale`, and bound formatters. */
export function useI18n(): I18nContextValue {
  const context = useContext(I18nContext);
  if (!context) {
    throw new Error("useI18n must be used within an <I18nProvider>");
  }
  return context;
}
