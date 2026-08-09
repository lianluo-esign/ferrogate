// App-level i18n provider + `useI18n()` hook (#346).
//
// Mirrors the console's existing provider idiom (see `theme-provider`): a React
// context, a versioned localStorage preference, and a document-side effect —
// here `<html lang>`. Switching locale updates React state only: it never
// reloads the document and never resets route/form/sidebar state.
import {
  type ReactNode,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  BOOTSTRAP_CATALOG,
  LOCALE_META,
  type Locale,
  type Messages,
  type TranslationKey,
  getLoadedCatalog,
  loadCatalog,
} from "./catalog";
import { resolveInitialLocale, writeStoredLocale } from "./detect";
import {
  type InterpolationValues,
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
} from "./format";

/**
 * Translate a typed key for `locale`, interpolating `{name}` placeholders.
 *
 * Resolves against the locale's FULL catalog IF it has already been lazily
 * loaded (`getLoadedCatalog`), else against the eager bootstrap subset. Chrome
 * keys are always available synchronously (they live in the bootstrap subset); a
 * key whose code-split chunk has not resolved yet gracefully yields the English
 * bootstrap string or, failing that, the key itself. For a live, re-rendering
 * surface prefer the context `t` (below), which tracks the active catalog as it
 * loads; this free function is for one-shot/synchronous callers.
 */
export function translate(
  locale: Locale,
  key: TranslationKey,
  values?: InterpolationValues,
): string {
  const catalog = getLoadedCatalog(locale) ?? BOOTSTRAP_CATALOG;
  // Typed catalogs guarantee the key exists once loaded; the `?? BOOTSTRAP ?? key`
  // chain covers a not-yet-loaded code-split chunk and any runtime drift.
  const template = catalog[key] ?? BOOTSTRAP_CATALOG[key] ?? key;
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
  const [locale, setLocaleState] = useState<Locale>(() => initialLocale ?? resolveInitialLocale());

  // The active message catalog. A locale whose FULL chunk is already cached
  // resolves SYNCHRONOUSLY here (including under the test suite, which warms the
  // cache in setup). Otherwise it seeds with the eager bootstrap subset — the
  // always-visible chrome renders with NO async hop — and swaps in the full,
  // dynamically imported catalog once it resolves via the effect below. Typed
  // `Partial<Messages>` because the bootstrap seed is intentionally partial.
  const [catalog, setCatalog] = useState<Partial<Messages>>(
    () => getLoadedCatalog(locale) ?? BOOTSTRAP_CATALOG,
  );

  // Reflect the active locale on the document element for a11y + `:lang()` CSS.
  useEffect(() => {
    document.documentElement.lang = LOCALE_META[locale].htmlLang;
  }, [locale]);

  // Keep `catalog` in sync with `locale`, lazily importing the active locale's
  // code-split chunk. This now fires for EVERY locale on first use — including
  // the default (English), whose bulk copy (`en/rest`) is split out of the entry
  // (#394) — not only for non-default locales.
  useEffect(() => {
    const alreadyLoaded = getLoadedCatalog(locale);
    if (alreadyLoaded) {
      setCatalog(alreadyLoaded);
      return;
    }
    // Full catalog not yet resolved: show the eager bootstrap subset (chrome is
    // translated immediately; other keys fall back to English/key) while the
    // chunk downloads, then re-render with the full catalog. `cancelled` guards a
    // locale change (or unmount) that lands before the import settles.
    let cancelled = false;
    setCatalog(BOOTSTRAP_CATALOG);
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
      // to the eager bootstrap subset (always-available chrome) and finally the
      // key itself for a not-yet-loaded code-split entry.
      t: (key, values) => interpolate(catalog[key] ?? BOOTSTRAP_CATALOG[key] ?? key, values),
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
