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
  CATALOGS,
  DEFAULT_LOCALE,
  LOCALE_META,
  type Locale,
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

/** Translate a typed key for `locale`, interpolating `{name}` placeholders. */
export function translate(
  locale: Locale,
  key: TranslationKey,
  values?: InterpolationValues,
): string {
  // Typed catalogs guarantee the key exists; the `?? DEFAULT` chain only guards
  // against a locale catalog being hand-edited out of sync at runtime.
  const template = CATALOGS[locale][key] ?? CATALOGS[DEFAULT_LOCALE][key] ?? key;
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

  // Reflect the active locale on the document element for a11y + `:lang()` CSS.
  useEffect(() => {
    document.documentElement.lang = LOCALE_META[locale].htmlLang;
  }, [locale]);

  const setLocale = useCallback((next: Locale) => {
    writeStoredLocale(next);
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
      t: (key, values) => translate(locale, key, values),
      format,
    };
  }, [locale, setLocale]);

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
