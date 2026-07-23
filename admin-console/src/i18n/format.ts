// Locale-aware message interpolation, pluralization, and value formatters.
//
// All formatters take an explicit `Locale` so they are pure and unit-testable;
// the provider (`./i18n-provider`) binds them to the active locale and exposes
// them through `useI18n()`. As pages migrate (#348) these replace ad-hoc
// `toLocaleString()` / hard-coded English number+date formatting.
import type { Locale } from "./catalog";

export type InterpolationValues = Record<string, string | number>;

/**
 * Replace `{name}` placeholders in a resolved message. Unmatched placeholders
 * are left verbatim so a missing value is visible in review rather than
 * silently blanked.
 */
export function interpolate(template: string, values?: InterpolationValues): string {
  if (!values) return template;
  return template.replace(/\{(\w+)\}/g, (match, name: string) =>
    name in values ? String(values[name]) : match,
  );
}

/**
 * Select a plural form for `count` using CLDR categories for `locale`.
 * `forms.other` is required; the rest are optional and fall back to `other`.
 */
export function selectPlural(
  locale: Locale,
  count: number,
  forms: Partial<Record<Intl.LDMLPluralRule, string>> & { other: string },
): string {
  const category = new Intl.PluralRules(locale).select(count);
  return forms[category] ?? forms.other;
}

export function formatNumber(
  locale: Locale,
  value: number,
  options?: Intl.NumberFormatOptions,
): string {
  return new Intl.NumberFormat(locale, options).format(value);
}

/** Integer token counts (e.g. LLM usage) with locale grouping. */
export function formatTokens(locale: Locale, tokens: number): string {
  return new Intl.NumberFormat(locale, { maximumFractionDigits: 0 }).format(tokens);
}

/** `ratio` is a fraction: `0.42` -> `42%`. */
export function formatPercent(
  locale: Locale,
  ratio: number,
  fractionDigits = 0,
): string {
  return new Intl.NumberFormat(locale, {
    style: "percent",
    minimumFractionDigits: fractionDigits,
    maximumFractionDigits: fractionDigits,
  }).format(ratio);
}

export function formatCurrency(
  locale: Locale,
  amount: number,
  currency: string,
  options?: Intl.NumberFormatOptions,
): string {
  return new Intl.NumberFormat(locale, {
    style: "currency",
    currency,
    ...options,
  }).format(amount);
}

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB", "PB"] as const;

/** Human byte size with binary (1024) steps and locale-formatted mantissa. */
export function formatBytes(locale: Locale, bytes: number, fractionDigits = 1): string {
  if (!Number.isFinite(bytes)) return formatNumber(locale, bytes);
  const sign = bytes < 0 ? "-" : "";
  let value = Math.abs(bytes);
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const digits = unit === 0 ? 0 : fractionDigits;
  return `${sign}${formatNumber(locale, value, {
    minimumFractionDigits: 0,
    maximumFractionDigits: digits,
  })} ${BYTE_UNITS[unit]}`;
}

export function formatDate(
  locale: Locale,
  value: Date | number | string,
  options: Intl.DateTimeFormatOptions = { dateStyle: "medium" },
): string {
  return new Intl.DateTimeFormat(locale, options).format(new Date(value));
}

export function formatTime(
  locale: Locale,
  value: Date | number | string,
  options: Intl.DateTimeFormatOptions = { timeStyle: "short" },
): string {
  return new Intl.DateTimeFormat(locale, options).format(new Date(value));
}

const RELATIVE_UNITS: { unit: Intl.RelativeTimeFormatUnit; ms: number }[] = [
  { unit: "year", ms: 365 * 24 * 60 * 60 * 1000 },
  { unit: "month", ms: 30 * 24 * 60 * 60 * 1000 },
  { unit: "week", ms: 7 * 24 * 60 * 60 * 1000 },
  { unit: "day", ms: 24 * 60 * 60 * 1000 },
  { unit: "hour", ms: 60 * 60 * 1000 },
  { unit: "minute", ms: 60 * 1000 },
  { unit: "second", ms: 1000 },
];

/**
 * Relative time from `now` to `value` (past is negative), auto-picking the
 * largest sensible unit: `-90_000` ms -> "1 minute ago" in `en`.
 */
export function formatRelativeTime(
  locale: Locale,
  value: Date | number,
  now: Date | number = Date.now(),
): string {
  const deltaMs = new Date(value).getTime() - new Date(now).getTime();
  const formatter = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  for (const { unit, ms } of RELATIVE_UNITS) {
    if (Math.abs(deltaMs) >= ms || unit === "second") {
      return formatter.format(Math.round(deltaMs / ms), unit);
    }
  }
  return formatter.format(0, "second");
}
