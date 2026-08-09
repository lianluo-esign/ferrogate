// Initial-locale resolution + persistence (#346).
//
// Resolution order (per the issue): a valid persisted choice, then
// `navigator.languages`, then English. Language is never inferred from IP.
// Only a validated locale code is persisted, under a versioned key, so a
// stale/renamed value can be rejected wholesale on a future format change.
import { DEFAULT_LOCALE, LOCALES, type Locale, isLocale } from "./catalog";

/** Versioned so a future catalog reshuffle can invalidate old preferences. */
export const LOCALE_STORAGE_KEY = "ferrogate-admin-locale-v1";

/** Read the persisted locale, or `null` if absent/invalid/unavailable. */
export function readStoredLocale(): Locale | null {
  try {
    const raw = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    return isLocale(raw) ? raw : null;
  } catch {
    // Private-mode / disabled storage: treat as "no preference".
    return null;
  }
}

/** Persist a validated locale code (no-op if storage is unavailable). */
export function writeStoredLocale(locale: Locale): void {
  try {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, locale);
  } catch {
    // Persistence is best-effort; the in-memory choice still applies.
  }
}

/** Map a BCP-47 tag to a supported locale by exact then base-language match. */
function matchLocale(tag: string): Locale | null {
  if (isLocale(tag)) return tag;
  const base = tag.toLowerCase().split("-")[0];
  return LOCALES.find((locale) => locale.toLowerCase().split("-")[0] === base) ?? null;
}

/**
 * Resolve the locale to start in. `preferred` defaults to the browser's
 * `navigator.languages`; a persisted choice always wins over it.
 */
export function resolveInitialLocale(
  preferred: readonly string[] = typeof navigator === "undefined"
    ? []
    : (navigator.languages ?? (navigator.language ? [navigator.language] : [])),
): Locale {
  const stored = readStoredLocale();
  if (stored) return stored;
  for (const tag of preferred) {
    const matched = matchLocale(tag);
    if (matched) return matched;
  }
  return DEFAULT_LOCALE;
}
