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
import { en } from "./locales/en";
import { zhCN } from "./locales/zh-CN";

/** Every valid translation key, derived from the English source catalog. */
export type TranslationKey = keyof typeof en;

/** The shape every locale catalog must satisfy: all keys, string values. */
export type Messages = Record<TranslationKey, string>;

/** Canonical initial locales for the console (#346). */
export const LOCALES = ["en", "zh-CN"] as const;
export type Locale = (typeof LOCALES)[number];

/** Source/fallback locale. */
export const DEFAULT_LOCALE: Locale = "en";

/**
 * Per-locale display metadata. `nativeName` is the autonym (the language's own
 * name), so the selector is legible whatever the active locale is. `htmlLang`
 * is the value written to `<html lang>` / passed to `Intl`.
 */
export const LOCALE_META: Record<Locale, { nativeName: string; htmlLang: string }> = {
  en: { nativeName: "English", htmlLang: "en" },
  "zh-CN": { nativeName: "简体中文", htmlLang: "zh-CN" },
};

/** The registry of loaded catalogs. */
export const CATALOGS: Record<Locale, Messages> = {
  en,
  "zh-CN": zhCN,
};

/** Runtime type guard for an untrusted locale code (storage, navigator, URL). */
export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && (LOCALES as readonly string[]).includes(value);
}
