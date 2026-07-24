import { expect, type Page } from "@playwright/test";

// The locales the console ships (mirrors LOCALES in src/i18n/catalog.ts). Kept
// as a literal union so the route-matrix spec parametrizes over exactly the
// supported codes and `<html lang>` values without importing app runtime.
export type MatrixLocale = "en" | "zh-CN";

// The versioned localStorage key the console persists the chosen locale under
// (mirrors LOCALE_STORAGE_KEY in src/i18n/detect.ts).
export const LOCALE_STORAGE_KEY = "ferrogate-admin-locale-v1";

// The value written to <html lang> for each locale (mirrors LOCALE_META in
// src/i18n/catalog.ts). Asserted by the route matrix per locale.
export const HTML_LANG: Record<MatrixLocale, string> = {
  en: "en",
  "zh-CN": "zh-CN",
};

// Autonym the LanguageSwitcher menu renders for each locale (translate="no", so
// stable regardless of the active locale) — the argument `chooseLanguage` takes.
export const LOCALE_AUTONYM: Record<MatrixLocale, "English" | "简体中文"> = {
  en: "English",
  "zh-CN": "简体中文",
};

// Seed the persisted locale BEFORE the app boots so the FIRST render (and the
// initial `<html lang>`) resolves to `locale` with no post-load switch — the
// same init-script idiom `installAuthenticatedAdminApi` uses for the session.
// `resolveInitialLocale()` reads this versioned key first (src/i18n/detect.ts),
// ahead of `navigator.languages`, so this pins the whole session's language.
export async function seedLocale(page: Page, locale: MatrixLocale): Promise<void> {
  await page.addInitScript(
    ({ key, value }) => localStorage.setItem(key, value),
    { key: LOCALE_STORAGE_KEY, value: locale },
  );
}

// Open the global LanguageSwitcher and pick a locale by its autonym.
//
// The trigger's accessible name is itself localized (en: "Language: English.
// Change language"; zh-CN: "当前语言：简体中文。切换语言"), so we match on the
// change-language verb in EITHER locale. The menu options are autonyms rendered
// `translate="no"`, so their names are stable regardless of the active locale.
export async function chooseLanguage(page: Page, name: "English" | "简体中文") {
  await page.getByRole("button", { name: /Change language|切换语言/ }).click();
  await page.getByRole("menuitemradio", { name }).click();
  await expect(page.locator('[role="menu"]')).toHaveCount(0);
}
