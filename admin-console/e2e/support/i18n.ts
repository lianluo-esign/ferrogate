import { expect, type Page } from "@playwright/test";

// The versioned localStorage key the console persists the chosen locale under
// (mirrors LOCALE_STORAGE_KEY in src/i18n/detect.ts).
export const LOCALE_STORAGE_KEY = "ferrogate-admin-locale-v1";

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
