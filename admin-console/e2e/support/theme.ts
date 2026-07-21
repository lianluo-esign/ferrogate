import { expect, type Page } from "@playwright/test";

export const THEME_STORAGE_KEY = "ferrogate-admin-theme-v1";

export async function chooseTheme(page: Page, name: "Light" | "Dark" | "System") {
  await page.getByRole("button", { name: /Theme: .*\. Change theme/ }).click();
  await page.getByRole("menuitemradio", { name }).click();
  await expect(page.locator('[role="menu"]')).toHaveCount(0);
}
