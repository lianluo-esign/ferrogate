import { installAuthenticatedAdminApi } from "./support/admin-api";
import { chooseTheme, THEME_STORAGE_KEY } from "./support/theme";
import {
  attachViewportScreenshot,
  expect,
  expectNoAxeViolations,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

test("System follows the OS while explicit themes remain stable", async ({ page }, testInfo) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/login");

  const root = page.locator("html");
  await expect(root).toHaveClass(/dark/);
  await expect(root).toHaveCSS("color-scheme", "dark");
  await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute("content", "#09090b");
  await expect(page.getByRole("button", { name: "Theme: System. Change theme" })).toBeVisible();

  await chooseTheme(page, "Light");
  await expect(root).toHaveClass(/light/);
  await expect(root).toHaveCSS("color-scheme", "light");
  await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute("content", "#ffffff");
  await expect.poll(() => page.evaluate((key) => localStorage.getItem(key), THEME_STORAGE_KEY)).toBe("light");

  await page.emulateMedia({ colorScheme: "dark" });
  await expect(root).toHaveClass(/light/);

  await chooseTheme(page, "System");
  await expect(root).toHaveClass(/dark/);
  await page.emulateMedia({ colorScheme: "light" });
  await expect(root).toHaveClass(/light/);

  await expectNoDocumentOverflow(page, testInfo);
  await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);
  await attachViewportScreenshot(page, testInfo, "theme-system");
});

test("stored dark theme survives reload and protected navigation", async ({ page }, testInfo) => {
  await installAuthenticatedAdminApi(page);
  await page.addInitScript(
    ({ key, value }) => localStorage.setItem(key, value),
    { key: THEME_STORAGE_KEY, value: "dark" },
  );

  await page.goto("/app/projects");
  const root = page.locator("html");
  const trigger = page.getByRole("button", { name: "Theme: Dark. Change theme" });
  await expect(root).toHaveClass(/dark/);
  await expect(trigger).toBeVisible();

  await page.reload();
  await expect(root).toHaveClass(/dark/);
  await expect(trigger).toBeVisible();

  const urlBefore = page.url();
  await chooseTheme(page, "Light");
  await expect(root).toHaveClass(/light/);
  await expect(page).toHaveURL(urlBefore);
  await expect(page.getByRole("button", { name: "Theme: Light. Change theme" })).toBeFocused();

  await expectNoDocumentOverflow(page, testInfo);
  await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);
  await attachViewportScreenshot(page, testInfo, "theme-protected");
});
