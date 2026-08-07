import {
  attachViewportScreenshot,
  expect,
  expectKeyboardFocus,
  expectNoAxeViolations,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";
import { chooseTheme } from "./support/theme";

test.describe("public auth routes", () => {
  test.use({
    expectedConsoleErrors: [/Failed to load resource: the server responded with a status of 401/],
  });
  test("login renders a keyboard- and axe-tested contract", async ({ page }, testInfo) => {
    await page.goto("/login");

    await expect(page.getByRole("main")).toHaveCount(1);
    await expect(page.getByRole("heading", { level: 1, name: "FerroGate Admin Console" })).toBeVisible();
    await expect(page.getByLabel("Email")).toBeVisible();
    await expect(page.getByLabel("Email")).toHaveAttribute("name", "email");
    await expect(page.getByLabel("Email")).toHaveAttribute("autocomplete", "email");
    // #346 placed the LanguageSwitcher BEFORE the ThemeSwitcher in the page's
    // top-right controls, so the first Tab now lands on it. The accessibility
    // property is unchanged: the first keyboard target is a meaningful,
    // announced control, and the theme toggle is the immediate next stop.
    await expectKeyboardFocus(
      page,
      page.getByRole("button", { name: "Language: English. Change language" }),
      testInfo,
    );
    await page.keyboard.press("Tab");
    await expect(
      page.getByRole("button", { name: "Theme: System. Change theme" }),
    ).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByLabel("Email")).toBeFocused();
    await expectNoDocumentOverflow(page, testInfo);
    await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);

    await chooseTheme(page, "Dark");
    await expect(page.locator("html")).toHaveClass(/dark/);
    await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);
    await attachViewportScreenshot(page, testInfo, "login");
  });

  test("register renders without browser or layout failures", async ({ page }, testInfo) => {
    await page.goto("/register");

    await expect(page.getByRole("main")).toHaveCount(1);
    await expect(page.getByRole("heading", { level: 1, name: "Create your organization" })).toBeVisible();
    await expect(page.getByLabel("Organization name")).toBeVisible();
    await expect(page.getByLabel("Organization name")).toHaveAttribute("name", "organization_name");
    await expect(page.getByLabel("Organization name")).toHaveAttribute("autocomplete", "organization");
    await expect(page.getByLabel("Your name (optional)")).toHaveAttribute("autocomplete", "name");
    await expectNoDocumentOverflow(page, testInfo);
    await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);

    await chooseTheme(page, "Dark");
    await expect(page.locator("html")).toHaveClass(/dark/);
    await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);
    await attachViewportScreenshot(page, testInfo, "register");
  });

  test("login server errors are announced and focused", async ({ page }) => {
    // Origin-relative since #696: the console session surface is same-origin.
    await page.route("**/v1/admin/login", (route) =>
      route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({
          error: { code: "invalid_credentials", message: "Email or password is incorrect" },
        }),
      }),
    );
    await page.goto("/login");
    await page.getByLabel("Email").fill("operator@example.com");
    await page.getByLabel("Password").fill("incorrect-password");
    await page.getByRole("button", { name: "Sign in" }).click();

    const error = page.getByRole("alert");
    await expect(error).toHaveText("Email or password is incorrect");
    await expect(error).toBeFocused();
  });
});
