import {
  attachViewportScreenshot,
  expect,
  expectKeyboardFocus,
  expectNoAxeViolations,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

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
    await expectKeyboardFocus(page, page.getByLabel("Email"), testInfo);
    await expectNoDocumentOverflow(page, testInfo);
    await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);

    await page.locator("html").evaluate((element) => element.classList.add("dark"));
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

    await page.locator("html").evaluate((element) => element.classList.add("dark"));
    await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);
    await attachViewportScreenshot(page, testInfo, "register");
  });

  test("login server errors are announced and focused", async ({ page }) => {
    await page.route("http://localhost:8081/v1/admin/login", (route) =>
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
