import {
  attachViewportScreenshot,
  expect,
  expectKeyboardFocus,
  expectNoAxeViolations,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

test.describe("public auth routes", () => {
  test("login renders a keyboard- and axe-tested contract", async ({ page }, testInfo) => {
    await page.goto("/login");

    await expect(page.getByText("FerroGate Admin Console")).toBeVisible();
    await expect(page.getByLabel("Email")).toBeVisible();
    await expectKeyboardFocus(page, page.getByLabel("Email"), testInfo);
    await expectNoDocumentOverflow(page, testInfo);
    await expectNoAxeViolations(page, testInfo, ["critical"]);
    await attachViewportScreenshot(page, testInfo, "login");
  });

  test("register renders without browser or layout failures", async ({ page }, testInfo) => {
    await page.goto("/register");

    await expect(page.getByText("Create your organization")).toBeVisible();
    await expect(page.getByLabel("Organization name")).toBeVisible();
    await expectNoDocumentOverflow(page, testInfo);
    await attachViewportScreenshot(page, testInfo, "register");
  });
});
