import { installAuthenticatedAdminApi } from "./support/admin-api";
import {
  attachViewportScreenshot,
  expect,
  expectKeyboardFocus,
  expectNoAxeViolations,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

test.beforeEach(async ({ page }) => {
  await installAuthenticatedAdminApi(page);
});

test("protected shell renders and exposes a keyboard entry point", async ({ page }, testInfo) => {
  await page.goto("/app");

  const heading = page.getByRole("heading", { name: "Operations overview" });
  await expect(heading).toBeVisible();
  const skipLink = page.getByRole("link", { name: "Skip to main content" });
  await expectKeyboardFocus(page, skipLink, testInfo);
  await page.keyboard.press("Enter");
  await expect(heading).toBeFocused();

  if (testInfo.project.name === "mobile-390") {
    const sidebarTrigger = page.getByRole("button", { name: "Toggle Sidebar" });
    await sidebarTrigger.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("dialog", { name: "Sidebar" })).toBeVisible();
    await page.keyboard.press("Control+b");
    await expect(page.getByRole("dialog", { name: "Sidebar" })).toBeHidden();
    await expect(sidebarTrigger).toBeFocused();
  }
  await expectNoDocumentOverflow(page, testInfo);
  await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);
  await attachViewportScreenshot(page, testInfo, "protected-shell");
});

test("typed resource mock supports direct data-route navigation", async ({ page }, testInfo) => {
  await page.goto("/app/mcp-servers");

  await expect(page.getByRole("heading", { name: "MCP servers" })).toBeVisible();
  await expect(page.getByText("incident-tools")).toBeVisible();
  await expectNoDocumentOverflow(page, testInfo);
  await attachViewportScreenshot(page, testInfo, "mcp-servers");
});
