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

  await expect(page.getByRole("heading", { name: "Operations overview" })).toBeVisible();
  const firstKeyboardTarget = testInfo.project.name === "mobile-390"
    ? page.getByRole("button", { name: "Toggle Sidebar" })
    : page.getByRole("link", { name: /FerroGate Admin Console/ });
  await expectKeyboardFocus(page, firstKeyboardTarget, testInfo);
  await expectNoDocumentOverflow(page, testInfo);
  await expectNoAxeViolations(page, testInfo, ["critical"]);
  await attachViewportScreenshot(page, testInfo, "protected-shell");
});

test("typed resource mock supports direct data-route navigation", async ({ page }, testInfo) => {
  await page.goto("/app/mcp-servers");

  await expect(page.getByRole("heading", { name: "MCP servers" })).toBeVisible();
  await expect(page.getByText("incident-tools")).toBeVisible();
  await expectNoDocumentOverflow(page, testInfo);
  await attachViewportScreenshot(page, testInfo, "mcp-servers");
});
