import { installAuthenticatedAdminApi } from "./support/admin-api";
import { installGatewayAssets } from "./support/gateway-assets";
import { chooseTheme } from "./support/theme";
import {
  expect,
  expectNoAxeViolations,
  test,
} from "./support/ui-contract";

test.beforeEach(async ({ page }) => {
  await installAuthenticatedAdminApi(page);
});

test("@desktop representative routes pass serious axe checks in both themes", async ({
  page,
}, testInfo) => {
  // /app/assets talks to the tenant GATEWAY surface, not /admin/v1/*, so it
  // needs its own mock on top of the shared admin one (#344/#348). Installing
  // it only routes /v1/assets*, leaving the other routes untouched.
  await installGatewayAssets(page);
  const routes = [
    { path: "/app/projects", heading: "Projects" },
    { path: "/app/tool-approvals", heading: "Tool approvals" },
    { path: "/app/ops/status", heading: "Ops status" },
    { path: "/app/assets", heading: "Assets" },
  ];

  for (const theme of ["light", "dark"] as const) {
    await page.goto(routes[0].path);
    await chooseTheme(page, theme === "dark" ? "Dark" : "Light");
    for (const route of routes) {
      await page.goto(route.path);
      await expect(page.locator("html")).toHaveClass(new RegExp(theme));
      await expect(page.getByRole("heading", { level: 1, name: route.heading })).toBeVisible();
      await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);
    }
  }
});

test("@desktop keyboard focus returns across row menus, sheets, dialogs, and confirmations", async ({
  page,
}) => {
  await page.goto("/app/projects");
  const newButton = page.getByRole("button", { name: "New" });
  await newButton.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog", { name: "New Projects" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(newButton).toBeFocused();

  const rowActions = page.getByRole("button", {
    name: "Actions for Production payments routing with long operator-visible context",
  });
  await rowActions.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("menuitem", { name: "Edit" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(rowActions).toBeFocused();

  await page.keyboard.press("Enter");
  await page.getByRole("menuitem", { name: "Delete" }).click();
  await expect(page.getByRole("alertdialog", { name: "Delete projects?" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(rowActions).toBeFocused();

  await page.goto("/app/tool-approvals");
  const approvalActions = page.getByRole("button", {
    name: "Actions for release-tools/deploy_production",
  });
  await approvalActions.focus();
  await page.keyboard.press("Enter");
  await page.getByRole("menuitem", { name: "Details" }).click();
  await expect(page.getByRole("dialog", { name: "Approval approval-e2e" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(approvalActions).toBeFocused();
});
