import { installAuthenticatedAdminApi } from "./support/admin-api";
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
  const routes = [
    { path: "/app/projects", heading: "Projects" },
    { path: "/app/tool-approvals", heading: "Tool approvals" },
    { path: "/app/ops/status", heading: "Ops status" },
  ];

  for (const theme of ["light", "dark"] as const) {
    await page.locator("html").evaluate((element, nextTheme) => {
      element.classList.toggle("dark", nextTheme === "dark");
    }, theme);
    for (const route of routes) {
      await page.goto(route.path);
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
