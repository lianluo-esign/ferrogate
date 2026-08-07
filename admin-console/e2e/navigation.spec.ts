import { installAuthenticatedAdminApi } from "./support/admin-api";
import {
  attachViewportScreenshot,
  expect,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

async function openMobileNavigationIfNeeded(
  page: Parameters<typeof installAuthenticatedAdminApi>[0],
  projectName: string,
): Promise<void> {
  if (projectName !== "mobile-390") return;
  const trigger = page.getByRole("button", { name: "Toggle Sidebar" });
  await trigger.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog", { name: "Sidebar" })).toBeVisible();
}

test.beforeEach(async ({ page }) => {
  await installAuthenticatedAdminApi(page);
});

test("native API key deep link has one active destination and the correct breadcrumb", async ({
  page,
}, testInfo) => {
  await page.goto("/app/api-keys-native");

  await expect(
    page.getByRole("navigation", { name: "breadcrumb" }).getByRole("link", {
      name: "Gateway API Keys",
    }),
  ).toHaveAttribute("aria-current", "page");
  await openMobileNavigationIfNeeded(page, testInfo.project.name);
  await expect(page.locator('[data-sidebar="menu-sub-button"][href="/app/api-keys-native"]')).toHaveAttribute(
    "data-active",
    "true",
  );
  await expect(page.locator('[data-sidebar="menu-sub-button"][href="/app/api-keys"]')).toHaveAttribute(
    "data-active",
    "false",
  );
  await expect(page.locator('[data-sidebar="menu-sub-button"][data-active="true"]')).toHaveCount(1);
  await attachViewportScreenshot(page, testInfo, "gateway-api-keys-navigation");
});

test("keyboard navigation closes mobile navigation and focuses the destination heading", async ({
  page,
}, testInfo) => {
  await page.goto("/app");
  await openMobileNavigationIfNeeded(page, testInfo.project.name);

  const group = page.getByRole("button", { name: "Organization" });
  await group.focus();
  await page.keyboard.press("Enter");
  // `exact` because the dashboard behind the sidebar legitimately renders an
  // inventory-row link accessibly named "View Workspaces", which the default
  // substring match would also resolve; the sidebar entry's exact name is
  // "Workspaces".
  const destination = page.getByRole("link", { name: "Workspaces", exact: true });
  await destination.focus();
  await page.keyboard.press("Enter");

  await expect(page).toHaveURL(/\/app\/workspaces$/);
  await expect(page.getByRole("heading", { name: "Workspaces" })).toBeFocused();
  if (testInfo.project.name === "mobile-390") {
    await expect(page.getByRole("dialog", { name: "Sidebar" })).toBeHidden();
  }
  await expectNoDocumentOverflow(page, testInfo);
  await attachViewportScreenshot(page, testInfo, "workspace-keyboard-navigation");
});

test("@desktop collapsed navigation preserves the active page and layout", async ({
  page,
}, testInfo) => {
  await page.goto("/app");

  await page.locator('[data-sidebar="trigger"]').click();
  await expect(page.locator('[data-variant="sidebar"][data-state="collapsed"]')).toBeVisible();
  await expect(page.getByRole("heading", { name: "Operations overview" })).toBeVisible();
  await expectNoDocumentOverflow(page, testInfo);
  await attachViewportScreenshot(page, testInfo, "collapsed-sidebar");
});
