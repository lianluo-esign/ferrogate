import { installAuthenticatedAdminApi } from "./support/admin-api";
import {
  attachViewportScreenshot,
  expect,
  expectNoAxeViolations,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

test.beforeEach(async ({ page }) => {
  await installAuthenticatedAdminApi(page);
});

test("generated forms search and select a paginated single entity reference", async ({
  page,
}, testInfo) => {
  const lookupRequests: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/admin/v1/tenant-accounts?")) lookupRequests.push(request.url());
  });

  await page.goto("/app/projects");
  await page.getByRole("button", { name: "New" }).click();
  const tenantPicker = page.getByRole("combobox", { name: "Tenant *" });
  await tenantPicker.click();

  await expect(page.getByRole("button", { name: "Load more" })).toBeVisible();
  const search = page.getByRole("searchbox", { name: "Search Tenant" });
  await search.fill("Tenant 24");
  await expect(page.getByRole("option", { name: /Tenant 24 operations/ })).toBeVisible();
  await search.press("ArrowDown");
  await expect(page.getByRole("option", { name: /Tenant 24 operations/ })).toBeFocused();
  await page.keyboard.press("Enter");

  await expect(tenantPicker).toBeFocused();
  await expect(page.getByRole("list", { name: "Selected Tenant" })).toContainText(
    "Tenant 24 operations",
  );
  await expect(page.getByRole("button", { name: "Copy tenant-24" })).toBeVisible();
  expect(
    lookupRequests.some((requestUrl) => {
      const url = new URL(requestUrl);
      return (
        url.searchParams.get("search") === "Tenant 24" &&
        url.searchParams.get("offset") === "0" &&
        url.searchParams.get("limit") === "20"
      );
    }),
  ).toBe(true);

  await expectNoDocumentOverflow(page, testInfo);
  await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);
  await attachViewportScreenshot(page, testInfo, "single-entity-reference");
});

test("generated forms support keyboard multi-selection and focus restoration", async ({
  page,
}, testInfo) => {
  await page.goto("/app/roles");
  await page.getByRole("button", { name: "New" }).click();
  const permissionPicker = page.getByRole("combobox", { name: "Permissions" });
  await permissionPicker.focus();
  await page.keyboard.press("Enter");

  const search = page.getByRole("searchbox", { name: "Search Permissions" });
  await search.fill("administration");
  await expect(page.getByRole("option", { name: /Read administration/ })).toBeVisible();
  await search.press("ArrowDown");
  await expect(page.getByRole("option", { name: /Read administration/ })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("option", { name: /Read administration/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(page.getByRole("option", { name: /Read administration/ })).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(page.getByRole("option", { name: /Write administration/ })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("option", { name: /Write administration/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await page.keyboard.press("Escape");

  await expect(permissionPicker).toBeFocused();
  const selected = page.getByRole("list", { name: "Selected Permissions" });
  await expect(selected).toContainText("Read administration");
  await expect(selected).toContainText("Write administration");
  await page.getByRole("button", { name: "Remove Read administration" }).click();
  await expect(selected).not.toContainText("Read administration");
  await expect(selected).toContainText("admin.write");

  await expectNoDocumentOverflow(page, testInfo);
  await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);
  await attachViewportScreenshot(page, testInfo, "multi-entity-reference");
});
