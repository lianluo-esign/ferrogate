import { installAuthenticatedAdminApi } from "./support/admin-api";
import { installGatewayAssets } from "./support/gateway-assets";
import {
  attachViewportScreenshot,
  expect,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

test.beforeEach(async ({ page }) => {
  await installAuthenticatedAdminApi(page);
});

test("resource records stay readable and preserve URL pagination", async ({ page }, testInfo) => {
  await page.goto("/app/projects?filter=active");

  await expect(page.getByRole("heading", { name: "Projects" })).toBeVisible();
  await expect(page.getByText("Showing 1-25 of 52")).toBeVisible();
  await expect(
    page.getByText("Production payments routing with long operator-visible context"),
  ).toBeVisible();

  if (testInfo.project.name === "desktop-1440") {
    await expect(page.getByRole("table")).toBeVisible();
  } else {
    await expect(page.locator("[data-compact-records]")).toBeVisible();
    const action = page.getByRole("button", {
      name: "Actions for Production payments routing with long operator-visible context",
    });
    const box = await action.boundingBox();
    expect(box?.width).toBeGreaterThanOrEqual(44);
    expect(box?.height).toBeGreaterThanOrEqual(44);
  }

  await page.getByRole("button", { name: "Next" }).click();
  await expect(page).toHaveURL(/filter=active.*page=2|page=2.*filter=active/);
  await expect(page.getByText("Showing 26-50 of 52")).toBeVisible();
  await expect(page.getByText("Project 26 cross-region inference operations")).toBeVisible();
  await page.reload();
  await expect(page.getByText("Project 26 cross-region inference operations")).toBeVisible();

  await expectNoDocumentOverflow(page, testInfo);
  await attachViewportScreenshot(page, testInfo, "paginated-project-records");
});

test("generic and bespoke operator data surfaces expose stable compact actions", async ({
  page,
}, testInfo) => {
  const routes = [
    { path: "/app/request-logs", heading: "Request logs" },
    { path: "/app/api-keys-native", heading: "API keys" },
    { path: "/app/api-keys", heading: "API / virtual keys" },
    { path: "/app/tool-approvals", heading: "Tool approvals" },
    { path: "/app/self-hosted-workers", heading: "Self-hosted workers" },
    { path: "/app/billing-events", heading: "Billing events" },
  ];

  for (const route of routes) {
    await page.goto(route.path);
    await expect(page.getByRole("heading", { name: route.heading })).toBeVisible();
    await expectNoDocumentOverflow(page, testInfo);
    if (testInfo.project.name !== "desktop-1440") {
      await expect(page.locator("[data-compact-records]")).toBeVisible();
    }
  }

  await page.goto("/app/request-logs");
  await expect(page.getByRole("button", { name: "Copy Request ID" }).first()).toBeVisible();

  await page.goto("/app/api-keys");
  const keyActions = page.getByRole("button", {
    name: "Actions for Production deployment automation",
  });
  await keyActions.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("menuitem", { name: "Rotate" })).toBeVisible();

  await page.goto("/app/tool-approvals");
  await expect(
    page.getByRole("button", { name: "Actions for release-tools/deploy_production" }),
  ).toBeVisible();
  await attachViewportScreenshot(page, testInfo, "responsive-approval-queue");
});

test("the assets registry uses the shared responsive record surface", async ({
  page,
}, testInfo) => {
  // #336 reuse (#344 review finding): the registry list previously rendered a
  // raw 6-column <Table> at every viewport, so it never appeared in this gate
  // at all. It now goes through components/resource/resource-table.tsx.
  await installGatewayAssets(page);
  await page.goto("/app/assets");
  await expect(page.getByRole("heading", { name: "Assets" })).toBeVisible();
  await expect(page.getByText("deploy-cli").first()).toBeVisible();
  await expectNoDocumentOverflow(page, testInfo);

  if (testInfo.project.name === "desktop-1440") {
    await expect(page.locator("table").first()).toBeVisible();
  } else {
    await expect(page.locator("[data-compact-records]")).toBeVisible();
  }
  await attachViewportScreenshot(page, testInfo, "responsive-assets-registry");
});
