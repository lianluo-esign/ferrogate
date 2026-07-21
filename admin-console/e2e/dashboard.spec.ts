import { installAuthenticatedAdminApi } from "./support/admin-api";
import {
  attachViewportScreenshot,
  expect,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

test("operator dashboard prioritizes live posture, action, traffic, and cost", async ({
  page,
}, testInfo) => {
  await installAuthenticatedAdminApi(page);
  await page.goto("/app");

  await expect(page.getByRole("heading", { name: "Operations overview" })).toBeVisible();
  const posture = page.getByRole("region", { name: "Gateway posture" });
  await expect(posture.getByText("Ready")).toBeVisible();
  await expect(posture.getByText("1 / 2")).toBeVisible();
  await expect(posture.getByText("$12.3456")).toBeVisible();
  await expect(page.getByText("1 provider need attention.")).toBeVisible();
  await expect(page.getByText("req-dashboard-failed")).toBeVisible();
  await expect(page.getByRole("link", { name: "View logs" })).toHaveAttribute(
    "href",
    "/app/request-logs",
  );
  await expect(page.getByRole("link", { name: "View reports" })).toHaveAttribute(
    "href",
    "/app/usage-reports",
  );

  const documentHeight = await page.evaluate(() => document.documentElement.scrollHeight);
  expect(documentHeight).toBeLessThan(2_500);
  await expectNoDocumentOverflow(page, testInfo);
  await attachViewportScreenshot(page, testInfo, "operator-dashboard");
});

test.describe("partial source failure", () => {
  test.use({
    expectedConsoleErrors: [/Failed to load resource: the server responded with a status of 503/],
  });

  test("one failed dashboard source does not hide healthy sources", async ({ page }, testInfo) => {
    await installAuthenticatedAdminApi(page, { failPaths: ["/admin/v1/provider-health"] });
    await page.goto("/app");

    await expect(
      page.getByText("Provider health is unavailable: forced browser-contract failure."),
    ).toBeVisible();
    await expect(page.getByText("Ready")).toBeVisible();
    await expect(page.getByText("req-dashboard-success")).toBeVisible();
    await expect(page.getByText("$12.3456")).toHaveCount(2);
    await expectNoDocumentOverflow(page, testInfo);
  });
});
