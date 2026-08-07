// Global control-plane cockpit browser contract (issue #343).
//
// One spec, three viewport PROJECTS (390x844, 768x1024, 1440x900 — see
// playwright.config.ts). Every untagged case runs on all three and asserts no
// horizontal overflow so the dense cockpit never clips; the @desktop case adds
// the "answer without scrolling on the first viewport" contract. The gate runs
// the real browser pass; locally this spec is verified with `--list` only.
import { installAuthenticatedAdminApi } from "./support/admin-api";
import {
  attachViewportScreenshot,
  expect,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

test("cockpit surfaces inventory, traffic, health, and filtered-view links", async ({
  page,
}, testInfo) => {
  await installAuthenticatedAdminApi(page);
  await page.goto("/app");

  await expect(page.getByRole("heading", { name: "Operations overview" })).toBeVisible();
  await expect(page.getByText("All tenants")).toBeVisible();

  // Traffic + cost band: durable lifetime totals with an explicit period.
  const traffic = page.getByRole("region", { name: "Traffic and cost" });
  await expect(traffic.getByText("12,000,000")).toBeVisible();
  await expect(traffic.getByText("3 / 4")).toBeVisible();
  await expect(traffic.getByText("$4,210.50")).toBeVisible();
  // Healthy workers derived from the gateway's real status labels (`online` +
  // `registered`), not from an `active` bucket the gateway never writes.
  await expect(traffic.getByText("9 / 12")).toBeVisible();

  // Core counts link to their FILTERED management views.
  await expect(traffic.getByRole("link", { name: "View MCP servers" })).toHaveAttribute(
    "href",
    "/app/mcp-servers",
  );
  await expect(traffic.getByRole("link", { name: "View Static assets" })).toHaveAttribute(
    "href",
    "/app/assets",
  );
  await expect(traffic.getByRole("link", { name: "View Agent runs" })).toHaveAttribute(
    "href",
    "/app/agent-runs",
  );
  await expect(
    traffic.getByRole("link", { name: "View Self-hosted workers" }),
  ).toHaveAttribute("href", "/app/workers/self-hosted");

  // Prioritized alerts with an evidence link to the source page.
  const alerts = page.getByRole("region", { name: "Alerts" });
  await expect(alerts.getByText("Providers unhealthy")).toBeVisible();
  await expect(alerts.getByText("anthropic")).toBeVisible();
  // The #458 alert kinds are titled, not a generic untitled "Alert".
  await expect(alerts.getByText("Tool approvals pending")).toBeVisible();
  // `exact` because the alerts region ALSO legitimately renders the #458
  // governance signal link "Scopes under quota pressure", which a substring
  // match would collide with; the titled alert kind is the node under test.
  await expect(alerts.getByText("Quota pressure", { exact: true })).toBeVisible();
  await expect(alerts.getByRole("link", { name: "Investigate" }).first()).toBeVisible();

  await expectNoDocumentOverflow(page, testInfo);
  await attachViewportScreenshot(page, testInfo, "cockpit");
});

test("period toggle re-scopes totals and preserves the choice in the URL", async ({ page }) => {
  await installAuthenticatedAdminApi(page);
  await page.goto("/app");

  const traffic = page.getByRole("region", { name: "Traffic and cost" });
  await expect(traffic.getByText("12,000,000")).toBeVisible();

  await page.getByRole("button", { name: "This month" }).click();
  await expect(page).toHaveURL(/[?&]period=month/);
  await expect(traffic.getByText("1,500,000")).toBeVisible();
  // Two nodes are correct UI: the period-scoped tokens AND cost tiles each
  // caption themselves with the active period, so the re-scoped label renders
  // once per tile. Any one being visible proves the toggle re-scoped the band.
  await expect(traffic.getByText("Calendar month 2026-07").first()).toBeVisible();
});

test("@desktop first viewport answers size, traffic, health, and action without scrolling", async ({
  page,
}, testInfo) => {
  await installAuthenticatedAdminApi(page);
  await page.goto("/app");

  await expect(page.getByRole("heading", { name: "Operations overview" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Traffic and cost" })).toBeVisible();

  // The alerts band (urgent action) sits within the first 1440x900 viewport.
  const alertsHeading = page.getByRole("heading", { name: "Alerts" });
  const box = await alertsHeading.boundingBox();
  expect(box).not.toBeNull();
  expect(box?.y ?? Number.POSITIVE_INFINITY).toBeLessThan(900);

  await expectNoDocumentOverflow(page, testInfo);
});

test("one unavailable section stays a partial error and never blanks healthy sections", async ({
  page,
}, testInfo) => {
  await installAuthenticatedAdminApi(page, { partialOverview: true });
  await page.goto("/app");

  const traffic = page.getByRole("region", { name: "Traffic and cost" });
  // Healthy sections stay populated ...
  await expect(traffic.getByText("12,000,000")).toBeVisible(); // usage ok
  await expect(traffic.getByText("3 / 4")).toBeVisible(); // runtime ok
  // ... while the failed section reads Unavailable (distinct from a zero).
  await expect(traffic.getByText("Unavailable").first()).toBeVisible();
  await expect(page.getByText("Overview section unavailable")).toBeVisible();

  await expectNoDocumentOverflow(page, testInfo);
});
