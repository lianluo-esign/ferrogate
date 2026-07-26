// Static-site publish + domain-management browser contract (issue #345).
//
// #345's remaining acceptance box: "Playwright covers publish, republish,
// open/preview, bind/unbind, mobile, and keyboard behavior." The static-sites
// page (src/pages/static-sites.tsx) and the domain bind/unbind page
// (src/pages/site-domains.tsx) are built on main; this is their first e2e spec.
//
// The crux (same as #344/#348): these pages drive the tenant GATEWAY surface
// (`/v1/assets` list, the registry `/manifest` + the `serving`-channel-resolved
// bundle manifest read the page derives every displayed policy from, the
// raw-bytes publish PUT, and the `serving` channel-move rollback) plus the
// Admin API site-domains bind/unbind — NOT the plain
// `/admin/v1/*` shell that installAuthenticatedAdminApi covers. So each test
// pairs the shared admin mock (session + app shell) with the bespoke, stateful
// installGatewayStaticSites mock (support/gateway-static-sites.ts) whose shapes
// match the generated OpenAPI contract.
//
// Web-first assertions only (no hard sleeps). MUTATIONS are asserted by
// intercepting the exact request (method + pathname + headers/body) with
// waitForRequest, and confirmed by the state-reflected UI change the pages'
// query-invalidation refetch produces (a new site row, a new history version,
// a bound/unbound hostname). DEV-writes / GATE-runs: chromium is not installed
// in the dev-loop, so this is authored here and executed by the gate across the
// three viewport projects (mobile-390 / tablet-768 / desktop-1440).
import type { Page, Request } from "@playwright/test";
import { installAuthenticatedAdminApi } from "./support/admin-api";
import { installGatewayStaticSites } from "./support/gateway-static-sites";
import {
  attachViewportScreenshot,
  expect,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

const GATEWAY_ORIGIN = "http://localhost:8080";

function isGatewayRequest(request: Request, method: string, pathname: string): boolean {
  return request.method() === method && new URL(request.url()).pathname === pathname;
}

/** The static-sites list row for a site slug (keyed by its stable test id). */
function siteRow(page: Page, slug: string) {
  return page.getByTestId(`static-site-${slug}`);
}

/** The per-site detail drawer (a Sheet = role dialog), anchored on copy unique
 * to it so it is never confused with the nested rollback/unpublish dialogs. */
function detailDrawer(page: Page) {
  return page.getByRole("dialog").filter({ hasText: "Version history" });
}

/** Opens a site's detail drawer and waits for the registry-backed history to load. */
async function openSiteDrawer(page: Page, slug: string): Promise<void> {
  await siteRow(page, slug).getByRole("button", { name: "More details" }).click();
  await expect(detailDrawer(page).getByRole("heading", { name: "Version history" })).toBeVisible();
}

test.beforeEach(async ({ page }) => {
  await installAuthenticatedAdminApi(page);
});

test("publish drives the static_site bundle PUT with x-site-* policy headers, byte progress, and a canonical serve URL", async ({
  page,
}, testInfo) => {
  // Hold the publish PUT so the determinate "Uploading bundle…" progress phase
  // is observable (it otherwise completes faster than a poll could catch it).
  await installGatewayStaticSites(page, { uploadHoldMs: 700 });
  await page.goto("/app/static-sites");
  await expect(page.getByRole("heading", { name: "Static sites" })).toBeVisible();

  // Fill the publish form for a brand-new site slug. The tenant is stated
  // read-only: it rides the API key server-side, not the publish path.
  await page.locator("#site-slug").fill("landing");
  await page.locator("#site-version").fill("1.0.0");
  await page.locator("#site-cache").fill("public, max-age=300");
  await page.getByRole("switch", { name: "Public access" }).click();
  await page.getByRole("switch", { name: "SPA fallback" }).click();
  await page.locator("#site-bundle").setInputFiles({
    name: "landing.zip",
    mimeType: "application/zip",
    buffer: Buffer.alloc(4096, 1),
  });

  // The live serve-URL preview exposes the canonical serve path as the slug is
  // typed (the tenant-scoped /sites/{tenant}/{site}/ address).
  await expect(page.getByText("/sites/tenant-e2e/landing/")).toBeVisible();

  const publishPromise = page.waitForRequest((request) =>
    isGatewayRequest(request, "PUT", "/v1/assets/static_site/landing/1.0.0"),
  );
  await page.getByRole("button", { name: "Publish", exact: true }).click();

  // 1) The publish is a single raw-bytes PUT carrying the serving policy as
  // x-site-* request headers (public opt-in + SPA fallback + Cache-Control).
  const publishRequest = await publishPromise;
  const headers = publishRequest.headers();
  expect(headers["x-site-public"]).toBe("true");
  expect(headers["x-site-spa-fallback"]).toBe("true");
  expect(headers["x-site-cache-control"]).toBe("public, max-age=300");

  // 2) Real byte-level progress surfaces during the held upload (the progressbar
  // is determinate; the phase label match ignores the trailing ellipsis).
  await expect(page.getByText("Uploading bundle")).toBeVisible();
  await expect(page.getByRole("progressbar")).toBeVisible();

  // 3) Success surfaces and the refetched list shows the new site with its
  // canonical serve URL link (the publish result made observable in the UI).
  await expect(page.getByText(/Published landing/)).toBeVisible();
  const newRow = siteRow(page, "landing");
  await expect(newRow).toBeVisible();
  await expect(newRow.getByRole("link", { name: /\/sites\/tenant-e2e\/landing\// })).toHaveAttribute(
    "href",
    `${GATEWAY_ORIGIN}/sites/tenant-e2e/landing/`,
  );

  await attachViewportScreenshot(page, testInfo, "static-sites-publish");
});

test("republish pushes a new bundle version to an existing site and it appears (active) in the history", async ({
  page,
}, testInfo) => {
  await installGatewayStaticSites(page);
  await page.goto("/app/static-sites");
  await expect(siteRow(page, "marketing")).toBeVisible();

  // Republish marketing at a new immutable bundle version.
  await page.locator("#site-slug").fill("marketing");
  await page.locator("#site-version").fill("3.0.0");
  await page.getByRole("switch", { name: "Public access" }).click();
  await page.locator("#site-bundle").setInputFiles({
    name: "marketing-v3.zip",
    mimeType: "application/zip",
    buffer: Buffer.alloc(2048, 9),
  });

  const publishPromise = page.waitForRequest((request) =>
    isGatewayRequest(request, "PUT", "/v1/assets/static_site/marketing/3.0.0"),
  );
  await page.getByRole("button", { name: "Publish", exact: true }).click();
  const publishRequest = await publishPromise;
  expect(publishRequest.method()).toBe("PUT");
  await expect(page.getByText(/Published marketing/)).toBeVisible();

  // The detail drawer's version history now retains the new bundle as the served
  // (Active) version alongside the prior retained versions.
  await openSiteDrawer(page, "marketing");
  const newVersion = page.getByTestId("static-site-version-3.0.0");
  await expect(newVersion).toBeVisible();
  await expect(newVersion).toContainText("Active");
  await expect(page.getByTestId("static-site-version-2.0.0")).toBeVisible();
  await expect(page.getByTestId("static-site-version-1.0.0")).toBeVisible();

  await attachViewportScreenshot(page, testInfo, "static-sites-republish");
});

test("open/preview exposes the canonical serve URL in the list and the detail drawer", async ({
  page,
}, testInfo) => {
  await installGatewayStaticSites(page);
  await page.goto("/app/static-sites");

  // The list row's serve-URL link resolves the tenant-scoped serve path against
  // the gateway origin and opens it in a new tab (rel=noopener).
  const listLink = siteRow(page, "marketing").getByRole("link", {
    name: /\/sites\/tenant-e2e\/marketing\//,
  });
  await expect(listLink).toHaveAttribute("href", `${GATEWAY_ORIGIN}/sites/tenant-e2e/marketing/`);
  await expect(listLink).toHaveAttribute("target", "_blank");

  // A site with a bound custom domain still advertises the TENANT-SCOPED serve
  // path as its canonical URL (docs is bound to docs.acme.example): a custom
  // hostname only serves once its #488 DNS ownership proof resolves, so it is
  // never substituted for the canonical link. Its liveness lives in the drawer.
  await expect(siteRow(page, "docs").getByRole("link", { name: /\/sites\/tenant-e2e\/docs\// })).toBeVisible();

  // The drawer's outbound "Open serve URL" affordance targets the same canonical
  // URL in a new tab.
  await openSiteDrawer(page, "marketing");
  const openLink = detailDrawer(page).getByRole("link", { name: /Open serve URL/ });
  await expect(openLink).toHaveAttribute("href", `${GATEWAY_ORIGIN}/sites/tenant-e2e/marketing/`);
  await expect(openLink).toHaveAttribute("target", "_blank");

  await attachViewportScreenshot(page, testInfo, "static-sites-preview");
});

test("bind attaches a custom domain to a site and unbind detaches it", async ({
  page,
}, testInfo) => {
  await installGatewayStaticSites(page);
  await page.goto("/app/site-domains");
  await expect(page.getByRole("heading", { name: "Site domains" })).toBeVisible();
  // The seeded binding is listed.
  await expect(page.getByTestId("site-domain-docs.acme.example")).toBeVisible();

  // Bind a new hostname: FQDN + a tenant chosen from the entity picker + a site.
  await page.locator("#bind-hostname").fill("app.acme.example");
  await page.getByRole("combobox", { name: "Tenant" }).click();
  await page.getByRole("searchbox", { name: "Search Tenant" }).fill("Tenant 3 operations");
  await page.getByRole("option", { name: /Tenant 3 operations/ }).click();
  await page.locator("#bind-site").fill("marketing");

  const bindPromise = page.waitForRequest((request) =>
    isGatewayRequest(request, "POST", "/admin/v1/site-domains"),
  );
  await page.getByRole("button", { name: "Bind hostname" }).click();
  const bindRequest = await bindPromise;
  const bindBody = bindRequest.postDataJSON() as Record<string, unknown>;
  expect(bindBody.hostname).toBe("app.acme.example");
  expect(bindBody.tenant_id).toBe("tenant-3");
  expect(bindBody.site).toBe("marketing");

  // The refetched list shows the new binding.
  await expect(page.getByText(/Bound app\.acme\.example/)).toBeVisible();
  const boundRow = page.getByTestId("site-domain-app.acme.example");
  await expect(boundRow).toBeVisible();

  // Unbind it behind the confirm dialog; the refetched list drops the row.
  await boundRow.getByRole("button", { name: "Unbind" }).click();
  const confirm = page.getByRole("alertdialog", { name: "Unbind app.acme.example?" });
  await expect(confirm).toBeVisible();

  const unbindPromise = page.waitForRequest((request) =>
    isGatewayRequest(request, "DELETE", "/admin/v1/site-domains/app.acme.example"),
  );
  await confirm.getByRole("button", { name: "Unbind" }).click();
  const unbindRequest = await unbindPromise;
  expect(unbindRequest.method()).toBe("DELETE");
  await expect(page.getByTestId("site-domain-app.acme.example")).toHaveCount(0);
  // The pre-existing binding is untouched.
  await expect(page.getByTestId("site-domain-docs.acme.example")).toBeVisible();

  await attachViewportScreenshot(page, testInfo, "site-domains-bind-unbind");
});

test("mobile viewport renders the site list and a publish/bind action without clipping", async ({
  page,
}, testInfo) => {
  await installGatewayStaticSites(page);
  await page.goto("/app/static-sites");

  // The list renders at every viewport (this case runs on mobile-390,
  // tablet-768, and desktop-1440) with no horizontal document overflow.
  await expect(page.getByRole("heading", { name: "Static sites" })).toBeVisible();
  await expect(siteRow(page, "marketing")).toBeVisible();
  await expect(siteRow(page, "docs")).toBeVisible();
  await expectNoDocumentOverflow(page, testInfo);

  const viewport = page.viewportSize();
  const withinViewport = async (locator: ReturnType<Page["getByRole"]>) => {
    await expect(locator).toBeVisible();
    const box = await locator.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual((viewport?.width ?? 0) + 1);
  };

  // The primary publish action and the marketing row's bind affordance both sit
  // within the viewport (not clipped off-screen).
  await withinViewport(page.getByRole("button", { name: "Publish", exact: true }));
  await withinViewport(siteRow(page, "marketing").getByRole("link", { name: "Bind a domain" }));

  await attachViewportScreenshot(page, testInfo, "static-sites-mobile");
});

test("keyboard operates the unbind confirm dialog (enter opens, escape dismisses, focus is trapped and restored)", async ({
  page,
}, testInfo) => {
  await installGatewayStaticSites(page);

  // Track every unbind DELETE so we can prove Escape never fires one.
  let unbindRequests = 0;
  page.on("request", (request) => {
    if (
      request.method() === "DELETE" &&
      new URL(request.url()).pathname.startsWith("/admin/v1/site-domains/")
    ) {
      unbindRequests += 1;
    }
  });

  await page.goto("/app/site-domains");
  const row = page.getByTestId("site-domain-docs.acme.example");
  await expect(row).toBeVisible();
  const unbindTrigger = row.getByRole("button", { name: "Unbind" });

  // Enter on the focused trigger opens the confirm dialog.
  await unbindTrigger.focus();
  await expect(unbindTrigger).toBeFocused();
  await page.keyboard.press("Enter");
  const confirm = page.getByRole("alertdialog", { name: "Unbind docs.acme.example?" });
  await expect(confirm).toBeVisible();

  // Focus is trapped inside the dialog: Tab keeps the active element within it.
  await page.keyboard.press("Tab");
  const focusInsideDialog = await page.evaluate(
    () => document.activeElement?.closest('[role="alertdialog"]') !== null,
  );
  expect(focusInsideDialog).toBe(true);

  // Escape dismisses the dialog WITHOUT unbinding, and returns focus to the trigger.
  await page.keyboard.press("Escape");
  await expect(page.getByRole("alertdialog")).toHaveCount(0);
  await expect(unbindTrigger).toBeFocused();
  expect(unbindRequests).toBe(0);

  // Re-open with Enter and confirm via the keyboard: the destructive action fires
  // and the refetched list drops the row.
  await page.keyboard.press("Enter");
  await expect(confirm).toBeVisible();
  const unbindPromise = page.waitForRequest((request) =>
    isGatewayRequest(request, "DELETE", "/admin/v1/site-domains/docs.acme.example"),
  );
  await confirm.getByRole("button", { name: "Unbind" }).focus();
  await page.keyboard.press("Enter");
  await unbindPromise;
  await expect(page.getByTestId("site-domain-docs.acme.example")).toHaveCount(0);
  expect(unbindRequests).toBe(1);

  await attachViewportScreenshot(page, testInfo, "site-domains-keyboard");
});
