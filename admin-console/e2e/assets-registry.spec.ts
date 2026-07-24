// Assets-registry lifecycle browser contract (issue #344).
//
// #344's remaining acceptance box: "Playwright covers upload, promotion, yank,
// download, delete confirmation, mobile, and partial errors." The registry page
// (src/pages/assets.tsx) is built on main; this is its first e2e spec.
//
// The crux (#348): the page fetches the tenant GATEWAY surface (`/v1/assets`,
// `/v1/assets/storage/summary`, the manifest, presign upload/commit, and the
// channel/yank/delete mutations) — NOT the `/admin/v1/*` Admin API that
// installAuthenticatedAdminApi covers. So each test pairs the shared admin mock
// (session + app shell) with the bespoke, stateful installGatewayAssets mock
// (support/gateway-assets.ts) whose shapes match the generated OpenAPI contract.
//
// Web-first assertions only (no hard sleeps). Lifecycle MUTATIONS are asserted
// by intercepting the exact request (method + pathname + query) with
// waitForRequest, and confirmed by the state-reflected UI change the page's
// query-invalidation refetch produces (a yanked badge, a repointed channel, a
// removed row). DEV-writes / GATE-runs: chromium is not installed in the
// dev-loop, so this is authored here and executed by the gate across the three
// viewport projects (mobile-390 / tablet-768 / desktop-1440).
import type { Page, Request } from "@playwright/test";
import { installAuthenticatedAdminApi } from "./support/admin-api";
import { installGatewayAssets } from "./support/gateway-assets";
import {
  attachViewportScreenshot,
  expect,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

function isGatewayRequest(request: Request, method: string, pathname: string): boolean {
  return request.method() === method && new URL(request.url()).pathname === pathname;
}

/** The detail dialog, anchored on copy unique to it (never the confirm dialogs). */
function detailDialog(page: Page) {
  return page.getByRole("dialog").filter({ hasText: "Registry manifest" });
}

/** Opens deploy-cli's registry detail dialog and waits for the manifest to load. */
async function openDeployCliDetail(page: Page): Promise<void> {
  await page.goto("/app/assets");
  await expect(page.getByRole("heading", { name: "Assets" })).toBeVisible();
  const row = page.getByRole("row").filter({ hasText: "deploy-cli" });
  await row.getByRole("button", { name: "More details" }).click();
  const detail = detailDialog(page);
  await expect(detail.getByText("cli_tool/deploy-cli")).toBeVisible();
  // The Versions heading only renders once the manifest query resolves.
  await expect(detail.getByRole("heading", { name: "Versions" })).toBeVisible();
}

test.beforeEach(async ({ page }) => {
  await installAuthenticatedAdminApi(page);
});

test("upload drives the presigned intent -> direct PUT -> commit flow with progress", async ({
  page,
}, testInfo) => {
  // Hold the direct-to-bucket PUT so the "Uploading to storage…" phase is
  // observable; the flow otherwise completes faster than a poll could catch it.
  await installGatewayAssets(page, { uploadHoldMs: 800 });
  await page.goto("/app/assets");

  // The card exposes the large-object entry point (storage summary enables it).
  await page.getByRole("button", { name: "Upload large object" }).click();
  const dialog = page.getByRole("dialog").filter({ hasText: "Large-object upload" });
  await dialog.locator("#presign-asset-name").fill("big-bundle");
  await dialog.locator("#presign-asset-version").fill("3.0.0");
  const bytes = Buffer.alloc(4096, 7);
  await dialog.locator("#presign-asset-file").setInputFiles({
    name: "big-bundle.tar.gz",
    mimeType: "application/gzip",
    buffer: bytes,
  });

  // Register both waiters up front: the intent fires on submit, the commit only
  // after the held bucket PUT resolves.
  const intentPromise = page.waitForRequest((request) =>
    isGatewayRequest(request, "POST", "/v1/assets/presign/upload/cli_tool/big-bundle/3.0.0"),
  );
  const commitPromise = page.waitForRequest((request) =>
    isGatewayRequest(request, "POST", "/v1/assets/presign/commit/cli_tool/big-bundle/3.0.0"),
  );

  await dialog.getByRole("button", { name: "Upload large object" }).click();

  // 1) Intent carries the client-hashed SHA-256 + declared byte length.
  const intentRequest = await intentPromise;
  const intentBody = intentRequest.postDataJSON() as { size_bytes: number; sha256: string };
  expect(intentBody.size_bytes).toBe(4096);
  expect(intentBody.sha256).toMatch(/^[0-9a-f]{64}$/);

  // 2) Progress surfaces during the held direct-to-bucket upload phase (the
  // phase status is a substring match, so the trailing ellipsis is irrelevant).
  await expect(page.getByText("Uploading to storage")).toBeVisible();
  await expect(page.getByRole("progressbar")).toBeVisible();

  // 3) Commit re-declares the intent's upload_id + verified size.
  const commitRequest = await commitPromise;
  const commitBody = commitRequest.postDataJSON() as { upload_id: string; size_bytes: number };
  expect(commitBody.upload_id).toBeTruthy();
  expect(commitBody.size_bytes).toBe(4096);

  // 4) Success surfaces and the dialog closes.
  await expect(page.getByText("Large object committed")).toBeVisible();
  await attachViewportScreenshot(page, testInfo, "assets-upload");
});

test("promotion moves a channel pointer to a version and repoints on refetch", async ({
  page,
}, testInfo) => {
  await installGatewayAssets(page);
  await openDeployCliDetail(page);
  const detail = detailDialog(page);

  await detail.getByRole("button", { name: "Set channel" }).click();
  const channelDialog = page.getByRole("dialog").filter({ hasText: "Set a channel pointer" });
  await channelDialog.locator("#asset-channel-name").fill("stable");
  await channelDialog.locator("#asset-channel-version").click();
  await page.getByRole("option", { name: "2.0.0" }).click();

  const [request] = await Promise.all([
    page.waitForRequest((r) =>
      isGatewayRequest(r, "PUT", "/v1/assets/cli_tool/deploy-cli/channels/stable"),
    ),
    channelDialog.getByRole("button", { name: "Set channel" }).click(),
  ]);
  // The target version rides the query string, matching the page's client.
  expect(new URL(request.url()).searchParams.get("version")).toBe("2.0.0");

  await expect(page.getByText("Channel pointer saved")).toBeVisible();
  // The refetched manifest repoints stable 1.5.0 -> 2.0.0 in the channels table.
  const channelsTable = detail.getByRole("table").nth(0);
  await expect(channelsTable.getByRole("row").filter({ hasText: "stable" })).toContainText(
    "2.0.0",
  );

  await attachViewportScreenshot(page, testInfo, "assets-promotion");
});

test("yank marks a version yanked via the consequence-confirm dialog", async ({
  page,
}, testInfo) => {
  await installGatewayAssets(page);
  await openDeployCliDetail(page);
  const detail = detailDialog(page);
  const versionsTable = detail.getByRole("table").nth(1);
  const activeRow = versionsTable.getByRole("row").filter({ hasText: "2.0.0" });

  await activeRow.getByRole("button", { name: "Yank" }).click();
  // A consequence-aware confirm names the exact resource before firing.
  const confirm = page.getByRole("dialog", { name: "Yank cli_tool/deploy-cli@2.0.0?" });
  await expect(confirm).toBeVisible();

  const [request] = await Promise.all([
    page.waitForRequest((r) =>
      isGatewayRequest(r, "POST", "/v1/assets/cli_tool/deploy-cli/2.0.0/yank"),
    ),
    confirm.getByRole("button", { name: "Yank" }).click(),
  ]);
  expect(request.method()).toBe("POST");

  await expect(page.getByText("Version yanked")).toBeVisible();
  // The refetched manifest flips 2.0.0's state badge to Yanked.
  await expect(
    versionsTable.getByRole("row").filter({ hasText: "2.0.0" }),
  ).toContainText("Yanked");

  await attachViewportScreenshot(page, testInfo, "assets-yank");
});

test("download issues a presigned GET for the exact version", async ({ page }, testInfo) => {
  await installGatewayAssets(page);
  await openDeployCliDetail(page);
  const detail = detailDialog(page);
  const versionsTable = detail.getByRole("table").nth(1);
  const activeRow = versionsTable.getByRole("row").filter({ hasText: "2.0.0" });

  // The download action GETs the versioned asset path (distinct from the DELETE
  // purge on the same path — asserted by method).
  const [request] = await Promise.all([
    page.waitForRequest((r) =>
      isGatewayRequest(r, "GET", "/v1/assets/cli_tool/deploy-cli/2.0.0"),
    ),
    activeRow.getByRole("button", { name: "Download" }).click(),
  ]);
  expect(request.method()).toBe("GET");

  await attachViewportScreenshot(page, testInfo, "assets-download");
});

test("permanent delete is gated behind a name@version-typed confirm dialog", async ({
  page,
}, testInfo) => {
  await installGatewayAssets(page);
  await openDeployCliDetail(page);
  const detail = detailDialog(page);
  const versionsTable = detail.getByRole("table").nth(1);
  const targetRow = versionsTable.getByRole("row").filter({ hasText: "1.5.0" });

  // No delete fires without an explicit, exactly-typed confirmation.
  let deleteRequested = false;
  await page.route(
    (url) => url.pathname === "/v1/assets/cli_tool/deploy-cli/1.5.0",
    async (route) => {
      if (route.request().method() === "DELETE") deleteRequested = true;
      await route.fallback();
    },
  );

  await targetRow.getByRole("button", { name: "Delete permanently" }).click();
  const deleteDialog = page
    .getByRole("dialog")
    .filter({ hasText: "Permanently delete deploy-cli@1.5.0?" });
  await expect(deleteDialog).toBeVisible();

  const confirmButton = deleteDialog.getByRole("button", { name: "Delete permanently" });
  // Disarmed on open, and a WRONG token keeps it disarmed (cannot delete).
  await expect(confirmButton).toBeDisabled();
  await deleteDialog.locator("#asset-delete-confirm").fill("deploy-cli@wrong");
  await expect(confirmButton).toBeDisabled();
  expect(deleteRequested).toBe(false);

  // The exact name@version identifier arms the destructive action.
  await deleteDialog.locator("#asset-delete-confirm").fill("deploy-cli@1.5.0");
  await expect(confirmButton).toBeEnabled();

  const [request] = await Promise.all([
    page.waitForRequest((r) =>
      isGatewayRequest(r, "DELETE", "/v1/assets/cli_tool/deploy-cli/1.5.0"),
    ),
    confirmButton.click(),
  ]);
  expect(request.method()).toBe("DELETE");

  await expect(page.getByText("Version permanently deleted")).toBeVisible();
  // The refetched manifest drops the purged version from the versions table.
  await expect(versionsTable.getByRole("row").filter({ hasText: "1.5.0" })).toHaveCount(0);

  await attachViewportScreenshot(page, testInfo, "assets-delete-confirm");
});

test("mobile viewport renders the registry and a lifecycle action without clipping", async ({
  page,
}, testInfo) => {
  await installGatewayAssets(page);
  await page.goto("/app/assets");

  // The registry list renders at every viewport (this case runs on mobile-390,
  // tablet-768, and desktop-1440) with no horizontal document overflow.
  await expect(page.getByRole("heading", { name: "Assets" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "deploy-cli" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "incident-tools" })).toBeVisible();
  await expectNoDocumentOverflow(page, testInfo);

  // A lifecycle surface (the detail dialog) is reachable and its primary action
  // sits within the viewport (not clipped off-screen).
  await openDeployCliDetail(page);
  const detail = detailDialog(page);
  const downloadButton = detail.getByRole("button", { name: "Download" }).first();
  await expect(downloadButton).toBeVisible();
  const box = await downloadButton.boundingBox();
  const viewport = page.viewportSize();
  expect(box).not.toBeNull();
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual((viewport?.width ?? 0) + 1);

  await attachViewportScreenshot(page, testInfo, "assets-mobile");
});

test.describe("partial errors", () => {
  // The forced 503 makes Chromium log a resource-load console error; tolerate it
  // so the partial-failure surface (not a blanked page) is what is under test.
  test.use({
    expectedConsoleErrors: [
      /Failed to load resource: the server responded with a status of 503/,
    ],
  });

  test("a failed storage-summary section stays a partial error and never blanks the registry", async ({
    page,
  }, testInfo) => {
    await installGatewayAssets(page, { failPaths: ["/v1/assets/storage/summary"] });
    await page.goto("/app/assets");

    // The failed section surfaces its own inline alert ...
    const storageAlert = page.getByRole("alert").filter({ hasText: "Failed to load storage usage" });
    await expect(storageAlert).toBeVisible();

    // ... while the healthy registry list stays fully populated (page not blanked).
    await expect(page.getByRole("heading", { name: "Assets" })).toBeVisible();
    await expect(page.getByRole("cell", { name: "deploy-cli" })).toBeVisible();
    await expect(page.getByRole("cell", { name: "incident-tools" })).toBeVisible();
    // The registry list request itself succeeds independently of the failed card.
    await expect(page.getByRole("row").filter({ hasText: "deploy-cli" })).toContainText("Bucket");

    await expectNoDocumentOverflow(page, testInfo);
    await attachViewportScreenshot(page, testInfo, "assets-partial-error");
  });
});
