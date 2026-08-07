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
  expectNoAxeViolations,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

function isGatewayRequest(request: Request, method: string, pathname: string): boolean {
  return request.method() === method && new URL(request.url()).pathname === pathname;
}

/**
 * One logical-resource record in the registry list, at any viewport.
 *
 * The list renders through the shared responsive data surface from #336
 * (components/resource/resource-table.tsx): a <table> row at desktop-1440 and a
 * `data-compact-records` <article> card at mobile-390 / tablet-768. Matching
 * either keeps these assertions viewport-agnostic instead of pinning them to
 * the desktop table (which is what made the previous mobile case assert a
 * `cell` role that a compact surface would never have).
 */
function registryRecord(page: Page, name: string) {
  return page
    .locator("tr, [data-compact-records] > article")
    .filter({ hasText: name });
}

/** The detail dialog, anchored on copy unique to it (never the confirm dialogs). */
function detailDialog(page: Page) {
  return page.getByRole("dialog").filter({ hasText: "Registry manifest" });
}

/** Opens deploy-cli's registry detail dialog and waits for the manifest to load. */
async function openDeployCliDetail(page: Page): Promise<void> {
  await page.goto("/app/assets");
  await expect(page.getByRole("heading", { name: "Assets" })).toBeVisible();
  const row = registryRecord(page, "deploy-cli").first();
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
  // Scoped to the announced role="status" node: the disabled submit button
  // legitimately mirrors the same phase label as its busy state, so an
  // unscoped text match resolves to two correct nodes.
  await expect(
    page.getByRole("status").filter({ hasText: "Uploading to storage" }),
  ).toBeVisible();
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
  // 1.2.0 is the version NO channel points at: the gateway rejects a yank while
  // a channel still references the version (#367), so a green yank has to
  // target an unreferenced one.
  const activeRow = versionsTable.getByRole("row").filter({ hasText: "1.2.0" }).first();

  await activeRow.getByRole("button", { name: "Yank" }).click();
  // A consequence-aware confirm names the exact resource before firing.
  const confirm = page.getByRole("dialog", { name: "Yank cli_tool/deploy-cli@1.2.0?" });
  await expect(confirm).toBeVisible();
  // No channel references it, so no blocker is claimed.
  await expect(confirm.getByRole("alert")).toHaveCount(0);

  const [request] = await Promise.all([
    page.waitForRequest((r) =>
      isGatewayRequest(r, "POST", "/v1/assets/cli_tool/deploy-cli/1.2.0/yank"),
    ),
    confirm.getByRole("button", { name: "Yank" }).click(),
  ]);
  expect(request.method()).toBe("POST");

  await expect(page.getByText("Version yanked")).toBeVisible();
  // The refetched manifest flips 1.2.0's state badge to Yanked.
  await expect(
    versionsTable.getByRole("row").filter({ hasText: "1.2.0" }).first(),
  ).toContainText("Yanked");

  await attachViewportScreenshot(page, testInfo, "assets-yank");
});

test("download issues a presigned GET for the exact version", async ({ page }, testInfo) => {
  await installGatewayAssets(page);
  await openDeployCliDetail(page);
  const detail = detailDialog(page);
  const versionsTable = detail.getByRole("table").nth(1);
  // deploy-cli@2.0.0 carries TWO variants, so it renders two rows; the
  // linux-arm64 one is only reachable because Download is now per-variant.
  const arm64Row = versionsTable.getByRole("row").filter({ hasText: "linux-arm64" });

  // The download action GETs the versioned asset path (distinct from the DELETE
  // purge on the same path — asserted by method) and selects the variant with
  // the `platform` query parameter the contract documents.
  const [request] = await Promise.all([
    page.waitForRequest((r) =>
      isGatewayRequest(r, "GET", "/v1/assets/cli_tool/deploy-cli/2.0.0"),
    ),
    arm64Row.getByRole("button", { name: "Download" }).click(),
  ]);
  expect(request.method()).toBe("GET");
  expect(new URL(request.url()).searchParams.get("platform")).toBe("linux-arm64");

  await attachViewportScreenshot(page, testInfo, "assets-download");
});

test("permanent delete is gated behind a name@version-typed confirm dialog", async ({
  page,
}, testInfo) => {
  await installGatewayAssets(page);
  await openDeployCliDetail(page);
  const detail = detailDialog(page);
  const versionsTable = detail.getByRole("table").nth(1);
  const targetRow = versionsTable.getByRole("row").filter({ hasText: "1.2.0" }).first();

  // No delete fires without an explicit, exactly-typed confirmation.
  let deleteRequested = false;
  await page.route(
    (url) => url.pathname === "/v1/assets/cli_tool/deploy-cli/1.2.0",
    async (route) => {
      if (route.request().method() === "DELETE") deleteRequested = true;
      await route.fallback();
    },
  );

  await targetRow.getByRole("button", { name: "Delete permanently" }).click();
  const deleteDialog = page
    .getByRole("dialog")
    .filter({ hasText: "Permanently delete deploy-cli@1.2.0?" });
  await expect(deleteDialog).toBeVisible();

  const confirmButton = deleteDialog.getByRole("button", { name: "Delete permanently" });
  // Disarmed on open, and a WRONG token keeps it disarmed (cannot delete).
  await expect(confirmButton).toBeDisabled();
  await deleteDialog.locator("#asset-delete-confirm").fill("deploy-cli@wrong");
  await expect(confirmButton).toBeDisabled();
  expect(deleteRequested).toBe(false);

  // The exact name@version identifier arms the destructive action.
  await deleteDialog.locator("#asset-delete-confirm").fill("deploy-cli@1.2.0");
  await expect(confirmButton).toBeEnabled();

  const [request] = await Promise.all([
    page.waitForRequest((r) =>
      isGatewayRequest(r, "DELETE", "/v1/assets/cli_tool/deploy-cli/1.2.0"),
    ),
    confirmButton.click(),
  ]);
  expect(request.method()).toBe("DELETE");

  await expect(page.getByText("Version permanently deleted")).toBeVisible();
  // The refetched manifest drops the purged version from the versions table.
  await expect(versionsTable.getByRole("row").filter({ hasText: "1.2.0" })).toHaveCount(0);

  await attachViewportScreenshot(page, testInfo, "assets-delete-confirm");
});

test.describe("channel-blocked delete", () => {
  // The mock's 409 rejection makes Chromium log a resource-load console error;
  // tolerate exactly that so the on-screen verdict (not a silent failure) is
  // what is under test.
  test.use({
    expectedConsoleErrors: [
      /Failed to load resource: the server responded with a status of 409/,
    ],
  });

  test("permanent delete names the channel blocker and keeps the 409 verdict on screen", async ({
    page,
  }, testInfo) => {
  // #367: removing the last resolvable variant of a channel-referenced version
  // is rejected with 409 asset_version_referenced, and the mock now models
  // that. `stable` points at 1.5.0, whose only variant is the default one.
  await installGatewayAssets(page);
  await openDeployCliDetail(page);
  const detail = detailDialog(page);
  const versionsTable = detail.getByRole("table").nth(1);
  const targetRow = versionsTable.getByRole("row").filter({ hasText: "1.5.0" }).first();

  await targetRow.getByRole("button", { name: "Delete permanently" }).click();
  const deleteDialog = page
    .getByRole("dialog")
    .filter({ hasText: "Permanently delete deploy-cli@1.5.0?" });

  // The blocker is named BEFORE anything destructive fires.
  const blocker = deleteDialog.getByRole("alert").first();
  await expect(blocker).toContainText("stable");
  await expect(blocker).toContainText("asset_version_referenced");

  // Proceeding surfaces the gateway's verdict IN the dialog, verbatim — not as
  // a toast that fades before the operator can read the remedy.
  await deleteDialog.locator("#asset-delete-confirm").fill("deploy-cli@1.5.0");
  await Promise.all([
    page.waitForRequest((r) =>
      isGatewayRequest(r, "DELETE", "/v1/assets/cli_tool/deploy-cli/1.5.0"),
    ),
    deleteDialog.getByRole("button", { name: "Delete permanently" }).click(),
  ]);
  await expect(deleteDialog).toContainText("move or delete the channel first");
  // Still on screen, and the version was NOT removed from the table. While the
  // modal confirm is open Radix aria-hides the detail dialog underneath it, so
  // role-based queries cannot see the versions table even though it is still
  // rendered on screen — assert through the DOM (CSS) instead.
  await expect(deleteDialog).toBeVisible();
  const backgroundVersionsTable = page
    .locator('[role="dialog"]')
    .filter({ hasText: "Registry manifest" })
    .locator("table")
    .nth(1);
  await expect(
    backgroundVersionsTable.locator("tr").filter({ hasText: "1.5.0" }).first(),
  ).toBeVisible();

  await attachViewportScreenshot(page, testInfo, "assets-delete-blocked");
  });
});

test("cancelling a large-object upload stops it and never reads as published", async ({
  page,
}, testInfo) => {
  // Hold the direct-to-bucket PUT so Cancel lands mid-transfer.
  await installGatewayAssets(page, { uploadHoldMs: 5_000 });
  await page.goto("/app/assets");

  await page.getByRole("button", { name: "Upload large object" }).click();
  const dialog = page.getByRole("dialog").filter({ hasText: "Large-object upload" });
  await dialog.locator("#presign-asset-name").fill("cancelled-bundle");
  await dialog.locator("#presign-asset-version").fill("4.0.0");
  await dialog.locator("#presign-asset-file").setInputFiles({
    name: "cancelled-bundle.tar.gz",
    mimeType: "application/gzip",
    buffer: Buffer.alloc(4096, 3),
  });

  const abortPromise = page.waitForRequest((request) =>
    isGatewayRequest(
      request,
      "POST",
      "/v1/assets/presign/abort/cli_tool/cancelled-bundle/4.0.0",
    ),
  );
  let commitSeen = false;
  page.on("request", (request) => {
    if (
      isGatewayRequest(
        request,
        "POST",
        "/v1/assets/presign/commit/cli_tool/cancelled-bundle/4.0.0",
      )
    ) {
      commitSeen = true;
    }
  });

  await dialog.getByRole("button", { name: "Upload large object" }).click();
  // role="status" scope for the same reason as the upload case above: the
  // disabled submit button mirrors the phase label as its busy state.
  await expect(
    page.getByRole("status").filter({ hasText: "Uploading to storage" }),
  ).toBeVisible();

  // Cancel is a REAL, enabled action mid-flight, not a greyed-out placeholder.
  const cancel = dialog.getByRole("button", { name: "Cancel upload" });
  await expect(cancel).toBeEnabled();
  await cancel.click();

  // The staged intent is released rather than left holding bucket capacity...
  const abortRequest = await abortPromise;
  expect(abortRequest.postDataJSON()).toMatchObject({ reason: "abandoned" });

  // ...and the outcome reads as a cancellation that explicitly denies a publish.
  await expect(dialog.getByRole("alert")).toContainText("Nothing was published");
  await expect(page.getByText("Large object committed")).toHaveCount(0);
  expect(commitSeen).toBe(false);

  await attachViewportScreenshot(page, testInfo, "assets-upload-cancelled");
});

test("@desktop the registry and its detail dialog pass serious axe checks", async ({
  page,
}, testInfo) => {
  // #331 reuse: the axe half of the quality gate. The registry never ran it, so
  // its bespoke tables, meters and confirm dialogs were unchecked.
  await installGatewayAssets(page);
  await page.goto("/app/assets");
  await expect(page.getByRole("heading", { name: "Assets" })).toBeVisible();
  await expect(registryRecord(page, "deploy-cli").first()).toBeVisible();
  await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);

  // The detail dialog is the page's densest surface; check it open too.
  await openDeployCliDetail(page);
  await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);
});

test("mobile viewport renders the registry and a lifecycle action without clipping", async ({
  page,
}, testInfo) => {
  await installGatewayAssets(page);
  await page.goto("/app/assets");

  // The registry list renders at every viewport (this case runs on mobile-390,
  // tablet-768, and desktop-1440) with no horizontal document overflow.
  await expect(page.getByRole("heading", { name: "Assets" })).toBeVisible();
  await expect(registryRecord(page, "deploy-cli").first()).toBeVisible();
  await expect(registryRecord(page, "incident-tools").first()).toBeVisible();
  await expectNoDocumentOverflow(page, testInfo);

  // #336 reuse: below the desktop breakpoint the list IS the shared compact
  // record surface, not a raw multi-column table, and its row action meets the
  // 44px touch target the responsive contract requires elsewhere.
  if (testInfo.project.name === "desktop-1440") {
    await expect(page.locator("table").first()).toBeVisible();
  } else {
    await expect(page.locator("[data-compact-records]")).toBeVisible();
    const action = registryRecord(page, "deploy-cli")
      .first()
      .getByRole("button", { name: "More details" });
    const actionBox = await action.boundingBox();
    expect(actionBox?.height).toBeGreaterThanOrEqual(44);
  }

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
    await expect(registryRecord(page, "deploy-cli").first()).toBeVisible();
    await expect(registryRecord(page, "incident-tools").first()).toBeVisible();
    // The registry list request itself succeeds independently of the failed card.
    await expect(registryRecord(page, "deploy-cli").first()).toContainText("Bucket");

    await expectNoDocumentOverflow(page, testInfo);
    await attachViewportScreenshot(page, testInfo, "assets-partial-error");
  });
});
