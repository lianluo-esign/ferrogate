import { installAuthenticatedAdminApi } from "./support/admin-api";
import { chooseLanguage, LOCALE_STORAGE_KEY } from "./support/i18n";
import {
  attachViewportScreenshot,
  expect,
  expectNoAxeViolations,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

// #346 acceptance — language switching (auth + one protected route).
//
// Proves en <-> zh-CN is selectable BEFORE and AFTER auth, updates html[lang]
// immediately, persists a validated code, and — crucially — does NOT trigger a
// full document reload or reset route/form state. A `window` sentinel and a typed
// form value are used as reload/state tripwires: a real reload clears both.
//
// DEV-writes / GATE-runs: chromium is not installed in the dev-loop environment,
// so this spec is authored here and executed by the test gate, which runs
// `npm run test:e2e:install` before `npm run test:e2e`. It is chromium-compatible
// and uses only web-first assertions (no hard sleeps).

type ReloadSentinel = { __i18nNoReload?: boolean };

async function plantReloadSentinel(page: import("@playwright/test").Page): Promise<void> {
  await page.evaluate(() => {
    (window as unknown as ReloadSentinel).__i18nNoReload = true;
  });
}

async function reloadSentinelSurvived(page: import("@playwright/test").Page): Promise<boolean> {
  return page.evaluate(() => (window as unknown as ReloadSentinel).__i18nNoReload === true);
}

test.describe("language switch on an auth page", () => {
  // The public login route probes the session and gets a 401 before sign-in.
  test.use({
    expectedConsoleErrors: [/Failed to load resource: the server responded with a status of 401/],
  });

  test("switches en -> zh-CN in place, updating html[lang] and preserving form state", async ({
    page,
  }, testInfo) => {
    await page.goto("/login");

    const html = page.locator("html");
    await expect(html).toHaveAttribute("lang", "en");
    await expect(
      page.getByRole("heading", { level: 1, name: "FerroGate Admin Console" }),
    ).toBeVisible();
    await expect(page.getByLabel("Email")).toBeVisible();
    await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();

    // Type into the form and plant a window sentinel; a full document reload would
    // clear BOTH. Switching locale must preserve them.
    await page.getByLabel("Email").fill("operator@example.com");
    await plantReloadSentinel(page);
    const urlBefore = page.url();

    await chooseLanguage(page, "简体中文");

    // html[lang] flips immediately and the visible copy is now Simplified Chinese.
    await expect(html).toHaveAttribute("lang", "zh-CN");
    await expect(
      page.getByRole("heading", { level: 1, name: "FerroGate 管理控制台" }),
    ).toBeVisible();
    await expect(page.getByLabel("邮箱")).toBeVisible();
    await expect(page.getByRole("button", { name: "登录" })).toBeVisible();

    // No full reload: the window sentinel survived, the route did not change, and
    // the typed form value is intact (state was not reset).
    expect(await reloadSentinelSurvived(page)).toBe(true);
    await expect(page).toHaveURL(urlBefore);
    await expect(page.getByLabel("邮箱")).toHaveValue("operator@example.com");

    // Only a validated locale code is persisted, under the versioned key.
    await expect
      .poll(() => page.evaluate((key) => localStorage.getItem(key), LOCALE_STORAGE_KEY))
      .toBe("zh-CN");

    await expectNoDocumentOverflow(page, testInfo);
    await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);
    await attachViewportScreenshot(page, testInfo, "language-switch-auth");
  });
});

test.describe("language switch on a protected route", () => {
  test.beforeEach(async ({ page }) => {
    await installAuthenticatedAdminApi(page);
  });

  test("switches en -> zh-CN without leaving the route or reloading", async ({
    page,
  }, testInfo) => {
    await page.goto("/app");

    const html = page.locator("html");
    await expect(html).toHaveAttribute("lang", "en");
    await expect(page.getByRole("heading", { name: "Operations overview" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Skip to main content" })).toBeVisible();

    await plantReloadSentinel(page);
    const urlBefore = page.url();

    await chooseLanguage(page, "简体中文");

    // Eager chrome copy (the skip link) flips immediately; the lazily loaded
    // dashboard namespace resolves to its Simplified Chinese heading.
    await expect(html).toHaveAttribute("lang", "zh-CN");
    await expect(page.getByRole("link", { name: "跳转到主要内容" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "运维概览" })).toBeVisible();

    // No reload (sentinel intact) and no route reset (same URL, still mounted on
    // the protected shell): the switch never navigated.
    expect(await reloadSentinelSurvived(page)).toBe(true);
    await expect(page).toHaveURL(urlBefore);

    await expectNoDocumentOverflow(page, testInfo);
    await expectNoAxeViolations(page, testInfo, ["critical", "serious"]);
    await attachViewportScreenshot(page, testInfo, "language-switch-protected");
  });
});
