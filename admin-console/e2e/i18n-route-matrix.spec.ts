import type { Locator, Page, TestInfo } from "@playwright/test";
import { installAuthenticatedAdminApi } from "./support/admin-api";
import {
  HTML_LANG,
  LOCALE_AUTONYM,
  type MatrixLocale,
  chooseLanguage,
  seedLocale,
} from "./support/i18n";
import {
  attachViewportScreenshot,
  expect,
  expectNoDocumentOverflow,
  test,
} from "./support/ui-contract";

// #348 acceptance — the BOTH-LOCALE Playwright route matrix.
//
// #346 landed the i18n runtime (provider, LanguageSwitcher, detection/persistence,
// typed en/zh-CN catalogs) and #348 finished migrating the ENTIRE operator copy
// onto that typed catalog (the `ferrogate/no-untranslated-literal` allowlist is
// EMPTY). What remained for #348 is the comprehensive browser route matrix in
// BOTH locales — authored here, RUN BY THE GATE. This spec runs across the three
// viewport PROJECTS in playwright.config.ts (390x844, 768x1024, 1440x900), so
// every representative route below is exercised at all three sizes in en AND
// zh-CN. For each it asserts:
//
//   * `document.documentElement.lang` matches the active locale;
//   * the shell / breadcrumb / primary page copy is in the expected language and
//     the OTHER locale's marker string is ABSENT (no mixed-language leakage);
//   * no document-level horizontal overflow and no clipped/overlapping primary
//     action (its box is non-zero and fully inside the viewport);
//   * identifiers / hashes / codes render byte-for-byte identically across a
//     real en -> zh-CN switch (a dedicated switch case below).
//
// It covers the acceptance surfaces: auth, dashboard, generic CRUD, a
// relationship form, guardrail/evidence, agent/worker, billing, ops, asset/site,
// dialogs, and mobile navigation — in both locales.
//
// DEV-writes / GATE-runs: chromium is not installed in the dev-loop environment,
// so this spec is authored here and executed by the test gate (which runs
// `npm run test:e2e:install` before `npm run test:e2e`). It is chromium-
// compatible and uses only web-first assertions (no hard sleeps).

const LOCALES: MatrixLocale[] = ["en", "zh-CN"];

function other(locale: MatrixLocale): MatrixLocale {
  return locale === "en" ? "zh-CN" : "en";
}

type LocalizedText = Record<MatrixLocale, string>;

// Always-visible app-shell chrome, in each locale. The skip link is eager
// bootstrap copy (renders synchronously, before any lazy route resolves), so it
// is a reliable "the shell is in language X" probe; the breadcrumb root proves
// the same for the navigation chrome. Both are byte-distinct across locales, so
// asserting one present + the other absent catches a mixed-language shell.
const SHELL_SKIP_LINK: LocalizedText = {
  en: "Skip to main content",
  "zh-CN": "跳转到主要内容",
};
const SHELL_BREADCRUMB_ROOT: LocalizedText = {
  en: "FerroGate Admin",
  "zh-CN": "FerroGate 管理",
};

/** Assert the active locale's `<html lang>` (a11y + `:lang()` CSS + `Intl`). */
async function expectHtmlLang(page: Page, locale: MatrixLocale): Promise<void> {
  await expect(page.locator("html")).toHaveAttribute("lang", HTML_LANG[locale]);
}

/**
 * Assert a primary action is neither clipped nor collapsed: it is visible, has a
 * non-zero box, and that box sits fully within the viewport horizontally. This
 * is the per-action complement to `expectNoDocumentOverflow` (document-level) and
 * catches a primary control pushed off the right edge or overlapped to 0 width by
 * a longer localized string.
 */
async function expectActionUnclipped(
  page: Page,
  action: Locator,
  testInfo: TestInfo,
): Promise<void> {
  await expect(action).toBeVisible();
  // Radix sheets/dialogs slide their content in (500ms), and `boundingBox()`
  // does not wait for animation stability, so an immediate read can catch the
  // action mid-flight outside the viewport. Wait until two consecutive reads
  // agree — the settled box — and hard-assert the overflow bounds on THAT.
  // A genuinely clipped action settles out of bounds and still fails below.
  let box = await action.boundingBox();
  await expect(async () => {
    const next = await action.boundingBox();
    const stable =
      box !== null &&
      next !== null &&
      Math.abs(next.x - box.x) < 0.5 &&
      Math.abs(next.y - box.y) < 0.5 &&
      Math.abs(next.width - box.width) < 0.5 &&
      Math.abs(next.height - box.height) < 0.5;
    box = next;
    if (!stable) throw new Error("action box still animating");
  }).toPass({ intervals: [100, 150, 250, 500], timeout: 5_000 });
  const viewport = page.viewportSize();
  const context = `${new URL(page.url()).pathname} @ ${testInfo.project.name}`;
  expect(box, `primary action has no box (${context})`).not.toBeNull();
  if (box && viewport) {
    expect(box.width, `primary action width (${context})`).toBeGreaterThan(0);
    expect(box.height, `primary action height (${context})`).toBeGreaterThan(0);
    expect(box.x, `primary action left edge (${context})`).toBeGreaterThanOrEqual(0);
    expect(
      box.x + box.width,
      `primary action right edge exceeds viewport (${context})`,
    ).toBeLessThanOrEqual(viewport.width + 1);
  }
}

// ---------------------------------------------------------------------------
// Public auth routes (login + register). No app shell; the page's own copy is
// the language probe. Login probes the session and 401s before sign-in.
// ---------------------------------------------------------------------------
test.describe("auth routes render fully in one locale", () => {
  test.use({
    expectedConsoleErrors: [/Failed to load resource: the server responded with a status of 401/],
  });

  const AUTH_ROUTES: {
    area: string;
    path: string;
    heading: LocalizedText;
    submit: LocalizedText;
  }[] = [
    {
      area: "auth-login",
      path: "/login",
      heading: { en: "FerroGate Admin Console", "zh-CN": "FerroGate 管理控制台" },
      submit: { en: "Sign in", "zh-CN": "登录" },
    },
    {
      area: "auth-register",
      path: "/register",
      heading: { en: "Create your organization", "zh-CN": "创建你的组织" },
      submit: { en: "Create organization", "zh-CN": "创建组织" },
    },
  ];

  for (const route of AUTH_ROUTES) {
    for (const locale of LOCALES) {
      test(`${route.area} renders in ${locale} with no cross-locale leakage`, async ({
        page,
      }, testInfo) => {
        await seedLocale(page, locale);
        await page.goto(route.path);

        await expectHtmlLang(page, locale);
        await expect(
          page.getByRole("heading", { level: 1, name: route.heading[locale] }),
        ).toBeVisible();
        const submit = page.getByRole("button", { name: route.submit[locale] });
        await expect(submit).toBeVisible();

        // No mixed language: the OTHER locale's heading + submit copy is absent.
        await expect(
          page.getByRole("heading", { level: 1, name: route.heading[other(locale)] }),
        ).toHaveCount(0);
        await expect(page.getByRole("button", { name: route.submit[other(locale)] })).toHaveCount(
          0,
        );

        await expectActionUnclipped(page, submit, testInfo);
        await expectNoDocumentOverflow(page, testInfo);
        await attachViewportScreenshot(page, testInfo, `${route.area}-${locale}`);
      });
    }
  }
});

// ---------------------------------------------------------------------------
// Protected route matrix — one representative route per acceptance area. Each is
// backed by the shared admin-API mock (`installAuthenticatedAdminApi`) exactly as
// the other protected specs are; only routes that mock cleanly are listed so an
// unmocked 501 never masquerades as a language failure.
// ---------------------------------------------------------------------------
test.describe("protected route matrix renders fully in one locale", () => {
  test.beforeEach(async ({ page }) => {
    await installAuthenticatedAdminApi(page);
  });

  const PROTECTED_ROUTES: {
    area: string;
    path: string;
    heading: LocalizedText;
    // Present only where the surface has an unambiguous localized primary action.
    primaryAction?: LocalizedText;
  }[] = [
    {
      area: "dashboard",
      path: "/app",
      heading: { en: "Operations overview", "zh-CN": "运维概览" },
    },
    {
      area: "crud-projects",
      path: "/app/projects",
      heading: { en: "Projects", "zh-CN": "项目" },
      primaryAction: { en: "New", "zh-CN": "新建" },
    },
    {
      area: "guardrail-evidence",
      path: "/app/guardrail-policies",
      heading: { en: "Guardrail policies", "zh-CN": "护栏策略" },
    },
    {
      area: "worker",
      path: "/app/self-hosted-workers",
      heading: { en: "Self-hosted workers", "zh-CN": "自托管工作节点" },
    },
    {
      area: "agent-tools",
      path: "/app/mcp-servers",
      heading: { en: "MCP servers", "zh-CN": "MCP 服务器" },
    },
    {
      area: "billing",
      path: "/app/billing-events",
      heading: { en: "Billing events", "zh-CN": "计费事件" },
    },
    {
      area: "ops",
      path: "/app/ops/status",
      heading: { en: "Ops status", "zh-CN": "运维状态" },
    },
    {
      area: "asset-site",
      path: "/app/site-domains",
      heading: { en: "Site domains", "zh-CN": "站点域名" },
    },
    {
      area: "logs",
      path: "/app/request-logs",
      heading: { en: "Request logs", "zh-CN": "请求日志" },
    },
  ];

  for (const route of PROTECTED_ROUTES) {
    for (const locale of LOCALES) {
      test(`${route.area} renders in ${locale} with localized shell + no leakage`, async ({
        page,
      }, testInfo) => {
        await seedLocale(page, locale);
        await page.goto(route.path);

        await expectHtmlLang(page, locale);

        // Eager shell chrome is in the active locale; the other locale's chrome
        // copy is absent (no mixed-language shell / breadcrumb).
        await expect(page.getByRole("link", { name: SHELL_SKIP_LINK[locale] })).toBeVisible();
        await expect(page.getByRole("link", { name: SHELL_SKIP_LINK[other(locale)] })).toHaveCount(
          0,
        );
        await expect(page.getByText(SHELL_BREADCRUMB_ROOT[other(locale)])).toHaveCount(0);

        // Lazy page copy resolves to the active locale (poll for it), and the
        // other locale's page heading never appears (its chunk is never loaded
        // for this session).
        await expect(
          page.getByRole("heading", { level: 1, name: route.heading[locale] }),
        ).toBeVisible();
        await expect(
          page.getByRole("heading", { level: 1, name: route.heading[other(locale)] }),
        ).toHaveCount(0);

        if (route.primaryAction) {
          const action = page.getByRole("button", { name: route.primaryAction[locale] });
          await expectActionUnclipped(page, action, testInfo);
          await expect(
            page.getByRole("button", { name: route.primaryAction[other(locale)] }),
          ).toHaveCount(0);
        }

        await expectNoDocumentOverflow(page, testInfo);
        await attachViewportScreenshot(page, testInfo, `${route.area}-${locale}`);
      });
    }
  }
});

// ---------------------------------------------------------------------------
// Relationship form + create DIALOG (generated forms). Opens the Projects create
// dialog — a single-entity reference (tenant) picker — and asserts its field
// label and its primary/secondary actions localize with no leakage, and that the
// primary action is unclipped inside the dialog.
// ---------------------------------------------------------------------------
test.describe("relationship form + create dialog localize", () => {
  test.beforeEach(async ({ page }) => {
    await installAuthenticatedAdminApi(page);
  });

  const NEW_ACTION: LocalizedText = { en: "New", "zh-CN": "新建" };
  const PROJECTS_TITLE: LocalizedText = { en: "Projects", "zh-CN": "项目" };
  const TENANT_FIELD: LocalizedText = { en: "Tenant *", "zh-CN": "租户 *" };
  const CREATE_ACTION: LocalizedText = { en: "Create", "zh-CN": "创建" };
  const CANCEL_ACTION: LocalizedText = { en: "Cancel", "zh-CN": "取消" };

  for (const locale of LOCALES) {
    test(`projects create dialog + tenant picker localize in ${locale}`, async ({
      page,
    }, testInfo) => {
      await seedLocale(page, locale);
      await page.goto("/app/projects");
      await expect(
        page.getByRole("heading", { level: 1, name: PROJECTS_TITLE[locale] }),
      ).toBeVisible();

      await page.getByRole("button", { name: NEW_ACTION[locale] }).click();
      const dialog = page.getByRole("dialog");
      await expect(dialog).toBeVisible();

      // The relationship (entity-reference) field label localizes, keeping the
      // required marker.
      await expect(dialog.getByRole("combobox", { name: TENANT_FIELD[locale] })).toBeVisible();

      // Primary (submit) + secondary (cancel) actions localize; the other
      // locale's submit label is absent inside the dialog.
      const create = dialog.getByRole("button", { name: CREATE_ACTION[locale] });
      await expect(create).toBeVisible();
      await expect(dialog.getByRole("button", { name: CANCEL_ACTION[locale] })).toBeVisible();
      await expect(dialog.getByRole("button", { name: CREATE_ACTION[other(locale)] })).toHaveCount(
        0,
      );

      await expectActionUnclipped(page, create, testInfo);
      await expectNoDocumentOverflow(page, testInfo);
      await attachViewportScreenshot(page, testInfo, `create-dialog-${locale}`);
    });
  }
});

// ---------------------------------------------------------------------------
// Mobile navigation sheet (mobile-390 project only). Opens the sidebar sheet and
// asserts the nav dialog + a nav GROUP label are in the active locale with no
// leakage. On tablet/desktop the sidebar is persistent (no sheet), so this case
// is scoped to the mobile viewport.
// ---------------------------------------------------------------------------
test.describe("mobile navigation sheet localizes", () => {
  test.beforeEach(async ({ page }) => {
    await installAuthenticatedAdminApi(page);
  });

  const TOGGLE: LocalizedText = { en: "Toggle Sidebar", "zh-CN": "切换侧边栏" };
  const SIDEBAR_DIALOG: LocalizedText = { en: "Sidebar", "zh-CN": "侧边栏" };
  const ORG_GROUP: LocalizedText = { en: "Organization", "zh-CN": "组织" };

  for (const locale of LOCALES) {
    test(`sidebar sheet chrome + nav group localize in ${locale}`, async ({ page }, testInfo) => {
      test.skip(
        testInfo.project.name !== "mobile-390",
        "mobile navigation sheet only exists at the mobile viewport",
      );
      await seedLocale(page, locale);
      await page.goto("/app");
      await expectHtmlLang(page, locale);

      const trigger = page.getByRole("button", { name: TOGGLE[locale] });
      await trigger.focus();
      await page.keyboard.press("Enter");

      const sheet = page.getByRole("dialog", { name: SIDEBAR_DIALOG[locale] });
      await expect(sheet).toBeVisible();
      // Nav group label (a collapsible group trigger) is in the active locale;
      // the other locale's label is absent from the sheet (no mixed-language nav).
      await expect(sheet.getByRole("button", { name: ORG_GROUP[locale] })).toBeVisible();
      await expect(sheet.getByRole("button", { name: ORG_GROUP[other(locale)] })).toHaveCount(0);

      await expectNoDocumentOverflow(page, testInfo);
      await attachViewportScreenshot(page, testInfo, `mobile-nav-${locale}`);
    });
  }
});

// ---------------------------------------------------------------------------
// Identifier stability across a REAL locale switch. On the request-logs surface
// the request_id is a copyable identifier: its full value is the element `title`
// and its visible text is a deterministic truncation — neither is locale-derived.
// Switching en -> zh-CN localizes the shell + page heading while the identifier
// stays byte-for-byte identical.
// ---------------------------------------------------------------------------
test("identifiers stay byte-for-byte identical across an en -> zh-CN switch", async ({
  page,
}, testInfo) => {
  await installAuthenticatedAdminApi(page);
  await seedLocale(page, "en");
  await page.goto("/app/request-logs");

  await expect(page.getByRole("heading", { level: 1, name: "Request logs" })).toBeVisible();

  // The request_id copyable: the full identifier lives in `title`; the visible
  // text is `TruncatedCopyable`'s deterministic prefix + ellipsis.
  const IDENTIFIER = "req-dashboard-success";
  const idBefore = page.locator(`[title="${IDENTIFIER}"]`);
  await expect(idBefore).toHaveCount(1);
  const visibleBefore = (await idBefore.textContent())?.trim();
  const titleBefore = await idBefore.getAttribute("title");
  expect(titleBefore).toBe(IDENTIFIER);

  await chooseLanguage(page, LOCALE_AUTONYM["zh-CN"]);

  // The switch localized the shell + heading (proving the locale really changed)
  await expectHtmlLang(page, "zh-CN");
  await expect(page.getByRole("heading", { level: 1, name: "请求日志" })).toBeVisible();

  // ... while the identifier is byte-for-byte unchanged: same count, same
  // visible text, same full title value.
  const idAfter = page.locator(`[title="${IDENTIFIER}"]`);
  await expect(idAfter).toHaveCount(1);
  expect((await idAfter.textContent())?.trim()).toBe(visibleBefore);
  expect(await idAfter.getAttribute("title")).toBe(titleBefore);

  await expectNoDocumentOverflow(page, testInfo);
  await attachViewportScreenshot(page, testInfo, "identifier-stability-switch");
});
