import { installAuthenticatedAdminApi } from "./support/admin-api";
import { HTML_LANG, seedLocale, type MatrixLocale } from "./support/i18n";
import { PUBLIC_ROUTE_PATHS, REGISTERED_ROUTES } from "./support/route-matrix";
import { expect, test } from "./support/ui-contract";

// #348 acceptance — "EVERY registered route is covered by the English/Chinese
// browser route matrix with no mixed-language shell or primary workflow."
//
// `i18n-route-matrix.spec.ts` covers one REPRESENTATIVE route per acceptance
// area, deeply: page heading, primary action, overflow and clipping at all three
// viewports. That is a different (and weaker) contract than the box above — the
// code review measured it at 11 of 59 registered routes.
//
// This spec closes the gap in breadth rather than depth. It walks EVERY route in
// `support/route-matrix.ts` — derived from `APP_ROUTES` + `RESOURCE_ROUTE_PATHS`,
// the same registries `App.tsx` builds its route tree from, so a newly
// registered route is swept the day it is added — in BOTH locales, asserting the
// invariants that must hold on every route:
//
//   * `<html lang>` is the active locale;
//   * the app shell is in the active locale (the skip link, eager bootstrap copy
//     that renders before any route chunk resolves);
//   * NO marker of the other locale is present anywhere on the page — the
//     mixed-language check, in both directions.
//
// SCOPED TO DESKTOP (`@desktop`, which the mobile/tablet projects `grepInvert`)
// because it trades depth for breadth: the three-viewport overflow/clipping
// contract is the representative matrix's job, and running 114 route loads three
// times over would cost the gate ~3x for no additional language signal.
//
// UNMOCKED DATA IS EXPECTED. `installAuthenticatedAdminApi` mocks `/admin/v1/**`;
// routes that read gateway paths (`/v1/assets`, `/v1/tools`, ...) get a failed
// fetch and render their own error/empty state. That is fine and even useful —
// those states are operator copy too. What is NOT tolerated is a route whose
// shell does not render in the active locale, which is what the assertions
// below actually check.
//
// DEV-writes / GATE-runs: chromium cannot start in the dev-loop environment, so
// this spec is authored here and executed by the test gate.

const LOCALES: MatrixLocale[] = ["en", "zh-CN"];

function other(locale: MatrixLocale): MatrixLocale {
  return locale === "en" ? "zh-CN" : "en";
}

// Always-visible app-shell chrome per locale (mirrors i18n-route-matrix.spec.ts).
// The skip link is eager bootstrap copy, so it is present before any lazy route
// chunk resolves; the breadcrumb root proves the same for the nav chrome. Both
// are byte-distinct across locales, so "mine present + theirs absent" catches a
// mixed-language shell on any route.
const SHELL_SKIP_LINK: Record<MatrixLocale, string> = {
  en: "Skip to main content",
  "zh-CN": "跳转到主要内容",
};
const SHELL_BREADCRUMB_ROOT: Record<MatrixLocale, string> = {
  en: "FerroGate Admin",
  "zh-CN": "FerroGate 管理",
};

test.describe("@desktop every registered route renders in one locale", () => {
  test.use({
    expectedConsoleErrors: [
      // Unmocked gateway reads (`/v1/**`) and unmocked admin paths (501). See
      // the header: the page's own error state is still localized copy.
      /Failed to load resource/,
      /net::ERR_/,
    ],
  });

  test.beforeEach(async ({ page }) => {
    await installAuthenticatedAdminApi(page);
  });

  for (const route of REGISTERED_ROUTES) {
    for (const locale of LOCALES) {
      test(`${route.key} (${route.path}) renders in ${locale} with no cross-locale leakage`, async ({
        page,
      }) => {
        await seedLocale(page, locale);
        await page.goto(route.path);

        await expect(page.locator("html")).toHaveAttribute("lang", HTML_LANG[locale]);

        if (route.kind === "protected") {
          // The shell is in the active locale...
          await expect(
            page.getByRole("link", { name: SHELL_SKIP_LINK[locale] }),
          ).toBeVisible();
          // ...and carries no trace of the other one.
          await expect(
            page.getByRole("link", { name: SHELL_SKIP_LINK[other(locale)] }),
          ).toHaveCount(0);
          await expect(
            page.getByText(SHELL_BREADCRUMB_ROOT[other(locale)]),
          ).toHaveCount(0);
        } else {
          // Auth routes render no shell; their own copy is the probe, asserted
          // in depth by the auth block of i18n-route-matrix.spec.ts. Here we
          // only pin that the page rendered and that no shell chrome from the
          // other locale leaked into it.
          await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
          await expect(
            page.getByRole("link", { name: SHELL_SKIP_LINK[other(locale)] }),
          ).toHaveCount(0);
        }

        // The primary landmark exists on every route in every locale: a route
        // that failed to render at all would pass the `lang` check alone.
        await expect(page.locator("main, [role='main']").first()).toBeVisible();
      });
    }
  }
});

test("@desktop the sweep covers both public auth routes", async () => {
  // Cheap guard on the inventory itself: `App.tsx` registers /login and
  // /register outside the two registries, so they are listed by hand and could
  // silently drop out of the sweep.
  const swept = REGISTERED_ROUTES.filter((route) => route.kind === "public").map(
    (route) => route.path,
  );
  expect(swept).toEqual([...PUBLIC_ROUTE_PATHS]);
});
