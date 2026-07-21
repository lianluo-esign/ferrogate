import { installAuthenticatedAdminApi } from "./support/admin-api";
import { expect, test } from "./support/ui-contract";

test("@desktop public auth routes do not request protected page modules", async ({ page }) => {
  const pageModules: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/src/pages/")) pageModules.push(url.pathname);
  });

  const authRoutes = [
    { path: "/login", module: "/src/pages/login.tsx", heading: "FerroGate Admin Console" },
    {
      path: "/register",
      module: "/src/pages/register.tsx",
      heading: "Create your organization",
    },
  ];

  for (const routeCase of authRoutes) {
    pageModules.length = 0;
    await page.goto(routeCase.path);
    await expect(page.getByRole("heading", { name: routeCase.heading })).toBeVisible();
    expect(pageModules).toContain(routeCase.module);
    expect(pageModules.filter((module) => module !== routeCase.module)).toEqual([]);
  }
});

test.describe("authenticated lazy routes", () => {
  test.beforeEach(async ({ page }) => {
    await installAuthenticatedAdminApi(page);
  });

  test("@desktop direct deep links preserve the shell while feature modules load", async ({
    page,
  }) => {
    const routes = [
      { path: "/app/projects", module: "resource-route", heading: "Projects" },
      {
        path: "/app/guardrail-policies",
        module: "guardrail-policies",
        heading: "Guardrail policies",
      },
      { path: "/app/wallets", module: "billing-wallets", heading: "Wallets" },
      { path: "/app/ops/status", module: "ops-status", heading: "Ops status" },
    ];

    for (const routeCase of routes) {
      const pattern = `**/src/pages/${routeCase.module}.tsx*`;
      await page.route(pattern, async (route) => {
        await new Promise((resolve) => setTimeout(resolve, 250));
        await route.continue();
      });
      await page.goto(routeCase.path);
      await expect(page.getByRole("status")).toHaveText("Loading page…");
      await expect(page.getByRole("heading", { level: 1, name: routeCase.heading })).toBeVisible();
      await expect(page.getByRole("link", { name: /FerroGate Admin Console/ })).toBeVisible();
      await page.unroute(pattern);
    }
  });

  test("@desktop client navigation loads a route without reloading the document", async ({
    page,
  }) => {
    let documentRequests = 0;
    page.on("request", (request) => {
      if (request.resourceType() === "document") documentRequests += 1;
    });

    await page.goto("/app");
    await expect(page.getByRole("heading", { name: "Operations overview" })).toBeVisible();
    await page.getByRole("button", { name: "Operations", exact: true }).click();
    await page.getByRole("link", { name: "System Status" }).click();
    await expect(page.getByRole("heading", { name: "Ops status" })).toBeVisible();
    expect(documentRequests).toBe(1);
  });
});

test.describe("route module failure", () => {
  test.use({
    expectedConsoleErrors: [
      /Failed to load resource: net::ERR_FAILED|Failed to fetch dynamically imported module|Route module failed to load|The above error occurred in one of your React components/,
    ],
    expectedPageErrors: [/Failed to fetch dynamically imported module/],
  });

  test("@desktop exposes a reload path and recovers after a transient chunk failure", async ({
    page,
  }) => {
    await installAuthenticatedAdminApi(page);
    let failedOnce = false;
    await page.route("**/src/pages/ops-config.tsx*", async (route) => {
      if (!failedOnce) {
        failedOnce = true;
        await route.abort("failed");
        return;
      }
      await route.continue();
    });

    await page.goto("/app/ops/config");
    await expect(page.getByRole("heading", { name: "Page failed to load" })).toBeVisible();
    await expect(page.getByRole("alert")).toContainText("could not be downloaded");
    await page.getByRole("button", { name: "Reload page" }).click();
    await expect(page.getByRole("heading", { name: "Config validate & reload" })).toBeVisible();
  });
});
