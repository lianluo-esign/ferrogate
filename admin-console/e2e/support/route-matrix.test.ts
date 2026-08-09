import { APP_ROUTES } from "@/lib/app-routes";
import { RESOURCE_ROUTE_PATHS } from "@/resources/route-paths";
// The route sweep's coverage claim, checked WITHOUT a browser.
//
// `i18n-route-sweep.spec.ts` asserts the #348 box "every registered route is
// covered by the English/Chinese browser route matrix". That claim is only as
// good as the inventory it loops over — and the inventory is the thing a future
// route can quietly fall out of. These tests pin it: they compare the derived
// inventory against the two registries `App.tsx` actually builds its route tree
// from, so an unswept route fails `npx vitest run` on the machine that added it,
// long before the chromium pass runs.
import { describe, expect, it } from "vitest";
import {
  PROTECTED_ROUTES,
  PUBLIC_ROUTE_PATHS,
  REGISTERED_ROUTES,
  ROUTE_PARAM_SAMPLES,
  resolveRoutePath,
} from "./route-matrix";

describe("i18n route-sweep inventory", () => {
  it("covers every registered route template, from both registries", () => {
    const registered = [
      ...PUBLIC_ROUTE_PATHS,
      ...Object.values(APP_ROUTES),
      ...Object.values(RESOURCE_ROUTE_PATHS),
    ].sort();
    expect(REGISTERED_ROUTES.map((route) => route.template).sort()).toEqual(registered);
  });

  it("visits a concrete path for every route — no unsubstituted parameter", () => {
    for (const route of REGISTERED_ROUTES) {
      expect(route.path, `${route.key} still contains a :param`).not.toMatch(/\/:/);
      expect(route.path.startsWith("/"), `${route.key} is not an absolute path`).toBe(true);
    }
  });

  it("refuses to invent a value for an unknown route parameter", () => {
    // The alternative — leaving `:thing` in the URL, or dropping the route —
    // is exactly the silent coverage gap this inventory exists to prevent.
    expect(() => resolveRoutePath("/app/widgets/:widgetId")).toThrow(/widgetId/);
  });

  it("keeps a sample for every parameter the registries actually use", () => {
    const used = new Set<string>();
    for (const template of Object.values(APP_ROUTES)) {
      for (const segment of template.split("/")) {
        if (segment.startsWith(":")) used.add(segment.slice(1));
      }
    }
    expect([...used].sort()).toEqual(Object.keys(ROUTE_PARAM_SAMPLES).sort());
  });

  it("classifies exactly the auth routes as public and everything else as shell-bearing", () => {
    const publicPaths = REGISTERED_ROUTES.filter((r) => r.kind === "public").map((r) => r.path);
    expect(publicPaths).toEqual([...PUBLIC_ROUTE_PATHS]);
    expect(PROTECTED_ROUTES).toHaveLength(
      Object.keys(APP_ROUTES).length + Object.keys(RESOURCE_ROUTE_PATHS).length,
    );
    for (const route of PROTECTED_ROUTES) {
      expect(route.path.startsWith("/app"), `${route.key} is not under /app`).toBe(true);
    }
  });
});
