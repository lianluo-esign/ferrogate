// The route sweep's coverage claim, checked WITHOUT a browser.
//
// `i18n-route-sweep.spec.ts` asserts the #348 box "every registered route is
// covered by the English/Chinese browser route matrix". That claim is only as
// good as the inventory it loops over — and the inventory is the thing a future
// route can quietly fall out of.
//
// These tests pin it against `src/App.tsx` ITSELF, not against the registries the
// inventory is built from. Comparing the inventory to `APP_ROUTES` +
// `RESOURCE_ROUTE_PATHS` is a tautology — both sides are the same expression, so
// a hard-coded `<Route path="/app/mutant" …>` in `App.tsx` stays green. Reading
// the router's own bindings (`app-route-bindings.ts`) makes that mutation fail
// `npx vitest run` on the machine that added it, long before the chromium pass.
import { describe, expect, it } from "vitest";
import { APP_ROUTES } from "@/lib/app-routes";
import { RESOURCE_ROUTE_PATHS } from "@/resources/route-paths";
import {
  ALLOWED_LITERAL_PATHS,
  boundRouteTemplates,
  parseRouteBindings,
  readAppSource,
  resourceSpreadParam,
  unregisteredLiteralBindings,
} from "./app-route-bindings";
import {
  PROTECTED_ROUTES,
  PUBLIC_ROUTE_PATHS,
  REGISTERED_ROUTES,
  resolveRoutePath,
  ROUTE_PARAM_SAMPLES,
} from "./route-matrix";

describe("i18n route-sweep inventory", () => {
  it("covers every route App.tsx actually binds", () => {
    // The one assertion that is NOT circular: the right-hand side is read out of
    // the router source, so a route bound there and missing from the inventory
    // (or vice versa) fails here.
    const bound = boundRouteTemplates(readAppSource()).sort();
    expect(REGISTERED_ROUTES.map((route) => route.template).sort()).toEqual(bound);
  });

  it("rejects a hard-coded <Route path> that bypasses the registries", () => {
    expect(
      unregisteredLiteralBindings(readAppSource()),
      "App.tsx binds a literal path the both-locale sweep will never visit — " +
        "register it in APP_ROUTES or RESOURCE_ROUTE_PATHS instead",
    ).toEqual([]);
  });

  it("binds every APP_ROUTES entry exactly once, and fans out the resource registry", () => {
    const bindings = parseRouteBindings(readAppSource());
    const appRouteKeys = bindings
      .filter((binding) => binding.kind === "appRoute")
      .map((binding) => binding.value);
    expect(appRouteKeys.sort()).toEqual(Object.keys(APP_ROUTES).sort());
    expect(bindings.filter((binding) => binding.kind === "resourceSpread")).toHaveLength(1);
    expect(resourceSpreadParam(readAppSource())).toBeDefined();
  });

  it("detects a literal route the registries do not know about", () => {
    // Pins the detector itself, so the empty result above is a real check and
    // not a parser that silently matches nothing.
    const mutated = readAppSource().replace(
      "<Route path=\"/\" element=",
      "<Route path=\"/app/mutant-literal\" element={null} />\n<Route path=\"/\" element=",
    );
    expect(mutated, "the mutation did not apply").not.toEqual(readAppSource());
    expect(unregisteredLiteralBindings(mutated)).toEqual(["\"/app/mutant-literal\""]);
    // An expression the inventory cannot resolve is the same hole as a literal.
    expect(parseRouteBindings("<Route path={SOME_OTHER_REGISTRY.thing} />")).toEqual([
      {
        source: "{SOME_OTHER_REGISTRY.thing}",
        kind: "literal",
        value: "SOME_OTHER_REGISTRY.thing",
      },
    ]);
  });

  it("treats only the auth pages and the two redirects as allowed literals", () => {
    expect([...ALLOWED_LITERAL_PATHS]).toEqual(["/login", "/register", "/", "*"]);
    expect([...PUBLIC_ROUTE_PATHS]).toEqual(["/login", "/register"]);
  });

  it("visits a concrete path for every route — no unsubstituted parameter", () => {
    for (const route of REGISTERED_ROUTES) {
      expect(route.path, `${route.key} still contains a :param`).not.toMatch(/\/:/);
      expect(route.path.startsWith("/"), `${route.key} is not an absolute path`).toBe(
        true,
      );
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
    const publicPaths = REGISTERED_ROUTES.filter((r) => r.kind === "public").map(
      (r) => r.path,
    );
    expect(publicPaths).toEqual([...PUBLIC_ROUTE_PATHS]);
    expect(PROTECTED_ROUTES).toHaveLength(
      Object.keys(APP_ROUTES).length + Object.keys(RESOURCE_ROUTE_PATHS).length,
    );
    for (const route of PROTECTED_ROUTES) {
      expect(route.path.startsWith("/app"), `${route.key} is not under /app`).toBe(true);
    }
  });
});
