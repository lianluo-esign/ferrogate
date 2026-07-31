// Adversarial tests for the router-binding parser that carries the #348 box
// "every registered route is covered by the English/Chinese browser route matrix".
//
// `route-matrix.test.ts` compares the sweep inventory against what
// `app-route-bindings.ts` reads out of `src/App.tsx`. That comparison is only as
// strong as the parser: a `<Route path=…>` the parser cannot see is a route that
// escapes both the inventory AND the "no hard-coded literal" check, because both
// sides of the comparison lose it together — the same tautology the derived
// inventory was supposed to end.
//
// These cases feed the parser hand-written router sources (it is pure: source
// text in, bindings out) and pin what it must detect. Each source below is valid
// react-router that would register a real, unswept, untranslated page.
import { describe, expect, it } from "vitest";
import { APP_ROUTES } from "@/lib/app-routes";
import { RESOURCE_ROUTE_PATHS } from "@/resources/route-paths";
import {
  boundRouteTemplates,
  parseRouteBindings,
  readAppSource,
  resourceSpreadParam,
  unregisteredLiteralBindings,
} from "./app-route-bindings";

/** A minimal router whose body is supplied per-case. */
function router(body: string): string {
  return [
    "const ROUTES = (",
    "  <Routes>",
    '    <Route path="/login" element={routeElement(LoginPage)} />',
    "    <Route element={<ProtectedRoute />}>",
    "      <Route element={<AppShell />}>",
    `        ${body}`,
    "        {Object.values(RESOURCE_ROUTE_PATHS).map((path) => (",
    "          <Route key={path} path={path} element={routeElement(ResourceRoutePage)} />",
    "        ))}",
    "      </Route>",
    "    </Route>",
    '    <Route path="/" element={<Navigate to="/app" replace />} />',
    '    <Route path="*" element={<Navigate to="/app" replace />} />',
    "  </Routes>",
    ");",
  ].join("\n");
}

describe("App.tsx route-binding parser", () => {
  it("ignores <Route> elements that bind no path at all", () => {
    // The two wrapper routes in the fixture carry `element` but no `path`; only
    // the four real bindings must show up.
    expect(parseRouteBindings(router("")).map((b) => b.value)).toEqual([
      "/login",
      "RESOURCE_ROUTE_PATHS",
      "/",
      "*",
    ]);
    expect(unregisteredLiteralBindings(router(""))).toEqual([]);
  });

  it("reports a braced string literal, not just a bare quoted one", () => {
    // `path={"/app/mutant"}` is the same coverage hole as `path="/app/mutant"`.
    expect(unregisteredLiteralBindings(router('<Route path={"/app/mutant"} element={null} />'))).toEqual(
      ['{"/app/mutant"}'],
    );
  });

  it("reports a template-literal path rather than dropping it", () => {
    const bindings = unregisteredLiteralBindings(
      router("<Route path={`/app/${slug}`} element={null} />"),
    );
    expect(bindings).toHaveLength(1);
    expect(bindings[0]).toContain("/app/");
  });

  it("reports a path taken from some other registry", () => {
    expect(
      unregisteredLiteralBindings(router("<Route path={OTHER_ROUTES.mutant} element={null} />")),
    ).toEqual(["{OTHER_ROUTES.mutant}"]);
  });

  it("sees a duplicated APP_ROUTES binding twice, so 'bound exactly once' can fail", () => {
    const doubled = router(
      "<Route path={APP_ROUTES.dashboard} element={null} />\n" +
        "        <Route path={APP_ROUTES.dashboard} element={null} />",
    );
    const keys = parseRouteBindings(doubled)
      .filter((b) => b.kind === "appRoute")
      .map((b) => b.value);
    expect(keys).toEqual(["dashboard", "dashboard"]);
  });

  it("stops trusting `path={path}` when the resource fan-out is gone", () => {
    // Without `Object.values(RESOURCE_ROUTE_PATHS).map((path) => …)` there is no
    // reason to believe a bare `path` identifier expands to the 23 resource
    // routes, so it must be reported instead of silently credited.
    const source = router("").replace("Object.values(RESOURCE_ROUTE_PATHS)", "SOME_LIST");
    expect(resourceSpreadParam(source)).toBeUndefined();
    expect(unregisteredLiteralBindings(source)).toEqual(["{path}"]);
  });

  it("expands the fan-out to every resource template and the APP_ROUTES member", () => {
    const templates = boundRouteTemplates(
      router("<Route path={APP_ROUTES.dashboard} element={null} />"),
    );
    expect(templates).toContain(APP_ROUTES.dashboard);
    for (const template of Object.values(RESOURCE_ROUTE_PATHS)) {
      expect(templates).toContain(template);
    }
    // `/` and `*` are redirects with no copy: bound, but deliberately not swept.
    expect(templates).not.toContain("/");
    expect(templates).not.toContain("*");
  });

  it("fails loudly when App.tsx binds an APP_ROUTES key that does not exist", () => {
    expect(() =>
      boundRouteTemplates(router("<Route path={APP_ROUTES.mutantMissing} element={null} />")),
    ).toThrow(/APP_ROUTES\.mutantMissing/);
  });

  it("detects a hard-coded route even when `element` is written before `path`", () => {
    // REGRESSION (#348): `<Route element={<Foo />} path="/app/mutant" />` is
    // valid, idiomatic react-router — `App.tsx` already writes
    // `element={<ProtectedRoute />}` and `element={<Navigate … />}` — and the
    // layout-route form `<Route path="/x" element={<Shell />}>` differs only in
    // attribute order. The `>` inside the JSX element ends the parser's
    // `[^>]*?` scan, so the whole binding is invisible: the route is registered,
    // renders untranslated copy, and is missing from BOTH the inventory and the
    // literal check, which keeps `route-matrix.test.ts` green.
    expect(
      unregisteredLiteralBindings(router("<Route element={<MutantPage />} path=\"/app/mutant\" />")),
    ).toEqual(['"/app/mutant"']);
    expect(
      unregisteredLiteralBindings(
        router('<Route element={cond ? <A /> : <B />} path="/app/mutant-two" />'),
      ),
    ).toEqual(['"/app/mutant-two"']);
  });

  it("keeps the real App.tsx clean under both orderings", () => {
    expect(unregisteredLiteralBindings(readAppSource())).toEqual([]);
  });
});
