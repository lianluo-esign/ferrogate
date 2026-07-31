import { describe, expect, test } from "vitest";
import type { RouteMatch, RouteMatcher } from "@ferrogate/routing";

// The crate ships only the abstraction (RouteMatch struct + RouteMatcher trait);
// the concrete matcher lives over the runtime route table. Smoke-test that the
// interface is implementable and shaped as the data plane expects.
describe("RouteMatcher interface", () => {
  const stub: RouteMatcher = {
    matchRoute(host, path) {
      if (path === "/v1/chat/completions") {
        return { routeName: "chat", upstreamName: host ? `up-${host}` : "up-default" };
      }
      return undefined;
    },
  };

  test("resolves a known path to a RouteMatch", () => {
    const m = stub.matchRoute("api.test", "/v1/chat/completions");
    expect(m).toEqual<RouteMatch>({ routeName: "chat", upstreamName: "up-api.test" });
  });

  test("returns undefined when no runtime route matches", () => {
    expect(stub.matchRoute(undefined, "/nope")).toBeUndefined();
  });

  // PORT-TODO(inventory §2.8): concrete Hono/matchit matcher over AppState's
  // hot-reloadable route table is ported in apps/gateway (Wave 3).
  test.todo("concrete runtime-route-table matcher (apps/gateway, Wave 3)");
});
