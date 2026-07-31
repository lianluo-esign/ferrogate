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

  /**
   * SCOPE PIN, not a deferral. The Rust crate `ferrogate-routing` ships only
   * the trait; the concrete matcher lives in the gateway over `AppState`'s
   * hot-reloadable route table, so a matcher here would be a divergence from
   * the crate. What this package owes is that the interface is implementable
   * and that a miss is `undefined` rather than a throw or a fallback route —
   * a fallback would silently send an unrouted request to some upstream.
   */
  test("the interface is satisfiable by an ordinary object, and a miss is undefined", () => {
    const matcher: RouteMatcher = {
      matchRoute: (host, path) =>
        host === "api.example.com" && path.startsWith("/v1/")
          ? { routeName: "v1", upstreamName: "primary" }
          : undefined,
    };
    expect(matcher.matchRoute("api.example.com", "/v1/chat")).toEqual({
      routeName: "v1",
      upstreamName: "primary",
    });
    expect(matcher.matchRoute("api.example.com", "/v2/chat")).toBeUndefined();
    expect(matcher.matchRoute(undefined, "/v1/chat")).toBeUndefined();
  });
});
