import { describe, expect, it } from "vitest";
import {
  findNavigationLeaf,
  isPathActive,
  NAV_DASHBOARD,
  NAV_GROUPS,
} from "@/components/layout/nav-config";
import { APP_DETAIL_ROUTE_PARENTS, APP_ROUTES } from "@/lib/app-routes";
import { RESOURCE_ROUTES } from "@/resources";
import { translate } from "@/i18n";

const navItems = [NAV_DASHBOARD, ...NAV_GROUPS.flatMap((group) => group.items)];

/** Resolve a leaf's typed catalog key to its English label for assertions. */
const enTitle = (pathname: string) => {
  const leaf = findNavigationLeaf(pathname);
  return leaf ? translate("en", leaf.titleKey) : undefined;
};

describe("admin navigation registry", () => {
  it("maps every protected route to exactly one navigation destination or detail parent", () => {
    const destinations = navItems.map((item) => item.url);
    expect(new Set(destinations).size).toBe(destinations.length);

    const registeredRoutes = [
      ...Object.values(APP_ROUTES),
      ...RESOURCE_ROUTES.map((route) => route.path),
    ];
    for (const route of registeredRoutes) {
      const expectedDestination = APP_DETAIL_ROUTE_PARENTS[route] ?? route;
      expect(
        destinations.filter((destination) => destination === expectedDestination),
        `${route} must have exactly one navigation destination`,
      ).toHaveLength(1);
    }
  });

  it("uses segment boundaries instead of raw prefix matching", () => {
    expect(isPathActive("/app/api-keys", "/app/api-keys")).toBe(true);
    expect(isPathActive("/app/api-keys/key-1", "/app/api-keys")).toBe(true);
    expect(isPathActive("/app/api-keys-native", "/app/api-keys")).toBe(false);
    expect(isPathActive("/app/projects", "/app")).toBe(false);
  });

  it("resolves detail routes to their longest matching navigation parent", () => {
    expect(enTitle("/app/agent-runs/run-1")).toBe("Agent Runs");
    expect(enTitle("/app/plugins/plugin-1/tools")).toBe("Plugins");
    expect(enTitle("/app/workers/self-hosted-runs")).toBe("Self-hosted Runs");
  });

  it("keeps virtual keys and native gateway API keys distinct", () => {
    expect(enTitle("/app/api-keys")).toBe("Virtual Keys");
    expect(enTitle("/app/api-keys-native")).toBe("Gateway API Keys");
  });

  it("labels every navigation destination with a resolvable catalog key", () => {
    for (const item of navItems) {
      expect(translate("en", item.titleKey), `${item.url} en label`).not.toBe(
        item.titleKey,
      );
      expect(translate("zh-CN", item.titleKey), `${item.url} zh-CN label`).not.toBe(
        item.titleKey,
      );
    }
  });
});
