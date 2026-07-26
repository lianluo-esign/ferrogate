// The registered-route inventory the #348 both-locale browser matrix sweeps.
//
// The acceptance box is "EVERY registered route is covered by the English/Chinese
// browser route matrix". A hand-listed set of representative paths cannot hold
// that line: it was 11 of 59 when the code review measured it, and every route
// added afterwards would silently escape. So the inventory is DERIVED from the
// same two registries `src/App.tsx` builds its `<Route>` tree from — add a route
// there and it is swept the same day, with no second list to remember.
//
// Deliberately a pure module (no `@playwright/test` import): `route-matrix.test.ts`
// runs it under vitest to prove the derivation still covers both registries, and
// `i18n-route-sweep.spec.ts` consumes it in the browser.
import { APP_ROUTES } from "@/lib/app-routes";
import { RESOURCE_ROUTE_PATHS } from "@/resources/route-paths";

export interface MatrixRoute {
  /** Registry key, used as the test name — stable and greppable. */
  key: string;
  /** The registered template, `:params` and all. */
  template: string;
  /** The template with sample values substituted; what the browser visits. */
  path: string;
  /** `public` routes render no app shell; `protected` ones render it. */
  kind: "public" | "protected";
}

/**
 * Sample values for the four parameterised routes. They are deliberately
 * obviously-fake: the shared admin mock answers an unknown id with an empty
 * list, so the page renders its own "not found"/empty state — which is exactly
 * the state whose COPY the sweep is checking. What matters is that a real value
 * is substituted at all; an unsubstituted `:runId` would silently 404 the route
 * and the sweep would be asserting on the wrong page.
 */
export const ROUTE_PARAM_SAMPLES: Readonly<Record<string, string>> = {
  runId: "run-sample-0001",
  policyId: "policy-sample-0001",
  workerId: "worker-sample-0001",
  pluginId: "plugin-sample-0001",
};

/** The auth routes, registered directly in `App.tsx` rather than in a registry. */
export const PUBLIC_ROUTE_PATHS = ["/login", "/register"] as const;

/**
 * Substitute `:param` segments from {@link ROUTE_PARAM_SAMPLES}.
 *
 * Throws on an unknown parameter rather than leaving it in place or dropping the
 * route: a silently skipped route is exactly the coverage gap this file exists
 * to close, so a new parameterised route must add its sample here.
 */
export function resolveRoutePath(template: string): string {
  return template
    .split("/")
    .map((segment) => {
      if (!segment.startsWith(":")) return segment;
      const name = segment.slice(1);
      const sample = ROUTE_PARAM_SAMPLES[name];
      if (sample === undefined) {
        throw new Error(
          `No ROUTE_PARAM_SAMPLES entry for ":${name}" in "${template}" — ` +
            "add one so the route is swept in both locales.",
        );
      }
      return sample;
    })
    .join("/");
}

/** Every route `App.tsx` registers, in a stable order, with samples applied. */
export const REGISTERED_ROUTES: readonly MatrixRoute[] = [
  ...PUBLIC_ROUTE_PATHS.map((path) => ({
    key: path.slice(1),
    template: path,
    path,
    kind: "public" as const,
  })),
  ...Object.entries(APP_ROUTES).map(([key, template]) => ({
    key,
    template,
    path: resolveRoutePath(template),
    kind: "protected" as const,
  })),
  ...Object.entries(RESOURCE_ROUTE_PATHS).map(([key, template]) => ({
    key: `resource:${key}`,
    template,
    path: template,
    kind: "protected" as const,
  })),
];

/** The protected subset — the routes that render the localized app shell. */
export const PROTECTED_ROUTES: readonly MatrixRoute[] = REGISTERED_ROUTES.filter(
  (route) => route.kind === "protected",
);
