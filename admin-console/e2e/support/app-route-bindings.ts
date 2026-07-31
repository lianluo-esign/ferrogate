// What `src/App.tsx` ACTUALLY binds — read out of the router itself.
//
// `route-matrix.ts` derives the sweep inventory from `APP_ROUTES` and
// `RESOURCE_ROUTE_PATHS`. Comparing that inventory back against the same two
// registries is a tautology: both sides of the assertion are the same
// expression, so it stays green even when someone adds
// `<Route path="/app/mutant" …>` straight into `App.tsx` — a registered route
// that renders untranslated copy and is invisible to the whole matrix.
//
// This module closes that gap by reading `src/App.tsx` and extracting every
// `path=` binding on a `<Route>`. The inventory is then checked against what the
// router binds, and any literal path that is not one of the four known
// non-page routes (`/login`, `/register`, `/`, `*`) is reported so the test can
// fail on it by name.
//
// Deliberately source-text based rather than "render the router and walk it":
// react-router does not expose the bound tree, and rendering `App` would drag in
// the whole provider stack (and every lazy page) just to learn a list of strings.
// The parser is pure — `parseRouteBindings` takes the source as an argument — so
// its own failure modes are testable without touching the real file.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { APP_ROUTES } from "@/lib/app-routes";
import { RESOURCE_ROUTE_PATHS } from "@/resources/route-paths";

/** Absolute path of the router module this inventory is derived from. */
export const APP_SOURCE_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../src/App.tsx",
);

/**
 * The literal `<Route path="…">` values that are allowed to bypass the
 * registries. `/login` and `/register` are the public auth pages (swept as
 * `PUBLIC_ROUTE_PATHS`); `/` and `*` render a `<Navigate>` redirect and have no
 * copy of their own, so they are not sweepable pages.
 */
export const ALLOWED_LITERAL_PATHS = ["/login", "/register", "/", "*"] as const;

/** Literal routes that render a real, sweepable page (as opposed to a redirect). */
export const LITERAL_PAGE_PATHS = ["/login", "/register"] as const;

export type RouteBindingKind = "literal" | "appRoute" | "resourceSpread";

export interface RouteBinding {
  /** The `path=` expression exactly as written in `App.tsx`. */
  readonly source: string;
  readonly kind: RouteBindingKind;
  /**
   * `literal` -> the literal path; `appRoute` -> the `APP_ROUTES` key;
   * `resourceSpread` -> the `RESOURCE_ROUTE_PATHS` identifier.
   */
  readonly value: string;
}

const ROUTE_TAG_RE = /<Route\b/g;
const PATH_ATTR_RE = /(?<![A-Za-z0-9_$])path\s*=\s*/;
const APP_ROUTES_MEMBER_RE = /^APP_ROUTES\.([A-Za-z0-9_$]+)$/;

/**
 * The attribute text of every `<Route …>` opening tag in `source`.
 *
 * Scanned rather than matched with `[^>]*?`: JSX attribute values routinely
 * contain `>` (`element={<Shell />}`, `element={cond ? <A /> : <B />}`), and a
 * regex that stops at the first `>` silently skips any `<Route>` whose `path`
 * is written AFTER such an attribute — a real, registered, unswept route that
 * disappears from the inventory and the literal check together. The scanner
 * tracks brace depth and quoting, so it ends the tag only at a top-level `>`.
 */
function routeTagAttributes(source: string): string[] {
  const tags: string[] = [];
  for (const match of source.matchAll(ROUTE_TAG_RE)) {
    const start = (match.index ?? 0) + match[0].length;
    let index = start;
    let depth = 0;
    let quote: string | undefined;
    while (index < source.length) {
      const char = source[index];
      if (quote !== undefined) {
        if (char === "\\") {
          index += 2;
          continue;
        }
        if (char === quote) quote = undefined;
      } else if (char === '"' || char === "'" || char === "`") {
        quote = char;
      } else if (char === "{") {
        depth += 1;
      } else if (char === "}") {
        depth -= 1;
      } else if (char === ">" && depth === 0) {
        break;
      }
      index += 1;
    }
    tags.push(source.slice(start, index));
  }
  return tags;
}

/**
 * The `path=` value of one `<Route>` tag: either the quoted string or the raw
 * text between the braces (brace- and quote-balanced, so `` path={`/a/${b}`} ``
 * survives intact). `undefined` when the tag binds no path — a layout route.
 */
function pathAttributeValue(
  attributes: string,
): { literal: string } | { expression: string } | undefined {
  const match = PATH_ATTR_RE.exec(attributes);
  if (!match) return undefined;
  const start = match.index + match[0].length;
  const opener = attributes[start];
  if (opener === '"' || opener === "'") {
    const end = attributes.indexOf(opener, start + 1);
    return { literal: attributes.slice(start + 1, end === -1 ? undefined : end) };
  }
  if (opener !== "{") return undefined;
  let depth = 0;
  let quote: string | undefined;
  let index = start;
  while (index < attributes.length) {
    const char = attributes[index];
    if (quote !== undefined) {
      if (char === "\\") {
        index += 2;
        continue;
      }
      if (char === quote) quote = undefined;
    } else if (char === '"' || char === "'" || char === "`") {
      quote = char;
    } else if (char === "{") {
      depth += 1;
    } else if (char === "}") {
      depth -= 1;
      if (depth === 0) break;
    }
    index += 1;
  }
  return { expression: attributes.slice(start + 1, index) };
}

/**
 * Find the identifier the `RESOURCE_ROUTE_PATHS` fan-out binds each path to,
 * e.g. `path` in `Object.values(RESOURCE_ROUTE_PATHS).map((path) => …)`.
 *
 * Returns `undefined` when the fan-out is absent — which is itself a finding:
 * it would mean the 23 resource routes are no longer registered the way the
 * inventory assumes.
 */
export function resourceSpreadParam(source: string): string | undefined {
  const match =
    /Object\.values\(\s*RESOURCE_ROUTE_PATHS\s*\)\s*\.map\(\s*\(?\s*([A-Za-z0-9_$]+)/.exec(
      source,
    );
  return match?.[1];
}

/** Every `<Route path=…>` binding in `source`, in source order. */
export function parseRouteBindings(source: string): RouteBinding[] {
  const spreadParam = resourceSpreadParam(source);
  const bindings: RouteBinding[] = [];
  for (const attributes of routeTagAttributes(source)) {
    const bound = pathAttributeValue(attributes);
    if (bound === undefined) continue;
    if ("literal" in bound) {
      bindings.push({
        source: `"${bound.literal}"`,
        kind: "literal",
        value: bound.literal,
      });
      continue;
    }
    const expression = bound.expression.trim();
    const member = APP_ROUTES_MEMBER_RE.exec(expression);
    if (member) {
      bindings.push({
        source: `{${expression}}`,
        kind: "appRoute",
        value: member[1],
      });
      continue;
    }
    if (spreadParam !== undefined && expression === spreadParam) {
      bindings.push({
        source: `{${expression}}`,
        kind: "resourceSpread",
        value: "RESOURCE_ROUTE_PATHS",
      });
      continue;
    }
    // Anything else is an expression the inventory cannot resolve to concrete
    // paths. Report it as a literal so the caller fails on it by name rather
    // than dropping it — an unresolvable binding is the same coverage hole as a
    // hard-coded one.
    bindings.push({ source: `{${expression}}`, kind: "literal", value: expression });
  }
  return bindings;
}

/**
 * Bindings that neither reference a registry nor match {@link ALLOWED_LITERAL_PATHS}.
 *
 * A non-empty result means `App.tsx` registers a route the both-locale sweep
 * will never visit.
 */
export function unregisteredLiteralBindings(source: string): string[] {
  const allowed = new Set<string>(ALLOWED_LITERAL_PATHS);
  return parseRouteBindings(source)
    .filter((binding) => binding.kind === "literal" && !allowed.has(binding.value))
    .map((binding) => binding.source);
}

/**
 * The concrete route templates `source` binds, excluding the redirect-only
 * literals — i.e. exactly the set the both-locale sweep must cover.
 */
export function boundRouteTemplates(source: string): string[] {
  const templates: string[] = [];
  for (const binding of parseRouteBindings(source)) {
    if (binding.kind === "literal") {
      if ((LITERAL_PAGE_PATHS as readonly string[]).includes(binding.value)) {
        templates.push(binding.value);
      }
      continue;
    }
    if (binding.kind === "appRoute") {
      const template = (APP_ROUTES as Record<string, string | undefined>)[binding.value];
      if (template === undefined) {
        throw new Error(
          `App.tsx binds APP_ROUTES.${binding.value}, which is not a key of APP_ROUTES.`,
        );
      }
      templates.push(template);
      continue;
    }
    templates.push(...Object.values(RESOURCE_ROUTE_PATHS));
  }
  return templates;
}

/** Read the real router module. */
export function readAppSource(): string {
  return readFileSync(APP_SOURCE_PATH, "utf8");
}
