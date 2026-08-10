import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { APP_ROUTES } from "@/lib/app-routes";
import { RESOURCE_ROUTES } from "@/resources";
import { describe, expect, it } from "vitest";

// Console <-> Admin API control-plane coverage gate (#463, epic #313).
//
// Epic #313's acceptance box 1 — "every Admin API control-plane group in the
// contract has a console page (or a documented deliberate exclusion)" — was a
// ONE-TIME manual gap analysis with nothing re-checking it, so a new
// `/admin/v1/<group>` could land without any operator surface and nobody would
// notice. This is the console counterpart of the Rust parity gate
// (`openapi_operations_are_covered_or_reviewed` in `ferrogate-control-plane-client`, whose
// `REVIEWED_EXCLUSIONS` discipline — owner + specific reason, never a rubber
// stamp — is mirrored below).
//
// WHERE COVERAGE COMES FROM
// -------------------------
// Nothing here duplicates a hand-written list of console pages. Coverage is
// DERIVED from the console's own sources of truth, so it cannot drift:
//
//   1. the generic resource registry — `RESOURCE_ROUTES`, each entry carrying
//      the `basePath` it actually calls (e.g. `/admin/v1/providers`) and the
//      route it is mounted at; and
//   2. the bespoke pages — parsed out of the ROUTER (`src/App.tsx`): every
//      `<Route path={APP_ROUTES.x} element={routeElement(YPage)} />` is paired
//      with the `@/pages/<file>` its component lazily imports, and that page's
//      source is scanned for the `/admin/v1/<group>` endpoints it calls.
//
// Deriving from real call sites (rather than matching kebab names) is what
// makes the gate honest: a group counts as covered only when a REGISTERED route
// leads to code that actually talks to that group's endpoints.

const testDir = path.dirname(fileURLToPath(import.meta.url));
const consoleRoot = path.resolve(testDir, "..", "..");
// Same relative hop as `scripts/check-api-types-drift.mjs`: the committed
// contract lives at <repo-root>/docs/openapi/admin-api.openapi.json.
const specPath = path.join(consoleRoot, "..", "docs", "openapi", "admin-api.openapi.json");
const appTsxPath = path.join(consoleRoot, "src", "App.tsx");
const pagesDir = path.join(consoleRoot, "src", "pages");

const ADMIN_V1_PREFIX = "/admin/v1/";

/** A console surface that serves one or more Admin API control-plane groups. */
interface ConsoleSurface {
  /** How the surface is built: generic CRUD registry vs a hand-written page. */
  kind: "resource-registry" | "bespoke-page";
  /** The route it is mounted at (proven registered, not assumed). */
  route: string;
  /** Registry resource key, or `src/pages/<file>.tsx` for a bespoke page. */
  source: string;
}

/**
 * A reviewed decision that a control-plane group carries NO console surface.
 * Mirrors the Rust gate's `ReviewedExclusion`: an entry removes the group from
 * the gap set, so it must name an owner and a specific reason. "Not needed" is
 * not a reason; a deferral must say what the eventual UI is and where it is
 * tracked.
 */
interface DeliberateExclusion {
  owner: string;
  reason: string;
}

const DELIBERATE_EXCLUSIONS: Readonly<Record<string, DeliberateExclusion>> = {
  // Platform billing groups + their provider bindings (#943, epic #941). A
  // PLATFORM-OPERATOR surface: it defines the price multipliers applied at
  // settlement, so its operator UI belongs in the same billing/ops cockpit that
  // owns wallets and metering, next to the per-tenant spend controls — not a
  // standalone page stranded from them. Deferred, needs UI — tracked on the
  // #313 chain as the #941 billing-group cockpit follow-up.
  "billing-groups": {
    owner: "billing/ops cockpit (#941 follow-up, #313 chain)",
    reason:
      "platform price-multiplier groups and their provider bindings; the operator UI belongs as a panel inside the existing wallets/metering billing cockpit rather than a standalone page — deferred, needs UI",
  },
  // Read-only cost-burn rollup (#428 slice B-surface): GET-only, no write verbs,
  // and it renders the SAME per-tenant billing period the wallets + metering
  // cockpit already owns. A standalone page would strand it away from the spend
  // controls operators act on, so the surface is deferred until the billing/ops
  // cockpit grows its per-agent spend panel next to `/app/wallets` and
  // `/app/metering`. Deferred, needs UI — tracked on the #313 chain as the
  // #428 cost-governance follow-up.
  "agent-cost-burn": {
    owner: "billing/ops cockpit (#428 follow-up, #313 chain)",
    reason:
      "read-only per-agent cost-burn rollup for a billing period; its operator UI belongs as a spend panel inside the existing wallets/metering cockpit rather than a standalone page — deferred, needs UI",
  },
  // Two groups surfaced by #747, not created by it — the same mechanism that
  // made #682 and #695 visible below. #677 routed the per-request cost
  // attribution read and its export without describing either in
  // `admin-api.openapi.json`, and this gate derives its group list FROM that
  // file, so neither group has been visible since #677 landed. The console has
  // had no cost-attribution surface that whole time; describing the contract is
  // what makes the gap countable.
  //
  // Both belong on the SAME operator screen as `agent-cost-burn` above — the
  // per-tenant spend panel beside `/app/wallets` and `/app/metering` — because
  // they answer the next question that panel raises ("which requests made up
  // this figure?"). A standalone read-only table would strand the chargeback
  // drill-down away from the spend controls, which is the exact reason
  // `agent-cost-burn` is deferred rather than built. Deferred, needs UI —
  // tracked on the #313 chain as the #677 cost-attribution follow-up. Both
  // entries must be deleted when that panel lands; an obsolete exclusion fails
  // the check below.
  "cost-records": {
    owner: "billing/ops cockpit (#677 follow-up, #313 chain)",
    reason:
      "read-only per-request cost attribution drill-down; it is the detail behind the per-agent burn rollup and belongs in the same wallets/metering spend panel rather than a page of its own — deferred, needs UI",
  },
  "cost-record-exports": {
    owner: "billing/ops cockpit (#677 follow-up, #313 chain)",
    reason:
      "download-only surface: it answers a CSV, JSONL or binary Parquet attachment rather than a renderable document, so it is a button on the cost-records panel above rather than a page — deferred, needs UI",
  },
  // (`observed-agent-activity` used to be excluded here as "deferred, needs UI".
  // #464 shipped that UI as the Unattributed tab on `src/pages/agent-runs.tsx`,
  // so the exclusion was DELETED: the group is now covered by a real call site
  // and the obsolete-exclusion check below would fail if the entry stayed.)
  // Legacy compatibility read: `/admin/v1/tenants` lists tenant references
  // DERIVED from API-key configuration, not durable records — there is nothing
  // to create, edit or delete. The console already renders the durable tenant
  // registry (`/admin/v1/tenant-accounts`) at `/app/tenants`, so a page here
  // would duplicate that route with a strictly weaker, non-editable dataset.
  // Read-only x402 spend-policy DIAGNOSTICS (#351): the two GETs expose the
  // declared and the effective policy plus its revision, and the single POST is
  // a dry-run evaluator that mutates nothing. The policy itself is authored in
  // `ferrogate.toml` (`[[x402_spend_policies]]`), NOT through this API, so a
  // console CRUD page would present editable-looking controls over a surface
  // that cannot write. The operator UI that belongs here is a spend panel next
  // to the wallets/metering cockpit, shared with the #428 cost-governance
  // follow-up. Deferred, needs UI — tracked on the #313 chain.
  "x402-spend-policies": {
    owner: "billing/ops cockpit (#351 diagnostics, #428 follow-up, #313 chain)",
    reason:
      "read-only effective-policy diagnostics plus a dry-run evaluator; the policy is authored in ferrogate.toml, not through this API, so a CRUD page would imply writes the surface does not support — deferred, needs UI alongside the wallets/metering spend panel",
  },
  // Read-only x402 payment-attempt INSPECTION (#352): two GETs over rows the
  // #354 settlement loop writes. There is no operator write path at all — an
  // attempt is minted by a paid egress request, never by a console action — so
  // a CRUD page here would present editable-looking controls over a surface
  // that cannot write. The operator UI that belongs here is the stuck-payment
  // panel next to the wallet holds it joins to, in the same wallets/metering
  // spend cockpit the x402 spend-policy diagnostics are waiting on. Operators
  // are NOT blocked meanwhile: the `ctl payment-attempts list|get` verbs cover
  // the surface today — the whole listing, not just its first page, by passing
  // the page's `next_cursor` back as `--filter cursor=…`. The endpoint is
  // CURSOR-paginated, so `--offset`/`--all-pages` do not apply to it and the
  // CLI now refuses both rather than silently re-serving page one. Deferred,
  // needs UI — tracked on the #313 chain.
  "payment-attempts": {
    owner: "billing/ops cockpit (#352 inspection, #428 follow-up, #313 chain)",
    reason:
      "read-only durable x402 payment-attempt inspection with no operator write path; covered today by the ctl payment-attempts verbs, and its UI belongs in the wallets/metering spend cockpit beside the wallet holds it joins — deferred, needs UI",
  },
  tenants: {
    owner: "tenancy (superseded by tenant-accounts)",
    reason:
      "derived-from-API-key-config compatibility read with no durable records; the console renders the authoritative tenant-accounts registry at /app/tenants instead",
  },
  // Two groups surfaced by #734, not created by it. #682 (BYOK) and #695
  // (semantic cache) merged while the API-contract-drift workflow was disabled,
  // so their operations never reached `admin-api.openapi.json` and this gate —
  // which derives its group list FROM that file — could not see them. The
  // console has had no surface for either since those PRs landed; #734 restoring
  // the contract is what makes the gap visible. Both are deferred rather than
  // built inside a documentation-integrity fix, and both must lose their entry
  // here when the page lands (an obsolete exclusion fails the check below).
  "provider-credentials": {
    owner: "provider/BYOK console surface (#682 follow-up, #313 chain)",
    reason:
      "per-tenant BYOK registration: the write verb takes a provider API key, so the page needs a credential-entry control that never renders the value back (the API returns only a last4 hint) and a rotation affordance distinct from create — a UX decision that has not been made, so a generic CRUD resource would be actively wrong here. Deferred, needs UI",
  },
  "semantic-cache-policies": {
    owner: "cache governance console surface (#695 follow-up, #313 chain)",
    reason:
      "every governed field is a TRI-STATE (null means inherit the deployment value, which is not the same as false or 0) and the group has no PATCH for exactly that reason, so a generic CRUD form would silently turn 'inherit' into a concrete value; it also carries a purge action that is not a CRUD leg. Belongs beside the gateway cache panel. Deferred, needs UI",
  },
  // #743's asset FLEET surface: the inventory, the quarantine review queue and
  // the release/reject decision. Three reasons a generic CRUD resource would be
  // WRONG here rather than merely thin, which is why this is a deferral with a
  // named shape instead of a registry entry:
  //
  //  1. **It is not CRUD.** There is no create and no update; the two writes are
  //     a decision (`release` | `reject`) and an irreversible force-delete, and
  //     BOTH carry a MANDATORY free-text reason and are refused without one. The
  //     generic form renders editable fields and a Save button; that is the
  //     wrong affordance for a moderation verdict, and the generic row DELETE —
  //     one click, no reason, no `force` — is the wrong affordance for a verb
  //     that destroys bytes and can take a live site down. A Save that silently
  //     400s on a missing reason is worse than no button.
  //  2. **The cross-tenant read is gated on a scope the console session may not
  //     hold.** `admin.assets.fleet` must be held EXACTLY (the admin wildcard
  //     does not grant it), so the page has a first-class "you are not
  //     authorized for the fleet view, here is the grant to mint" state that no
  //     other console resource has, plus a per-tenant fallback view.
  //  3. **The list is deliberately not linkable to bytes.** No cell may become a
  //     download link and no preview may be rendered: metadata is a smaller
  //     permission than content, and the generic renderer's habit of turning a
  //     URL-ish string into an anchor is exactly the mistake to avoid. The API
  //     withholds `storage_uri` so the console cannot make one by accident, but
  //     the SCREEN still has to be designed around "you can see it and you
  //     cannot fetch it".
  //
  // The eventual UI is a two-pane abuse-response screen — the fleet inventory
  // with tenant/type/visibility filters, and a quarantine queue whose row action
  // opens a decision dialog that requires the reason before it enables Release
  // or Reject — mounted beside the hosting surfaces (`/app/site-domains`), not
  // in the CRUD registry. Operators are not blocked meanwhile: all three
  // operations are ordinary `/admin/v1` calls the CLI and the generated SDKs
  // reach today. Deferred, needs UI — tracked on the #313 chain as the #743
  // hosting-abuse-response follow-up. This entry must be DELETED when that
  // screen lands; an obsolete exclusion fails the check below.
  experiments: {
    owner: "observability cockpit (#693 follow-up, #313 chain)",
    reason:
      "experiment outcome reads are derived from gateway observations rather than an editable resource; they belong beside the existing model and metering diagnostics as a comparison report, not in the CRUD registry — deferred, needs UI",
  },
  "spend-anomalies": {
    owner: "billing/ops cockpit (#697 follow-up, #313 chain)",
    reason:
      "spend-anomaly reads are a derived incident ledger with no operator mutation surface; the eventual screen belongs in the wallets/metering operations cockpit beside cost attribution, rather than as a standalone CRUD page — deferred, needs UI",
  },
  assets: {
    owner: "hosting abuse-response console surface (#743 follow-up, #313 chain)",
    reason:
      "asset fleet inventory plus a quarantine review queue whose writes are a reasoned release/reject decision and an irreversible force-delete that must state whether it is taking a live channel down, not CRUD legs; it also needs a distinct-scope ('admin.assets.fleet' held exactly) unauthorized state and a list that must never link to bytes, so a generic CRUD resource would render the wrong affordances. Belongs as a two-pane abuse-response screen beside the site-domains hosting surfaces — deferred, needs UI",
  },
  "tenant-data": {
    owner: "platform storage operations (#828, #313 chain)",
    reason:
      "audited SQL reads, resumable JSONL downloads and destructive point-in-time restore are operator/customer workflows rather than a CRUD page; export is streamed directly to R2 and restore needs a deliberate confirmation tool, so this API/CLI surface is intentionally excluded from the generic console — tracked by #828",
  },
  "retention-policies": {
    owner: "asset lifecycle operations (#744, #313 chain)",
    reason:
      "tenant/operator retention rules are a narrow control-plane surface consumed by the scheduled asset sweeper; the eventual UI belongs in a tenant asset-lifecycle/settings screen, while a generic CRUD resource would hide the destructive retention semantics — deferred, needs UI",
  },
};

/**
 * Groups whose console surface is deliberately NOT named after the API group.
 * The gate does not need this map to compute coverage (coverage is derived from
 * real call sites) — it exists so every divergence between the contract's
 * vocabulary and the operator-facing IA is written down and VERIFIED: each
 * entry is asserted against the surface actually resolved, so a rename on
 * either side fails the test instead of silently rotting a comment.
 */
const EXPECTED_NON_IDENTITY_SURFACES: Readonly<Record<string, { source: string; why: string }>> = {
  // The console's tenant IA is keyed on the durable registry, and the generic
  // resource is named after the API group it calls, not the route it mounts.
  "self-hosted-worker-records": {
    source: "self-hosted-workers",
    why: "durable worker records are the data behind the operator-facing 'self-hosted workers' resource; the record/registration split is an API detail",
  },
  // `/app/api-keys` is taken by the bespoke virtual-keys page (the operator's
  // primary key surface), so the native api-keys CRUD mounts at a distinct
  // route rather than renaming the API group.
  "api-keys": {
    source: "api-keys-native",
    why: "native API keys mount at /app/api-keys-native because /app/api-keys is the bespoke virtual-keys page",
  },
  // Provider fleet health is one operator screen; the three reads that feed it
  // (health, catalogued models, adapters, extensions) are separate API groups.
  "provider-models": {
    source: "ops-provider-health",
    why: "provider catalogue read feeding the single provider-health ops screen",
  },
  "framework-adapters": {
    source: "ops-provider-health",
    why: "adapter inventory read feeding the single provider-health ops screen",
  },
  extensions: {
    source: "ops-provider-health",
    why: "extension inventory read feeding the single provider-health ops screen",
  },
  // The dashboard IS the overview endpoint's page; naming it 'overview' would
  // duplicate the app root.
  overview: {
    source: "dashboard",
    why: "the overview read backs the /app dashboard landing page",
  },
  // Billing IA groups the metering reads onto one page, and the outbox
  // dead-letter queue is presented as 'billing dead letters'.
  "metering-events": {
    source: "billing-metering",
    why: "metering reads are consolidated onto one billing metering page",
  },
  "metering-export-status": {
    source: "billing-metering",
    why: "metering reads are consolidated onto one billing metering page",
  },
  "usage-aggregates": {
    source: "billing-metering",
    why: "metering reads are consolidated onto one billing metering page",
  },
  "billing-outbox-dead-letters": {
    source: "billing-dead-letters",
    why: "the outbox implementation detail is dropped from the operator-facing page name",
  },
  // Ops screens are namespaced under an 'ops-' prefix in the page layer.
  config: { source: "ops-config", why: "gateway config reload/validate lives under the ops IA" },
  drain: { source: "ops-drain", why: "drain control lives under the ops IA" },
  status: { source: "ops-status", why: "gateway status lives under the ops IA" },
  observability: {
    source: "ops-observability",
    why: "observability snapshot lives under the ops IA",
  },
  "gateway-configs": {
    source: "ops-gateway-configs",
    why: "gateway config profiles live under the ops IA",
  },
  "provider-health": {
    source: "ops-provider-health",
    why: "provider health lives under the ops IA",
  },
  "request-log-exports": {
    source: "ops-observability",
    why: "log export jobs are driven from the observability ops screen",
  },
  // Remaining renames: catalogue/cockpit page names that read better than the
  // API group name.
  tools: { source: "tools-catalog", why: "the tools read renders the tool catalogue page" },
  wallets: { source: "billing-wallets", why: "wallets are part of the billing cockpit IA" },
  "payment-methods": {
    source: "billing-payment-methods",
    why: "payment methods are part of the billing cockpit IA",
  },
  "self-hosted-runs": {
    source: "self-hosted-runs",
    why: "identity page name, but mounted under the /app/workers/* IA rather than /app/self-hosted-runs",
  },
};

// ---------------------------------------------------------------------------
// Pure helpers — the gate's logic, testable against synthetic input so we can
// prove it FAILS when it should without touching the real contract.
// ---------------------------------------------------------------------------

/**
 * Every distinct control-plane group in the contract: the first path segment
 * after `/admin/v1/`. `/admin/v1/guardrail-policies/{id}/activate` -> `guardrail-policies`.
 */
function extractControlPlaneGroups(specJson: string): string[] {
  const spec = JSON.parse(specJson) as { paths?: Record<string, unknown> };
  const groups = new Set<string>();
  for (const apiPath of Object.keys(spec.paths ?? {})) {
    const group = controlPlaneGroupOf(apiPath);
    if (group) groups.add(group);
  }
  return [...groups].sort();
}

function controlPlaneGroupOf(apiPath: string): string | undefined {
  if (!apiPath.startsWith(ADMIN_V1_PREFIX)) return undefined;
  const segment = apiPath.slice(ADMIN_V1_PREFIX.length).split("/")[0];
  // `{tenant_id}` style templates are never a group name.
  if (!segment || segment.startsWith("{")) return undefined;
  return segment;
}

/** Groups with neither a console surface nor a reviewed exclusion. */
function findUncoveredGroups(
  groups: readonly string[],
  surfaces: ReadonlyMap<string, ConsoleSurface>,
  exclusions: Readonly<Record<string, DeliberateExclusion>>,
): string[] {
  return groups.filter((group) => !surfaces.has(group) && !(group in exclusions)).sort();
}

/** Exclusions that no longer match any contract group (the map has rotted). */
function findStaleExclusions(
  groups: readonly string[],
  exclusions: Readonly<Record<string, DeliberateExclusion>>,
): string[] {
  const contract = new Set(groups);
  return Object.keys(exclusions)
    .filter((group) => !contract.has(group))
    .sort();
}

/** Exclusions that DID get a console surface and should now be deleted. */
function findObsoleteExclusions(
  surfaces: ReadonlyMap<string, ConsoleSurface>,
  exclusions: Readonly<Record<string, DeliberateExclusion>>,
): string[] {
  return Object.keys(exclusions)
    .filter((group) => surfaces.has(group))
    .sort();
}

// ---------------------------------------------------------------------------
// Coverage resolution from the console's own sources of truth.
// ---------------------------------------------------------------------------

/** Generic CRUD resources: each registered route declares the group it calls. */
function resolveRegistrySurfaces(): Map<string, ConsoleSurface> {
  const surfaces = new Map<string, ConsoleSurface>();
  for (const route of RESOURCE_ROUTES) {
    const group = controlPlaneGroupOf(route.config.basePath);
    if (!group) continue;
    surfaces.set(group, {
      kind: "resource-registry",
      route: route.path,
      source: route.config.key,
    });
  }
  return surfaces;
}

/** Bespoke pages, read out of the router: route path -> `pages/<file>` name. */
function resolveRegisteredBespokePages(): Map<string, string> {
  const app = readFileSync(appTsxPath, "utf8");
  const componentToPage = new Map<string, string>();
  for (const match of app.matchAll(
    /const (\w+) = lazy\(\(\) => import\("@\/pages\/([\w-]+)"\)\)/g,
  )) {
    componentToPage.set(match[1], match[2]);
  }
  const pageToRoute = new Map<string, string>();
  for (const match of app.matchAll(
    /path=\{APP_ROUTES\.(\w+)\}[\s\S]{0,160}?routeElement\((\w+)\)/g,
  )) {
    const routeKey = match[1] as keyof typeof APP_ROUTES;
    const page = componentToPage.get(match[2]);
    const route = APP_ROUTES[routeKey];
    // Keep the shallowest route for a page reached by several paths.
    if (page && route && !pageToRoute.has(page)) pageToRoute.set(page, route);
  }
  return pageToRoute;
}

/** The `/admin/v1/<group>` endpoints a page's source actually calls. */
function groupsCalledBy(pageFile: string): string[] {
  const source = readFileSync(path.join(pagesDir, `${pageFile}.tsx`), "utf8");
  const groups = new Set<string>();
  for (const match of source.matchAll(/["'`]\/admin\/v1\/([\w-]+)/g)) groups.add(match[1]);
  return [...groups];
}

function resolveConsoleSurfaces(): Map<string, ConsoleSurface> {
  const surfaces = resolveRegistrySurfaces();
  // Deterministic order so a group served by several pages always resolves to
  // the same surface regardless of router edit order.
  const pages = [...resolveRegisteredBespokePages().entries()].sort(([a], [b]) =>
    a.localeCompare(b),
  );
  for (const [page, route] of pages) {
    for (const group of groupsCalledBy(page)) {
      // The generic registry wins: it is the declared owner of its basePath.
      if (surfaces.has(group)) continue;
      surfaces.set(group, { kind: "bespoke-page", route, source: page });
    }
  }
  return surfaces;
}

// ---------------------------------------------------------------------------
// Caller-facing (`/v1/`) groups that also owe a console surface (#474).
//
// The gate above deliberately scopes itself to `/admin/v1/`: most `/v1/` paths
// are data-plane traffic (chat completions, embeddings, MCP) that no operator
// screen could meaningfully render, so requiring a page for every one of them
// would be noise. But a caller-facing CONTROL protocol — submit a durable job,
// observe it, collect it, cancel it — is exactly the kind of surface an
// operator needs, and #474's acceptance box asks for one.
//
// Listing a group here makes the requirement RECORDABLE: coverage is derived
// from real call sites the same way as above, so deleting the page (or
// renaming the endpoints out from under it) reddens this test instead of
// silently un-covering the protocol. Removing an entry is the "reviewed
// exclusion" and must be argued in review, exactly like DELIBERATE_EXCLUSIONS.
const CALLER_FACING_TRACKED_GROUPS: Readonly<Record<string, { why: string }>> = {
  "agent-jobs": {
    why: "the #474 async agent-job protocol is a caller-facing CONTROL surface (submit/observe/collect/cancel over a durable run id), not data-plane traffic — operators need to follow and cancel a long-running job",
  },
};

/** The `/v1/<group>` prefix a caller-facing path belongs to, if any. */
function callerFacingGroupOf(apiPath: string): string | undefined {
  if (!apiPath.startsWith("/v1/")) return undefined;
  const segment = apiPath.slice("/v1/".length).split("/")[0];
  if (!segment || segment.startsWith("{")) return undefined;
  return segment;
}

/** Caller-facing `/v1/<group>` endpoints a page's source actually calls. */
function callerFacingGroupsCalledBy(pageFile: string): string[] {
  const source = readFileSync(path.join(pagesDir, `${pageFile}.tsx`), "utf8");
  const groups = new Set<string>();
  for (const match of source.matchAll(/["'`]\/v1\/([\w-]+)/g)) groups.add(match[1]);
  return [...groups];
}

function resolveCallerFacingSurfaces(): Map<string, ConsoleSurface> {
  const surfaces = new Map<string, ConsoleSurface>();
  const pages = [...resolveRegisteredBespokePages().entries()].sort(([a], [b]) =>
    a.localeCompare(b),
  );
  for (const [page, route] of pages) {
    for (const group of callerFacingGroupsCalledBy(page)) {
      if (surfaces.has(group)) continue;
      surfaces.set(group, { kind: "bespoke-page", route, source: page });
    }
  }
  return surfaces;
}

const contractGroups = extractControlPlaneGroups(readFileSync(specPath, "utf8"));
const consoleSurfaces = resolveConsoleSurfaces();

describe("Admin API control-plane groups (contract)", () => {
  it("parses a non-trivial set of groups out of the committed contract", () => {
    // A parsing regression that silently yielded {} would make the gate vacuous.
    expect(contractGroups.length).toBeGreaterThan(40);
    expect(contractGroups).toContain("guardrail-policies");
    expect(contractGroups).toContain("agent-cost-burn");
    expect(contractGroups.every((group) => /^[a-z][a-z0-9-]*$/.test(group))).toBe(true);
  });

  it("takes the first segment after /admin/v1/ as the group", () => {
    const spec = JSON.stringify({
      paths: {
        "/admin/v1/guardrail-policies/{id}/activate": {},
        "/admin/v1/guardrail-policies": {},
        "/admin/v1/wallets/{tenant_id}/ledger": {},
        "/v1/chat/completions": {},
        "/healthz": {},
        "/admin/v1/": {},
      },
    });
    expect(extractControlPlaneGroups(spec)).toEqual(["guardrail-policies", "wallets"]);
  });
});

describe("console coverage of the Admin API control plane (#313 acceptance box 1)", () => {
  it("resolves surfaces only from registered routes and real page files", () => {
    for (const [group, surface] of consoleSurfaces) {
      expect(surface.route, `group ${group} resolved to an empty route`).toMatch(/^\/app/);
      if (surface.kind === "bespoke-page") {
        // Prove the page exists on disk — never trust the router text alone.
        expect(
          existsSync(path.join(pagesDir, `${surface.source}.tsx`)),
          `group ${group} maps to missing page src/pages/${surface.source}.tsx`,
        ).toBe(true);
        expect(Object.values(APP_ROUTES)).toContain(surface.route);
      } else {
        expect(RESOURCE_ROUTES.map((route) => route.path)).toContain(surface.route);
      }
    }
    // Both discovery mechanisms must contribute, or one silently broke.
    const kinds = [...consoleSurfaces.values()].map((surface) => surface.kind);
    expect(kinds.filter((kind) => kind === "resource-registry").length).toBeGreaterThan(15);
    expect(kinds.filter((kind) => kind === "bespoke-page").length).toBeGreaterThan(15);
  });

  it("covers every control-plane group with a console surface or a reviewed exclusion", () => {
    const uncovered = findUncoveredGroups(contractGroups, consoleSurfaces, DELIBERATE_EXCLUSIONS);
    expect(
      uncovered,
      `Admin API control-plane group(s) with no console surface: ${uncovered.join(", ")}.\nAdd a console page (a generic resource in src/resources/index.ts, or a bespoke page registered in src/App.tsx that calls the group's /admin/v1/<group> endpoints), or add a DELIBERATE_EXCLUSIONS entry in this file naming an owner and a SPECIFIC reason (see epic #313 acceptance box 1).`,
    ).toEqual([]);
  });

  it("fails when a new control-plane group has neither a surface nor an exclusion", () => {
    // The negative case: a synthetic group proves the gate is not vacuous,
    // without mutating the committed contract.
    const synthetic = [...contractGroups, "brand-new-thing"];
    expect(findUncoveredGroups(synthetic, consoleSurfaces, DELIBERATE_EXCLUSIONS)).toEqual([
      "brand-new-thing",
    ]);
    // ...and it passes again once the group is owned, either way.
    expect(
      findUncoveredGroups(synthetic, consoleSurfaces, {
        ...DELIBERATE_EXCLUSIONS,
        "brand-new-thing": { owner: "test", reason: "synthetic" },
      }),
    ).toEqual([]);
    const withSurface = new Map(consoleSurfaces).set("brand-new-thing", {
      kind: "bespoke-page",
      route: "/app/brand-new-thing",
      source: "brand-new-thing",
    });
    expect(findUncoveredGroups(synthetic, withSurface, DELIBERATE_EXCLUSIONS)).toEqual([]);
  });
});

describe("console coverage of tracked caller-facing groups (#474 acceptance box 1)", () => {
  const callerFacingSurfaces = resolveCallerFacingSurfaces();
  const callerFacingGroups = new Set(
    Object.keys(JSON.parse(readFileSync(specPath, "utf8")).paths ?? {})
      .map(callerFacingGroupOf)
      .filter((group): group is string => group !== undefined),
  );

  it("keeps every tracked group in the contract (the list cannot rot)", () => {
    for (const group of Object.keys(CALLER_FACING_TRACKED_GROUPS)) {
      expect(callerFacingGroups.has(group), `/v1/${group} is no longer in the contract`).toBe(true);
    }
  });

  it("gives every tracked caller-facing group a registered console surface", () => {
    for (const [group, tracked] of Object.entries(CALLER_FACING_TRACKED_GROUPS)) {
      const surface = callerFacingSurfaces.get(group);
      expect(
        surface,
        `caller-facing group /v1/${group} has no console surface (${tracked.why}). Add a bespoke page registered in src/App.tsx that calls its /v1/<group> endpoints, or delete the CALLER_FACING_TRACKED_GROUPS entry with a reviewed rationale.`,
      ).toBeDefined();
      expect(
        existsSync(path.join(pagesDir, `${(surface as NonNullable<typeof surface>).source}.tsx`)),
        `group /v1/${group} maps to missing page src/pages/${(surface as NonNullable<typeof surface>).source}.tsx`,
      ).toBe(true);
      expect(Object.values(APP_ROUTES)).toContain((surface as NonNullable<typeof surface>).route);
    }
  });

  it("resolves the #474 agent-jobs protocol to its own page", () => {
    expect(callerFacingSurfaces.get("agent-jobs")).toEqual({
      kind: "bespoke-page",
      route: APP_ROUTES.agentJobs,
      source: "agent-jobs",
    });
  });
});

describe("DELIBERATE_EXCLUSIONS hygiene", () => {
  it("gives every exclusion an owner and a specific, non-empty rationale", () => {
    for (const [group, exclusion] of Object.entries(DELIBERATE_EXCLUSIONS)) {
      expect(exclusion.owner.trim(), `exclusion ${group} has no owner`).not.toBe("");
      // Long enough that "n/a" or "not needed" cannot pass as review.
      expect(
        exclusion.reason.trim().length,
        `exclusion ${group} needs a real rationale, not a rubber stamp`,
      ).toBeGreaterThan(40);
    }
  });

  it("rejects an exclusion for a group the contract no longer has", () => {
    expect(findStaleExclusions(contractGroups, DELIBERATE_EXCLUSIONS)).toEqual([]);
    expect(
      findStaleExclusions(contractGroups, {
        ...DELIBERATE_EXCLUSIONS,
        "removed-group": { owner: "test", reason: "synthetic" },
      }),
    ).toEqual(["removed-group"]);
  });

  it("rejects an exclusion for a group that now HAS a console surface", () => {
    expect(findObsoleteExclusions(consoleSurfaces, DELIBERATE_EXCLUSIONS)).toEqual([]);
    const covered = [...consoleSurfaces.keys()][0];
    expect(
      findObsoleteExclusions(consoleSurfaces, {
        ...DELIBERATE_EXCLUSIONS,
        [covered]: { owner: "test", reason: "synthetic" },
      }),
    ).toEqual([covered]);
  });
});

describe("documented group -> surface renames", () => {
  it("matches the surface each renamed group actually resolves to", () => {
    for (const [group, expected] of Object.entries(EXPECTED_NON_IDENTITY_SURFACES)) {
      const surface = consoleSurfaces.get(group);
      expect(surface, `documented rename for ${group} has no surface`).toBeDefined();
      expect(surface?.source, `${group} -> ${expected.why}`).toBe(expected.source);
    }
  });

  it("only documents renames that are genuinely not the identity mapping", () => {
    // A group whose surface already matches its own name does not belong in the
    // rename table; keeping it there would make the table meaningless noise.
    const identity = Object.entries(EXPECTED_NON_IDENTITY_SURFACES)
      .filter(([group, expected]) => group === expected.source && !isRenamedRoute(group))
      .map(([group]) => group);
    expect(identity).toEqual([]);
  });
});

/** True when the route the surface mounts at is not `/app/<group>`. */
function isRenamedRoute(group: string): boolean {
  const surface = consoleSurfaces.get(group);
  return surface !== undefined && surface.route !== `/app/${group}`;
}
