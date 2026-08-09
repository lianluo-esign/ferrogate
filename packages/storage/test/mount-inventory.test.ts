/**
 * The anti-staleness gate for the mount inventory in `src/index.ts`.
 *
 * This package's history is the repo's dominant defect in miniature: the header
 * of `src/index.ts` asserted "THE DURABLE HALF OF THIS PACKAGE IS NOT MOUNTED ON
 * ANY WORKER … ZERO importers", and by the time anyone re-read it FIVE of the
 * named classes had been wired into `apps/gateway`, `apps/control-plane` and
 * `apps/mcp`. A prose marker cannot fail, so it rotted, in the direction that
 * makes a reader distrust the whole file.
 *
 * So the split is re-derived here from the actual source of `apps/` on every
 * run. It fails in BOTH directions, which is the point:
 *   - mount one of {@link DEAD} (good news) → red, and the marker must be
 *     corrected in the same commit;
 *   - unmount one of {@link MOUNTED} (the regression this repo keeps suffering)
 *     → red, exactly like deleting the wiring line.
 *
 * It is a grep, not a type check, but COMMENTS ARE STRIPPED FIRST. Without that
 * the gate would be vacuous in the direction that matters: every one of these
 * modules discusses the store it mounts in its own header, so renaming the
 * import binding — a real unmount — would leave the name behind in prose and the
 * test would happily stay green.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const appsRoot = path.resolve(here, "../../../apps");

/** Every TS file under each app's `src`, as one blob per app (tests excluded — a test may name anything). */
function appSources(): { app: string; text: string }[] {
  const apps = readdirSync(appsRoot).filter((name) =>
    statSync(path.join(appsRoot, name)).isDirectory(),
  );
  // A silently-empty scan would make every "dead" assertion pass for the wrong
  // reason — the exact vacuity this file exists to prevent. Fail here instead.
  if (apps.length === 0) throw new Error(`no apps found under ${appsRoot}`);
  return apps.flatMap((app) => {
    const src = path.join(appsRoot, app, "src");
    let files: string[];
    try {
      files = walk(src);
    } catch {
      return [];
    }
    return [
      { app, text: files.map((file) => stripComments(readFileSync(file, "utf8"))).join("\n") },
    ];
  });
}

/** Drop `/* … *\/` and `// …` so a mention in prose never counts as a mount. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

function walk(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return walk(full);
    return entry.name.endsWith(".ts") ? [full] : [];
  });
}

const SOURCES = appSources();

function importersOf(symbol: string): string[] {
  const pattern = new RegExp(`\\b${symbol}\\b`);
  return SOURCES.filter(({ text }) => pattern.test(text))
    .map(({ app }) => app)
    .sort();
}

/**
 * The comment-stripped blob for one app, or a throw that names it.
 *
 * `SOURCES.find(...)` is `… | undefined`, and `expect(found).toBeDefined()` does
 * not narrow it for the assertion on the next line — so the two rival-implementation
 * tests below used to bridge the gap with `!`, which `lint/style/noNonNullAssertion`
 * forbids. Narrowing here is the better shape anyway: if {@link appSources} ever
 * stops producing an app (renamed directory, `src/` moved, the `catch` above
 * swallowing a read error) the failure names the app and lists what WAS scanned,
 * instead of reading as "cannot read properties of undefined".
 */
function sourcesFor(app: string): string {
  const found = SOURCES.find((entry) => entry.app === app);
  if (found === undefined) {
    const scanned = SOURCES.map((entry) => entry.app).join(", ");
    throw new Error(`the apps/ scan produced no blob for apps/${app} (scanned: ${scanned})`);
  }
  return found.text;
}

/** Exports the `src/index.ts` header claims are LIVE, with the app that mounts them. */
const MOUNTED: [symbol: string, app: string][] = [
  ["EnvBindingTenantDatabaseRouter", "gateway"],
  // The other two apps that route per-tenant. The header named them; only the
  // gateway leg was gated, so `apps/control-plane` could have dropped the
  // router and this file would have stayed green — the exact silent-unmount
  // this file exists to catch, one app over. MCP intentionally uses its own
  // durable-object-only adapter because it does not serve native bindings.
  ["EnvBindingTenantDatabaseRouter", "control-plane"],
  // NOT `ControlDatabaseTenantRegistry`: comment-stripping showed that all three
  // of its "importers" were prose. It reaches the request path only INSIDE
  // `EnvBindingTenantDatabaseRouter`, which constructs one — a transitive mount,
  // which is a different (and weaker) claim than a direct one.
  ["D1WalletStore", "gateway"],
  ["D1WorkflowBudgetStore", "gateway"],
  ["D1UsageLedger", "gateway"],
  ["D1ReferenceGuardedDeletes", "control-plane"],
  // The development-only router remains an explicit gateway mount.
  ["SharedDatabaseTenantRouter", "gateway"],
  // WAVE 20 — moved up from `DEAD`, which is this gate working in its "good
  // news" direction: `apps/gateway/src/metering/budget-alerts.ts` imports the
  // class and constructs one as the `claims` port, so the once-per-period
  // arbiter behind budget-threshold alert delivery (cutover HOLD item A1) is
  // now a real mount. Keeping it in `DEAD` would have made the wave's own
  // suite red; keeping it in NEITHER list is the state that let five classes
  // rot. Unmounting it now reddens here as well as in
  // `apps/gateway/test/metering/budget-alerts.test.ts`.
  ["budgetAlertStoreForTenant", "gateway"],
  // #738 — the same "good news" direction, and the reason this gate is worth
  // its cost: `apps/control-plane/src/routes/site_domain.ts` constructs one to
  // project a completed DNS-TXT ownership proof into the typed
  // `site_domain_verifications` table that `apps/gateway`'s custom-domain
  // resolver joins. Before that the table had no writer anywhere, so a verified
  // hostname served nothing. Leaving the symbol in `DEAD` made THIS suite red on
  // the branch that mounted it, which is exactly the forcing function intended.
  ["D1SiteDomainVerificationStore", "control-plane"],
  // #744 — the scheduled gateway sweep owns tenant enumeration and uses the
  // package executor against each tenant object.
  ["D1RetentionPolicyStore", "gateway"],
  ["R2AssetBlobStore", "gateway"],
  // #822 — `TenantDataObject`, and the only entry in this list whose unmount is
  // not merely a dead export but an UNBOOTABLE WORKER. workerd resolves the
  // `[[durable_objects.bindings]] class_name = "TenantDataObject"` stanza in
  // `apps/gateway/wrangler.toml` against the ENTRY module's named exports, so
  // deleting the re-export from `apps/gateway/src/worker.ts` stops the gateway
  // starting — and `@cloudflare/vitest-pool-workers` does not run that check, so
  // every gateway suite stays green. This gate and
  // `apps/gateway/test/wrangler-bindings.test.ts` are the two places that fail
  // instead. Reached from `apps/gateway/src/tenancy/tenant-data.ts` as well,
  // which is where `env.TENANT_DATA.idFromName(tenantId)` is issued.
  ["TenantDataObject", "gateway"],
  // #859 — the D1-shaped facade is now used by the gateway request-log writer
  // and by AgentRunState's cross-script evidence writer. It remains a facade,
  // not a second storage authority: both call the same TenantDataObject RPC.
  ["DurableObjectD1Database", "gateway"],
  ["DurableObjectD1Database", "agent-runtime"],
  // #819 — MOVED UP FROM `DEAD`, which is the transition that entry was written
  // to force. `apps/gateway/src/tenancy/resolver.ts` constructs one on the
  // `durable_object` branch, and that branch is now the DEFAULT
  // (`GATEWAY_TENANT_DB_ROUTING = "durable_object"` in the committed
  // `wrangler.toml`), so unmounting it takes every tenant's storage with it.
  //
  // The D1-shaped facade moved into the direct gateway and agent-runtime
  // evidence paths in #859, so those mounts are asserted above. The router
  // still constructs the same facade transitively for other tenant stores.
  ["DurableObjectTenantDatabaseRouter", "gateway"],
  // #820's follow-up: `apps/control-plane` provisions every new tenant onto a
  // Durable Object but resolved its own tenant-DATA paths through
  // `EnvBindingTenantDatabaseRouter`, which cannot reach one. Unmounting this
  // puts that back — an admin wallet credit that writes no `wallets` row and a
  // fleet asset view that reports an empty fleet, both with every test green,
  // which is precisely the failure class this file exists for.
  ["BackendDispatchingTenantDatabaseRouter", "control-plane"],
  ["DurableObjectTenantDatabaseRouter", "control-plane"],
  // #856 — tenant-object schedules use the package store and its transaction
  // backed at-most-once claim gate.
  ["D1AgentScheduleStore", "control-plane"],
];

/** Exports the `src/index.ts` header claims are DEAD: no app names them at all. */
const DEAD = ["D1BillingEventLedger", "TenantMonotonicUpserts", "ControlMonotonicUpserts"];

describe("mount inventory (src/index.ts §1.7 marker)", () => {
  test("the app scan is not empty (a vacuous scan would pass everything)", () => {
    expect(SOURCES.length).toBeGreaterThan(3);
    expect(SOURCES.every(({ text }) => text.length > 0)).toBe(true);
  });

  test.each(MOUNTED)("%s is still mounted, in apps/%s", (symbol, app) => {
    expect(importersOf(symbol)).toContain(app);
  });

  test.each(DEAD)("%s is still dead — no app mounts it", (symbol) => {
    expect(importersOf(symbol)).toEqual([]);
  });

  // The native/compatibility path still has a rival scheduler. The typed
  // tenant-object path is asserted as a real package-store mount above.
  test("apps/control-plane still carries a rival schedule engine", () => {
    expect(sourcesFor("control-plane")).toContain("parseCronExpression");
    expect(importersOf("D1AgentScheduleStore")).toContain("control-plane");
  });

  test("apps/gateway still carries an app-local asset metadata store", () => {
    expect(sourcesFor("gateway")).toContain("class D1AssetMetadataStore");
    expect(importersOf("R2AssetBlobStore")).toContain("gateway");
  });
});
