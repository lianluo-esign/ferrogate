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

/** Exports the `src/index.ts` header claims are LIVE, with the app that mounts them. */
const MOUNTED: [symbol: string, app: string][] = [
  ["EnvBindingTenantDatabaseRouter", "gateway"],
  // The other two apps that route per-tenant. The header named them; only the
  // gateway leg was gated, so `apps/control-plane` or `apps/mcp` could have
  // dropped the router and this file would have stayed green — the exact
  // silent-unmount this file exists to catch, one app over.
  ["EnvBindingTenantDatabaseRouter", "control-plane"],
  ["EnvBindingTenantDatabaseRouter", "mcp"],
  // NOT `ControlDatabaseTenantRegistry`: comment-stripping showed that all three
  // of its "importers" were prose. It reaches the request path only INSIDE
  // `EnvBindingTenantDatabaseRouter`, which constructs one — a transitive mount,
  // which is a different (and weaker) claim than a direct one.
  ["D1WalletStore", "gateway"],
  ["D1WorkflowBudgetStore", "gateway"],
  ["D1UsageLedger", "gateway"],
  ["D1ReferenceGuardedDeletes", "control-plane"],
  // The two OTHER routers, both live in `apps/gateway/src/tenancy/resolver.ts`
  // and both previously absent from this gate AND from the `src/index.ts`
  // inventory — so they were neither claimed live nor claimed dead, which is
  // the state in which a mount disappears without anything noticing.
  ["NonAtomicD1RestTenantDatabaseRouter", "gateway"],
  ["SharedDatabaseTenantRouter", "gateway"],
];

/** Exports the `src/index.ts` header claims are DEAD: no app names them at all. */
const DEAD = [
  "D1BillingEventLedger",
  "D1BudgetAlertStore",
  "D1RetentionPolicyStore",
  "D1AgentScheduleStore",
  "D1SiteDomainVerificationStore",
  "TenantMonotonicUpserts",
  "ControlMonotonicUpserts",
  "R2AssetBlobStore",
];

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

  // The two duplications the marker calls out by name. These assert the RIVAL
  // implementation exists and does NOT go through this package: if someone
  // finally deletes the duplicate and imports the engine here, this reddens and
  // the marker comes out with it.
  test("apps/control-plane still carries a rival schedule engine", () => {
    const controlPlane = SOURCES.find(({ app }) => app === "control-plane");
    expect(controlPlane).toBeDefined();
    expect(controlPlane!.text).toContain("parseCronExpression");
    expect(importersOf("D1AgentScheduleStore")).toEqual([]);
  });

  test("apps/gateway still carries an app-local asset metadata store", () => {
    const gateway = SOURCES.find(({ app }) => app === "gateway");
    expect(gateway).toBeDefined();
    expect(gateway!.text).toContain("class D1AssetMetadataStore");
    expect(importersOf("R2AssetBlobStore")).toEqual([]);
  });
});
