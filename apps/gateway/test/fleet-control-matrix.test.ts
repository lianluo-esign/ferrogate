/**
 * THE FLEET CONTROL MATRIX — the same question as `./fleet-consistency.test.ts`,
 * asked MECHANICALLY.
 *
 * ## Why a second fleet file exists
 *
 * `./fleet-consistency.test.ts` is the wave-21 LEDGER: it records the measured
 * state of each finding as an exact table (`expect(appsMatching(x)).toEqual([
 * "gateway"])`) and goes red in both directions, which is what forces the
 * document and the code to move together. That is the right shape for a
 * finding. It is the wrong shape for a CLASS, for one reason:
 *
 * > every table in it is a HAND-WRITTEN list of Workers, and a hand list is
 * > correct exactly until someone adds a Worker or adds a control.
 *
 * Wave 21 enumerated 23 capabilities and found 5 divergences BY INSPECTION.
 * Inspection does not survive the next refactor. This file is the gate that
 * does: nothing below names which Workers enforce anything. The fleet, the role
 * sets, the source-of-truth class of every control on every Worker, and the
 * whole refusal table are all COMPUTED from `apps/{*}/src/**` and
 * `apps/{*}/wrangler.toml`, and the assertions are PROPERTIES over those
 * computations.
 *
 * The practical difference: add a sixth Worker that spends, and every control
 * in §3 immediately requires it without anyone editing this file. Add a
 * seventh refusal code shared by two Workers, and §4 immediately requires the
 * two to agree on its status and its wording. Point one Worker's control at a
 * private source of truth, and §3.3 fails naming the cell.
 *
 * ## The defect class, and the one search key that finds it
 *
 * A CONTROL an operator applies in one place that does not apply everywhere it
 * is enforced. It has shipped three times — the wave-16 admission bypass, the
 * wave-20 agent-upstream half-withdrawal, and the three wave-21 findings — and
 * every one was invisible to per-Worker suites because **each Worker was
 * individually correct**. The shape all of them share, stated once:
 *
 * > **a control that is DURABLE on one Worker and VAR-ONLY or IN-MEMORY on
 * > another.**
 *
 * §3.3 is that sentence as an assertion, evaluated for every control in the
 * registry against every Worker that enforces it, with the class DERIVED (from
 * the SQL a Worker actually issues and the vars it actually reads) rather than
 * declared.
 *
 * ## What the registry in §3 does and does not contain
 *
 * It contains, per control, only TOKENS: the durable authority (a table name or
 * a `resource_kind`), the deploy-time var, the in-memory fallback, the
 * enforcement point (a quoted refusal code or an engine call), and WHICH ROLE
 * SET must enforce it — where the role set itself is computed in §2. It
 * contains no list of Workers, no expected verdict and no recorded matrix.
 * Every assertion in §3 is uniform across all rows: the same five properties
 * are demanded of every control, so a new control gets a real gate by adding
 * five tokens, and a stale token fails §3.1 rather than passing vacuously.
 *
 * ## Source-text, and why that is forced
 *
 * The five Workers are separately bundled and no app may import another's
 * module graph — `wrangler deploy` would reject the coupling and the package
 * boundaries forbid it. Reading the other Workers as TEXT through `?raw` is the
 * only way a workerd test with no filesystem can see them at all; it is the
 * technique `./admission-consistency.test.ts`, `./env-var-drift.test.ts` and
 * `./fleet-consistency.test.ts` already use. §5 is the exception and is
 * behavioural through `SELF`.
 *
 * Every probe runs against COMMENT-STRIPPED source, because a comment claiming
 * a control is enforced is exactly how FC-2 hid (`apps/agent-runtime`'s auth
 * middleware states the lifecycle ladder is "already here"; it is not). §1
 * proves the stripper preserves code before any probe runs, and proves it
 * WITHOUT a per-Worker canary list — see {@link EXPORT_AT_COLUMN_ZERO}.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { DRAIN_VAR } from "../src/routes/readiness.js";

declare global {
  interface ImportMeta {
    glob(pattern: string, options: object): Record<string, string>;
  }
}

// ---------------------------------------------------------------------------
// §0  DISCOVERY — the fleet is found, never listed
// ---------------------------------------------------------------------------

/**
 * Every `apps/{name}/src/**\/*.ts` in the repository, keyed by path.
 *
 * The `*` in the APP position is the point: `./fleet-consistency.test.ts` globs
 * five explicit app directories, so a sixth Worker is invisible to it until
 * someone edits the file. Here a sixth Worker appears in this map the moment it
 * has a `src/`, joins whichever role sets §2 computes it into, and is held to
 * every control in §3 that those roles require.
 */
const ALL_SRC = import.meta.glob("../../*/src/**/*.ts", {
  query: "?raw",
  import: "default",
  eager: true,
});

/** Every `apps/{name}/wrangler.toml`. Having one is what makes an app a WORKER. */
const ALL_TOML = import.meta.glob("../../*/wrangler.toml", {
  query: "?raw",
  import: "default",
  eager: true,
});

/**
 * `../../mcp/src/ports.ts` → `mcp`; `../src/ports.ts` → `gateway`.
 *
 * Vite NORMALISES glob keys, so this Worker's own matches come back collapsed
 * (`../wrangler.toml`, not `../../gateway/wrangler.toml`). Resolving properly
 * against this file's own directory is what keeps the host Worker in the fleet
 * — a naive prefix match would silently drop `apps/gateway` from every table
 * below, and a fleet consistency gate blind to one Worker is worse than none.
 */
const HERE: readonly string[] = ["apps", "gateway", "test"];

function appOf(path: string): string {
  const segments = [...HERE];
  for (const part of path.split("/")) {
    if (part === "." || part === "") continue;
    if (part === "..") segments.pop();
    else segments.push(part);
  }
  if (segments[0] !== "apps" || segments.length < 3) {
    throw new Error(`fleet-control-matrix: unparseable glob key ${path} → ${segments.join("/")}`);
  }
  return segments[1] as string;
}

/**
 * The DEPLOYED fleet: apps that ship a `wrangler.toml` AND have TypeScript
 * source. `apps/cli` is excluded by that rule rather than by name — it is a
 * command-line client, not a Worker, and it has no `wrangler.toml`.
 */
const FLEET: readonly string[] = Object.keys(ALL_TOML)
  .map(appOf)
  .filter((app) => Object.keys(ALL_SRC).some((path) => appOf(path) === app))
  .sort();

/**
 * Remove block comments and whole-line `//` / ` *` comments.
 *
 * Identical to the stripper `./fleet-consistency.test.ts` uses, deliberately:
 * conservative, never touching the tail of a line that has code on it, so a
 * `"https://…"` inside a string literal survives intact.
 */
function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .filter((line) => !/^\s*(\/\/|\*)/.test(line))
    .join("\n");
}

/** TOML: drop `#` comment lines, leaving only the stanzas that DEPLOY. */
function stripTomlComments(source: string): string {
  return source
    .split("\n")
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");
}

interface Module {
  readonly path: string;
  /** Comment-stripped. Everything in §2-§4 reads this. */
  readonly code: string;
  /** As committed. Only §1 reads this, to prove the stripper kept the code. */
  readonly raw: string;
}

const CODE: Record<string, readonly Module[]> = Object.fromEntries(
  FLEET.map((app) => [
    app,
    Object.entries(ALL_SRC)
      .filter(([path]) => appOf(path) === app)
      .map(([path, raw]) => {
        if (typeof raw !== "string" || raw.length === 0) {
          throw new Error(`fleet-control-matrix: ${path} inlined empty`);
        }
        return { path, code: stripComments(raw), raw };
      }),
  ]),
);

const TOML: Record<string, { readonly live: string; readonly full: string }> = Object.fromEntries(
  FLEET.map((app) => {
    const entry = Object.entries(ALL_TOML).find(([path]) => appOf(path) === app);
    const full = (entry as [string, string])[1];
    return [app, { live: stripTomlComments(full), full }];
  }),
);

/** The Workers whose comment-stripped code matches `probe`, in fleet order. */
function appsMatching(probe: RegExp): string[] {
  return FLEET.filter((app) => CODE[app]?.some((m) => probe.test(m.code)));
}

/** The files on one Worker that match `probe` — makes a failure legible. */
function filesMatching(app: string, probe: RegExp): string[] {
  return (CODE[app] ?? []).filter((m) => probe.test(m.code)).map((m) => m.path);
}

// ---------------------------------------------------------------------------
// §0.1  DURABLE READS — every SQL table each Worker actually issues
// ---------------------------------------------------------------------------

/**
 * `const RESOURCE_TABLE = "control_plane_resources"` → `RESOURCE_TABLE` ↦
 * `control_plane_resources`, per Worker.
 *
 * Needed because the fleet interpolates its table names
 * (`FROM ${RESOURCE_TABLE}`), so a naive text scan for `FROM tenants` finds the
 * gateway and MISSES `apps/mcp` and `apps/agent-runtime`, which read the same
 * table through a constant. A classifier that mis-reads a durable read as
 * absent would invent divergences that are not there, and a gate that cries
 * wolf gets deleted.
 */
function constantTable(app: string): ReadonlyMap<string, string> {
  const out = new Map<string, string>();
  for (const module of CODE[app] ?? []) {
    for (const m of module.code.matchAll(
      /\b(?:const|let)\s+([A-Z][A-Z0-9_]*)\s*(?::\s*string\s*)?=\s*"([a-z0-9_]+)"/g,
    )) {
      out.set(m[1] as string, m[2] as string);
    }
  }
  return out;
}

/**
 * The set of TABLES a Worker reads or writes, resolved through its constants.
 *
 * Extracted from SQL STRING LITERALS only — a backtick or double-quoted literal
 * that contains `SELECT` / `INSERT INTO` / `UPDATE` / `DELETE FROM` — and never
 * from prose. Scanning free text for `FROM x` picks up English ("the answer
 * FROM here"), and a table set polluted with `here`, `of` and `its` makes §4's
 * ratchet unreadable and therefore ignorable.
 */
/** The SQL statements one module contains, as text. */
function sqlLiteralsOf(code: string): readonly string[] {
  return [
    ...[...code.matchAll(/`([^`]*)`/g)].map((m) => m[1] as string),
    ...[...code.matchAll(/"((?:SELECT|INSERT INTO|UPDATE|DELETE FROM)[^"]*)"/gi)].map(
      (m) => m[1] as string,
    ),
  ].filter((literal) => /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b/i.test(literal));
}

function tablesOf(app: string): ReadonlySet<string> {
  const constants = constantTable(app);
  const out = new Set<string>();
  for (const module of CODE[app] ?? []) {
    for (const literal of sqlLiteralsOf(module.code)) {
      for (const m of literal.matchAll(
        /\b(?:FROM|INTO|UPDATE|JOIN)\s+(?:\$\{(\w+)\}|([a-z_][a-z0-9_]*))/gi,
      )) {
        const name = m[1] !== undefined ? constants.get(m[1]) : (m[2] as string).toLowerCase();
        // `UPDATE … SET` — `SET` is a keyword, never a table.
        if (name === undefined || name === "set") continue;
        out.add(name);
      }
    }
  }
  return out;
}

/** The SQL each Worker issues in its OWN source. */
const OWN_SQL_TABLES: Record<string, ReadonlySet<string>> = Object.fromEntries(
  FLEET.map((app) => [app, tablesOf(app)]),
);

/** Every table name any Worker issues SQL against — the fleet's SQL vocabulary. */
const TABLE_VOCABULARY: ReadonlySet<string> = new Set(
  FLEET.flatMap((app) => [...(OWN_SQL_TABLES[app] ?? [])]),
);

/**
 * Evidence, in one module, that this file talks to a control DATABASE — as
 * opposed to naming a table in a string for some other reason.
 */
const DATABASE_EVIDENCE = /\.prepare\(|\bCONTROL_DB\b|\benv\.DB\b|D1Database/;

/**
 * The set of tables a Worker resolves a control from, SQL issued here or not.
 *
 * The second clause exists because a correct fix can move the statement out of
 * the Worker. `apps/mcp` and `apps/agent-runtime` resolve the activated
 * guardrail revision through `@ferrogate/guardrails`, so the `SELECT` lives in
 * `packages/`, and a scan of `apps/{*}/src` alone would score both Workers
 * VAR-ONLY — inventing the exact divergence this file exists to detect, on the
 * commit that CLOSES it. A gate that cries wolf on a fix is a gate that gets
 * deleted.
 *
 * Scanning `packages/` instead is not the answer and would be worse: every
 * Worker that IMPORTS a package would score durable whether or not it mounts
 * the port, and "a module that exists and is not wired" is this repository's
 * dominant defect. So the evidence demanded here is on the WORKER: it names the
 * authority table as a literal, in a file that also evidences a control-database
 * read. Prose cannot satisfy it — every probe runs on comment-stripped source —
 * and the table must already be in the fleet's own SQL vocabulary, so an
 * invented name proves nothing.
 */
function durableTablesOf(app: string): ReadonlySet<string> {
  const out = new Set(OWN_SQL_TABLES[app] ?? []);
  for (const module of CODE[app] ?? []) {
    if (!DATABASE_EVIDENCE.test(module.code)) continue;
    // A module that issues its OWN SQL is scored on that SQL and nothing else.
    // Without this, a module could point its `SELECT` at a private table while
    // an untouched `const X_TABLE = "…"` next to it kept the old name — the
    // statement moves, the constant stays, and the Worker still scores durable
    // against an authority it no longer reads. Only a module that DELEGATES its
    // read (no SQL of its own) is scored on the authority it names.
    if (sqlLiteralsOf(module.code).length > 0) continue;
    for (const m of module.code.matchAll(/"([a-z_][a-z0-9_]*)"/g)) {
      const name = m[1] as string;
      if (TABLE_VOCABULARY.has(name)) out.add(name);
    }
  }
  return out;
}

const TABLES: Record<string, ReadonlySet<string>> = Object.fromEntries(
  FLEET.map((app) => [app, durableTablesOf(app)]),
);

/** Which Workers resolve a control from `table`. */
function appsReadingTable(table: string): string[] {
  return FLEET.filter((app) => TABLES[app]?.has(table));
}

// ---------------------------------------------------------------------------
// §0.2  THE REFUSAL TABLE — every (status, code, message) the fleet can emit
// ---------------------------------------------------------------------------

/**
 * The three spellings a refusal takes in this repo, scanned SEPARATELY.
 *
 * `STATUS_SHAPE` and `MESSAGE_SHAPE` both read the ladder tables
 * (`{ status: 429, code: "…", message: … }`) but are two regexes rather than
 * one deliberately: the `message` field is written three different ways
 * (`"literal"`, `() => "literal"`, `(limit: number) => \`template\``) and a
 * single pattern with an optional trailing group silently prefers the SHORTEST
 * match, capturing no message at all. That is not a cosmetic bug in a
 * consistency gate — it makes every wording assertion vacuous on the Workers
 * whose tables use the arrow form, which is most of them.
 *
 * `THROW_SHAPE` is the direct `new HttpError(503, "node_draining", MESSAGE)` a
 * middleware raises. It is needed for the same reason: the wave-16 ladder is
 * entirely the record form and the drain gate is entirely the throw form, so a
 * scan that saw only one would have a blind spot shaped exactly like one of the
 * shipped defects.
 */
const STATUS_SHAPE = /status:\s*(\d{3}),\s*code:\s*"([a-z_]+)"/g;
const MESSAGE_SHAPE =
  /code:\s*"([a-z_]+)",\s*message:\s*(?:\([^)]*\)\s*(?::\s*[\w<>[\]| ]+\s*)?=>\s*)?(`[^`]*`|"[^"]*")/g;
const THROW_SHAPE = /HttpError\(\s*(\d{3}),\s*"([a-z_]+)",\s*(`[^`]*`|"[^"]*"|[A-Z][A-Z0-9_]*)/g;

/**
 * `const NODE_DRAINING_MESSAGE = "gateway node is draining…"` per Worker.
 *
 * The throw form usually names a CONSTANT rather than inlining the sentence —
 * which is good practice and would make the wording invisible to a literal-only
 * scan, so the constant is resolved. `NODE_DRAINING_MESSAGE` is the case that
 * matters: three Workers now refuse a drained deployment and an operator greps
 * for that exact sentence.
 */
function stringConstants(app: string): ReadonlyMap<string, string> {
  const out = new Map<string, string>();
  for (const module of CODE[app] ?? []) {
    for (const m of module.code.matchAll(
      /\b(?:const|let)\s+([A-Z][A-Z0-9_]*)\s*(?::\s*string\s*)?=\s*\n?\s*"([^"]*)"/g,
    )) {
      out.set(m[1] as string, m[2] as string);
    }
  }
  return out;
}

const STRINGS: Record<string, ReadonlyMap<string, string>> = Object.fromEntries(
  FLEET.map((app) => [app, stringConstants(app)]),
);

/** `code` ↦ Worker ↦ the statuses that Worker spells it with. */
const STATUS_INDEX = new Map<string, Map<string, Set<number>>>();
/** `code` ↦ Worker ↦ the message texts that Worker uses for it. */
const MESSAGE_INDEX = new Map<string, Map<string, Set<string>>>();

function record<T>(
  index: Map<string, Map<string, Set<T>>>,
  code: string,
  app: string,
  value: T,
): void {
  const byApp = index.get(code) ?? new Map<string, Set<T>>();
  const values = byApp.get(app) ?? new Set<T>();
  values.add(value);
  byApp.set(app, values);
  index.set(code, byApp);
}

for (const app of FLEET) {
  for (const module of CODE[app] ?? []) {
    for (const m of module.code.matchAll(new RegExp(STATUS_SHAPE.source, "g"))) {
      record(STATUS_INDEX, m[2] as string, app, Number(m[1]));
    }
    for (const m of module.code.matchAll(new RegExp(MESSAGE_SHAPE.source, "g"))) {
      record(MESSAGE_INDEX, m[1] as string, app, (m[2] as string).slice(1, -1));
    }
    for (const m of module.code.matchAll(new RegExp(THROW_SHAPE.source, "g"))) {
      const code = m[2] as string;
      record(STATUS_INDEX, code, app, Number(m[1]));
      const literal = m[3] as string;
      const text =
        literal.startsWith('"') || literal.startsWith("`")
          ? literal.slice(1, -1)
          : STRINGS[app]?.get(literal);
      if (text !== undefined) record(MESSAGE_INDEX, code, app, text);
    }
  }
}

const REFUSAL_INDEX: ReadonlyMap<string, ReadonlyMap<string, ReadonlySet<number>>> = STATUS_INDEX;

/** Total refusal declarations found, for the non-vacuity guard. */
const REFUSAL_COUNT = [...STATUS_INDEX.values()].reduce(
  (n, byApp) => n + [...byApp.values()].reduce((m, s) => m + s.size, 0),
  0,
);

// ---------------------------------------------------------------------------
// §1  THE SCAN IS REAL — non-vacuity, with no hand-written canary list
// ---------------------------------------------------------------------------

/**
 * The mechanical vacuity guard: a line beginning `export ` in COLUMN ZERO.
 *
 * Several tables computed above are legitimately empty for some Workers, so a
 * glob that silently resolved to nothing — or a `stripComments` that ate string
 * literals — would let this whole file pass while reading no code. That is the
 * failure mode `./fleet-consistency.test.ts` guards with a per-Worker canary
 * TOKEN, which is itself a hand list that rots.
 *
 * This is the same guard without the list. A comment line never starts at
 * column zero with `export ` (block-comment bodies are indented and prefixed
 * `*`, line comments start `//`), so the count is a pure measure of top-level
 * code — and it must be IDENTICAL before and after stripping, on every Worker.
 * A stripper regression drops the count; a glob that resolved to nothing drops
 * it to zero. Either is red here, ahead of every probe below.
 */
const EXPORT_AT_COLUMN_ZERO = /^export /gm;

function countExports(text: string): number {
  return (text.match(EXPORT_AT_COLUMN_ZERO) ?? []).length;
}

describe("§1 the scan is real", () => {
  it("discovered the deployed fleet from wrangler.toml, not from a list", () => {
    // Five Workers today. Asserted as a FLOOR, not an equality: a sixth Worker
    // must not fail here — it must fail in §3, where the controls it is missing
    // are named. An equality would train the next person to edit the number.
    expect(FLEET.length, `discovered fleet: ${FLEET.join(", ")}`).toBeGreaterThanOrEqual(5);
    expect(
      FLEET,
      "apps/cli has no wrangler.toml and must not be treated as a Worker",
    ).not.toContain("cli");
  });

  it("globbed real source for every discovered Worker", () => {
    for (const app of FLEET) {
      expect(CODE[app]?.length, `${app} module count`).toBeGreaterThan(9);
    }
  });

  it("comment stripping preserves every line of top-level code, on every Worker", () => {
    for (const app of FLEET) {
      const raw = (CODE[app] ?? []).reduce((n, m) => n + countExports(m.raw), 0);
      const stripped = (CODE[app] ?? []).reduce((n, m) => n + countExports(m.code), 0);
      expect(raw, `${app} exports its own modules`).toBeGreaterThan(50);
      expect(stripped, `${app}: stripComments is eating code (${raw} → ${stripped})`).toBe(raw);
    }
  });

  it("does NOT see a control that only a comment claims", () => {
    // The measurement that justifies stripping at all, kept mechanical: for
    // EVERY Worker, no refusal code may be produced by prose alone. The scan
    // runs on stripped text, so a Worker whose only occurrence of a refusal
    // code is inside a docblock contributes nothing — which is exactly how
    // FC-2 hid, in `apps/agent-runtime/src/middleware/auth.ts`, where the
    // lifecycle ladder is asserted in a paragraph and absent from the code.
    const claimedOnlyInProse = FLEET.flatMap((app) =>
      [...REFUSAL_INDEX.keys()]
        .filter(
          (code) =>
            !REFUSAL_INDEX.get(code)?.has(app) &&
            (CODE[app] ?? []).some((m) => m.raw.includes(code) && !m.code.includes(code)),
        )
        .map((code) => `${app} names ${code} only in prose`),
    );
    // Recorded, not forbidden: prose may legitimately discuss another Worker's
    // refusal. The assertion is that the SCAN did not count it.
    for (const claim of claimedOnlyInProse) {
      const [app, , code] = claim.split(" ") as [string, string, string];
      expect(REFUSAL_INDEX.get(code)?.has(app) ?? false, claim).toBe(false);
    }
    expect(
      REFUSAL_COUNT,
      "the refusal scan found nothing — all three shapes went stale",
    ).toBeGreaterThan(80);
    // The MESSAGE scan is asserted separately, because it is the half that goes
    // silently vacuous: a status can be captured while every wording is missed,
    // and a wording assertion over an empty set passes.
    expect(
      MESSAGE_INDEX.size,
      "no refusal wording was captured — every wording assertion is vacuous",
    ).toBeGreaterThan(40);
  });

  it("resolved a real table set for every Worker that touches a database", () => {
    const withTables = FLEET.filter((app) => (TABLES[app]?.size ?? 0) > 0);
    expect(withTables.length, "no Worker issues SQL — the literal scan went stale").toBeGreaterThan(
      3,
    );
    // The interpolated form specifically: if constant resolution broke, this
    // set collapses to the gateway alone and every §3 class turns to `var`,
    // manufacturing divergences that do not exist.
    expect(
      appsReadingTable("control_plane_resources").length,
      "constant-interpolated table names stopped resolving",
    ).toBeGreaterThan(2);
  });
});

// ---------------------------------------------------------------------------
// §2  ROLE SETS — computed from what a Worker DOES, never declared
// ---------------------------------------------------------------------------

/**
 * A Worker that resolves a TENANT CREDENTIAL. Probe: it can answer `401
 * invalid_api_key`, which only a credential resolver has any reason to.
 */
const CREDENTIAL: readonly string[] = appsMatching(/"invalid_api_key"/);

/**
 * A Worker that admits SPEND-PRODUCING work off that credential. Probe: it
 * carries the wave-16 admission ladder, whose first rung is `403
 * quota_scope_disabled`.
 *
 * This is the set every "stop spending" control has to reach to mean what an
 * operator thinks it means, and computing it is what makes §3 survive a sixth
 * Worker: a new app that ports the ladder joins SPEND automatically and is
 * immediately required to honour the drain, the suspension and the quota.
 */
const SPEND: readonly string[] = appsMatching(/"quota_scope_disabled"/);

/**
 * A Worker that SCREENS tenant content through a guardrail detector. Probe: it
 * calls a detector, in either of the two calling conventions the fleet uses
 * (`ports.guardrails.inspectInput(…)` / `deps.guardrails.evaluate(…)` on the
 * two agent surfaces, `screen…(…)` / `GuardrailEngine` on the gateway).
 *
 * Deliberately NOT "has a module with `guardrail` in the path": that would
 * sweep in `apps/control-plane`, which AUTHORS policy and screens nothing.
 * Requiring the writer to also be an enforcer is how a consistency gate starts
 * manufacturing findings.
 */
const SCREENING: readonly string[] = appsMatching(
  /\bguardrails\.\w+\(|screen[A-Z]\w*\(|GuardrailEngine/,
);

const ROLES: Record<string, readonly string[]> = {
  credential: CREDENTIAL,
  spend: SPEND,
  screening: SCREENING,
};

describe("§2 the role sets are derived from behaviour", () => {
  it("every Worker that spends also resolves a credential", () => {
    // The framing guard. A Worker that runs the admission ladder without
    // resolving a credential would be charging counters against nothing, and a
    // Worker outside CREDENTIAL is outside every credential-scoped control in
    // §3 — which is how one would escape the matrix quietly.
    for (const app of SPEND) {
      expect(CREDENTIAL, `${app} admits spend but resolves no credential`).toContain(app);
    }
  });

  it("every role set is non-empty and smaller than the fleet", () => {
    // Non-vacuity for §3: a role probe that matched nothing would make every
    // coverage assertion `[] ⊆ anything` and pass while proving nothing. A
    // probe that matched EVERYTHING (including `apps/telemetry`, which owns no
    // tenant state) would be equally wrong in the other direction.
    for (const [name, apps] of Object.entries(ROLES)) {
      expect(apps.length, `role ${name} matched no Worker`).toBeGreaterThan(0);
      expect(apps.length, `role ${name} matched the whole fleet`).toBeLessThan(FLEET.length);
    }
  });

  it("the collector Worker is in no tenant-control role", () => {
    // `apps/telemetry` authenticates ONE operator-issued collector token and
    // owns no tenant state, so a control that restricts a TENANT has nothing to
    // apply to there. Saying so mechanically is the honest half of this audit:
    // a consistency requirement invented between Workers that never shared a
    // concern is noise, and noise trains readers to skip the file.
    for (const [name, apps] of Object.entries(ROLES)) {
      expect(apps, `telemetry was swept into role ${name}`).not.toContain("telemetry");
    }
  });
});

// ---------------------------------------------------------------------------
// §3  THE CONTROL REGISTRY — tokens in, properties out
// ---------------------------------------------------------------------------

/** How a Worker resolves a control. The whole finding is in this union. */
type SourceClass = "durable" | "var" | "in-memory" | "none";

interface FleetControl {
  /** Stable id, used in failure messages and in FLEET-CONSISTENCY.md. */
  readonly id: string;
  readonly title: string;
  /**
   * Which computed role set MUST enforce this control, or `"self"` for a
   * control that is not fleet-mandatory but must AGREE wherever it is present
   * (the agent-upstream catalog is the example: only two Workers can reach an
   * upstream, and both must reach the same rows).
   */
  readonly required: keyof typeof ROLES | "self";
  /** Where the control is ENFORCED — a quoted refusal code or an engine call. */
  readonly enforcement: RegExp;
  /** Durable authority: table names, resolved through each Worker's constants. */
  readonly authorityTables: readonly string[];
  /** Durable authority that is a `resource_kind` rather than a table. */
  readonly authorityText?: RegExp;
  /** Deploy-time var resolution — `wrangler deploy` is the only way to change it. */
  readonly deployVar?: RegExp;
  /** In-memory / dev-table resolution — nothing outside the isolate can change it. */
  readonly devTable?: RegExp;
  /** The refusal code whose wire contract must agree across enforcers. */
  readonly refusalCode?: string;
  /** Non-empty when this row is expected RED until a named fix lands. */
  readonly pending?: string;
}

/**
 * The eight controls an operator applies.
 *
 * Every field is a TOKEN. There is no Worker named anywhere in this table and
 * no expected verdict: §3.1-§3.5 compute both. Adding a control is five tokens;
 * getting one of them wrong fails §3.1 rather than passing vacuously.
 */
const CONTROLS: readonly FleetControl[] = [
  {
    id: "admission",
    title: "the wave-16 admission ladder (quota scope, budget, wallet, RPM)",
    required: "spend",
    enforcement: /"quota_scope_disabled"/,
    authorityTables: ["quota_policies", "wallets", "usage_monthly_rollups"],
    deployVar: /FG_DEV_QUOTA_POLICIES|GATEWAY_QUOTA_POLICIES/,
    refusalCode: "quota_scope_disabled",
  },
  {
    id: "tenant-lifecycle",
    title: "operator suspension of a tenant (FC-2)",
    required: "spend",
    enforcement: /"tenancy_suspended"/,
    authorityTables: [],
    // ONE authority in TWO durable representations, and both must count.
    //
    // The `tenants` table is read by every credential Worker; the CONTROL is
    // its `status` COLUMN, and only a lifecycle lookup selects it — probing the
    // table alone would report the fleet consistent, which is exactly how FC-2
    // survived a matrix built on tables. `apps/control-plane` holds the same
    // authority as the `tenant-accounts` / `projects` / `workspaces` documents
    // an operator PATCHes, which `CollectionSpec.project` writes through into
    // the typed row the data plane reads. Counting only one spelling would
    // misclassify the writer as var-only and manufacture a divergence.
    authorityText:
      /\bstatus\b[^;]{0,200}\bFROM\s+(?:\$\{[A-Z_]*TENANTS?[A-Z_]*\}|tenants)\b|TENANT_ACCOUNTS_COLLECTION\s*=\s*"tenant-accounts"/is,
    devTable: /FG_DEV_API_KEYS|TENANCY_LIFECYCLE/,
    refusalCode: "tenancy_suspended",
    pending: "FC-2",
  },
  {
    id: "drain",
    title: "operator drain of the deployment (FC-1)",
    required: "spend",
    enforcement: /"node_draining"/,
    authorityTables: [],
    authorityText: /"runtime-state"/,
    deployVar: /GATEWAY_DRAIN/,
    refusalCode: "node_draining",
    pending: "FC-1",
  },
  {
    id: "guardrail-binding",
    title: "an activated guardrail policy revision (FC-3)",
    required: "screening",
    enforcement: /\bguardrails\.\w+\(|screen[A-Z]\w*\(|GuardrailEngine/,
    authorityTables: ["guardrail_policy_bindings", "guardrail_policy_revisions"],
    deployVar: /FG_DEV_(?:MCP|A2A)_GUARDRAILS/,
    pending: "FC-3",
  },
  {
    id: "agent-upstream-catalog",
    title: "withdrawal of an agent upstream (FC-4, closed 2026-08-01)",
    required: "self",
    enforcement: /AGENT_UPSTREAM_COLLECTION/,
    authorityTables: ["control_plane_resources"],
    deployVar: /\bAGENT_UPSTREAMS\b/,
  },
  {
    id: "quota-plan",
    title: "the plan an operator assigns a tenant",
    required: "spend",
    enforcement: /"quota_resolution_unavailable"/,
    authorityTables: ["plans", "quota_policies"],
    deployVar: /FG_DEV_QUOTA_POLICIES/,
    refusalCode: "quota_resolution_unavailable",
  },
  {
    id: "rpm-counter",
    title: "the shared RPM window (FC-5 — one counter, three Workers)",
    required: "spend",
    enforcement: /\.RATE_LIMIT\b/,
    authorityTables: [],
    // A Durable Object namespace is the durable authority here, and it is
    // durable on every borrower BECAUSE the class is defined once — which
    // §3.6 asserts off the committed deploy config.
    authorityText: /\.RATE_LIMIT\b/,
    refusalCode: "rate_limit_exceeded",
  },
  {
    id: "operator-deny-rules",
    title: "the operator `[[policies]]` deny table (FC-6c)",
    required: "self",
    enforcement: /BasicPolicyEngine/,
    authorityTables: [],
    authorityText: /BasicPolicyEngine/,
    deployVar: /GATEWAY_POLICIES|\bpolicies\b/,
  },
];

/** The Workers that ENFORCE a control. */
function enforcers(control: FleetControl): string[] {
  return appsMatching(control.enforcement);
}

/** The Workers that hold the control's DURABLE authority. */
function durableHolders(control: FleetControl): string[] {
  const byTable = control.authorityTables.flatMap((table) => appsReadingTable(table));
  const byText = control.authorityText === undefined ? [] : appsMatching(control.authorityText);
  return FLEET.filter((app) => byTable.includes(app) || byText.includes(app));
}

/**
 * How ONE Worker resolves ONE control.
 *
 * `durable` wins over `var` deliberately: the precedence this repo has settled
 * on — and states in `apps/gateway/src/routes/agent-upstreams.ts` — is *durable
 * when a control database is bound, var otherwise, fail-closed on a read error
 * and specifically NOT back to the var*. A Worker with both is correct. The
 * defect is a Worker with ONLY the var while a sibling has the durable read,
 * and that is what this function makes visible.
 */
function classOf(app: string, control: FleetControl): SourceClass {
  if (durableHolders(control).includes(app)) return "durable";
  if (control.deployVar !== undefined && appsMatching(control.deployVar).includes(app))
    return "var";
  if (control.devTable !== undefined && appsMatching(control.devTable).includes(app))
    return "in-memory";
  return "none";
}

/** The whole row, as data — this object is what a failure message prints. */
function matrixRow(control: FleetControl): Record<string, SourceClass> {
  return Object.fromEntries(enforcers(control).map((app) => [app, classOf(app, control)]));
}

describe.each(CONTROLS.map((control) => [control.id, control] as const))(
  "§3 control `%s`",
  (_id, control) => {
    it("3.1 the probes are live — enforcement and authority both hit real code", () => {
      // Runs first, for every row. A renamed refusal code or a renamed table
      // would otherwise turn every assertion below into a comparison of empty
      // sets, and this file would report a perfectly consistent fleet while
      // reading nothing. That is the dominant defect mode in this repository.
      expect(enforcers(control), `${control.id}: enforcement probe matched no Worker`).not.toEqual(
        [],
      );
      expect(
        durableHolders(control),
        `${control.id}: authority probe matched no Worker — the table or resource_kind was renamed`,
      ).not.toEqual([]);
    });

    it("3.2 every Worker the role set requires actually enforces it", () => {
      // COVERAGE. `required` names a role set computed in §2 from behaviour, so
      // this assertion widens by itself the day a sixth Worker starts spending.
      if (control.required === "self") {
        expect(enforcers(control).length, `${control.id} is enforced nowhere`).toBeGreaterThan(0);
        return;
      }
      const missing = (ROLES[control.required] ?? []).filter(
        (app) => !enforcers(control).includes(app),
      );
      expect(
        missing,
        `${control.id}: these ${control.required} Workers cannot enforce it — an operator who ` +
          `applies it there changes nothing${control.pending ? ` (${control.pending})` : ""}`,
      ).toEqual([]);
    });

    it("3.3 every enforcer resolves it from the SAME source-of-truth class", () => {
      // THE ASSERTION THIS FILE EXISTS FOR.
      //
      // All four shipped defects are one sentence: a control DURABLE on one
      // Worker and VAR-ONLY or IN-MEMORY on another. The operator mutates the
      // durable side, the var side keeps its deploy-time answer, both Workers'
      // own suites stay green, and the exploit is "call the other endpoint".
      //
      // The classes are DERIVED — from the SQL each Worker issues, resolved
      // through its own table constants, and from the vars it reads — so this
      // cannot drift out of date the way a recorded matrix does.
      const row = matrixRow(control);
      const classes = new Set(Object.values(row));
      const durable = Object.entries(row).filter(([, k]) => k === "durable");
      const private_ = Object.entries(row).filter(([, k]) => k === "var" || k === "in-memory");

      const durableOn = durable.map(([app]) => app).join(", ");
      const privateOn = private_.map(([app, kind]) => `${kind.toUpperCase()} on ${app}`).join(", ");
      const pending = control.pending === undefined ? "" : ` (${control.pending})`;
      expect(
        private_.length === 0 || durable.length === 0,
        `${control.id}: DURABLE on ${durableOn} and ${privateOn} — this is the exact shape of every fleet control defect shipped so far. ${JSON.stringify(row)}${pending}`,
      ).toBe(true);

      expect(
        classes.size,
        `${control.id}: enforcers disagree on where the truth lives ${JSON.stringify(row)}`,
      ).toBe(1);
      expect(
        [...classes][0],
        `${control.id}: enforced against nothing resolvable ${JSON.stringify(row)}`,
      ).not.toBe("none");
    });

    it("3.4 a control APPLIED durably is OBSERVED by every enforcer", () => {
      // The `agent-upstream-fleet-withdrawal.test.ts` property, stated for
      // every row: if the operator's action lands in a durable store, then
      // every Worker that enforces the control must read that store. FC-1 is
      // this assertion failing — `apps/control-plane` writes the
      // `runtime-state/drain` document and the gateway refuses off a different
      // variable, so the operator's one action reaches nothing.
      const holders = durableHolders(control);
      const blind = enforcers(control).filter((app) => !holders.includes(app));
      expect(
        blind,
        `${control.id}: these Workers enforce it without reading the authority ` +
          `(${holders.join(", ")}) — an operator action there is a no-op for them` +
          `${control.pending ? ` (${control.pending})` : ""}`,
      ).toEqual([]);
    });

    it("3.4b no enforcer reads only SOME of the control's durable authorities", () => {
      // 3.4 asks whether an enforcer reads the authority AT ALL, which a
      // control with several tables can satisfy while quietly privatising one
      // of them. That partial form is the same defect at a finer grain: point
      // `apps/mcp`'s quota chain at its own `quota_policies` and it still reads
      // `wallets` and `usage_monthly_rollups`, so it still looks durable — and
      // every quota an operator writes stops applying there.
      //
      // Only the TABLE authorities are demanded of everyone. `authorityText`
      // is deliberately excluded: for `tenant-lifecycle` it holds two DIFFERENT
      // durable spellings of one authority (the typed `tenants.status` column
      // and the `tenant-accounts` document the operator PATCHes), and requiring
      // both would demand the control plane issue the data plane's SQL.
      if (control.authorityTables.length === 0) return;
      const partial = enforcers(control)
        .map((app) => {
          const missing = control.authorityTables.filter(
            (table) => !(TABLES[app] ?? new Set()).has(table),
          );
          return missing.length === 0 ? null : `${app} does not read ${missing.join(", ")}`;
        })
        .filter((entry): entry is string => entry !== null);
      expect(
        partial,
        `${control.id}: an enforcer resolves part of this control from somewhere else` +
          `${control.pending ? ` (${control.pending})` : ""}`,
      ).toEqual([]);
    });

    it("3.5 the refusal is the SAME wire answer on every enforcer", () => {
      // A client that fails over from a 429 on one Worker to a 403 on another
      // is looking at two products, and a `denied_by` that is a hard deny on
      // one and a retryable throttle on the other is the same admission bug
      // wearing a different response. Modelled on
      // `./admission-consistency.test.ts`, generalised to the registry.
      if (control.refusalCode === undefined) return;
      const byApp = REFUSAL_INDEX.get(control.refusalCode);
      expect(byApp, `${control.id}: no Worker declares ${control.refusalCode}`).toBeDefined();
      const emitters = [...(byApp as ReadonlyMap<string, ReadonlySet<number>>).keys()].sort();
      const statuses = new Set(
        [...(byApp as ReadonlyMap<string, ReadonlySet<number>>).values()].flatMap((s) => [...s]),
      );
      expect(
        statuses.size,
        `${control.id}: ${control.refusalCode} has more than one status across ` +
          `${emitters.join(", ")}`,
      ).toBe(1);

      // Wording is compared as the SET each Worker uses, not as one string.
      // A code may legitimately carry several messages on one Worker — the
      // admission ladder's `quota_resolution_unavailable` names which of the
      // four lookups failed — and demanding a single text would forbid that
      // detail rather than catch drift. The property that matters is that a
      // caller switching surfaces sees the SAME set of possible reasons.
      const byWorker = MESSAGE_INDEX.get(control.refusalCode);
      const perApp = emitters.map((app) => [app, [...(byWorker?.get(app) ?? [])].sort()] as const);
      const withText = perApp.filter(([, texts]) => texts.length > 0);
      const distinct = new Set(withText.map(([, texts]) => JSON.stringify(texts)));
      expect(
        distinct.size,
        `${control.id}: ${control.refusalCode} is worded differently across Workers ` +
          `${JSON.stringify(Object.fromEntries(withText))}`,
      ).toBeLessThanOrEqual(1);
    });
  },
);

describe("§3.6 the shared RPM counter stays ONE namespace", () => {
  /**
   * FC-5's trap, kept here because it is the one control whose source of truth
   * is a Durable Object NAMESPACE rather than a row, so §3.3 cannot see it.
   *
   * `RateLimiterDurableObject` is DEFINED by one Worker and BORROWED by the
   * others through `script_name`, so `idFromName("key:<id>")` addresses the
   * same instance from all of them and a credential at 60 rpm is charged ONE
   * window across every spend surface. A second definition is a second, private
   * counter namespace — it compiles, it deploys, every per-Worker suite passes,
   * and it hands that Worker its own full quota. That is the wave-16 bypass
   * restored quietly, and nothing but this assertion refuses it.
   *
   * Computed from the committed deploy config of whichever Workers §2 put in
   * SPEND, so a sixth spend Worker is held to it without an edit here.
   */
  const CLASS = "RateLimiterDurableObject";

  it("exactly one Worker DEFINES the limiter class", () => {
    const definers = FLEET.filter((app) =>
      new RegExp(`new_(?:sqlite_)?classes\\s*=\\s*\\[[^\\]]*"${CLASS}"`).test(
        TOML[app]?.live ?? "",
      ),
    );
    expect(definers.length, `definers: ${definers.join(", ")}`).toBe(1);
  });

  it("every OTHER spend Worker borrows it rather than declaring it", () => {
    const definers = FLEET.filter((app) =>
      new RegExp(`new_(?:sqlite_)?classes\\s*=\\s*\\[[^\\]]*"${CLASS}"`).test(
        TOML[app]?.live ?? "",
      ),
    );
    for (const app of SPEND.filter((a) => !definers.includes(a))) {
      // Live declaration of the class WITHOUT `script_name` is a private
      // namespace by another route, so the LIVE config must not name it...
      expect(
        new RegExp(CLASS).test(TOML[app]?.live ?? ""),
        `${app} declares the limiter class in its live config`,
      ).toBe(false);
      // ...while the deploy-time stanza (commented out because workerd refuses
      // a cross-script DO binding under `wrangler dev --local`) must survive,
      // pointed at the one definer. Deleting it is how the shared counter
      // silently stops being shared at the next deploy.
      expect(TOML[app]?.full, `${app} lost the RATE_LIMIT deploy stanza`).toContain(
        `class_name = "${CLASS}"`,
      );
      expect(TOML[app]?.full, `${app} lost script_name — a private namespace at deploy`).toMatch(
        /script_name\s*=\s*"[^"]+"/,
      );
    }
  });
});

// ---------------------------------------------------------------------------
// §4  THE FLEET-WIDE RATCHETS — new controls are discovered, not declared
// ---------------------------------------------------------------------------

/**
 * Codes whose status legitimately differs, each pinned to its EXACT current
 * spelling so a change is red.
 *
 * The exemption list is the only hand-written list in this file and its
 * polarity is deliberate: a code NOT listed here must agree, so anything new
 * fails closed. Both entries are documented divergences with a reason in the
 * code that produces them.
 */
const STATUS_EXEMPT: ReadonlyMap<string, ReadonlySet<number>> = new Map([
  // `apps/gateway/src/assets/egress.ts:206` — Rust's `server/assets.rs:1114`
  // writes the asset-download counter failure as 429 while every inference
  // path writes 503, and the Rust CODE is what is ported. Pinned so the 429
  // cannot spread to a Worker that does not serve assets.
  ["governance_counter_unavailable", new Set([429, 503])],
  // The admin plane answers 422 for a semantically invalid document and the
  // data plane answers 400 for a malformed request body. Different questions,
  // same word.
  ["invalid_request", new Set([400, 422])],
]);

describe("§4 fleet-wide ratchets", () => {
  it("4.1 no refusal code carries two different statuses across the fleet", () => {
    // Mechanical DISCOVERY, not a registry read: every code any Worker can
    // emit, grouped, with disagreement forbidden. A control added tomorrow that
    // lands on two Workers is gated by this line on the day it lands, with
    // nobody editing this file.
    const shared = [...REFUSAL_INDEX.entries()].filter(([, byApp]) => byApp.size > 1);
    expect(shared.length, "no code is shared by two Workers — the scan went stale").toBeGreaterThan(
      20,
    );
    const disagreements = shared
      .filter(([code, byApp]) => {
        const statuses = new Set([...byApp.values()].flatMap((s) => [...s]));
        const exempt = STATUS_EXEMPT.get(code);
        if (exempt !== undefined) {
          return statuses.size !== exempt.size || [...statuses].some((s) => !exempt.has(s));
        }
        return statuses.size > 1;
      })
      .map(
        ([code, byApp]) =>
          `${code}: ${JSON.stringify(
            Object.fromEntries([...byApp].map(([app, s]) => [app, [...s]])),
          )}`,
      );
    expect(disagreements).toEqual([]);
  });

  it("4.2 the admission ladder is worded identically wherever it is enforced", () => {
    // The half `./admission-consistency.test.ts` proves for three hand-named
    // FILES, proved here for whatever Workers §2 computed into SPEND.
    const ladder = ["quota_scope_disabled", "monthly_budget_exceeded", "wallet_balance_exhausted"];
    for (const code of ladder) {
      const emitters = [...(REFUSAL_INDEX.get(code)?.keys() ?? [])].sort();
      expect(emitters, `${code} is not on every spend Worker`).toEqual([...SPEND].sort());
      const byWorker = MESSAGE_INDEX.get(code);
      const perApp = emitters.map((app) => [app, [...(byWorker?.get(app) ?? [])].sort()] as const);
      for (const [app, texts] of perApp) {
        expect(texts.length, `${code} has no captured wording on ${app}`).toBeGreaterThan(0);
      }
      const distinct = new Set(perApp.map(([, texts]) => JSON.stringify(texts)));
      expect(distinct.size, `${code} wording ${JSON.stringify(Object.fromEntries(perApp))}`).toBe(
        1,
      );
    }
  });

  it("4.3 every table two Workers share is a registered control or a declared non-control", () => {
    // The NEW-CONTROL ratchet. A table read by more than one Worker is a shared
    // source of truth by definition, and the question "does a change to it
    // apply everywhere?" is the question nobody asked before either bypass
    // shipped. Anything shared that is neither in §3's registry nor listed
    // below fails, so the default for a new shared table is FAIL.
    const NOT_A_CONTROL: ReadonlySet<string> = new Set([
      // Credential resolution. Held by `./admission-consistency.test.ts` and by
      // each Worker's 401-vs-403 taxonomy suite; the fleet property (same
      // status for the same key state) is §4.1's.
      "api_keys",
      "static_api_keys",
      "api_key_directory",
      // RBAC grant tables. FC-7: parsed by four Workers, consulted by two, and
      // every `rbac_action` in the contract is on an `/admin/v1/` path today.
      "roles",
      "permissions",
      "tenant_role_bindings",
      // Tenant hierarchy identity, not lifecycle. The CONTROL on `tenants` is
      // its `status` column and that is registered as `tenant-lifecycle`.
      "tenants",
      "projects",
      "workspaces",
      // Ledgers and audit: append-only records of what happened, not controls
      // an operator applies. `usage_monthly_rollups` has one writer by design.
      "audit_events",
      "billing_report_outbox",
      "usage_monthly_rollups",
      // #664 — the per-decision evidence trail. Newly SHARED (written by
      // `apps/gateway/src/requestlog/`, read by
      // `apps/control-plane/src/routes/admin_request_log.ts`), and classified
      // here for the same reason `audit_events` immediately above is: it
      // records what the system DID, and nothing consults it before deciding
      // anything. Answering this ratchet's question explicitly — "does a change
      // to it apply to both Workers?" — yes, and it is enforced by the schema
      // rather than by a registry entry: both Workers name the columns of
      // `sql/d1-ts/control/0003_request_log_columns.sql`, both suites apply the
      // deployed migration rather than a fixture, and a column rename breaks
      // `apps/gateway/test/requestlog/write.test.ts` and
      // `apps/control-plane/test/request-logs-read.test.ts` together.
      //
      // The one thing on this table that IS a fence — the tenant filter on the
      // admin read — is not shared: only the control plane serves it, and
      // `request-logs-read.test.ts` proves it from both tenants' sides plus the
      // JSONL export. If a second Worker ever grows a `request_logs` READ, that
      // fence becomes a fleet property and this entry must move into CONTROLS.
      "request_logs",
      // Money the admission ladder reads; the CONTROL is the ladder, which is
      // registered as `admission`.
      "wallets",
      "wallet_reservations",
      // Transport identity for self-hosted workers.
      "self_hosted_worker_registrations",
      // Per-tenant D1 ROUTING. `TenantDatabaseRouter.forTenant` reads it to
      // find which database a tenant's rows live in — it answers "where", not
      // "may you". The day it grows a `disabled`/`status` column it becomes a
      // control and belongs in CONTROLS instead, which is the decision this
      // list exists to force rather than to skip.
      "tenant_databases",
      // Schema introspection, not a row of state.
      "sqlite_master",
    ]);
    const registered = new Set(CONTROLS.flatMap((c) => c.authorityTables));
    const shared = [...new Set(FLEET.flatMap((app) => [...(TABLES[app] ?? [])]))]
      .filter((table) => appsReadingTable(table).length > 1)
      .sort();
    expect(shared.length, "no shared tables found — the SQL scan went stale").toBeGreaterThan(15);
    const unclassified = shared
      .filter((table) => !registered.has(table) && !NOT_A_CONTROL.has(table))
      .map((table) => `${table} (${appsReadingTable(table).join(", ")})`);
    expect(
      unclassified,
      "a source of truth is shared by two Workers and nobody has asked whether a change to it " +
        "applies to both — register it in CONTROLS or declare it a non-control",
    ).toEqual([]);
  });

  it("4.4 no registered control names an authority the fleet does not have", () => {
    // The inverse of 4.3, and the guard against the registry rotting into
    // fiction: every table a control claims must be issued by some Worker.
    const orphans = CONTROLS.flatMap((control) =>
      control.authorityTables
        .filter((table) => appsReadingTable(table).length === 0)
        .map((table) => `${control.id} → ${table}`),
    );
    expect(orphans, "a registered authority table is read by no Worker").toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// §5  ONE OPERATOR ACTION, EVERY ENFORCER — behavioural
// ---------------------------------------------------------------------------

/**
 * The `agent-upstream-fleet-withdrawal.test.ts` shape, applied to the drain.
 *
 * Everything above is source text; this is the deployed Worker. The operator's
 * ONE action — `POST /admin/v1/drain {"draining": true}`, which
 * `apps/control-plane/src/routes/admin_config_ops.ts::setAdminDrain` commits as
 * the durable `runtime-state/drain` document — is reproduced by row content,
 * exactly as the withdrawal test reproduces `D1ControlPlaneStore.create`. Then
 * the gateway is asked, over `SELF`, whether it has stopped taking billable
 * work.
 *
 * **This is RED until FC-1 lands, and that is the point.** The gateway refuses
 * off the deploy-time `GATEWAY_DRAIN` var, a different variable from the one
 * the operator's API writes, so the drain the operator applied is observed by
 * nobody. A test written after the fix would never have been seen red and would
 * prove nothing; this one states the defect.
 */
const CONTROL_RESOURCE_TABLE = "control_plane_resources";
const DRAIN_COLLECTION = "runtime-state";
const DRAIN_ID = "drain";

const bindings = env as unknown as Record<string, unknown>;

function controlDb(): D1Database {
  const binding = bindings.CONTROL_DB as D1Database | undefined;
  if (binding === undefined) {
    throw new Error(
      "the fleet control matrix expects the `CONTROL_DB` binding (apps/gateway/wrangler.toml). " +
        "Without it §5 would prove nothing.",
    );
  }
  return binding;
}

/** `setAdminDrain` — the operator's one action, by row content. */
async function applyDrain(draining: boolean): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const document = { id: DRAIN_ID, draining, reason: "migration window", changed_at: now };
  await controlDb()
    .prepare(
      `INSERT INTO ${CONTROL_RESOURCE_TABLE}
         (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, 1, ?, ?)
       ON CONFLICT (resource_kind, resource_id) DO UPDATE SET
         document_json = excluded.document_json`,
    )
    .bind(DRAIN_COLLECTION, DRAIN_ID, JSON.stringify(document), now, now)
    .run();
}

async function clearDrain(): Promise<void> {
  await controlDb()
    .prepare(`DELETE FROM ${CONTROL_RESOURCE_TABLE} WHERE resource_kind = ?`)
    .bind(DRAIN_COLLECTION)
    .run();
}

/**
 * A spend-producing request with a deliberately INVALID body.
 *
 * Undrained this is `400 invalid_request` from the inference module's own Zod
 * chain, so a drained `503 node_draining` also proves the gate ran BEFORE the
 * body was examined — the same negative control `./routes/drain.test.ts` uses.
 */
function postAi(path: string): Promise<Response> {
  return SELF.fetch(`https://gw.test${path}`, {
    method: "POST",
    headers: { authorization: "Bearer fg_root", "content-type": "application/json" },
    body: "{}",
  });
}

async function refusalOf(res: Response): Promise<{ status: number; code: string }> {
  const body = (await res.json()) as { error?: { code?: string } };
  return { status: res.status, code: body.error?.code ?? "" };
}

describe("§5 one operator action, observed by every enforcer", () => {
  beforeEach(clearDrain);
  afterEach(async () => {
    await clearDrain();
    delete bindings[DRAIN_VAR];
  });

  it("5.1 the durable drain the admin API writes stops the gateway spending", async () => {
    // BEFORE — the positive control. Without it the refusal below could pass
    // against a fleet that refuses everything, which is the vacuous shape this
    // repository keeps finding.
    expect((await refusalOf(await postAi("/v1/chat/completions"))).status).toBe(400);

    await applyDrain(true);

    // AFTER — no redeploy, no restart, no var flip. This is what the operator
    // was told happened when the control plane answered
    // `200 {"object":"drain","draining":true}`.
    expect(
      await refusalOf(await postAi("/v1/chat/completions")),
      "FC-1: the operator drained the fleet and the gateway kept accepting billable work — " +
        "it refuses off the deploy-time GATEWAY_DRAIN var, a different variable from the one " +
        "POST /admin/v1/drain writes",
    ).toEqual({ status: 503, code: "node_draining" });
  });

  it("5.2 lifting the drain lets work through again, in the same isolate", async () => {
    // The inverse. A drain that cannot be LIFTED without a deploy is an outage
    // an operator cannot end, and a gate that only ever tests the refusing
    // direction would not notice.
    await applyDrain(true);
    expect((await refusalOf(await postAi("/v1/chat/completions"))).status).toBe(503);
    await applyDrain(false);
    expect(
      (await refusalOf(await postAi("/v1/chat/completions"))).status,
      "FC-1: the drain could not be lifted through the admin API",
    ).toBe(400);
  });

  it("5.3 the deploy-time var keeps working — the durable read is an ADDITION", async () => {
    // Non-regression, and the reason FC-1's fix must be a PRECEDENCE rather
    // than a replacement: `wrangler versions` var flips are how a deployment is
    // drained when no control database is bound, and `./routes/drain.test.ts`
    // holds the whole var decision table. This asserts the two coexist, so the
    // fix cannot be "swap the source" — which would break every deployment
    // running without CONTROL_DB.
    bindings.GATEWAY_DRAIN = "true";
    expect(await refusalOf(await postAi("/v1/chat/completions"))).toEqual({
      status: 503,
      code: "node_draining",
    });
  });

  it("5.4 the drain document is durable state, not a var — proven by its authority", () => {
    // What makes 5.1 a FLEET assertion rather than a gateway one: the state the
    // operator wrote lives in `control_plane_resources`, which every spend
    // Worker already issues SQL against for other controls. So "the other two
    // Workers cannot see it" is never a platform limit — it is a wiring gap.
    expect(
      appsReadingTable(CONTROL_RESOURCE_TABLE),
      "the control resource table is not reachable from the spend Workers",
    ).toEqual(expect.arrayContaining([...SPEND]));
    expect(filesMatching("control-plane", /"runtime-state"/).length).toBeGreaterThan(0);
  });
});
