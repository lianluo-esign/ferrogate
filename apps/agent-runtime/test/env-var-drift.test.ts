/**
 * THE CONTRACT BETWEEN `src/` AND `wrangler.toml`, DERIVED MECHANICALLY.
 *
 * ## The gap this closes — AR-T9, and the wave-14 correction to AR-T6/7/8
 *
 * `docs/rewrite/MOUNT-SEAMS.md` records AR-T9 (`AGENT_RUNTIME_ENABLED`,
 * `AGENT_JOB_MAX_OPEN_PER_TENANT`, `AGENT_JOB_DISPATCH_TTL_SECS`,
 * `FG_DEV_A2A_GUARDRAILS`) as **"weak: absent ≈ default, so drift is invisible;
 * no name-drift gate"**, and §15.3 corrects AR-T6/T7/T8 to: `vitest.config.ts`
 * pins those three as explicit miniflare bindings, "which win over the toml —
 * so the COMMITTED value is never exercised", making them drift gates at best.
 *
 * Both observations are about VALUES. This file asserts the two directions of
 * the code↔config contract instead, which need no value to be observable:
 *
 *   1. every var the source reads off `env` is DECLARED in `wrangler.toml`, or
 *      is one of a small, exactly-pinned set of classified exceptions; and
 *   2. every name `wrangler.toml` declares is READ by the source — a
 *      declared-but-unread var is dead configuration that tells an operator a
 *      knob exists when nothing consults it.
 *
 * The last `describe` then MEASURES the pinning effect rather than assuming it,
 * and finds something §15.3 did not say: all three pinned values are IDENTICAL
 * to the committed ones, so the runner does in fact see the committed value —
 * it just does not see it BECAUSE of the toml. That distinction is the whole
 * reason those rows can only ever be drift gates, and it is now asserted rather
 * than argued.
 *
 * ## Why it cannot rot
 *
 * The read side is derived by globbing every `.ts` file under `../src` with
 * `?raw` (a VITE transform — the bytes are inlined at build time, the only way
 * a workerd test with no filesystem can read source at all) and scanning for
 * env access. The declared side is derived by parsing the committed
 * `wrangler.toml` — the same bytes `vitest.config.ts` binds as
 * `TEST_WRANGLER_TOML`, asserted equal below. The ONLY hand-written thing is
 * the exception table, asserted with `toEqual` on the exact set.
 *
 * ## What this gate deliberately does NOT claim
 *
 * The read-side scanner is a LOWER BOUND: it sees `env.X`, `env["X"]`,
 * `env[CONST]` and `(env as T).X`, but not a binding read through a renamed
 * parameter. That direction is safe rather than unsound — a missed read can
 * only make direction (2) STRICTER — and `READ_INDIRECTLY` is empty here.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

declare global {
  interface ImportMeta {
    glob(pattern: string, options: object): Record<string, string>;
  }
}

const SOURCES = import.meta.glob("../src/**/*.ts", {
  query: "?raw",
  import: "default",
  eager: true,
});

const TOML_FILES = import.meta.glob("../wrangler.toml", {
  query: "?raw",
  import: "default",
  eager: true,
});

const VITEST_CONFIG_FILES = import.meta.glob("../vitest.config.ts", {
  query: "?raw",
  import: "default",
  eager: true,
});

function only(files: Record<string, string>, what: string): string {
  const values = Object.values(files);
  if (values.length !== 1 || typeof values[0] !== "string" || values[0].length === 0) {
    throw new Error(`env-var drift gate: expected exactly one ${what}, got ${values.length}`);
  }
  return values[0];
}

const WRANGLER_TOML = only(TOML_FILES, "wrangler.toml");
const VITEST_CONFIG = only(VITEST_CONFIG_FILES, "vitest.config.ts");

/**
 * Comments removed, so a var NAMED ONLY IN PROSE never counts as a read.
 *
 * Load-bearing rather than tidy: every var in this repo is discussed at length
 * in doc comments, so a scanner that kept comments would report all of them as
 * read and the dead-config half of this gate would assert nothing. The
 * `[^:"'`\\]` guard on the line-comment rule stops `https://` from eating the
 * rest of a line.
 */
function withoutComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'`\\])\/\/[^\n]*/g, "$1");
}

const CODE: ReadonlyMap<string, string> = new Map(
  Object.entries(SOURCES).map(([path, text]) => [path, withoutComments(text)]),
);

/** Every `const NAME = "STRING"` in the app, for resolving `env[NAME]`. */
function stringConstants(): ReadonlyMap<string, string> {
  const out = new Map<string, string>();
  for (const text of CODE.values()) {
    for (const m of text.matchAll(
      /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*"([^"]+)"/g,
    )) {
      out.set(m[1] as string, m[2] as string);
    }
  }
  return out;
}

/**
 * `env.NAME`, `env["NAME"]`, `env[CONST]` and `(env as T).NAME`.
 *
 * The optional `as …` arm is not cosmetic. Several bindings in this repo are
 * read through an inline cast, and an earlier draft of this scanner without
 * that arm reported a live operator switch in `apps/gateway` as
 * DECLARED-BUT-UNREAD — a false accusation whose "fix" would have been deleting
 * it from the deploy config. A var-drift gate that mis-reads the code is worse
 * than no gate.
 */
const ENV_DOT =
  /\benv\b(?:\s+as\s+[^;={}]{0,200}(?:\{[^{}]*\}[^;=]{0,60})?)?\s*\)*\s*\??\s*\.\s*([A-Z][A-Z0-9_]*)\b/g;
const ENV_STRING_INDEX = /\benv\b(?:\s+as\s+[^;={}]{0,200})?\s*\)*\s*\??\s*\[\s*"([^"]+)"\s*\]/g;
const ENV_IDENT_INDEX =
  /\benv\b(?:\s+as\s+[^;={}]{0,200})?\s*\)*\s*\??\s*\[\s*([A-Za-z_$][\w$]*)\s*\]/g;

interface Reads {
  /** var name → source files that read it. */
  readonly named: ReadonlyMap<string, readonly string[]>;
  /** identifier → files, for `env[x]` where `x` is not a literal constant. */
  readonly dynamic: ReadonlyMap<string, readonly string[]>;
}

function envReads(): Reads {
  const constants = stringConstants();
  const named = new Map<string, string[]>();
  const dynamic = new Map<string, string[]>();
  const push = (map: Map<string, string[]>, key: string, file: string): void => {
    const list = map.get(key);
    if (list === undefined) map.set(key, [file]);
    else if (!list.includes(file)) list.push(file);
  };
  for (const [file, text] of CODE) {
    for (const m of text.matchAll(ENV_DOT)) push(named, m[1] as string, file);
    for (const m of text.matchAll(ENV_STRING_INDEX)) push(named, m[1] as string, file);
    for (const m of text.matchAll(ENV_IDENT_INDEX)) {
      const ident = m[1] as string;
      const resolved = constants.get(ident);
      if (resolved === undefined) push(dynamic, ident, file);
      else push(named, resolved, file);
    }
  }
  return { named, dynamic };
}

interface Declared {
  /** `[vars]` entries: name → raw TOML right-hand side. */
  readonly vars: ReadonlyMap<string, string>;
  /** Every other binding name: name → the stanza that declares it. */
  readonly bindings: ReadonlyMap<string, string>;
}

/**
 * Line-oriented TOML parse, for the reason the sibling binding gates already
 * argue: a table ends at the next header, and a regex that
 * spans headers is how a config gate quietly starts matching nothing. Comment
 * lines are dropped, so commenting a stanza out reads as deleting it — which is
 * what it is, and what the mount-mutation sweep does.
 *
 * Binding stanzas name their binding with `binding = "X"` everywhere EXCEPT
 * `[[durable_objects.bindings]]`, which uses `name = "X"`. Both are collected;
 * the root table's `name` (the Worker's own name) is not a binding and is
 * skipped, as are `[triggers]` and `[observability*]`, which have neither.
 */
function declared(): Declared {
  const vars = new Map<string, string>();
  const bindings = new Map<string, string>();
  let section = "";
  for (const line of WRANGLER_TOML.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#") || trimmed === "") continue;
    if (trimmed.startsWith("[")) {
      section = trimmed;
      continue;
    }
    const m = /^([A-Za-z0-9_]+)\s*=\s*(.*)$/.exec(trimmed);
    if (m === null) continue;
    const [, key, raw] = m as unknown as [string, string, string];
    if (section === "[vars]") {
      vars.set(key, raw);
      continue;
    }
    if (key !== "binding" && key !== "name") continue;
    if (section === "" || section === "[triggers]" || section.startsWith("[observability")) {
      continue;
    }
    const value = /^"([^"]+)"/.exec(raw);
    if (value !== null) bindings.set(value[1] as string, section);
  }
  return { vars, bindings };
}

/** A double-quoted TOML scalar, or `undefined` for anything else. */
function tomlString(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  const m = /^"([^"]*)"/.exec(raw);
  return m === null ? undefined : (m[1] as string);
}

/** Does the name appear anywhere in `wrangler.toml`, including its comments? */
function mentionedInToml(name: string): boolean {
  return new RegExp(`\\b${name}\\b`).test(WRANGLER_TOML);
}

const TOML_LINES = WRANGLER_TOML.split(/\r?\n/);

/**
 * Is `pattern` written within `radius` lines of some mention of `name`?
 *
 * This is what turns "it's a secret, that's why it isn't declared" from a claim
 * in a test file into a property of the DEPLOY CONFIG. An operator reads
 * `wrangler.toml`, not this test.
 */
function documentedNear(name: string, pattern: RegExp, radius: number): boolean {
  const nameAt = new RegExp(`\\b${name}\\b`);
  for (let i = 0; i < TOML_LINES.length; i += 1) {
    if (!nameAt.test(TOML_LINES[i] as string)) continue;
    const window = TOML_LINES.slice(Math.max(0, i - radius), i + radius + 1).join("\n");
    if (pattern.test(window)) return true;
  }
  return false;
}

/** Does the name appear as a whole token anywhere in comment-stripped source? */
function referencedInCode(name: string): boolean {
  const pattern = new RegExp(`\\b${name}\\b`);
  for (const text of CODE.values()) if (pattern.test(text)) return true;
  return false;
}

const READS = envReads();
const DECLARED = declared();

// ---------------------------------------------------------------------------
// The exception table — the ONLY hand-written part of this file.
// ---------------------------------------------------------------------------

/**
 * Deploy-time SECRETS (`wrangler secret put`). This Worker has none: its
 * outbound credentials are per-worker transport secrets held in D1, and its
 * mTLS material is a binding, not a var. Asserted empty rather than omitted,
 * because "none" is a claim that can become false.
 */
const SECRETS: readonly string[] = [];

/**
 * Vars and BINDINGS deliberately left out of the committed config, each NAMED
 * in its prose so an operator can still discover it.
 *
 *  - `DB` / `CONTROL_DB` — the two `[[d1_databases]]` stanzas are written out
 *    IN FULL but COMMENTED. That is not laziness: `vitest.config.ts` loads this
 *    `wrangler.toml`, so an uncommented stanza injects an EMPTY unmigrated
 *    database into every unit test and routes the durable-first branch of
 *    `resolveDeps` onto schema-less tables — 106 of 259 tests go red on a
 *    correct tree. The durable adapters have their own chained harness
 *    (`test/durable/harness/`) which binds and MIGRATES both. Uncommenting is a
 *    deploy step, and `CLOUD-VERIFICATION.md` row B1 is where it is tracked.
 *  - `AGENT_UPSTREAMS` — deliberately NOT committed even as `"[]"`, because
 *    `resolveDeps` reads `env.AGENT_UPSTREAMS ?? env.FG_DEV_AGENT_UPSTREAMS`
 *    and a committed empty would SHADOW the dev fallback the A2A tests seed.
 *  - `FG_DEV_AGENT_UPSTREAMS` — the dev fallback itself, named in that same
 *    block.
 */
const DOCUMENTED_BUT_UNDECLARED = [
  "AGENT_UPSTREAMS",
  "CONTROL_DB",
  "DB",
  "FG_DEV_AGENT_UPSTREAMS",
] as const;

/**
 * Reads that `wrangler.toml` does not declare AND does not even mention.
 *
 * The honest residue. Both are dev fallbacks that `resolveDeps` consults when
 * `FG_DEV_IN_MEMORY_PORTS = "1"` — which IS the committed posture — so on a
 * plain `wrangler deploy` of this file they are the API-key and self-hosted-
 * worker directories the auth ladder actually uses, and the deploy config names
 * neither. Their sibling `FG_DEV_AGENT_UPSTREAMS` IS documented, so an operator
 * reading the config would reasonably conclude the list is complete.
 *
 * Fixing that is a `wrangler.toml` edit — the integrate step's file — so this
 * list is pinned rather than papered over. `CLOUD-VERIFICATION.md` row B1 is
 * the human step that turns the posture off for a deploy.
 */
const UNDOCUMENTED = ["FG_DEV_API_KEYS", "FG_DEV_SELF_HOSTED_WORKERS"] as const;

/**
 * Declared names read through a renamed parameter, invisible to the
 * `env`-anchored scanner. None here — every declared name is read directly.
 */
const READ_INDIRECTLY: readonly string[] = [];

describe("the env-var drift gate itself", () => {
  it("inlined the real source tree — an empty scan would assert nothing", () => {
    const files = [...CODE.keys()];
    expect(files.length).toBeGreaterThan(15);
    expect(files.some((f) => f.endsWith("/src/ports.ts"))).toBe(true);
    expect(files.some((f) => f.endsWith("/src/runs/addressing.ts"))).toBe(true);
  });

  it("inlined the committed wrangler.toml, not a fixture", () => {
    expect(WRANGLER_TOML).toContain('name = "ferrogate-agent-runtime"');
    const bound = (env as unknown as { TEST_WRANGLER_TOML?: string }).TEST_WRANGLER_TOML;
    expect(bound).toBe(WRANGLER_TOML);
  });

  it("parsed both sides — neither an empty read set nor an empty declared set", () => {
    expect([...DECLARED.vars.keys()].sort()).toEqual([
      "AGENT_JOB_DISPATCH_TTL_SECS",
      "AGENT_JOB_MAX_OPEN_PER_TENANT",
      "AGENT_RUNTIME_ENABLED",
      "CONTAINER_GOVERNED_EGRESS_HOSTS",
      "FG_DEV_A2A_GUARDRAILS",
      "FG_DEV_IN_MEMORY_PORTS",
      "FG_REQUIRE_PRODUCTION_MTLS",
    ]);
    expect([...DECLARED.bindings.keys()].sort()).toEqual(["AGENT_RUN_STATE", "WORKER_PLANE"]);
    expect(READS.named.size).toBeGreaterThanOrEqual(14);
    expect(READS.named.has("AGENT_JOB_MAX_OPEN_PER_TENANT")).toBe(true);
    expect(READS.named.has("WORKER_PLANE")).toBe(true);
  });
});

describe("every var the source reads is declared or explicitly excepted", () => {
  const declaredNames = new Set([...DECLARED.vars.keys(), ...DECLARED.bindings.keys()]);
  const undeclared = [...READS.named.keys()].filter((n) => !declaredNames.has(n)).sort();

  it("has no undeclared read outside the exception table", () => {
    expect(undeclared).toEqual([...SECRETS, ...DOCUMENTED_BUT_UNDECLARED, ...UNDOCUMENTED].sort());
  });

  it("documents every secret in wrangler.toml, next to its name", () => {
    for (const name of SECRETS) {
      expect(mentionedInToml(name)).toBe(true);
      expect(documentedNear(name, /secret/i, 8)).toBe(true);
    }
  });

  it("keeps every documented-but-undeclared knob named in wrangler.toml", () => {
    // Not vacuous: four entries today, including the two commented-out D1
    // stanzas whose whole justification lives in that prose.
    expect(DOCUMENTED_BUT_UNDECLARED.length).toBe(4);
    for (const name of DOCUMENTED_BUT_UNDECLARED) {
      expect(mentionedInToml(name), `${name} is read but no longer documented`).toBe(true);
    }
  });

  it("pins the exact set of reads wrangler.toml does not even mention", () => {
    const silent = undeclared.filter((name) => !mentionedInToml(name));
    expect(silent).toEqual([...UNDOCUMENTED].sort());
  });

  it("keeps both D1 stanzas COMMENTED, which is what makes DB/CONTROL_DB undeclared", () => {
    // The claim behind the two exceptions above, stated so it cannot rot. If
    // someone uncomments a stanza the name becomes DECLARED, this goes red, and
    // the exception table has to be updated — which is the moment to notice
    // that 106 unit tests are about to change posture.
    expect(DECLARED.bindings.has("DB")).toBe(false);
    expect(DECLARED.bindings.has("CONTROL_DB")).toBe(false);
    expect(WRANGLER_TOML).toContain('#   binding = "DB"');
    expect(WRANGLER_TOML).toContain('#   binding = "CONTROL_DB"');
  });

  it("pins every dynamic env[…] lookup site", () => {
    expect(Object.fromEntries(READS.dynamic)).toEqual({});
  });
});

describe("every name wrangler.toml declares is read by the source", () => {
  it("has no dead [vars] entry", () => {
    const dead = [...DECLARED.vars.keys()].filter(
      (name) => !READS.named.has(name) && !READ_INDIRECTLY.includes(name),
    );
    expect(dead, "declared in [vars] but read nowhere in src/ — dead config").toEqual([]);
  });

  it("has no dead binding stanza", () => {
    const dead = [...DECLARED.bindings.keys()].filter(
      (name) => !READS.named.has(name) && !READ_INDIRECTLY.includes(name),
    );
    expect(dead, "a binding is declared but nothing in src/ reads it").toEqual([]);
  });

  it("still finds a real reference for each indirectly-read name", () => {
    for (const name of READ_INDIRECTLY) {
      expect(referencedInCode(name)).toBe(true);
    }
  });
});

describe("which committed [vars] values this runner can actually observe", () => {
  /**
   * THE HONEST PART, and a sharpening of MOUNT-SEAMS.md §15.3.
   *
   * That section says `vitest.config.ts` pins `FG_DEV_IN_MEMORY_PORTS`,
   * `FG_REQUIRE_PRODUCTION_MTLS` and `CONTAINER_GOVERNED_EGRESS_HOSTS` as
   * explicit miniflare bindings "which win over the toml — so the COMMITTED
   * value is never exercised". The first half is true and the second is
   * imprecise: all three pins carry the SAME value the toml commits, so the
   * runner does observe the committed value; it just does not observe it
   * BECAUSE the toml supplies it. Change the toml alone and nothing moves,
   * which is exactly why those rows can only ever be drift gates.
   *
   * This measures the whole `[vars]` table instead of arguing about three rows,
   * and requires every divergence to be explained by a pin actually written in
   * `vitest.config.ts`. Both failure modes are loud: a NEW silent override (a
   * `.dev.vars` file on one machine, say) is red because nothing explains it,
   * and a pin whose value stops matching the toml is red here too.
   */
  function pinnedInVitestConfig(name: string): boolean {
    return new RegExp(`(^|[\\s{,])${name}\\s*:`, "m").test(VITEST_CONFIG);
  }

  const rows = [...DECLARED.vars.entries()]
    .map(([name, raw]) => ({ name, committed: tomlString(raw) }))
    .filter((row): row is { name: string; committed: string } => row.committed !== undefined)
    .map((row) => ({ ...row, runtime: (env as unknown as Record<string, unknown>)[row.name] }));

  const PINNED_AND_EQUAL = [
    "CONTAINER_GOVERNED_EGRESS_HOSTS",
    "FG_DEV_IN_MEMORY_PORTS",
    "FG_REQUIRE_PRODUCTION_MTLS",
  ] as const;

  it("compared every committed [vars] value against the runtime one", () => {
    expect(rows.length).toBe(DECLARED.vars.size);
    expect(rows.length).toBe(7);
  });

  it("explains every overridden var with an explicit pin in vitest.config.ts", () => {
    const overridden = rows.filter((r) => r.runtime !== r.committed).map((r) => r.name);
    const unexplained = overridden.filter((name) => !pinnedInVitestConfig(name));
    expect(
      unexplained,
      "these [vars] do not reach the runner as committed, and vitest.config.ts does not pin them",
    ).toEqual([]);
    expect(overridden).toEqual([]);
  });

  it("shows the three §15.3 rows are PINNED yet carry the committed value", () => {
    // Not vacuous in either direction: the first expectation fails if the pins
    // are removed from `vitest.config.ts`, the second if a pin's value is
    // changed to something the toml does not commit.
    for (const name of PINNED_AND_EQUAL) {
      expect(pinnedInVitestConfig(name), `${name} is no longer pinned in vitest.config.ts`).toBe(
        true,
      );
      const row = rows.find((r) => r.name === name);
      expect(row, `${name} left [vars]`).toBeDefined();
      expect(row?.runtime, `${name} is pinned to a value the committed config does not carry`).toBe(
        row?.committed,
      );
    }
  });

  it("records that all seven committed values reach this runner unchanged", () => {
    const observable = rows.filter((r) => r.runtime === r.committed).map((r) => r.name);
    expect(observable.sort()).toEqual([...DECLARED.vars.keys()].sort());
    expect(observable.length).toBe(7);
  });
});
