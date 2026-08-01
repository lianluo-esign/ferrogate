/**
 * THE CONTRACT BETWEEN `src/` AND `wrangler.toml`, DERIVED MECHANICALLY.
 *
 * ## The gap this closes
 *
 * `docs/rewrite/MOUNT-SEAMS.md` records the same shape in every app: `[vars]`
 * entries whose committed value is a fail-closed empty are behaviourally
 * indistinguishable from being ABSENT, so no behavioural test can hold them and
 * the mount-mutation sweep reports deleting them as GREEN (GW-T18, CP-T5,
 * AR-T9, TEL-T3). `test/wrangler-bindings.test.ts` in this app holds the
 * Durable Object and KV stanzas; the `[vars]` table and the code↔config
 * contract as a whole had no gate.
 *
 * What a test CAN hold, without the committed value ever being observable, is
 * that the two sides keep naming the same things:
 *
 *   1. every var the source reads off `env` is DECLARED in `wrangler.toml`, or
 *      is one of a small, exactly-pinned set of classified exceptions; and
 *   2. every name `wrangler.toml` declares is READ by the source — a
 *      declared-but-unread var is dead configuration that tells an operator a
 *      knob exists when nothing consults it.
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
 * only make direction (2) STRICTER — and `READ_INDIRECTLY` is empty here, so
 * nothing is being excused.
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
 * Deploy-time SECRETS (`wrangler secret put`). A committed value would be a
 * leaked credential, so absence from `[vars]` is the whole point; what the
 * deploy config owes an operator instead is a written instruction, and
 * `documentedNear(…, /secret/i, …)` below holds it to that.
 *
 * `FERROGATE_MCP_IDENTITY_KEY` is the 32-byte AEAD key `webCryptoIdentityCipher`
 * seals stored OAuth grants under. `wrangler.toml` has a "NOT DECLARED — and
 * why" block naming it.
 */
const SECRETS = ["FERROGATE_MCP_IDENTITY_KEY"] as const;

/**
 * Vars deliberately left out of `[vars]` but NAMED in the config's prose, so an
 * operator can still discover them. None here today — asserted empty rather
 * than omitted, because "none" is a claim that can become false.
 */
const DOCUMENTED_BUT_UNDECLARED: readonly string[] = [];

/**
 * Reads that `wrangler.toml` does not declare AND does not even mention.
 *
 * The honest residue. `FG_DEV_MCP_DURABLE_UPSTREAMS` switches
 * `src/upstreams.ts` onto the durable upstream catalog; its two siblings
 * (`FG_DEV_IN_MEMORY_PORTS`, `FG_DEV_MCP_GUARDRAILS`) ARE declared, so an
 * operator reading `[vars]` would reasonably conclude the dev switches are all
 * there. Fixing it is a `wrangler.toml` edit — the integrate step's file — so
 * it is pinned here rather than papered over.
 */
const UNDOCUMENTED = ["FG_DEV_MCP_DURABLE_UPSTREAMS"] as const;

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
    expect(files.some((f) => f.endsWith("/src/upstreams.ts"))).toBe(true);
  });

  it("inlined the committed wrangler.toml, not a fixture", () => {
    expect(WRANGLER_TOML).toContain('name = "ferrogate-mcp"');
    const bound = (env as unknown as { TEST_WRANGLER_TOML?: string }).TEST_WRANGLER_TOML;
    expect(bound).toBe(WRANGLER_TOML);
  });

  it("parsed both sides — neither an empty read set nor an empty declared set", () => {
    expect([...DECLARED.vars.keys()].sort()).toEqual([
      "FG_DEV_IN_MEMORY_PORTS",
      "FG_DEV_MCP_GUARDRAILS",
    ]);
    expect([...DECLARED.bindings.keys()].sort()).toEqual([
      "DB",
      "MCP_OAUTH_FLOWS",
      "MCP_OAUTH_KV",
      "MCP_SESSION",
    ]);
    expect(READS.named.size).toBeGreaterThanOrEqual(7);
    expect(READS.named.has("MCP_SESSION")).toBe(true);
    expect(READS.named.has("FG_DEV_IN_MEMORY_PORTS")).toBe(true);
  });
});

describe("every var the source reads is declared or explicitly excepted", () => {
  const declaredNames = new Set([...DECLARED.vars.keys(), ...DECLARED.bindings.keys()]);
  const undeclared = [...READS.named.keys()].filter((n) => !declaredNames.has(n)).sort();

  it("has no undeclared read outside the exception table", () => {
    expect(undeclared).toEqual([...SECRETS, ...DOCUMENTED_BUT_UNDECLARED, ...UNDOCUMENTED].sort());
  });

  it("documents every secret in wrangler.toml, next to its name", () => {
    // Not vacuous: one entry today.
    expect(SECRETS.length).toBeGreaterThan(0);
    for (const name of SECRETS) {
      expect(mentionedInToml(name), `${name} is read but never mentioned in wrangler.toml`).toBe(
        true,
      );
      expect(
        documentedNear(name, /secret/i, 8),
        `wrangler.toml names ${name} but never says it is a secret`,
      ).toBe(true);
    }
  });

  it("keeps every documented-but-undeclared knob named in wrangler.toml", () => {
    for (const name of DOCUMENTED_BUT_UNDECLARED) {
      expect(mentionedInToml(name)).toBe(true);
    }
  });

  it("pins the exact set of reads wrangler.toml does not even mention", () => {
    const silent = undeclared.filter((name) => !mentionedInToml(name));
    expect(silent).toEqual([...UNDOCUMENTED].sort());
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
   * `vitest.config.ts` pins vars as explicit miniflare bindings, and an
   * explicit binding BEATS the `[vars]` table — the effect that made three
   * agent-runtime rows unprovable in wave 14. This measures it rather than
   * assuming either way, and requires every divergence to be explained by a pin
   * actually written in `vitest.config.ts`.
   */
  function pinnedInVitestConfig(name: string): boolean {
    return new RegExp(`(^|[\\s{,])${name}\\s*:`, "m").test(VITEST_CONFIG);
  }

  const rows = [...DECLARED.vars.entries()]
    .map(([name, raw]) => ({ name, committed: tomlString(raw) }))
    .filter((row): row is { name: string; committed: string } => row.committed !== undefined)
    .map((row) => ({ ...row, runtime: (env as unknown as Record<string, unknown>)[row.name] }));

  it("compared every committed [vars] value against the runtime one", () => {
    expect(rows.length).toBe(DECLARED.vars.size);
    expect(rows.length).toBe(2);
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

  it("records that BOTH committed values reach this runner unchanged", () => {
    // Worth stating: `vitest.config.ts` here pins only test-fixture bindings
    // (`TEST_*`, `TENANT_DB_A`), never a declared var — so unlike the gateway
    // and telemetry, a behavioural test in this app really is exercising the
    // committed config. `FG_DEV_IN_MEMORY_PORTS = "1"` is the posture the whole
    // offline suite runs under, and CLOUD-VERIFICATION.md row B1 is the human
    // step that flips it for a deploy.
    const observable = rows.filter((r) => r.runtime === r.committed).map((r) => r.name);
    expect(observable.sort()).toEqual([...DECLARED.vars.keys()].sort());
    expect((env as unknown as { FG_DEV_IN_MEMORY_PORTS?: string }).FG_DEV_IN_MEMORY_PORTS).toBe(
      "1",
    );
  });
});
