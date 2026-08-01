/**
 * THE CONTRACT BETWEEN `src/**` AND `wrangler.toml`, DERIVED MECHANICALLY.
 *
 * ## The gap this closes
 *
 * `docs/rewrite/MOUNT-SEAMS.md` records **TEL-T3** as a seam with *"no gate;
 * drift is invisible"*: `[vars] MAX_BODY_BYTES` is the only var this Worker
 * declares, `vitest.config.ts` overrides it with `"2048"`, and therefore no
 * behavioural test in this suite can see the committed value at all. The same
 * shape is recorded for the gateway (GW-T18), control-plane (CP-T5) and
 * agent-runtime (AR-T9). What was missing everywhere is the cheaper, stronger
 * property that does NOT require the committed value to be observable:
 *
 *   1. every `env.<VAR>` the source reads is DECLARED in `wrangler.toml`, or is
 *      an explicitly classified exception (a `wrangler secret put` secret, a
 *      dev-only flag, or a knob deliberately left unset); and
 *   2. every name `wrangler.toml` declares is actually READ by the source — a
 *      declared-but-unread var is dead configuration that misleads operators
 *      into thinking a knob exists.
 *
 * ## Why it cannot rot
 *
 * BOTH SIDES ARE DERIVED, never hand-listed. The read side comes from globbing
 * every `.ts` file under `../src` and scanning it for env access; the declared
 * side comes from parsing the committed `wrangler.toml`. The only hand-written
 * thing is the EXCEPTION TABLE, and it is asserted with `toEqual` on the exact
 * set — so adding an undeclared `env.X` read, or deleting the read behind an
 * exception, turns this file red rather than silently drifting.
 *
 * `?raw` is a VITE transform: the file's real bytes are inlined at build time,
 * which is the only way a workerd test (no filesystem) can read source or
 * config at all. It is the same mechanism
 * `apps/gateway/test/source-nul-bytes.test.ts` already relies on, and it reads
 * the SAME committed files wrangler deploys.
 *
 * ## What this gate deliberately does NOT claim
 *
 * The read-side scanner is a LOWER BOUND. It sees `env.X`, `env["X"]`,
 * `env[CONST]` and `(env as T).X`, but a binding read through a renamed
 * parameter (`function f(bindings: Env) { bindings.X }`) is invisible to it.
 * That direction is safe: a missed read can only make the "declared but unread"
 * check *stricter*, and that check therefore uses whole-token presence in the
 * source rather than the scanner's output.
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
 * This matters more than it looks: every var in this repo is discussed at
 * length in doc comments, so a scanner that kept comments would report all of
 * them as read and the "dead config" half of the gate would assert nothing.
 * The `[^:"'`\\]` guard in the line-comment rule is what stops `https://` from
 * eating the rest of a line.
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
 * The optional `as …` arm is not cosmetic: `src/` reads several bindings
 * through an inline cast, and without it the scanner silently misses them —
 * which is exactly how a var-drift gate becomes a gate that proves nothing.
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
 * Line-oriented TOML parse, for the same reason `wrangler-bindings.test.ts`
 * argues: a table ends at the next header, and a regex that spans headers is
 * how a config gate quietly starts matching nothing. Comment lines are dropped,
 * so commenting a stanza out reads as deleting it — which is what it is.
 *
 * Binding stanzas name their binding with `binding = "X"` everywhere EXCEPT
 * `[[durable_objects.bindings]]`, which uses `name = "X"`. Both are collected.
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
    // `section === ""` is the ROOT table, whose `name = "ferrogate-telemetry"`
    // is the Worker's own name, not a binding.
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
 * Vars the source reads that `wrangler.toml` does not declare, and why that is
 * correct. Asserted as an EXACT set below, so a new undeclared read is red.
 *
 * `secret` — seeded per environment with `wrangler secret put`. A committed
 * value would be a leaked credential, so absence is the whole point; what the
 * deploy config owes an operator instead is a written instruction, and the
 * `documented` assertion below holds it to that.
 */
const SECRETS = ["COLLECTOR_TOKEN"] as const;

/**
 * Reads that `wrangler.toml` does not declare AND does not even mention.
 *
 * This is the honest residue: an operator reading the deploy config has no way
 * to discover these knobs. Telemetry has none. It is asserted empty rather than
 * omitted, because "empty" is a claim that can become false.
 */
const UNDOCUMENTED: readonly string[] = [];

/**
 * Declared names read through a renamed parameter, which the `env`-anchored
 * scanner cannot see. Each entry must still be a whole-token reference in
 * source, which is asserted below.
 */
const READ_INDIRECTLY: readonly string[] = [];

describe("the env-var drift gate itself", () => {
  it("inlined the real source tree — an empty scan would assert nothing", () => {
    const files = [...CODE.keys()];
    expect(files.length).toBeGreaterThanOrEqual(8);
    expect(files.some((f) => f.endsWith("/src/limits.ts"))).toBe(true);
    expect(files.some((f) => f.endsWith("/src/app.ts"))).toBe(true);
  });

  it("inlined the committed wrangler.toml, not a fixture", () => {
    expect(WRANGLER_TOML).toContain('name = "ferrogate-telemetry"');
    expect(WRANGLER_TOML).toContain("[vars]");
  });

  it("parsed both sides — neither an empty read set nor an empty declared set", () => {
    // Without this, every assertion below would pass vacuously the moment the
    // scanner regressed. These three names are read in three different SHAPES:
    // `env?.TELEMETRY` (optional chain), `env?.MAX_BODY_BYTES` (plain) and
    // `c.env?.COLLECTOR_TOKEN` (member of a Hono context).
    expect([...READS.named.keys()].sort()).toEqual([
      "COLLECTOR_TOKEN",
      "MAX_BODY_BYTES",
      "TELEMETRY",
    ]);
    expect([...DECLARED.vars.keys()]).toEqual(["MAX_BODY_BYTES"]);
    expect([...DECLARED.bindings.keys()]).toEqual(["TELEMETRY"]);
  });
});

/**
 * The deploy-config lines this app had NO gate for — measured GREEN under
 * mutation during the wave-17 seam pass (TEL-T1, TEL-T5), and both
 * deploy-blocking. `vitest.config.ts` overrides `main`, and telemetry is not in
 * `e2e/`, so `wrangler dev --local` was the ONLY proof channel for either.
 */
describe("the deploy config's unobservable lines", () => {
  it("keeps nodejs_compat in compatibility_flags (TEL-T5)", () => {
    expect(WRANGLER_TOML).toMatch(/^compatibility_flags\s*=\s*\[[^\]]*"nodejs_compat"/m);
  });

  it("pins a compatibility_date", () => {
    expect(WRANGLER_TOML).toMatch(/^compatibility_date\s*=\s*"\d{4}-\d{2}-\d{2}"/m);
  });

  it("points main at the ENTRY module, not the composition root (TEL-T1)", () => {
    expect(WRANGLER_TOML).toMatch(/^main\s*=\s*"src\/worker\.ts"/m);
  });
});

describe("every var the source reads is declared or explicitly excepted", () => {
  const declaredNames = new Set([...DECLARED.vars.keys(), ...DECLARED.bindings.keys()]);
  const undeclared = [...READS.named.keys()].filter((n) => !declaredNames.has(n)).sort();

  it("has no undeclared read outside the exception table", () => {
    expect(undeclared).toEqual([...SECRETS, ...UNDOCUMENTED].sort());
  });

  it("documents every secret in wrangler.toml with its seeding command", () => {
    // The load-bearing half of "it's a secret, that's why it isn't here". A
    // secret nobody is told to set is a Worker that fails closed in production
    // for a reason the deploy config never mentions.
    for (const name of SECRETS) {
      expect(mentionedInToml(name), `${name} is read but never mentioned in wrangler.toml`).toBe(
        true,
      );
      expect(
        new RegExp(`wrangler secret put ${name}\\b`).test(WRANGLER_TOML),
        `wrangler.toml never tells an operator to \`wrangler secret put ${name}\``,
      ).toBe(true);
    }
  });

  it("pins the exact set of reads wrangler.toml does not even mention", () => {
    const silent = undeclared.filter((name) => !mentionedInToml(name));
    expect(silent).toEqual([...UNDOCUMENTED].sort());
  });

  it("pins every dynamic env[…] lookup site", () => {
    // A dynamic index is a var whose NAME comes from data, so neither half of
    // this gate can reason about it. Telemetry has none; if one appears, this
    // goes red and forces a decision rather than a silent hole.
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
      expect(referencedInCode(name), `${name} is excepted as indirect but appears nowhere`).toBe(
        true,
      );
    }
  });
});

describe("which committed [vars] values this runner can actually observe", () => {
  /**
   * THE HONEST PART, and the reason `MOUNT-SEAMS.md` TEL-T3 says "drift is
   * invisible" for this Worker.
   *
   * `vitest.config.ts` pins `MAX_BODY_BYTES: "2048"` as an explicit miniflare
   * binding, and an explicit binding BEATS the `[vars]` table. So the committed
   * `"4194304"` is never exercised, and any test that asserted on it would be
   * asserting something the runner cannot see. Rather than pretend otherwise,
   * this compares the two and requires every divergence to be explained by a
   * pin that is actually written in `vitest.config.ts`.
   *
   * That makes both failure modes loud: a NEW silent override (someone pins a
   * var somewhere else, e.g. a `.dev.vars` file) is red because nothing in
   * `vitest.config.ts` explains it, and a REMOVED pin is red because the value
   * suddenly matches and the expected-override set shrinks.
   */
  function pinnedInVitestConfig(name: string): boolean {
    return new RegExp(`(^|[\\s{,])${name}\\s*:`, "m").test(VITEST_CONFIG);
  }

  const comparable = [...DECLARED.vars.entries()]
    .map(([name, raw]) => ({ name, committed: tomlString(raw) }))
    .filter((row): row is { name: string; committed: string } => row.committed !== undefined);

  const observed = comparable.map((row) => ({
    ...row,
    runtime: (env as unknown as Record<string, unknown>)[row.name],
  }));

  it("compared a non-empty set of committed values", () => {
    expect(comparable.length).toBe(DECLARED.vars.size);
    expect(comparable.length).toBeGreaterThan(0);
  });

  it("explains every overridden var with an explicit pin in vitest.config.ts", () => {
    const overridden = observed
      .filter((row) => row.runtime !== row.committed)
      .map((row) => row.name);
    const unexplained = overridden.filter((name) => !pinnedInVitestConfig(name));
    expect(
      unexplained,
      "these [vars] do not reach the runner as committed, and vitest.config.ts does not pin them",
    ).toEqual([]);
    // Not vacuous: MAX_BODY_BYTES really is overridden today, so an empty
    // `overridden` here would mean the comparison stopped working.
    expect(overridden).toEqual(["MAX_BODY_BYTES"]);
  });

  it("records that the committed MAX_BODY_BYTES ceiling is UNPROVABLE here", () => {
    // Stated as an assertion so it cannot quietly stop being true. The
    // committed 4 MiB ceiling is the deployed one; the suite exercises 2048.
    expect(tomlString(DECLARED.vars.get("MAX_BODY_BYTES"))).toBe("4194304");
    expect((env as unknown as { MAX_BODY_BYTES?: string }).MAX_BODY_BYTES).toBe("2048");
  });
});
