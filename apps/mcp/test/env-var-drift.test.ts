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

/** One LIVE `[[durable_objects.bindings]]` stanza. */
interface DurableObjectBinding {
  readonly name: string;
  readonly className: string;
  /** Present ⇒ the class is defined and migrated by ANOTHER script. */
  readonly scriptName?: string;
}

/**
 * The LIVE Durable Object bindings, split by who owns the class.
 *
 * The split is the whole point (#666). Three of this Worker's five bindings
 * name classes `src/worker.ts` exports and `[[migrations]]` introduces; the
 * other two, `RATE_LIMIT` and `TENANT_DATA`, name gateway-owned classes through
 * `script_name`, which this Worker must NOT export and must NOT migrate. A gate
 * that treats all five the same either fails on the correct config or — the way
 * this file used to be written — only stays green while a shared namespace is
 * commented out and therefore not shared at all.
 */
function durableObjectBindings(): DurableObjectBinding[] {
  const out: DurableObjectBinding[] = [];
  let current: Record<string, string> | null = null;
  const flush = (): void => {
    if (current?.name !== undefined && current.class_name !== undefined) {
      out.push({
        name: current.name,
        className: current.class_name,
        ...(current.script_name === undefined ? {} : { scriptName: current.script_name }),
      });
    }
    current = null;
  };
  for (const line of TOML_LINES) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#") || trimmed === "") continue;
    if (trimmed.startsWith("[")) {
      flush();
      if (trimmed === "[[durable_objects.bindings]]") current = {};
      continue;
    }
    const m = /^([A-Za-z0-9_]+)\s*=\s*"([^"]+)"/.exec(trimmed);
    if (m !== null && current !== null) current[m[1] as string] = m[2] as string;
  }
  flush();
  return out;
}

/** Class names bound LIVE and defined by THIS script. */
function localDurableObjectClasses(): string[] {
  return durableObjectBindings()
    .filter((b) => b.scriptName === undefined)
    .map((b) => b.className);
}

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
 * Vars and BINDINGS deliberately left out of the committed config, each NAMED
 * in its prose so an operator can still discover it.
 *
 * **EMPTY since issue #666**, and that is the fix rather than an oversight. Its
 * one entry was `RATE_LIMIT`, the SHARED admission counter namespace, whose
 * cross-script stanza was written out IN FULL but COMMENTED with "UNCOMMENT AT
 * DEPLOY TIME" above it. That made the committed tree the broken configuration:
 * a deploy that forgot the two lines gave `/v1/mcp` its own full RPM quota and
 * said nothing. The stanza is now LIVE and asserted as such by
 * `describe("the SHARED cross-script RATE_LIMIT binding")` below; the harness
 * resolves it offline through an auxiliary `ferrogate-gateway` worker
 * (`apps/gateway/test/support/rate-limit-aux-worker.ts`).
 *
 * The list is kept — rather than deleted along with its last entry — because
 * the NEXT binding somebody is tempted to comment out belongs here with a
 * written reason, not in a comment nobody re-reads.
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
 * CLOUDFLARE PRODUCT BINDINGS the source reads that this Worker does not declare
 * in the committed template — so the code path behind each is UNREACHABLE in
 * production today.
 *
 * `CONTROL_D1` (control-plane-d1 §Step2) is the control-plane's D1 database. mcp
 * is a READ-ONLY control consumer, so under the `"d1"` posture
 * `src/control-data.ts` opens a `withSession("first-unconstrained")` replica
 * session on `env.CONTROL_D1`. But the committed default is
 * `MCP_CONTROL_STORAGE = "durable_object"`, so that branch is never taken and the
 * read is dead in production while the dual-capability code ships ahead of the
 * cutover. The real binding is DEPLOY-TIME state in wrangler.deploy.toml (a live
 * `[[d1_databases]]` here would break the hermetic miniflare load), so the
 * template carries only a PORT-TODO. When the posture flips to `"d1"` this
 * graduates into a committed binding and leaves this list.
 */
const UNDECLARED_BINDINGS = ["CONTROL_D1"] as const;

/**
 * Declared names read through a renamed parameter, invisible to the
 * `env`-anchored scanner. Zero-D1 S5 (#881) deleted the `BILLING_DB` D1 stanza
 * (control billing compatibility): every control read now resolves the
 * CONTROL_DATA object, so no binding is read indirectly any more.
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
      "MCP_CONTROL_STORAGE",
    ]);
    expect([...DECLARED.bindings.keys()].sort()).toEqual([
      "ASSETS",
      // Zero-D1 S5 (#881): the `DB` and `BILLING_DB` control D1 stanzas are
      // deleted; control reads resolve the CONTROL_DATA object.
      "CONTROL_DATA",
      // #687's unified CLIENT session, the other axis from MCP_SESSION below.
      "MCP_CLIENT_SESSION",
      "MCP_OAUTH_FLOWS",
      "MCP_OAUTH_KV",
      "MCP_SESSION",
      // Cross-script, pointed at `ferrogate-gateway` (#666). It is in this list
      // because it is LIVE; while it was commented out it was not.
      "RATE_LIMIT",
      // Cross-script tenant catalog and identity storage, owned by gateway.
      "TENANT_DATA",
    ]);
    expect(READS.named.size).toBeGreaterThanOrEqual(7);
    expect(READS.named.has("MCP_SESSION")).toBe(true);
    expect(READS.named.has("FG_DEV_IN_MEMORY_PORTS")).toBe(true);
  });
});

/**
 * The deploy-config lines this app had NO gate for at all — ported from
 * `apps/gateway/test/wrangler-bindings.test.ts` during the wave-17 seam pass,
 * where MCP-T2/T6/T7 were measured GREEN under every mutation.
 *
 * All three are deploy-blocking and none of them is observable to
 * `@cloudflare/vitest-pool-workers`, which builds a Durable Object namespace
 * from the BINDING alone and never reads `[[migrations]]`, and which supplies
 * its own runtime flags regardless of `compatibility_flags`.
 */
describe("the deploy config's unobservable lines", () => {
  it("keeps nodejs_compat in compatibility_flags (MCP-T2)", () => {
    expect(WRANGLER_TOML).toMatch(/^compatibility_flags\s*=\s*\[[^\]]*"nodejs_compat"/m);
  });

  it("points main at the ENTRY module (MCP-T1)", () => {
    expect(WRANGLER_TOML).toMatch(/^main\s*=\s*"src\/worker\.ts"/m);
  });

  it("introduces every bound DO class in a new_sqlite_classes migration (MCP-T6/T7)", () => {
    // Cloudflare rejects at deploy: "Cannot create binding for class X because
    // it is not currently defined". `new_classes` is NOT an acceptable
    // substitute — it deploys and hands the object the key-value backend.
    const sqlite = [...WRANGLER_TOML.matchAll(/new_sqlite_classes\s*=\s*\[([^\]]*)\]/g)].flatMap(
      (m) => [...(m[1] ?? "").matchAll(/"([^"]+)"/g)].map((e) => e[1] as string),
    );
    const legacy = [...WRANGLER_TOML.matchAll(/new_classes\s*=\s*\[([^\]]*)\]/g)].flatMap((m) =>
      [...(m[1] ?? "").matchAll(/"([^"]+)"/g)].map((e) => e[1] as string),
    );
    // LOCAL classes only. A `[[durable_objects.bindings]]` carrying
    // `script_name` binds a class ANOTHER script defines and migrates
    // (`RATE_LIMIT` → `ferrogate-gateway`, #666); a `[[migrations]]` entry for
    // it here would claim to introduce a class this Worker does not export and
    // is rejected at deploy. `crossScriptClasses` is subtracted rather than the
    // list being hand-written, so a NEW local class still has to be migrated.
    const bound = localDurableObjectClasses();
    expect(bound.sort()).toEqual([
      "FerroGateMcpSession",
      // #687: one instance per (tenant, CLIENT session).
      "FerroGateMcpUnifiedSession",
      "McpOauthFlowClaim",
    ]);
    for (const className of bound) {
      expect(legacy, `${className} was introduced with new_classes`).not.toContain(className);
      expect(sqlite, `${className} is bound but no migration introduces it`).toContain(className);
    }
  });
});

describe("every var the source reads is declared or explicitly excepted", () => {
  const declaredNames = new Set([...DECLARED.vars.keys(), ...DECLARED.bindings.keys()]);
  const undeclared = [...READS.named.keys()].filter((n) => !declaredNames.has(n)).sort();

  it("has no undeclared read outside the exception table", () => {
    expect(undeclared).toEqual(
      [...SECRETS, ...DOCUMENTED_BUT_UNDECLARED, ...UNDECLARED_BINDINGS, ...UNDOCUMENTED].sort(),
    );
  });

  it("records each undeclared BINDING as an open PORT-TODO, not an oversight", () => {
    // Not vacuous: one entry today (`CONTROL_D1`).
    expect(UNDECLARED_BINDINGS.length).toBeGreaterThan(0);
    for (const name of UNDECLARED_BINDINGS) {
      expect(mentionedInToml(name)).toBe(true);
      expect(
        documentedNear(name, /PORT-TODO/, 6),
        `${name} is read by src/ with no binding declared and no PORT-TODO explaining it`,
      ).toBe(true);
      expect(DECLARED.bindings.has(name)).toBe(false);
    }
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
    // The list is EMPTY since #666 (see its comment), so the loop below asserts
    // nothing — which is only acceptable because emptiness is itself the
    // assertion here. A future entry restores the loop's work.
    expect(DOCUMENTED_BUT_UNDECLARED.length).toBe(0);
    for (const name of DOCUMENTED_BUT_UNDECLARED) {
      expect(mentionedInToml(name)).toBe(true);
    }
  });

  /**
   * WAS "keeps RATE_LIMIT commented, CROSS-SCRIPT, and claimed by no
   * migration". The first third of that title was the defect (#666): the
   * counter this Worker charges has to be the namespace `apps/gateway` charges,
   * and a stanza that is only uncommented by hand at deploy time is not a
   * shared counter — it is a shared counter's photograph. The other two thirds
   * are unchanged and still the things that silently un-share it.
   */
  it("keeps RATE_LIMIT LIVE, CROSS-SCRIPT, and claimed by no migration", () => {
    const rateLimit = durableObjectBindings().find((b) => b.name === "RATE_LIMIT");

    //  1. commenting it out (its state until #666): `limiterForEnv` falls back
    //     to the per-isolate counter and a 60 rpm cap becomes 60·N, silently.
    expect(rateLimit, "RATE_LIMIT is not a LIVE [[durable_objects.bindings]]").toBeDefined();
    expect(DECLARED.bindings.has("RATE_LIMIT")).toBe(true);
    //  2. dropping `script_name`: deploys cleanly, creates a SECOND private
    //     namespace, doubles every credential's RPM allowance.
    expect(rateLimit?.className).toBe("RateLimiterDurableObject");
    expect(rateLimit?.scriptName).toBe("ferrogate-gateway");
    //  3. adding a migration for it here: this script does not export the
    //     class, so claiming to introduce it is rejected at deploy.
    expect(WRANGLER_TOML).not.toMatch(
      /^\s*#?\s*new_(?:sqlite_)?classes\s*=.*RateLimiterDurableObject/m,
    );
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
    expect(rows.length).toBe(3);
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
