/**
 * THE CONTRACT BETWEEN `src/` AND `wrangler.toml`, DERIVED MECHANICALLY.
 *
 * ## The gap this closes — GW-T18
 *
 * `docs/rewrite/MOUNT-SEAMS.md` records GW-T18 as the largest accepted hole in
 * this Worker's config coverage, and wave 14 sharpened the wording to: *"not
 * '5 of 49 vars have a drift gate', but 'the other 44 have no gate of any kind,
 * behavioural or drift'"*. Commenting out the entire `[vars]` table leaves the
 * suite green, because `vitest.config.ts` re-supplies as explicit miniflare
 * bindings the handful of vars any test actually reads.
 *
 * `test/wrangler-bindings.test.ts` closes five of them by NAME (the three
 * asset-signature vars and the two operator config tables) plus the eight cache
 * vars, one hand-written list at a time. That approach does not scale to 49 and
 * rots the moment someone adds a var, because the list is authored, not derived.
 *
 * This file takes the other route and asserts the two directions of the
 * code↔config contract, both sides DERIVED:
 *
 *   1. every var the source reads off `env` is DECLARED in `wrangler.toml`, or
 *      is one of a small, exactly-pinned set of classified exceptions; and
 *   2. every name `wrangler.toml` declares is READ by the source — a
 *      declared-but-unread var is dead configuration that tells an operator a
 *      knob exists when nothing consults it.
 *
 * Neither direction needs the committed VALUE to be observable, which is why
 * this works where a behavioural gate cannot: the fail-closed empties GW-T18
 * describes are behaviourally identical to being absent, but their NAMES are
 * still a contract, and a rename on either side is now loud.
 *
 * ## Why it cannot rot
 *
 * The read side is derived by globbing every `.ts` file under `../src` with
 * `?raw` (a VITE transform — the bytes are inlined at build time, the only way
 * a workerd test with no filesystem can read source at all, and the same
 * mechanism `test/source-nul-bytes.test.ts` already relies on) and scanning for
 * env access. The declared side is derived by parsing the committed
 * `wrangler.toml`. The ONLY hand-written thing is the exception table below,
 * and it is asserted with `toEqual` on the exact set — so a new undeclared read
 * is red, and deleting the read behind an exception is also red.
 *
 * ## What this gate deliberately does NOT claim
 *
 * The read-side scanner is a LOWER BOUND on reads. It sees `env.X`, `env["X"]`,
 * `env[CONST]` and `(env as T).X`, but a binding read through a renamed
 * parameter — `src/assets/handlers.ts` does `bindings.ASSETS` — is invisible to
 * it. That direction is safe rather than unsound: a missed read can only make
 * direction (2) STRICTER, and the one name it misses today is pinned in
 * `READ_INDIRECTLY` with a whole-token source check of its own.
 *
 * It also says nothing about VALUES, except in the last `describe`, which
 * measures exactly how much of the committed `[vars]` table this runner can
 * observe at all — and finds that most of the interesting ones it cannot.
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
 * This is load-bearing here more than anywhere: this Worker's `wrangler.toml`
 * and its source discuss every var at length, and a scanner that kept comments
 * would report all 49 as read, making direction (2) assert nothing at all.
 * The `[^:"'`\\]` guard on the line-comment rule stops `https://` from eating
 * the rest of a line.
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
 * The optional `as …` arm is not cosmetic. `src/assets/handlers.ts` reads
 * `(env as { FG_REQUIRE_AGENT_RUN_ID?: string }).FG_REQUIRE_AGENT_RUN_ID`, and
 * an earlier draft of this scanner without that arm reported the var as
 * DECLARED-BUT-UNREAD — a false accusation that would have been "fixed" by
 * deleting a live operator switch from the deploy config. A var-drift gate that
 * mis-reads the code is worse than none.
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
 * Line-oriented TOML parse, for the reason `test/wrangler-bindings.test.ts`
 * already argues at length: a table ends at the next header, and a regex that
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
 * leaked credential, so their absence from `[vars]` is the whole point. What
 * the deploy config owes an operator instead is a written instruction, and
 * `documentedNear(…, /secret/i, …)` below holds it to that.
 */
const SECRETS = [
  "ASSET_S3_ACCESS_KEY_ID",
  "ASSET_S3_SECRET_ACCESS_KEY",
  "ASSET_S3_SESSION_TOKEN",
  // Issue #682: the fleet-wide AES-256 key that seals every tenant's own
  // provider credential. ONE binding for the whole fleet — the per-tenant part
  // is row data in control D1, which is what keeps onboarding and rotation off
  // the deploy path. A committed value would decrypt every tenant's key.
  "FERROGATE_BYOK_MASTER_KEY",
  "GATEWAY_DEV_API_KEY",
  "GATEWAY_TENANT_DB_API_TOKEN",
  "GUARDRAIL_EVIDENCE_HMAC_KEY",
  "TELEMETRY_TOKEN",
] as const;

/**
 * Deploy-time SECRETS the `env`-anchored scanner cannot see, because they are
 * read off a RENAMED parameter — the `READ_INDIRECTLY` shape, but for a name
 * that must never appear in `[vars]` at all.
 *
 * They are a separate list rather than entries in {@link SECRETS} for a reason
 * worth stating: `SECRETS` is asserted with `toEqual` against the set of
 * undeclared READS, so putting an invisible-to-the-scanner name in it would
 * make that assertion fail — and "fixing" that by loosening the `toEqual` would
 * cost the exactness the whole gate rests on. Instead these get the SAME two
 * documentation assertions plus a whole-token source check, so a secret cannot
 * hide here either.
 *
 * `BILLING_ALERTS_WEBHOOK_SIGNING_SECRET` (WAVE 20) is the HMAC-SHA256 key a
 * budget-alert receiver authenticates the notification with
 * (`X-FerroGate-Signature` over `"<timestamp>.<body>"`). A committed value
 * would let anyone forge a budget alert, so `[vars]` carries the
 * `wrangler secret put` instruction next to the two knobs that ARE committed.
 * `budgetAlertConfigFromEnv` reads it as `bindings.BILLING_ALERTS_WEBHOOK_SIGNING_SECRET`.
 */
const SECRETS_READ_INDIRECTLY = ["BILLING_ALERTS_WEBHOOK_SIGNING_SECRET"] as const;

/**
 * Plain vars deliberately left out of `[vars]`, each NAMED in the config's
 * prose so an operator can still discover it.
 *
 * These are not secrets and not dead: they are knobs whose committed default
 * lives in code (`ASSET_S3_REGION` → `auto`, `ASSET_SCANNER_TIMEOUT_SECS` → 30)
 * and which the config documents rather than restates. The assertion below is
 * that they stay documented; if one drops out of the prose it moves to
 * `UNDOCUMENTED` and the count of silent knobs goes up, visibly.
 */
const DOCUMENTED_BUT_UNDECLARED = [
  "ASSET_S3_REGION",
  "ASSET_SCANNER_ASYNC_THRESHOLD_BYTES",
  "ASSET_SCANNER_TIMEOUT_SECS",
  "ASSET_SCANNER_UNAVAILABLE",
  "GATEWAY_DEV_TENANT_ID",
] as const;

/**
 * CLOUDFLARE PRODUCT BINDINGS the source reads that this Worker does not
 * declare — so the code path behind each one is UNREACHABLE in production.
 *
 * **EMPTY as of issue #673, and the entry that used to be here was `AI`.**
 *
 * The old note said `src/guardrails/config.ts` reads `env.AI` for the Workers AI
 * Llama-Guard detector while `wrangler.toml` carried only a PORT-TODO, and it
 * pinned that as a deliberate state because "declaring it costs the offline,
 * docker-free property this project's testing strategy is built on" — the
 * `@cloudflare/vitest-pool-workers` remote-proxy failure. The CONCLUSION drawn
 * from it no longer holds, because the cost is avoidable — and the measurement
 * itself was over-read. What a runner refuses is `remote = false` on an AI
 * binding, not the binding; declared with no `remote` key and the pool's
 * `remoteBindings: false`, `[ai]` loads offline in both the pool and
 * `wrangler dev --local` and nothing proxies anywhere. So the suite stays
 * offline AND the deployed Worker gets the binding. `[ai] binding = "AI"` is
 * committed and `AI` is therefore DECLARED, which is what the assertions below
 * now say.
 *
 * This is not a test being routed around: the old claim was that the AI code
 * path is dead in production, and issue #673 is the work that made it live.
 * Leaving the claim standing would have been the lie.
 */
const UNDECLARED_BINDINGS: readonly string[] = [];

/**
 * Reads that `wrangler.toml` does not declare AND does not even mention.
 *
 * The honest residue: an operator reading the deploy config has no way to
 * discover these. One today — `FG_DEV_IN_MEMORY_PORTS`, the local-dev switch
 * `src/assets/handlers.ts` shares with `apps/mcp` and `apps/agent-runtime`,
 * both of whose configs DO name it. Fixing it is a `wrangler.toml` edit, which
 * is the integrate step's file, so it is pinned here rather than papered over.
 */
const UNDOCUMENTED = ["FG_DEV_IN_MEMORY_PORTS"] as const;

/**
 * Declared names read through a RENAMED PARAMETER, which the `env`-anchored
 * scanner cannot see. Each must still be a whole-token reference in source,
 * which is asserted below, so this cannot be used to excuse a dead binding.
 *
 * `ASSETS` is the R2 bucket: `assetDepsFromEnv` takes the env as `bindings` and
 * reads `bindings.ASSETS`.
 *
 * The two `BILLING_ALERTS_*` vars are the same shape, added in WAVE 20:
 * `budgetAlertConfigFromEnv` (`src/metering/budget-alerts.ts`) narrows the env
 * to a `BudgetAlertBindings` parameter named `bindings` and reads
 * `bindings.BILLING_ALERTS_WEBHOOK_URL` /
 * `bindings.BILLING_ALERTS_WEBHOOK_TIMEOUT_SECS`. They are NOT dead config —
 * the "still finds a real reference" case below re-proves each one appears in
 * `src/`, so this list cannot be used to smuggle in a var nothing reads.
 */
const READ_INDIRECTLY = [
  "ASSETS",
  "BILLING_ALERTS_WEBHOOK_TIMEOUT_SECS",
  "BILLING_ALERTS_WEBHOOK_URL",
] as const;

describe("the env-var drift gate itself", () => {
  it("inlined the real source tree — an empty scan would assert nothing", () => {
    const files = [...CODE.keys()];
    expect(files.length).toBeGreaterThan(50);
    expect(files.some((f) => f.endsWith("/src/adapters.ts"))).toBe(true);
    expect(files.some((f) => f.endsWith("/src/cache/config.ts"))).toBe(true);
    expect(files.some((f) => f.endsWith("/src/tenancy/resolver.ts"))).toBe(true);
  });

  it("inlined the committed wrangler.toml, not a fixture", () => {
    expect(WRANGLER_TOML).toContain('name = "ferrogate-gateway"');
    // The same file `vitest.config.ts` binds as TEST_WRANGLER_TOML for
    // `test/wrangler-bindings.test.ts`; asserting they agree keeps the two
    // gates from ever reading different bytes.
    const bound = (env as unknown as { TEST_WRANGLER_TOML?: string }).TEST_WRANGLER_TOML;
    expect(bound).toBe(WRANGLER_TOML);
  });

  it("parsed both sides — neither an empty read set nor an empty declared set", () => {
    // GW-T18 counted 49 `[vars]`; WAVE 20 committed the two `BILLING_ALERTS_*`
    // knobs, so 51; #669 committed `TELEMETRY_ATTRIBUTE_PROFILE` (52) and #664
    // committed `REQUEST_LOG_RETENTION_DAYS` + `REQUEST_LOG_RETENTION_POLICIES`
    // (54), and #679 committed `GATEWAY_BUDGET_HOLD_USD` (55). Pinning the exact number makes an accidental parser regression (or
    // a silently deleted table) loud here first — and it is why adding a var is
    // deliberately a two-file change: the count below must be re-stated by
    // whoever adds one, rather than drifting silently. Note this merge is why
    // the number is 54 and not either branch's 52 or 53: BOTH sets landed.
    //
    // #672 committed `GATEWAY_CLOUDFLARE`, the account-level `[cloudflare]`
    // block AI Gateway routing needs, so 56. Re-derived by running this gate
    // against the merged `wrangler.toml` — the parser's own count, not 55 + 1.
    //
    // #678 committed `GATEWAY_ATTRIBUTION_POLICIES` ("[]"), the no-control-database
    // fallback for the required-tag policy, so 57. Re-derived the same way and
    // cross-checked independently against the committed file
    // (`grep -cE '^[A-Z][A-Z0-9_]*[[:space:]]*=' wrangler.toml` ⇒ 57), not
    // arrived at by adding one to the previous line.
    //
    // #681 committed TWO: `GATEWAY_RESIDENCY_POLICIES` ("[]"), the
    // no-control-database fallback for the residency policy, and
    // `GATEWAY_LOG_REGION` (""), the operator's assertion about where this
    // deployment's durable request log physically lives. 57 -> 59, re-derived
    // by running this gate against the merged `wrangler.toml` and
    // cross-checked with the same grep (⇒ 59).
    expect(DECLARED.vars.size).toBe(59);
    expect(DECLARED.bindings.size).toBeGreaterThanOrEqual(9);
    expect(READS.named.size).toBeGreaterThanOrEqual(60);

    // Four reads in four different SHAPES, so a regression in any one arm of
    // the scanner is caught rather than silently shrinking the read set:
    //   plain          `env.GATEWAY_MODELS`
    //   inline cast    `(env as {…}).FG_REQUIRE_AGENT_RUN_ID`
    //   string index   `env["GATEWAY_RELIABILITY"]`
    //   const index    `env[GUARDRAIL_POLICY_VAR]` → GATEWAY_GUARDRAIL_POLICIES
    expect(READS.named.has("GATEWAY_MODELS")).toBe(true);
    expect(READS.named.has("FG_REQUIRE_AGENT_RUN_ID")).toBe(true);
    expect(READS.named.has("GATEWAY_RELIABILITY")).toBe(true);
    expect(READS.named.has("GATEWAY_GUARDRAIL_POLICIES")).toBe(true);
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

  it("documents every secret in wrangler.toml, next to its name", () => {
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

  it("documents every indirectly-read secret, and keeps it out of [vars]", () => {
    // Not vacuous: the loop proves nothing on an empty list.
    expect(SECRETS_READ_INDIRECTLY.length).toBeGreaterThan(0);
    for (const name of SECRETS_READ_INDIRECTLY) {
      // It really is read by src/ — this is what stops the list being a place
      // to park a name nothing consults.
      expect(
        referencedInCode(name),
        `${name} is excepted as an indirectly-read secret but appears nowhere in src/`,
      ).toBe(true);
      // …and really is invisible to the scanner, i.e. it belongs on THIS list
      // and not in `SECRETS`. The day someone rewrites the read as `env.NAME`
      // this goes red and the name moves up, which is the correction we want.
      expect(READS.named.has(name)).toBe(false);
      // A committed value would be a leaked credential.
      expect(DECLARED.vars.has(name), `${name} is a secret and must not be in [vars]`).toBe(false);
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
      expect(mentionedInToml(name), `${name} is read but no longer documented`).toBe(true);
    }
  });

  it("records each undeclared BINDING as an open PORT-TODO, not an oversight", () => {
    for (const name of UNDECLARED_BINDINGS) {
      expect(mentionedInToml(name)).toBe(true);
      expect(
        documentedNear(name, /PORT-TODO/, 6),
        `${name} is read by src/ with no binding declared and no PORT-TODO explaining it`,
      ).toBe(true);
      expect(DECLARED.bindings.has(name)).toBe(false);
    }
  });

  /**
   * The INVERSE of the claim this file used to pin (issue #673).
   *
   * `AI` sat in {@link UNDECLARED_BINDINGS} with an assertion that
   * `wrangler.toml` has NO `[ai]` stanza — i.e. that every Workers AI code path
   * is dead in production. Two readers exist now (the `workers-ai` provider
   * family's dispatcher and the Llama-Guard detector), so that claim had to be
   * inverted rather than deleted: the stanza must be present, and the binding
   * must be reachable under the name the source actually reads.
   */
  it("declares the [ai] binding the Workers AI code paths read", () => {
    expect(/^\[ai\]/m.test(WRANGLER_TOML)).toBe(true);
    expect(DECLARED.bindings.get("AI")).toBe("[ai]");
    expect(READS.named.has("AI")).toBe(true);
  });

  it("pins the exact set of reads wrangler.toml does not even mention", () => {
    const silent = undeclared.filter((name) => !mentionedInToml(name));
    expect(silent).toEqual([...UNDOCUMENTED].sort());
  });

  it("pins every dynamic env[…] lookup site", () => {
    // A dynamic index is a var whose NAME comes from data — the tenant-database
    // router, the cache fingerprint, the guardrail detector table and the
    // provider-secret resolver all take a binding name from config and look it
    // up. Neither half of this gate can reason about those, so the sites are
    // enumerated instead: a NEW one is red, and has to be justified.
    const sites = Object.fromEntries(
      [...READS.dynamic].map(([ident, files]) => [ident, [...files].sort()]),
    );
    expect(sites).toEqual({
      key: ["../src/routes/readiness.ts"],
      name: [
        "../src/cache/fingerprint.ts",
        "../src/guardrails/detectors.ts",
        "../src/keys/provider-secrets.ts",
      ],
    });
  });
});

describe("every name wrangler.toml declares is read by the source", () => {
  it("has no dead [vars] entry", () => {
    const dead = [...DECLARED.vars.keys()].filter(
      (name) => !READS.named.has(name) && !(READ_INDIRECTLY as readonly string[]).includes(name),
    );
    expect(dead, "declared in [vars] but read nowhere in src/ — dead config").toEqual([]);
  });

  it("has no dead binding stanza", () => {
    const dead = [...DECLARED.bindings.keys()].filter(
      (name) => !READS.named.has(name) && !(READ_INDIRECTLY as readonly string[]).includes(name),
    );
    expect(dead, "a binding is declared but nothing in src/ reads it").toEqual([]);
  });

  it("FC-1's durable drain needed NO new binding — wave 22 is wrangler-INERT", () => {
    // Stated as an assertion rather than as prose in a commit message, because
    // "we added a binding and forgot the deploy config" is a failure mode that
    // only appears in production. The gateway's drain now reads the durable
    // `runtime-state/drain` document, and it does so through `CONTROL_DB` —
    // a binding this Worker ALREADY declared and already reads for RBAC, the
    // guardrail policy store and the agent-upstream registry.
    //
    // So there is nothing new to place in `CLOUD-VERIFICATION.md`: no stanza,
    // no placeholder id, no `[[migrations]]` tag, no `src/worker.ts` re-export.
    // If a future change moves that read onto a NEW binding, the two halves
    // below disagree and this is red before the deploy is attempted.
    expect(DECLARED.bindings.get("CONTROL_DB"), "CONTROL_DB stanza in wrangler.toml").toBe(
      "[[d1_databases]]",
    );
    const readiness = [...CODE.entries()].find(([path]) => path.endsWith("routes/readiness.ts"));
    expect(readiness, "src/routes/readiness.ts").toBeDefined();
    const source = (readiness as [string, string])[1];
    expect(source, "the drain resolver must read the DECLARED control binding").toMatch(
      /CONTROL_DB/,
    );
    expect(source).toContain("control_plane_resources");
    // And the whole read set stays inside what wrangler.toml knows about: no
    // binding name appears in the drain modules that the deploy config does not
    // declare (or explicitly except).
    const drainReads = new Set<string>();
    for (const path of ["routes/readiness.ts", "routes/drain.ts"]) {
      const entry = [...CODE.entries()].find(([p]) => p.endsWith(path));
      expect(entry, path).toBeDefined();
      for (const [, name] of (entry as [string, string])[1].matchAll(
        /\benv\??\.([A-Z][A-Z0-9_]{2,})\b/g,
      )) {
        drainReads.add(name as string);
      }
    }
    // Non-vacuity first: an empty set would make the loop below assert nothing,
    // which is the shape this repository keeps finding. BOTH drain sources must
    // be visible here — the durable binding and the deploy-time override.
    expect([...drainReads].sort(), "the drain's env read set").toEqual([
      "CONTROL_DB",
      "GATEWAY_DRAIN",
    ]);
    for (const name of drainReads) {
      expect(
        DECLARED.bindings.has(name) ||
          DECLARED.vars.has(name) ||
          (READ_INDIRECTLY as readonly string[]).includes(name),
        `the drain reads env.${name}, which wrangler.toml does not declare`,
      ).toBe(true);
    }
  });

  it("still finds a real reference for each indirectly-read name", () => {
    // Not vacuous: the loop proves nothing on an empty list.
    expect(READ_INDIRECTLY.length).toBeGreaterThan(0);
    for (const name of READ_INDIRECTLY) {
      expect(referencedInCode(name), `${name} is excepted as indirect but appears nowhere`).toBe(
        true,
      );
      expect(DECLARED.bindings.has(name) || DECLARED.vars.has(name)).toBe(true);
    }
  });
});

describe("which committed [vars] values this runner can actually observe", () => {
  /**
   * THE HONEST PART, and the direct measurement behind GW-T18's wording.
   *
   * `vitest.config.ts` pins several vars as explicit miniflare bindings, and an
   * explicit binding BEATS the `[vars]` table. For those, the committed value
   * is never exercised, so any test asserting on it would be asserting
   * something the runner cannot see. Rather than pretend otherwise, this
   * compares committed against runtime and requires every divergence to be
   * explained by a pin actually written in `vitest.config.ts`.
   *
   * Both failure modes are loud: a NEW silent override (a `.dev.vars` file on
   * one machine, say — the exact hazard `vitest.config.ts` documents) is red
   * because nothing in the config explains it, and a REMOVED pin is red because
   * the expected-override set shrinks.
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
    // #678: 56 -> 57 (`GATEWAY_ATTRIBUTION_POLICIES`). Same re-derivation as
    // the `DECLARED.vars.size` pin above.
    // #681: 57 -> 59 (`GATEWAY_RESIDENCY_POLICIES`, `GATEWAY_LOG_REGION`).
    expect(rows.length).toBe(59);
  });

  it("explains every overridden var with an explicit pin in vitest.config.ts", () => {
    const overridden = rows.filter((r) => r.runtime !== r.committed).map((r) => r.name);
    const unexplained = overridden.filter((name) => !pinnedInVitestConfig(name));
    expect(
      unexplained,
      "these [vars] do not reach the runner as committed, and vitest.config.ts does not pin them",
    ).toEqual([]);
    // Not vacuous: these really are overridden today, so an empty result would
    // mean the comparison stopped working.
    expect(overridden.sort()).toEqual(
      [
        "GATEWAY_NATIVE_API_KEYS",
        "GATEWAY_STATIC_API_KEYS",
        "SELF_HOSTED_WORKER_REGISTRY",
        "TENANCY_LIFECYCLE",
        "TENANT_RBAC_ACTIONS",
      ].sort(),
    );
  });

  it("records how many committed values ARE observable, and how many are not", () => {
    // The number GW-T18 is really about. Stated as an assertion so it cannot
    // drift silently in either direction: pinning one more var in
    // `vitest.config.ts`, or committing a different value for one, moves it.
    // WAVE 20: 44 -> 46. The two new `BILLING_ALERTS_*` vars ARE observable,
    // i.e. they DO reach the runner as committed — deliberately. `""` and `"5"`
    // are the OFF posture (`budgetAlertConfigFromEnv` requires a non-empty
    // http(s) URL), so the committed values configure no alerting in the suite,
    // and `test/metering/budget-alerts.test.ts` supplies its own URL and secret
    // on the env it passes. The committed value is therefore inert rather than
    // absent, which is what keeps it from shadowing a fixture.
    //
    // #664: 46 -> 48. `REQUEST_LOG_RETENTION_DAYS` ("400") and
    // `REQUEST_LOG_RETENTION_POLICIES` ("{}") are observable for the same
    // reason and are NOT inert — the committed 400-day window is a live policy,
    // which is the point (an unset window means "keep forever", and an evidence
    // table that grows without bound is the half of #664 that is not about
    // reading). `test/requestlog/mount.test.ts` asserts the committed value
    // parses into a real policy rather than a blank.
    //
    // #672: 50 -> 51. `GATEWAY_CLOUDFLARE` ("") is observable and INERT — the
    // empty account block is the OFF posture (`cloudflareAccountFromEnv` treats
    // blank as absent, and a provider that then asks to be routed refuses the
    // whole table), so the committed value configures no AI Gateway routing for
    // the suite. `test/inference/cloudflare-ai-gateway-mount.test.ts` supplies
    // its own account block on the env it drives, in its own isolate.
    //
    // #678: 51 -> 52. `GATEWAY_ATTRIBUTION_POLICIES` ("[]") is observable and
    // INERT — an empty table means no tenant requires tags, which is the
    // pre-#678 posture, so the committed value enforces nothing in this suite.
    // `test/attribution/enforcement.test.ts` supplies its own policies on the
    // env it drives, so the committed blank cannot shadow them.
    //
    // #681: 52 -> 54. `GATEWAY_RESIDENCY_POLICIES` ("[]") and
    // `GATEWAY_LOG_REGION` ("") are both observable and both INERT. An empty
    // policy table means no tenant is governed, which is the pre-#681 posture;
    // and `GATEWAY_LOG_REGION` is only ever CONSULTED for a tenant whose policy
    // says `log_residency = "in_region"`, so with no such tenant the blank
    // constrains nothing. `test/residency/enforcement.test.ts` supplies both on
    // the env it drives, so the committed blanks cannot shadow them.
    const observable = rows.filter((r) => r.runtime === r.committed);
    expect(observable.length).toBe(54);
    expect(rows.length - observable.length).toBe(5);
  });
});
