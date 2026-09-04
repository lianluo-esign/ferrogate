/**
 * THE CONTRACT BETWEEN `src/` AND `wrangler.toml`, DERIVED MECHANICALLY.
 *
 * ## The gap this closes — CP-T5
 *
 * `docs/rewrite/MOUNT-SEAMS.md` records CP-T5 as: the five `[vars]` fail-closed
 * empties are covered only "partially" by `test/auth.test.ts`, and **"No
 * name-drift gate exists here (the gateway has one; this app does not). Known
 * gap"**. Unlike the gateway, this Worker had no config gate of any kind beyond
 * `test/cron-trigger.test.ts`.
 *
 * This file closes it from both directions, both sides DERIVED rather than
 * hand-listed:
 *
 *   1. every var the source reads off `env` is DECLARED in `wrangler.toml`, or
 *      is one of a small, exactly-pinned set of classified exceptions; and
 *   2. every name `wrangler.toml` declares is READ by the source — a
 *      declared-but-unread var is dead configuration that tells an operator a
 *      knob exists when nothing consults it.
 *
 * Neither direction needs the committed VALUE to be observable, which is why it
 * works where a behavioural gate cannot: a fail-closed empty is behaviourally
 * identical to an absent var, but its NAME is still a contract, and a rename on
 * either side is now loud.
 *
 * ## Why it cannot rot
 *
 * The read side is derived by globbing every `.ts` file under `../src` with
 * `?raw` (a VITE transform — the bytes are inlined at build time, the only way
 * a workerd test with no filesystem can read source at all) and scanning for
 * env access. The declared side is derived by parsing the committed
 * `wrangler.toml` — the same bytes `vitest.config.ts` binds as
 * `TEST_WRANGLER_TOML`, asserted equal below so the two can never diverge. The
 * ONLY hand-written thing is the exception table, asserted with `toEqual` on
 * the exact set.
 *
 * ## The finding this gate records rather than hides
 *
 * SIX operator-visible knobs are read by `src/adapters.ts` and are not merely
 * undeclared — they are not NAMED anywhere in `wrangler.toml`, not even in a
 * comment. Four of them choose and configure the SITE-DOMAIN TXT RESOLVER, i.e.
 * whether domain-verification does real DNS-over-HTTPS or answers from a static
 * table. An operator reading the deploy config cannot discover that the switch
 * exists. Fixing that is a `wrangler.toml` edit, which is the integrate step's
 * file, so this gate PINS the list instead: it can only shrink by documenting
 * them, and it goes red if a seventh appears.
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
 * Deploy-time SECRETS (`wrangler secret put`) — NAMED in `wrangler.toml`'s
 * prose, never declared in `[vars]`, because a `[vars]` entry is committed
 * plaintext in a tracked file.
 *
 *  - `ADMIN_CONSOLE_JWT_SECRET` — the HS256 signing key for the admin-console
 *    session JWT (`src/session/`), which every SSO login also ends in. Wave 18
 *    mounted that surface on `src/index.ts` and documented the secret in
 *    `wrangler.toml`, which is what let this move out of {@link UNDOCUMENTED}.
 *  - `SITE_DOMAIN_CF_API_TOKEN` — the Cloudflare API token
 *    `GET /admin/v1/site-domains/{hostname}` reads custom-hostname certificate
 *    state with (#738). It needs the ZONE-level "SSL and Certificates: Edit"
 *    group, so it is a real credential and cannot be a committed `[vars]` line.
 *
 * Absence is SAFE for this one too, and behaviourally:
 * `resolveSiteDomainCertificates` falls back to
 * `UnconfiguredSiteDomainCertificates` when the token (or the zone, or the
 * account) is missing, so the endpoint reports `certificate_status:
 * "unconfigured"` and makes NO outbound call —
 * `test/site-domain-certificate.test.ts` pins that.
 *
 * Absence is SAFE, and that is asserted behaviourally rather than by
 * convention: `test/console-session.test.ts` ("an unconfigured deployment")
 * pins that with no secret bound every console route answers
 * `503 admin_console_unconfigured` instead of signing a session with a
 * guessable key.
 */
const SECRETS: readonly string[] = [
  "ADMIN_CONSOLE_JWT_SECRET",
  "SITE_DOMAIN_CF_API_TOKEN",
  // #697 — the two HMAC keys `src/finops/notify.ts` signs a spend-anomaly alert
  // with. Never `[vars]`: a plaintext signing key in a tracked file is a key
  // anyone who can read the repository can forge alerts with.
  "SPEND_ANOMALY_WEBHOOK_SIGNING_SECRET",
  "BILLING_ALERTS_WEBHOOK_SIGNING_SECRET",
  // The shared secret the vega BFF signs a trusted "already-verified email"
  // bridge-login with and `src/session/routes.ts` verifies before minting a
  // session with no password. Never `[vars]`: a plaintext value in a tracked
  // file is one any repository reader could forge a login with. vega-api and
  // this Worker MUST hold the identical value; a mismatch fails the bridge
  // login CLOSED. Absent ⇒ the bridge-login route is simply unavailable.
  "OAUTH_BRIDGE_LOGIN_SECRET",
];

/**
 * Vars deliberately left out of `[vars]`, each NAMED in the config's prose so
 * an operator can still discover it.
 *
 *  - `CONTROL_PLANE_STORE` — the durability switch. Deliberately UNSET so that
 *    absent means "D1 whenever `DB` is bound"; committing `"memory"` would ship
 *    a control plane that forgets everything on eviction.
 *  - `ADMIN_CONSOLE_ALLOWED_ORIGIN` — deliberately ABSENT so that with no
 *    console origin configured the CORS layer stays closed.
 *  - `SITE_DOMAIN_CERTIFICATES` (#738) — the custom-domain certificate backend
 *    switch. Deliberately UNSET so that absent means "this deployment does not
 *    read certificate state", which makes NO outbound Cloudflare call. Setting
 *    it is an explicit act, exactly like `SITE_DOMAIN_RESOLVER`.
 *  - `SITE_DOMAIN_CF_ZONE_ID` / `SITE_DOMAIN_CF_ACCOUNT_ID` — real account
 *    resource ids. A `[vars]` entry is committed plaintext in a tracked file and
 *    a committed zone id is a leak, so these are named in the config's prose and
 *    supplied at deploy time.
 *  - `SITE_DOMAIN_CERTIFICATE_RECORDS` — the deterministic backend's table.
 *    Absent because the deterministic backend is off by default.
 *
 * All are documented in `wrangler.toml`, which the assertion below holds.
 */
const DOCUMENTED_BUT_UNDECLARED = [
  "ADMIN_CONSOLE_ALLOWED_ORIGIN",
  "CONTROL_PLANE_STORE",
  "SITE_DOMAIN_CERTIFICATES",
  "SITE_DOMAIN_CERTIFICATE_RECORDS",
  "SITE_DOMAIN_CF_ACCOUNT_ID",
  "SITE_DOMAIN_CF_ZONE_ID",
  // #697 — the #170 budget-alert receiver, which spend-anomaly delivery falls
  // back to when no anomaly-specific URL is set. Declared in
  // `apps/gateway/wrangler.toml` (that Worker owns the budget alerter) and only
  // NAMED here, because declaring the same operator-facing URL in two deploy
  // configs is how the two come to disagree.
  "BILLING_ALERTS_WEBHOOK_URL",
  // #892 — the bootstrap model-catalog import's OPTIONAL fallback bindings. The
  // data-plane env tables and account block live in `apps/gateway/wrangler.toml`
  // (that Worker owns them); `POST /admin/v1/config/import-model-catalog` reads
  // them here ONLY when the import request body omits a field. Declaring the same
  // tables in a second Worker's `[vars]` is how the two come to disagree, so they
  // are NAMED in this app's `wrangler.toml` prose and supplied per-call instead —
  // exactly the `BILLING_ALERTS_WEBHOOK_URL` pattern above.
  "GATEWAY_CLOUDFLARE",
  "GATEWAY_MODELS",
  "GATEWAY_PROVIDERS",
] as const;

/**
 * CLOUDFLARE PRODUCT BINDINGS the source reads that this Worker does not declare
 * in the committed template — so the code path behind each is UNREACHABLE in
 * production today.
 *
 * `CONTROL_D1` (control-plane-d1 §Step2) is the control-plane's D1 database. As
 * the SINGLE control writer this Worker holds the PLAIN binding (primary
 * reads/writes, read-your-writes with no bookmark plumbing). `src/control-data.ts`
 * reads `env.CONTROL_D1` under the `"d1"` posture, but the committed default is
 * `CONTROL_PLANE_CONTROL_STORAGE = "durable_object"`, so that branch is never
 * taken and the read is dead in production while the dual-capability code ships
 * ahead of the cutover. The real binding is DEPLOY-TIME state in
 * wrangler.deploy.toml (a live `[[d1_databases]]` here would break the hermetic
 * miniflare load), so the template carries only a commented stanza + PORT-TODO.
 * When the posture flips to `"d1"` this graduates into a committed binding and
 * leaves this list.
 */
const UNDECLARED_BINDINGS = ["CONTROL_D1"] as const;

/**
 * Reads that `wrangler.toml` does not declare AND does not even mention.
 *
 * The honest residue, and the reason this file is worth more than a rename
 * check. `SITE_DOMAIN_RESOLVER` selects between the DNS-over-HTTPS resolver and
 * a static answer table for domain verification; the other three configure it.
 * `ADMIN_LIST_DEFAULT_LIMIT` / `ADMIN_LIST_MAX_LIMIT` are the admin pagination
 * ceilings. None appear in the deploy config in any form.
 *
 * `ADMIN_CONSOLE_JWT_SECRET` used to be parked here. Wave 18 mounted the
 * console-session surface on `src/index.ts` and documented the secret in
 * `wrangler.toml`, so it moved to {@link SECRETS} — which is the stricter list,
 * because that one asserts the name really is named in the deploy config.
 */
const UNDOCUMENTED = [
  "ADMIN_LIST_DEFAULT_LIMIT",
  "ADMIN_LIST_MAX_LIMIT",
  // The Workers Analytics Engine query bindings `src/adapters.ts` reads to back
  // the billing-analytics surface: an account id, an API token and a dataset
  // name. The token is a real credential and the account id a real resource id,
  // so like the `SITE_DOMAIN_CF_*` ids they are NEVER committed to `[vars]`;
  // they are supplied at deploy time and named in no config file, which is
  // exactly what lands them here rather than in DOCUMENTED_BUT_UNDECLARED.
  "BILLING_ANALYTICS_ACCOUNT_ID",
  "BILLING_ANALYTICS_API_TOKEN",
  "BILLING_ANALYTICS_DATASET",
  "SITE_DOMAIN_RESOLVER",
  "SITE_DOMAIN_RESOLVER_ENDPOINT",
  "SITE_DOMAIN_RESOLVER_TIMEOUT_MS",
  "SITE_DOMAIN_TXT_ANSWERS",
] as const;

/**
 * Declared names read through a renamed parameter, invisible to the
 * `env`-anchored scanner. None here — every declared name is read directly.
 */
const READ_INDIRECTLY: readonly string[] = [];

describe("the env-var drift gate itself", () => {
  it("inlined the real source tree — an empty scan would assert nothing", () => {
    const files = [...CODE.keys()];
    expect(files.length).toBeGreaterThan(40);
    expect(files.some((f) => f.endsWith("/src/adapters.ts"))).toBe(true);
    expect(files.some((f) => f.endsWith("/src/site_domain_txt.ts"))).toBe(true);
  });

  it("inlined the committed wrangler.toml, not a fixture", () => {
    expect(WRANGLER_TOML).toContain('name = "ferrogate-control-plane"');
    // The same bytes `vitest.config.ts` binds for `test/cron-trigger.test.ts`.
    // Asserting they agree keeps the two config gates from ever reading
    // different files.
    const bound = (env as unknown as { TEST_WRANGLER_TOML?: string }).TEST_WRANGLER_TOML;
    expect(bound).toBe(WRANGLER_TOML);
  });

  it("parsed both sides — neither an empty read set nor an empty declared set", () => {
    expect([...DECLARED.vars.keys()].sort()).toEqual([
      "CONTROL_PLANE_CONTROL_STORAGE",
      "CONTROL_PLANE_NATIVE_API_KEYS",
      "CONTROL_PLANE_SEED",
      "CONTROL_PLANE_STATIC_API_KEYS",
      // Track A G2: the `quota_policies` write source. `"control"` (default)
      // dual-writes each quota policy to the shared control object with a
      // tenant-object shadow; `"tenant_object"` writes ONLY the tenant object and
      // skips the control mirror. A plain `[vars]` entry — names a topology, holds
      // no secret. Read by `quotaPolicyWritesTenantObjectOnly` in
      // `store/quota_registry.ts`.
      "CONTROL_QUOTA_POLICY_SOURCE",
      // Track A G2: the `spend_throttles` write source. `"control"` (default)
      // dual-writes the finops auto-throttle to the shared control object with a
      // tenant-object shadow; `"tenant_object"` writes ONLY the tenant object and
      // no control mirror. A plain `[vars]` entry — it names a topology, holds no
      // secret. Read by `spendThrottleWritesTenantObjectOnly` in `finops/pass.ts`.
      "CONTROL_SPEND_THROTTLE_SOURCE",
      // #683: the SIEM export sinks. A `[vars]` entry rather than a secret
      // because it holds no secret BY CONSTRUCTION — a sink's credential is an
      // `env://` REFERENCE and `src/siem/config.ts` refuses an inline literal,
      // which is what makes this list safe to commit.
      // Track A G2: the `tenants.document_json` tenant-account write/read source.
      // `"control"` (default) mirrors the whole admin document into the shared
      // control object and serves the operator LIST from it; `"tenant_object"`
      // NULLs the mirror and fans the LIST out across each tenant object. A plain
      // `[vars]` entry — names a topology, holds no secret. Read by
      // `tenantAccountWritesTenantObjectOnly` in `store/quota_registry.ts`.
      "CONTROL_TENANT_ACCOUNT_SOURCE",
      "SIEM_EXPORT_SINKS",
      "SPEND_ANOMALY_WEBHOOK_TIMEOUT_SECS",
      "SPEND_ANOMALY_WEBHOOK_URL",
      "TENANCY_LIFECYCLE",
      "TENANT_DEFAULT_LOCATION_HINT",
      "TENANT_RBAC_ACTIONS",
    ]);
    // `PROMPT_LABELS` is the KV namespace the prompt deployment labels (#694)
    // write their edge pointer into; `apps/gateway` binds the same name and
    // reads it. `AUDIT_ANCHORS` is the R2 bucket the audit-anchor pass writes
    // (#684). Both joined `DB` in the same release, and both are listed here
    // rather than excepted because they are normal, operator-visible bindings.
    // The order is `wrangler.toml` declaration order: d1, then kv, then r2.
    // `SIEM_EXPORTS` (#683) is the SECOND R2 bucket, and the separation is
    // deliberate rather than incidental: `AUDIT_ANCHORS` is worth what it costs
    // to forge, so the bulk-export path must not hold write access to it.
    // `ASSETS` (#743) is the THIRD R2 bucket and the only one this Worker does
    // not own: it is the data plane's asset bucket, bound here for exactly one
    // operation (the operator force-delete) and narrowed to `delete` at the
    // composition root, so this Worker can reclaim an object and cannot fetch
    // one.
    // `TENANT_DATA` (#820) is the FOURTH and the only DURABLE OBJECT namespace,
    // and the only binding here declared with a `script_name`: it is the
    // gateway's `TenantDataObject`, borrowed cross-script so that
    // `idFromName(tenantId)` names the SAME object from both Workers. This
    // Worker mints tenants, so it is the Worker that has to record them on the
    // roster and seed their model catalog — into the object the data plane will
    // read, not one of its own. See the stanza's comment in `wrangler.toml` for
    // why it carries no `[[migrations]]` entry and no `src/worker.ts` re-export.
    // `LEGACY_TENANT_DB` — the pre-M9 shared tenant D1 (`ferrogate-tenant`) — has
    // LEFT this list. #821 PR2d deleted its stanza once the tenant-by-tenant
    // backfill that was its only reader retired (the `migrateTenantStorage` route
    // now answers 410 Gone), so this Worker binds NO D1 database at all.
    expect([...DECLARED.bindings.keys()]).toEqual([
      // Zero-D1 S5 (#881): the `DB` (`ferrogate-control`) stanza is deleted;
      // control reads resolve the CONTROL_DATA object. #821 PR2d then deleted the
      // last d1 stanza, `LEGACY_TENANT_DB`.
      "PROMPT_LABELS",
      // `KEY_DIRECTORY` (#882) is the SECOND KV namespace: the api_key_directory
      // projection this Worker WRITES and `apps/gateway` reads on the auth hot
      // path. Declared right after PROMPT_LABELS, so kv order is preserved.
      "KEY_DIRECTORY",
      // `PLATFORM_CONFIG` is the THIRD KV namespace: one deployment-wide,
      // non-secret provider/model projection written here and read by the
      // gateway. Polaris catalog writes never fan this graph out per tenant.
      "PLATFORM_CONFIG",
      // `IDENTITY_DIRECTORY` (#66) is the FOURTH KV namespace: the login-bootstrap
      // projection this Worker both writes and reads (CONTROL-PLANE-PRIVATE — the
      // gateway neither binds nor reads it). Declared after PLATFORM_CONFIG.
      "IDENTITY_DIRECTORY",
      "AUDIT_ANCHORS",
      "SIEM_EXPORTS",
      "ASSETS",
      "TENANT_DATA",
      "CONTROL_DATA",
      // Zero-D1 Plan B: the gateway's singleton `PlatformDataObject`, bound
      // CROSS-SCRIPT (like TENANT_DATA/CONTROL_DATA) as the home for platform/
      // unattributed guardrail evidence the operator read's platform leg reads.
      "PLATFORM_DATA",
    ]);
    expect(READS.named.size).toBeGreaterThanOrEqual(13);
    // Two reads in two different shapes, so a regression in either arm of the
    // scanner shrinks the read set loudly instead of silently.
    expect(READS.named.has("CONTROL_PLANE_SEED")).toBe(true);
    expect(READS.named.has("CONTROL_DATA")).toBe(true);
  });
});

/**
 * The deploy-config lines this app had NO gate for — measured GREEN under
 * mutation during the wave-17 seam pass (CP-T1, CP-T2), and both
 * deploy-blocking.
 */
describe("the deploy config's unobservable lines", () => {
  it("keeps nodejs_compat in compatibility_flags (CP-T2)", () => {
    // `@cloudflare/vitest-pool-workers` supplies its own runtime flags, so
    // commenting this line out left all 587 control-plane tests green while the
    // deployed Worker would fail to resolve `node:` builtins.
    expect(WRANGLER_TOML).toMatch(/^compatibility_flags\s*=\s*\[[^\]]*"nodejs_compat"/m);
  });

  it("pins a compatibility_date", () => {
    expect(WRANGLER_TOML).toMatch(/^compatibility_date\s*=\s*"\d{4}-\d{2}-\d{2}"/m);
  });

  it("points main at the ENTRY module, not the composition root (CP-T1)", () => {
    // `src/index.ts` exports `MOUNTED_ROUTES` (an array), and workerd rejects a
    // non-handler named export on the entry module AT STARTUP. That check is
    // DEPLOY-ONLY; the NAME is assertable here, which downgrades "the Worker
    // will not boot" to "a test fails".
    expect(WRANGLER_TOML).toMatch(/^main\s*=\s*"src\/worker\.ts"/m);
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
    for (const name of SECRETS) {
      expect(mentionedInToml(name)).toBe(true);
      expect(documentedNear(name, /secret/i, 8)).toBe(true);
    }
  });

  it("keeps every documented-but-undeclared knob named in wrangler.toml", () => {
    // Not vacuous: TEN entries today, counted off the table above — it was
    // two before #738 added the four `SITE_DOMAIN_*` knobs, seven with #697's
    // `BILLING_ALERTS_WEBHOOK_URL` fallback, and ten with #892's three
    // `GATEWAY_*` bootstrap-import fallback bindings, and the stale count is the
    // kind of drift this whole file exists to catch, so it does not get to live
    // here.
    expect(DOCUMENTED_BUT_UNDECLARED.length).toBe(10);
    for (const name of DOCUMENTED_BUT_UNDECLARED) {
      expect(mentionedInToml(name), `${name} is read but no longer documented`).toBe(true);
    }
  });

  it("pins the exact set of reads wrangler.toml does not even mention", () => {
    const silent = undeclared.filter((name) => !mentionedInToml(name));
    expect(silent).toEqual([...UNDOCUMENTED].sort());
  });

  it("pins every dynamic env[…] lookup site", () => {
    // A dynamic index is a var whose NAME comes from data, which neither half
    // of this gate can reason about. There is none here; if one appears this
    // goes red and forces a decision rather than leaving a silent hole.
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
   * agent-runtime rows unprovable in wave 14. This measures it instead of
   * assuming either way: committed value against runtime value, with every
   * divergence required to be explained by a pin actually written in
   * `vitest.config.ts`.
   *
   * Both failure modes are loud: a NEW silent override (a `.dev.vars` file on
   * one machine, say) is red because nothing in the config explains it, and a
   * REMOVED pin is red because the expected-override set shrinks.
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
    // EIGHT since #697 added the two `SPEND_ANOMALY_WEBHOOK_*` delivery knobs
    // (six since #683's `SIEM_EXPORT_SINKS`). Re-derived by counting the
    // committed `[vars]` table, not by incrementing the old number.
    // #879 added `CONTROL_PLANE_CONTROL_STORAGE` (Zero-D1 S3 posture) ⇒ 9.
    // Tokyo-forced tenant placement added `TENANT_DEFAULT_LOCATION_HINT` ⇒ 10.
    // The experiment/eval backfill gate `CONTROL_EXPERIMENT_EVAL_BACKFILL` was
    // added ⇒ 11, then RETIRED with the 0043 drop of its two projections ⇒ 10.
    // Track A G2 added `CONTROL_SPEND_THROTTLE_SOURCE` (spend_throttles write
    // source) ⇒ 11.
    // Track A G2 added `CONTROL_TENANT_ACCOUNT_SOURCE` (tenants.document_json
    // write/read source) ⇒ 12.
    // Track A G2 added `CONTROL_QUOTA_POLICY_SOURCE` (quota_policies write
    // source) ⇒ 13.
    expect(rows.length).toBe(13);
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

  it("records that ALL eight committed values reach this runner unchanged", () => {
    // NOTE (#683): `test/siem-export.test.ts` OVERRIDES `SIEM_EXPORT_SINKS` at
    // runtime to arm a sink, and restores it to the committed `"[]"` in its
    // `afterEach` for exactly this assertion — the pool shares one isolate per
    // file, and a leaked override would make this gate report a drift the
    // deploy config does not have.
    //
    // The good case, and worth stating: unlike the gateway (5 of 49 pinned) and
    // telemetry (1 of 1 pinned), nothing here is masked — `vitest.config.ts`
    // pins only test-fixture bindings, never a declared var. So a behavioural
    // test in this app IS exercising the committed config.
    //
    // Not vacuous: a pin added later flips this, and `expect(observable)` below
    // reads the RUNTIME values, so it also fails if `env` stopped resolving.
    const observable = rows.filter((r) => r.runtime === r.committed).map((r) => r.name);
    expect(observable.sort()).toEqual([...DECLARED.vars.keys()].sort());
    expect(observable.length).toBe(13);
  });
});
