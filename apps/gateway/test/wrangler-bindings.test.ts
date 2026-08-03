/**
 * The parts of `wrangler.toml` that NO behavioural test in this suite can see.
 *
 * ## Why this file exists
 *
 * The wave-12 mount-mutation sweep removed each wired seam one at a time and
 * required the suite to go red. THREE edits to the committed `wrangler.toml`
 * left all 1610 gateway tests GREEN, which means that part of the deploy config
 * was not mounted by anything — the exact "fake mount" shape this project keeps
 * finding:
 *
 *  1. deleting `new_sqlite_classes = ["RateLimiterDurableObject"]` from the
 *     `[[migrations]]` stanza. `@cloudflare/vitest-pool-workers` creates a
 *     Durable Object namespace from the BINDING alone and never consults the
 *     migration list, so the suite cannot tell. Cloudflare can: a
 *     `[[durable_objects.bindings]]` whose `class_name` was never introduced by
 *     a migration is rejected AT DEPLOY (`Cannot create binding for class
 *     RateLimiterDurableObject because it is not currently defined`), so the
 *     first `wrangler deploy` of the cloud verification would fail — and, worse,
 *     a class introduced with `new_classes` instead of `new_sqlite_classes`
 *     deploys fine and gives every counter the WRONG storage backend.
 *  2. deleting the whole `[[services]] TELEMETRY_COLLECTOR` stanza. Every
 *     telemetry test injects its own collector onto `env`, so none of them reads
 *     the declared binding; without this file the gateway could ship with no
 *     route to `apps/telemetry` at all and the suite would not notice.
 *  3. deleting `GATEWAY_SKILL_PACKAGES` / `GATEWAY_PROMPT_TEMPLATES` from
 *     `[vars]`. These are a weaker case and are treated as such below — see the
 *     third `describe`.
 *
 * `TEST_WRANGLER_TOML` is the COMMITTED file, bound verbatim by
 * `vitest.config.ts` (workerd has no filesystem). Asserting against a fixture
 * copy would prove nothing.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { BuiltinEicarScreener } from "../src/assets/ports.js";
import { withSignatureVerification } from "../src/assets/signature-screener.js";
import {
  CACHE_DISABLED_API_KEYS_VAR,
  CACHE_DISABLED_MODELS_VAR,
  CACHE_DISABLED_POLICY,
  CACHE_DISABLED_PROFILES_VAR,
  CACHE_ENABLED_VAR,
  CACHE_MAX_RECORDS_VAR,
  CACHE_MODE_VAR,
  CACHE_SEMANTIC_THRESHOLD_VAR,
  CACHE_TTL_VAR,
} from "../src/cache/config.js";
import { PROMPT_TEMPLATES_VAR } from "../src/routes/prompts.js";
import { SKILL_PACKAGES_VAR } from "../src/routes/skills.js";
import * as entry from "../src/worker.js";

function wranglerToml(): string {
  const raw = (env as unknown as { TEST_WRANGLER_TOML?: string }).TEST_WRANGLER_TOML;
  if (typeof raw !== "string" || raw.length === 0) {
    throw new Error(
      "gateway binding gate: TEST_WRANGLER_TOML is not bound; restore it in apps/gateway/vitest.config.ts",
    );
  }
  return raw;
}

/**
 * The bodies of every `[[<header>]]` array-of-tables stanza, as line lists.
 *
 * Line-oriented on purpose, exactly as `cron-trigger.test.ts` argues: a TOML
 * table ends at the next header, and a regex that spans headers is the kind of
 * subtlety that makes a config gate quietly match nothing. Comment lines are
 * dropped, so commenting a stanza out reads as deleting it — which is what it
 * is, and what the mutation sweep does.
 */
function stanzas(header: string): string[][] {
  const out: string[][] = [];
  let current: string[] | null = null;
  for (const line of wranglerToml().split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#")) continue;
    if (/^\[/.test(trimmed)) {
      if (current !== null) out.push(current);
      current = trimmed === `[[${header}]]` ? [] : null;
      continue;
    }
    if (current !== null && trimmed !== "") current.push(trimmed);
  }
  if (current !== null) out.push(current);
  return out;
}

/** `key = "value"` out of a stanza body. */
function value(body: readonly string[], key: string): string | undefined {
  for (const line of body) {
    const match = new RegExp(`^${key}\\s*=\\s*"([^"]*)"`).exec(line);
    if (match !== null) return match[1];
  }
  return undefined;
}

/** Every class named by any migration, split by which storage backend it got. */
function migratedClasses(): { sqlite: string[]; legacy: string[] } {
  const sqlite: string[] = [];
  const legacy: string[] = [];
  for (const body of stanzas("migrations")) {
    for (const line of body) {
      const match = /^(new_sqlite_classes|new_classes)\s*=\s*\[([^\]]*)\]/.exec(line);
      if (match === null) continue;
      const target = match[1] === "new_sqlite_classes" ? sqlite : legacy;
      for (const entryMatch of (match[2] ?? "").matchAll(/"([^"]+)"/g)) {
        target.push(entryMatch[1] as string);
      }
    }
  }
  return { sqlite, legacy };
}

describe("the runtime contract at the top of the file", () => {
  it("keeps nodejs_compat in compatibility_flags", () => {
    // GW-T2, corrected in wave 17. The row's *Expected RED* was "whole suite":
    // measured, deleting the line left every gateway suite GREEN, because
    // `@cloudflare/vitest-pool-workers` supplies its own runtime flags and does
    // not fail a module that needs `node:` builtins the way the deployed
    // Worker does. So the one line whose absence stops the Worker starting had
    // no gate at all.
    expect(wranglerToml()).toMatch(/^compatibility_flags\s*=\s*\[[^\]]*"nodejs_compat"/m);
  });

  it("pins a compatibility_date", () => {
    // Undated, Cloudflare applies the oldest semantics, silently changing
    // behaviour the whole port was written against.
    expect(wranglerToml()).toMatch(/^compatibility_date\s*=\s*"\d{4}-\d{2}-\d{2}"/m);
  });

  it("points main at the ENTRY module, not the composition root", () => {
    // GW-T1 is marked DEPLOY-ONLY because workerd's entrypoint-shape check is
    // what catches it. The NAME is still assertable here, which downgrades
    // "the Worker will not boot" to "a test fails".
    expect(wranglerToml()).toMatch(/^main\s*=\s*"src\/worker\.ts"/m);
  });
});

describe("every Durable Object binding is deployable", () => {
  const bindings = stanzas("durable_objects.bindings");

  it("declares at least the four classes this Worker exports", () => {
    // A guard on the gate itself: if the parser ever stopped matching, every
    // assertion below would pass vacuously over an empty list.
    expect(bindings.length).toBeGreaterThanOrEqual(4);
  });

  it("introduces each bound class in a [[migrations]] new_sqlite_classes", () => {
    const { sqlite, legacy } = migratedClasses();
    for (const body of bindings) {
      const className = value(body, "class_name");
      expect(
        className,
        `a [[durable_objects.bindings]] has no class_name: ${body.join(" ")}`,
      ).toBeDefined();
      // `new_classes` is not an acceptable substitute: it deploys, and then the
      // object gets the key-value backend instead of the SQLite one every
      // counter/state class here assumes.
      expect(legacy, `${className} was introduced with new_classes`).not.toContain(className);
      expect(sqlite, `${className} is bound but no migration introduces it`).toContain(className);
    }
  });

  it("binds each namespace under the NAME src/ reads it by", () => {
    // GW-T8/GW-T10/GW-T12, corrected in wave 17.
    //
    // Every assertion above is about `class_name`. NONE of them was about
    // `name`, and `name` is the half `src/` reads: `env.RATE_LIMIT`,
    // `env.PROVIDER_CIRCUIT`, `env.SHADOW_BUDGET`. Measured: renaming
    // `name = "RATE_LIMIT"` to anything else in `apps/gateway/wrangler.toml`
    // left BOTH cited gates green — `test/ratelimit/durable-object.spec.ts`
    // runs under `test/ratelimit/harness/vitest.config.ts`, which points at
    // `harness/wrangler.toml`, a DIFFERENT file, so the escalation suite
    // proves nothing about the deployed config.
    //
    // The consequence is not cosmetic. Each of these three reads degrades
    // SILENTLY when its binding is absent: `rateLimit()` falls back to the
    // per-isolate limiter (every isolate gets the full RPM allowance — the
    // quieter form of the admission bypass wave 16 closed), the provider
    // circuit becomes a per-isolate `Map`, and the shadow budget stops being a
    // cross-isolate cap.
    //
    // TENANT_DATA (#822) is the fourth, and the one whose absence does NOT
    // degrade: `src/tenancy/tenant-data.ts` reads it as
    // `env.TENANT_DATA.idFromName(tenantId)` and REFUSES with a 503 when it is
    // undefined, because a tenant's wallet has no per-isolate approximation.
    const names = bindings.map((body) => value(body, "name"));
    for (const required of ["RATE_LIMIT", "PROVIDER_CIRCUIT", "SHADOW_BUDGET", "TENANT_DATA"]) {
      expect(names, `no [[durable_objects.bindings]] is named ${required}`).toContain(required);
    }
  });

  it("gives TENANT_DATA the SQLite backend, which is immutable after deploy", () => {
    // #822. Named separately from the loops above rather than left to them,
    // because this is the one binding on this Worker whose misconfiguration is
    // UNRECOVERABLE. `new_classes` deploys cleanly and silently hands the
    // object the key-value backend, at which point `ctx.storage.sql` does not
    // exist and `TenantDataObject` has no database; the backend choice is then
    // IMMUTABLE for the life of the namespace (`storage_type_mismatch`), and
    // switching requires a `deleted` tombstone — i.e. every tenant's wallet,
    // usage and asset rows. There is no second chance at deploy time, so the
    // assertion is made here, before it.
    const tenantData = stanzas("durable_objects.bindings").find(
      (body) => value(body, "name") === "TENANT_DATA",
    );
    expect(tenantData, "no [[durable_objects.bindings]] is named TENANT_DATA").toBeDefined();
    expect(value(tenantData as string[], "class_name")).toBe("TenantDataObject");

    const { sqlite, legacy } = migratedClasses();
    expect(sqlite).toContain("TenantDataObject");
    expect(legacy).not.toContain("TenantDataObject");

    // And the entry-module half of the pair. The generic loop below asserts
    // this for every binding; it is repeated here so that deleting the
    // `export { TenantDataObject }` line from `src/worker.ts` names the class
    // in the failure message rather than reporting an anonymous `undefined`.
    expect(
      typeof (entry as unknown as Record<string, unknown>).TenantDataObject,
      "src/worker.ts does not re-export TenantDataObject; workerd resolves class_name against the ENTRY module",
    ).toBe("function");
  });

  it("resolves each bound class against the ENTRY module's exports", () => {
    // workerd resolves `class_name` against `main`. The three named exports in
    // `src/worker.ts` are held by their own mutation proofs; this closes the
    // loop from the CONFIG side, so adding a fourth binding without its export
    // fails here rather than at `wrangler dev`.
    for (const body of stanzas("durable_objects.bindings")) {
      const className = value(body, "class_name") as string;
      expect(
        typeof (entry as unknown as Record<string, unknown>)[className],
        `class_name ${className} is not exported by src/worker.ts`,
      ).toBe("function");
    }
  });
});

describe("the telemetry service binding", () => {
  it("declares TELEMETRY_COLLECTOR against ferrogate-telemetry", () => {
    const services = stanzas("services");
    const collector = services.find((body) => value(body, "binding") === "TELEMETRY_COLLECTOR");
    expect(collector, "no [[services]] stanza binds TELEMETRY_COLLECTOR").toBeDefined();
    // The name is load-bearing: it is resolved by NAME at deploy time against
    // the account's Workers, and `apps/telemetry/wrangler.toml` has `name =
    // "ferrogate-telemetry"`. A rename on either side silently unbinds it.
    expect(value(collector as string[], "service")).toBe("ferrogate-telemetry");
  });

  it("is actually READABLE at runtime, not merely declared", () => {
    // The declaration is only half the answer to "is this binding real". The
    // other half is that the runtime resolved it to something with a `fetch` —
    // which is what production gets from the service binding and what
    // `src/telemetry/emit.ts` calls. Under vitest this is the stub
    // `vitest.config.ts` registers; the shape is the deployed one.
    const collector = (env as unknown as { TELEMETRY_COLLECTOR?: { fetch?: unknown } })
      .TELEMETRY_COLLECTOR;
    expect(collector, "TELEMETRY_COLLECTOR is declared but did not resolve").toBeDefined();
    expect(typeof collector?.fetch).toBe("function");
  });
});

describe("the operator config tables the tooling routes read", () => {
  /**
   * A DELIBERATELY WEAKER gate than the two above, and it is worth being
   * explicit about why.
   *
   * The committed value of both vars is the fail-closed EMPTY table, which is
   * behaviourally identical to the var being absent (`parseSkillPackages` /
   * `parsePromptTemplates` return `[]` for both). So no behavioural test can
   * distinguish "declared empty" from "not declared", and the mount-mutation
   * sweep correctly reports removing them as GREEN. That is not a fake mount —
   * it is a var whose committed value is inert BY DESIGN, and it has to stay
   * inert: `test/auth.test.ts` asserts `/v1/skills` answers an empty catalog,
   * and vitest loads this same `wrangler.toml`, so a non-empty placeholder here
   * would turn tests red on a correct tree.
   *
   * What IS worth pinning is the DRIFT: the deploy config must name the exact
   * vars the handlers read (an operator who sets a mistyped var gets silence),
   * and the committed value must stay the fail-closed empty.
   */
  function vars(): Map<string, string> {
    const out = new Map<string, string>();
    let inVars = false;
    for (const line of wranglerToml().split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed.startsWith("#")) continue;
      if (/^\[/.test(trimmed)) {
        inVars = trimmed === "[vars]";
        continue;
      }
      const match = /^([A-Za-z0-9_]+)\s*=\s*"([^"]*)"/.exec(trimmed);
      if (inVars && match !== null) out.set(match[1] as string, match[2] as string);
    }
    return out;
  }

  it("declares the skill-package and prompt-template vars the handlers read", () => {
    const declared = vars();
    expect([...declared.keys()], "the [vars] parser matched nothing").toContain("GATEWAY_MODELS");
    expect(declared.has(SKILL_PACKAGES_VAR), `${SKILL_PACKAGES_VAR} is not declared`).toBe(true);
    expect(declared.has(PROMPT_TEMPLATES_VAR), `${PROMPT_TEMPLATES_VAR} is not declared`).toBe(
      true,
    );
  });

  it("commits the fail-closed EMPTY table for both", () => {
    const declared = vars();
    expect(declared.get(SKILL_PACKAGES_VAR)).toBe("[]");
    expect(declared.get(PROMPT_TEMPLATES_VAR)).toBe("[]");
  });
});

describe("the asset publisher-signature policy vars", () => {
  /**
   * Wave 13 added `src/assets/signature-screener.ts` in front of the asset
   * scanner. Its three bindings have the SAME inert-by-design shape as the
   * skill/prompt tables above — with all three blank
   * `withSignatureVerification` returns the inner screener by identity, so no
   * behavioural test in `test/assets/**` can distinguish "declared blank" from
   * "not declared", and the mount-mutation sweep reports removing them GREEN.
   *
   * So they are pinned HERE, on the two things that can actually rot:
   *
   *  1. DRIFT — the deploy config must name the exact three vars the code
   *     reads. An operator who sets a var this Worker does not read gets a
   *     signature gate that is silently off, which is the worst possible
   *     failure mode for this particular feature.
   *  2. POSTURE — the committed values must stay blank. `vitest` loads THIS
   *     `wrangler.toml`, so a non-empty placeholder would start refusing or
   *     relabeling pushes in the unit suite on a correct tree.
   *
   * The third case is the one that makes this a real gate rather than a
   * spelling test: it feeds each DECLARED name back into the actual
   * `withSignatureVerification` and requires it to change the composition.
   * Rename the var in `src/` without renaming it here (or vice versa) and this
   * goes red.
   */
  const SIGNATURE_VARS = [
    "FERROGATE_ASSET_REQUIRE_SIGNATURE",
    "FERROGATE_ASSET_PUBLISHER_ED25519_KEYS",
    "FERROGATE_ASSET_PUBLISHER_MINISIGN_KEYS",
  ] as const;

  /**
   * The `[vars]` table, re-parsed here rather than shared with the describe
   * above so this gate keeps working if that one is ever reorganised.
   */
  function declaredSignatureVars(): Map<string, string> {
    const out = new Map<string, string>();
    let inVars = false;
    for (const line of wranglerToml().split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed.startsWith("#")) continue;
      if (/^\[/.test(trimmed)) {
        inVars = trimmed === "[vars]";
        continue;
      }
      const match = /^(FERROGATE_ASSET_[A-Za-z0-9_]+)\s*=\s*"([^"]*)"/.exec(trimmed);
      if (inVars && match !== null) out.set(match[1] as string, match[2] as string);
    }
    return out;
  }

  it("declares the exact three vars src/assets/signature*.ts reads", () => {
    const declared = declaredSignatureVars();
    expect([...declared.keys()].sort()).toEqual([...SIGNATURE_VARS].sort());
  });

  it("commits the inert OFF posture for all three", () => {
    for (const name of SIGNATURE_VARS) {
      expect(declaredSignatureVars().get(name), `${name} must be committed blank`).toBe("");
    }
  });

  it("proves each DECLARED name is one the screener composition actually reads", () => {
    const declared = [...declaredSignatureVars().keys()];
    // Not vacuous: the loop below proves nothing on an empty list.
    expect(declared.length).toBe(SIGNATURE_VARS.length);
    const inner = new BuiltinEicarScreener();
    expect(withSignatureVerification(inner, {})).toBe(inner);
    for (const name of declared) {
      // The switch takes a boolean word; the two key tables take key material.
      const value = name.endsWith("REQUIRE_SIGNATURE") ? "1" : "publisher-a=AAAA";
      const composed = withSignatureVerification(inner, { [name]: value });
      expect(composed, `${name} is declared but nothing in src/ reads it`).not.toBe(inner);
    }
  });
});

describe("the response-cache [vars] src/cache/config.ts reads", () => {
  /**
   * A NAME-DRIFT gate, in the same weaker class as the asset-signature one
   * above, and added in wave 14 for a specific reason.
   *
   * That wave ported the SEMANTIC cache layer (`src/cache/semantic.ts`) and
   * with it a new operator var, `GATEWAY_CACHE_SEMANTIC_THRESHOLD`. The var was
   * read by `cachePolicyFromEnv` but declared NOWHERE in the deploy config,
   * while the other seven members of its family were — so an operator who set
   * `GATEWAY_CACHE_MODE = "semantic"` had no adjacent knob for the cut-off and
   * no way to discover one.
   *
   * The committed value is the code's own fallback (`0.92`, the Rust default),
   * which is deliberate: it means declaring it CANNOT change behaviour, and it
   * also means a behavioural gate is impossible — deleting the line is
   * indistinguishable from keeping it, exactly as `MOUNT-SEAMS.md` GW-T18 says
   * of the other fail-closed empties. What a test CAN hold is that the config
   * keeps naming every var the code reads, so a rename on either side is loud.
   */
  function declaredVars(): Set<string> {
    const declared = new Set<string>();
    let inVars = false;
    for (const line of wranglerToml().split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed.startsWith("#")) continue;
      if (/^\[/.test(trimmed)) {
        inVars = trimmed === "[vars]";
        continue;
      }
      const match = /^([A-Z0-9_]+)\s*=/.exec(trimmed);
      if (inVars && match !== null) declared.add(match[1] as string);
    }
    return declared;
  }

  const CACHE_VARS = [
    CACHE_ENABLED_VAR,
    CACHE_TTL_VAR,
    CACHE_MAX_RECORDS_VAR,
    CACHE_MODE_VAR,
    CACHE_SEMANTIC_THRESHOLD_VAR,
    CACHE_DISABLED_MODELS_VAR,
    CACHE_DISABLED_API_KEYS_VAR,
    CACHE_DISABLED_PROFILES_VAR,
  ];

  it("declares every var the cache policy reads", () => {
    const declared = declaredVars();
    // A guard on the parser: if it ever matched nothing, the loop below would
    // pass vacuously.
    expect([...declared], "the [vars] parser matched nothing").toContain("GATEWAY_MODELS");
    for (const name of CACHE_VARS) {
      expect(declared, `${name} is read by src/cache/config.ts but not declared`).toContain(name);
    }
  });

  it("commits the semantic threshold at the value the code falls back to", () => {
    // If these two ever diverge, an operator reading the deploy config would be
    // told a different default than an operator reading the code.
    expect(wranglerToml()).toMatch(new RegExp(`^${CACHE_SEMANTIC_THRESHOLD_VAR} = "0\\.92"$`, "m"));
    expect(CACHE_DISABLED_POLICY.semanticSimilarityThreshold).toBe(0.92);
  });

  it("ships the cache DISABLED, so an unconfigured deployment caches nothing", () => {
    expect(wranglerToml()).toMatch(new RegExp(`^${CACHE_ENABLED_VAR} = "false"$`, "m"));
  });
});
