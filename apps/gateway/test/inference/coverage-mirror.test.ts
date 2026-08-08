/**
 * #894 — the coverage MIRROR SELECTOR, `shadow.ts::coverageMirrorFor`.
 *
 * `test/evals/coverage-leg.test.ts` drives the deployed chain end to end and
 * proves a score lands on a leg that never served. It cannot reach the
 * selector's refusals: a ladder with a residency-violating candidate, a
 * credential whose provider allowlist forbids the fallback, the rotation across
 * more than two candidates, or the budget the mirror is charged against. Each of
 * those was `null`-tested by nothing, and every one of them either spends the
 * tenant's money or ships their prompt somewhere policy says it may not go.
 *
 * ## MUTATION LOG
 *
 * Every row below was applied to `src/`, run, and reverted.
 *
 * | mutation                                                                     | red |
 * |------------------------------------------------------------------------------|-----|
 * | `coverageMirrorFor`: drop the `callerCanUseProvider` filter on `nonPrimary`     | `never covers a provider the credential is forbidden to use` |
 * | `coverageMirrorFor`: drop the denied-PRIMARY refusal                           | `spends nothing on a request the ladder is about to refuse 403` |
 * | `coverageMirrorFor`: `const route = rotated[0]` (drop the residency re-check)   | `never covers a candidate the residency policy forbids` |
 * | `coverageMirrorFor`: delete the whole `budget` block                           | `charges coverage against its own budget key, never the mirror's` |
 * | `coverageMirrorFor`: `const rotated = [...nonPrimary]` (drop the rotation)      | `rotates coverage across every non-primary candidate` |
 * | `coverageMirrorFor`: `coverageCursor = (cursor + 1) % nonPrimary.length`        | `a short ladder does not clamp a longer ladder's rotation` |
 * | `coverageMirrorFor`: `shadowSampled(stickyKeyFor(caller) + "~coverage", …)`     | `samples per REQUEST, so both arms see the same caller population` |
 */
import { describe, expect, it } from "vitest";
import type { Caller, PhysicalRoute } from "../../src/inference/ports.js";
import {
  COVERAGE_BUDGET_LIMIT,
  coverageBudgetKey,
  coverageMirrorFor,
} from "../../src/inference/shadow.js";
import type { ResidencyPolicy } from "../../src/residency/policy.js";

const TENANT = "tenant_cov";
const MODEL = "ladder-model";

function route(provider: string, overrides: Partial<PhysicalRoute> = {}): PhysicalRoute {
  return {
    logicalModel: MODEL,
    provider,
    providerModel: `${provider}-model`,
    providerKind: "openai",
    baseUrl: `https://${provider}.test/v1`,
    apiKey: "sk-test",
    enabled: true,
    ...overrides,
  };
}

function caller(overrides: Partial<Caller> = {}): Caller {
  return {
    scope: { kind: "tenant", tenantId: TENANT },
    apiKeyId: "key_cov",
    ...overrides,
  } as Caller;
}

function mirrorFor(input: {
  readonly candidates: readonly PhysicalRoute[];
  readonly samplingKey: string;
  readonly caller?: Caller;
  readonly coveragePercent?: number;
  readonly residencyPolicy?: ResidencyPolicy | null;
}): ReturnType<typeof coverageMirrorFor> {
  return coverageMirrorFor({
    candidates: input.candidates,
    caller: input.caller ?? caller(),
    tenantId: TENANT,
    operation: "chat.completions",
    logicalModel: MODEL,
    body: { model: MODEL, messages: [{ role: "user", content: "hi" }] },
    coveragePercent: input.coveragePercent ?? 100,
    residencyPolicy: input.residencyPolicy ?? null,
    samplingKey: input.samplingKey,
  });
}

// ---------------------------------------------------------------------------
// The credential's provider allow/deny list (#894 review finding)
// ---------------------------------------------------------------------------

describe("coverage inherits the credential's provider allowlist", () => {
  it("never covers a provider the credential is forbidden to use", () => {
    // `callerCanUseProvider` is consulted in exactly ONE place on the served
    // path — inside `dispatchWithFailover`, terminally — and `planUpstream`'s
    // candidate list is deliberately NOT filtered by it. So a coverage mirror
    // reading `planned.candidates` would dispatch the tenant's prompt to a
    // provider the key is explicitly denied, and pay for the completion.
    const ladder = [route("openai-eu"), route("azure-us"), route("openai-us")];
    const restricted = caller({ allowedProviders: ["openai-eu", "openai-us"] });

    for (let index = 0; index < 8; index += 1) {
      const mirror = mirrorFor({
        candidates: ladder,
        caller: restricted,
        samplingKey: `r${index}`,
      });
      expect(mirror?.route.provider).not.toBe("azure-us");
    }
    // ANTI-VACUITY: the same ladder with an unrestricted key DOES reach
    // `azure-us`, so the assertion above is the allowlist and not a rotation
    // that happens never to land there.
    const seen = new Set<string>();
    for (let index = 0; index < 8; index += 1) {
      seen.add(mirrorFor({ candidates: ladder, samplingKey: `r${index}` })?.route.provider ?? "");
    }
    expect(seen.has("azure-us")).toBe(true);
  });

  it("honours a denylist as well as an allowlist", () => {
    const ladder = [route("openai-eu"), route("azure-us")];
    const denied = caller({ deniedProviders: ["azure-us"] } as Partial<Caller>);
    expect(mirrorFor({ candidates: ladder, caller: denied, samplingKey: "d1" })).toBeNull();
  });

  it("spends nothing on a request the ladder is about to refuse 403", () => {
    // The mirror is spawned BEFORE `dispatchWithFailover`. A request whose
    // PRIMARY the credential may not use is refused `provider_not_allowed` and
    // serves the client nothing — it must not already have shipped the prompt to
    // a second provider and paid for a completion.
    const ladder = [route("azure-us"), route("openai-eu")];
    const restricted = caller({ allowedProviders: ["openai-eu"] });
    expect(mirrorFor({ candidates: ladder, caller: restricted, samplingKey: "p1" })).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Residency (#681), re-applied on the second dispatch leg
// ---------------------------------------------------------------------------

describe("coverage re-applies the residency policy", () => {
  const EU_ONLY: ResidencyPolicy = {
    regionGated: true,
    allowedRegions: ["eu"],
    requireZeroDataRetention: false,
    logResidency: "unconstrained",
  };

  it("never covers a candidate the residency policy forbids", () => {
    // Coverage is a REAL outbound dispatch of the tenant's prompt to a second
    // provider, so a regression here is a data-residency violation, not a
    // metric error.
    const ladder = [
      route("openai-eu", { region: "eu" }),
      route("azure-us", { region: "us" }),
      route("openai-eu2", { region: "eu" }),
    ];
    for (let index = 0; index < 8; index += 1) {
      const mirror = mirrorFor({
        candidates: ladder,
        samplingKey: `res${index}`,
        residencyPolicy: EU_ONLY,
      });
      expect(mirror?.route.region).toBe("eu");
    }
    // ANTI-VACUITY: without the policy the same rotation does reach `azure-us`.
    const seen = new Set<string>();
    for (let index = 0; index < 8; index += 1) {
      seen.add(mirrorFor({ candidates: ladder, samplingKey: `res${index}` })?.route.provider ?? "");
    }
    expect(seen.has("azure-us")).toBe(true);
  });

  it("refuses rather than falls back when EVERY non-primary is out of region", () => {
    const ladder = [route("openai-eu", { region: "eu" }), route("azure-us", { region: "us" })];
    expect(
      mirrorFor({ candidates: ladder, samplingKey: "res-none", residencyPolicy: EU_ONLY }),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The budget — the one behaviour in this slice that spends without bound
// ---------------------------------------------------------------------------

describe("coverage carries its own budget", () => {
  it("charges coverage against its own budget key, never the mirror's", () => {
    // Without this field `runShadowMirror` falls back to
    // `route.shadowMaxRequests ?? 0`, i.e. UNCAPPED, charged against the shared
    // per-logical-model key an experiment mirror uses.
    const mirror = mirrorFor({
      candidates: [route("openai-eu"), route("azure-us")],
      samplingKey: "b1",
    });
    expect(mirror?.budget).toEqual({
      key: coverageBudgetKey(TENANT, MODEL),
      limit: COVERAGE_BUDGET_LIMIT,
    });
    expect(COVERAGE_BUDGET_LIMIT).toBeGreaterThan(0);
    // Per TENANT and per LADDER: one tenant's coverage cannot exhaust another's.
    expect(coverageBudgetKey(TENANT, MODEL)).not.toBe(coverageBudgetKey("tenant_other", MODEL));
    expect(coverageBudgetKey(TENANT, MODEL)).not.toBe(coverageBudgetKey(TENANT, "other-model"));
  });
});

// ---------------------------------------------------------------------------
// The rotation
// ---------------------------------------------------------------------------

describe("coverage rotates across the whole non-primary tail", () => {
  it("rotates coverage across every non-primary candidate", () => {
    // A fixed `candidates[1]` would leave positions 2 and 3 at `no_signal` for
    // ever — the blind spot #894 exists to remove, one position down.
    const ladder = [route("p0"), route("a1"), route("a2"), route("a3")];
    const covered = new Set<string>();
    for (let index = 0; index < 12; index += 1) {
      covered.add(
        mirrorFor({ candidates: ladder, samplingKey: `x${index}` })?.route.provider ?? "",
      );
    }
    expect(covered).toEqual(new Set(["a1", "a2", "a3"]));
  });

  it("a short ladder does not clamp a longer ladder's rotation", () => {
    // THE DEFECT. The cursor is one module global; reducing it modulo the
    // CURRENT ladder's non-primary count means a two-leg ladder (`% 1 === 0`)
    // resets it to zero on every sample, so a longer ladder sharing the isolate
    // always restarts at position 0 and its deeper candidates never accumulate a
    // score. Interleaving the two must still cover all of A.
    const long = [route("p0"), route("a1"), route("a2"), route("a3")];
    const short = [route("q0"), route("b1")];
    const covered = new Set<string>();
    for (let index = 0; index < 12; index += 1) {
      covered.add(mirrorFor({ candidates: long, samplingKey: `y${index}` })?.route.provider ?? "");
      mirrorFor({ candidates: short, samplingKey: `z${index}` });
    }
    expect(covered).toEqual(new Set(["a1", "a2", "a3"]));
  });
});

// ---------------------------------------------------------------------------
// The sample bucket
// ---------------------------------------------------------------------------

describe("coverage samples per request, not per caller", () => {
  it("samples per REQUEST, so both arms see the same caller population", () => {
    // A sticky per-API-key bucket makes the covered leg's scores come from a
    // FIXED caller subset while the served leg's come from everybody, so
    // `legQualityVerdicts` reads a difference between two prompt populations as
    // a difference between two providers. It also breaks the spend bound: one
    // key at 5% mirrors either 0% or 100% of its sampled traffic.
    const ladder = [route("p0"), route("a1")];
    const one = caller({ apiKeyId: "key_one" });
    let sampled = 0;
    const total = 400;
    for (let index = 0; index < total; index += 1) {
      if (
        mirrorFor({
          candidates: ladder,
          caller: one,
          coveragePercent: 25,
          samplingKey: `fg-req-${index}`,
        }) !== null
      ) {
        sampled += 1;
      }
    }
    // A sticky bucket would give exactly 0 or exactly `total`. A per-request
    // bucket gives roughly a quarter; the band is wide enough that the hash
    // never has to be re-derived here, and narrow enough to exclude both
    // degenerate answers.
    expect(sampled).toBeGreaterThan(total * 0.1);
    expect(sampled).toBeLessThan(total * 0.45);
  });

  it("still spends nothing at 0%, and always samples at 100%", () => {
    // The money guarantee, on both guards.
    const ladder = [route("p0"), route("a1")];
    for (let index = 0; index < 20; index += 1) {
      expect(
        mirrorFor({ candidates: ladder, coveragePercent: 0, samplingKey: `zero-${index}` }),
      ).toBeNull();
      expect(
        mirrorFor({ candidates: ladder, coveragePercent: 100, samplingKey: `all-${index}` }),
      ).not.toBeNull();
    }
  });

  it("is null for a ladder with no non-primary leg", () => {
    expect(mirrorFor({ candidates: [route("p0")], samplingKey: "solo" })).toBeNull();
    expect(mirrorFor({ candidates: [], samplingKey: "empty" })).toBeNull();
  });
});
