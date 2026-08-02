/**
 * Every REGISTERED family adjudicates the caching directive (issue #690).
 *
 * The `OwnedJsonObject` brand enforces "you copied before you mutated". It
 * cannot enforce "you adjudicated the caller's directive", because an adapter
 * that calls no mutator never touches a branded type at all — nothing in a type
 * system can require a call that produces no value. `azure-openai` sat in
 * exactly that blind spot: it builds its own upstream body, called neither
 * helper, and so answered 200 to a `{"mode":"off"}` it had never read while
 * forwarding `prompt_cache` verbatim to an upstream that rejects unknown
 * members. Two families had been fixed by hand and the third was simply not
 * remembered.
 *
 * What CAN be made total is the POPULATION. `GatewayProviderFamily` is derived
 * from `adapters.ts`'s own registry table, so {@link FAMILY_CACHING} below is
 * exhaustive by construction: a tenth adapter fails `bun run typecheck` until
 * someone states what it does with the directive and supplies a route to prove
 * it on. The declaration is then checked against the adapter's real behaviour,
 * so declaring a refusal without implementing it fails here too — the record is
 * a claim under test, not documentation.
 *
 * This runs at the ADAPTER boundary rather than through a dispatch, deliberately:
 * that is where adjudication lives, it is reached through the real
 * `defaultAdapterRegistry` (so the sweep cannot miss a family the deployed path
 * can resolve), and it needs no credentials or bindings — so all nine families
 * are covered rather than the three that are cheap to dispatch end to end.
 * `prompt-caching.test.ts` is where the dispatched proof lives.
 */
import { describe, expect, it } from "vitest";

import { defaultAdapterRegistry } from "../../src/inference/index.js";
import type { GatewayProviderFamily, PhysicalRoute } from "../../src/inference/index.js";

const SYSTEM_PROMPT = "You are a claims adjuster. <10k tokens of policy text>";

interface FamilyCaching {
  /** A route this family's adapter will accept, so the sweep reaches its body. */
  readonly route: PhysicalRoute;
  /**
   * `emitted` — this family has a per-request breakpoint and must put
   * {@link mechanism} on the wire. `refused` — it chooses its own prefix and
   * lifetime (or has no cache at all), so promising a caller's breakpoint would
   * be a promise nobody kept.
   */
  readonly explicit: "emitted" | "refused";
  /**
   * `honoured` — this family can guarantee the prompt is not written into a
   * provider cache, either by emitting no breakpoint or because it has no cache
   * to write into. `refused` — its caching is automatic and cannot be turned
   * off per request, so a 200 here would do the opposite of what was asked.
   */
  readonly off: "honoured" | "refused";
  /** The member a breakpoint family emits. Required when `explicit` is emitted. */
  readonly mechanism?: string;
}

const route = (
  over: Partial<PhysicalRoute> & Pick<PhysicalRoute, "providerKind">,
): PhysicalRoute => ({
  logicalModel: "sweep",
  provider: "sweep-provider",
  providerModel: "sweep-model",
  baseUrl: "https://sweep.example/v1",
  apiKey: "provider-secret",
  enabled: true,
  ...over,
});

/**
 * TOTAL over the registry. Adding a family to `REGISTERED_ADAPTERS` without a
 * row here is a compile error, which is the whole point of the record.
 */
const FAMILY_CACHING: Record<GatewayProviderFamily, FamilyCaching> = {
  "openai-compatible": {
    route: route({ providerKind: "openai-compatible" }),
    explicit: "refused",
    off: "refused",
  },
  anthropic: {
    route: route({ providerKind: "anthropic" }),
    explicit: "emitted",
    off: "honoured",
    mechanism: "cache_control",
  },
  grok: { route: route({ providerKind: "grok" }), explicit: "refused", off: "refused" },
  openrouter: { route: route({ providerKind: "openrouter" }), explicit: "refused", off: "refused" },
  // The family this sweep exists for: OpenAI-compatible in its caching but not
  // in its addressing, so it cannot delegate and had to be wired by hand.
  "azure-openai": {
    route: route({
      providerKind: "azure-openai",
      baseUrl: "https://example.openai.azure.example/?api-version=2024-02-15-preview",
    }),
    explicit: "refused",
    off: "refused",
  },
  gemini: { route: route({ providerKind: "gemini" }), explicit: "refused", off: "refused" },
  bedrock: {
    route: route({
      providerKind: "bedrock",
      baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.example",
      awsCredentials: {
        // The published AWS documentation example credentials, already used by
        // `packages/providers/test/sigv4-golden.test.ts`. Not a real key.
        accessKeyId: "AKIAIOSFODNN7EXAMPLE",
        secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region: "us-east-1",
      },
    }),
    explicit: "emitted",
    off: "honoured",
    mechanism: "cachePoint",
  },
  vertex: {
    route: route({
      providerKind: "vertex",
      baseUrl: "https://us-central1-aiplatform.googleapis.example",
      gcpCredentials: {
        accessToken: "ya29.EXAMPLE-ACCESS-TOKEN",
        projectId: "ferrogate-example",
        location: "us-central1",
      },
    }),
    explicit: "refused",
    off: "refused",
  },
  // The asymmetric one: Workers AI has NO prompt cache, so `explicit` is
  // refused (there is nothing to promise) while `off` is satisfied vacuously —
  // nothing was ever going to be written.
  "workers-ai": {
    route: route({
      providerKind: "workers-ai",
      baseUrl: "https://api.cloudflare.example/client/v4/accounts/acct_placeholder/ai",
    }),
    explicit: "refused",
    off: "honoured",
  },
};

const plan = (physical: PhysicalRoute, promptCache: unknown) => ({
  operation: "chat.completions" as const,
  route: physical,
  logicalModel: "sweep",
  providerModel: physical.providerModel,
  stream: false,
  body: {
    model: "sweep",
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: "is claim 91 covered?" },
    ],
    prompt_cache: promptCache,
  } as Record<string, unknown>,
});

const families = Object.entries(FAMILY_CACHING) as Array<[GatewayProviderFamily, FamilyCaching]>;

describe("no registered family may silently ignore the caching directive", () => {
  it("covers every family the deployed registry can resolve", () => {
    // Counted off the registry rather than carried forward: if this drifts, the
    // sweep below is testing a remembered population instead of the real one,
    // which is precisely the failure that let Azure through.
    for (const [family] of families) {
      expect(defaultAdapterRegistry.adapterFor(family), family).not.toBeNull();
    }
    expect(families).toHaveLength(9);
  });

  it("either honours a contract on the wire or refuses it — never a silent 200", () => {
    for (const [family, spec] of families) {
      for (const directive of [{ mode: "off" }, { mode: "explicit", ttl: "5m" }]) {
        const adapter = defaultAdapterRegistry.adapterFor(family);
        const result = adapter!.buildUpstreamRequest(plan(spec.route, directive));
        const label = `${family} / ${directive.mode}`;
        const disposition = directive.mode === "off" ? spec.off : spec.explicit;

        if (disposition === "refused") {
          expect(result.ok, label).toBe(false);
          // `unsupported_capability`, not `invalid_request`: the ladder treats
          // it as "try the next candidate", which is what makes a refusal a
          // re-route rather than a failed request.
          expect(result.ok === false && result.error.kind, label).toBe("unsupported_capability");
          continue;
        }
        expect(result.ok, label).toBe(true);
        const wire = JSON.stringify(result.ok === true ? result.request.body : undefined);
        if (disposition === "honoured") {
          // `off` is honoured by emitting no breakpoint AND removing any the
          // caller left, which is what makes the directive a control rather
          // than a comment. A family with no cache at all has nothing to strip.
          if (spec.mechanism !== undefined) expect(wire, label).not.toContain(spec.mechanism);
        } else {
          expect(wire, label).toContain(spec.mechanism);
        }
        expect(wire, label).not.toContain("prompt_cache");
      }
    }
  });

  it("accepts `auto` everywhere and never leaks FerroGate's own member", () => {
    for (const [family, spec] of families) {
      const adapter = defaultAdapterRegistry.adapterFor(family);
      const result = adapter!.buildUpstreamRequest(plan(spec.route, { mode: "auto" }));
      // `auto` is the mode documented as never refused; a family that refuses
      // it takes itself off every ladder for no reason the caller can act on.
      expect(result.ok, family).toBe(true);
      expect(
        JSON.stringify(result.ok === true ? result.request.body : undefined),
        family,
      ).not.toContain("prompt_cache");
    }
  });
});
