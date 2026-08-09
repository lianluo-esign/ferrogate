/**
 * PINS FOR THE THREE ELIGIBILITY DEVIATIONS in `src/inference/candidates.ts`.
 *
 * Same contract as `test/inference/platform-limits.test.ts` and
 * `test/streaming/parity-limits.test.ts`, for the third kind of kept marker:
 * a PARTIAL port. `routeExclusionReasons` is deliberately wider than
 * `model_routing.rs::route_exclusion_reasons` on three legs, and the marker on
 * that function is open precisely because the fix for each is blocked on a file
 * this slice does not own (`wrangler.toml` for 1 and 2, a green assertion's
 * expectation for 3).
 *
 * A PARTIAL marker with no test is the worst outcome available: the Rust
 * behavior is gone AND nothing holds the substitute, so the substitute can
 * drift into something looser than the comment promises and every suite stays
 * green. Deviation 3 is the proof — it went undocumented for three burndown
 * waves and the in-body comment described a Rust behavior that
 * `model_routing.rs:374` does not have.
 *
 * Each test therefore asserts BOTH directions: what the port does, and the Rust
 * answer it is not giving. That way the pin goes red if the deviation widens,
 * AND it names the exact assertion a future 1:1 pass has to flip.
 */

import { describe, expect, it } from "vitest";
import {
  eligibleCandidates,
  routeExclusionReasons,
  routeRequirements,
} from "../../src/inference/index.js";
import type { PhysicalRoute, RouteRequirements } from "../../src/inference/index.js";
import type { ResidencyPolicy } from "../../src/residency/index.js";

/** A route that declares NOTHING optional — the shape `GATEWAY_MODELS` ships. */
const UNDECLARED: PhysicalRoute = {
  logicalModel: "m",
  provider: "p",
  providerModel: "pm",
  providerKind: "openai",
  baseUrl: "https://p.test/v1",
  enabled: true,
};

const CHAT_BODY = { model: "m", messages: [{ role: "user", content: "hi" }] };

const IMAGE_BODY = {
  model: "m",
  messages: [
    {
      role: "user",
      content: [
        { type: "text", text: "what is this" },
        { type: "image_url", image_url: { url: "https://img.example/a.png" } },
      ],
    },
  ],
};

describe("deviation 1 — an undeclared `capabilities` is neutral for EVERY endpoint", () => {
  it("does not exclude an undeclared route from a STREAMING chat request", () => {
    // Rust: `allow_undeclared_capabilities` needs `capabilities.len() == 1`, and
    // a streaming request requires `{Chat, Streaming}`, so the legacy escape
    // hatch is OFF and the undeclared route is excluded twice
    // (`missing_capability` for each). Here it survives.
    const requirements = routeRequirements("chat.completions", CHAT_BODY, true, 8);
    expect(requirements.capabilities).toEqual(expect.arrayContaining(["chat", "streaming"]));
    expect(routeExclusionReasons(UNDECLARED, requirements, null)).toEqual([]);
  });

  it("does not exclude an undeclared route from an EMBEDDINGS request", () => {
    // Rust: `Embeddings` is not a conversational endpoint, so the hatch is off
    // and the undeclared route is `missing_capability=embeddings`.
    const requirements = routeRequirements("embeddings", { model: "m", input: "hi" }, false, 4);
    expect(requirements.capabilities).toContain("embeddings");
    expect(routeExclusionReasons(UNDECLARED, requirements, null)).toEqual([]);
  });

  it("STILL holds a route that DID declare capabilities to the exact Rust test", () => {
    // The half that is not deviated, and the reason the deviation is called a
    // "declare to arm" rule: declaring the field arms the full Rust gate.
    const requirements = routeRequirements("chat.completions", CHAT_BODY, true, 8);
    const declared: PhysicalRoute = { ...UNDECLARED, capabilities: ["chat"] };
    const reasons = routeExclusionReasons(declared, requirements, null);
    expect(reasons.map((reason) => reason.code)).toEqual(["missing_capability"]);
    expect(reasons[0]?.detail).toBe("required_capability=streaming");
  });
});

describe("deviation 2 — an undeclared `context_window` never excludes", () => {
  const requirements: RouteRequirements = {
    capabilities: ["chat"],
    requiredContextWindow: 100_000,
    unboundedMediaContext: false,
  };

  it("admits a route with no declared window against a huge requirement", () => {
    // Rust: `ContextWindowUndeclared { required: 100000 }`.
    expect(routeExclusionReasons(UNDECLARED, requirements, null)).toEqual([]);
  });

  it("excludes a DECLARED window that is too small, exactly as Rust does", () => {
    const small: PhysicalRoute = { ...UNDECLARED, contextWindow: 8_192 };
    const reasons = routeExclusionReasons(small, requirements, null);
    expect(reasons.map((reason) => reason.code)).toEqual(["context_window_too_small"]);
    expect(reasons[0]?.detail).toBe("required_context_window=100000;declared_context_window=8192");
  });
});

describe("deviation 3 — unbounded media context does NOT exclude a window-less route", () => {
  it("marks an image-bearing chat body as unbounded and requires `vision`", () => {
    const requirements = routeRequirements("chat.completions", IMAGE_BODY, false, 64);
    expect(requirements.unboundedMediaContext).toBe(true);
    expect(requirements.capabilities).toContain("vision");
    // Rust also drops `required_context_window` on this branch.
    expect(requirements.requiredContextWindow).toBeUndefined();
  });

  it("leaves a route WITHOUT a declared window eligible — Rust excludes it", () => {
    // THE DEVIATION. `model_routing.rs:374` pushes `MediaContextUnbounded` for
    // every route unconditionally, so Rust's `eligible_routes` is empty here and
    // `rejection()` answers 400 `invalid_request`. This port serves the request.
    //
    // A 1:1 pass flips this expectation to a one-element
    // `["media_context_unbounded"]`, and must then also flip
    // `test/inference/validation.test.ts` → "accepts the multimodal
    // content-part array form" from 200 to 400. Those two edits are the whole
    // change; they are named here so the next owner does not have to find them.
    const requirements = routeRequirements("chat.completions", IMAGE_BODY, false, 64);
    expect(routeExclusionReasons(UNDECLARED, requirements, null)).toEqual([]);

    const decision = eligibleCandidates([UNDECLARED], requirements, null);
    expect(decision.eligible).toHaveLength(1);
    expect(decision.exclusions).toEqual([]);
  });

  it("DOES exclude a route that declared a window — the half that is 1:1", () => {
    // The guard the port added is `route.contextWindow !== undefined`, so a
    // declaring route gets the Rust answer. Without this assertion the guard
    // could be deleted outright and only the test above would notice, which
    // would read as "the deviation got worse" rather than "it got fixed".
    const requirements = routeRequirements("chat.completions", IMAGE_BODY, false, 64);
    const declaring: PhysicalRoute = { ...UNDECLARED, contextWindow: 200_000 };
    const reasons = routeExclusionReasons(declaring, requirements, null);
    expect(reasons.map((reason) => reason.code)).toEqual(["media_context_unbounded"]);
  });
});

/**
 * The residency policy shape #681 replaced the bare `regionAllowlist` argument
 * with, restricted to the REGION leg so the four assertions below still say
 * exactly what they said before.
 *
 * The signature change was deliberate and is stated in the PR: the region gate
 * moved into `residency/policy.ts::residencyViolations` so that the SHADOW
 * MIRROR — which is not a candidate and never reaches `routeExclusionReasons` —
 * applies the identical rule. The BEHAVIOUR these cases pin is unchanged: an
 * absent policy is no gate, an armed one excludes an undeclared region, a
 * declared region outside the list, and nothing else.
 */
function regionsOnly(...allowedRegions: readonly string[]): ResidencyPolicy {
  return {
    regionGated: true,
    allowedRegions,
    requireZeroDataRetention: false,
    logResidency: "unconstrained",
  };
}

describe("region is NOT deviated from", () => {
  const requirements: RouteRequirements = {
    capabilities: [],
    unboundedMediaContext: false,
  };

  it("is no gate at all when the tenant has no policy", () => {
    expect(routeExclusionReasons(UNDECLARED, requirements, null)).toEqual([]);
  });

  it("excludes an UNDECLARED region once the policy is armed", () => {
    // The one leg where an omitted field DOES exclude in this port, because it
    // does in Rust (`None => reasons.push(RegionUndeclared)`).
    const reasons = routeExclusionReasons(UNDECLARED, requirements, regionsOnly("eu"));
    expect(reasons.map((reason) => reason.code)).toEqual(["region_undeclared"]);
  });

  it("excludes a declared region outside the allowlist", () => {
    const us: PhysicalRoute = { ...UNDECLARED, region: "us" };
    const reasons = routeExclusionReasons(us, requirements, regionsOnly("eu"));
    expect(reasons.map((reason) => reason.code)).toEqual(["region_not_allowed"]);
    expect(reasons[0]?.detail).toBe("declared_region=us");
  });

  it("admits a declared region INSIDE the allowlist", () => {
    const eu: PhysicalRoute = { ...UNDECLARED, region: "eu" };
    expect(routeExclusionReasons(eu, requirements, regionsOnly("eu"))).toEqual([]);
  });
});
