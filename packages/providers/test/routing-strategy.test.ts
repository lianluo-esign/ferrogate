/**
 * `RoutingStrategy`'s serde bridge — the half of the split enum this package
 * can hold.
 *
 * One closed vocabulary is declared in three places today: the PascalCase
 * variants (`src/models.ts`), the snake_case wire enum
 * (`src/schemas.ts:routingStrategySchema`) and — since the failover ladder
 * landed — `ROUTING_STRATEGIES` in `apps/gateway/src/inference/strategy.ts`.
 * Rust has exactly one, `#[serde(rename_all = "snake_case")] enum
 * RoutingStrategy`, and gets the mapping from the derive.
 *
 * These tests bind the two declarations INSIDE this package to each other, so a
 * strategy added to one and not the other fails here. They cannot reach the
 * gateway's third copy — that is stated in the surviving PORT-TODO on
 * `src/models.ts` and is a gateway edit — but they do guarantee that whichever
 * of the two a consumer picks, it sees the same closed set.
 */
import { describe, expect, test } from "vitest";

import {
  DEFAULT_ROUTING_STRATEGY,
  type RoutingStrategy,
  routingStrategyAsStr,
  routingStrategyFromStr,
  routingStrategySchema,
} from "../src/index.js";

/** Every in-memory variant, listed once so a new one has to be added here. */
const VARIANTS: RoutingStrategy[] = ["Priority", "LowestCost", "LowestLatency", "Balanced"];

describe("RoutingStrategy — the PascalCase variants and the wire enum are one set", () => {
  test("as_str produces exactly `routingStrategySchema`'s options, in order", () => {
    // Not `expect(x).toEqual(x)`: the left side is derived from the variant
    // table in models.ts, the right side from the Zod enum in schemas.ts. They
    // are separate declarations and this is what forces them to agree.
    expect(VARIANTS.map(routingStrategyAsStr)).toEqual([...routingStrategySchema.options]);
  });

  test("every wire value the schema accepts parses back to a variant", () => {
    for (const wire of routingStrategySchema.options) {
      const variant = routingStrategyFromStr(wire);
      expect(VARIANTS).toContain(variant);
      expect(routingStrategyAsStr(variant)).toBe(wire);
    }
  });

  test("the snake_case rename is real, not a lowercase() coincidence", () => {
    // `LowestCost` -> "lowestcost" would pass a naive round-trip test; serde
    // writes "lowest_cost", and the gateway's config var is read with that key.
    expect(routingStrategyAsStr("LowestCost")).toBe("lowest_cost");
    expect(routingStrategyAsStr("LowestLatency")).toBe("lowest_latency");
    expect(routingStrategySchema.safeParse("lowestcost").success).toBe(false);
    expect(routingStrategySchema.safeParse("LowestCost").success).toBe(false);
  });

  test("the default matches Rust's `#[default] Priority` on both sides", () => {
    expect(DEFAULT_ROUTING_STRATEGY).toBe("Priority");
    expect(routingStrategyAsStr(DEFAULT_ROUTING_STRATEGY)).toBe("priority");
  });

  test("an unknown name throws and names the accepted set (Rust `FromStr` error)", () => {
    expect(() => routingStrategyFromStr("cheapest")).toThrow(/unknown routing strategy/);
    expect(() => routingStrategyFromStr("cheapest")).toThrow(/lowest_cost/);
    // Case matters: the wire form is the only accepted spelling.
    expect(() => routingStrategyFromStr("Priority")).toThrow(/unknown routing strategy/);
  });
});
