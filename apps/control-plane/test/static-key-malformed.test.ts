/**
 * A mis-shaped `CONTROL_PLANE_STATIC_API_KEYS` entry must FAIL CLOSED, not 500.
 *
 * `resolveApiKeys` builds a {@link JsonApiKeyAuthenticator} from
 * `parseJson<StaticKeyDeclaration[]>(env.CONTROL_PLANE_STATIC_API_KEYS, [])`.
 * `parseJson` validates that the value is JSON, but it CASTS the result to the
 * declared type without checking each field — so an operator who writes
 * `[{"key":"fg_…"}]` (the GATEWAY field name) instead of `[{"secret":"fg_…"}]`
 * produces an entry whose `secret` is `undefined` at runtime despite the
 * `readonly secret: string` type.
 *
 * The comparison `secretsEqual(key.secret, presentedKey)` then read `.length`
 * off `undefined` and threw a `TypeError`, which Hono's `onError` turned into a
 * `500 internal_error` on EVERY authenticated request — one typo took the whole
 * admin surface (and MCP's cross-app static-key leg, which shares the table)
 * down. `parseJson`'s own contract is the opposite: "A malformed binding must
 * not silently disable authentication. An empty key set means every credential
 * is unknown → 401, which fails closed." This pins that same posture ONE LEVEL
 * DEEPER — at the individual entry, not just the whole array.
 */
import { describe, expect, it } from "vitest";
import { JsonApiKeyAuthenticator } from "../src/adapters.js";

const FIXED_NOW = () => 1_000_000;

describe("JsonApiKeyAuthenticator: a static key entry with no `secret`", () => {
  it("does not throw — an unmatched credential falls through to `unknown` (→ 401)", async () => {
    // The exact operator mistake: `key` (the gateway field) instead of
    // `secret` (the control-plane field). `secret` is therefore `undefined`.
    const malformed = [{ key: "fg_wrong_field", id: "typo" }] as unknown as ConstructorParameters<
      typeof JsonApiKeyAuthenticator
    >[1];
    const auth = new JsonApiKeyAuthenticator([], malformed, FIXED_NOW);

    const resolution = await auth.authenticate("fg_wrong_field");
    expect(resolution.outcome).toBe("unknown");
  });

  it("skips the mis-shaped entry WITHOUT masking a well-formed one beside it", async () => {
    const keys = [
      { id: "broken" }, // no secret at all
      { secret: "fg_good", id: "healthy", organization_id: "tenant_a", scopes: ["*"] },
    ] as unknown as ConstructorParameters<typeof JsonApiKeyAuthenticator>[1];
    const auth = new JsonApiKeyAuthenticator([], keys, FIXED_NOW);

    // The healthy key still resolves...
    const good = await auth.authenticate("fg_good");
    expect(good.outcome).toBe("resolved");
    if (good.outcome === "resolved") {
      expect(good.auth.tenancy.tenantId).toBe("tenant_a");
    }

    // ...and an unknown credential is still a clean 401-shaped `unknown`, not a
    // crash from the broken entry sitting earlier in the array.
    const miss = await auth.authenticate("fg_nope");
    expect(miss.outcome).toBe("unknown");
  });

  it("also fails closed when a NATIVE key entry omits its `secret`", async () => {
    const native = [{ id: "broken_native" }] as unknown as ConstructorParameters<
      typeof JsonApiKeyAuthenticator
    >[0];
    const auth = new JsonApiKeyAuthenticator(native, [], FIXED_NOW);

    const resolution = await auth.authenticate("fg_anything");
    expect(resolution.outcome).toBe("unknown");
  });
});
