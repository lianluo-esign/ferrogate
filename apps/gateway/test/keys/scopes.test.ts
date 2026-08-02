/**
 * The membership scope ladder and the narrowing rule.
 *
 * Pure logic (no binding), ported from
 * `crates/ferrogate-auth-service/src/membership_role.rs` (issue #517). The
 * defect that module was written to close: every console session — `viewer`
 * included — was minted a fixed `admin.read + admin.write + assets.read +
 * assets.write` gateway key, so an invited viewer walked away with a credential
 * that could mutate the control plane. The ladder below is the fix, and these
 * assertions are what stop it from being flattened again.
 */
import { describe, expect, test } from "vitest";
import {
  INFERENCE_SCOPES,
  MEMBERSHIP_ROLES,
  isOwnerRole,
  membershipRoleAtLeast,
  membershipRoleFromStored,
  membershipRoleGatewayScopes,
  narrowScopes,
  parseMembershipRole,
} from "../../src/keys/index.js";
import { hasScope, isPrivilegedScope } from "../../src/ports.js";

describe("the seven inference scopes", () => {
  test("are exactly the contract's inference scopes, and none is privileged", () => {
    // Six until issue #703 added `audio.create`, the first data-plane scope
    // minted since the port began. It is not a widening of anything: `hasScope`
    // gives an UNSCOPED key every non-privileged scope (asserted below), and a
    // key with an explicit scope list simply does not hold this one until it is
    // re-minted — which is the fail-closed direction and exactly what a new
    // capability should do to credentials issued before it existed.
    expect([...INFERENCE_SCOPES].sort()).toEqual(
      [
        "audio.create",
        "chat.completions",
        "embeddings.create",
        "images.generate",
        "messages.create",
        "models.read",
        "responses.create",
      ].sort(),
    );
    expect(INFERENCE_SCOPES).toHaveLength(7);
    for (const scope of INFERENCE_SCOPES) {
      expect(isPrivilegedScope(scope)).toBe(false);
    }
  });

  test("an unscoped durable key reaches every one of them, and no admin scope", () => {
    for (const scope of INFERENCE_SCOPES) {
      expect(hasScope([], scope)).toBe(true);
    }
    expect(hasScope([], "admin.read")).toBe(false);
    expect(hasScope([], "admin.write")).toBe(false);
  });
});

describe("MembershipRole parsing", () => {
  test("the ladder is owner > admin > member > viewer", () => {
    expect(MEMBERSHIP_ROLES).toEqual(["owner", "admin", "member", "viewer"]);
    expect(membershipRoleAtLeast("owner", "viewer")).toBe(true);
    expect(membershipRoleAtLeast("admin", "member")).toBe(true);
    expect(membershipRoleAtLeast("member", "admin")).toBe(false);
    expect(membershipRoleAtLeast("viewer", "viewer")).toBe(true);
  });

  test("parsing is CASE-SENSITIVE, so `Owner` is not owner", () => {
    // Rust is explicit that this is deliberate: the pre-#517 gates were literal
    // `role != "owner"` compares, so accepting `"Owner"` would GRANT owner
    // authority to a stored value that is denied today.
    expect(parseMembershipRole("owner")).toBe("owner");
    expect(parseMembershipRole("Owner")).toBeNull();
    expect(parseMembershipRole("OWNER")).toBeNull();
    expect(parseMembershipRole("superadmin")).toBeNull();
    expect(parseMembershipRole("")).toBeNull();
  });

  test("a stored value that is not a tier resolves to VIEWER, never owner", () => {
    // The dangerous-default guard: a typo'd or hostile role string in a D1 row
    // (which never carried the Postgres CHECK) must land on the least
    // privileged tier.
    expect(membershipRoleFromStored("owner")).toBe("owner");
    expect(membershipRoleFromStored("Owner")).toBe("viewer");
    expect(membershipRoleFromStored("root")).toBe("viewer");
    expect(membershipRoleFromStored("")).toBe("viewer");
    expect(isOwnerRole(membershipRoleFromStored("Owner"))).toBe(false);
    expect(isOwnerRole(membershipRoleFromStored("admin"))).toBe(false);
    expect(isOwnerRole(membershipRoleFromStored("owner"))).toBe(true);
  });
});

describe("the tier scope ladder", () => {
  test("matches the Rust table exactly", () => {
    expect(membershipRoleGatewayScopes("owner")).toEqual([
      "admin.read",
      "admin.write",
      "assets.read",
      "assets.write",
    ]);
    expect(membershipRoleGatewayScopes("admin")).toEqual([
      "admin.read",
      "admin.write",
      "assets.read",
      "assets.write",
    ]);
    expect(membershipRoleGatewayScopes("member")).toEqual([
      "admin.read",
      "assets.read",
      "assets.write",
    ]);
    expect(membershipRoleGatewayScopes("viewer")).toEqual(["admin.read", "assets.read"]);
  });

  test("`admin.write` — the self-escalation scope — reaches only owner and admin", () => {
    // Any `admin.write` holder can mint an arbitrarily-scoped key via
    // POST /admin/v1/virtual-keys, so this is THE line in the ladder.
    expect(hasScope(membershipRoleGatewayScopes("owner"), "admin.write")).toBe(true);
    expect(hasScope(membershipRoleGatewayScopes("admin"), "admin.write")).toBe(true);
    expect(hasScope(membershipRoleGatewayScopes("member"), "admin.write")).toBe(false);
    expect(hasScope(membershipRoleGatewayScopes("viewer"), "admin.write")).toBe(false);
  });

  test("a VIEWER holds no `.write` scope of any kind", () => {
    for (const scope of membershipRoleGatewayScopes("viewer")) {
      expect(scope.endsWith(".write")).toBe(false);
    }
    expect(hasScope(membershipRoleGatewayScopes("viewer"), "assets.write")).toBe(false);
  });

  test("a member may write assets but not the control plane", () => {
    const member = membershipRoleGatewayScopes("member");
    expect(hasScope(member, "assets.write")).toBe(true);
    expect(hasScope(member, "admin.read")).toBe(true);
    expect(hasScope(member, "admin.write")).toBe(false);
  });

  test("no tier's scope set is empty, which would silently mean data-plane-all", () => {
    // An empty set is the *unscoped virtual key* state (`hasScope` grants every
    // non-privileged scope). A tier that produced one would quietly hand a
    // console user the whole data plane.
    for (const role of MEMBERSHIP_ROLES) {
      expect(membershipRoleGatewayScopes(role).length).toBeGreaterThan(0);
      expect(membershipRoleGatewayScopes(role)).not.toContain("*");
    }
  });
});

describe("narrowScopes", () => {
  test("a minted key can never exceed the minting principal", () => {
    expect(
      narrowScopes(["admin.write", "chat.completions"], membershipRoleGatewayScopes("member")),
    ).toEqual([]);
    expect(
      narrowScopes(["assets.write", "admin.write"], membershipRoleGatewayScopes("owner")),
    ).toEqual(["assets.write", "admin.write"]);
  });

  test("a requested wildcard is granted only when the minter literally holds it", () => {
    expect(narrowScopes(["*"], membershipRoleGatewayScopes("owner"))).toEqual([]);
    expect(narrowScopes(["*"], ["*"])).toEqual(["*"]);
    expect(narrowScopes(["admin.write"], ["*"])).toEqual([]);
  });

  test("preserves request order and drops duplicates", () => {
    expect(narrowScopes(["b", "a", "b", "c"], ["a", "b"])).toEqual(["b", "a"]);
  });

  test("an empty granting set narrows everything away", () => {
    // Not to "unscoped" — that would be an ESCALATION, because an empty scope
    // set grants every non-privileged scope via `hasScope`. The caller decides
    // what an empty result means; narrowing itself never invents a grant.
    expect(narrowScopes(["chat.completions"], [])).toEqual([]);
  });
});
