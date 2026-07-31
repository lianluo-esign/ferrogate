/**
 * The scope vocabulary a durable/virtual key can carry, and the membership
 * ladder that mints it.
 *
 * Clean-room port of `crates/ferrogate-auth-service/src/membership_role.rs`
 * (issue #517) plus the six data-plane inference scopes from the runtime API
 * contract.
 *
 * Scope *evaluation* lives in `../ports.ts::hasScope` and is NOT duplicated
 * here — one implementation, one place, exactly as Rust keeps `scope_set_allows`
 * as "the single source of truth for scope-set semantics". This module only
 * supplies the vocabulary and the ladder.
 */

/**
 * The six data-plane inference scopes, taken from
 * `docs/openapi/runtime-api-contract.json` (the `auth.scope` of the six
 * inference operations). These are what a key needs to reach the model path;
 * none of them is privileged (`admin.*`), which is why an unscoped virtual key
 * can still call inference but can never call the control plane.
 */
export const INFERENCE_SCOPES: readonly string[] = [
  "models.read",
  "chat.completions",
  "responses.create",
  "messages.create",
  "embeddings.create",
  "images.generate",
];

/**
 * The four tenant membership tiers, MOST PRIVILEGED FIRST (Rust
 * `MembershipRole::ALL`). The order is load-bearing: `membershipRoleAtLeast`
 * reads the ladder off this array.
 */
export const MEMBERSHIP_ROLES = ["owner", "admin", "member", "viewer"] as const;
export type MembershipRole = (typeof MEMBERSHIP_ROLES)[number];

/**
 * Rust `MembershipRole::parse` — the STRICT parse for write paths (invite,
 * change-role, SCIM provisioning). Case-SENSITIVE on purpose: the pre-#517
 * gates were literal `role != "owner"` comparisons, so accepting `"Owner"`
 * here would *grant* owner authority to a stored value that is denied today.
 *
 * Returns `null` where Rust returns `Err(InvalidMembershipRole)`.
 */
export function parseMembershipRole(value: string): MembershipRole | null {
  return (MEMBERSHIP_ROLES as readonly string[]).includes(value) ? (value as MembershipRole) : null;
}

/**
 * Rust `MembershipRole::from_stored` — resolution for values ALREADY in
 * storage (legacy rows, or rows written straight into a D1 database that never
 * carried the Postgres `CHECK`).
 *
 * **Fails closed by design**: an unrecognised value resolves to `viewer`, the
 * LEAST-privileged tier, never `owner`. A typo'd or hostile role string must
 * not be able to mint an `admin.write` key.
 */
export function membershipRoleFromStored(value: string): MembershipRole {
  return parseMembershipRole(value) ?? "viewer";
}

/** Rust `MembershipRole::is_owner` — the owner-only gate. */
export function isOwnerRole(role: MembershipRole): boolean {
  return role === "owner";
}

/**
 * `true` when `role` sits at or above `floor` on the ladder
 * (`owner > admin > member > viewer`).
 */
export function membershipRoleAtLeast(role: MembershipRole, floor: MembershipRole): boolean {
  return MEMBERSHIP_ROLES.indexOf(role) <= MEMBERSHIP_ROLES.indexOf(floor);
}

/**
 * Rust `MembershipRole::gateway_api_key_scopes` — the scopes minted on the
 * console gateway virtual key for this tier.
 *
 * | tier   | scopes                                                     |
 * |--------|------------------------------------------------------------|
 * | owner  | `admin.read`, `admin.write`, `assets.read`, `assets.write`  |
 * | admin  | `admin.read`, `admin.write`, `assets.read`, `assets.write`  |
 * | member | `admin.read`, `assets.read`, `assets.write`                 |
 * | viewer | `admin.read`, `assets.read`                                 |
 *
 * Anchored on one fact: **`admin.write` is the self-escalation scope.** Any
 * `admin.write` holder can call `POST /admin/v1/virtual-keys` and mint an
 * arbitrarily-scoped key, so handing it to a non-administrative tier makes that
 * tier meaningless. `owner` and `admin` share a scope set — the difference
 * between them is tenant administration, gated by `isOwnerRole` and not
 * expressible as a gateway scope. `viewer` holds NO `.write` scope at all.
 */
export function membershipRoleGatewayScopes(role: MembershipRole): readonly string[] {
  switch (role) {
    case "owner":
    case "admin":
      return ["admin.read", "admin.write", "assets.read", "assets.write"];
    case "member":
      return ["admin.read", "assets.read", "assets.write"];
    case "viewer":
      return ["admin.read", "assets.read"];
  }
}

/**
 * Narrow a requested scope set to what a minting principal may actually
 * delegate — the virtual-key scope-narrowing rule.
 *
 * A virtual key is minted BY a principal, and it must never carry a scope that
 * principal does not itself hold: otherwise `POST /admin/v1/virtual-keys`
 * becomes a privilege-escalation primitive for anyone who can reach it. The
 * intersection is order-preserving on `requested` and duplicate-free.
 *
 * The wildcard is deliberately NOT special-cased on the `requested` side: a
 * caller asking for `"*"` gets `"*"` only if the granting set literally holds
 * `"*"`. Treating a requested wildcard as "everything I have" would silently
 * widen a key whenever the granter is later re-scoped upward.
 */
export function narrowScopes(
  requested: readonly string[],
  grantedByMinter: readonly string[],
): readonly string[] {
  const granted = new Set(grantedByMinter);
  const seen = new Set<string>();
  const narrowed: string[] = [];
  for (const scope of requested) {
    if (!granted.has(scope) || seen.has(scope)) continue;
    seen.add(scope);
    narrowed.push(scope);
  }
  return narrowed;
}
