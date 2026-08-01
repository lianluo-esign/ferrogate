/**
 * The four tenant-membership tiers — clean-room port of
 * `crates/ferrogate-auth-service/src/membership_role.rs` (issue #517).
 *
 * `sql/d1-ts/control/0001_init_control.sql` has carried
 * `CHECK (role IN ('owner','admin','member','viewer'))` on
 * `admin_user_tenant_memberships` since the migration shipped — and its comment
 * calls the column out as "a privilege tier, not a description", the one
 * enumeration CHECK the rewrite deliberately kept. Nothing in TypeScript had
 * ever read it. This module is that column's meaning.
 *
 * Two asymmetries carry the whole security argument, and they are opposites on
 * purpose:
 *
 *  - {@link parseMembershipRole} is the WRITE-side validator. It is
 *    CASE-SENSITIVE and total: an unknown value is `null` (→ 422), never a
 *    silently stored string. Rust states the reason plainly — the pre-#517
 *    gates were literal `role != "owner"` comparisons, so accepting `"Owner"`
 *    here would *grant* owner authority to a value that is denied today.
 *  - {@link membershipRoleFromStored} is the READ-side resolver for rows the
 *    validator never saw (legacy rows, rows written straight into a database
 *    that never carried the CHECK). It FAILS CLOSED to `viewer`, the least
 *    privilege — a typo'd or hostile role string must not mint an `admin.write`
 *    key and must not pass {@link isOwner}.
 */

/** A tenant membership tier. The strings are exactly the CHECK's four values. */
export type MembershipRole = "owner" | "admin" | "member" | "viewer";

/** Every tier, most privileged first (Rust `MembershipRole::ALL`). */
export const MEMBERSHIP_ROLES: readonly MembershipRole[] = ["owner", "admin", "member", "viewer"];

const ROLE_SET: ReadonlySet<string> = new Set(MEMBERSHIP_ROLES);

/**
 * Strict parse for WRITE paths (invite, change-role). Case-sensitive; `null`
 * for anything outside the closed set. Rust `MembershipRole::parse`.
 */
export function parseMembershipRole(value: string): MembershipRole | null {
  return ROLE_SET.has(value) ? (value as MembershipRole) : null;
}

/**
 * Resolution for values ALREADY in storage. Unrecognised ⇒ `viewer`.
 * Rust `MembershipRole::from_stored` — the dangerous-default guard of #517.
 */
export function membershipRoleFromStored(value: string): MembershipRole {
  return parseMembershipRole(value) ?? "viewer";
}

/** The owner-only gate, replacing the literal `role != "owner"` compares. */
export function isOwner(role: MembershipRole): boolean {
  return role === "owner";
}

/** `owner, admin, member, viewer` — for the 422 message. */
export function acceptedMembershipRoles(): string {
  return MEMBERSHIP_ROLES.join(", ");
}

/**
 * The scopes minted on this tier's console gateway virtual key (Rust
 * `MembershipRole::gateway_api_key_scopes`).
 *
 * The ladder is anchored on one fact: **`admin.write` is the self-escalation
 * scope.** Any `admin.write` holder can call `POST /admin/v1/virtual-keys` and
 * mint an arbitrarily-scoped key, so handing it to a non-administrative tier
 * makes that tier meaningless.
 *
 * | tier   | scopes                                                     |
 * |--------|------------------------------------------------------------|
 * | owner  | `admin.read`, `admin.write`, `assets.read`, `assets.write`  |
 * | admin  | `admin.read`, `admin.write`, `assets.read`, `assets.write`  |
 * | member | `admin.read`, `assets.read`, `assets.write`                 |
 * | viewer | `admin.read`, `assets.read`                                 |
 *
 * `owner` and `admin` share a scope set: the difference between them is tenant
 * administration (the team endpoints), which is gated by {@link isOwner} and is
 * not expressible as a gateway scope. `viewer` holds NO `.write` scope at all.
 */
export function gatewayApiKeyScopes(role: MembershipRole): readonly string[] {
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
