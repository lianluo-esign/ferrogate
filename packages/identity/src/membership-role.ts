/**
 * The four tenant-membership tiers (issue #517).
 *
 * Clean-room port of `crates/ferrogate-auth-service/src/membership_role.rs`.
 *
 * NOTE FOR THE INTEGRATE STEP: `apps/gateway/src/keys/scopes.ts` holds a
 * sibling port of the same Rust module for the gateway's key-minting ladder.
 * A package cannot import from an app, so this is a second copy rather than a
 * shared import; the two must be consolidated (most naturally by moving the
 * gateway's copy here and re-exporting). Until then, treat a change to either
 * as a change to both — a predicate with two implementations is precisely the
 * shape that lets a mutation of one leave the other green.
 */

/** Every tier, MOST PRIVILEGED FIRST (Rust `MembershipRole::ALL`). */
export const MEMBERSHIP_ROLES = ["owner", "admin", "member", "viewer"] as const;
export type MembershipRole = (typeof MEMBERSHIP_ROLES)[number];

/**
 * Rust `MembershipRole::parse` — the STRICT parse for WRITE paths (SCIM
 * provisioning, SSO config, invite, change-role). Case-SENSITIVE on purpose:
 * the pre-#517 gates were literal `role != "owner"` comparisons, so accepting
 * `"Owner"` here would GRANT owner authority to a value that is denied today.
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
 * LEAST-privileged tier, never `owner`.
 */
export function membershipRoleFromStored(value: string): MembershipRole {
  return parseMembershipRole(value) ?? "viewer";
}

/** Rust `MembershipRole::is_owner` — the owner-only gate. */
export function isOwnerRole(role: string): boolean {
  return role === "owner";
}

/** `owner, admin, member, viewer` — for error messages. */
export const ACCEPTED_MEMBERSHIP_ROLES = MEMBERSHIP_ROLES.join(", ");
