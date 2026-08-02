/**
 * Small shared helpers, ported verbatim in behaviour from
 * `crates/ferrogate-auth-service/src/util.rs`.
 */
import type { IdentityRandom } from "./ports.js";

/**
 * Rust `util::is_valid_email`. Deliberately the SAME weak check, not a
 * stricter one: this value is compared against `admin_users.email` rows that
 * were admitted by the Rust predicate, so tightening it here would silently
 * lock existing accounts out of SSO.
 */
export function isValidEmail(email: string): boolean {
  const at = email.indexOf("@");
  if (at < 0) return false;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  return (
    local.length > 0 && domain.includes(".") && !domain.startsWith(".") && !domain.endsWith(".")
  );
}

/**
 * Rust `util::next_id`, re-based on the CSPRNG.
 *
 * The Rust version is `{kind}-{nanos}-{pid}`; a Worker has no pid and its
 * clock is coarsened against timing attacks, so two ids minted in the same
 * request would collide. Random suffix instead — the id is an opaque primary
 * key, so nothing depends on it being time-ordered.
 */
export function nextId(kind: string, random: IdentityRandom): string {
  return `${kind}_${random.hex(12)}`;
}

/**
 * The password hash stored for an account that can only ever authenticate
 * through an IdP (Rust `util::unusable_password_hash`). It must not be a valid
 * hash of anything: `verify_password` has to fail for every input.
 */
export const UNUSABLE_PASSWORD_HASH = "!";
