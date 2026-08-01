/**
 * Required Cloudflare API-token permission groups — slice **S3**.
 *
 * Ported from `crates/ferrogate-cloudflare/src/scopes.rs`. This is the
 * machine-adjacent source of truth `CloudflareClient.preflight()` names when a
 * token authenticates but is under-scoped.
 *
 * An API token is scoped by attaching **permission groups** at the account (or
 * zone) level. A deployment that uses only some Cloudflare features can grant
 * only the corresponding subset — but preflight reports the FULL foundational
 * set on purpose, so an operator provisions once instead of discovering each
 * missing group at its own first use, in production.
 *
 * The strings are Cloudflare dashboard names. A typo here is un-actionable
 * advice and the type system cannot notice it, which is why `test/scopes.test.ts`
 * pins every row verbatim.
 *
 * This module has NO imports, deliberately: it is the leaf of the package's
 * dependency graph (`errors.ts` reads it), so a consumer can adopt just the
 * table.
 */

/** One required token permission group and why FerroGate needs it. */
export interface TokenPermissionGroup {
  /** Cloudflare's dashboard name for the permission group. */
  readonly name: string;
  /** Cloudflare's access level(s) for the group — Read / Edit / Write. */
  readonly access: string;
  /** Which FerroGate Cloudflare subsystem consumes it. */
  readonly usedBy: string;
}

/** The full set of permission groups FerroGate's integrations depend on. */
export const REQUIRED_TOKEN_PERMISSION_GROUPS: readonly TokenPermissionGroup[] = [
  {
    name: "AI Gateway",
    access: "Read, Edit",
    usedBy: "AI Gateway management + inference proxying",
  },
  { name: "Secrets Store", access: "Read, Write", usedBy: "cf:// secret backend" },
  { name: "D1", access: "Read, Edit", usedBy: "D1-backed state, incl. tenant database lifecycle" },
  { name: "Workers Scripts", access: "Edit", usedBy: "Worker deployment" },
  {
    name: "Workers R2 Storage",
    access: "Read, Edit",
    usedBy: "R2 bucket MANAGEMENT (distinct from the S3 key pair)",
  },
  {
    name: "API Tokens",
    access: "Write",
    usedBy: "minting/revoking bucket-scoped R2 API tokens",
  },
  { name: "Cloudflare Pages", access: "Edit", usedBy: "Pages deployment" },
  {
    name: "Workflows (Workers Scripts)",
    access: "Write, Edit",
    usedBy: "Workflows orchestration",
  },
];

/** The permission-group names, in table order, for embedding in an error. */
export function requiredGroupNames(): readonly string[] {
  return REQUIRED_TOKEN_PERMISSION_GROUPS.map((group) => group.name);
}
