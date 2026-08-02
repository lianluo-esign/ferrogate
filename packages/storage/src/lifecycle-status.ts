/**
 * The one place that interprets the `status` column shared by `tenant_accounts`,
 * `projects` and `workspaces` (ports `ferrogate-storage::lifecycle_status`,
 * issue #514).
 *
 * The read-side default is FAIL-OPEN and load-bearing: absent/unrecognized ⇒
 * `active`, because these columns were decorative before #514 so legacy rows carry
 * arbitrary values; failing closed on them would revoke every pre-existing
 * tenant's traffic. Denial is opt-in — an operator must have explicitly written
 * `suspended`/`disabled`/`deleted`. The WRITE side is strict (rejects typos like
 * `"suspend"`), closing the "green confirmation for a control never applied" gap.
 */
export type LifecycleStatus = "active" | "suspended" | "disabled" | "deleted";

/** Every token a write handler accepts, for rejection messages / the OpenAPI enum. */
export const LIFECYCLE_STATUS_ALL: readonly LifecycleStatus[] = [
  "active",
  "suspended",
  "disabled",
  "deleted",
];

/**
 * Interpret a raw `status` value (case/whitespace-insensitive). Anything outside
 * the closed vocabulary — including "" — is `active` (fail-open for legacy rows).
 */
export function parseLifecycleStatus(raw: string): LifecycleStatus {
  switch (raw.trim().toLowerCase()) {
    case "suspended":
      return "suspended";
    case "disabled":
      return "disabled";
    case "deleted":
      return "deleted";
    default:
      return "active";
  }
}

/** Strict write-side parse: `undefined` for anything outside the closed vocabulary. */
export function parseLifecycleStatusStrict(raw: string): LifecycleStatus | undefined {
  switch (raw.trim().toLowerCase()) {
    case "active":
      return "active";
    case "suspended":
      return "suspended";
    case "disabled":
      return "disabled";
    case "deleted":
      return "deleted";
    default:
      return undefined;
  }
}

export function lifecycleStatusIsActive(status: LifecycleStatus): boolean {
  return status === "active";
}

/** Request-time seam: may a credential whose chain contains this state serve traffic? */
export function lifecycleStatusAllowsRequests(status: LifecycleStatus): boolean {
  return lifecycleStatusIsActive(status);
}

/** Attach-time seam: may a NEW child row be created under this state? */
export function lifecycleStatusAllowsAttach(status: LifecycleStatus): boolean {
  return lifecycleStatusIsActive(status);
}

/**
 * Recovery seam: may a credential in this state reach the lifecycle status
 * PUT/PATCH routes that turn the hierarchy back ON? `disabled` (the tenant's own
 * off switch) is admitted here and ONLY here so it is not a one-way door;
 * `suspended`/`deleted` (platform-operator actions) still deny.
 */
export function lifecycleStatusAllowsRecovery(status: LifecycleStatus): boolean {
  return status === "active" || status === "disabled";
}
