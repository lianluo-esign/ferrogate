/**
 * The per-tenant DATA-RESIDENCY and ZERO-DATA-RETENTION policy, and the pure
 * decision it produces about one route. No I/O, no bindings, no Hono.
 *
 * ============================================================================
 * THE DEFECT THIS SLICE CLOSES (#681)
 * ============================================================================
 *
 * An EU tenant could not state "inference and logs stay in the EU, and never
 * route to a provider without a ZDR agreement". What existed was
 * `Caller.regionAllowlist`, read by `inference/candidates.ts`, and **nothing
 * populated it**: `inference/identity.ts::callerFromAuth` never set the field,
 * the `api_keys` row has no column for it, and every green test that exercised
 * it injected the caller by hand. The gate was real code, on the real request
 * path, that no deployed request could ever arm.
 *
 * ZDR did not exist at all, and the mirror leg (`inference/shadow.ts`) selected
 * its route from the FULL candidate list — before eligibility — so it had never
 * been shown a residency constraint of any kind.
 *
 * ============================================================================
 * ZDR IS A PROPERTY OF THE ROUTE, ASSERTED BY THE OPERATOR AND VERIFIED HERE
 * ============================================================================
 *
 * `zeroDataRetention` is NOT a request flag and is deliberately not a boolean
 * with a default. It is `boolean | undefined` on the ROUTE, and the three states
 * are distinct because they are three different facts about the world:
 *
 *   `true`      — the operator asserts a ZDR agreement covers this provider
 *                 account. The policy is satisfied.
 *   `false`     — the operator asserts the opposite: this account retains.
 *                 Refused, and the message says so.
 *   `undefined` — NOBODY HAS SAID. Refused, and the message says THAT instead.
 *
 * Collapsing `undefined` into `true` would let every route in every existing
 * `GATEWAY_MODELS` table satisfy a ZDR policy the day it is switched on, which
 * is the precise shape of "a compliance control the customer discovers is
 * hollow from someone else". Collapsing it into `false` would be safe but
 * indistinguishable from a deliberate denial in the refusal message, and an
 * operator's remedy differs: one is "annotate the route", the other is
 * "renegotiate or move the traffic".
 *
 * ============================================================================
 * WHY REGION AND ZDR SHARE ONE TYPE AND ONE EVALUATION
 * ============================================================================
 *
 * Because they must be enforced at the same places, and a second policy object
 * evaluated at a subset of them is how the mirror leg came to be unguarded in
 * the first place. There is exactly one function that answers "may this route
 * carry this tenant's prompt" — {@link residencyViolations} — and every leg
 * that can put a prompt on the wire calls it: route eligibility
 * (`inference/candidates.ts`), and the shadow mirror
 * (`inference/shadow.ts::shadowMirrorFor`).
 */

/**
 * Where the DURABLE RECORD of a request may live.
 *
 * The buyer's question is usually about the logs, not the inference: #664 gave
 * every request a durable row and #677 made cost queryable, and both land in
 * whichever database the deployment bound. `in_region` says that row may only
 * be written by a deployment whose log store is declared to sit in one of
 * {@link ResidencyPolicy.allowedRegions}; `unconstrained` is the pre-#681
 * posture and is what a tenant that only cares about INFERENCE residency
 * states.
 *
 * There is no "off" spelling. A policy row that omits the field reads as
 * `unconstrained`, because that is the behaviour every existing deployment
 * already has and silently tightening it would refuse traffic nobody asked to
 * have refused.
 */
export type LogResidency = "in_region" | "unconstrained";

/** One tenant's residency requirement. */
export interface ResidencyPolicy {
  /**
   * Is the REGION leg armed at all?
   *
   * Carried explicitly instead of being inferred from `allowedRegions.length`,
   * because those two facts genuinely come apart in one case and conflating
   * them there is a silent grant: {@link effectiveResidencyPolicy} can
   * intersect a tenant policy with a credential allowlist down to the EMPTY
   * set, which means "no region satisfies both" — the opposite of the "no
   * region gate" that an empty list means everywhere else.
   */
  readonly regionGated: boolean;
  /**
   * The regions a route may declare, meaningful only when {@link regionGated}.
   *
   * A route that declares NO region does not satisfy an armed gate. That is the
   * pre-existing Rust reading (`if !region_allowlist.is_empty()`) and it is the
   * only fail-closed one: most provider rows in this tree declare no region at
   * all, so treating "undeclared" as "wherever you like" would make the control
   * inert on exactly the catalogue it is meant to constrain.
   */
  readonly allowedRegions: readonly string[];
  /** Refuse any route that does not ASSERT zero data retention. */
  readonly requireZeroDataRetention: boolean;
  readonly logResidency: LogResidency;
}

/**
 * The facts a route asserts about itself, as this module needs them.
 *
 * Structurally a subset of `inference/ports.ts::PhysicalRoute`, declared
 * separately so this module does not depend on the inference slice — the
 * middleware that enforces log placement runs on the OUTER app and must not
 * drag the inference ports in with it. The compiler checks the two agree at the
 * one place they meet, `inference/candidates.ts`.
 */
export interface RouteResidencyFacts {
  readonly region?: string | undefined;
  /** See the module docs: `undefined` is "unverified", never "yes". */
  readonly zeroDataRetention?: boolean | undefined;
}

/**
 * Which constraint a route failed. The vocabulary is the refusal's, so an
 * operator reading a 403 knows what to change.
 */
export type ResidencyConstraint =
  | "region_undeclared"
  | "region_not_allowed"
  | "zero_data_retention_unverified"
  | "zero_data_retention_denied";

/** One unmet constraint, with the fact that failed it. */
export interface ResidencyViolation {
  readonly constraint: ResidencyConstraint;
  /** `key=value`, in the shape `candidates.ts::RouteExclusion.detail` uses. */
  readonly detail: string;
}

/** Nothing to say — hoisted so the unpoliced common path allocates nothing. */
const NO_VIOLATIONS: readonly ResidencyViolation[] = [];

/**
 * May this route carry this tenant's prompt?
 *
 * Returns EVERY unmet constraint rather than the first, because the refusal has
 * to be actionable: a route that is both out of region and unverified for ZDR
 * needs two changes, and reporting one at a time turns one operator round trip
 * into two.
 */
export function residencyViolations(
  route: RouteResidencyFacts,
  policy: ResidencyPolicy | null,
): readonly ResidencyViolation[] {
  if (policy === null) return NO_VIOLATIONS;
  const violations: ResidencyViolation[] = [];

  if (policy.regionGated) {
    if (route.region === undefined || route.region === "") {
      violations.push({ constraint: "region_undeclared", detail: "declared_region=none" });
    } else if (!policy.allowedRegions.includes(route.region)) {
      violations.push({
        constraint: "region_not_allowed",
        detail: `declared_region=${route.region}`,
      });
    }
  }

  if (policy.requireZeroDataRetention) {
    if (route.zeroDataRetention === undefined) {
      violations.push({
        constraint: "zero_data_retention_unverified",
        detail: "declared_zero_data_retention=none",
      });
    } else if (route.zeroDataRetention === false) {
      violations.push({
        constraint: "zero_data_retention_denied",
        detail: "declared_zero_data_retention=false",
      });
    }
  }

  return violations.length === 0 ? NO_VIOLATIONS : violations;
}

/** Is this constraint about WHERE, rather than about retention? */
export function isRegionConstraint(constraint: ResidencyConstraint): boolean {
  return constraint === "region_undeclared" || constraint === "region_not_allowed";
}

/**
 * The human half of a refusal: what the tenant's policy demanded.
 *
 * Rendered from the POLICY, not from the routes, on purpose. Listing the
 * offending routes would leak one operator's catalogue into a tenant-visible
 * error; listing the requirement tells the operator reading the log exactly
 * what a route would have to declare to be reachable, which is the only thing
 * they can act on.
 */
export function residencyRequirementSummary(policy: ResidencyPolicy): string {
  const parts: string[] = [];
  if (policy.regionGated) {
    parts.push(`region in [${[...policy.allowedRegions].join(", ")}]`);
  }
  if (policy.requireZeroDataRetention) {
    parts.push("zero data retention");
  }
  return parts.join(" and ");
}

/**
 * Normalize a stored/declared policy row into a {@link ResidencyPolicy}, or
 * `null` for "this tenant is not governed".
 *
 * ## Fail-CLOSED on a malformed row, unlike its #678 sibling
 *
 * `attribution/policy.ts::parseAttributionPolicy` fails OPEN, and says why: an
 * unreadable attribution requirement can only refuse traffic that was already
 * being served, so a typo becomes an outage. The direction here is the opposite
 * for a reason that is not symmetric. An unreadable RESIDENCY requirement, read
 * as "no policy", does not refuse anything — it SERVES the request, possibly
 * out of region, which is the exact breach the tenant bought the control to
 * prevent, and it is invisible because everything succeeds.
 *
 * So a row that names a residency control this function cannot fully parse is
 * reported as {@link ResidencyPolicyError} by {@link parseResidencyPolicyRow}
 * and refused upstream. `null` is reserved for a row that names NO control at
 * all, which is a complete and unambiguous reading of "not governed".
 */
export type ParsedResidencyPolicy =
  | { readonly ok: true; readonly policy: ResidencyPolicy | null }
  | { readonly ok: false; readonly detail: string };

/** The raw shape a var entry or a D1 row projects into. */
export interface ResidencyPolicyRow {
  readonly allowedRegions?: unknown;
  readonly requireZeroDataRetention?: unknown;
  readonly logResidency?: unknown;
}

/** `1`/`0`/`true`/`false`/`"true"` — SQLite has no boolean, D1 hands back both. */
function parseFlag(raw: unknown): boolean | null {
  if (raw === undefined || raw === null) return false;
  if (typeof raw === "boolean") return raw;
  if (raw === 1 || raw === "1" || raw === "true") return true;
  if (raw === 0 || raw === "0" || raw === "false") return false;
  return null;
}

function parseLogResidency(raw: unknown): LogResidency | null {
  if (raw === undefined || raw === null || raw === "") return "unconstrained";
  return raw === "in_region" || raw === "unconstrained" ? raw : null;
}

/** Parse one row. See {@link ParsedResidencyPolicy} on the fail-closed direction. */
export function parseResidencyPolicyRow(row: ResidencyPolicyRow): ParsedResidencyPolicy {
  const zdr = parseFlag(row.requireZeroDataRetention);
  if (zdr === null) {
    return { ok: false, detail: "require_zero_data_retention is not a boolean" };
  }
  const logResidency = parseLogResidency(row.logResidency);
  if (logResidency === null) {
    return { ok: false, detail: "log_residency must be 'in_region' or 'unconstrained'" };
  }

  const rawRegions = row.allowedRegions;
  let regions: string[] = [];
  if (rawRegions !== undefined && rawRegions !== null) {
    if (!Array.isArray(rawRegions)) {
      return { ok: false, detail: "residency_regions must be a JSON array of region names" };
    }
    // A non-string entry is REFUSED rather than dropped: silently ignoring
    // `["eu-west-1", 3]` would narrow the allowlist by one region without
    // telling anyone, and a narrowed allowlist looks exactly like a working
    // policy right up until the route it was meant to permit is refused.
    if (rawRegions.some((entry) => typeof entry !== "string")) {
      return { ok: false, detail: "residency_regions contains a non-string entry" };
    }
    regions = (rawRegions as string[]).map((entry) => entry.trim()).filter((entry) => entry !== "");
    regions = [...new Set(regions)];
  }

  // `log_residency: in_region` with no regions names no region to stay in. That
  // is not a policy, it is a sentence with the object missing, and admitting it
  // would silently grant "logs anywhere" to a tenant who asked the opposite.
  if (logResidency === "in_region" && regions.length === 0) {
    return {
      ok: false,
      detail: "log_residency = 'in_region' requires a non-empty residency_regions list",
    };
  }

  if (regions.length === 0 && !zdr) {
    return { ok: true, policy: null };
  }
  return {
    ok: true,
    policy: {
      regionGated: regions.length > 0,
      allowedRegions: regions,
      requireZeroDataRetention: zdr,
      logResidency,
    },
  };
}

/**
 * Combine the TENANT policy with the per-credential `region_allowlist` the
 * inference path already carried (`Caller.regionAllowlist`).
 *
 * Both must hold, so the regions INTERSECT. A contradiction between the two —
 * "this key may only use us-east-1; this tenant may only use eu-west-1" —
 * therefore refuses every route, rather than quietly serving from whichever
 * list happened to be consulted last. That case is exactly why
 * {@link ResidencyPolicy.regionGated} is carried explicitly: the intersection
 * is `[]`, which everywhere else in this file means "no gate".
 */
export function effectiveResidencyPolicy(
  tenantPolicy: ResidencyPolicy | null,
  keyRegionAllowlist: readonly string[] | undefined,
): ResidencyPolicy | null {
  const keyRegions = [...new Set((keyRegionAllowlist ?? []).filter((region) => region !== ""))];
  if (tenantPolicy === null) {
    return keyRegions.length === 0
      ? null
      : {
          regionGated: true,
          allowedRegions: keyRegions,
          requireZeroDataRetention: false,
          logResidency: "unconstrained",
        };
  }
  if (keyRegions.length === 0) return tenantPolicy;
  if (!tenantPolicy.regionGated) {
    return { ...tenantPolicy, regionGated: true, allowedRegions: keyRegions };
  }
  return {
    ...tenantPolicy,
    allowedRegions: tenantPolicy.allowedRegions.filter((region) => keyRegions.includes(region)),
  };
}
