/**
 * Data-residency and zero-data-retention policy (#681).
 *
 * `policy.ts`     — the requirement and the per-route decision, pure.
 * `source.ts`     — where a tenant's policy comes from (`quota_policies` / var).
 * `middleware.ts` — the ladder position, the log-placement gate, the refusal.
 * `carrier.ts`    — how the resolved policy reaches the inner routing app.
 */
export {
  type LogResidency,
  type ParsedResidencyPolicy,
  type ResidencyConstraint,
  type ResidencyPolicy,
  type ResidencyPolicyRow,
  type ResidencyViolation,
  type RouteResidencyFacts,
  effectiveResidencyPolicy,
  isRegionConstraint,
  jurisdictionForPolicyAndAddress,
  jurisdictionForResidencyPolicy,
  parseResidencyPolicyRow,
  residencyRequirementSummary,
  residencyViolations,
} from "./policy.js";
export {
  type ResidencyBindings,
  type ResidencyDatabase,
  type ResidencyPolicySource,
  type ResidencyResolution,
  DEFAULT_RESIDENCY_TTL_MS,
  NO_RESIDENCY_POLICIES,
  cachedResidencyPolicySource,
  d1ResidencyPolicySource,
  residencyPolicySourceFromEnv,
  residencyPolicySourceFromVars,
} from "./source.js";
export {
  type ResidencyMiddlewareOptions,
  RESIDENCY_GOVERNED_OPERATION_IDS,
  logPlacementMessage,
  logPlacementSatisfied,
  residency,
} from "./middleware.js";
export {
  recordResidencyPolicy,
  recordTenantObjectAddressForEnv,
  residencyPolicyFor,
  tenantObjectAddressFor,
} from "./carrier.js";
