/**
 * Attribution-tag enforcement (#678).
 *
 * `policy.ts`     — the requirement and the decision, pure.
 * `source.ts`     — where a tenant's policy comes from (`quota_policies` / var).
 * `middleware.ts` — the ladder position and the refusal.
 * `defaults.ts`   — how a defaulted tag reaches `Usage.metadata`.
 */
export {
  type AttributionDecision,
  type AttributionPolicy,
  type MissingTagAction,
  type TagMap,
  attributionDecision,
  missingTagMessage,
  parseAttributionPolicy,
  parseMissingTagAction,
} from "./policy.js";
export {
  type AttributionBindings,
  type AttributionPolicySource,
  type AttributionResolution,
  DEFAULT_POLICY_TTL_MS,
  NO_ATTRIBUTION_POLICIES,
  attributionPolicySourceFromEnv,
  attributionPolicySourceFromVars,
  cachedAttributionPolicySource,
  d1AttributionPolicySource,
} from "./source.js";
export {
  type AttributionMiddlewareOptions,
  ATTRIBUTED_OPERATION_IDS,
  attributionTags,
} from "./middleware.js";
export { attributionDefaultsFor, recordAttributionDefaults } from "./defaults.js";
