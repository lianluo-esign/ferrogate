/**
 * `src/delegation/` — the gateway half of the verifiable delegation chain
 * (#691).
 *
 * The chain FORMAT, the mint, the verifier and the revocation source all live
 * in `@ferrogate/identity`, deliberately: they are pure logic with a WebCrypto
 * dependency and no transport, so the one place the rules are implemented is
 * shared with whatever mints links (`apps/agent-runtime`) rather than
 * duplicated per Worker. What lives here is the two things only a Worker can
 * do — resolve the key and the database out of bindings (`source.ts`) and turn
 * a refusal into an HTTP status (`middleware.ts`).
 */
export {
  DELEGATION_REQUIRES_CREDENTIAL,
  DELEGATION_UNAVAILABLE,
  type DelegationMiddlewareOptions,
  delegationChain,
} from "./middleware.js";
export {
  type DelegationBindings,
  type DelegationVerifier,
  delegationVerifierFromEnv,
} from "./source.js";
