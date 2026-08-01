/**
 * `@ferrogate/sso` — SAML 2.0 Service Provider.
 *
 * A clean-room TypeScript port of `crates/ferrogate-auth-service/src/saml.rs`
 * (551 lines) and the SAML half of `src/sso.rs` (issue #283), for Cloudflare
 * Workers. See `README.md` for the wiring line `apps/control-plane` must add,
 * the mount gate that proves it, and the honest list of what Workers cannot do
 * (no trust store — `x509.ts` explains what that means and what replaces it).
 *
 * Nothing here is exported that lets a caller skip the signature check:
 * `parseAndValidateResponse` is public because the Rust API was, but the flow
 * entry point (`handleSamlAcs`) verifies BEFORE it parses, and that order is
 * held by `test/flow.test.ts`.
 *
 * `store-contract.ts` is NOT re-exported here on purpose — it imports `vitest`,
 * and pulling that into a Worker bundle would be a deploy failure. It is
 * reachable as `@ferrogate/sso/store-contract` from test code only.
 */

export { SamlError, SamlFlowError } from "./errors.js";
export type { SamlErrorCode, SamlFlowErrorCode } from "./errors.js";

export { urlencode, urldecode } from "./urlcodec.js";

export { parseIdpPublicKey, importIdpVerificationKey } from "./x509.js";
export type { IdpPublicKey } from "./x509.js";

export { formatSamlInstant, parseSamlInstant } from "./instant.js";

export {
  MAX_DEFLATE_EXPANSION_RATIO,
  MAX_INFLATED_SAML_RESPONSE_BYTES,
  MAX_SAML_RESPONSE_B64_CHARS,
} from "./deflate.js";

export {
  RedirectBindingParams,
  parseRedirectBindingParams,
  verifyRedirectSignature,
  SIG_ALG_RSA_SHA1,
  SIG_ALG_RSA_SHA256,
} from "./redirect-binding.js";

export { buildAuthnRequestRedirect } from "./authn-request.js";
export type { AuthnRequestOptions } from "./authn-request.js";

export { parseAndValidateResponse } from "./response.js";
export type { AssertionExpectations, ValidatedAssertion } from "./response.js";

export {
  handleSamlAcs,
  handleSamlAuthorize,
  SAML_CLOCK_SKEW_SECS,
  SSO_FLOW_TTL_SECS,
} from "./flow.js";
export type { SamlAcsResult, SamlAuthorizeResult } from "./flow.js";

export { admitSamlConfig } from "./config.js";
export type { SamlConfigRequest, SamlConfigTimestamps } from "./config.js";

export { createInMemorySsoStores } from "./memory-store.js";
export type {
  InMemorySsoConfigStore,
  InMemorySsoPendingFlowStore,
  InMemorySsoStores,
} from "./memory-store.js";

export { webCryptoRandomHex } from "./ports.js";
export type {
  SamlPorts,
  SsoPendingFlow,
  SsoPendingFlowStore,
  SsoProviderConfigStore,
  StoredSsoProviderConfig,
} from "./ports.js";
