import { defineConfig } from "vitest/config";

/**
 * Pure-logic package: the OIDC relying-party and SCIM 2.0 provisioning halves
 * of `crates/ferrogate-auth-service`. Every port (repository, api-key
 * authenticator, session issuer, clock, randomness, HTTP transport) is
 * injected, so there is no Cloudflare binding, no network, no live IdP and no
 * live account — hence plain vitest rather than `@cloudflare/vitest-pool-workers`.
 *
 * The one platform dependency is `crypto.subtle` (RSASSA-PKCS1-v1_5 / RSA-PSS /
 * ECDSA verify + SHA-256 digest), which is ambient in both workerd and Node
 * >= 18, so it needs no pool. The fixtures in `test/jwt-fixtures.ts` mint real
 * keys with the same WebCrypto API the verifier uses, so a signature that
 * verifies here verifies on workerd.
 */
export default defineConfig({
  test: { include: ["test/**/*.test.ts"] },
});
