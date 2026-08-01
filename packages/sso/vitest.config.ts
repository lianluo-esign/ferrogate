import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

/**
 * `@ferrogate/sso` runs its ENTIRE suite inside the real local `workerd`
 * (miniflare), not plain node vitest — even though it declares no Cloudflare
 * binding and would otherwise qualify as a "pure-logic package" per
 * `docs/rewrite/TESTING.md`.
 *
 * The reason is that every security-critical claim this package makes is a
 * claim about the RUNTIME, not about this package's code:
 *
 *   * `crypto.subtle.verify("RSASSA-PKCS1-v1_5", ...)` with **SHA-1** — SHA-1
 *     is deprecated and several runtimes (and workerd itself, for *signing*)
 *     refuse it. Node 24's WebCrypto and workerd do not agree by construction.
 *     A SHA-1 verification proven only under node would be a claim about node.
 *   * `crypto.subtle.importKey("spki", ...)` accepting the DER our hand-rolled
 *     X.509 parser slices out of a real openssl certificate.
 *   * `DecompressionStream("deflate-raw")` / `CompressionStream("deflate-raw")`
 *     — "deflate-raw" is a comparatively recent addition and is exactly the
 *     variant the SAML HTTP-Redirect binding mandates.
 *
 * All three are the production runtime's behaviour. Proving them anywhere else
 * would be proving the wrong thing.
 */
export default defineConfig({
  plugins: [
    cloudflareTest({
      miniflare: {
        compatibilityDate: "2025-06-01",
        compatibilityFlags: ["nodejs_compat"],
      },
    }),
  ],
  test: { include: ["test/**/*.test.ts"] },
});
