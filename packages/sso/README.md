# `@ferrogate/sso` — SAML 2.0 Service Provider

A clean-room TypeScript port of the SAML half of `ferrogate-auth-service` for
Cloudflare Workers.

| Rust source (read-only reference) | TS owner |
|---|---|
| `crates/ferrogate-auth-service/src/saml.rs` (551 lines) | `src/{redirect-binding,response,authn-request,x509,der,xml,instant,deflate,urlcodec,base64}.ts` |
| `src/sso.rs` — `handle_saml_authorize`, `handle_saml_acs`, the `"saml"` branch of `handle_set_sso_config`, `SSO_FLOW_TTL_SECS`, `SAML_CLOCK_SKEW_SECS` | `src/{flow,config,ports,memory-store}.ts` |
| `src/saml/tests.rs` (283 lines) | `test/**` (110 tests, all adversarial cases plus 15 the Rust suite did not have) |

**Not ported here, on purpose:** `sso.rs::complete_sso_login` — the tail shared
with OIDC (JIT user provisioning, the cross-tenant account-takeover guard, the
tier-scoped gateway-key mint, session issuance). It belongs to
`apps/control-plane`, which owns those tables; duplicating it per protocol is
how the takeover guard ends up implemented twice and fixed once. `handleSamlAcs`
stops at a validated identity and hands it over.

## Binding: HTTP-Redirect, and why that is the safe choice

Both legs use the **HTTP-Redirect binding**, whose signature is a *detached* RSA
signature over the URL query octet string
(`SAMLResponse=..&RelayState=..&SigAlg=..`), per SAML 2.0 Bindings §3.4.4.1.
That deliberately avoids XML Digital Signature canonicalisation (exclusive C14N)
entirely — the single richest source of SAML authentication bypasses in the
wild. There is no XML-dsig code here, hand-rolled or otherwise: the bytes are
authenticated by WebCrypto against the IdP certificate FIRST, and only then
parsed.

## Everything fails closed

Every refusal throws. `SamlError` (protocol) and `SamlFlowError` (handler, with
the Rust handler's HTTP status) both carry the **verbatim Rust message string**
plus a stable `code`. There is no path out of `handleSamlAcs` that reaches an
authenticated state without `crypto.subtle.verify` having returned `true`.

Refused: an unsigned response · a missing/unsupported `SigAlg` · a non-base64
signature · a signature from any other key · a tampered payload or RelayState ·
**a signature valid over a re-serialised form of the query but not over the raw
octets** · a replayed or expired flow state · a non-`Success` status · an
issuer, audience or `InResponseTo` mismatch · a clock-skew-adjusted
`NotBefore`/`NotOnOrAfter` violation · a missing usable email · malformed,
mis-nested or oversized XML · a `DOCTYPE` · an unknown entity reference · a
malformed, zlib-wrapped, truncated or bomb-sized DEFLATE payload · a
non-RSA/unparseable/BER-encoded certificate · a non-UTC timestamp.

## Platform notes (the honest list)

### Workers have no trust store

There is no system root store and no chain-validation API in workerd, so this
port does not validate a certificate chain, a CA signature, the certificate's
own `notBefore`/`notAfter`, or a CRL/OCSP responder.

That is not a regression and not the relevant control. SAML IdP signing
certificates are conventionally self-signed and pinned out of band: the tenant
owner pastes the exact certificate from their IdP metadata into
`POST /v1/admin/team/sso-config`, and `admitSamlConfig` refuses at that moment if
it is not usable. **The configured certificate IS the trust anchor** — the Rust
port worked the same way. Issuer validation is therefore "was this signed by the
exact key this tenant pinned", plus the `Issuer`-element equality check against
the configured `saml_idp_entity_id`. What the tenant loses is revocation and
expiry: a rotated or compromised IdP key stays trusted until the config is
updated. That is inherent to key pinning. Full detail in `src/x509.ts`.

### X.509 parsing: hand-rolled, ~120 lines, no dependency

`docs/legacy/inventory-edge-control.md` §5.4 suggested `@peculiar/x509`. That
pulls in `@peculiar/asn1-schema` + `asn1js` + `pvtsutils` + `pvutils` to extract
ONE field. `src/der.ts` + `src/x509.ts` walk `Certificate → tbsCertificate →
subjectPublicKeyInfo` instead and slice the SPKI out **verbatim**, then hand it
to `crypto.subtle.importKey("spki", ...)`, which does its own full structural
validation. A bug in the walk can therefore cause a REFUSAL, never an
acceptance — the signature is checked by WebCrypto against a key WebCrypto
itself parsed. Test fixtures are real openssl-produced certificates, not
certificates built by our own encoder.

### One deliberate divergence from Rust: decompression-bomb caps

`saml.rs` called `read_to_end` on the DEFLATE decoder with no bound — a
pre-authentication DoS. This port caps the encoded payload at 32 KiB **before
decoding** (which is what actually bounds worst-case memory: 32 KiB × ¾ ×
DEFLATE's 1032:1 maximum ≈ 24.8 MiB) and refuses an inflated result over 1 MiB.
`src/deflate.ts` documents why the cap cannot be enforced mid-stream on workerd
(every chunked-read shape leaks an unhandled promise rejection; only
`new Response(readable).arrayBuffer()` observes the pipe's internal rejection).

## Tests

`bun run test` — 110 tests, all inside the **real local `workerd`**
(`@cloudflare/vitest-pool-workers`), not node. `vitest.config.ts` explains why: every
security claim here is a claim about the runtime's WebCrypto (including SHA-1
verification, which several runtimes refuse) and its `deflate-raw` streams.

### Mutation proof

`./mutation-sweep.sh` breaks each of the 25 security seams one at a time, greps
the file back off disk to confirm the edit landed, runs the suite, requires RED
in a NAMED test, restores and re-verifies the checksum.

**Last run: 25/25 RED, 0 still-green, final restore GREEN at 110 tests.**

The sweep is what found that the mismatched-end-tag check in `src/xml.ts` had no
test only it could fail (`<a><b></a>` is caught by the end-of-document check
instead); `test/response.test.ts` now carries a balanced-but-mis-nested document
that nothing else catches.

## Wiring — the seam `apps/control-plane` must mount

This package exports a seam and mounts nothing. **Nobody may edit
`apps/*/src/index.ts`, `apps/*/src/worker.ts` or `apps/*/wrangler.toml` except
the integrate step**, so the exact lines are specified here.

The three routes are `inventory-edge-control.md` §5.1's
`GET /v1/admin/auth/saml/authorize`, `GET /v1/admin/auth/saml/acs`, and the
`"saml"` branch of `POST /v1/admin/team/sso-config`. They are part of the
`/v1/admin/*` console identity surface that `apps/control-plane/src/index.ts`'s
header already lists as "still to come", and they are **not** among the 257
contract operations, so they do not affect the anti-drift gate.

### 1. Dependency

`apps/control-plane/package.json`, in `dependencies`:

```json
"@ferrogate/sso": "workspace:*"
```

### 2. Routes (a NEW file `apps/control-plane/src/routes/saml.ts`, this
package's scope to specify, the integrate step's to create)

```ts
import { handleSamlAcs, handleSamlAuthorize, SamlFlowError } from "@ferrogate/sso";

// GET /v1/admin/auth/saml/authorize?tenant_id=...
const result = await handleSamlAuthorize(deps.samlPorts, tenantId);
return c.json({ authorize_url: result.authorizeUrl, state: result.state }, 200);

// GET /v1/admin/auth/saml/acs
// `rawQuery` MUST be the verbatim query string. `new URL(c.req.url).search.slice(1)`
// is correct; `c.req.query()` is NOT — it decodes, and the signature is over the
// RAW octets. Passing a decoded or re-serialised query defeats the entire check.
const identity = await handleSamlAcs(deps.samlPorts, new URL(c.req.url).search.slice(1));
return completeSsoLogin(deps, identity); // the shared OIDC/SAML tail, control-plane-owned
```

`SamlFlowError` carries `.status` and `.code`; map it straight onto the
control plane's error envelope. Do not collapse the statuses — 401 vs 422 vs
500 vs 404 is the ported contract.

### 3. Ports (`apps/control-plane/src/adapters.ts`, in `resolveDeps`)

```ts
samlPorts: {
  configs: d1SsoProviderConfigStore(env.CONTROL_DB),
  flows: d1SsoPendingFlowStore(env.CONTROL_DB),
  now: () => Math.floor(Date.now() / 1000),
  randomHex: webCryptoRandomHex,
},
```

**`d1SsoPendingFlowStore.take` MUST be a single atomic statement** —
`DELETE FROM sso_pending_flows WHERE state = ?1 AND expires_at_unix > ?2 RETURNING *`.
A `SELECT` followed by a `DELETE` reintroduces replay, and no test in THIS
package would notice, because they exercise the in-memory map. That is the
two-implementations trap this repo keeps falling into, so the contract is
exported as a test:

```ts
// apps/control-plane/test/saml-store-contract.test.ts
import { samlPendingFlowStoreContract } from "@ferrogate/sso/store-contract";
describe("D1 SSO pending-flow store", () => {
  samlPendingFlowStoreContract(() => d1SsoPendingFlowStore(env.CONTROL_DB));
});
```

### 4. Mount gate (the seam is only proven when removing it goes RED)

Add `apps/control-plane/test/saml-mount.test.ts` asserting, through `SELF`, a
thing ONLY the real mount can produce:

```ts
// Seam: the `samlPorts` line in resolveDeps + the route registration.
// MUT: delete the `configs:` line from resolveDeps  → this test must go RED.
// MUT: replace the ACS's raw-query argument with `c.req.query("SAMLResponse")`
//      → the tamper test below must go RED.
test("ACS refuses a tampered assertion with 401 and the ported code", async () => {
  const res = await SELF.fetch(`https://x.test/v1/admin/auth/saml/acs?${tamperedQuery}`);
  expect(res.status).toBe(401);
  expect((await res.json()).error.code).toBe("saml_signature_verification_failed");
});
test("ACS refuses a REPLAY of a redirect it already accepted", async () => {
  expect((await SELF.fetch(`https://x.test/v1/admin/auth/saml/acs?${validQuery}`)).status).toBe(200);
  const replay = await SELF.fetch(`https://x.test/v1/admin/auth/saml/acs?${validQuery}`);
  expect(replay.status).toBe(401);
  expect((await replay.json()).error.code).toBe("unknown_saml_state");
});
```

A test that only asserts the route EXISTS (405/404 shape) does not hold this
seam and must not be counted as the gate.

### 5. D1 schema

`sql/d1-ts/control/` needs `sso_provider_configs` (one row per tenant, keyed by
`tenant_id`, carrying both the OIDC and the SAML columns — one table, because
`provider_kind` is the discriminant that stops a tenant being configured for
both at once) and `sso_pending_flows` (PRIMARY KEY `state`, plus
`expires_at_unix`). Column names mirror `StoredSsoProviderConfig` /
`SsoPendingFlow` in `src/ports.ts`.
