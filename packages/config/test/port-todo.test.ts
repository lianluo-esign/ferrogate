import { describe, test } from "vitest";

/**
 * The visible registry of `@ferrogate/config` behaviors that are still NOT
 * ported (docs/rewrite/TESTING.md). A behavior may sit here only while nothing
 * enforces it; once it is implemented — or once it is established as
 * unimplementable and pinned as an approximation — it leaves this file.
 *
 * CLOSED (moved out of this file, now held by real assertions):
 *   - `validate.rs`'s long tail: provider/model uniqueness + cross-references,
 *     header validity, plugin/skill-package manifests + permissions, prompt
 *     placeholders, managed-worker action lists, storage identifier checks,
 *     skill-package materialization
 *     → validate-entities/sections/plugins-policies.test.ts
 *   - `ferrogate_mcp::validate_mcp_server_config` in full — reconnect bounds,
 *     auth-mode/static-header pairing, the whole OAuth config leg, and the stdio
 *     `command` requirement (the per-server TLS leg is a PLATFORM LIMIT, kept and
 *     pinned in validate-entities.test.ts)
 *     → validate-entities.test.ts > "validate_mcp_server_config"
 *   - `CapabilityTargetSelector::supports_action` + `::validate()` over
 *     `agent_runtime.managed_worker.target_grants` (the two filesystem
 *     pre-flights are a PLATFORM LIMIT, kept and pinned)
 *     → validate-sections.test.ts > "target_grants: CapabilityTargetSelector"
 *   - `guardrails[].regex` engine parity: the Rust `regex` crate refuses the
 *     backreferences and lookaround JS `RegExp` accepts, so a config Rust
 *     REFUSES no longer slips through with different match semantics
 *     → validate-plugins-policies.test.ts > "regex-crate accept-set parity"
 *   - `ed25519-dalek::verify_strict`'s small-order / non-canonical `A` and `R`
 *     rejection, which `crypto.subtle.verify` does not make
 *     → signed-snapshot.test.ts > "verify_strict parity"
 *   - `http::Uri` vs WHATWG `URL` on the `mcp.http` plugin endpoint: an endpoint
 *     with no authority ("http:///rpc", "http:/rpc") has no `Uri::authority()`
 *     and Rust refuses it, while `new URL` re-parses it as "http://rpc/" and
 *     reports the first PATH SEGMENT as the host — so the config was accepted
 *     and `must include host` was unreachable dead code
 *     → validate-rule-identity.test.ts > "validate_plugins + validate_builtin_plugin_shape"
 *   - the ~115 ported validators that had NO assertion at all (a rule with no
 *     test is a rule that can be deleted while every suite stays green)
 *     → validate-rule-identity.test.ts
 *
 * KEPT AS PLATFORM LIMITS (never `test.todo`, because they are not pending work
 * — they are pinned approximations with the limitation written at the source):
 *   - MCP per-server TLS (`tls.ca_cert_path` / `insecure_skip_verify`): no
 *     filesystem, and `fetch()` has no hook to add a CA root or skip
 *     verification → src/validate/entities.ts, pinned in validate-entities.test.ts
 *   - `CapabilityTargetSelector` filesystem/CLI pre-flights (`canonicalize`,
 *     `is_dir`/`is_file`): a Worker isolate has no filesystem
 *     → src/validate/capability-target.ts, pinned in validate-sections.test.ts
 *   - no `std::env`, no socket peer address, no cross-isolate shared state, no
 *     filesystem for the loader, and CF-terminated TLS making `[tls]`/`[tls.acme]`
 *     inert → src/{secrets,network-access,loader,schema/sections}.ts, all pinned
 *     in platform-limits.test.ts
 *   - WebCrypto has no synchronous Ed25519, so the signed-snapshot surface is
 *     async where Rust was sync → src/signed-snapshot.ts
 *
 * REMOVED AS N/A ON CLOUDFLARE (never to be ported, so deliberately NOT
 * `test.todo`): `validate_tls`, `validate_acme_tls`, `validate_acme_dns01_tls`,
 * `validate_acme_http01_tls`, `validate_manual_tls_files`. Cloudflare terminates
 * TLS in front of the Worker: there is no cert/key file to load (the Rust
 * pre-flight is pingora's `load_certs_and_key_files`), no `:80` HTTP-01
 * challenge listener a Worker can own, and no ACME storage directory. See
 * src/validate.ts and the pins in platform-limits.test.ts.
 */
describe("x402 policy-invariant validation (PORT-TODO inventory §5.2)", () => {
  // DELIBERATE PRODUCT DECISION, not a platform gap: x402/Solana payments are
  // deprioritized, so `@ferrogate/policy`'s x402 surface is unported and
  // `x402_spend_policies[].policy` is carried opaquely. The scope-shape half
  // (blank / duplicate `(scope_type, scope_id)`) IS enforced — see
  // src/validate/sections.ts > validateX402SpendPolicies and src/x402-scope.ts.
  test.todo("delegate X402SpendPolicy.validate() to @ferrogate/policy once ported");
  test.todo("resolve_effective_x402_spend_policy inheritance resolution");
});

describe("wave-2 package relocations (PORT-TODO inventory §5.3)", () => {
  // BEHAVIOR IS CLOSED in every case below — these are inlined here (read from
  // the crates, verbatim) so `@ferrogate/config` type-checks and validates
  // standalone. The open item is the IMPORT EDGE: re-export from the owning
  // package once it lands, and do not re-derive the logic.
  //
  // CLOSED: the `@ferrogate/{providers,storage,guardrails}` enums. Those three
  // packages have landed, so `ModelCapability`/`RoutingStrategy`,
  // `StorageProviderKind`/`PostgresTlsMode` (+ `DEFAULT_DURABLE_PROVIDER_ORDER`
  // and the `is_durable`/`implemented` predicates) and `ContentSource` are now
  // IMPORTED from their owner. Not cosmetic: the `ContentSource` copy had
  // already lost the `unknown` variant, narrowing the default
  // `guardrails[].sources` set → test/sibling-enum-parity.test.ts.
  //
  // STILL OPEN — but not for a wave-2 reason. `McpTransport`/`McpAuthType`,
  // `is_cloudflare_managed_mcp_url` and `CloudflareConfig` have NO owning
  // `packages/*` library to import from: the MCP port lives in the `apps/mcp`
  // WORKER and there is no `@ferrogate/cloudflare` package at all. A
  // `packages/*` library must not depend on an app, so these stay inlined
  // (verbatim from the crates) and are pinned against the Rust source instead.
  test.todo("re-export McpTransport/McpAuthType once an @ferrogate/mcp LIBRARY exists");
  test.todo("re-export is_cloudflare_managed_mcp_url once an @ferrogate/mcp LIBRARY exists");
  test.todo("re-export CloudflareConfig from @ferrogate/cloudflare");
  test.todo("relocate build_target_uri/normalize_host to apps/gateway (#560)");
});
