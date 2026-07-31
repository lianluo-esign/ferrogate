import { describe, test } from "vitest";

// Not-yet-ported behaviors, flagged so they stay visible (docs/rewrite/TESTING.md).
// The `validate.rs` long-tail helpers that used to be listed here (provider/model
// uniqueness + cross-references, header validity, plugin/skill-package manifest +
// permissions, prompt placeholders, managed-worker action lists, storage identifier
// checks, skill-package materialization) are now ported and held by
// validate-entities/sections/plugins-policies.test.ts. What remains is what depends
// on a wave-2 sibling package, plus the one engine difference worth re-checking.
describe("validate.rs legs owned by sibling packages (PORT-TODO inventory §5.4)", () => {
  test.todo(
    "ferrogate_mcp::validate_mcp_server_config: reconnect backoff bounds, static-header/auth-mode " +
      "pairing, OAuth config, per-server TLS and stdio `command` — needs @ferrogate/mcp's full " +
      "McpServerConfig (the modeled legs — name shape, deny-by-default tools_to_execute, and the " +
      "network-transport url requirement — are ported)",
  );
  test.todo(
    "agent_runtime.managed_worker.target_grants: selector.supports_action(action) + " +
      "selector.validate() — needs @ferrogate/runtime's CapabilityTargetSelector",
  );
  test.todo(
    "guardrails[].regex: Rust compiles with the `regex` crate, which rejects backreferences and " +
      "lookaround that JS RegExp accepts — re-check against the detector engine the Worker runs",
  );
});

describe("x402 policy-invariant validation (PORT-TODO inventory §5.2)", () => {
  test.todo("delegate X402SpendPolicy.validate() to @ferrogate/policy once ported");
  test.todo("resolve_effective_x402_spend_policy inheritance resolution");
});

// REMOVED AS N/A ON CLOUDFLARE (never to be ported, so deliberately NOT test.todo):
// validate_tls, validate_acme_tls, validate_acme_dns01_tls, validate_acme_http01_tls and
// validate_manual_tls_files. Cloudflare terminates TLS in front of the Worker: there is no
// cert/key file to load (the Rust pre-flight is pingora's load_certs_and_key_files), no :80
// HTTP-01 challenge listener a Worker can own, and no ACME storage directory. See src/validate.ts.
