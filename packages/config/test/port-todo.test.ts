import { describe, test } from "vitest";

// Not-yet-ported behaviors, flagged so they stay visible (docs/rewrite/TESTING.md).
describe("validate.rs long-tail helpers (PORT-TODO inventory §5.4)", () => {
  test.todo("provider/model name uniqueness + cross-reference checks");
  test.todo("header name/value validity via http types (validate_headers)");
  test.todo("plugin/skill-package manifest + permission validation");
  test.todo("prompt-template placeholder checks");
  test.todo("managed-worker action lists + target grants");
  test.todo("storage postgres identifier/DSN checks");
  test.todo("materialize_skill_package_resources[_with_previous]");
});

describe("x402 policy-invariant validation (PORT-TODO inventory §5.2)", () => {
  test.todo("delegate X402SpendPolicy.validate() to @ferrogate/policy once ported");
  test.todo("resolve_effective_x402_spend_policy inheritance resolution");
});
