import { describe, expect, test } from "vitest";
import { DEFAULT_APPROVAL_POLICY, approvalPolicySchema } from "@ferrogate/schemas";

describe("approvalPolicySchema", () => {
  test("accepts the snake_case wire tokens", () => {
    expect(approvalPolicySchema.parse("never")).toBe("never");
    expect(approvalPolicySchema.parse("always")).toBe("always");
  });

  test("default matches Rust ApprovalPolicy::Never", () => {
    expect(DEFAULT_APPROVAL_POLICY).toBe("never");
  });

  // Edge: PascalCase / unknown tokens are rejected (serde is snake_case).
  test("rejects non-snake_case or unknown variants", () => {
    expect(approvalPolicySchema.safeParse("Never").success).toBe(false);
    expect(approvalPolicySchema.safeParse("sometimes").success).toBe(false);
  });
});
