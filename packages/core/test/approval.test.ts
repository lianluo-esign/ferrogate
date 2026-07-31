import { describe, expect, it } from "vitest";

import { approvalPolicySchema, DEFAULT_APPROVAL_POLICY } from "../src/index";

describe("ApprovalPolicy", () => {
  it("parses the snake_case wire forms", () => {
    expect(approvalPolicySchema.parse("never")).toBe("never");
    expect(approvalPolicySchema.parse("always")).toBe("always");
  });

  it("rejects any other value (edge case)", () => {
    expect(approvalPolicySchema.safeParse("sometimes").success).toBe(false);
    expect(approvalPolicySchema.safeParse("Never").success).toBe(false);
  });

  it("defaults to Never", () => {
    expect(DEFAULT_APPROVAL_POLICY).toBe("never");
  });
});
