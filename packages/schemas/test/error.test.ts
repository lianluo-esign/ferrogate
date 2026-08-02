import { describe, expect, test } from "vitest";
import {
  GatewayError,
  type GatewayResult,
  gatewayErrorSchema,
  newGatewayError,
} from "@ferrogate/schemas";

describe("gatewayError", () => {
  test("newGatewayError builds a throwable GatewayError with code+message", () => {
    const err = newGatewayError("upstream_timeout", "provider did not respond");
    expect(err).toBeInstanceOf(GatewayError);
    expect(err).toBeInstanceOf(Error);
    expect(err.code).toBe("upstream_timeout");
    expect(err.message).toBe("provider did not respond");
  });

  test("serializes to exactly { code, message }", () => {
    const err = newGatewayError("e", "m");
    expect(err.toJSON()).toEqual({ code: "e", message: "m" });
    expect(JSON.parse(JSON.stringify(err))).toEqual({ code: "e", message: "m" });
  });

  test("wire schema requires both code and message", () => {
    expect(gatewayErrorSchema.safeParse({ code: "x" }).success).toBe(false);
    expect(gatewayErrorSchema.safeParse({ message: "x" }).success).toBe(false);
    expect(gatewayErrorSchema.safeParse({ code: "x", message: "y" }).success).toBe(true);
  });

  // GatewayResult<T> == Result<T, GatewayError> — both arms are constructible.
  test("GatewayResult models both the ok and err arms", () => {
    const ok: GatewayResult<number> = { ok: true, value: 42 };
    const err: GatewayResult<number> = { ok: false, error: newGatewayError("e", "m") };
    expect(ok.ok && ok.value).toBe(42);
    expect(!err.ok && err.error.code).toBe("e");
  });
});
