import { describe, expect, it } from "vitest";

import {
  GatewayError,
  gatewayErrorSchema,
  type GatewayResult,
  newGatewayError,
} from "../src/index";

describe("GatewayError", () => {
  it("GatewayError.new sets code + message and is throwable", () => {
    const err = GatewayError.new("rate_limited", "slow down");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("GatewayError");
    expect(err.code).toBe("rate_limited");
    expect(err.message).toBe("slow down");
  });

  it("serializes to exactly { code, message }", () => {
    const err = GatewayError.new("bad_request", "nope");
    expect(err.toJSON()).toEqual({ code: "bad_request", message: "nope" });
    expect(JSON.parse(JSON.stringify(err))).toEqual({ code: "bad_request", message: "nope" });
    expect(gatewayErrorSchema.parse(err.toJSON())).toEqual({ code: "bad_request", message: "nope" });
  });

  it("newGatewayError and fromData round-trip the wire shape", () => {
    expect(newGatewayError("x", "y")).toBeInstanceOf(GatewayError);
    const back = GatewayError.fromData({ code: "c", message: "m" });
    expect(back).toBeInstanceOf(GatewayError);
    expect(back.code).toBe("c");
    expect(back.message).toBe("m");
  });

  it("rejects a malformed wire shape (edge case)", () => {
    expect(gatewayErrorSchema.safeParse({ code: "c" }).success).toBe(false);
    expect(gatewayErrorSchema.safeParse({ code: 1, message: "m" }).success).toBe(false);
  });
});

describe("GatewayResult", () => {
  it("specializes the Result envelope to GatewayError", () => {
    const ok: GatewayResult<number> = { ok: true, value: 5 };
    const err: GatewayResult<number> = { ok: false, error: GatewayError.new("bad", "nope") };
    expect(ok.ok && ok.value).toBe(5);
    expect(!err.ok && err.error.code).toBe("bad");
  });
});
