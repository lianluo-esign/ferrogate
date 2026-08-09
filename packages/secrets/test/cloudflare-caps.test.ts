import { describe, expect, it } from "vitest";
import {
  CfSecretsCapacityPolicy,
  CfSecretsCapacityWarning,
  DEFAULT_CF_SECRETS_WARN_AT,
} from "../src/index.js";

describe("CfSecretsCapacityPolicy.checkValueSize", () => {
  const policy = CfSecretsCapacityPolicy.default();

  it("passes a value at the 1024-byte cap", () => {
    expect(() => policy.checkValueSize("s", "n", "x".repeat(1024))).not.toThrow();
  });

  it("rejects a value over the beta cap with its byte count", () => {
    expect(() => policy.checkValueSize("s", "n", "x".repeat(1025))).toThrow(
      /1025 bytes.*beta cap of 1024/,
    );
  });

  it("measures UTF-8 bytes, not UTF-16 code units", () => {
    // "€" is 3 UTF-8 bytes; 342 of them = 1026 bytes > 1024, but .length = 342.
    const value = "€".repeat(342);
    expect(value.length).toBeLessThan(1024);
    expect(() => policy.checkValueSize("s", "n", value)).toThrow(/1026 bytes/);
  });
});

describe("CfSecretsCapacityPolicy.checkSecretBudget", () => {
  const policy = CfSecretsCapacityPolicy.default();

  it("hard-errors creating a NEW secret at the budget", () => {
    expect(() => policy.checkSecretBudget("s", "n", 100, false)).toThrow(/100 secrets.*budget/);
  });

  it("allows overwriting an existing name at the budget (no new slot)", () => {
    const warning = policy.checkSecretBudget("s", "n", 100, true);
    expect(warning).toBeInstanceOf(CfSecretsCapacityWarning);
    expect(warning?.usedAfterWrite).toBe(100);
  });

  it("returns a warning at/above the soft threshold", () => {
    expect(
      policy.checkSecretBudget("s", "n", DEFAULT_CF_SECRETS_WARN_AT - 1, false),
    ).toBeInstanceOf(CfSecretsCapacityWarning);
  });

  it("returns null comfortably below the soft threshold", () => {
    expect(policy.checkSecretBudget("s", "n", 10, false)).toBeNull();
  });
});

describe("CfSecretsCapacityPolicy.fromEnv", () => {
  it("applies overrides and clamps warn_at to max_secrets", () => {
    const policy = CfSecretsCapacityPolicy.fromEnv({
      FERROGATE_CF_SECRETS_MAX_SECRETS: "50",
      FERROGATE_CF_SECRETS_WARN_AT: "999",
      FERROGATE_CF_SECRETS_MAX_VALUE_BYTES: "2048",
    });
    expect(policy.maxSecrets).toBe(50);
    expect(policy.warnAtSecrets).toBe(50); // clamped
    expect(policy.maxValueBytes).toBe(2048);
  });

  it("ignores unset / non-numeric / zero, keeping beta defaults", () => {
    const policy = CfSecretsCapacityPolicy.fromEnv({
      FERROGATE_CF_SECRETS_MAX_SECRETS: "0",
      FERROGATE_CF_SECRETS_MAX_VALUE_BYTES: "nope",
    });
    expect(policy.maxSecrets).toBe(100);
    expect(policy.maxValueBytes).toBe(1024);
  });

  it("a configured (non-beta) cap is labelled 'configured' in the error", () => {
    const policy = CfSecretsCapacityPolicy.fromEnv({
      FERROGATE_CF_SECRETS_MAX_VALUE_BYTES: "16",
    });
    expect(() => policy.checkValueSize("s", "n", "x".repeat(17))).toThrow(/configured cap of 16/);
  });
});
