import { describe, expect, test } from "vitest";
import {
  SITE_DOMAIN_VERIFICATION_ATTEMPT_COOLDOWN_SECONDS,
  effectiveSiteDomainVerificationState,
  isPaymentAttemptStateTerminal,
  markVerified,
  pendingSiteDomainVerification,
  siteDomainVerificationAttemptDecision,
  siteDomainVerificationServes,
  transitionPaymentAttempt,
} from "../src/index.js";

describe("site-domain verification rate-limit CAS (#576)", () => {
  const cooldown = SITE_DOMAIN_VERIFICATION_ATTEMPT_COOLDOWN_SECONDS;

  test("the first attempt (no prior check) is always allowed", () => {
    expect(siteDomainVerificationAttemptDecision(undefined, 0, cooldown)).toEqual({
      kind: "allowed",
    });
  });

  test("a call inside the cooldown is rate-limited with a bounded retry hint", () => {
    const decision = siteDomainVerificationAttemptDecision(100, 110, cooldown);
    expect(decision).toEqual({ kind: "rate_limited", retryAfterSecs: 20 });
  });

  test("a call at/after the cooldown is allowed again", () => {
    expect(siteDomainVerificationAttemptDecision(100, 100 + cooldown, cooldown).kind).toBe(
      "allowed",
    );
  });
});

describe("site-domain verification lifecycle (#488)", () => {
  test("a pending challenge past its TTL resolves to expired at read time", () => {
    const v = pendingSiteDomainVerification("t1", "example.com", "site", "tok", 0);
    const afterTtl = v.tokenExpiresAtUnix + 1;
    expect(effectiveSiteDomainVerificationState(v, afterTtl)).toBe("expired");
    expect(siteDomainVerificationServes(v, afterTtl)).toBe(false);
  });

  test("a verified proof serves until its re-verification deadline, then expires", () => {
    const v = pendingSiteDomainVerification("t1", "example.com", "site", "tok", 0);
    markVerified(v, 10);
    expect(siteDomainVerificationServes(v, 20)).toBe(true);
    const afterDeadline = (v.verificationExpiresAtUnix ?? 0) + 1;
    expect(effectiveSiteDomainVerificationState(v, afterDeadline)).toBe("expired");
  });
});

describe("payment-attempt state machine (deprioritized §1.5.4)", () => {
  test("terminal states are recognised; an unknown spelling is not terminal", () => {
    expect(isPaymentAttemptStateTerminal("settled")).toBe(true);
    expect(isPaymentAttemptStateTerminal("released")).toBe(true);
    expect(isPaymentAttemptStateTerminal("authorized")).toBe(false);
    expect(isPaymentAttemptStateTerminal("bogus")).toBe(false);
  });

  test("CAS transition: applied on a legal edge with matching generation", () => {
    const out = transitionPaymentAttempt("challenged", 3, ["challenged"], "authorized", 3);
    expect(out).toEqual({ kind: "applied", toState: "authorized", generation: 4 });
  });

  test("CAS transition: idempotent when already in the target state", () => {
    expect(transitionPaymentAttempt("settled", 5, ["submitted"], "settled", 5)).toEqual({
      kind: "idempotent",
      state: "settled",
      generation: 5,
    });
  });

  test("CAS transition: conflict on a stale generation (lost update)", () => {
    const out = transitionPaymentAttempt("challenged", 4, ["challenged"], "authorized", 3);
    expect(out.kind).toBe("conflict");
  });
});
