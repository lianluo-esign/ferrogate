import { describe, expect, test } from "vitest";

import {
  PAYMENT_ATTEMPT_STATES,
  type PaymentAttemptState,
  isInitial,
  isPreSubmission,
  isReconcilable,
  isTerminal,
  parsePaymentAttemptState,
  retainsHoldWhenUnresolved,
} from "../src/index.js";

describe("PaymentAttemptState alphabet (#352)", () => {
  test("every state round-trips through its durable spelling", () => {
    for (const state of PAYMENT_ATTEMPT_STATES) {
      expect(parsePaymentAttemptState(state)).toBe(state);
    }
    expect(PAYMENT_ATTEMPT_STATES.length).toBe(8);
    expect(new Set(PAYMENT_ATTEMPT_STATES).size).toBe(8);
  });

  test("unknown spelling is refused rather than defaulted", () => {
    expect(parsePaymentAttemptState("")).toBeUndefined();
    expect(parsePaymentAttemptState("Settled")).toBeUndefined();
    expect(parsePaymentAttemptState("unknown")).toBeUndefined();
  });

  test("outcome_unknown is non-terminal and retains its hold", () => {
    const unknown: PaymentAttemptState = "outcome_unknown";
    expect(isTerminal(unknown)).toBe(false);
    expect(retainsHoldWhenUnresolved(unknown)).toBe(true);
    expect(isPreSubmission(unknown)).toBe(false);
    expect(isReconcilable(unknown)).toBe(true);
    // It is the ONLY state that retains a hold while unresolved.
    for (const state of PAYMENT_ATTEMPT_STATES) {
      expect(retainsHoldWhenUnresolved(state)).toBe(state === "outcome_unknown");
    }
  });

  test("sweepable and reconcilable sets are disjoint and non-terminal", () => {
    for (const state of PAYMENT_ATTEMPT_STATES) {
      expect(isPreSubmission(state) && isReconcilable(state)).toBe(false);
      if (isPreSubmission(state) || isReconcilable(state)) {
        expect(isTerminal(state)).toBe(false);
      }
    }
    expect(isReconcilable("submitted")).toBe(true);
    expect(isPreSubmission("submitted")).toBe(false);
    expect(isPreSubmission("authorized")).toBe(true);
    expect(isPreSubmission("challenged")).toBe(true);
  });

  test("terminal and initial sets match the documented truth table", () => {
    const terminal = PAYMENT_ATTEMPT_STATES.filter(isTerminal);
    expect(terminal).toEqual(["settled", "denied", "released", "failed"]);
    const initial = PAYMENT_ATTEMPT_STATES.filter(isInitial);
    expect(initial).toEqual(["challenged", "authorized", "denied"]);
  });
});
