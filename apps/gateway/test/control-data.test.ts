import { describe, expect, it, vi } from "vitest";
import {
  CONTROL_STORAGE_MISCONFIGURED,
  type ControlDataBindings,
  controlDatabaseFrom,
} from "../src/control-data.js";

function fakeControlData(): ControlDataBindings["CONTROL_DATA"] {
  return {
    idFromName: vi.fn(() => ({})),
    get: vi.fn(() => ({})),
  } as unknown as ControlDataBindings["CONTROL_DATA"];
}

describe("gateway CONTROL storage seam", () => {
  it("uses the CONTROL_DATA facade by default", () => {
    expect(controlDatabaseFrom({ CONTROL_DATA: fakeControlData() })).toBeDefined();
  });

  it("returns undefined when neither CONTROL_DATA nor CONTROL_D1 is bound", () => {
    // The optional control reads (guardrails/RBAC/budget-alerts) degrade to
    // their config path rather than 503 when the binding is absent.
    expect(controlDatabaseFrom({})).toBeUndefined();
  });

  it("reads through a first-unconstrained replica session under the d1 posture", () => {
    // The gateway is a READ-ONLY control consumer, so `d1` opens a colo-local
    // replica session instead of a cross-region hop to the Tokyo primary.
    const withSession = vi.fn(() => ({ prepare: vi.fn(), batch: vi.fn() }));
    const CONTROL_D1 = { withSession } as unknown as D1Database;
    const result = controlDatabaseFrom({ GATEWAY_CONTROL_STORAGE: "d1", CONTROL_D1 });

    expect(result).toBeDefined();
    expect(withSession).toHaveBeenCalledWith("first-unconstrained");
  });

  it("returns undefined under the d1 posture when CONTROL_D1 is unbound", () => {
    expect(controlDatabaseFrom({ GATEWAY_CONTROL_STORAGE: "d1" })).toBeUndefined();
  });

  it("fails closed on d1_compat (now retired) and any other unknown posture", () => {
    for (const mode of ["d1_compat", "invalid"]) {
      let error: unknown;
      try {
        controlDatabaseFrom({ GATEWAY_CONTROL_STORAGE: mode });
      } catch (caught) {
        error = caught;
      }
      expect(error, `mode ${mode} must be refused`).toMatchObject({
        status: 503,
        code: CONTROL_STORAGE_MISCONFIGURED,
      });
    }
  });
});
