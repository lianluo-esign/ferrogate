import type { DurableObjectNamespace } from "@cloudflare/workers-types";
import { describe, expect, it, vi } from "vitest";
import { CONTROL_STORAGE_MISCONFIGURED, controlDatabaseFrom } from "../src/control-data.js";

function fakeControlData(): DurableObjectNamespace {
  return {
    idFromName: vi.fn(() => ({})),
    get: vi.fn(() => ({})),
  } as unknown as DurableObjectNamespace;
}

describe("agent-runtime control database seam", () => {
  it("uses the CONTROL_DATA facade by default", () => {
    const result = controlDatabaseFrom({ CONTROL_DATA: fakeControlData() });

    expect(result).toBeDefined();
  });

  it("returns undefined when CONTROL_DATA is unbound", () => {
    // Zero-D1 S5 (#881): the Durable Object is the only backend. There is no
    // `CONTROL_DB` legacy fallback any more, so an env with no CONTROL_DATA
    // resolves to `undefined` (the optional reads' config path).
    expect(controlDatabaseFrom({})).toBeUndefined();
  });

  it("reads through a first-unconstrained replica session under the d1 posture", () => {
    // agent-runtime is a READ-ONLY control consumer, so `d1` must open a replica
    // session (colo-local reads) rather than pin every read to the Tokyo primary.
    const withSession = vi.fn(() => ({ prepare: vi.fn(), batch: vi.fn() }));
    const CONTROL_D1 = { withSession } as unknown;
    const result = controlDatabaseFrom({ AGENT_RUNTIME_CONTROL_STORAGE: "d1", CONTROL_D1 });

    expect(result).toBeDefined();
    expect(withSession).toHaveBeenCalledWith("first-unconstrained");
  });

  it("returns undefined under the d1 posture when CONTROL_D1 is unbound", () => {
    expect(controlDatabaseFrom({ AGENT_RUNTIME_CONTROL_STORAGE: "d1" })).toBeUndefined();
  });

  it("fails closed on d1_compat (now retired) and any other unknown posture", () => {
    // `d1_compat` was the S2–S4 rollback posture; S5 deleted it, so it is an
    // illegal value like any other rather than a legacy fallback.
    for (const mode of ["d1_compat", "unknown"]) {
      let error: unknown;
      try {
        controlDatabaseFrom({ AGENT_RUNTIME_CONTROL_STORAGE: mode });
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
