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
