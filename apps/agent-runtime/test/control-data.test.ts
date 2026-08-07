import type { D1Database, DurableObjectNamespace } from "@cloudflare/workers-types";
import { describe, expect, it, vi } from "vitest";
import { CONTROL_STORAGE_MISCONFIGURED, controlDatabaseFrom } from "../src/control-data.js";

function fakeControlData(): DurableObjectNamespace {
  return {
    idFromName: vi.fn(() => ({})),
    get: vi.fn(() => ({})),
  } as unknown as DurableObjectNamespace;
}

describe("agent-runtime control database seam", () => {
  const legacyDb = { prepare: vi.fn() } as unknown as D1Database;

  it("uses the CONTROL_DATA facade by default", () => {
    const result = controlDatabaseFrom({ CONTROL_DATA: fakeControlData() }, { legacy: [legacyDb] });

    expect(result).toBeDefined();
    expect(result).not.toBe(legacyDb);
  });

  it("uses the legacy D1 control database in d1_compat mode and when unbound", () => {
    expect(
      controlDatabaseFrom(
        { AGENT_RUNTIME_CONTROL_STORAGE: "d1_compat", CONTROL_DATA: fakeControlData() },
        { legacy: [legacyDb] },
      ),
    ).toBe(legacyDb);
    expect(controlDatabaseFrom({}, { legacy: [legacyDb] })).toBe(legacyDb);
    expect(controlDatabaseFrom({ AGENT_RUNTIME_CONTROL_STORAGE: "d1_compat" })).toBeUndefined();
  });

  it("fails closed on an unknown storage posture", () => {
    let error: unknown;
    try {
      controlDatabaseFrom({ AGENT_RUNTIME_CONTROL_STORAGE: "unknown" });
    } catch (caught) {
      error = caught;
    }

    expect(error).toMatchObject({ status: 503, code: CONTROL_STORAGE_MISCONFIGURED });
  });
});
