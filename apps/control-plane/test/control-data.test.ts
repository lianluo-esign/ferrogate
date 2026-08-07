import { describe, expect, it } from "vitest";
import { resolveStore } from "../src/adapters.js";
import {
  CONTROL_STORAGE_MISCONFIGURED,
  type ControlDataBindings,
  controlDatabaseFrom,
} from "../src/control-data.js";
import type { ControlPlaneBindings } from "../src/ports.js";

function controlNamespace(onAddress: (name: unknown, id: unknown) => void) {
  return {
    idFromName(name: unknown) {
      const id = { toString: () => "control-id" };
      onAddress(name, id);
      return id;
    },
    get(id: unknown) {
      onAddress("get", id);
      return { fetch: async () => new Response(null, { status: 200 }) };
    },
  } as unknown as ControlDataBindings["CONTROL_DATA"];
}

describe("control-plane CONTROL storage seam", () => {
  it("uses the CONTROL_DATA facade by default and honors d1_compat", () => {
    const legacy = { prepare: () => undefined } as unknown as D1Database;
    const addresses: unknown[][] = [];
    const namespace = controlNamespace((name, id) => addresses.push([name, id]));

    const facade = controlDatabaseFrom({ CONTROL_DATA: namespace, DB: legacy });
    expect(facade).toBeDefined();
    expect(facade).not.toBe(legacy);
    expect(addresses[0]?.[0]).toBe("control");

    expect(
      controlDatabaseFrom({
        CONTROL_PLANE_CONTROL_STORAGE: "d1_compat",
        CONTROL_DATA: namespace,
        DB: legacy,
      }),
    ).toBe(legacy);
    expect(controlDatabaseFrom({ DB: legacy })).toBe(legacy);
  });

  it("fails closed for an unknown posture", () => {
    let error: unknown;
    try {
      controlDatabaseFrom({ CONTROL_PLANE_CONTROL_STORAGE: "invalid" });
    } catch (caught) {
      error = caught;
    }
    expect(error).toMatchObject({ status: 503, code: CONTROL_STORAGE_MISCONFIGURED });
  });

  it("makes resolveStore construct over the resolved CONTROL_DATA facade", () => {
    const legacy = { prepare: () => undefined } as unknown as D1Database;
    const addresses: unknown[][] = [];
    const namespace = controlNamespace((name, id) => addresses.push([name, id]));

    const store = resolveStore({ DB: legacy, CONTROL_DATA: namespace } as ControlPlaneBindings);

    expect(store).toBeDefined();
    expect(addresses.some(([name]) => name === "control")).toBe(true);
    expect(addresses.some(([name]) => name === "get")).toBe(true);
  });
});
