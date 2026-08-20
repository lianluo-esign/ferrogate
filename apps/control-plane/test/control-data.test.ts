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
  it("resolves the CONTROL_DATA facade, and rejects d1_compat and other unknown postures", () => {
    // Zero-D1 S5 (#881): `durable_object` is the only posture; there is no
    // `DB` (`ferrogate-control`) legacy fallback and no `d1_compat` leg.
    const addresses: unknown[][] = [];
    const namespace = controlNamespace((name, id) => addresses.push([name, id]));

    const facade = controlDatabaseFrom({ CONTROL_DATA: namespace });
    expect(facade).toBeDefined();
    // Accessing a method resolves (addresses) the singleton "control" object.
    void (facade as D1Database).prepare;
    expect(addresses[0]?.[0]).toBe("control");

    // No CONTROL_DATA bound ⇒ undefined, never a fall-through to a legacy binding.
    expect(controlDatabaseFrom({})).toBeUndefined();

    for (const mode of ["d1_compat", "invalid"]) {
      // (d1 is now a legal posture, so it must NOT appear here.)
      let error: unknown;
      try {
        controlDatabaseFrom({ CONTROL_PLANE_CONTROL_STORAGE: mode });
      } catch (caught) {
        error = caught;
      }
      expect(error, `mode ${mode} must be refused`).toMatchObject({
        status: 503,
        code: CONTROL_STORAGE_MISCONFIGURED,
      });
    }
  });

  it("returns the plain CONTROL_D1 binding under the d1 posture (primary, read-your-writes)", () => {
    // The control-plane is the SINGLE writer: it holds the plain binding so its
    // reads hit the primary and see its own writes with no bookmark plumbing.
    // No `withSession` wrapping here — that is reserved for the read-only twins.
    const CONTROL_D1 = { prepare() {}, batch() {}, withSession() {} } as unknown as D1Database;
    const resolved = controlDatabaseFrom({ CONTROL_PLANE_CONTROL_STORAGE: "d1", CONTROL_D1 });
    expect(resolved).toBe(CONTROL_D1);

    // d1 posture with no CONTROL_D1 bound ⇒ undefined (a unit env), same shape
    // as the DO leg with no CONTROL_DATA.
    expect(controlDatabaseFrom({ CONTROL_PLANE_CONTROL_STORAGE: "d1" })).toBeUndefined();
  });

  it("makes resolveStore construct over the resolved CONTROL_DATA facade", () => {
    const addresses: unknown[][] = [];
    const namespace = controlNamespace((name, id) => addresses.push([name, id]));

    const store = resolveStore({ CONTROL_DATA: namespace } as ControlPlaneBindings);
    expect(store).toBeDefined();

    // The facade resolves the DO stub lazily (per operation), so accessing a
    // method on the SAME resolution the store is built over is what addresses
    // the singleton "control" object.
    void (controlDatabaseFrom({ CONTROL_DATA: namespace }) as D1Database).prepare;
    expect(addresses.some(([name]) => name === "control")).toBe(true);
    expect(addresses.some(([name]) => name === "get")).toBe(true);
  });
});
