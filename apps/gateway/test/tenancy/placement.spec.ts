import { describe, expect, test } from "vitest";
import { tenantDataObjectFor } from "../../src/tenancy/tenant-data.js";

describe("gateway tenant object addressing", () => {
  test("selects jurisdiction before idFromName and passes the first-get hint", () => {
    const calls: Array<readonly unknown[]> = [];
    const unrestricted = {
      idFromName(name: string) {
        calls.push(["unrestricted.idFromName", name]);
        return `unrestricted:${name}`;
      },
      get(id: string, options?: unknown) {
        calls.push(["unrestricted.get", id, options]);
        return { id };
      },
    };
    const namespace = {
      ...unrestricted,
      jurisdiction(value: string) {
        calls.push(["jurisdiction", value]);
        return {
          idFromName(name: string) {
            calls.push(["eu.idFromName", name]);
            return `eu:${name}`;
          },
          get(id: string, options?: unknown) {
            calls.push(["eu.get", id, options]);
            return { id };
          },
        };
      },
    };

    const stub = tenantDataObjectFor(
      { TENANT_DATA: namespace as never },
      "tenant-eu",
      { jurisdiction: "eu", locationHint: "weur" },
    );

    // `tenantDataObjectFor` now returns a request-safe wrapper that derives
    // the real stub lazily, on first member access — a stub created in one
    // request and used from another's `ctx.waitUntil` is workerd's "Cannot
    // perform I/O on behalf of a different request" on the billing drain (see
    // `requestSafeTenantDataStub`). Construction alone must therefore address
    // NOTHING; the jurisdiction→idFromName→get(hint) sequence this test pins
    // happens per derivation, and one property read is what triggers it.
    expect(calls).toEqual([]);
    void (stub as { id?: unknown }).id;

    expect(calls).toEqual([
      ["jurisdiction", "eu"],
      ["eu.idFromName", "tenant-eu"],
      ["eu.get", "eu:tenant-eu", { locationHint: "weur" }],
    ]);
  });
});
