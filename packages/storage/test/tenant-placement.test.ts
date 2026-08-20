import { describe, expect, test } from "vitest";
import {
  type TenantJurisdiction,
  type TenantObjectNamespaceLike,
  locationHintFromCloudflareSignal,
  tenantJurisdictionForResidencyRegions,
  tenantObjectStubFor,
} from "../src/index.js";

function makeNamespace(): {
  readonly namespace: TenantObjectNamespaceLike<string>;
  readonly calls: {
    jurisdictions: string[];
    ids: string[];
    gets: Array<{ id: string; options?: { locationHint?: string } }>;
  };
} {
  const calls: {
    jurisdictions: string[];
    ids: string[];
    gets: Array<{ id: string; options?: { locationHint?: string } }>;
  } = { jurisdictions: [], ids: [], gets: [] };
  const make = (prefix: string): TenantObjectNamespaceLike<string> => {
    const value = {
      idFromName(name: string) {
        const id = `${prefix}:${name}`;
        calls.ids.push(id);
        return id;
      },
      get(id: string, options?: { locationHint?: string }) {
        calls.gets.push({ id, ...(options === undefined ? {} : { options }) });
        return id;
      },
      jurisdiction(value: TenantJurisdiction) {
        calls.jurisdictions.push(value);
        return make(value);
      },
    };
    return value as TenantObjectNamespaceLike<string>;
  };
  return { namespace: make("unrestricted"), calls };
}

describe("tenant placement", () => {
  test.each([
    [{ continent: "EU", colo: "FRA" }, "weur"],
    [{ continent: "EU", colo: "WAW" }, "eeur"],
    [{ continent: "NA", colo: "IAD" }, "enam"],
    [{ continent: "NA", colo: "SFO" }, "wnam"],
    [{ continent: "SA", colo: "GRU" }, "sam"],
    [{ continent: "AF", colo: "JNB" }, "afr"],
    [{ continent: "AS", colo: "NRT" }, "apac-ne"],
    [{ continent: "AS", colo: "SIN" }, "apac-se"],
    [{ continent: "OC", colo: "SYD" }, "oc"],
    [{ continent: "ME", colo: "DXB" }, "me"],
  ] as const)("maps %j to %s", (signal, locationHint) => {
    expect(locationHintFromCloudflareSignal(signal).locationHint).toBe(locationHint);
  });

  test("records the signal used and has an explicit fallback for missing CF data", () => {
    expect(locationHintFromCloudflareSignal({}).source).toBe("cf.unavailable");
    expect(locationHintFromCloudflareSignal({}).locationHint).toBe("apac-ne");
    expect(locationHintFromCloudflareSignal({ continent: "EU", colo: "FRA" }).source).toBe(
      "cf.continent=EU;cf.colo=FRA",
    );
  });

  test("selects jurisdiction before deriving a different id and passes the first-get hint", () => {
    const { namespace, calls } = makeNamespace();

    const euStub = tenantObjectStubFor(namespace, "tenant-a", {
      jurisdiction: "eu",
      locationHint: "weur",
    });
    const unrestrictedStub = tenantObjectStubFor(namespace, "tenant-a");

    expect(euStub).toBe("eu:tenant-a");
    expect(unrestrictedStub).toBe("unrestricted:tenant-a");
    expect(euStub).not.toBe(unrestrictedStub);
    expect(calls.jurisdictions).toEqual(["eu"]);
    expect(calls.gets).toEqual([
      { id: "eu:tenant-a", options: { locationHint: "weur" } },
      { id: "unrestricted:tenant-a" },
    ]);
  });

  test("derives supported jurisdictions from the existing residency region vocabulary", () => {
    expect(tenantJurisdictionForResidencyRegions(["eu-west-1"])).toBe("eu");
    expect(tenantJurisdictionForResidencyRegions(["us-east-1"])).toBe("us");
    expect(tenantJurisdictionForResidencyRegions(["fedramp-high"])).toBe("fedramp");
    expect(tenantJurisdictionForResidencyRegions([])).toBeUndefined();
  });
});
