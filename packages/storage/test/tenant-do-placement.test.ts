import { describe, expect, test } from "vitest";
import {
  DurableObjectTenantDatabaseRouter,
  type TenantDataNamespaceLike,
  type TenantDataStub,
} from "../src/tenant-do.js";
import type { TenantJurisdiction, TenantObjectGetOptions } from "../src/tenant-placement.js";

function namespace(): {
  readonly value: TenantDataNamespaceLike;
  readonly calls: {
    jurisdictions: string[];
    ids: string[];
    gets: Array<{ id: unknown; options?: { locationHint?: string } }>;
  };
} {
  const calls: {
    jurisdictions: string[];
    ids: string[];
    gets: Array<{ id: unknown; options?: { locationHint?: string } }>;
  } = { jurisdictions: [], ids: [], gets: [] };
  const stub: TenantDataStub = {
    async query() {
      throw new Error("not reached");
    },
    async batch() {
      throw new Error("not reached");
    },
  };
  const make = (prefix: string): TenantDataNamespaceLike => {
    const value = {
    idFromName(name: string) {
      const id = `${prefix}:${name}` as unknown as DurableObjectId;
      calls.ids.push(String(id));
      return id;
    },
    get(id: DurableObjectId, options?: TenantObjectGetOptions) {
      calls.gets.push({ id, ...(options === undefined ? {} : { options }) });
      return stub;
    },
    jurisdiction(value: TenantJurisdiction) {
      calls.jurisdictions.push(value);
      return make(value);
    },
    };
    return value as TenantDataNamespaceLike;
  };
  return { value: make("unrestricted"), calls };
}

const controlDb = {
  prepare(): never {
    throw new Error("forTenant must not read CONTROL_DB");
  },
} as unknown as D1Database;

describe("DurableObjectTenantDatabaseRouter placement", () => {
  test("forTenant forwards jurisdiction and locationHint without CONTROL I/O", async () => {
    const { value, calls } = namespace();
    const router = new DurableObjectTenantDatabaseRouter(value, controlDb);

    await router.forTenant("tenant-a", { jurisdiction: "eu", locationHint: "weur" });

    expect(calls.jurisdictions).toEqual(["eu"]);
    expect(calls.gets).toEqual([
      { id: "eu:tenant-a", options: { locationHint: "weur" } },
    ]);
  });
});
