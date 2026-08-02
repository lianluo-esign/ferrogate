import { expect, test } from "vitest";
import type { SsoPendingFlow, SsoPendingFlowStore } from "./ports.js";

/**
 * The executable contract every `SsoPendingFlowStore` must satisfy — in-memory
 * or D1-backed.
 *
 * It is exported from the package (rather than living in `test/`) precisely so
 * `apps/control-plane` can run the IDENTICAL block against its durable store.
 * The SAML replay defence is `take`'s single-use semantics and nothing else:
 * the assertion signature stays valid forever, so a replayed redirect is
 * cryptographically indistinguishable from the original. If the durable twin
 * implements `take` as a SELECT followed by a DELETE, replay comes back — and
 * no test in `packages/sso` would notice, because it would still be exercising
 * the in-memory map.
 *
 * Call inside a `describe`:
 *
 * ```ts
 * describe("D1 pending-flow store", () => {
 *   samlPendingFlowStoreContract(() => new D1SsoPendingFlowStore(env.CONTROL_DB));
 * });
 * ```
 */
export function samlPendingFlowStoreContract(
  makeStore: () => SsoPendingFlowStore | Promise<SsoPendingFlowStore>,
): void {
  const flow = (overrides: Partial<SsoPendingFlow> = {}): SsoPendingFlow => ({
    state: "state-1",
    tenantId: "tenant_acme",
    providerKind: "saml",
    codeVerifier: null,
    requestId: "_req-1",
    createdAtUnix: 1_000,
    expiresAtUnix: 1_600,
    ...overrides,
  });

  test("an inserted flow is returned by take", async () => {
    const store = await makeStore();
    await store.insert(flow());
    expect(await store.take("state-1", 1_100)).toMatchObject({
      state: "state-1",
      tenantId: "tenant_acme",
      providerKind: "saml",
      requestId: "_req-1",
    });
  });

  test("take CONSUMES: the second call returns null (the replay defence)", async () => {
    const store = await makeStore();
    await store.insert(flow());
    expect(await store.take("state-1", 1_100)).not.toBeNull();
    expect(await store.take("state-1", 1_100)).toBeNull();
  });

  test("concurrent takes of the same state: exactly ONE wins", async () => {
    const store = await makeStore();
    await store.insert(flow());
    const results = await Promise.all([
      store.take("state-1", 1_100),
      store.take("state-1", 1_100),
      store.take("state-1", 1_100),
      store.take("state-1", 1_100),
    ]);
    expect(results.filter((result) => result !== null)).toHaveLength(1);
  });

  test("an EXPIRED flow is not returned", async () => {
    const store = await makeStore();
    await store.insert(flow({ expiresAtUnix: 1_600 }));
    expect(await store.take("state-1", 1_600)).toBeNull();
  });

  test("a flow one second before expiry IS returned", async () => {
    const store = await makeStore();
    await store.insert(flow({ expiresAtUnix: 1_600 }));
    expect(await store.take("state-1", 1_599)).not.toBeNull();
  });

  test("presenting an EXPIRED state still burns it", async () => {
    // Otherwise a state that expires between two replays becomes usable again
    // if the clock is ever adjusted backwards.
    const store = await makeStore();
    await store.insert(flow({ expiresAtUnix: 1_600 }));
    expect(await store.take("state-1", 2_000)).toBeNull();
    expect(await store.take("state-1", 1_100)).toBeNull();
  });

  test("an unknown state is null, never a default flow", async () => {
    const store = await makeStore();
    await store.insert(flow());
    expect(await store.take("some-other-state", 1_100)).toBeNull();
  });

  test("states are independent: taking one does not consume another", async () => {
    const store = await makeStore();
    await store.insert(flow({ state: "a" }));
    await store.insert(flow({ state: "b" }));
    expect(await store.take("a", 1_100)).not.toBeNull();
    expect(await store.take("b", 1_100)).not.toBeNull();
  });

  test("every field round-trips (a store that drops requestId breaks InResponseTo)", async () => {
    const store = await makeStore();
    await store.insert(
      flow({ state: "full", tenantId: "tenant_z", requestId: "_abc", codeVerifier: null }),
    );
    const taken = await store.take("full", 1_100);
    expect(taken).toEqual({
      state: "full",
      tenantId: "tenant_z",
      providerKind: "saml",
      codeVerifier: null,
      requestId: "_abc",
      createdAtUnix: 1_000,
      expiresAtUnix: 1_600,
    });
  });
}
