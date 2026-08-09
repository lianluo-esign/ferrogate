/**
 * `resolveDeps` must build its {@link GovernancePort} FROM
 * `CONTAINER_GOVERNED_EGRESS_HOSTS` — the sealed-by-default mount (#471).
 *
 * ## Why this file exists
 *
 * `test/isolation-grant.test.ts` is a thorough test of the POLICY: it builds
 * `inMemoryGovernancePort({ governedEgressHosts: [...] })` by hand, eleven
 * times, and pins every branch including the sealed one. What it never does is
 * call `resolveDeps`. So the composition line
 *
 *     governance: inMemoryGovernancePort({
 *       governedEgressHosts: parseGovernedEgressHosts(env.CONTAINER_GOVERNED_EGRESS_HOSTS),
 *     }),
 *
 * — `MOUNT-SEAMS.md` **AR-P4**, a T1 tenant-isolation seam — had no gate at
 * all. The operator var could stop being read entirely and every one of those
 * eleven assertions would still pass, because they never go through the wiring.
 *
 * That is the same shape as GW-A1 and it is worth naming precisely: a port
 * tested as a FACTORY is not a port proven MOUNTED.
 *
 * ## Why the mutation the inventory suggested does not prove this
 *
 * AR-P4's recorded recipe was to replace the `parseGovernedEgressHosts(...)`
 * call with the literal `["*"]`. That mutation is a NO-OP here, and the wave-14
 * sweep dutifully reported GREEN for it. `inMemoryGovernancePort` matches egress
 * hosts with `allowedHosts.has(host)` — an EXACT set membership test. `"*"` is a
 * wildcard for `grantableCapabilities` but is just a literal hostname for
 * egress, so `["*"]` governs exactly one host named `*` and refuses everything
 * else, which is what a sealed tier does anyway. The recipe is corrected in
 * MOUNT-SEAMS.md; the real proof is below, and it is behavioural.
 */
import { describe, expect, it } from "vitest";
import { resolveDeps } from "../src/ports.js";

/** The minimum env `resolveDeps` needs to return a dep bundle at all (AR-P3). */
function envWith(governedEgressHosts: string | undefined): Parameters<typeof resolveDeps>[0] {
  return {
    FG_DEV_IN_MEMORY_PORTS: "1",
    ...(governedEgressHosts === undefined
      ? {}
      : { CONTAINER_GOVERNED_EGRESS_HOSTS: governedEgressHosts }),
  } as unknown as Parameters<typeof resolveDeps>[0];
}

const REQUEST = {
  workspaceId: "ws_1",
  tenantId: "tenant_a",
  requiredCapabilities: ["network.egress"],
  egressAllowlist: ["upstream.test"],
  parentActionFingerprint: null,
};

describe("resolveDeps mounts the governed-egress allowlist", () => {
  it("REFUSES a host the operator never governed (the sealed default)", async () => {
    const deps = resolveDeps(envWith(""));
    expect(
      deps,
      "resolveDeps returned undefined; the dev port bundle is not available",
    ).toBeDefined();

    const decision = await deps?.governance.authorize(
      REQUEST as unknown as Parameters<NonNullable<typeof deps>["governance"]["authorize"]>[0],
    );
    expect(decision?.outcome).toBe("deny");
    expect(decision?.outcome === "deny" ? decision.denial.code : null).toBe(
      "egress_host_not_governed",
    );
    // The sealed wording is the operator-facing half of #471, and it is only
    // reachable when the allowlist really is empty.
    expect(decision?.outcome === "deny" ? decision.denial.message : "").toContain("sealed");
  });

  it("is sealed when the var is ABSENT, not just when it is empty", async () => {
    // A missing var must not read as "unconfigured, therefore permissive".
    const deps = resolveDeps(envWith(undefined));
    const decision = await deps?.governance.authorize(
      REQUEST as unknown as Parameters<NonNullable<typeof deps>["governance"]["authorize"]>[0],
    );
    expect(decision?.outcome).toBe("deny");
  });

  it("GRANTS exactly the host the operator var declares — only the real wiring can do this", async () => {
    // This is the assertion the seam needs: nothing but `resolveDeps` actually
    // reading `CONTAINER_GOVERNED_EGRESS_HOSTS` can turn the refusal above into
    // a grant. Unwire the var and this test fails.
    const deps = resolveDeps(envWith("upstream.test"));
    const decision = await deps?.governance.authorize(
      REQUEST as unknown as Parameters<NonNullable<typeof deps>["governance"]["authorize"]>[0],
    );
    expect(decision?.outcome).toBe("allow");
    expect(decision?.outcome === "allow" ? decision.grant.allowedHosts : []).toEqual([
      "upstream.test",
    ]);
  });

  it("parses a COMMA-SEPARATED list, and still refuses anything outside it", async () => {
    const deps = resolveDeps(envWith("upstream.test, other.test"));
    const allowed = await deps?.governance.authorize({
      ...REQUEST,
      egressAllowlist: ["other.test"],
    } as unknown as Parameters<NonNullable<typeof deps>["governance"]["authorize"]>[0]);
    expect(allowed?.outcome).toBe("allow");

    const refused = await deps?.governance.authorize({
      ...REQUEST,
      egressAllowlist: ["evil.test"],
    } as unknown as Parameters<NonNullable<typeof deps>["governance"]["authorize"]>[0]);
    expect(refused?.outcome).toBe("deny");
  });
});
