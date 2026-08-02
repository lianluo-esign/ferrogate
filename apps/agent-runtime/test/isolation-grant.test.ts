/**
 * The ISOLATION-TIER approximation, pinned.
 *
 * Rust `agent-worker` ships FOUR isolation backends (inventory-edge-control
 * §8.2). Three of them — Firecracker microVM, Docker `--network none`, and
 * `unshare` local-process namespaces — cannot exist on Cloudflare: workerd
 * exposes no `/dev/kvm`, no AF_VSOCK, no process spawn and no namespace
 * syscalls. Those are kept as PORT-TODO platform limits in
 * `src/runs/governance.ts`, and they are NOT what this file tests.
 *
 * What this file tests is the one backend that IS CF-native, and the honesty
 * of what it advertises. `IsolationGrant` is the whole of what this Worker
 * promises a caller about the tier its workload will run in, and every field
 * on it is either a security posture (#471) or a capability disclosure. An
 * approximation that nobody asserts is how `enableInternet` quietly becomes
 * `true` in a refactor.
 */
import { describe, expect, it } from "vitest";
import { inMemoryGovernancePort } from "../src/ports.js";

const REQUEST = {
  tenantId: "tenant-a",
  workspaceId: "ws-a",
  frameworkAdapter: "native",
  requiredCapabilities: ["network.egress"],
  egressAllowlist: ["upstream.test"],
  parentActionFingerprint: null,
} as const;

describe("IsolationGrant — the CF-native tier, and what it admits it cannot do", () => {
  it("grants the Cloudflare Sandbox backend and nothing else", async () => {
    // The three unportable backends must never appear as a grant. If one ever
    // does, something has claimed an isolation guarantee this platform cannot
    // deliver — which is worse than refusing the workload.
    const port = inMemoryGovernancePort({ governedEgressHosts: ["upstream.test"] });
    const decision = await port.authorize(REQUEST);
    expect(decision.outcome).toBe("allow");
    if (decision.outcome !== "allow") return;
    expect(decision.grant.backend).toBe("cloudflare_sandbox");
  });

  it("pins enableInternet=false and interceptHttps=true — load-bearing #471", async () => {
    // These two are the sealed-egress posture. They are pinned literals in the
    // type as well, so this test and the compiler both have to be defeated for
    // the container to reach the open internet.
    const port = inMemoryGovernancePort({ governedEgressHosts: ["upstream.test"] });
    const decision = await port.authorize(REQUEST);
    if (decision.outcome !== "allow") throw new Error("expected an allow");
    expect(decision.grant.enableInternet).toBe(false);
    expect(decision.grant.interceptHttps).toBe(true);
  });

  it("advertises snapshotSupported=false — Cloudflare has no snapshot primitive", async () => {
    // Rust advertises per-backend snapshot support. Neither Containers nor
    // Durable Objects can checkpoint and restore a live process image, so the
    // honest answer is `false`. Reporting `true` — or omitting the field and
    // letting a caller assume — would promise a restore that cannot happen.
    const port = inMemoryGovernancePort({ governedEgressHosts: ["upstream.test"] });
    const decision = await port.authorize(REQUEST);
    if (decision.outcome !== "allow") throw new Error("expected an allow");
    expect(decision.grant.snapshotSupported).toBe(false);
  });

  it("the granted hosts are the INTERSECTION, never the request", async () => {
    // A grant that echoed the request back would make the operator allowlist
    // decorative.
    const port = inMemoryGovernancePort({ governedEgressHosts: ["upstream.test"] });
    const decision = await port.authorize({
      ...REQUEST,
      egressAllowlist: ["upstream.test", "evil.test"],
    });
    // `evil.test` is outside the governed set, so the whole request is refused
    // rather than silently narrowed — a partial grant would let a caller probe
    // the allowlist one host at a time.
    expect(decision.outcome).toBe("deny");
    if (decision.outcome !== "deny") return;
    expect(decision.denial.code).toBe("egress_host_not_governed");
  });

  it("an EMPTY operator allowlist is SEALED, not open (#471)", async () => {
    // The failure mode this exists for: a forgotten configuration must refuse
    // egress, never permit it.
    const port = inMemoryGovernancePort({ governedEgressHosts: [] });
    const decision = await port.authorize(REQUEST);
    expect(decision.outcome).toBe("deny");
    if (decision.outcome !== "deny") return;
    expect(decision.denial.status).toBe(422);
    expect(decision.denial.message).toContain("sealed");
  });

  it("a workload asking for NO egress is still granted under a sealed tier", async () => {
    // Sealed must mean "no egress", not "no workloads" — otherwise the safe
    // default is unusable and operators will disable it.
    const port = inMemoryGovernancePort({ governedEgressHosts: [] });
    const decision = await port.authorize({ ...REQUEST, egressAllowlist: [] });
    expect(decision.outcome).toBe("allow");
    if (decision.outcome !== "allow") return;
    expect(decision.grant.allowedHosts).toEqual([]);
    expect(decision.grant.enableInternet).toBe(false);
  });
});
