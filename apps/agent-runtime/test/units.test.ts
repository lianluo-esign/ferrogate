/**
 * The pure decision logic, asserted directly.
 *
 * These are the functions whose behaviour the HTTP tests depend on but cannot
 * pin precisely: the constant-time secret comparison, the derived job id, the
 * worker-dialect status normalizer, and the transport posture. A bug in any of
 * them would show up as a confusing integration failure, or not at all.
 */
import { describe, expect, it } from "vitest";
import {
  agentJobRunId,
  canonicalTargetFingerprint,
  timingSafeEqualStrings,
} from "../src/crypto.js";
import {
  admitTransport,
  extractApiKey,
  hasScope,
  transportChannel,
  transportPosture,
} from "../src/middleware/auth.js";
import {
  inMemoryGovernancePort,
  inMemoryWorkerIdentityPort,
  isCanonicalActionFingerprint,
  normalizedCapabilities,
  parseGovernedEgressHosts,
} from "../src/ports.js";
import { isAddressableRunId } from "../src/runs/governance.js";
import {
  canonicalRunStatus,
  isTerminalStatus,
  workerReportedOutput,
  workerReportedRunState,
} from "../src/runs/model.js";

describe("timingSafeEqualStrings", () => {
  it("is correct", () => {
    expect(timingSafeEqualStrings("abc", "abc")).toBe(true);
    expect(timingSafeEqualStrings("abc", "abd")).toBe(false);
    expect(timingSafeEqualStrings("abc", "ab")).toBe(false);
    expect(timingSafeEqualStrings("", "")).toBe(true);
    expect(timingSafeEqualStrings("", "a")).toBe(false);
  });

  it("is unicode-safe", () => {
    // Byte-wise comparison, so a multi-byte code point is not truncated.
    expect(timingSafeEqualStrings("é", "é")).toBe(true);
    expect(timingSafeEqualStrings("é", "e")).toBe(false);
  });
});

describe("agentJobRunId", () => {
  it("is deterministic — the whole idempotency mechanism", async () => {
    const first = await agentJobRunId("tenant-a", "key-1");
    expect(await agentJobRunId("tenant-a", "key-1")).toBe(first);
    expect(first).toMatch(/^job-[0-9a-f]{32}$/);
  });

  it("is namespaced by tenant", async () => {
    expect(await agentJobRunId("tenant-a", "k")).not.toBe(await agentJobRunId("tenant-b", "k"));
  });

  it("cannot be confused by a split at the tenant/key boundary", async () => {
    // The 0x1f domain break exists precisely so ("ab","c") and ("a","bc")
    // cannot hash to the same job id.
    expect(await agentJobRunId("ab", "c")).not.toBe(await agentJobRunId("a", "bc"));
  });
});

describe("canonicalRunStatus", () => {
  it("accepts every worker dialect for the same state", () => {
    for (const word of ["completed", "complete", "succeeded", "success", "finished", "done"]) {
      expect(canonicalRunStatus(word)).toBe("completed");
    }
    for (const word of ["started", "running", "in_progress", "accepted", "resumed"]) {
      expect(canonicalRunStatus(word)).toBe("running");
    }
    expect(canonicalRunStatus("timeout")).toBe("timed_out");
    expect(canonicalRunStatus("budget_exhausted")).toBe("exhausted");
    expect(canonicalRunStatus("turn_limit_exceeded")).toBe("max_turns_exceeded");
  });

  it("normalizes separators and strips the event-name prefix", () => {
    expect(canonicalRunStatus("run.completed")).toBe("completed");
    expect(canonicalRunStatus("JOB-FAILED")).toBe("failed");
    expect(canonicalRunStatus("agent_run_cancelled")).toBe("cancelled");
    expect(canonicalRunStatus("  Deadline Exceeded ")).toBe("timed_out");
  });

  it("returns undefined for an unrecognized word rather than guessing", () => {
    expect(canonicalRunStatus("wobbling")).toBeUndefined();
    expect(canonicalRunStatus("")).toBeUndefined();
  });

  it("classifies terminality the way the collect verb needs", () => {
    expect(isTerminalStatus("queued")).toBe(false);
    expect(isTerminalStatus("running")).toBe(false);
    for (const status of [
      "completed",
      "failed",
      "cancelled",
      "timed_out",
      "max_turns_exceeded",
      "exhausted",
    ]) {
      expect(isTerminalStatus(status), status).toBe(true);
    }
  });
});

describe("workerReportedRunState", () => {
  it("lets the lifecycle BODY win over the event kind", () => {
    // A worker sending `kind: "lifecycle"` puts the state in the body; a worker
    // naming the event `run.completed` carries it in the kind. Both dialects.
    expect(workerReportedRunState("lifecycle", { state: "failed" })?.status).toBe("failed");
    expect(workerReportedRunState("run.completed", {})?.status).toBe("completed");
    expect(workerReportedRunState("lifecycle", { status: "succeeded" })?.status).toBe("completed");
  });

  it("returns undefined when neither dialect names a state", () => {
    expect(workerReportedRunState("log", { message: "hi" })).toBeUndefined();
  });

  it("re-serializes a structured output instead of dropping it", () => {
    // The #472 work-product shape.
    const output = workerReportedOutput({ output: { pull_request: "https://x.test/1" } });
    expect(output).toContain("pull_request");
    expect(workerReportedOutput({ output: "  text  " })).toBe("text");
    expect(workerReportedOutput({ output: null, result: "fallback" })).toBe("fallback");
    expect(workerReportedOutput({})).toBeUndefined();
  });

  it("carries a valid turn count and ignores a nonsense one", () => {
    expect(workerReportedRunState("lifecycle", { state: "running", turns: 3 })?.turnsExecuted).toBe(
      3,
    );
    expect(
      workerReportedRunState("lifecycle", { state: "running", turns: "many" })?.turnsExecuted,
    ).toBeUndefined();
  });
});

describe("credential extraction and scopes", () => {
  it("x-api-key wins over Authorization, and blanks count as absent", () => {
    expect(extractApiKey(new Headers({ "x-api-key": "k1", authorization: "Bearer k2" }))).toBe(
      "k1",
    );
    expect(extractApiKey(new Headers({ "x-api-key": "   ", authorization: "Bearer k2" }))).toBe(
      "k2",
    );
    expect(extractApiKey(new Headers({ authorization: "bearer k3" }))).toBe("k3");
    expect(extractApiKey(new Headers({ authorization: "Basic abc" }))).toBeNull();
    expect(extractApiKey(new Headers({ authorization: "Bearer   " }))).toBeNull();
    expect(extractApiKey(new Headers())).toBeNull();
  });

  it("an EMPTY scope set grants data-plane scopes but never admin.*", () => {
    // Load-bearing asymmetry: a virtual key with no scopes must not become an
    // admin key.
    const bare = { subject: "s", tenancy: { tenantId: "t" }, scopes: [], platformOperator: false };
    expect(hasScope(bare, "agent.runs.read")).toBe(true);
    expect(hasScope(bare, "admin.write")).toBe(false);
  });

  it("the wildcard and the platform-operator flag grant everything", () => {
    const wildcard = {
      subject: "s",
      tenancy: { tenantId: "t" },
      scopes: ["*"],
      platformOperator: false,
    };
    expect(hasScope(wildcard, "admin.write")).toBe(true);
    const operator = {
      subject: "s",
      tenancy: { tenantId: null },
      scopes: [],
      platformOperator: true,
    };
    expect(hasScope(operator, "admin.write")).toBe(true);
  });

  it("a listed scope set grants only what it lists", () => {
    const listed = {
      subject: "s",
      tenancy: { tenantId: "t" },
      scopes: ["agent.runs.read"],
      platformOperator: false,
    };
    expect(hasScope(listed, "agent.runs.read")).toBe(true);
    expect(hasScope(listed, "agent.runs.create")).toBe(false);
  });
});

describe("worker transport posture", () => {
  it("parses the transport-security marker", () => {
    expect(transportChannel(new Headers({ "x-ferrogate-transport-security": "mutual_tls" }))).toBe(
      "unverified_mutual_tls_marker",
    );
    expect(
      transportChannel(new Headers({ "x-ferrogate-transport-security": "symmetric_aead" })),
    ).toBe("symmetric_aead");
    expect(transportChannel(new Headers({ "x-ferrogate-transport-security": "none" }))).toBeNull();
    expect(transportChannel(new Headers())).toBeNull();
  });

  it("admits both channels under the pre-production marker posture", () => {
    expect(transportPosture(undefined)).toBe("marker_contract");
    expect(transportPosture("0")).toBe("marker_contract");
    expect(admitTransport("marker_contract", "symmetric_aead")).toBeNull();
    expect(admitTransport("marker_contract", "unverified_mutual_tls_marker")).toBeNull();
  });

  it("FAILS CLOSED on every channel a Worker can observe under the production posture", () => {
    expect(transportPosture("1")).toBe("require_production_mtls");
    // A downgrade is 403; an unverified mTLS *claim* is 501 — better to refuse
    // than to accept an unverifiable claim as production-grade.
    expect(admitTransport("require_production_mtls", "symmetric_aead")?.status).toBe(403);
    expect(admitTransport("require_production_mtls", "unverified_mutual_tls_marker")?.status).toBe(
      501,
    );
  });
});

describe("worker identity registry", () => {
  const registered = {
    tenant_id: "t",
    workspace_id: "w",
    worker_id: "worker",
    framework_adapter: "native",
    token_id: "tok",
    token_secret: "s".repeat(64),
    capabilities: ["Coding", "coding", " CODING "],
  };
  const identity = {
    tenant_id: "t",
    workspace_id: "w",
    worker_id: "worker",
    token_id: "tok",
    token_secret: "s".repeat(64),
  };

  it("an EMPTY registry admits nobody — the fail-closed default", async () => {
    const port = inMemoryWorkerIdentityPort([]);
    const result = await port.validate(identity);
    expect(result.outcome).toBe("rejected");
  });

  it("admits a matching identity and normalizes its capabilities", async () => {
    const port = inMemoryWorkerIdentityPort([registered]);
    const result = await port.validate(identity);
    expect(result.outcome).toBe("resolved");
    if (result.outcome === "resolved") {
      expect(result.worker.capabilities).toEqual(["coding"]);
      // The secret never leaves the registry.
      expect(Object.hasOwn(result.worker, "token_secret")).toBe(false);
    }
  });

  it("rejects a wrong secret, a wrong token id, and a blank field", async () => {
    const port = inMemoryWorkerIdentityPort([registered]);
    expect((await port.validate({ ...identity, token_secret: "x".repeat(64) })).outcome).toBe(
      "rejected",
    );
    expect((await port.validate({ ...identity, token_id: "other" })).outcome).toBe("rejected");
    const blank = await port.validate({ ...identity, worker_id: "  " });
    expect(blank.outcome).toBe("rejected");
    if (blank.outcome === "rejected") expect(blank.failure.reason).toBe("invalid_shape");
  });

  it("rejects an expired identity against the worker's own clock", async () => {
    const port = inMemoryWorkerIdentityPort([{ ...registered, identity_expires_at_unix: 1_000 }]);
    expect((await port.validate({ ...identity, observed_at_unix: 999 })).outcome).toBe("resolved");
    expect((await port.validate({ ...identity, observed_at_unix: 1_000 })).outcome).toBe(
      "rejected",
    );
  });

  it("distinguishes inactive from unknown", async () => {
    const port = inMemoryWorkerIdentityPort([{ ...registered, active: false }]);
    const inactive = await port.validate(identity);
    expect(inactive.outcome).toBe("rejected");
    if (inactive.outcome === "rejected") expect(inactive.failure.reason).toBe("inactive_worker");

    const unknown = await port.validate({ ...identity, worker_id: "ghost" });
    if (unknown.outcome === "rejected") expect(unknown.failure.reason).toBe("unknown_worker");
  });
});

describe("governance", () => {
  it("EMPTY governed-host list means SEALED, not open", async () => {
    const port = inMemoryGovernancePort({ governedEgressHosts: [] });
    const denied = await port.authorize({
      tenantId: "t",
      workspaceId: "w",
      frameworkAdapter: "native",
      requiredCapabilities: [],
      egressAllowlist: ["anything.test"],
      parentActionFingerprint: null,
    });
    expect(denied.outcome).toBe("deny");
    if (denied.outcome === "deny") {
      expect(denied.denial.status).toBe(422);
      expect(denied.denial.message).toContain("sealed");
    }
  });

  it("grants only hosts inside the operator allowlist", async () => {
    const port = inMemoryGovernancePort({ governedEgressHosts: ["gateway.test"] });
    const allowed = await port.authorize({
      tenantId: "t",
      workspaceId: "w",
      frameworkAdapter: "native",
      requiredCapabilities: [],
      egressAllowlist: ["GATEWAY.TEST"],
      parentActionFingerprint: null,
    });
    expect(allowed.outcome).toBe("allow");
    if (allowed.outcome === "allow") {
      expect(allowed.grant.allowedHosts).toEqual(["gateway.test"]);
      // #471: both pinned, and snapshotting is honestly advertised OFF.
      expect(allowed.grant.enableInternet).toBe(false);
      expect(allowed.grant.interceptHttps).toBe(true);
      expect(allowed.grant.snapshotSupported).toBe(false);
    }

    const denied = await port.authorize({
      tenantId: "t",
      workspaceId: "w",
      frameworkAdapter: "native",
      requiredCapabilities: [],
      egressAllowlist: ["gateway.test", "evil.test"],
      parentActionFingerprint: null,
    });
    expect(denied.outcome).toBe("deny");
  });

  it("refuses an ungrantable capability with 403", async () => {
    const port = inMemoryGovernancePort({
      governedEgressHosts: [],
      grantableCapabilities: ["coding"],
    });
    const denied = await port.authorize({
      tenantId: "t",
      workspaceId: "w",
      frameworkAdapter: "native",
      requiredCapabilities: ["coding", "kernel.debug"],
      egressAllowlist: [],
      parentActionFingerprint: null,
    });
    expect(denied.outcome).toBe("deny");
    if (denied.outcome === "deny") {
      expect(denied.denial.status).toBe(403);
      expect(denied.denial.message).toContain("kernel.debug");
      expect(denied.denial.message).not.toContain("coding,");
    }
  });
});

describe("identifier shapes", () => {
  it("the action fingerprint contract is sha256:<64 lowercase hex>", async () => {
    expect(isCanonicalActionFingerprint(`sha256:${"a".repeat(64)}`)).toBe(true);
    expect(isCanonicalActionFingerprint(`sha256:${"A".repeat(64)}`)).toBe(false);
    expect(isCanonicalActionFingerprint(`sha256:${"a".repeat(63)}`)).toBe(false);
    expect(isCanonicalActionFingerprint("a".repeat(64))).toBe(false);
    expect(isCanonicalActionFingerprint(await canonicalTargetFingerprint("tool:read:/etc"))).toBe(
      true,
    );
  });

  it("a run id is a bounded, opaque token", () => {
    expect(isAddressableRunId("job-abc123")).toBe(true);
    // A separator in a path segment must never reach a DO name or storage key.
    expect(isAddressableRunId("a/b")).toBe(false);
    expect(isAddressableRunId("")).toBe(false);
    expect(isAddressableRunId("x".repeat(129))).toBe(false);
  });

  it("capabilities are trimmed, lowercased, deduped and sorted", () => {
    expect(normalizedCapabilities([" B ", "a", "A", ""])).toEqual(["a", "b"]);
    expect(normalizedCapabilities(undefined)).toEqual([]);
  });

  it("the governed-egress host list tolerates operator formatting", () => {
    expect(parseGovernedEgressHosts(" A.test , b.test ,, ")).toEqual(["a.test", "b.test"]);
    expect(parseGovernedEgressHosts("")).toEqual([]);
    expect(parseGovernedEgressHosts(undefined)).toEqual([]);
  });
});
