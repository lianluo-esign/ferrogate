/**
 * The enforcement chokepoint — input block, output redaction, and the FAIL
 * POSTURE.
 *
 * The fail-posture tests are the security-critical ones: they hold the
 * `provider_on_error = Block` default (`crates/ferrogate-config/src/config/
 * types.rs:1954-1959` → `crates/ferrogate-gateway/src/state.rs:6335-6342`).
 * Getting this branch backwards turns every detector outage into an open door.
 */
import type { GuardrailDetector, PolicyRevision } from "@ferrogate/guardrails";
import { normalizeRequest, normalizeResponse } from "@ferrogate/guardrails";
import { describe, expect, test } from "vitest";
import {
  GuardrailEngine,
  InMemoryGuardrailEvidenceSink,
  redactText,
  unavailableEvidenceSink,
} from "../../src/guardrails/index.js";
import {
  EVIDENCE_HMAC_KEY,
  PROBE_SECRET,
  bodyWithProbeSecret,
  chatContext,
  cleanBody,
  failingDetector,
  secretScanPolicy,
  slowDetector,
  sourceFor,
} from "./fixtures.js";

function engineFor(
  policy = secretScanPolicy(),
  overrides: Parameters<typeof sourceFor>[1] = {},
  evidence = new InMemoryGuardrailEvidenceSink(),
): { engine: GuardrailEngine; evidence: InMemoryGuardrailEvidenceSink } {
  return {
    engine: new GuardrailEngine({
      policies: sourceFor(policy, overrides),
      evidence,
      evidenceHmacKey: EVIDENCE_HMAC_KEY,
    }),
    evidence,
  };
}

/**
 * Attach a LOCAL fallback detector to the policy's single check — the shape
 * `provider_on_error = "fallback_detector"` compiles to
 * (`crates/ferrogate-gateway/src/state.rs:6327-6330`).
 */
function withLocalFallback(policy: PolicyRevision, keywords: string[]): PolicyRevision {
  return {
    ...policy,
    checks: policy.checks.map((check, index) =>
      index === 0
        ? {
            ...check,
            fallback_detector: {
              kind: "local" as const,
              keywords,
              regex: [],
              secret_patterns: [],
              max_input_bytes: null,
            },
          }
        : check,
    ),
  };
}

describe("input screening", () => {
  test("a secret in the prompt blocks with the Rust code/message pair", async () => {
    const { engine } = engineFor();
    const match = await engine.matchGuardrail(
      "request",
      chatContext({ envelope: normalizeRequest("chat_completions", bodyWithProbeSecret()) }),
    );

    expect(match).not.toBeNull();
    expect(match?.effect).toBe("deny");
    expect(match?.actionKind).toBe("block");
    expect(match?.code).toBe("guardrail_blocked");
    expect(match?.message).toBe("request blocked by guardrail policy");
  });

  test("the keyword probe marker blocks too", async () => {
    const { engine } = engineFor();
    const match = await engine.matchGuardrail(
      "request",
      chatContext({
        envelope: normalizeRequest("chat_completions", {
          model: "gpt-4o",
          messages: [{ role: "user", content: "run FERROGATE-GUARDRAIL-PROBE now" }],
        }),
      }),
    );
    expect(match?.effect).toBe("deny");
  });

  test("a clean prompt is not blocked", async () => {
    const { engine } = engineFor();
    const match = await engine.matchGuardrail(
      "request",
      chatContext({ envelope: normalizeRequest("chat_completions", cleanBody()) }),
    );
    expect(match).toBeNull();
  });

  test("a secret split across two adjacent user parts is still caught", async () => {
    // The coalesced-group scan exists precisely for this (inventory §3.4(a)).
    const { engine } = engineFor();
    const half = Math.floor(PROBE_SECRET.length / 2);
    const match = await engine.matchGuardrail(
      "request",
      chatContext({
        envelope: normalizeRequest("chat_completions", {
          model: "gpt-4o",
          messages: [
            {
              role: "user",
              content: [
                { type: "text", text: PROBE_SECRET.slice(0, half) },
                { type: "text", text: PROBE_SECRET.slice(half) },
              ],
            },
          ],
        }),
      }),
    );
    expect(match?.effect).toBe("deny");
  });
});

describe("output screening", () => {
  const responsePolicy = secretScanPolicy({
    policyId: "response-redact",
    stage: "response",
    onFail: [
      { kind: "redact", code: "guardrail_redacted", message: "response redacted by policy" },
    ],
  });

  test("a secret in the completion is REDACTED, not blocked", async () => {
    const { engine } = engineFor(responsePolicy);
    const body = new TextEncoder().encode(
      JSON.stringify({
        id: "chatcmpl-1",
        choices: [{ index: 0, message: { role: "assistant", content: `key ${PROBE_SECRET} ok` } }],
      }),
    );
    const context = chatContext({
      envelope: normalizeResponse("chat_completions", body, false),
    });
    const match = await engine.matchGuardrail("response", context);

    expect(match?.effect).toBe("redact");
    if (match === null) {
      throw new Error("unreachable: the assertion above already failed");
    }
    const redacted = redactText(match, new TextDecoder().decode(body));
    expect(redacted).not.toContain(PROBE_SECRET);
    expect(redacted).toContain("[REDACTED]");
    // The rest of the document survives — this is a redaction, not a wipe.
    expect(JSON.parse(redacted).id).toBe("chatcmpl-1");
  });

  test("a redact with no usable patch FAILS CLOSED to deny", async () => {
    // `require_approval` is not the point here: a `quarantine`/`redact` whose
    // evidence carries no patch must become `guardrail_invalid_redaction`
    // (state_quota_and_policy.rs:1553-1567). A detector that reports a finding
    // and NO patches reproduces exactly that.
    const detector: GuardrailDetector = {
      descriptor: () => ({
        id: "no-patch",
        version: "v1",
        supports_request: true,
        supports_response: true,
        supports_transform: false,
        supported_sources: ["assistant"],
        credential: "none",
        data_residency: "in_repo",
        max_payload_bytes: 1024,
        declared_failure_modes: [],
      }),
      health: () => ({
        circuit_open: false,
        consecutive_failures: 0,
        in_flight: 0,
        request_total: 1,
        success_total: 1,
        failure_total: 0,
      }),
      evaluate: () =>
        Promise.resolve({
          verdict: "fail",
          findings: [{ category: "pii.custom", severity: "high", attributes: {} }],
          patches: [],
          detector_version: "v1",
        }),
    };
    const { engine } = engineFor(responsePolicy, { deterministic: detector });
    const body = new TextEncoder().encode(
      JSON.stringify({ choices: [{ message: { role: "assistant", content: "hi" } }] }),
    );
    const match = await engine.matchGuardrail(
      "response",
      chatContext({ envelope: normalizeResponse("chat_completions", body, false) }),
    );

    expect(match?.effect).toBe("deny");
    expect(match?.code).toBe("guardrail_invalid_redaction");
  });
});

describe("FAIL POSTURE — a detector error/timeout fails CLOSED", () => {
  test("a detector timeout denies with guardrail_provider_unavailable", async () => {
    const { engine } = engineFor(secretScanPolicy(), {
      deterministic: failingDetector("timeout", "deadline exceeded"),
    });
    const match = await engine.matchGuardrail(
      "request",
      chatContext({ envelope: normalizeRequest("chat_completions", cleanBody()) }),
    );

    expect(match).not.toBeNull();
    expect(match?.effect).toBe("deny");
    expect(match?.code).toBe("guardrail_provider_unavailable");
  });

  test("a detector that blows the policy deadline denies", async () => {
    const { engine } = engineFor(secretScanPolicy({ deadlineMs: 1 }), {
      deterministic: slowDetector(25),
    });
    const match = await engine.matchGuardrail(
      "request",
      chatContext({ envelope: normalizeRequest("chat_completions", cleanBody()) }),
    );
    expect(match?.effect).toBe("deny");
    expect(match?.code).toBe("guardrail_provider_unavailable");
  });

  test.each(["unavailable", "overloaded", "circuit_open", "internal"] as const)(
    "detector error kind %s denies",
    async (kind) => {
      const { engine } = engineFor(secretScanPolicy(), {
        deterministic: failingDetector(kind),
      });
      const match = await engine.matchGuardrail(
        "request",
        chatContext({ envelope: normalizeRequest("chat_completions", cleanBody()) }),
      );
      expect(match?.effect).toBe("deny");
      expect(match?.code).toBe("guardrail_provider_unavailable");
    },
  );

  test("a detector that throws a NON-DetectorError still fails closed", async () => {
    const detector = {
      ...failingDetector("internal"),
      evaluate: () => Promise.reject(new TypeError("adapter exploded")),
    };
    const { engine } = engineFor(secretScanPolicy(), { deterministic: detector });
    const match = await engine.matchGuardrail(
      "request",
      chatContext({ envelope: normalizeRequest("chat_completions", cleanBody()) }),
    );
    expect(match?.effect).toBe("deny");
  });

  test("the operator CAN opt into fail-open with on_error = record", async () => {
    // `provider_on_error = "record"` compiles to `[PolicyAction::record()]`
    // (state.rs:6340). This asserts the opt-in is real — and, by contrast, that
    // the default above is genuinely a default and not a hard-coded deny.
    const { engine, evidence } = engineFor(secretScanPolicy({ onError: [{ kind: "record" }] }), {
      deterministic: failingDetector("unavailable"),
    });
    const match = await engine.matchGuardrail(
      "request",
      chatContext({ envelope: normalizeRequest("chat_completions", cleanBody()) }),
    );
    expect(match).toBeNull();
    // NEVER a silent pass: the error is still on the evidence row.
    expect(evidence.evaluations()[0]?.verdict).toBe("error");
    expect(evidence.checks()[0]?.errorKind).toBe("unavailable");
  });

  test("a failing primary with a working fallback uses the fallback verdict", async () => {
    const policy = withLocalFallback(secretScanPolicy(), ["FERROGATE-GUARDRAIL-PROBE"]);
    const { engine, evidence } = engineFor(policy, {
      deterministic: failingDetector("unavailable"),
    });
    const match = await engine.matchGuardrail(
      "request",
      chatContext({
        envelope: normalizeRequest("chat_completions", {
          model: "gpt-4o",
          messages: [{ role: "user", content: "run FERROGATE-GUARDRAIL-PROBE" }],
        }),
      }),
    );
    expect(match?.code).toBe("guardrail_blocked");
    expect(evidence.checks()[0]?.usedFallback).toBe(true);
  });

  test("a failing primary AND a failing fallback still fails closed", async () => {
    const policy = withLocalFallback(secretScanPolicy(), ["never-matches"]);
    const engine = new GuardrailEngine({
      policies: sourceFor(policy, {
        deterministic: failingDetector("unavailable"),
        "deterministic#fallback": failingDetector("unavailable"),
      }),
      evidence: new InMemoryGuardrailEvidenceSink(),
    });
    const match = await engine.matchGuardrail(
      "request",
      chatContext({ envelope: normalizeRequest("chat_completions", cleanBody()) }),
    );
    expect(match?.effect).toBe("deny");
    expect(match?.code).toBe("guardrail_provider_unavailable");
  });
});

describe("other fail-closed branches", () => {
  test("unrecordable evidence denies with guardrail_evidence_unavailable", async () => {
    const engine = new GuardrailEngine({
      policies: sourceFor(secretScanPolicy()),
      evidence: unavailableEvidenceSink,
    });
    const match = await engine.matchGuardrail(
      "request",
      chatContext({ envelope: normalizeRequest("chat_completions", cleanBody()) }),
    );
    expect(match?.effect).toBe("deny");
    expect(match?.code).toBe("guardrail_evidence_unavailable");
  });

  test("an evidence sink that THROWS also denies", async () => {
    const engine = new GuardrailEngine({
      policies: sourceFor(secretScanPolicy()),
      evidence: {
        append: () => {
          throw new Error("D1 unreachable");
        },
      },
    });
    const match = await engine.matchGuardrail(
      "request",
      chatContext({ envelope: normalizeRequest("chat_completions", cleanBody()) }),
    );
    expect(match?.code).toBe("guardrail_evidence_unavailable");
  });

  test("reject_streaming denies a streaming request before dispatch", async () => {
    const { engine } = engineFor(secretScanPolicy({ streaming: "reject_streaming" }));
    const match = await engine.matchGuardrail(
      "request",
      chatContext({
        streaming: true,
        envelope: normalizeRequest("chat_completions", cleanBody()),
      }),
    );
    expect(match?.effect).toBe("deny");
    expect(match?.code).toBe("guardrail_streaming_unsupported");
  });

  test("reject_streaming does NOT touch a non-streaming request", async () => {
    const { engine } = engineFor(secretScanPolicy({ streaming: "reject_streaming" }));
    const match = await engine.matchGuardrail(
      "request",
      chatContext({ envelope: normalizeRequest("chat_completions", cleanBody()) }),
    );
    expect(match).toBeNull();
  });
});

describe("shadow mode", () => {
  test("a shadow policy records but never enforces", async () => {
    const { engine, evidence } = engineFor(secretScanPolicy({ mode: "shadow" }));
    const match = await engine.matchGuardrail(
      "request",
      chatContext({ envelope: normalizeRequest("chat_completions", bodyWithProbeSecret()) }),
    );
    expect(match).toBeNull();
    expect(evidence.evaluations()[0]?.verdict).toBe("fail");
    expect(evidence.evaluations()[0]?.enforcementStatus).toBe("shadow_only");
  });
});

describe("enforcement selection across co-matching policies", () => {
  test("an unconditional block outranks an approval-gated deny", async () => {
    // Two policies match; the require_approval one sorts FIRST by policy_id.
    const approval = secretScanPolicy({
      policyId: "aaa-approval",
      onFail: [
        {
          kind: "require_approval",
          code: "guardrail_requires_approval",
          message: "needs approval",
        },
      ],
    });
    const hardBlock = secretScanPolicy({ policyId: "zzz-block" });
    const { policySourceFromRuntimes: build } = await import("../../src/guardrails/index.js");
    const { runtimeFor } = await import("./fixtures.js");
    const engine = new GuardrailEngine({
      policies: build([runtimeFor(approval), runtimeFor(hardBlock)]),
      evidence: new InMemoryGuardrailEvidenceSink(),
    });
    const match = await engine.matchGuardrail(
      "request",
      chatContext({ envelope: normalizeRequest("chat_completions", bodyWithProbeSecret()) }),
    );
    // rank(block) = 3 > rank(require_approval) = 2 — the hard block must win,
    // or a `Block` silently degrades into an approvable action.
    expect(match?.actionKind).toBe("block");
    expect(match?.ruleId).toBe("zzz-block");
  });
});
