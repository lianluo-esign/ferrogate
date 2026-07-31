/**
 * EVIDENCE NON-PERSISTENCE — the crate's headline security invariant.
 *
 * `docs/legacy/inventory-policy-core.md`, appendix §1/§2:
 *   "`matched_text` is never persisted — only `fingerprint` goes to durable
 *    evidence; conformance harness asserts the raw value never appears in
 *    serialized results."
 *   "HMAC-keyed, non-reversible fingerprints (`hmac-sha256:<hex>`) for all
 *    secret/PII evidence."
 *
 * These tests scan the FULL serialized evidence blob for the flagged value.
 * That is the only assertion shape that actually holds the invariant: checking
 * a named field would pass while the value leaked through some other one.
 */
import { normalizeRequest } from "@ferrogate/guardrails";
import { describe, expect, test } from "vitest";
import {
  GuardrailEngine,
  InMemoryGuardrailEvidenceSink,
  envelopeFingerprint,
  sanitizedEvidenceToken,
} from "../../src/guardrails/index.js";
import {
  EVIDENCE_HMAC_KEY,
  PROBE_SECRET,
  bodyWithProbeSecret,
  chatContext,
  secretScanPolicy,
  sourceFor,
} from "./fixtures.js";

async function evidenceForBlockedRequest(
  hmacKey: Uint8Array | "none" = EVIDENCE_HMAC_KEY,
): Promise<InMemoryGuardrailEvidenceSink> {
  const evidence = new InMemoryGuardrailEvidenceSink();
  const engine = new GuardrailEngine({
    policies: sourceFor(secretScanPolicy()),
    evidence,
    ...(hmacKey !== "none" ? { evidenceHmacKey: hmacKey } : {}),
  });
  await engine.matchGuardrail(
    "request",
    chatContext({ envelope: normalizeRequest("chat_completions", bodyWithProbeSecret()) }),
  );
  return evidence;
}

describe("matched content is never persisted", () => {
  test("the flagged secret appears nowhere in the serialized evidence", async () => {
    const evidence = await evidenceForBlockedRequest();
    // Sanity: the evaluation really did fire, so the assertion is not vacuous.
    expect(evidence.evaluations()).toHaveLength(1);
    expect(evidence.evaluations()[0]?.verdict).toBe("fail");
    expect(evidence.evaluations()[0]?.findingCount).toBeGreaterThan(0);

    expect(evidence.serialized()).not.toContain(PROBE_SECRET);
  });

  test("the prompt text appears nowhere in the serialized evidence", async () => {
    const evidence = new InMemoryGuardrailEvidenceSink();
    const engine = new GuardrailEngine({
      policies: sourceFor(secretScanPolicy()),
      evidence,
      evidenceHmacKey: EVIDENCE_HMAC_KEY,
    });
    await engine.matchGuardrail(
      "request",
      chatContext({
        envelope: normalizeRequest("chat_completions", {
          model: "gpt-4o",
          messages: [
            { role: "system", content: "you are a helpful assistant" },
            { role: "user", content: `my patient id is 12345 and ${PROBE_SECRET}` },
          ],
        }),
      }),
    );
    const blob = evidence.serialized();
    expect(blob).not.toContain(PROBE_SECRET);
    expect(blob).not.toContain("patient id");
    expect(blob).not.toContain("helpful assistant");
    expect(blob).not.toContain("12345");
  });

  test("only category COUNTS survive, not the matched values", async () => {
    const evidence = await evidenceForBlockedRequest();
    const row = evidence.evaluations()[0];
    expect(row?.findingCategoryCounts).toEqual({ "secret.aws_access_key_id": 1 });
    expect(row?.findingCount).toBe(1);
  });
});

describe("keyed, non-reversible input fingerprints", () => {
  test("the input fingerprint is an hmac-sha256 hex digest", async () => {
    const evidence = await evidenceForBlockedRequest();
    expect(evidence.evaluations()[0]?.inputFingerprint).toMatch(/^hmac-sha256:[0-9a-f]{64}$/);
  });

  test("with no key configured the fingerprint is explicitly unavailable", async () => {
    // The Rust returned the literal `hmac-sha256:unavailable` rather than an
    // UNKEYED digest — an unkeyed sha256 of a short prompt is reversible.
    const evidence = await evidenceForBlockedRequest("none");
    expect(evidence.evaluations()[0]?.inputFingerprint).toBe("hmac-sha256:unavailable");
  });

  test("the fingerprint is deterministic and content-sensitive", () => {
    const one = chatContext({
      envelope: normalizeRequest("chat_completions", {
        messages: [{ role: "user", content: "a" }],
      }),
    });
    const two = chatContext({
      envelope: normalizeRequest("chat_completions", {
        messages: [{ role: "user", content: "b" }],
      }),
    });
    expect(envelopeFingerprint(one, EVIDENCE_HMAC_KEY)).toBe(
      envelopeFingerprint(one, EVIDENCE_HMAC_KEY),
    );
    expect(envelopeFingerprint(one, EVIDENCE_HMAC_KEY)).not.toBe(
      envelopeFingerprint(two, EVIDENCE_HMAC_KEY),
    );
  });

  test("a different key yields a different fingerprint for the same content", () => {
    const context = chatContext({
      envelope: normalizeRequest("chat_completions", {
        messages: [{ role: "user", content: "a" }],
      }),
    });
    expect(envelopeFingerprint(context, EVIDENCE_HMAC_KEY)).not.toBe(
      envelopeFingerprint(context, new TextEncoder().encode("other-key")),
    );
  });

  test("tenants are separated in the fingerprint keyspace", () => {
    const envelope = normalizeRequest("chat_completions", {
      messages: [{ role: "user", content: "a" }],
    });
    const a = envelopeFingerprint(
      { envelope, tenant: { organizationId: "tenant_a" } },
      EVIDENCE_HMAC_KEY,
    );
    const b = envelopeFingerprint(
      { envelope, tenant: { organizationId: "tenant_b" } },
      EVIDENCE_HMAC_KEY,
    );
    expect(a).not.toBe(b);
  });
});

describe("evidence token sanitization", () => {
  test("a hostile category name cannot smuggle content into evidence", () => {
    expect(sanitizedEvidenceToken("secret.aws_access_key_id", "x")).toBe(
      "secret.aws_access_key_id",
    );
    expect(sanitizedEvidenceToken(`leaked ${PROBE_SECRET}`, "uncategorized")).toBe("uncategorized");
    expect(sanitizedEvidenceToken("a".repeat(65), "uncategorized")).toBe("uncategorized");
    expect(sanitizedEvidenceToken("  ", "uncategorized")).toBe("uncategorized");
  });

  test("a detector reporting a content-bearing category is sanitized end to end", async () => {
    const evidence = new InMemoryGuardrailEvidenceSink();
    const engine = new GuardrailEngine({
      policies: sourceFor(secretScanPolicy(), {
        deterministic: {
          descriptor: () => ({
            id: "hostile",
            version: `v1 ${PROBE_SECRET}`,
            supports_request: true,
            supports_response: true,
            supports_transform: false,
            supported_sources: ["user"],
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
              verdict: "fail" as const,
              findings: [
                {
                  category: `exfil ${PROBE_SECRET}`,
                  severity: "high" as const,
                  matched_text: PROBE_SECRET,
                  attributes: {},
                },
              ],
              patches: [],
              detector_version: `sneaky ${PROBE_SECRET}`,
            }),
        },
      }),
      evidence,
      evidenceHmacKey: EVIDENCE_HMAC_KEY,
    });
    await engine.matchGuardrail(
      "request",
      chatContext({ envelope: normalizeRequest("chat_completions", bodyWithProbeSecret()) }),
    );

    // Both the category AND the detector_version carried the secret; neither
    // reaches durable evidence, and `matched_text` is dropped outright.
    expect(evidence.serialized()).not.toContain(PROBE_SECRET);
    expect(evidence.evaluations()[0]?.findingCategoryCounts).toEqual({ uncategorized: 1 });
    expect(evidence.checks()[0]?.detectorVersion).toBe("unknown");
  });
});

describe("evidence capacity", () => {
  test("a full sink refuses rather than dropping evidence silently", () => {
    const sink = new InMemoryGuardrailEvidenceSink(1);
    const row = (id: string) =>
      ({
        id,
        requestId: "fg-1",
        tenant: {},
        scopeType: "platform",
        target: "m/p",
        protocol: "chat_completions" as const,
        stage: "request" as const,
        mode: "enforce",
        policyId: "p",
        policyRevision: 1,
        verdict: "pass",
        action: "allow",
        enforcementStatus: "enforced",
        latencyMs: 0,
        findingCategoryCounts: {},
        findingCount: 0,
        transformed: false,
        inputFingerprint: "hmac-sha256:unavailable",
        occurredAtUnix: 0,
      }) as const;
    expect(sink.append(row("a"), [])).toBe(true);
    expect(sink.append(row("b"), [])).toBe(false);
    // ...but the SAME id is an upsert, not a new row (streaming screens per frame).
    expect(sink.append(row("a"), [])).toBe(true);
    expect(sink.evaluations()).toHaveLength(1);
  });
});
