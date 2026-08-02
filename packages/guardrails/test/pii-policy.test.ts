/**
 * `kind: "pii"` as a POLICY (issue #680).
 *
 * A detector that only exists as a library class is not a product feature — an
 * operator reaches it through a signed policy revision or not at all. The cases
 * that matter here are the ones where the HOST cannot satisfy what the policy
 * asked for. Every one of them must RAISE, because the alternative is a
 * detector that builds weaker than requested and then answers `pass`, which an
 * operator reads as "screened and clean".
 */
import { describe, expect, test } from "vitest";
import {
  type DetectorDefinition,
  type DetectorInput,
  DetectorSecret,
  InMemoryPiiTokenVault,
  type WorkersAiClient,
  buildGuardrailDetector,
  detectorDefinitionSchema,
  normalizeRequest,
  validateDetectorDefinition,
} from "../src/index.js";

const CARD = "4111111111111111";
const FINGERPRINT_REF = "GUARDRAIL_FINGERPRINT_KEY";
const SECRETS = (ref: string): string | undefined =>
  ref === FINGERPRINT_REF ? "test-fingerprint-key" : undefined;

function definition(overrides: Record<string, unknown> = {}): DetectorDefinition {
  return detectorDefinitionSchema.parse({
    kind: "pii",
    fingerprint_secret_ref: FINGERPRINT_REF,
    ...overrides,
  }) as DetectorDefinition;
}

function chatInput(text: string): DetectorInput {
  const envelope = normalizeRequest("chat_completions", {
    messages: [{ role: "user", content: text }],
  });
  return {
    protocol: envelope.protocol,
    stage: envelope.stage,
    tenant: { organization_id: "org" },
    text: "",
    segments: envelope.segments,
  };
}

describe("pii detector definition", () => {
  test("defaults to the whole validated pack and irreversible masking", () => {
    const def = definition();
    expect(def).toMatchObject({ kind: "pii", redaction: "mask" });
    expect((def as { entities: string[] }).entities).toContain("credit_card");
    expect(() => validateDetectorDefinition(def)).not.toThrow();
  });

  test("an empty entity list is rejected — it would pass forever, finding nothing", () => {
    expect(() => validateDetectorDefinition(definition({ entities: [] }))).toThrowError(
      /entities must be non-empty/,
    );
  });

  test("keyed evidence is not optional at the policy layer either", () => {
    expect(() => detectorDefinitionSchema.parse({ kind: "pii", entities: ["email"] })).toThrow();
    expect(() =>
      validateDetectorDefinition(definition({ fingerprint_secret_ref: "  " })),
    ).toThrowError(/fingerprint_secret_ref/);
  });

  test("an unknown field is refused (the revision is a strict document)", () => {
    expect(() =>
      detectorDefinitionSchema.parse({
        kind: "pii",
        fingerprint_secret_ref: FINGERPRINT_REF,
        endpoint: "https://presidio.example.com",
      }),
    ).toThrow();
  });
});

describe("building a pii detector from a revision", () => {
  test("the compiled detector screens a real request body", async () => {
    const detector = buildGuardrailDetector("pii-check", definition(), ["user"], {
      secrets: SECRETS,
    });
    expect(detector).toBeDefined();
    const result = await (detector as NonNullable<typeof detector>).evaluate(
      chatInput(`charge ${CARD}`),
      Date.now() + 5_000,
    );
    expect(result.verdict).toBe("fail");
    expect(result.findings.map((f) => f.category)).toContain("pii.credit_card");
    expect(result.patches[0]?.replacement).toBe("[REDACTED:CREDIT_CARD]");
  });

  test("an unresolvable fingerprint ref is a build error, never an unkeyed detector", () => {
    expect(() => buildGuardrailDetector("pii-check", definition(), ["user"], {})).toThrow();
  });

  test("REVERSIBLE redaction with no vault refuses to build, rather than becoming irreversible", () => {
    expect(() =>
      buildGuardrailDetector("pii-check", definition({ redaction: "tokenize" }), ["user"], {
        secrets: SECRETS,
      }),
    ).toThrowError(/reversible \(tokenize\) redaction but no token vault/);
  });

  test("with a vault the same revision builds and the redaction really is reversible", async () => {
    const vault = new InMemoryPiiTokenVault();
    const detector = buildGuardrailDetector(
      "pii-check",
      definition({ redaction: "tokenize" }),
      ["user"],
      { secrets: SECRETS, piiVault: vault },
    );
    const result = await (detector as NonNullable<typeof detector>).evaluate(
      chatInput(`charge ${CARD}`),
      Date.now() + 5_000,
    );
    const replacement = result.patches[0]?.replacement as string;
    expect(replacement).toMatch(/^\[CREDIT_CARD:tok_[0-9a-f]{24}\]$/);
    expect(vault.restore(replacement)).toBe(CARD);
  });

  test("an AI stage with no Workers AI transport refuses to build", () => {
    expect(() =>
      buildGuardrailDetector("pii-check", definition({ ai: { entities: ["person"] } }), ["user"], {
        secrets: SECRETS,
      }),
    ).toThrowError(/Workers AI stage but no Workers AI transport/);
  });

  test("with a transport the AI stage is wired and declared on the descriptor", () => {
    const client: WorkersAiClient = { run: async () => ({ response: '{"entities":[]}' }) };
    const detector = buildGuardrailDetector(
      "pii-check",
      definition({ ai: { entities: ["person"], timeout_ms: 500 } }),
      ["user"],
      { secrets: SECRETS, workersAiClient: client },
    );
    expect(detector?.descriptor().data_residency).toBe("provider_saas");
    expect(detector?.descriptor().supports_transform).toBe(true);
  });

  test("the secret never reaches the detector's serialized surface", () => {
    const detector = buildGuardrailDetector("pii-check", definition(), ["user"], {
      secrets: SECRETS,
    });
    expect(JSON.stringify(detector?.descriptor())).not.toContain("test-fingerprint-key");
    expect(String(DetectorSecret.new("test-fingerprint-key"))).toBe("<redacted>");
  });
});
