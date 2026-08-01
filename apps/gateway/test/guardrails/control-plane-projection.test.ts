/**
 * The READ side of the `guardrail_policy` write half — and the boot-resilience
 * guard that made closing it safe.
 *
 * `apps/control-plane` now projects a created revision into
 * `guardrail_policy_revisions` and points `guardrail_policy_bindings` at it on
 * activate (`apps/control-plane/src/store/guardrail_registry.ts`, proved in
 * `apps/control-plane/test/guardrail-write-half.test.ts`). This file is the
 * other half of that join: given rows of exactly that shape, the data plane
 * must COMPILE them and BLOCK a matching request. The two apps are sibling
 * workspaces and neither depends on the other, so the join is by row content:
 * the control-plane suite asserts what it writes, this one asserts what the
 * request path does with it.
 *
 * The second and third blocks are the reason wave 16 refused to project at all.
 * `policySourceFromStore` compiles every active revision EAGERLY at
 * construction, and `loadGuardrailPolicyStore` validates every revision as it
 * seeds the store — so before this slice ONE bad row anywhere in the table took
 * the gateway's entire guardrail source down at boot, and with it every request
 * (`guardrailDepsFromEnv` lets the throw propagate, so the request answers 503).
 * Admission now keeps new bad rows out; these tests cover the rows that were
 * already there, and the class admission provably CANNOT catch:
 *
 *  - a revision that fails `validatePolicyRevision` — a legacy partial document;
 *  - a revision that VALIDATES but cannot BUILD in this environment, because a
 *    `fingerprint_secret_ref` resolves to nothing here. The control plane cannot
 *    see the gateway's secret bindings, so this class is unreachable from
 *    admission by construction and resilience is the only answer.
 *
 * "Fail that one policy CLOSED" is literal and is asserted: the broken policy is
 * NOT dropped from the source (dropping it would silently stop screening the
 * traffic it fences, which is fail-OPEN). It stays selected, and its check
 * raises a `DetectorError`, which the engine turns into `on_error` — block.
 */
import {
  DetectorError,
  type DetectorInput,
  type PolicyRevision,
  envelopeFromText,
  policyRevisionSchema,
} from "@ferrogate/guardrails";
import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  D1GuardrailPolicyStore,
  type GuardrailDatabase,
  InMemoryGuardrailPolicyStore,
  loadGuardrailPolicyStore,
  policySourceFromStore,
} from "../../src/guardrails/index.js";
import { FINGERPRINT_SECRET_REF, TEST_SECRETS } from "./fixtures.js";

const bindings = env as unknown as Record<string, unknown>;

function controlDb(): D1Database {
  const binding = bindings.CONTROL_DB as D1Database | undefined;
  if (binding === undefined) {
    throw new Error(
      "guardrail projection tests expect the `CONTROL_DB` binding (apps/gateway/wrangler.toml).",
    );
  }
  return binding;
}

// ---------------------------------------------------------------------------
// Rows in the exact shape `apps/control-plane` projects
// ---------------------------------------------------------------------------

/**
 * The revision document the control plane stores in `revision_json`, built the
 * way the admin API builds it: a complete `PolicyRevision` with a non-empty
 * `created_by`, parsed through the same schema both sides use.
 */
function projectedRevision(overrides: Record<string, unknown> = {}): PolicyRevision {
  return policyRevisionSchema.parse({
    policy_id: "gp_projected",
    revision: 1,
    name: "block launch codes",
    checks: [
      {
        id: "kw",
        enabled: true,
        stage: "request",
        sources: ["user"],
        detector: { kind: "local", keywords: ["launch codes"], regex: [], secret_patterns: [] },
      },
    ],
    on_pass: [{ kind: "allow" }],
    on_fail: [{ kind: "block", code: "guardrail_blocked", message: "blocked by policy" }],
    on_error: [{ kind: "block", code: "guardrail_unavailable", message: "detector unavailable" }],
    created_at_unix: 1,
    created_by: "static_operator",
    ...overrides,
  }) as PolicyRevision;
}

/** Insert a revision row with the control plane's statement, unvalidated. */
async function insertRevisionRow(
  policyId: string,
  revision: number,
  document: unknown,
): Promise<void> {
  await controlDb()
    .prepare(
      "INSERT INTO guardrail_policy_revisions " +
        "(policy_id, revision, immutable_id, created_at_unix, created_by, revision_json) " +
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(policyId, revision, `${policyId}@${revision}`, 1, "static_operator", JSON.stringify(document))
    .run();
}

async function insertBindingRow(policyId: string, activeRevision: number): Promise<void> {
  await controlDb()
    .prepare(
      "INSERT INTO guardrail_policy_bindings " +
        "(policy_id, active_revision, updated_at_unix, generation, binding_json) " +
        "VALUES (?1, ?2, ?3, 1, ?4)",
    )
    .bind(policyId, activeRevision, 1, JSON.stringify({ archived_revisions: [], updated_by: "op" }))
    .run();
}

async function resetPolicyTables(): Promise<void> {
  const db = controlDb();
  await db.batch([
    db.prepare("DELETE FROM guardrail_policy_bindings"),
    db.prepare("DELETE FROM guardrail_policy_revisions"),
  ]);
}

/**
 * The gateway's boot path, end to end: durable rows -> compiled source.
 *
 * Composed exactly as `src/guardrails/config.ts::guardrailDepsFromEnv` composes
 * it, INCLUDING the `failClosedPolicyIds` set — otherwise these tests would
 * prove a posture the production composition root does not have.
 */
async function bootSource(
  seed?: InMemoryGuardrailPolicyStore,
): Promise<ReturnType<typeof policySourceFromStore>> {
  const durable = new D1GuardrailPolicyStore(controlDb() as unknown as GuardrailDatabase);
  const durablePolicyIds = new Set<string>();
  const store = await loadGuardrailPolicyStore(durable, seed, {
    onDurablePolicy: (policyId) => durablePolicyIds.add(policyId),
  });
  return policySourceFromStore(
    store,
    { secrets: TEST_SECRETS },
    { failClosedPolicyIds: durablePolicyIds },
  );
}

const OFFENDING_TEXT = "here are the launch codes";

/**
 * A `DetectorInput` over one user segment — the same shape
 * `apps/gateway/src/guardrails/engine.ts` hands a compiled check.
 */
function detectorInput(text: string): DetectorInput {
  const envelope = envelopeFromText(
    "chat_completions",
    "request",
    "user",
    "messages[0].content",
    text,
  );
  return {
    protocol: envelope.protocol,
    stage: envelope.stage,
    tenant: { organization_id: "tenant_a" },
    text,
    segments: envelope.segments,
  };
}

beforeEach(resetPolicyTables);
afterEach(resetPolicyTables);

// ---------------------------------------------------------------------------
// 1. A projected revision is really enforced
// ---------------------------------------------------------------------------

describe("a control-plane-projected revision is compiled and enforced", () => {
  test("the active revision selects for a matching context and its check FAILS the text", async () => {
    await insertRevisionRow("gp_projected", 1, projectedRevision());
    await insertBindingRow("gp_projected", 1);

    const source = await bootSource();
    const selected = source.policiesFor({ organization_id: "tenant_a", model: "gpt-4o" });
    expect(selected).toHaveLength(1);
    expect(selected[0]?.revision.policy_id).toBe("gp_projected");

    const check = selected[0]?.checks[0];
    expect(check).toBeDefined();
    const result = await (check as NonNullable<typeof check>).detector.evaluate(
      detectorInput(OFFENDING_TEXT),
      Date.now() + 2000,
    );
    // Not "the row is present": the compiled detector actually refuses the text.
    expect(result.verdict).toBe("fail");
  });

  test("a revision with NO binding row is not enforced", async () => {
    await insertRevisionRow("gp_projected", 1, projectedRevision());
    const source = await bootSource();
    expect(source.policiesFor({ organization_id: "tenant_a" })).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 2. A pre-existing malformed row must not prevent boot
// ---------------------------------------------------------------------------

describe("a malformed pre-existing row fails ONE policy, never the boot", () => {
  test("a legacy partial revision document does not take the source down", async () => {
    // The literal shape wave 16 left in the document store: no name, no checks,
    // no actions, no created_by. `validatePolicyRevision` refuses it, which is
    // what used to throw out of `loadGuardrailPolicyStore`.
    await insertRevisionRow("gp_legacy", 1, { policy_id: "gp_legacy", revision: 1, detectors: [] });
    await insertBindingRow("gp_legacy", 1);
    await insertRevisionRow("gp_projected", 1, projectedRevision());
    await insertBindingRow("gp_projected", 1);

    const source = await bootSource();

    // The healthy policy still screens. Before the guard, this line was never
    // reached: the boot threw.
    const selected = source.policiesFor({ organization_id: "tenant_a" });
    expect(selected.map((runtime) => runtime.revision.policy_id)).toEqual(["gp_projected"]);
  });

  test("a revision whose secret ref does not resolve HERE fails that policy CLOSED", async () => {
    // Validates fine (the ref is non-empty), cannot BUILD (nothing resolves it
    // in this Worker's env). Admission in the control plane cannot see the
    // gateway's secret bindings, so this class is unreachable from there.
    await insertRevisionRow(
      "gp_unresolvable",
      1,
      projectedRevision({
        policy_id: "gp_unresolvable",
        checks: [
          {
            id: "presidio",
            enabled: true,
            stage: "request",
            sources: ["user"],
            detector: {
              kind: "presidio",
              endpoint: "https://presidio.guardrails.invalid-host.example",
              fingerprint_secret_ref: "env://NOT_BOUND_ANYWHERE",
            },
          },
        ],
      }),
    );
    await insertBindingRow("gp_unresolvable", 1);
    await insertRevisionRow("gp_projected", 1, projectedRevision());
    await insertBindingRow("gp_projected", 1);

    const source = await bootSource();
    const selected = source.policiesFor({ organization_id: "tenant_a" });

    // BOTH are present. Dropping the broken one would stop screening the
    // traffic it fences — fail OPEN — which is the wrong direction for a
    // guardrail.
    expect(selected.map((runtime) => runtime.revision.policy_id).sort()).toEqual([
      "gp_projected",
      "gp_unresolvable",
    ]);

    // The healthy one still works.
    const healthy = selected.find((runtime) => runtime.revision.policy_id === "gp_projected");
    const healthyResult = await (healthy as NonNullable<typeof healthy>).checks[0]?.detector.evaluate(
      detectorInput(OFFENDING_TEXT),
      Date.now() + 2000,
    );
    expect(healthyResult?.verdict).toBe("fail");

    // The broken one refuses to evaluate, so the engine takes `on_error`
    // (block) rather than passing the content through unscreened.
    const broken = selected.find((runtime) => runtime.revision.policy_id === "gp_unresolvable");
    const brokenCheck = (broken as NonNullable<typeof broken>).checks[0];
    expect(brokenCheck).toBeDefined();
    expect(brokenCheck?.enabled).toBe(true);
    await expect(
      (brokenCheck as NonNullable<typeof brokenCheck>).detector.evaluate(
        detectorInput("anything at all"),
        Date.now() + 2000,
      ),
    ).rejects.toBeInstanceOf(DetectorError);
  });

  test("a CONFIG-declared policy that cannot compile is STILL a hard boot failure", async () => {
    // The boundary of the guard, asserted directly. `GATEWAY_GUARDRAIL_POLICIES`
    // is this deployment's own configuration: an operator who mistypes a secret
    // ref there must be told at boot, not handed a policy that refuses every
    // request forever. Only rows that arrived from the durable control tables
    // are allowed to fail closed — see `PolicySourceOptions.failClosedPolicyIds`.
    const configSeed = new InMemoryGuardrailPolicyStore();
    configSeed.putRevision(
      projectedRevision({
        policy_id: "gp_from_config",
        checks: [
          {
            id: "presidio",
            enabled: true,
            stage: "request",
            sources: ["user"],
            detector: {
              kind: "presidio",
              endpoint: "https://presidio.guardrails.invalid-host.example",
              fingerprint_secret_ref: "env://NOT_BOUND_ANYWHERE",
            },
          },
        ],
      }),
    );
    expect(configSeed.activate("gp_from_config", 1, 0, "worker_var").ok).toBe(true);

    await expect(bootSource(configSeed)).rejects.toThrow(/did not resolve/);
  });

  test("a policy whose ref DOES resolve is unaffected by the guard", async () => {
    // The guard must not become a blanket catch that hides a working detector's
    // real compilation. This one resolves `FINGERPRINT_SECRET_REF` through
    // `TEST_SECRETS` and must compile for real.
    await insertRevisionRow(
      "gp_keyed",
      1,
      projectedRevision({
        policy_id: "gp_keyed",
        checks: [
          {
            id: "secrets",
            enabled: true,
            stage: "request",
            sources: ["user"],
            detector: {
              kind: "local",
              keywords: ["launch codes"],
              regex: [],
              secret_patterns: ["aws_access_key_id"],
              fingerprint_secret_ref: FINGERPRINT_SECRET_REF,
            },
          },
        ],
      }),
    );
    await insertBindingRow("gp_keyed", 1);

    const source = await bootSource();
    const selected = source.policiesFor({ organization_id: "tenant_a" });
    expect(selected).toHaveLength(1);
    const result = await (selected[0] as NonNullable<(typeof selected)[0]>).checks[0]?.detector.evaluate(
      detectorInput(OFFENDING_TEXT),
      Date.now() + 2000,
    );
    expect(result?.verdict).toBe("fail");
  });
});
