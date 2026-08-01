/**
 * **ONE ACTIVATION, EVERY DOOR** — the fleet effect of
 * `POST /admin/v1/guardrail-policies/{policy_id}/activate`.
 * (`docs/rewrite/FLEET-CONSISTENCY.md` finding **FC-3**.)
 *
 * ## Why this file exists when `test/guardrails.test.ts` is already green
 *
 * That suite proves the MCP tool chokepoint really calls a real detector on
 * both stages, and that the port is really mounted. **It cannot fail for the
 * defect an operator actually cares about**, because it drives the detector
 * from `FG_DEV_MCP_GUARDRAILS` — a deploy-time var committed as `""`, which
 * parses to `{}`, which matches nothing, which allows everything. The question
 * it never asks is the fleet one:
 *
 * > An operator activates a guardrail policy. Does it reach the surface the
 * > payload was moved to?
 *
 * Before this file the answer was no, and every per-Worker suite was green
 * while it was no. `apps/gateway` merged the durable
 * `guardrail_policy_revisions` + `guardrail_policy_bindings` rows into its
 * detector source; `apps/mcp` and `apps/agent-runtime` did not read those rows
 * at all. That is the exact shape of the two bypasses this project has already
 * shipped — a control that is DURABLE on one Worker and VAR-ONLY on another.
 *
 * So the assertions below are deliberately written as ONE path: write the
 * revision and flip the binding through the CONTROL PLANE's own writer, then
 * require the GATEWAY's own durable reader, the DEPLOYED MCP Worker and
 * AGENT-RUNTIME's real screening function to agree about it — inside a single
 * `it()`, so a regression on any side fails the same test rather than a
 * different app's suite six minutes later.
 *
 * ## How three Workers are reached from one test
 *
 * The five Workers are separately bundled and no app may import another's
 * module graph — that coupling is what `wrangler deploy` would reject. This
 * file is a TEST, not a bundle, and it reaches each side differently on
 * purpose:
 *
 *  - **THE ACTIVATION** is `apps/control-plane`'s REAL write path,
 *    `projectGuardrailRevision` + `projectGuardrailActivation`
 *    (`src/store/guardrail_registry.ts`) — the functions
 *    `POST /admin/v1/guardrail-policies` and `…/activate` call, generation-
 *    guarded CAS included. Not hand-written SQL: hand-written SQL would keep
 *    passing after the control plane started writing somewhere else.
 *  - **THE GATEWAY DOOR** is `apps/gateway`'s REAL durable reader,
 *    `D1GuardrailPolicyStore` + `loadGuardrailPolicyStore` +
 *    `policySourceFromStore`, invoked against the SAME `env.DB` handle — the
 *    code path `guardrailDepsFromEnv` runs on that Worker's boot.
 *  - **THE MCP DOOR** is behavioural and end to end: `SELF.fetch` into the
 *    deployed `src/worker.ts` of THIS Worker over JSON-RPC `tools/call`, with
 *    `FG_DEV_MCP_GUARDRAILS` pinned EMPTY for the whole file so nothing here
 *    can be explained by the var.
 *  - **THE A2A DOOR** is `apps/agent-runtime`'s REAL screening function,
 *    `screenA2aAgainstDurablePolicies` (`src/guardrails.ts`), against the same
 *    handle. Its BEHAVIOURAL half — the deployed agent-runtime Worker refusing
 *    `message:send` and cutting `message:stream` mid-flight — is
 *    `apps/agent-runtime/test/durable/guardrail-policy-activation.spec.ts`,
 *    which runs in that app's durable harness where `CONTROL_DB` is bound.
 *
 * The two cross-app imports are only sound because both modules are LEAVES: D1
 * plus `@ferrogate/guardrails`, no Hono, no Worker entry, no route. That is
 * asserted off the files' own source text below rather than trusted to this
 * docblock, exactly as `apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts`
 * asserts its own.
 *
 * ## The two scope classes, and why there are two policies
 *
 * `scopeMatches` (a verbatim port of the Rust) requires a policy's
 * `managed_action` selector and the request's managed-action context to be BOTH
 * present or BOTH absent. That is not an artefact of the port: Rust's MCP tool
 * guardrail passes `managed_action: Some(ManagedActionContext { class: Mcp, … })`
 * (`server/managed_action_guardrail.rs:148`) while its A2A ingress passes
 * `managed_action: None` (`server/local.rs:9993`). A model-content policy and a
 * managed-action policy are genuinely different scopes, and asserting that one
 * revision covers both would be asserting behaviour Rust never had.
 *
 * FC-3 was never "one scope should cover everything". It was that **an
 * activated revision reached one Worker and no other.** Each policy below is
 * activated ONCE and required to be live on EVERY Worker that enforces its
 * scope.
 */
import { SELF, applyD1Migrations, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  GUARDRAIL_BINDING_LIST_SQL,
  GUARDRAIL_BINDING_POINTER_SQL,
  GUARDRAIL_BINDING_TABLE,
  GUARDRAIL_REVISION_LIST_ALL_SQL,
  GUARDRAIL_REVISION_TABLE,
  type PolicySelectionContext,
  type PolicyRevision,
  envelopeFromText,
  envelopeManagedAction,
  flattenedText,
} from "@ferrogate/guardrails";

import {
  A2A_GUARDRAIL_BINDING_SQL,
  A2A_GUARDRAIL_POINTER_SQL,
  A2A_GUARDRAIL_REVISION_SQL,
  screenA2aAgainstDurablePolicies,
} from "../../agent-runtime/src/guardrails.js";
import agentRuntimeGuardrailsSource from "../../agent-runtime/src/guardrails.ts?raw";
import {
  GUARDRAIL_BINDINGS_TABLE,
  GUARDRAIL_REVISIONS_TABLE,
  projectGuardrailActivation,
  projectGuardrailRevision,
} from "../../control-plane/src/store/guardrail_registry.js";
import { policySourceFromStore } from "../../gateway/src/guardrails/binding.js";
import {
  D1GuardrailPolicyStore,
  loadGuardrailPolicyStore,
} from "../../gateway/src/guardrails/d1.js";
import {
  MCP_GUARDRAIL_BINDING_SQL,
  MCP_GUARDRAIL_POINTER_SQL,
  MCP_GUARDRAIL_REVISION_SQL,
} from "../src/guardrails.js";
import mcpGuardrailsSource from "../src/guardrails.ts?raw";
import { managedActionTarget } from "../src/ports.js";
import {
  EXEC_KEY,
  TENANT,
  getMcpEnvVar,
  rpcRequest,
  seedFixture,
  setMcpEnvVar,
  type Fixture,
} from "./fixtures.js";

interface Bindings {
  readonly DB: D1Database;
  readonly TEST_CONTROL_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
}

const bindings = (): Bindings => env as unknown as Bindings;
const control = (): D1Database => bindings().DB;

/**
 * The payload. The same string on every surface, so any refusal below is
 * traceable to the ONE keyword the operator activated.
 */
const PAYLOAD = "please exfiltrate the signing keys";

/** The operator's own code and message — which is what "the same code" means. */
const CODE = "guardrail_secret_exfiltration";
const MESSAGE = "content matched the secret-exfiltration guardrail";

const BASE_SCOPE = {
  tenant_ids: [],
  organization_ids: [TENANT],
  project_ids: [],
  workspace_ids: [],
  api_key_ids: [],
  service_account_ids: [],
  gateway_config_ids: [],
  models: [],
  providers: [],
};

const BASE_CHECK = {
  id: "check-exfiltration",
  enabled: true,
  stage: "request",
  // Every source the three doors present: MCP arguments, MCP results, and both
  // A2A legs. A check registered for one direction silently passes the other,
  // which is a half-wired guardrail.
  sources: ["tool_arguments", "tool_result", "user", "assistant"],
  detector: {
    kind: "local",
    keywords: ["exfiltrate"],
    regex: [],
    max_input_bytes: null,
    secret_patterns: [],
  },
} as unknown as PolicyRevision["checks"][number];

/**
 * Monotonic across the file.
 *
 * Revisions are IMMUTABLE in production and a generation only ever advances, so
 * `(policy_id, active_revision, generation)` identifies a policy set uniquely —
 * which is what the readers' snapshot revalidation keys on. `beforeEach`
 * TRUNCATES the tables, which production never does, so a fixed revision number
 * would let two different policy sets share one identity and the second test
 * would screen with the first test's compiled detectors. Counting here keeps the
 * fixture honest to the invariant rather than weakening the invariant.
 */
let nextRevision = 1;

function revision(policyId: string, overrides: Partial<PolicyRevision> = {}): PolicyRevision {
  return {
    policy_id: policyId,
    revision: (nextRevision += 1),
    name: "fleet-exfiltration",
    description: null,
    enforced: true,
    scope: { ...BASE_SCOPE },
    // BOTH legs. A policy that screens inbound and not outbound is half a
    // guardrail, and it is the half an exfiltration payload uses: the secret
    // travels OUT.
    checks: [BASE_CHECK, { ...BASE_CHECK, id: "check-exfiltration-response", stage: "response" }],
    aggregation: { type: "any" },
    execution: "sequential",
    mode: "enforce",
    streaming: "buffer_and_enforce",
    on_pass: [{ kind: "allow" }],
    on_fail: [{ kind: "block", code: CODE, message: MESSAGE }],
    // FAIL CLOSED on a detector that could not run — Rust's `provider_on_error`
    // default is `Block`.
    on_error: [
      { kind: "block", code: "guardrail_provider_unavailable", message: "detector unavailable" },
    ],
    deadline_ms: 2_000,
    created_at_unix: 0,
    created_by: "operator",
    ...overrides,
  } as PolicyRevision;
}

/** A MANAGED-ACTION policy: the MCP `tools/call` scope class. */
function managedActionPolicy(overrides: Partial<PolicyRevision> = {}): PolicyRevision {
  const base = revision("policy-fleet-managed-action", overrides);
  return {
    ...base,
    scope: { ...base.scope, managed_action: { classes: ["mcp"], targets: [] } },
  };
}

/** A MODEL-CONTENT policy: the gateway chat / A2A scope class. */
function modelContentPolicy(overrides: Partial<PolicyRevision> = {}): PolicyRevision {
  return revision("policy-fleet-model-content", overrides);
}

/** `POST /admin/v1/guardrail-policies` + `…/activate`, through the real writer. */
async function activateThroughControlPlane(document: PolicyRevision): Promise<void> {
  await projectGuardrailRevision(control(), document, 0);
  const outcome = await projectGuardrailActivation(
    control(),
    document.policy_id,
    document.revision,
    "operator",
    0,
  );
  expect(outcome, "the control-plane CAS must commit the activation").toMatchObject({ ok: true });
}

/**
 * What the GATEWAY compiles out of the same rows, for a given selection.
 *
 * The store is CONSTRUCTED rather than resolved with `fromEnv` because the
 * binding NAMES differ by Worker — the gateway calls the control database
 * `CONTROL_DB`, this Worker calls it `DB` — and that difference is cosmetic:
 * both point at `database_name = "ferrogate-control"`. What must not differ,
 * and what this file asserts, is the TABLES and the answer.
 */
async function gatewayActivatedCodes(selection: PolicySelectionContext): Promise<string[]> {
  const store = await loadGuardrailPolicyStore(new D1GuardrailPolicyStore(control()));
  return policySourceFromStore(store)
    .policiesFor(selection)
    .flatMap((runtime) => runtime.revision.on_fail.map((action) => action.code ?? ""));
}

const call = (args: unknown, tool = "srv-echo"): Request =>
  rpcRequest(
    { jsonrpc: "2.0", id: 11, method: "tools/call", params: { name: tool, arguments: args } },
    { key: EXEC_KEY },
  );

async function rpcError(res: Response): Promise<{ code: number; message: string }> {
  expect(res.status).toBe(200);
  const body = (await res.json()) as { error?: { code: number; message: string } };
  expect(body.error, "expected a JSON-RPC error object").toBeDefined();
  return body.error as { code: number; message: string };
}

function a2a(stage: "request" | "response", text: string, tenantId = TENANT): Promise<unknown> {
  return screenA2aAgainstDurablePolicies(
    { CONTROL_DB: control() },
    { stage, tenantId, agentId: "planner", streaming: false, text },
  );
}

let fixture: Fixture;
const originalVar = getMcpEnvVar("FG_DEV_MCP_GUARDRAILS");

beforeAll(async () => {
  await applyD1Migrations(control(), bindings().TEST_CONTROL_D1_SCHEMA);
});

beforeEach(async () => {
  fixture = seedFixture();
  // THE VAR IS PINNED EMPTY FOR THE WHOLE FILE. Anything refused below was
  // refused because of a durable ACTIVATED REVISION and nothing else — without
  // this line every assertion here could be satisfied by the dev var, which is
  // precisely the thing FC-3 says is not the enforcement authority.
  setMcpEnvVar("FG_DEV_MCP_GUARDRAILS", "");
  await control().prepare(`DELETE FROM ${GUARDRAIL_BINDINGS_TABLE}`).run();
  await control().prepare(`DELETE FROM ${GUARDRAIL_REVISIONS_TABLE}`).run();
});

afterEach(() => {
  // Leaving the var pinned would silently disarm `test/guardrails.test.ts` if
  // the file ordering ever changed.
  setMcpEnvVar("FG_DEV_MCP_GUARDRAILS", originalVar);
});

describe("FC-3 — one activation, every door", () => {
  it("CONTROL: with nothing activated the same payload passes every door", async () => {
    // Without this control the refusals below would prove nothing: a Worker
    // that refused everything would also pass them.
    const res = await SELF.fetch(call({ q: PAYLOAD }));
    expect(res.status).toBe(200);
    expect(fixture.calls, "the tool must really have dispatched").toHaveLength(1);
    expect(await gatewayActivatedCodes({ organization_id: TENANT })).toEqual([]);
    expect(await a2a("request", PAYLOAD)).toEqual({ outcome: "allow" });
  });

  it("ONE managed-action activation shuts the MCP door AND is live on the gateway, same code", async () => {
    await activateThroughControlPlane(managedActionPolicy());

    // ---- the GATEWAY's own durable reader, over the same rows -------------
    const gatewayCodes = await gatewayActivatedCodes({
      organization_id: TENANT,
      managed_action: { class: "mcp", target: managedActionTarget("srv", "echo") },
    });
    expect(gatewayCodes, "the gateway must hold the activated revision").toContain(CODE);

    // ---- the DEPLOYED MCP Worker, over JSON-RPC ---------------------------
    const error = await rpcError(await SELF.fetch(call({ q: PAYLOAD })));
    expect(error.code).toBe(-32001);
    expect(
      error.message,
      "MCP must refuse with the code the operator activated, not a private one",
    ).toContain(CODE);
    // The ORDERING assertion: a build that screened after the dispatch would
    // still answer an error while the bytes had already left.
    expect(fixture.calls, "the payload must never reach the upstream").toHaveLength(0);
    // Never echo what matched.
    expect(error.message).not.toContain("signing keys");
  });

  it("the SAME activation screens a matching tool RESULT, not just the arguments", async () => {
    // A policy that reaches arguments and not results is half a guardrail, and
    // it is the half an exfiltration payload uses: the secret travels OUT.
    await activateThroughControlPlane(
      managedActionPolicy({ checks: [{ ...BASE_CHECK, id: "check-result", stage: "response" }] }),
    );
    const error = await rpcError(await SELF.fetch(call({ q: "exfiltrate" })));
    expect(error.code).toBe(-32001);
    expect(error.message).toContain(CODE);
  });

  it("ONE model-content activation shuts the A2A door AND is live on the gateway, same code", async () => {
    await activateThroughControlPlane(modelContentPolicy());

    const gatewayCodes = await gatewayActivatedCodes({ organization_id: TENANT });
    expect(gatewayCodes, "the gateway must hold the activated revision").toContain(CODE);

    expect(await a2a("request", PAYLOAD)).toMatchObject({
      outcome: "deny",
      code: CODE,
      message: MESSAGE,
    });
    // The RESPONSE leg too: a policy that screens inbound and not outbound is
    // the half an exfiltration payload uses.
    expect(await a2a("response", PAYLOAD)).toMatchObject({ outcome: "deny", code: CODE });
  });

  it("clean content under the SAME activation still passes every door", async () => {
    // The other half of every pair above: the guardrail must not refuse
    // everything, which would satisfy the refusal assertions vacuously.
    await activateThroughControlPlane(managedActionPolicy());
    await activateThroughControlPlane(modelContentPolicy());
    const res = await SELF.fetch(call({ q: "hello there" }));
    expect(res.status).toBe(200);
    expect(fixture.calls).toHaveLength(1);
    expect(await a2a("request", "hello there")).toEqual({ outcome: "allow" });
  });

  it("a MODEL-CONTENT policy does not police a MANAGED ACTION", async () => {
    // Rust parity, pinned so nobody "fixes" the two scope classes into one and
    // silently changes behaviour Rust never had (`scopeMatches`).
    await activateThroughControlPlane(modelContentPolicy());
    const res = await SELF.fetch(call({ q: PAYLOAD }));
    expect(res.status).toBe(200);
    expect(fixture.calls).toHaveLength(1);
  });

  it("a MANAGED-ACTION policy does not police model content", async () => {
    await activateThroughControlPlane(managedActionPolicy());
    expect(await a2a("request", PAYLOAD)).toEqual({ outcome: "allow" });
  });

  it("a tenant the policy does not scope is untouched by the activation", async () => {
    // The fence. A guardrail that policed every tenant would satisfy every
    // refusal assertion above and be a different, worse bug.
    await activateThroughControlPlane(modelContentPolicy());
    expect(await a2a("request", PAYLOAD, "tenant-not-scoped")).toEqual({ outcome: "allow" });
  });
});

describe("FC-3 — the properties that make the shared reader trustworthy", () => {
  it("the cross-app imports stay LEAVES", () => {
    // If either screening module grew a Hono/route/env import this file would
    // quietly pull one Worker's module graph into another's test bundle.
    // Asserted off the source text, not the docblock.
    for (const [label, source] of [
      ["agent-runtime", agentRuntimeGuardrailsSource],
      ["mcp", mcpGuardrailsSource],
    ] as const) {
      const specifiers = [...source.matchAll(/from\s+"([^"]+)";/g)].map((match) => match[1] ?? "");
      expect(specifiers.length, `${label}: the file must import something`).toBeGreaterThan(0);
      for (const specifier of specifiers) {
        expect(
          specifier === "@ferrogate/guardrails" || specifier === "./ports.js",
          `${label}: unexpected import ${specifier} — the fleet reader must stay a leaf`,
        ).toBe(true);
      }
    }
  });

  it("every screening Worker names the SAME two control tables", () => {
    // The search key both shipped defects were found with: a control resolved
    // from a different source of truth on a different Worker. Three names, one
    // place.
    expect(GUARDRAIL_REVISION_TABLE).toBe(GUARDRAIL_REVISIONS_TABLE);
    expect(GUARDRAIL_BINDING_TABLE).toBe(GUARDRAIL_BINDINGS_TABLE);
  });

  it("every screening Worker issues the SAME statements, character for character", () => {
    // The repo restates cross-Worker SQL per Worker on purpose — an operator
    // grepping for a table must find every reader, and the fleet matrix derives
    // each control's source-of-truth class from the literals in each Worker's
    // own `src/`. This is the price of that convention, paid: the restatements
    // are pinned against the statements actually executed.
    expect(MCP_GUARDRAIL_REVISION_SQL).toBe(GUARDRAIL_REVISION_LIST_ALL_SQL);
    expect(A2A_GUARDRAIL_REVISION_SQL).toBe(GUARDRAIL_REVISION_LIST_ALL_SQL);
    expect(MCP_GUARDRAIL_BINDING_SQL).toBe(GUARDRAIL_BINDING_LIST_SQL);
    expect(A2A_GUARDRAIL_BINDING_SQL).toBe(GUARDRAIL_BINDING_LIST_SQL);
    expect(MCP_GUARDRAIL_POINTER_SQL).toBe(GUARDRAIL_BINDING_POINTER_SQL);
    expect(A2A_GUARDRAIL_POINTER_SQL).toBe(GUARDRAIL_BINDING_POINTER_SQL);
    // And the gateway reads the same rows, through its own constants.
    expect(GUARDRAIL_REVISION_LIST_ALL_SQL).toContain(GUARDRAIL_REVISIONS_TABLE);
    expect(GUARDRAIL_BINDING_LIST_SQL).toContain(GUARDRAIL_BINDINGS_TABLE);
  });

  it("a detector that cannot BUILD fails the policy CLOSED, not open", async () => {
    // Rust: DetectorError -> CheckOutcome::Error -> AggregateOutcome::Error ->
    // `on_error`, whose `provider_on_error` default is Block. Getting this
    // backwards is itself the vulnerability, so it is pinned rather than
    // assumed.
    //
    // The mechanism is the one the durable path really meets: the control
    // plane can only check that a `fingerprint_secret_ref` is non-empty — it
    // cannot see another Worker's secret bindings — so a revision whose ref
    // resolves to nothing HERE is admissible there. Dropping it would leave the
    // traffic it fences screened by nothing at all, silently.
    await activateThroughControlPlane(
      modelContentPolicy({
        checks: [
          {
            ...BASE_CHECK,
            detector: {
              kind: "local",
              keywords: ["exfiltrate"],
              regex: [],
              max_input_bytes: null,
              secret_patterns: ["aws_access_key_id"],
              fingerprint_secret_ref: "env://A_SECRET_THIS_WORKER_DOES_NOT_BIND",
            },
          },
        ] as unknown as PolicyRevision["checks"],
      }),
    );
    expect(
      await a2a("request", "entirely harmless"),
      "a policy that could not be compiled has cleared nothing",
    ).toMatchObject({ outcome: "deny", code: "guardrail_provider_unavailable" });
  });

  it("SHADOW mode observes and never enforces", async () => {
    await activateThroughControlPlane(modelContentPolicy({ mode: "shadow" }));
    expect(await a2a("request", PAYLOAD)).toEqual({ outcome: "allow" });
  });

  it("a binding that points at a revision the table does not hold activates NOTHING", async () => {
    // Never faked: activating a policy whose text is unknown would tell a
    // caller it was screened by rules nobody can read back.
    const outcome = await projectGuardrailActivation(control(), "policy-ghost", 7, "operator", 0);
    expect(outcome).toMatchObject({ ok: true });
    expect(await a2a("request", PAYLOAD)).toEqual({ outcome: "allow" });
    expect(await gatewayActivatedCodes({ organization_id: TENANT })).toEqual([]);
  });

  it("the envelope a durable policy screens is the one each surface builds", () => {
    // Guards the join between a policy's declared `sources` and the envelope
    // each door constructs: a check written for `tool_arguments` that met a
    // `user` segment would silently pass.
    expect(envelopeManagedAction("request", "managed_action:x", PAYLOAD).segments[0]?.source).toBe(
      "tool_arguments",
    );
    expect(envelopeManagedAction("response", "managed_action:x", PAYLOAD).segments[0]?.source).toBe(
      "tool_result",
    );
    const a2aEnvelope = envelopeFromText("a2a", "request", "user", "a2a:planner/message", PAYLOAD);
    expect(a2aEnvelope.segments[0]?.source).toBe("user");
    expect(flattenedText(a2aEnvelope)).toBe(PAYLOAD);
  });
});
