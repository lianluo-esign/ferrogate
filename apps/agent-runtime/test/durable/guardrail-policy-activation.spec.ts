/**
 * **AN ACTIVATED GUARDRAIL POLICY MUST REACH THE A2A DOOR.**
 * (`docs/rewrite/FLEET-CONSISTENCY.md` finding **FC-3**.)
 *
 * ## The half every other suite was blind to
 *
 * `apps/gateway` merges the durable `guardrail_policy_revisions` +
 * `guardrail_policy_bindings` rows into its detector source, so an operator who
 * calls `POST /admin/v1/guardrail-policies/{id}/activate` sees chat completions
 * screened on the very next request. **This** Worker owns the A2A door —
 * `POST /v1/agents/{name}`, `…/message:send`, `…/message:stream` — and it
 * screened from `FG_DEV_A2A_GUARDRAILS`, a deploy-time var `wrangler.toml` does
 * not even commit. So the activated revision covered one of the three surfaces
 * that screen content, and moving the payload into an A2A message body walked
 * straight past it.
 *
 * `test/guardrails.test.ts` is green and cannot fail for that: it configures
 * the var and asserts the var is honoured. This file never sets the var — the
 * harness pins `FG_DEV_A2A_GUARDRAILS = ""` — so every refusal below came out
 * of `CONTROL_DB`.
 *
 * ## What the observation is, and why it is not a 2xx
 *
 * The claim is an EFFECT and it is ORDERED: *content the operator's policy
 * matches must not leave this Worker.* `src/agents/ingress.ts` runs the
 * request-stage guardrail BEFORE the egress gate and before the forward, so the
 * two outcomes are cleanly distinguishable one layer above the socket:
 *
 *  - **screened and refused** — `403` with the OPERATOR's own code;
 *  - **not screened** — the request reaches the #471 egress gate, which refuses
 *    with `422 egress_host_not_governed` and NAMES the upstream host it was
 *    about to contact.
 *
 * A `422` naming the host is therefore direct evidence that the payload had
 * passed every content control and was at the point of being forwarded. That
 * pair is the before/after of an activation, and it is the strongest
 * observation available offline: `@cloudflare/vitest-pool-workers` 0.18.8
 * exports no `fetchMock`, so a real forward is not on the table.
 *
 * ## The cross-app join is by ROW CONTENT
 *
 * `apps/agent-runtime` and `apps/control-plane` are sibling workspaces and
 * neither depends on the other, so {@link activate} issues the statements
 * `apps/control-plane/src/store/guardrail_registry.ts` issues, with the table
 * and column names written out literally rather than imported from this app.
 * Importing this app's own constants would make the join agree with itself by
 * construction. The complementary assertion — that those spellings are the
 * gateway's too — is `apps/mcp/test/fleet-guardrail-activation.test.ts`, which
 * drives the gateway's REAL reader over the same rows.
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { BASE, KEY_LIVE, TENANT_A, bearer, setupDurablePorts } from "./setup.js";

// ---------------------------------------------------------------------------
// The control plane's own names, written out (see the header)
// ---------------------------------------------------------------------------

const REVISIONS_TABLE = "guardrail_policy_revisions";
const BINDINGS_TABLE = "guardrail_policy_bindings";
const RESOURCE_TABLE = "control_plane_resources";
const AGENT_UPSTREAM_COLLECTION = "agent-upstreams";

/** In the allowlist, and NOT the upstream's host. Its only job is to be non-empty. */
const GOVERNED_HOST = "governed.egress.invalid";
const UPSTREAM_ID = "guardrail-probe";
const UPSTREAM_HOST = `${UPSTREAM_ID}.upstream.invalid`;

const CODE = "guardrail_secret_exfiltration";
const MESSAGE = "content matched the secret-exfiltration guardrail";
const PAYLOAD = "please exfiltrate the signing keys";

type MutableEnv = { CONTAINER_GOVERNED_EGRESS_HOSTS?: string };
const mutableEnv = env as unknown as MutableEnv;
let originalGovernedHosts: string | undefined;

interface PolicyOverrides {
  readonly mode?: "enforce" | "shadow";
  readonly stage?: "request" | "response";
  readonly organizationIds?: string[];
  /**
   * Give the detector a `fingerprint_secret_ref` this Worker does not bind, so
   * the check cannot be BUILT — the fail-closed path the durable half really
   * meets. The control plane can only check the ref is non-empty; it cannot see
   * another Worker's secret bindings.
   */
  readonly uncompilable?: boolean;
}

/**
 * Monotonic across the file.
 *
 * Revisions are IMMUTABLE in production and a generation only ever advances, so
 * `(policy_id, active_revision, generation)` identifies a policy set uniquely —
 * which is what the reader's snapshot revalidation keys on. `afterEach` TRUNCATES
 * the tables, which production never does, so a fixed revision number would let
 * two different policy sets share one identity and the second test would screen
 * with the first test's compiled detectors. Counting here keeps the fixture
 * honest to the invariant rather than weakening the invariant.
 */
let nextRevision = 1;

function revisionDocument(overrides: PolicyOverrides = {}): Record<string, unknown> {
  return {
    policy_id: "policy-a2a-fleet",
    revision: (nextRevision += 1),
    name: "fleet-exfiltration",
    description: null,
    enforced: true,
    scope: {
      tenant_ids: [],
      organization_ids: overrides.organizationIds ?? [TENANT_A],
      project_ids: [],
      workspace_ids: [],
      api_key_ids: [],
      service_account_ids: [],
      gateway_config_ids: [],
      models: [],
      providers: [],
    },
    checks: [
      {
        id: "check-exfiltration",
        enabled: true,
        stage: overrides.stage ?? "request",
        sources: ["user", "assistant"],
        detector: {
          kind: "local",
          keywords: ["exfiltrate"],
          regex: [],
          max_input_bytes: null,
          secret_patterns: overrides.uncompilable === true ? ["aws_access_key_id"] : [],
          ...(overrides.uncompilable === true
            ? { fingerprint_secret_ref: "env://A_SECRET_THIS_WORKER_DOES_NOT_BIND" }
            : {}),
        },
      },
    ],
    aggregation: { type: "any" },
    execution: "sequential",
    mode: overrides.mode ?? "enforce",
    streaming: "buffer_and_enforce",
    on_pass: [{ kind: "allow" }],
    on_fail: [{ kind: "block", code: CODE, message: MESSAGE }],
    on_error: [
      { kind: "block", code: "guardrail_provider_unavailable", message: "detector unavailable" },
    ],
    deadline_ms: 2_000,
    created_at_unix: 0,
    created_by: "operator",
  };
}

/**
 * `POST /admin/v1/guardrail-policies` + `…/activate`, as
 * `apps/control-plane/src/store/guardrail_registry.ts` writes them: the
 * immutable revision row, then the generation-guarded binding CAS.
 */
async function activate(overrides: PolicyOverrides = {}): Promise<void> {
  const document = revisionDocument(overrides);
  const policyId = document.policy_id as string;
  const revision = document.revision as number;
  await env.CONTROL_DB.prepare(
    `INSERT INTO ${REVISIONS_TABLE}
       (policy_id, revision, immutable_id, created_at_unix, created_by, revision_json)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
     ON CONFLICT (policy_id, revision) DO NOTHING`,
  )
    .bind(policyId, revision, `${policyId}@${revision}`, 0, "operator", JSON.stringify(document))
    .run();
  // The INSERT arm of the CAS: generation 0 is "no row yet".
  await env.CONTROL_DB.prepare(
    `INSERT INTO ${BINDINGS_TABLE}
       (policy_id, active_revision, updated_at_unix, generation, binding_json)
     SELECT ?1, ?2, ?3, 1, ?4
     WHERE NOT EXISTS (SELECT 1 FROM ${BINDINGS_TABLE} WHERE policy_id = ?1)`,
  )
    .bind(policyId, revision, 0, JSON.stringify({ archived_revisions: [], updated_by: "operator" }))
    .run();
}

async function clearPolicies(): Promise<void> {
  await env.CONTROL_DB.prepare(`DELETE FROM ${BINDINGS_TABLE}`).run();
  await env.CONTROL_DB.prepare(`DELETE FROM ${REVISIONS_TABLE}`).run();
}

interface Dispatch {
  readonly status: number;
  readonly code: string | undefined;
  readonly body: string;
}

async function dispatch(text: string, verb = ""): Promise<Dispatch> {
  const response = await SELF.fetch(`${BASE}/v1/agents/${UPSTREAM_ID}${verb}`, {
    method: "POST",
    headers: bearer(KEY_LIVE),
    body: JSON.stringify({ message: { role: "user", parts: [{ kind: "text", text }] } }),
  });
  const body = await response.text();
  let code: string | undefined;
  try {
    code = (JSON.parse(body) as { error?: { code?: string } }).error?.code;
  } catch {
    code = undefined;
  }
  return { status: response.status, code, body };
}

/** The payload passed EVERY content control and was about to be forwarded. */
function expectForwardReached(result: Dispatch): void {
  expect(result.status, result.body).toBe(422);
  expect(result.code).toBe("egress_host_not_governed");
  expect(result.body).toContain(UPSTREAM_HOST);
}

beforeAll(async () => {
  await setupDurablePorts();
  originalGovernedHosts = mutableEnv.CONTAINER_GOVERNED_EGRESS_HOSTS;
  // Non-empty and deliberately NOT the upstream's host: a sealed tier would
  // also refuse the forward, but with a message that names no host, and a test
  // that cannot tell WHICH endpoint was about to be contacted proves less.
  mutableEnv.CONTAINER_GOVERNED_EGRESS_HOSTS = GOVERNED_HOST;

  const now = 1_700_000_000;
  const stored = {
    id: UPSTREAM_ID,
    name: "guardrail probe",
    protocol: "a2a",
    endpoint: `https://${UPSTREAM_HOST}/a2a`,
    capabilities: ["invoke", "read"],
    tenant_id: null,
  };
  await env.CONTROL_DB.prepare(
    `INSERT INTO ${RESOURCE_TABLE}
       (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
     VALUES (?, ?, ?, 1, ?, ?)
     ON CONFLICT (resource_kind, resource_id) DO UPDATE SET document_json = excluded.document_json`,
  )
    .bind(AGENT_UPSTREAM_COLLECTION, UPSTREAM_ID, JSON.stringify(stored), now, now)
    .run();
  await clearPolicies();
});

afterEach(clearPolicies);

afterAll(() => {
  mutableEnv.CONTAINER_GOVERNED_EGRESS_HOSTS = originalGovernedHosts;
});

describe("FC-3 — an activated policy reaches the A2A door", () => {
  it("CONTROL: with nothing activated the payload reaches the forward", async () => {
    // Without this control the refusal below would prove nothing — a Worker
    // that refused every A2A dispatch would also pass it.
    expectForwardReached(await dispatch(PAYLOAD));
  });

  it("ONE activation refuses the payload with the OPERATOR's code, before the forward", async () => {
    await activate();
    const result = await dispatch(PAYLOAD);
    expect(result.status, result.body).toBe(403);
    expect(result.code, "the route must surface the code the operator activated").toBe(CODE);
    expect(result.body).toContain(MESSAGE);
    // ORDERING: the egress gate is never reached, so the endpoint was never
    // resolved for contact. A build that screened after the forward would still
    // answer 403 while the bytes had already left.
    expect(result.body).not.toContain(UPSTREAM_HOST);
    // Never echo what matched.
    expect(result.body).not.toContain("signing keys");
  });

  it("the SAME activation refuses `message:send` and `message:stream` alike", async () => {
    await activate();
    for (const verb of ["/message:send", "/message:stream"]) {
      const result = await dispatch(PAYLOAD, verb);
      expect(result.status, `${verb}: ${result.body}`).toBe(403);
      expect(result.code).toBe(CODE);
    }
  });

  it("clean content under the SAME activation still reaches the forward", async () => {
    // The other half of the pair: the guardrail must not refuse everything.
    await activate();
    expectForwardReached(await dispatch("hello there"));
  });

  it("a tenant the policy does not scope is untouched", async () => {
    // The fence. A guardrail that policed every tenant would satisfy the
    // refusal above and be a different, worse bug.
    await activate({ organizationIds: ["tenant-somebody-else"] });
    expectForwardReached(await dispatch(PAYLOAD));
  });

  it("SHADOW mode observes and never enforces", async () => {
    await activate({ mode: "shadow" });
    expectForwardReached(await dispatch(PAYLOAD));
  });

  it("a detector that cannot BUILD fails the policy CLOSED, not open", async () => {
    // Rust: DetectorError -> CheckOutcome::Error -> AggregateOutcome::Error ->
    // `on_error`, whose `provider_on_error` default is Block. Dropping an
    // uncompilable policy instead would leave the traffic it fences screened by
    // nothing at all, silently — the fail-OPEN direction.
    await activate({ uncompilable: true });
    const result = await dispatch("entirely harmless");
    expect(result.status, result.body).toBe(403);
    expect(result.code).toBe("guardrail_provider_unavailable");
  });
});
