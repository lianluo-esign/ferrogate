/**
 * `ferrogate apply -f <file>` — the declarative (GitOps) sync gate, issue #702.
 *
 * The four properties the command exists to have, one describe-block each:
 *
 *  * **diffable**  — the plan is printed BEFORE anything is sent, field by field;
 *  * **dry-runnable** — `--dry-run` reaches the same plan and opens no socket
 *    for a mutation;
 *  * **idempotent** — applying the same file twice sends mutations the first
 *    time and NONE the second. That is proven against a STATEFUL fake control
 *    plane below, not asserted: run 1's writes really are run 2's reads. A
 *    script-driven fake could not tell a converged apply from a broken one.
 *  * **explicit about deletion** — a resource that exists on the server and is
 *    absent from the file is REPORTED and KEPT by default, and only removed
 *    when the operator says `--prune`.
 */
import type { JsonValue } from "@ferrogate/core";
import { describe, expect, test } from "vitest";
import { main } from "../src/index.js";
import type {
  ApiResponse,
  FakeControlPlaneClient,
  RawApiResponse,
  RecordedRequest,
  RequestContext,
  RequestSpec,
} from "../src/ports.js";
import { CliError } from "../src/errors.js";
import { createTestRuntime } from "./helpers.js";

// ---------------------------------------------------------------------------
// A stateful, in-memory control plane
// ---------------------------------------------------------------------------

type Record_ = Record<string, JsonValue>;

interface StatefulState {
  readonly quotaPolicies: Map<string, Record_>;
  /** `policy_id` -> `{ policy_id, head_revision, active_revision }`. */
  readonly guardrailPolicies: Map<string, Record_>;
  /** `policy_id@revision` -> the stored revision document. */
  readonly guardrailRevisions: Map<string, Record_>;
}

interface StatefulClient extends FakeControlPlaneClient {
  readonly state: StatefulState;
  /** Every mutating request seen so far (POST/PUT/PATCH/DELETE). */
  mutations(): readonly RecordedRequest[];
}

function listBody(items: readonly Record_[]): JsonValue {
  return { object: "list", data: items as JsonValue[], total: items.length };
}

function asObject(body: JsonValue | undefined): Record_ {
  return body !== undefined && body !== null && typeof body === "object" && !Array.isArray(body)
    ? (body as Record_)
    : {};
}

/**
 * The fake control plane, faithful to the three route families `apply` drives:
 * `quota_policy` (composite `scope_type/scope_id` key) and `guardrail_policy`
 * (append-only revisions plus an activation pointer). Shapes mirror
 * `apps/control-plane/src/routes/{quota_policy,guardrail_policy}.ts`.
 */
function createStatefulControlPlane(seed: Partial<StatefulState> = {}): StatefulClient {
  const state: StatefulState = {
    quotaPolicies: seed.quotaPolicies ?? new Map(),
    guardrailPolicies: seed.guardrailPolicies ?? new Map(),
    guardrailRevisions: seed.guardrailRevisions ?? new Map(),
  };
  const requests: RecordedRequest[] = [];

  const segmentsUnder = (path: string, prefix: string): string[] =>
    path.startsWith(prefix)
      ? path
          .slice(prefix.length)
          .split("/")
          .filter((part) => part !== "")
          .map((part) => decodeURIComponent(part))
      : [];

  const handle = (spec: RequestSpec): { status: number; body: JsonValue } => {
    const body = asObject(spec.body);

    if (spec.path.startsWith("/admin/v1/quota-policies")) {
      const segments = segmentsUnder(spec.path, "/admin/v1/quota-policies");
      const id = segments.join(":");
      if (spec.method === "GET" && segments.length === 0) {
        return { status: 200, body: listBody([...state.quotaPolicies.values()]) };
      }
      if (spec.method === "POST") {
        const created = `${String(body.scope_type)}:${String(body.scope_id)}`;
        if (state.quotaPolicies.has(created)) {
          throw CliError.api({ httpStatus: 409, code: "conflict", message: "already exists" });
        }
        const stored = { ...body, id: created, tenant_id: null };
        state.quotaPolicies.set(created, stored);
        return { status: 201, body: { object: "quota_policy", quota_policy: stored } };
      }
      if (spec.method === "PUT") {
        const [scopeType, scopeId] = segments;
        const stored = {
          ...body,
          scope_type: scopeType as JsonValue,
          scope_id: scopeId as JsonValue,
          id,
          tenant_id: null,
        };
        state.quotaPolicies.set(id, stored);
        return { status: 200, body: { object: "quota_policy", quota_policy: stored } };
      }
      if (spec.method === "DELETE") {
        state.quotaPolicies.delete(id);
        return { status: 200, body: { object: "quota_policy", id, deleted: true } };
      }
    }

    if (spec.path.startsWith("/admin/v1/guardrail-policies")) {
      const segments = segmentsUnder(spec.path, "/admin/v1/guardrail-policies");
      const [policyId, tail, revisionText] = segments;

      if (spec.method === "GET" && segments.length === 0) {
        return { status: 200, body: listBody([...state.guardrailPolicies.values()]) };
      }
      if (spec.method === "GET" && tail === "revisions" && policyId !== undefined) {
        const items = [...state.guardrailRevisions.values()].filter(
          (item) => item.policy_id === policyId,
        );
        return { status: 200, body: listBody(items) };
      }
      // Create the policy and its revision 1.
      if (spec.method === "POST" && segments.length === 0) {
        const created = String(body.policy_id);
        const stored = {
          ...body,
          revision: 1,
          id: `${created}@1`,
          status: "draft",
          created_by: "platform_operator",
          created_at_unix: 1_700_000_000,
        };
        state.guardrailRevisions.set(stored.id, stored);
        state.guardrailPolicies.set(created, {
          id: created,
          policy_id: created,
          head_revision: 1,
          active_revision: null,
        });
        return { status: 201, body: { object: "guardrail_policy_revision", policy: stored } };
      }
      if (spec.method === "POST" && tail === "revisions" && policyId !== undefined) {
        const policy = state.guardrailPolicies.get(policyId);
        const next = Number(policy?.head_revision ?? 0) + 1;
        const stored = {
          ...body,
          policy_id: policyId as JsonValue,
          revision: next,
          id: `${policyId}@${next}`,
          status: "draft",
          created_by: "platform_operator",
          created_at_unix: 1_700_000_000,
        };
        state.guardrailRevisions.set(stored.id, stored);
        if (policy !== undefined) policy.head_revision = next;
        return { status: 201, body: { object: "guardrail_policy_revision", policy: stored } };
      }
      if (spec.method === "POST" && tail === "activate" && policyId !== undefined) {
        const revision = Number(body.revision);
        const policy = state.guardrailPolicies.get(policyId);
        if (policy === undefined || !state.guardrailRevisions.has(`${policyId}@${revision}`)) {
          throw CliError.api({ httpStatus: 404, code: "not_found", message: "no such revision" });
        }
        policy.active_revision = revision;
        return { status: 200, body: { object: "guardrail_policy_revision", policy } };
      }
      if (spec.method === "DELETE" && tail === "revisions" && policyId !== undefined) {
        const key = `${policyId}@${Number(revisionText)}`;
        const stored = state.guardrailRevisions.get(key);
        if (stored !== undefined) stored.status = "archived";
        const policy = state.guardrailPolicies.get(policyId);
        if (policy !== undefined) policy.active_revision = null;
        return { status: 200, body: { object: "guardrail_policy_revision", id: key, deleted: true } };
      }
    }

    throw CliError.api({
      httpStatus: 404,
      code: "not_found",
      message: `the stateful fake has no route for ${spec.method} ${spec.path}`,
    });
  };

  return {
    requests,
    state,
    mutations: () => requests.filter((entry) => entry.spec.method !== "GET"),
    async send(spec: RequestSpec, context: RequestContext): Promise<ApiResponse> {
      requests.push({ spec, context });
      const { status, body } = handle(spec);
      return { status, body };
    },
    async sendRaw(): Promise<RawApiResponse> {
      throw new Error("the apply path never issues a raw export");
    },
  };
}

function runtimeWith(files: Record<string, string>, client: StatefulClient) {
  const base = createTestRuntime({ files });
  return { ...base, client };
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const QUOTA_ONLY = JSON.stringify({
  apiVersion: "ferrogate.io/v1alpha1",
  kind: "DesiredState",
  resources: {
    "quota-policies": [
      { scope_type: "tenant", scope_id: "acme", rpm_limit: 600, enabled: true },
    ],
  },
});

const GUARDRAIL_ONLY = JSON.stringify({
  apiVersion: "ferrogate.io/v1alpha1",
  kind: "DesiredState",
  resources: {
    "guardrail-policies": [
      {
        policy_id: "pii",
        name: "pii-redaction",
        enforced: true,
        checks: [],
        on_pass: "allow",
        on_fail: "block",
        on_error: "allow",
      },
    ],
  },
});

const ARGV = (file: string, ...rest: string[]) => [
  "apply",
  "-f",
  file,
  "--endpoint",
  "https://cp.example",
  "--non-interactive",
  ...rest,
];

// ---------------------------------------------------------------------------

describe("ferrogate apply converges the declared resources", () => {
  test("a quota policy the server does not have is created", async () => {
    const client = createStatefulControlPlane();
    const runtime = runtimeWith({ "/desired.json": QUOTA_ONLY }, client);

    expect(await main(ARGV("/desired.json"), runtime)).toBe(0);

    expect([...client.state.quotaPolicies.keys()]).toEqual(["tenant:acme"]);
    expect(client.state.quotaPolicies.get("tenant:acme")).toMatchObject({
      scope_type: "tenant",
      scope_id: "acme",
      rpm_limit: 600,
    });
    const posts = client.mutations();
    expect(posts).toHaveLength(1);
    expect(posts[0]?.spec.method).toBe("POST");
    expect(posts[0]?.spec.path).toBe("/admin/v1/quota-policies");
  });

  test("a declared field that differs on the server is replaced, in place", async () => {
    const client = createStatefulControlPlane({
      quotaPolicies: new Map([
        ["tenant:acme", { id: "tenant:acme", scope_type: "tenant", scope_id: "acme", rpm_limit: 60, enabled: true }],
      ]),
    });
    const runtime = runtimeWith({ "/desired.json": QUOTA_ONLY }, client);

    expect(await main(ARGV("/desired.json"), runtime)).toBe(0);

    expect(client.state.quotaPolicies.get("tenant:acme")?.rpm_limit).toBe(600);
    const writes = client.mutations();
    expect(writes).toHaveLength(1);
    expect(writes[0]?.spec.method).toBe("PUT");
    expect(writes[0]?.spec.path).toBe("/admin/v1/quota-policies/tenant/acme");
  });
});

describe("ferrogate apply is idempotent", () => {
  test("a second apply of the same file against the state the first produced sends nothing", async () => {
    const client = createStatefulControlPlane();
    const runtime = runtimeWith({ "/desired.json": QUOTA_ONLY }, client);

    expect(await main(ARGV("/desired.json"), runtime)).toBe(0);
    const afterFirst = client.mutations().length;
    expect(afterFirst).toBe(1);

    // Same file, same process-shaped invocation, and — crucially — the SAME
    // server state object the first run mutated.
    const second = runtimeWith({ "/desired.json": QUOTA_ONLY }, client);
    expect(await main(ARGV("/desired.json"), second)).toBe(0);

    expect(client.mutations()).toHaveLength(afterFirst);
    expect(second.stdout()).toContain("unchanged");
  });

  test("a guardrail policy whose ACTIVE revision already matches appends no revision", async () => {
    const client = createStatefulControlPlane();
    const first = runtimeWith({ "/desired.json": GUARDRAIL_ONLY }, client);

    expect(await main(ARGV("/desired.json"), first)).toBe(0);
    // Create-revision-1 plus activate.
    expect(client.mutations()).toHaveLength(2);
    expect(client.state.guardrailPolicies.get("pii")?.active_revision).toBe(1);

    const second = runtimeWith({ "/desired.json": GUARDRAIL_ONLY }, client);
    expect(await main(ARGV("/desired.json"), second)).toBe(0);

    expect(client.mutations()).toHaveLength(2);
    expect(client.state.guardrailRevisions.size).toBe(1);
  });

  test("a guardrail policy whose content changed appends the next revision and activates it", async () => {
    const client = createStatefulControlPlane();
    expect(await main(ARGV("/desired.json"), runtimeWith({ "/desired.json": GUARDRAIL_ONLY }, client))).toBe(0);

    const changed = GUARDRAIL_ONLY.replace('"enforced":true', '"enforced":false');
    expect(changed).not.toBe(GUARDRAIL_ONLY);
    expect(await main(ARGV("/desired.json"), runtimeWith({ "/desired.json": changed }, client))).toBe(0);

    expect(client.state.guardrailPolicies.get("pii")?.active_revision).toBe(2);
    expect(client.state.guardrailRevisions.get("pii@2")?.enforced).toBe(false);
    // Revision 1 is untouched: revisions are immutable history.
    expect(client.state.guardrailRevisions.get("pii@1")?.enforced).toBe(true);
  });
});

describe("ferrogate apply is diffable and dry-runnable", () => {
  test("--dry-run prints the plan and sends no mutation", async () => {
    const client = createStatefulControlPlane();
    const runtime = runtimeWith({ "/desired.json": QUOTA_ONLY }, client);

    expect(await main(ARGV("/desired.json", "--dry-run"), runtime)).toBe(0);

    expect(client.mutations()).toHaveLength(0);
    expect(client.state.quotaPolicies.size).toBe(0);
    expect(runtime.stdout()).toContain("create quota-policies/tenant:acme");
    expect(runtime.stdout()).toContain("rpm_limit");
  });

  test("an update names the old and the new value of every changed field", async () => {
    const client = createStatefulControlPlane({
      quotaPolicies: new Map([
        ["tenant:acme", { id: "tenant:acme", scope_type: "tenant", scope_id: "acme", rpm_limit: 60, enabled: true }],
      ]),
    });
    const runtime = runtimeWith({ "/desired.json": QUOTA_ONLY }, client);

    expect(await main(ARGV("/desired.json", "--dry-run"), runtime)).toBe(0);

    const out = runtime.stdout();
    expect(out).toContain("update quota-policies/tenant:acme");
    expect(out).toContain("rpm_limit: 60 -> 600");
  });
});

describe("ferrogate apply never deletes silently", () => {
  const seeded = () =>
    createStatefulControlPlane({
      quotaPolicies: new Map([
        ["tenant:acme", { id: "tenant:acme", scope_type: "tenant", scope_id: "acme", rpm_limit: 600, enabled: true }],
        ["tenant:legacy", { id: "tenant:legacy", scope_type: "tenant", scope_id: "legacy", rpm_limit: 5, enabled: true }],
      ]),
    });

  test("a server-only resource is reported and KEPT by default", async () => {
    const client = seeded();
    const runtime = runtimeWith({ "/desired.json": QUOTA_ONLY }, client);

    expect(await main(ARGV("/desired.json"), runtime)).toBe(0);

    expect(client.state.quotaPolicies.has("tenant:legacy")).toBe(true);
    expect(client.mutations()).toHaveLength(0);
    expect(runtime.stdout()).toContain("orphan quota-policies/tenant:legacy");
    expect(runtime.stderr()).toContain("--prune");
  });

  test("--prune deletes it, and says so in the plan", async () => {
    const client = seeded();
    const runtime = runtimeWith({ "/desired.json": QUOTA_ONLY }, client);

    expect(await main(ARGV("/desired.json", "--prune", "--yes"), runtime)).toBe(0);

    expect(client.state.quotaPolicies.has("tenant:legacy")).toBe(false);
    const writes = client.mutations();
    expect(writes).toHaveLength(1);
    expect(writes[0]?.spec.method).toBe("DELETE");
    expect(writes[0]?.spec.path).toBe("/admin/v1/quota-policies/tenant/legacy");
    expect(runtime.stdout()).toContain("delete quota-policies/tenant:legacy");
  });

  test("--prune without --yes refuses before any request when prompting is disabled", async () => {
    const client = seeded();
    const runtime = runtimeWith({ "/desired.json": QUOTA_ONLY }, client);

    expect(await main(ARGV("/desired.json", "--prune"), runtime)).toBe(2);
    expect(client.mutations()).toHaveLength(0);
    expect(client.state.quotaPolicies.has("tenant:legacy")).toBe(true);
    // Named refusal, not the generic usage banner an unimplemented command
    // would also exit 2 with — otherwise this test passes on a CLI that has no
    // `apply` at all.
    expect(runtime.stderr()).toContain("refusing to prune");
    expect(runtime.stderr()).toContain("--yes");
  });

  test("--prune --dry-run shows the deletions without performing them", async () => {
    const client = seeded();
    const runtime = runtimeWith({ "/desired.json": QUOTA_ONLY }, client);

    expect(await main(ARGV("/desired.json", "--prune", "--dry-run"), runtime)).toBe(0);
    expect(client.mutations()).toHaveLength(0);
    expect(client.state.quotaPolicies.has("tenant:legacy")).toBe(true);
    expect(runtime.stdout()).toContain("delete quota-policies/tenant:legacy");
  });
});

describe("ferrogate apply refuses documents it cannot honour", () => {
  test("a resource kind with no write operation in the contract is named, not attempted", async () => {
    const client = createStatefulControlPlane();
    const document = JSON.stringify({
      apiVersion: "ferrogate.io/v1alpha1",
      kind: "DesiredState",
      resources: { models: [{ id: "gpt-4o" }] },
    });
    const runtime = runtimeWith({ "/desired.json": document }, client);

    expect(await main(ARGV("/desired.json"), runtime)).toBe(2);
    expect(client.requests).toHaveLength(0);
    expect(runtime.stderr()).toContain("models");
    expect(runtime.stderr()).toContain("read-only");
  });

  test("an unknown apiVersion is a validation failure, not a best-effort apply", async () => {
    const client = createStatefulControlPlane();
    const document = JSON.stringify({
      apiVersion: "ferrogate.io/v99",
      kind: "DesiredState",
      resources: {},
    });
    const runtime = runtimeWith({ "/desired.json": document }, client);

    expect(await main(ARGV("/desired.json"), runtime)).toBe(5);
    expect(client.requests).toHaveLength(0);
  });

  test("a quota policy missing its identity fields is refused before anything is sent", async () => {
    const client = createStatefulControlPlane();
    const document = JSON.stringify({
      apiVersion: "ferrogate.io/v1alpha1",
      kind: "DesiredState",
      resources: { "quota-policies": [{ rpm_limit: 10 }] },
    });
    const runtime = runtimeWith({ "/desired.json": document }, client);

    expect(await main(ARGV("/desired.json"), runtime)).toBe(5);
    expect(client.mutations()).toHaveLength(0);
  });
});
