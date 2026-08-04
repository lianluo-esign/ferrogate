/**
 * `POST /admin/v1/guardrail-policies/{policy_id}/dry-run`, driven through the
 * exported Worker against a REAL D1 binding.
 *
 * The endpoint is the one place the control plane evaluates policy content
 * rather than merely storing it, so these tests hold the three things a
 * placeholder version of it silently got wrong:
 *
 *  1. `selected` is COMPUTED from the revision's scope fence, not asserted.
 *  2. `checks` reports a real per-check outcome, not `[]` for every policy.
 *  3. it dispatches nothing, and it cannot be pointed at another tenant.
 *
 * `store: "d1"` leaves `CONTROL_PLANE_STORE` unset, so the Worker takes its
 * production default and every read below goes through `D1ControlPlaneStore`
 * against the migration in `sql/d1-ts/control/`.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, resetD1, seedD1 } from "./d1.js";
import { BASE, arm, jsonRequest, operatorKey, tenantKey } from "./harness.js";

const KEY = operatorKey.secret;

interface DryRunCheckBody {
  readonly id: string;
  readonly detector: string;
  readonly result: string;
}

interface DryRunBody {
  readonly object: string;
  readonly policy_revision: string;
  readonly selected: boolean;
  readonly result: string;
  readonly checks: readonly DryRunCheckBody[];
  readonly provider_dispatched: boolean;
  readonly external_action_dispatched: boolean;
}

/** A `local` detector check binding, in `@ferrogate/guardrails` wire shape. */
function localCheck(
  id: string,
  detector: Record<string, unknown>,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id,
    enabled: true,
    stage: "request",
    sources: ["user"],
    detector: { kind: "local", keywords: [], regex: [], secret_patterns: [], ...detector },
    ...overrides,
  };
}

/** Seed a policy + one revision straight into the table, then dry-run it. */
async function seedPolicy(
  policyId: string,
  revision: Record<string, unknown>,
  tenantId: string | null = null,
): Promise<void> {
  await seedD1("guardrail-policies", [
    {
      id: policyId,
      policy_id: policyId,
      head_revision: 1,
      active_revision: 1,
      tenant_id: tenantId,
    },
  ]);
  await seedD1("guardrail-policy-revisions", [
    {
      id: `${policyId}@1`,
      policy_id: policyId,
      revision: 1,
      status: "active",
      tenant_id: tenantId,
      ...revision,
    },
  ]);
}

async function dryRun(policyId: string, body: unknown, secret = KEY): Promise<Response> {
  return SELF.fetch(
    `${BASE}/admin/v1/guardrail-policies/${policyId}/dry-run`,
    jsonRequest(secret, "POST", body),
  );
}

beforeAll(applySchema);

describe("guardrail dry-run: check evaluation (real D1)", () => {
  beforeEach(async () => {
    await resetD1();
    arm({ staticKeys: [operatorKey], store: "d1" });
  });

  it("FAILS a local keyword check whose keyword is present in the text", async () => {
    await seedPolicy("gp_kw", {
      checks: [localCheck("kw", { keywords: ["forbidden"] })],
    });

    const response = await dryRun("gp_kw", { stage: "request", text: "a forbidden phrase" });
    expect(response.status).toBe(200);
    const body = (await response.json()) as DryRunBody;
    expect(body.object).toBe("guardrail_policy_dry_run");
    expect(body.result).toBe("planned");
    expect(body.selected).toBe(true);
    expect(body.checks).toEqual([{ id: "kw", detector: "local", result: "fail" }]);
    // The dry-run PLANS; nothing was dispatched to reach that answer.
    expect(body.provider_dispatched).toBe(false);
    expect(body.external_action_dispatched).toBe(false);
  });

  it("PASSES the same check when the keyword is absent", async () => {
    await seedPolicy("gp_kw2", {
      checks: [localCheck("kw", { keywords: ["forbidden"] })],
    });

    const body = (await (
      await dryRun("gp_kw2", { stage: "request", text: "an allowed phrase" })
    ).json()) as DryRunBody;
    expect(body.checks).toEqual([{ id: "kw", detector: "local", result: "pass" }]);
  });

  it("evaluates a regex check, and an UNCOMPILABLE pattern simply does not match", async () => {
    await seedPolicy("gp_re", {
      checks: [
        localCheck("re", { regex: ["c[au]rd\\d{2}"] }),
        localCheck("broken", { regex: ["("] }),
      ],
    });

    const body = (await (
      await dryRun("gp_re", { stage: "request", text: "card42 please" })
    ).json()) as DryRunBody;
    expect(body.checks).toEqual([
      { id: "re", detector: "local", result: "fail" },
      // Rust: `Regex::new(p).is_ok_and(...)` — a pattern that does not compile
      // yields `false`, it does not abort the dry-run or fail the check.
      { id: "broken", detector: "local", result: "pass" },
    ]);
  });

  it("compares `max_input_bytes` in UTF-8 BYTES, not UTF-16 code units", async () => {
    await seedPolicy("gp_bytes", {
      checks: [localCheck("size", { max_input_bytes: 4 })],
    });

    // Four code units, TWELVE UTF-8 bytes. `text.length > 4` would be false;
    // Rust's `str::len()` is bytes, so this is over the cap.
    const over = (await (
      await dryRun("gp_bytes", { stage: "request", text: "语言语言" })
    ).json()) as DryRunBody;
    expect(over.checks).toEqual([{ id: "size", detector: "local", result: "fail" }]);

    const under = (await (
      await dryRun("gp_bytes", { stage: "request", text: "abcd" })
    ).json()) as DryRunBody;
    expect(under.checks).toEqual([{ id: "size", detector: "local", result: "pass" }]);
  });

  it("reports a DISABLED binding as `disabled`, never as a pass", async () => {
    await seedPolicy("gp_off", {
      checks: [localCheck("kw", { keywords: ["forbidden"] }, { enabled: false })],
    });

    const body = (await (
      await dryRun("gp_off", { stage: "request", text: "a forbidden phrase" })
    ).json()) as DryRunBody;
    expect(body.checks).toEqual([{ id: "kw", detector: "local", result: "disabled" }]);
  });

  it("never dispatches a REMOTE detector: `not_executed`", async () => {
    await seedPolicy("gp_remote", {
      checks: [
        {
          id: "http",
          enabled: true,
          stage: "request",
          sources: ["user"],
          detector: {
            kind: "custom_http",
            // A URL that would fail loudly in the test runtime if it were ever
            // fetched, which is the point: it must not be.
            endpoint: "https://detector.invalid/scan",
          },
        },
      ],
    });

    const body = (await (
      await dryRun("gp_remote", { stage: "request", text: "anything" })
    ).json()) as DryRunBody;
    expect(body.checks).toEqual([{ id: "http", detector: "custom_http", result: "not_executed" }]);
    expect(body.provider_dispatched).toBe(false);
    expect(body.external_action_dispatched).toBe(false);
  });

  it("does not execute a local detector that needs the request document or a host secret", async () => {
    await seedPolicy("gp_local_deferred", {
      checks: [
        localCheck("secrets", {
          secret_patterns: ["github_token"],
          fingerprint_secret_ref: "env:FINGERPRINT",
        }),
        localCheck("json", { json: { required_keys: ["/model"] } }),
      ],
    });

    const body = (await (
      await dryRun("gp_local_deferred", { stage: "request", text: "ghp_x" })
    ).json()) as DryRunBody;
    expect(body.checks).toEqual([
      { id: "secrets", detector: "local", result: "not_executed" },
      { id: "json", detector: "local", result: "not_executed" },
    ]);
  });

  it("only evaluates checks bound to the REQUESTED stage", async () => {
    await seedPolicy("gp_stage", {
      checks: [
        localCheck("on-request", { keywords: ["boom"] }),
        localCheck("on-response", { keywords: ["boom"] }, { stage: "response" }),
      ],
    });

    const request = (await (
      await dryRun("gp_stage", { stage: "request", text: "boom" })
    ).json()) as DryRunBody;
    expect(request.checks).toEqual([{ id: "on-request", detector: "local", result: "fail" }]);

    const response = (await (
      await dryRun("gp_stage", { stage: "response", text: "boom" })
    ).json()) as DryRunBody;
    expect(response.checks).toEqual([{ id: "on-response", detector: "local", result: "fail" }]);
  });

  it("reports an UNPARSEABLE check as `not_executed` rather than dropping it", async () => {
    await seedPolicy("gp_bad", {
      checks: [{ id: "mystery", enabled: true, stage: "request", detector: { kind: "quantum" } }],
    });

    const body = (await (
      await dryRun("gp_bad", { stage: "request", text: "x" })
    ).json()) as DryRunBody;
    expect(body.checks).toEqual([
      { id: "mystery", detector: "unparseable", result: "not_executed" },
    ]);
  });
});

describe("guardrail dry-run: selection is computed from the revision scope", () => {
  beforeEach(async () => {
    await resetD1();
    arm({ staticKeys: [operatorKey], store: "d1" });
  });

  it("is NOT selected when the revision is fenced to another model", async () => {
    await seedPolicy("gp_scope", {
      scope: { models: ["gpt-4o"] },
      checks: [localCheck("kw", { keywords: ["boom"] })],
    });

    const miss = (await (
      await dryRun("gp_scope", { stage: "request", text: "boom", model: "claude-3" })
    ).json()) as DryRunBody;
    expect(miss.selected).toBe(false);
    // An unselected revision would not run, so it reports no per-check plan.
    expect(miss.checks).toEqual([]);

    const hit = (await (
      await dryRun("gp_scope", { stage: "request", text: "boom", model: "gpt-4o" })
    ).json()) as DryRunBody;
    expect(hit.selected).toBe(true);
    expect(hit.checks).toEqual([{ id: "kw", detector: "local", result: "fail" }]);
  });

  it("fails CLOSED (`selected: false`) on a malformed scope fence", async () => {
    await seedPolicy("gp_badscope", {
      scope: { models: "gpt-4o" },
      checks: [localCheck("kw", { keywords: ["boom"] })],
    });

    const body = (await (
      await dryRun("gp_badscope", { stage: "request", text: "boom" })
    ).json()) as DryRunBody;
    expect(body.selected).toBe(false);
    expect(body.checks).toEqual([]);
  });

  it("an absent scope is unfenced and selects", async () => {
    await seedPolicy("gp_noscope", { checks: [localCheck("kw", { keywords: ["boom"] })] });

    const body = (await (
      await dryRun("gp_noscope", { stage: "request", text: "boom" })
    ).json()) as DryRunBody;
    expect(body.selected).toBe(true);
    expect(body.policy_revision).toBe("gp_noscope@1");
  });

  it("rejects a retired service-account selector instead of treating it as inert", async () => {
    await seedPolicy("gp_service_account_dry_run", { checks: [] });

    const response = await dryRun("gp_service_account_dry_run", {
      stage: "request",
      text: "",
      service_account_id: "service-account-1",
    });
    expect(response.status).toBe(400);
    expect((await response.json()) as { error: { code: string } }).toMatchObject({
      error: { code: "invalid_request_body" },
    });
  });

  it("fails closed for a legacy persisted service-account scope", async () => {
    await seedPolicy("gp_legacy_service_account", {
      scope: { service_account_ids: ["service-account-1"] },
      checks: [localCheck("kw", { keywords: ["boom"] })],
    });

    const body = (await (
      await dryRun("gp_legacy_service_account", { stage: "request", text: "boom" })
    ).json()) as DryRunBody;
    expect(body.selected).toBe(false);
    expect(body.checks).toEqual([]);
  });
});

describe("guardrail dry-run: #515 — the body may not re-point the tenant", () => {
  const TENANT_SECRET = "tenant-a-secret";

  beforeEach(async () => {
    await resetD1();
    arm({
      staticKeys: [operatorKey],
      nativeKeys: [tenantKey(TENANT_SECRET, "tenant-a")],
      rbac: { "tenant-a": ["*"] },
      store: "d1",
    });
  });

  it("403s a tenant caller that names a DIFFERENT organization_id", async () => {
    await seedPolicy("gp_515", { checks: [] }, "tenant-a");

    const response = await dryRun(
      "gp_515",
      { stage: "request", text: "", organization_id: "tenant-b" },
      TENANT_SECRET,
    );
    expect(response.status).toBe(403);
    expect((await response.json()) as { error: { code: string } }).toMatchObject({
      error: { code: "guardrail_policy_scope_denied" },
    });
  });

  it("admits a tenant caller that names its OWN organization_id", async () => {
    await seedPolicy("gp_515b", { checks: [] }, "tenant-a");

    const response = await dryRun(
      "gp_515b",
      { stage: "request", text: "", organization_id: "tenant-a" },
      TENANT_SECRET,
    );
    expect(response.status).toBe(200);
  });

  it("selects a tenant caller against ITS OWN tenant even with no body field", async () => {
    await seedPolicy(
      "gp_515c",
      { scope: { tenant_ids: ["tenant-a"] }, checks: [localCheck("kw", { keywords: ["boom"] })] },
      "tenant-a",
    );

    const body = (await (
      await dryRun("gp_515c", { stage: "request", text: "boom" }, TENANT_SECRET)
    ).json()) as DryRunBody;
    // The selection context carries the CALLER's tenant, so a revision fenced
    // to that tenant is selected without the caller naming it.
    expect(body.selected).toBe(true);
    expect(body.checks).toEqual([{ id: "kw", detector: "local", result: "fail" }]);
  });

  it("cannot dry-run ANOTHER tenant's policy (store fence): 404", async () => {
    await seedPolicy("gp_other", { checks: [] }, "tenant-b");

    const response = await dryRun("gp_other", { stage: "request", text: "" }, TENANT_SECRET);
    expect(response.status).toBe(404);
  });
});
