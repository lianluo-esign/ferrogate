/**
 * THE TENANCY LIFECYCLE GATE, on the port this Worker actually DEPLOYS.
 * (`docs/rewrite/FLEET-CONSISTENCY.md` finding **FC-2**.)
 *
 * ## Why this file has to exist even though a suspension test already passed
 *
 * `test/units.test.ts` has proved "a suspended tenancy is 403" since wave 16 —
 * through {@link inMemoryApiKeyPort}, reading the `FG_DEV_API_KEYS` var. That
 * is the ONLY port that could ever return the `tenancy_suspended` outcome.
 * `d1ApiKeyPort` (`src/durable/adapters.ts`), the port every real deployment
 * mounts, returns exactly `unknown` / `key_suspended` / `resolved` /
 * `unavailable` — so the DEPLOYED Worker could render the refusal and could
 * never produce it.
 *
 * A green suite, a control that did not exist in production, and no test that
 * could tell the difference. FLEET-CONSISTENCY calls that the
 * `lifecycle-tenancy-scenario-neverrun` failure mode, and this suite is the
 * posture it was missing: the dev bundle is ABSENT here
 * (`harness/wrangler.toml` sets no `FG_DEV_*`), both databases are real, and
 * every request goes through `SELF` into the real `src/worker.ts`.
 *
 * The FLEET half — one suspension, all three spending Workers refusing with
 * the SAME status and code — is
 * `apps/mcp/test/fleet-tenancy-suspension.test.ts`. This file is the per-Worker
 * half: it is what makes the wrap in `resolveDeps` provable at the mount.
 */
import { SELF, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  BASE,
  KEY_DISABLED,
  KEY_LIVE,
  KEY_UNKNOWN,
  TENANT_A,
  bearer,
  errorCode,
  setupDurablePorts,
  tenantResourceDb,
} from "./setup.js";

/** `POST /v1/agents/{name}` — bearer `agents.invoke`, and it spends nothing. */
async function dispatch(key: string): Promise<{ status: number; code: string | undefined }> {
  const response = await SELF.fetch(`${BASE}/v1/agents/no-such-agent`, {
    method: "POST",
    headers: bearer(key),
    body: JSON.stringify({ input: {} }),
  });
  return { status: response.status, code: await errorCode(response) };
}

/**
 * What an ADMITTED caller gets: the A2A catalog is empty in this harness, so it
 * lands on the handler's own 404. Pinned rather than asserted as "not a 403",
 * because "not a 403" is satisfied by a Worker that refuses everything for an
 * unrelated reason and then the refusals below prove nothing.
 */
const ADMITTED = { status: 404, code: "agent_not_found" } as const;
const REFUSED = { status: 403, code: "tenancy_suspended" } as const;

const PROJECT = "proj-a";
const WORKSPACE = "ws-a";

async function seedHierarchy(): Promise<void> {
  // `tenants` is CONTROL state; `projects`/`workspaces` are TENANT data and,
  // since #821 PR2a, are READ from the caller tenant's own object — so they are
  // SEEDED there too (`env.DB` is what a routed deployment never writes).
  await env.CONTROL_DB.prepare(
    "INSERT OR REPLACE INTO tenants (id, name, slug, status) VALUES (?, 'A', 'a', 'active')",
  )
    .bind(TENANT_A)
    .run();
  const tenantDb = await tenantResourceDb(TENANT_A);
  await tenantDb
    .prepare(
      "INSERT OR REPLACE INTO projects (id, tenant_id, name, slug, status) VALUES (?, ?, 'p', 'p', 'active')",
    )
    .bind(PROJECT, TENANT_A)
    .run();
  await tenantDb
    .prepare(
      "INSERT OR REPLACE INTO workspaces (id, project_id, tenant_id, name, slug, status) " +
        "VALUES (?, ?, ?, 'w', 'w', 'active')",
    )
    .bind(WORKSPACE, PROJECT, TENANT_A)
    .run();
}

async function setTenantStatus(status: string): Promise<void> {
  const result = await env.CONTROL_DB.prepare("UPDATE tenants SET status = ?1 WHERE id = ?2")
    .bind(status, TENANT_A)
    .run();
  expect(result.meta.changes, "the lifecycle update touched no tenant row").toBe(1);
}

async function setProjectStatus(status: string): Promise<void> {
  const result = await (await tenantResourceDb(TENANT_A))
    .prepare("UPDATE projects SET status = ?1 WHERE id = ?2")
    .bind(status, PROJECT)
    .run();
  expect(result.meta.changes, "the lifecycle update touched no project row").toBe(1);
}

beforeAll(async () => {
  await setupDurablePorts();
});

beforeEach(async () => {
  await seedHierarchy();
});

describe("the DEPLOYED credential port can now produce a tenancy refusal", () => {
  it("admits a live key whose whole chain is active", async () => {
    // The positive control. Without it every refusal below would pass against a
    // Worker that refuses this credential for some unrelated reason.
    expect(await dispatch(KEY_LIVE)).toEqual(ADMITTED);
  });

  it("403 tenancy_suspended once the CONTROL database says the tenant is suspended", async () => {
    await setTenantStatus("suspended");
    // Before FC-2 this was `404 agent_not_found`: the key was never revoked,
    // only its tenancy, so `d1ApiKeyPort` resolved it and nothing looked at
    // `tenants.status` at all.
    expect(await dispatch(KEY_LIVE)).toEqual(REFUSED);
  });

  it("re-admits when the operator lifts the suspension", async () => {
    await setTenantStatus("suspended");
    expect(await dispatch(KEY_LIVE)).toEqual(REFUSED);
    // A gate that refused unconditionally would satisfy the test above.
    await setTenantStatus("active");
    expect(await dispatch(KEY_LIVE)).toEqual(ADMITTED);
  });

  it("walks the ANCESTORS: a suspended PROJECT under an active tenant denies", async () => {
    // Rust `check_lifecycle_chain`. A gate that read only `tenants.status`
    // passes the test above and fails this one.
    await setProjectStatus("suspended");
    expect(await dispatch(KEY_LIVE)).toEqual(REFUSED);
  });

  it.each(["disabled", "deleted"])("refuses a %s tenancy as well", async (status) => {
    // PORT-TODO(P: FLEET-CONSISTENCY §FC-2), stated as an assertion rather than
    // as prose: every inactive status DENIES, which is the decision that
    // matters, but this Worker's `ApiKeyResolution` has ONE inactive-tenancy
    // arm so all three report `tenancy_suspended`. `apps/gateway` distinguishes
    // them (`tenancy_disabled` / `tenancy_deleted`). Closing the gap is a
    // widened union plus a `switch` arm in `src/middleware/auth.ts`, which is
    // outside the slice that landed this gate. When that lands, THIS assertion
    // is the one that must change — it is not a claim that the codes agree.
    await setTenantStatus(status);
    expect(await dispatch(KEY_LIVE)).toEqual(REFUSED);
  });

  it("leaves an unrecognised status ADMITTED — absence is not suspension", async () => {
    // The fail-OPEN READ default #514 chose deliberately: these columns were
    // decorative before it, so legacy rows carry arbitrary values and denial is
    // opt-in. The WRITE side is strict, which is where a typo is caught.
    await setTenantStatus("suspend");
    expect(await dispatch(KEY_LIVE)).toEqual(ADMITTED);
  });
});

describe("the 401-vs-403 taxonomy is unchanged by the gate", () => {
  it("a suspended KEY on a suspended tenant is still 401, never 403", async () => {
    // The ordering that matters: the credential decision is made FIRST, so a
    // dead key answers the same 401 an unknown one gets. A gate that reported
    // the tenancy failure here would disclose that the credential exists.
    await setTenantStatus("suspended");
    expect(await dispatch(KEY_DISABLED)).toEqual({ status: 401, code: "invalid_api_key" });
    expect(await dispatch(KEY_UNKNOWN)).toEqual({ status: 401, code: "invalid_api_key" });
  });
});

describe("FAIL CLOSED", () => {
  it("503s rather than admitting when a lifecycle row cannot be read", async () => {
    // Rust `LifecycleGateError::Unavailable`: fail-open here would make "flap
    // the control plane" a suspension bypass. Renaming the table is the
    // cheapest real read failure available offline — the query raises exactly
    // as it would against an unreachable database.
    await env.CONTROL_DB.prepare("ALTER TABLE tenants RENAME TO tenants_quarantined").run();
    try {
      const refused = await dispatch(KEY_LIVE);
      expect(refused.status, "ADMITTED a caller whose tenancy it could not read").toBe(503);
      expect(refused.code).toBe("agent_runtime_unavailable");
    } finally {
      await env.CONTROL_DB.prepare("ALTER TABLE tenants_quarantined RENAME TO tenants").run();
    }
    // The refusal was the outage, not a suspension: the tenant is still live.
    expect(await dispatch(KEY_LIVE)).toEqual(ADMITTED);
  });
});
