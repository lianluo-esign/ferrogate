/**
 * `GET /admin/v1/status`, `/admin/v1/overview`, `/admin/v1/observability` and
 * `/metrics`, against a REAL D1 binding.
 *
 * Two jobs:
 *
 *  1. hold the CLOSED half — `status.snapshot` reports the config snapshot the
 *     control plane actually promoted, not a hard-coded `"unversioned"`; and
 *  2. PIN THE APPROXIMATION for the half that is a platform limit — the
 *     observability feed stays EMPTY because Analytics Engine has no readable
 *     binding (its query side is the account-scoped REST API, unavailable
 *     offline and to this app). A future change that starts fabricating series
 *     here has to delete an assertion to do it.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, resetD1, seedD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey } from "./harness.js";

const KEY = operatorKey.secret;

interface StatusBody {
  readonly service: string;
  readonly runtime: string;
  readonly snapshot: string;
  readonly providers: number;
  readonly auth_required: boolean;
}

async function status(): Promise<StatusBody> {
  const response = await SELF.fetch(`${BASE}/admin/v1/status`, { headers: bearer(KEY) });
  expect(response.status).toBe(200);
  return (await response.json()) as StatusBody;
}

beforeAll(applySchema);

describe("runtime status (real D1)", () => {
  beforeEach(async () => {
    await resetD1();
    arm({ staticKeys: [operatorKey], store: "d1" });
  });

  it("reports `unversioned` when NO config snapshot has been promoted", async () => {
    expect((await status()).snapshot).toBe("unversioned");
  });

  it("reports the snapshot id of the config the control plane promoted", async () => {
    // A minimal but LOADABLE gateway config: `reloadAdminConfig` runs it
    // through the same `@ferrogate/config` gate `validate` does and refuses a
    // candidate that would not load, so a snapshot id only exists if it passed.
    await seedD1("gateway-configs", [{ id: "cfg_1", config: {} }]);

    const reloaded = await SELF.fetch(
      `${BASE}/admin/v1/config/reload`,
      jsonRequest(KEY, "POST", { gateway_config_id: "cfg_1" }),
    );
    expect(reloaded.status).toBe(200);
    const promoted = (await reloaded.json()) as { config_snapshot_id: string | null };
    expect(promoted.config_snapshot_id).toEqual(expect.any(String));

    // The status endpoint reads the SAME durable activation record, so the two
    // cannot disagree about which config is current.
    expect((await status()).snapshot).toBe(promoted.config_snapshot_id);
    expect((await status()).snapshot).not.toBe("unversioned");
  });

  it("counts real rows from the durable store", async () => {
    await seedD1("providers", [{ id: "p1" }, { id: "p2" }]);
    expect((await status()).providers).toBe(2);
  });

  it("still answers when a sub-source cannot be read (status is the debugging endpoint)", async () => {
    const body = await status();
    expect(body.service).toBe("ferrogate-control-plane");
    // Rust reports `"pingora"`; this data plane is a Worker and says so.
    expect(body.runtime).toBe("workers");
    expect(body.auth_required).toBe(true);
  });
});

describe("PLATFORM LIMIT: a config reload cannot swap a live isolate's snapshot", () => {
  beforeEach(async () => {
    await resetD1();
    arm({ staticKeys: [operatorKey], store: "d1" });
  });

  it("reports `applied: false` — it promotes durably, it does not swap a fleet", async () => {
    await seedD1("gateway-configs", [{ id: "cfg_1", config: {} }]);

    const response = await SELF.fetch(
      `${BASE}/admin/v1/config/reload`,
      jsonRequest(KEY, "POST", { gateway_config_id: "cfg_1" }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      status: string;
      applied: boolean;
      propagation: string;
    };
    expect(body.status).toBe("accepted");
    // There is no process to signal: isolates are created and evicted by the
    // platform and nothing can reach into a running one. `applied: true` would
    // be a lie an operator acts on during an incident.
    expect(body.applied).toBe(false);
    expect(body.propagation).toBe("on_next_isolate_config_read");
  });

  it("still REFUSES a candidate that would not load — the safe half is real", async () => {
    await seedD1("gateway-configs", [
      { id: "cfg_bad", config: { providers: "not-a-list-of-providers" } },
    ]);

    const response = await SELF.fetch(
      `${BASE}/admin/v1/config/reload`,
      jsonRequest(KEY, "POST", { gateway_config_id: "cfg_bad" }),
    );
    expect(response.status).toBe(409);
    expect((await response.json()) as { error: { code: string } }).toMatchObject({
      error: { code: "config_reload_rejected" },
    });

    // And the rejected candidate did NOT become the active snapshot.
    expect((await status()).snapshot).toBe("unversioned");
  });
});

describe("PLATFORM LIMIT: the observability feed has no readable Analytics Engine", () => {
  beforeEach(async () => {
    await resetD1();
    arm({ staticKeys: [operatorKey], store: "d1" });
  });

  it("answers an EMPTY list rather than fabricating series", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/observability`, { headers: bearer(KEY) });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { object: string; data: unknown[] };
    expect(body.object).toBe("list");
    // Empty means "this deployment exposes no queryable series". Anything here
    // that was not read from a real source would be a fabricated metric.
    expect(body.data).toEqual([]);
  });

  it("/metrics exposes only gauges the control plane can actually answer", async () => {
    await seedD1("request-logs", [{ id: "r1" }, { id: "r2" }, { id: "r3" }]);

    const response = await SELF.fetch(`${BASE}/metrics`, { headers: bearer(KEY) });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/plain; version=0.0.4; charset=utf-8");

    const text = await response.text();
    expect(text).toContain("ferrogate_control_plane_up 1");
    // A real count off the durable store, not a placeholder zero.
    expect(text).toContain("ferrogate_request_log_entries 3");
    // NOT the gateway's snapshot: this Worker measures no upstream latency or
    // token counters, so publishing those series (as zeros) would read on a
    // dashboard as "the gateway served no traffic".
    expect(text).not.toContain("ferrogate_upstream");
    expect(text).not.toContain("ferrogate_tokens");
  });
});
