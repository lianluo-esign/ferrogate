/**
 * Self-hosted worker state belongs to the tenant object (#856).
 *
 * These tests inspect the object database rather than the HTTP response. A
 * generic control-plane document can make registration look successful while
 * leaving the worker runtime with no tenant-owned state at all.
 */
import { SELF, env } from "cloudflare:test";
import { DurableObjectD1Database, type TenantDatabaseRouter } from "@ferrogate/storage";
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import type { ControlPlaneBindings } from "../src/ports.js";
import {
  openTenantManagedWorkerRepository,
  openTenantWorkerRepository,
  type TenantWorkerIdentity,
} from "../src/store/tenant-worker.js";
import { openTenantScheduleRepository } from "../src/schedule/tenant-schedule.js";
import { resolveTenantStorage } from "../src/adapters.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, jsonRequest, operatorKey } from "./harness.js";

function tenantNamespace(): TenantDataNamespace {
  const namespace = (env as unknown as { TENANT_DATA?: TenantDataNamespace }).TENANT_DATA;
  if (namespace === undefined) throw new Error("tenant worker tests require TENANT_DATA");
  return namespace;
}

function tenantDb(tenantId: string): D1Database {
  const namespace = tenantNamespace();
  return new DurableObjectD1Database(
    tenantId,
    namespace.get(namespace.idFromName(tenantId)),
  ).asD1Database();
}

function freshTenant(label: string): string {
  return `worker_state_${label}_${crypto.randomUUID().slice(0, 8)}`;
}

async function provisionObjectTenant(tenantId: string): Promise<void> {
  await db()
    .prepare(
      `INSERT INTO tenant_databases
         (tenant_id, storage_backend, provisioning_status, schema_version,
          binding_name, migration_state, provisioned_at_unix, updated_at_unix)
       VALUES (?, 'durable_object', 'ready', 17, NULL, 'done', 1, 1)`,
    )
    .bind(tenantId)
    .run();
}

function identity(tenantId: string, workerId = "worker-1"): TenantWorkerIdentity {
  return {
    tenantId,
    workerId,
    workspaceId: "workspace-1",
    tokenId: "token-1",
    tokenSecret: "secret-1",
    status: "active",
    document: { id: workerId, tenant_id: tenantId, worker_id: workerId },
    registeredAtUnix: 100,
    updatedAtUnix: 100,
  };
}

describe("tenant worker repository", () => {
  beforeAll(applySchema);

  beforeEach(async () => {
    arm({ store: "d1", staticKeys: [operatorKey] });
    await resetD1();
    await db().prepare("DELETE FROM self_hosted_worker_registrations").run();
    // Each test uses fresh object names. Waking the object here also applies
    // the real tenant migration before the adapter is exercised.
    await tenantDb(freshTenant("schema")).prepare("SELECT 1").first();
  });

  test("writes identity and worker evidence into the tenant object", async () => {
    const tenantId = freshTenant("writes");
    const repository = await openTenantWorkerRepository(
      resolveTenantStorage(env as unknown as ControlPlaneBindings),
      tenantId,
    );
    expect(repository).not.toBeNull();

    await repository?.upsertIdentity(identity(tenantId));
    await repository?.recordHeartbeat("worker-1", { status: "active", load: 0.2 }, 101);
    await repository?.recordArtifact("worker-1", { artifact_id: "artifact-1", sha256: "abc" }, 102);
    await repository?.recordCheckpoint("worker-1", { checkpoint_id: "checkpoint-1" }, 103);
    await repository?.recordTelemetry("worker-1", { kind: "started" }, 104);

    expect(
      (
        await tenantDb(tenantId)
          .prepare("SELECT tenant_id, token_id, token_secret FROM self_hosted_worker_identities")
          .all()
      ).results,
    ).toEqual([{ tenant_id: tenantId, token_id: "token-1", token_secret: "secret-1" }]);
    expect(
      (
        await tenantDb(tenantId)
          .prepare("SELECT worker_id, reported_at_unix FROM self_hosted_worker_heartbeats")
          .all()
      ).results,
    ).toEqual([{ worker_id: "worker-1", reported_at_unix: 101 }]);
    expect(
      (
        await tenantDb(tenantId)
          .prepare("SELECT worker_id, artifact_json FROM self_hosted_worker_artifacts")
          .all()
      ).results,
    ).toEqual([
      {
        worker_id: "worker-1",
        artifact_json: JSON.stringify({ artifact_id: "artifact-1", sha256: "abc" }),
      },
    ]);
    expect(
      (
        await tenantDb(tenantId)
          .prepare("SELECT worker_id, checkpoint_json FROM self_hosted_worker_checkpoints")
          .all()
      ).results,
    ).toEqual([
      {
        worker_id: "worker-1",
        checkpoint_json: JSON.stringify({ checkpoint_id: "checkpoint-1" }),
      },
    ]);
    expect(
      (
        await tenantDb(tenantId)
          .prepare("SELECT worker_id, event_json FROM self_hosted_worker_telemetry_events")
          .all()
      ).results,
    ).toEqual([
      { worker_id: "worker-1", event_json: JSON.stringify({ kind: "started" }) },
    ]);
  });

  test("writes managed worker lifecycle state into the tenant object", async () => {
    const tenantId = freshTenant("managed");
    const repository = await openTenantManagedWorkerRepository(
      resolveTenantStorage(env as unknown as ControlPlaneBindings),
      tenantId,
    );
    expect(repository).not.toBeNull();

    await repository?.upsertTemplate("template-1", { name: "default" });
    await repository?.upsertInstance("instance-1", { workspace_id: "workspace-1" }, 201);
    await repository?.upsertSession("session-1", { instance_id: "instance-1" }, 202);
    await repository?.appendLifecycleEvent("event-1", { kind: "started" }, 203);
    await repository?.upsertIsolationSelection("session-1", { backend: "gvisor" }, 204);
    await repository?.upsertIsolationPolicy("session-1", { allow_network: false });

    const object = tenantDb(tenantId);
    expect(
      await object.prepare("SELECT template_json FROM managed_worker_templates").first(),
    ).toEqual({ template_json: JSON.stringify({ name: "default" }) });
    expect(
      await object.prepare("SELECT instance_json FROM agent_worker_instances").first(),
    ).toEqual({ instance_json: JSON.stringify({ workspace_id: "workspace-1" }) });
    expect(
      await object.prepare("SELECT session_json FROM managed_worker_sessions").first(),
    ).toEqual({ session_json: JSON.stringify({ instance_id: "instance-1" }) });
    expect(
      await object.prepare("SELECT event_json FROM managed_worker_lifecycle_events").first(),
    ).toEqual({ event_json: JSON.stringify({ kind: "started" }) });
    expect(
      await object.prepare("SELECT selection_json FROM managed_worker_isolation_selections").first(),
    ).toEqual({ selection_json: JSON.stringify({ backend: "gvisor" }) });
    expect(
      await object.prepare("SELECT policy_json FROM managed_worker_isolation_policies").first(),
    ).toEqual({ policy_json: JSON.stringify({ allow_network: false }) });
  });

  test("migrates legacy schedule documents and fire history before typed reads", async () => {
    const tenantId = freshTenant("schedule-migration");
    await provisionObjectTenant(tenantId);
    const scheduleId = `legacy-schedule-${crypto.randomUUID().slice(0, 8)}`;
    const legacySchedule = {
      id: scheduleId,
      tenant_id: tenantId,
      workspace_id: "workspace-legacy",
      name: "legacy interval",
      enabled: true,
      spec_kind: "interval",
      interval_secs: 60,
      target_kind: "agent_run",
      target: { agent: "legacy" },
      overlap_policy: "skip",
      catchup_policy: "skip_missed",
      jitter_secs: 0,
      next_fire_at_unix: 1_000,
      last_fire_at_unix: null,
    };
    await db()
      .prepare(
        `INSERT INTO control_plane_resources
           (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind("agent-schedules", scheduleId, JSON.stringify(legacySchedule), 4, 10, 20)
      .run();
    await db()
      .prepare(
        `INSERT INTO control_plane_resources
           (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        "agent-schedule-fires",
        "legacy-fire-1",
        JSON.stringify({
          id: "legacy-fire-1",
          tenant_id: tenantId,
          schedule_id: scheduleId,
          scheduled_fire_at_unix: 940,
          fired_at_unix: 941,
          outcome: "dispatched",
          detail: "legacy",
        }),
        1,
        11,
        21,
      )
      .run();

    const router = resolveTenantStorage(env as unknown as ControlPlaneBindings);
    const first = await openTenantScheduleRepository(router, tenantId, db());
    expect(first).not.toBeNull();
    const migrated = await first?.store.getSchedule(scheduleId);
    expect(migrated).toMatchObject({
      scheduleId,
      tenantId,
      revision: 4,
      nextFireAtUnix: 1_000,
    });
    expect(await first?.store.listScheduleFires(scheduleId, 10)).toMatchObject([
      { fireId: "legacy-fire-1", scheduledFireAtUnix: 940, detail: "legacy" },
    ]);

    const second = await openTenantScheduleRepository(router, tenantId, db());
    expect(await second?.store.listScheduleFires(scheduleId, 10)).toHaveLength(1);
  });

  test("keeps two tenant objects physically separate", async () => {
    const first = freshTenant("first");
    const second = freshTenant("second");
    const router = resolveTenantStorage(env as unknown as ControlPlaneBindings);
    const firstRepository = await openTenantWorkerRepository(router, first);
    const secondRepository = await openTenantWorkerRepository(router, second);

    await firstRepository?.upsertIdentity(identity(first, "same-worker-id"));
    await secondRepository?.upsertIdentity(identity(second, "same-worker-id"));

    expect(
      await tenantDb(first)
        .prepare("SELECT tenant_id FROM self_hosted_worker_identities WHERE worker_id = ?")
        .bind("same-worker-id")
        .first(),
    ).toEqual({ tenant_id: first });
    expect(
      await tenantDb(second)
        .prepare("SELECT tenant_id FROM self_hosted_worker_identities WHERE worker_id = ?")
        .bind("same-worker-id")
        .first(),
    ).toEqual({ tenant_id: second });
  });

  test("does not treat a non-object handle as tenant worker authority", async () => {
    const nonObjectRouter: TenantDatabaseRouter = {
      control: () => undefined as unknown as D1Database,
      forTenant: async (tenantId) => ({
        tenantId,
        db: undefined as unknown as D1Database,
        source: "shared_development",
        supportsAtomicBatch: true,
      }),
      provisionedTenants: async () => [],
    };

    expect(await openTenantWorkerRepository(nonObjectRouter, "tenant_shared")).toBeNull();
  });

  test("admin writes all self-hosted worker evidence into the tenant object", async () => {
    const tenantId = freshTenant("http");
    const workerId = `worker-${crypto.randomUUID().slice(0, 8)}`;
    await provisionObjectTenant(tenantId);
    const register = await SELF.fetch(
      `${BASE}/admin/v1/self-hosted-workers`,
      jsonRequest(operatorKey.secret, "POST", {
        id: workerId,
        tenant_id: tenantId,
        workspace_id: "workspace-http",
        name: "object-backed worker",
      }),
    );
    expect(register.status, await register.clone().text()).toBe(201);

    for (const [path, body] of [
      [`heartbeat`, {}],
      [`artifacts`, { artifact_id: "artifact-http", sha256: "abc" }],
      [`checkpoints`, { checkpoint_id: "checkpoint-http" }],
      [`events`, { kind: "started", payload: { source: "test" } }],
    ] as const) {
      const response = await SELF.fetch(
        `${BASE}/admin/v1/self-hosted-workers/${workerId}/${path}`,
        jsonRequest(operatorKey.secret, "POST", body),
      );
      expect(response.status, await response.clone().text()).toBe(path === "heartbeat" ? 200 : 201);
    }

    const object = tenantDb(tenantId);
    expect(
      await object
        .prepare("SELECT worker_id, workspace_id FROM self_hosted_worker_identities")
        .first(),
    ).toEqual({ worker_id: workerId, workspace_id: "workspace-http" });
    expect(
      await object
        .prepare("SELECT COUNT(*) AS total FROM self_hosted_worker_heartbeats WHERE worker_id = ?")
        .bind(workerId)
        .first(),
    ).toEqual({ total: 1 });
    expect(
      await object
        .prepare("SELECT COUNT(*) AS total FROM self_hosted_worker_artifacts WHERE worker_id = ?")
        .bind(workerId)
        .first(),
    ).toEqual({ total: 1 });
    expect(
      await object
        .prepare("SELECT COUNT(*) AS total FROM self_hosted_worker_checkpoints WHERE worker_id = ?")
        .bind(workerId)
        .first(),
    ).toEqual({ total: 1 });
    expect(
      await object
        .prepare("SELECT COUNT(*) AS total FROM self_hosted_worker_telemetry_events WHERE worker_id = ?")
        .bind(workerId)
        .first(),
    ).toEqual({ total: 1 });
  });

  test("does not move a bootstrap worker id across tenant or workspace", async () => {
    const workerId = `worker-${crypto.randomUUID().slice(0, 8)}`;
    const firstTenant = freshTenant("first-registry");
    await provisionObjectTenant(firstTenant);
    const first = await SELF.fetch(
      `${BASE}/admin/v1/self-hosted-workers`,
      jsonRequest(operatorKey.secret, "POST", {
        id: workerId,
        tenant_id: firstTenant,
        workspace_id: "workspace-one",
      }),
    );
    expect(first.status, await first.clone().text()).toBe(201);

    const secondTenant = freshTenant("second-registry");
    const second = await SELF.fetch(
      `${BASE}/admin/v1/self-hosted-workers`,
      jsonRequest(operatorKey.secret, "POST", {
        id: workerId,
        tenant_id: secondTenant,
        workspace_id: "workspace-two",
      }),
    );
    expect(second.status, await second.clone().text()).toBe(409);
    expect(
      await tenantDb(secondTenant)
        .prepare("SELECT worker_id FROM self_hosted_worker_identities WHERE worker_id = ?")
        .bind(workerId)
        .first(),
    ).toBeNull();
  });

  test("hydrates a legacy worker identity before child evidence writes", async () => {
    const tenantId = freshTenant("legacy-child");
    const workerId = `worker-${crypto.randomUUID().slice(0, 8)}`;
    await provisionObjectTenant(tenantId);
    const register = await SELF.fetch(
      `${BASE}/admin/v1/self-hosted-workers`,
      jsonRequest(operatorKey.secret, "POST", {
        id: workerId,
        tenant_id: tenantId,
        workspace_id: "workspace-legacy",
      }),
    );
    expect(register.status, await register.clone().text()).toBe(201);
    await tenantDb(tenantId)
      .prepare("DELETE FROM self_hosted_worker_identities WHERE worker_id = ?")
      .bind(workerId)
      .run();

    const artifact = await SELF.fetch(
      `${BASE}/admin/v1/self-hosted-workers/${workerId}/artifacts`,
      jsonRequest(operatorKey.secret, "POST", { artifact_id: "artifact-legacy" }),
    );
    expect(artifact.status, await artifact.clone().text()).toBe(201);
    expect(
      await tenantDb(tenantId)
        .prepare("SELECT worker_id FROM self_hosted_worker_identities WHERE worker_id = ?")
        .bind(workerId)
        .first(),
    ).toEqual({ worker_id: workerId });
  });

  test("a tenant schedule dispatch is recorded in the tenant object queue", async () => {
    const tenantId = freshTenant("dispatch");
    const workerId = `worker-${crypto.randomUUID().slice(0, 8)}`;
    await provisionObjectTenant(tenantId);
    const register = await SELF.fetch(
      `${BASE}/admin/v1/self-hosted-workers`,
      jsonRequest(operatorKey.secret, "POST", {
        id: workerId,
        tenant_id: tenantId,
        workspace_id: "workspace-dispatch",
      }),
    );
    expect(register.status, await register.clone().text()).toBe(201);

    const scheduleId = `schedule-${crypto.randomUUID().slice(0, 8)}`;
    const created = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules`,
      jsonRequest(operatorKey.secret, "POST", {
        id: scheduleId,
        tenant_id: tenantId,
        workspace_id: "workspace-dispatch",
        cron_expr: "*/5 * * * *",
        target_kind: "self_hosted_dispatch",
        target: { worker_id: workerId, input: "hello" },
      }),
    );
    expect(created.status, await created.clone().text()).toBe(201);

    const runNow = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules/${scheduleId}/run-now`,
      jsonRequest(operatorKey.secret, "POST", {}),
    );
    expect(runNow.status, await runNow.clone().text()).toBe(202);

    const dispatch = await tenantDb(tenantId)
      .prepare("SELECT dispatch_id, dispatch_json FROM self_hosted_run_dispatches")
      .first<{ dispatch_id: string; dispatch_json: string }>();
    expect(dispatch?.dispatch_id).toContain(`schedule-dispatch-${scheduleId}-`);
    expect(JSON.parse(dispatch?.dispatch_json ?? "{}")).toMatchObject({ worker_id: workerId });
  });
});
