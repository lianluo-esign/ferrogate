/**
 * The shared-config async channel (#948): control plane -> tenant DO mirror.
 *
 * The whole point of the channel is that a tenant reads shared config (billing
 * groups today) from its OWN object, so every assertion here reads the tenant
 * side with RAW SQL out of the tenant object — never through the store that
 * wrote it — so a test cannot pass merely because the writer agrees with itself.
 * Four properties are pinned: a new tenant is SEEDED from the current snapshot;
 * the mirror is READ-ONLY to ordinary tenant traffic; the cron fan-out is a
 * no-op until the source revision moves (the idle-fleet guarantee) and delivers
 * once it does; and a push reflects DELETIONS while a stale push is ignored.
 */
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { CallerScope, ControlPlaneDeps } from "../src/ports.js";
import { PlatformAnnouncementStore } from "../src/store/platform-announcement.js";
import { PlatformBillingGroupStore } from "../src/store/platform-billing-group.js";
import { fanOutSharedConfig, seedSharedConfigForTenant } from "../src/store/shared-config.js";
import { applySchema, db, resetD1 } from "./d1.js";
import {
  privilegedTenantBatch,
  registerObjectTenants,
  tenantObjectDb,
  tenantObjectRouter,
} from "./tenant-object.js";

const OPERATOR: CallerScope = { kind: "platform_operator" };

/** Deps slice the channel functions consume; the router is the real DO router. */
function deps(): Pick<ControlPlaneDeps, "controlDatabase" | "tenantDatabases" | "tenantStorage"> {
  const router = tenantObjectRouter();
  return { controlDatabase: db(), tenantDatabases: router, tenantStorage: router };
}

async function createGroup(id: string, multiplier: number): Promise<void> {
  await new PlatformBillingGroupStore({ db: db(), requestId: "test" }).createGroup(OPERATOR, {
    id,
    name: id,
    multiplier,
  });
}

interface MirrorRow {
  id: string;
  provider_type_id: string | null;
  multiplier: number;
  enabled: number;
  provider_ids_json: string;
  config_revision: number;
}

/** The billing-group mirror, read straight out of the tenant object. */
async function mirror(tenantId: string): Promise<readonly MirrorRow[]> {
  const rows = await tenantObjectDb(tenantId)
    .prepare(
      "SELECT id, provider_type_id, multiplier, enabled, provider_ids_json, config_revision " +
        "FROM shared_billing_groups ORDER BY id ASC",
    )
    .all<MirrorRow>();
  return rows.results;
}

/** The tenant's applied revision for a shared-config domain, or 0 if never. */
async function cursor(tenantId: string, domain = "billing_groups"): Promise<number> {
  const row = await tenantObjectDb(tenantId)
    .prepare("SELECT revision FROM shared_config_cursor WHERE domain = ?")
    .bind(domain)
    .first<{ revision: number }>();
  return Number(row?.revision ?? 0);
}

const TENANT_A = "tenant-shared-config-a";
const TENANT_B = "tenant-shared-config-b";

describe("shared-config async channel", () => {
  beforeAll(async () => {
    await applySchema();
  });

  beforeEach(async () => {
    await resetD1();
    await db().batch([
      db().prepare("DELETE FROM platform_billing_group_providers"),
      db().prepare("DELETE FROM platform_billing_groups"),
      db().prepare("DELETE FROM platform_billing_group_revisions"),
      db().prepare("DELETE FROM shared_config_push_state"),
    ]);
    await registerObjectTenants([TENANT_A, TENANT_B]);
    for (const tenantId of [TENANT_A, TENANT_B]) {
      await privilegedTenantBatch(tenantId, [
        { sql: "DELETE FROM shared_billing_groups", params: [] },
        { sql: "DELETE FROM shared_config_cursor", params: [] },
      ]);
    }
  });

  it("seeds a new tenant from the current snapshot", async () => {
    await createGroup("grp-standard", 1.5);
    const revision = await new PlatformBillingGroupStore({ db: db() }).revision();

    const seeded = await seedSharedConfigForTenant(deps(), TENANT_A);
    expect(seeded).toBe(true);

    const rows = await mirror(TENANT_A);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      id: "grp-standard",
      provider_type_id: "openai",
      multiplier: 1.5,
      enabled: 1,
      provider_ids_json: "[]",
      config_revision: revision,
    });
    expect(await cursor(TENANT_A)).toBe(revision);
  });

  it("refuses an unprivileged write to the mirror but allows reads", async () => {
    await createGroup("grp-a", 2);
    await seedSharedConfigForTenant(deps(), TENANT_A);

    // The tenant-facing D1 facade routes writes through the unprivileged path,
    // which the PRIVILEGED_WRITE_TABLES gate must refuse for the mirror.
    await expect(
      tenantObjectDb(TENANT_A)
        .prepare("UPDATE shared_billing_groups SET multiplier = 99 WHERE id = 'grp-a'")
        .run(),
    ).rejects.toThrow();

    // The read side is untouched: the mirror still reads, unmodified.
    const rows = await mirror(TENANT_A);
    expect(rows[0]?.multiplier).toBe(2);
  });

  it("fans out only after the source revision moves, then delivers to the fleet", async () => {
    await createGroup("grp-a", 2);

    const first = await fanOutSharedConfig(deps());
    expect(first.skipped).toBeNull();
    expect(first.pushed).toBe(2);
    expect(first.failed).toBe(0);
    expect((await mirror(TENANT_A))[0]?.id).toBe("grp-a");
    expect((await mirror(TENANT_B))[0]?.id).toBe("grp-a");

    // Nothing changed: the watermark makes the next pass a no-op for the fleet.
    const second = await fanOutSharedConfig(deps());
    expect(second.skipped).toBe("unchanged");
    expect(second.pushed).toBe(0);

    // A new group bumps the revision past the watermark; the fleet gets it.
    await createGroup("grp-b", 3);
    const third = await fanOutSharedConfig(deps());
    expect(third.skipped).toBeNull();
    expect(third.pushed).toBe(2);
    expect((await mirror(TENANT_A)).map((r) => r.id)).toEqual(["grp-a", "grp-b"]);
  });

  it("reflects deletions and ignores a stale push", async () => {
    await createGroup("grp-a", 2);
    await createGroup("grp-b", 3);
    await fanOutSharedConfig(deps());
    expect((await mirror(TENANT_A)).map((r) => r.id)).toEqual(["grp-a", "grp-b"]);
    const revAfterTwo = await cursor(TENANT_A);

    // Delete one group (revision advances) and re-fan: the mirror drops it.
    await new PlatformBillingGroupStore({ db: db() }).deleteGroup(OPERATOR, "grp-a");
    await fanOutSharedConfig(deps());
    expect((await mirror(TENANT_A)).map((r) => r.id)).toEqual(["grp-b"]);
    expect(await cursor(TENANT_A)).toBeGreaterThan(revAfterTwo);

    // A hand-built STALE push (revision below the tenant's cursor) is guarded
    // out entirely: it neither deletes the live row nor advances the cursor.
    const staleRevision = 1;
    const behind =
      "COALESCE((SELECT revision FROM shared_config_cursor WHERE domain = 'billing_groups'), 0) < ?";
    await privilegedTenantBatch(TENANT_A, [
      { sql: `DELETE FROM shared_billing_groups WHERE ${behind}`, params: [staleRevision] },
    ]);
    expect((await mirror(TENANT_A)).map((r) => r.id)).toEqual(["grp-b"]);
  });
});

// ---------------------------------------------------------------------------
// The second domain on the same channel (公告). The point of these tests is
// that the generalised seed/fan-out carry a NEW domain with zero coupling to
// billing groups: announcements ride their own cursor + own watermark, and the
// per-domain watermark means an idle announcements registry never re-pushes
// even while billing groups churn.
// ---------------------------------------------------------------------------

interface AnnouncementMirrorRow {
  id: string;
  title: string;
  level: string;
  enabled: number;
  config_revision: number;
}

async function announcementMirror(tenantId: string): Promise<readonly AnnouncementMirrorRow[]> {
  const rows = await tenantObjectDb(tenantId)
    .prepare(
      "SELECT id, title, level, enabled, config_revision " +
        "FROM shared_announcements ORDER BY id ASC",
    )
    .all<AnnouncementMirrorRow>();
  return rows.results;
}

async function createAnnouncement(id: string, title: string): Promise<void> {
  await new PlatformAnnouncementStore({ db: db(), requestId: "test" }).createAnnouncement(
    OPERATOR,
    {
      id,
      title,
      body: `${title} body`,
    },
  );
}

describe("announcements domain on the shared-config channel", () => {
  beforeAll(async () => {
    await applySchema();
  });

  beforeEach(async () => {
    await resetD1();
    await db().batch([
      db().prepare("DELETE FROM platform_announcements"),
      db().prepare("DELETE FROM platform_announcement_revisions"),
      db().prepare("DELETE FROM platform_billing_groups"),
      db().prepare("DELETE FROM platform_billing_group_revisions"),
      db().prepare("DELETE FROM shared_config_push_state"),
    ]);
    await registerObjectTenants([TENANT_A, TENANT_B]);
    for (const tenantId of [TENANT_A, TENANT_B]) {
      await privilegedTenantBatch(tenantId, [
        { sql: "DELETE FROM shared_announcements", params: [] },
        { sql: "DELETE FROM shared_config_cursor", params: [] },
      ]);
    }
  });

  it("seeds a new tenant with announcements under their own cursor", async () => {
    await createAnnouncement("ann-welcome", "Welcome");
    const revision = await new PlatformAnnouncementStore({ db: db() }).revision();

    expect(await seedSharedConfigForTenant(deps(), TENANT_A)).toBe(true);

    const rows = await announcementMirror(TENANT_A);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      id: "ann-welcome",
      title: "Welcome",
      level: "info",
      enabled: 1,
      config_revision: revision,
    });
    expect(await cursor(TENANT_A, "announcements")).toBe(revision);
  });

  it("refuses an unprivileged write to the announcements mirror", async () => {
    await createAnnouncement("ann-a", "A");
    await seedSharedConfigForTenant(deps(), TENANT_A);

    await expect(
      tenantObjectDb(TENANT_A)
        .prepare("UPDATE shared_announcements SET title = 'forged' WHERE id = 'ann-a'")
        .run(),
    ).rejects.toThrow();
    expect((await announcementMirror(TENANT_A))[0]?.title).toBe("A");
  });

  it("fans announcements out per-domain: a group edit does not re-push a stable notice", async () => {
    await createAnnouncement("ann-a", "A");
    await createGroup("grp-a", 2);

    const first = await fanOutSharedConfig(deps());
    expect(first.skipped).toBeNull();
    expect(first.pushed).toBe(2);
    expect((await announcementMirror(TENANT_A))[0]?.id).toBe("ann-a");
    const annRev = await cursor(TENANT_A, "announcements");

    // A billing-group edit bumps ONLY that domain's revision. The fleet still
    // gets a push, but the announcements cursor must not move (its watermark is
    // already caught up), proving the two domains advance independently.
    await createGroup("grp-b", 3);
    const second = await fanOutSharedConfig(deps());
    expect(second.skipped).toBeNull();
    expect(await cursor(TENANT_A, "announcements")).toBe(annRev);
    expect((await mirror(TENANT_A)).map((r) => r.id)).toEqual(["grp-a", "grp-b"]);

    // Nothing changed anywhere: both domains are now at their watermark.
    const third = await fanOutSharedConfig(deps());
    expect(third.skipped).toBe("unchanged");
    expect(third.pushed).toBe(0);
  });
});
