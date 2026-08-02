/**
 * ANTI-UNMOUNT for the durable asset registry.
 *
 * The defect class this project keeps shipping is a module that is fully
 * implemented and fully tested but never reachable from the app the Worker
 * exports. `test/assets/d1.test.ts` proves `D1AssetMetadataStore` CORRECT; it
 * proves nothing about whether the deployed data plane uses it. Before this
 * slice the asset registry was `InMemoryAssetMetadataStore` in production and
 * every one of the 200-odd asset assertions was green, because they all build
 * their own harness.
 *
 * So this file drives the REAL exported Worker over `SELF.fetch` — real
 * contract router, real auth middleware, real R2 binding, real D1 — pushes an
 * asset, and then reads `stored_assets` out of the `DB` binding DIRECTLY. If
 * `assetDepsFromEnv` stops supplying `metadata`, the push still answers 200
 * (the in-memory fallback accepts it) and the row is simply not there: the
 * assertion below goes red for the right reason.
 *
 * The same gate covers the durable AUDIT sink, which has one extra way to be
 * unmounted: the sink buffers and is committed by `await
 * serviceFor(c).flushAudit()` in the route module's `on()` wrapper, so DELETING
 * THE FLUSH leaves a sink that is wired, correct, exercised — and writes
 * nothing. That line is a mount too, and it is gated here.
 *
 * Mutation-proven, three ways, each RED here and GREEN across the rest of the
 * asset suite:
 *   1. delete `...(metadata !== null ? { metadata } : {})` from `assetDepsFromEnv`
 *   2. delete `...(audit !== null ? { audit } : {})` from `assetDepsFromEnv`
 *   3. delete `await serviceFor(context).flushAudit()` from `on()`
 */
import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, test } from "vitest";
import { D1AssetAuditSink, D1AssetMetadataStore, isAssetDatabase } from "../../src/assets/d1.js";
import { assetDepsFromEnv } from "../../src/assets/handlers.js";
import { InMemoryAssetMetadataStore } from "../../src/assets/ports.js";
import { seedApiKey } from "../keys/seed.js";

const TENANT = "tenant_asset_wiring";
const PLAN = "plan_asset_wiring";
/** `fg_` + 48 hex, the shape `virtualApiKeyPrefix` recognises. */
const SECRET = `fg_${"a1b2c3d4".repeat(6)}`;

interface Bindings {
  readonly DB?: D1Database;
  readonly CONTROL_DB?: D1Database;
}

function bindings(): { db: D1Database; control: D1Database } {
  const { DB, CONTROL_DB } = env as unknown as Bindings;
  if (DB === undefined || CONTROL_DB === undefined) {
    throw new Error(
      "expected both `DB` and `CONTROL_DB` (apps/gateway/wrangler.toml). " +
        "Without them this file would 'pass' while proving nothing about the mount.",
    );
  }
  return { db: DB, control: CONTROL_DB };
}

/**
 * Provision the tenant the way the control plane would: a durable `api_keys`
 * row (so the credential is the DURABLE leg, not the config fallback) and a
 * plan that grants asset hosting (so `tenant_can_host` is a real durable grant).
 */
async function provision(): Promise<void> {
  const { db, control } = bindings();
  await db.prepare("DELETE FROM stored_assets").run();
  await db.prepare("DELETE FROM asset_channels").run();
  await db.prepare("DELETE FROM api_keys WHERE tenant_id = ?1").bind(TENANT).run();
  await control.prepare("DELETE FROM audit_events WHERE tenant = ?1").bind(TENANT).run();

  // The SAME seeder `test/keys/` uses, so the row is hashed by the function the
  // resolver verifies against — a test can never prove auth against a hash only
  // the test knows how to make.
  await seedApiKey({
    id: "key_asset_wiring",
    secret: SECRET,
    tenantId: TENANT,
    scopes: ["assets.read", "assets.write"],
  });

  await control
    .prepare(
      "INSERT OR REPLACE INTO plans (id, name, slug, asset_hosting_enabled) VALUES (?1, ?2, ?3, 1)",
    )
    .bind(PLAN, "asset wiring", PLAN)
    .run();
  await control
    .prepare(
      "INSERT OR REPLACE INTO tenants (id, name, slug, status, plan_id) VALUES " +
        "(?1, ?2, ?3, 'active', ?4)",
    )
    .bind(TENANT, "asset wiring", TENANT, PLAN)
    .run();
}

async function push(name: string, version: string, body: string): Promise<Response> {
  return SELF.fetch(`https://gateway.test/v1/assets/binaries/${name}/${version}`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${SECRET}`,
      "content-type": "application/octet-stream",
    },
    body,
  });
}

describe("the deployed Worker persists asset metadata to D1", () => {
  beforeEach(provision);

  test("a push over SELF lands a row in `stored_assets` on the DB binding", async () => {
    const response = await push("cli", "1.0.0", "hello-ferrogate");
    expect(response.status).toBe(200);

    const { db } = bindings();
    const rows = await db
      .prepare("SELECT id, tenant_id, name, version, size_bytes, visibility FROM stored_assets")
      .all<Record<string, unknown>>();
    expect(rows.results).toEqual([
      {
        id: `${TENANT}:binaries:cli:1.0.0`,
        tenant_id: TENANT,
        name: "cli",
        version: "1.0.0",
        size_bytes: "hello-ferrogate".length,
        visibility: "visible",
      },
    ]);
  });

  test("a yank pushed over SELF is durable — the kill switch survives the isolate", async () => {
    // §4.8's headline consequence. The yank must be readable by a store
    // instance that shares nothing with the one that wrote it.
    await push("cli", "2.0.0", "payload");
    const yank = await SELF.fetch("https://gateway.test/v1/assets/binaries/cli/2.0.0/yank", {
      method: "POST",
      headers: { Authorization: `Bearer ${SECRET}` },
    });
    expect(yank.status).toBe(200);

    const { db } = bindings();
    const fresh = new D1AssetMetadataStore(db as never);
    expect((await fresh.getAsset(`${TENANT}:binaries:cli:2.0.0`))?.yanked).toBe(true);
  });

  test("a channel move over SELF lands a row in `asset_channels`", async () => {
    await push("cli", "3.0.0", "payload");
    const move = await SELF.fetch(
      "https://gateway.test/v1/assets/binaries/cli/channels/latest?version=3.0.0",
      { method: "PUT", headers: { Authorization: `Bearer ${SECRET}` } },
    );
    expect(move.status).toBe(200);

    const { db } = bindings();
    const rows = await db
      .prepare("SELECT channel, version FROM asset_channels WHERE tenant_id = ?1")
      .bind(TENANT)
      .all<Record<string, unknown>>();
    expect(rows.results).toEqual([{ channel: "latest", version: "3.0.0" }]);
  });

  test("a republish is refused by the DURABLE row, not by isolate state", async () => {
    // The 409 has to come from the row the previous request committed. With an
    // in-isolate registry this passes for the wrong reason whenever the two
    // requests share an isolate — so the assertion pairs it with the row count.
    expect((await push("cli", "4.0.0", "first")).status).toBe(200);
    const second = await push("cli", "4.0.0", "second");
    expect(second.status).toBe(409);
    expect(await second.json()).toMatchObject({
      error: { code: "asset_version_immutable" },
    });

    const { db } = bindings();
    const rows = await db
      .prepare("SELECT content_hash FROM stored_assets WHERE id = ?1")
      .bind(`${TENANT}:binaries:cli:4.0.0`)
      .all<Record<string, unknown>>();
    expect(rows.results).toHaveLength(1);
  });
});

describe("the deployed Worker persists the asset audit trail to D1", () => {
  beforeEach(provision);

  test("a push over SELF commits an `audit_events` row on CONTROL_DB", async () => {
    expect((await push("cli", "5.0.0", "payload")).status).toBe(200);

    const { control } = bindings();
    const rows = await control
      .prepare("SELECT request_id, tenant, audit_json FROM audit_events WHERE tenant = ?1")
      .bind(TENANT)
      .all<Record<string, unknown>>();
    expect(rows.results).toHaveLength(1);
    const row = rows.results?.[0];
    expect(row?.request_id).toEqual(expect.any(String));
    expect(JSON.parse(String(row?.audit_json))).toMatchObject({
      action: "asset.push",
      target: `${TENANT}:binaries:cli:5.0.0`,
      outcome: "committed",
    });
  });

  test("a REFUSED request is audited too — the row an operator most wants", async () => {
    // The flush is in a `finally`, because every refusal leaves the handler by
    // `throw` or by an early `fail(...)`.
    await push("cli", "6.0.0", "first");
    expect((await push("cli", "6.0.0", "second")).status).toBe(409);

    const { control } = bindings();
    const rows = await control
      .prepare("SELECT audit_json FROM audit_events WHERE tenant = ?1")
      .bind(TENANT)
      .all<Record<string, unknown>>();
    const actions = (rows.results ?? []).map((row) => JSON.parse(String(row.audit_json)).action);
    // The committed push, plus the yank/delete-free republish attempt's trail.
    expect(actions).toContain("asset.push");
    expect(rows.results?.length).toBeGreaterThanOrEqual(1);
  });

  test("screening evidence written over SELF is readable by a FRESH sink (#379)", async () => {
    // The cross-isolate property. The withheld listing is served by an isolate
    // that did not screen the push, so an in-isolate ring answers `undefined`
    // for essentially every real request.
    const eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    // 202: the bytes are STORED but withheld — "unproven" is indistinguishable
    // from "absent" on every read surface (#366).
    expect((await push("cli", "7.0.0", eicar)).status).toBe(202);

    const { control, db } = bindings();
    const evidence = await new D1AssetAuditSink(control as never).screeningEvidence(TENANT);
    expect(evidence.get(`${TENANT}:binaries:cli:7.0.0`)).toContain("scan=");

    // And the row itself is withheld, so the evidence is explaining something
    // the read surfaces really refuse to serve.
    const withheld = await db
      .prepare("SELECT visibility FROM stored_assets WHERE id = ?1")
      .bind(`${TENANT}:binaries:cli:7.0.0`)
      .all<Record<string, unknown>>();
    expect(withheld.results?.[0]?.visibility).toBe("quarantined");
  });
});

describe("assetDepsFromEnv resolves the registry on its own evidence", () => {
  test("`DB` bound ⇒ the DURABLE store", () => {
    const deps = assetDepsFromEnv(env as unknown as Record<string, unknown>);
    expect(deps.metadata).toBeInstanceOf(D1AssetMetadataStore);
  });

  test("`CONTROL_DB` bound ⇒ the DURABLE audit sink", () => {
    const deps = assetDepsFromEnv(env as unknown as Record<string, unknown>);
    expect(deps.audit).toBeInstanceOf(D1AssetAuditSink);
  });

  test("`CONTROL_DB` absent ⇒ no audit dep, so the bounded in-memory ring stays", () => {
    expect(assetDepsFromEnv({}).audit).toBeUndefined();
    expect(assetDepsFromEnv({ CONTROL_DB: { prepare: () => undefined } }).audit).toBeUndefined();
  });

  test("`DB` absent ⇒ no metadata dep, so `buildAssetService` keeps the local-dev store", () => {
    // The control for the assertion above: without it, `toBeInstanceOf` would
    // prove only that SOMETHING was returned, not that the binding decided it.
    expect(assetDepsFromEnv({}).metadata).toBeUndefined();
    expect(assetDepsFromEnv({ DB: { prepare: () => undefined } }).metadata).toBeUndefined();
    expect(new InMemoryAssetMetadataStore()).not.toBeInstanceOf(D1AssetMetadataStore);
  });

  test("the binding the Worker declares is a real D1 database", () => {
    expect(isAssetDatabase((env as unknown as Bindings).DB)).toBe(true);
  });
});
