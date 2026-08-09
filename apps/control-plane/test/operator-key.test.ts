/**
 * The platform-operator console credential — the ONE writer of
 * `static_api_keys.platform_operator = 1` (#912).
 *
 * `store/static_keys.ts` hard-binds `platform_operator = 0` for every key the
 * admin API mints, and `api-keys-write-half.test.ts` pins that. This file pins
 * the counterpart: a SUPERADMIN's console session mints a DISTINCT credential
 * that really does resolve to `platformOperator:true`, minted here directly
 * through `provisionPlatformOperatorApiKey` and PROVEN by driving it through the
 * same `deps.apiKeys` authenticator the Worker resolves every request with — not
 * by reading the row back, which would only show the writer agreeing with
 * itself.
 *
 * The world is armed with `store: "d1"` so `resolveApiKeys` wires the real
 * `D1ApiKeyAuthenticator` over the control database this function writes.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolveDeps } from "../src/adapters.js";
import { callerScope } from "../src/ports.js";
import type { ControlPlaneBindings } from "../src/ports.js";
import {
  platformOperatorApiKeyId,
  provisionPlatformOperatorApiKey,
  revokePlatformOperatorApiKey,
} from "../src/session/index.js";
import { hashApiKeySecret } from "../src/store/api_keys.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { arm } from "./harness.js";

function deps() {
  return resolveDeps(env as unknown as ControlPlaneBindings, { requestId: "operator-key-test" });
}

async function staticRow(id: string): Promise<{
  key_hash: string;
  tenant_id: string | null;
  platform_operator: number;
  scopes_json: string | null;
  enabled: number;
  expires_at_unix: number | null;
} | null> {
  return await db()
    .prepare(
      `SELECT key_hash, tenant_id, platform_operator, scopes_json, enabled, expires_at_unix
         FROM static_api_keys WHERE id = ?`,
    )
    .bind(id)
    .first();
}

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  await db().prepare("DELETE FROM static_api_keys").run();
  arm({ store: "d1" });
});

const USER = "user-superadmin";

describe("provisionPlatformOperatorApiKey", () => {
  it("writes platform_operator=1, tenant_id NULL, the least-privilege scopes and a 30d expiry", async () => {
    const before = Math.floor(Date.now() / 1000);
    const secret = await provisionPlatformOperatorApiKey(deps(), USER);
    expect(secret).not.toBeNull();
    expect(String(secret).startsWith("fg_")).toBe(true);

    const row = await staticRow(platformOperatorApiKeyId(USER));
    expect(row).not.toBeNull();
    expect(row?.platform_operator).toBe(1);
    // A durable operator key is untenanted — it sees every tenant.
    expect(row?.tenant_id).toBeNull();
    expect(row?.enabled).toBe(1);
    // Least privilege: the concrete console scopes, NEVER the wildcard.
    expect(JSON.parse(row?.scopes_json ?? "null")).toEqual([
      "admin.read",
      "admin.write",
      "assets.read",
      "assets.write",
    ]);
    // 30-day expiry (the refresh-token TTL), not open-ended.
    const ttl = Number(row?.expires_at_unix) - before;
    expect(ttl).toBeGreaterThanOrEqual(60 * 60 * 24 * 30 - 5);
    expect(ttl).toBeLessThanOrEqual(60 * 60 * 24 * 30 + 5);
    // Only the tagged digest is stored — never the plaintext.
    expect(row?.key_hash).toBe(await hashApiKeySecret(String(secret)));
    expect(row?.key_hash).not.toContain(String(secret));
  });

  it("resolves through deps.apiKeys to a PLATFORM OPERATOR — callerScope is platform_operator", async () => {
    const secret = await provisionPlatformOperatorApiKey(deps(), USER);
    const resolution = await deps().apiKeys.authenticate(String(secret));
    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome !== "resolved") throw new Error("unreachable");
    expect(resolution.auth.platformOperator).toBe(true);
    expect(callerScope(resolution.auth)).toEqual({ kind: "platform_operator" });
  });

  it("ROTATES on a second call — the old secret stops authenticating, the new one works", async () => {
    const first = await provisionPlatformOperatorApiKey(deps(), USER);
    expect((await deps().apiKeys.authenticate(String(first))).outcome).toBe("resolved");

    const second = await provisionPlatformOperatorApiKey(deps(), USER);
    expect(second).not.toBe(first);
    // One row per superadmin — the rotation replaced, it did not accumulate.
    const rows = await db()
      .prepare("SELECT id FROM static_api_keys WHERE id = ?")
      .bind(platformOperatorApiKeyId(USER))
      .all<{ id: string }>();
    expect(rows.results).toHaveLength(1);

    expect((await deps().apiKeys.authenticate(String(first))).outcome).not.toBe("resolved");
    expect((await deps().apiKeys.authenticate(String(second))).outcome).toBe("resolved");
  });

  it("returns null with no control database, minting nothing", async () => {
    const secret = await provisionPlatformOperatorApiKey(
      { ...deps(), controlDatabase: null },
      USER,
    );
    expect(secret).toBeNull();
    expect(await staticRow(platformOperatorApiKeyId(USER))).toBeNull();
  });
});

describe("revokePlatformOperatorApiKey", () => {
  it("deletes the row so the secret no longer authenticates", async () => {
    const secret = await provisionPlatformOperatorApiKey(deps(), USER);
    expect((await deps().apiKeys.authenticate(String(secret))).outcome).toBe("resolved");

    await revokePlatformOperatorApiKey(deps(), USER);

    expect(await staticRow(platformOperatorApiKeyId(USER))).toBeNull();
    expect((await deps().apiKeys.authenticate(String(secret))).outcome).not.toBe("resolved");
  });
});

describe("the fence the operator key crosses and a tenant key does not", () => {
  it("a tenant static key resolves to platformOperator=false", async () => {
    // A plain, tenant-scoped static key (platform_operator = 0) — the shape the
    // admin API mints — must never resolve to platform root.
    const secret = "fg_tenant_static_probe";
    const now = Math.floor(Date.now() / 1000);
    await db()
      .prepare(
        `INSERT INTO static_api_keys
           (key_hash, id, tenant_id, platform_operator, scopes_json, enabled, expires_at_unix,
            created_at_unix, updated_at_unix)
         VALUES (?, 'tenant-static-probe', 't-1', 0, ?, 1, NULL, ?, ?)`,
      )
      .bind(await hashApiKeySecret(secret), JSON.stringify(["admin.read"]), now, now)
      .run();

    const resolution = await deps().apiKeys.authenticate(secret);
    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome !== "resolved") throw new Error("unreachable");
    expect(resolution.auth.platformOperator).toBe(false);
    expect(callerScope(resolution.auth)).toEqual({ kind: "tenant", tenantId: "t-1" });
  });
});
