/**
 * Durable credential resolution, driven through the exported Worker against a
 * REAL D1 binding and the REAL control migration.
 *
 * Three things are held here, and each one is a way this app has historically
 * been got wrong:
 *
 *  1. an operator key provisioned in `static_api_keys` authenticates, with the
 *     row's `scopes_json` / `platform_operator` / lifecycle columns deciding
 *     what it can do — the var is no longer the source of truth;
 *  2. the 401-vs-403 taxonomy is unchanged by the source of the row (disabled
 *     STATIC key → 403; a credential the database cannot authorize → 401);
 *  3. the PLATFORM LIMIT is pinned: a key present in `api_key_directory` — the
 *     narrow credential→tenant routing index, which carries no scopes — is
 *     `401 invalid_api_key` on this Worker, exactly as an unknown key is. See
 *     the sharpened PORT-TODO in `src/store/api_keys.ts`.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { hashApiKeySecret } from "../src/store/api_keys.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest } from "./harness.js";

interface DurableStaticKey {
  readonly secret: string;
  readonly id: string;
  readonly tenantId?: string | null;
  readonly platformOperator?: boolean;
  /** `undefined` writes SQL `NULL` — the wildcard. `[]` writes the empty set. */
  readonly scopes?: readonly string[];
  readonly enabled?: boolean;
  readonly expiresAtUnix?: number | null;
  /** Written verbatim, to exercise a mis-provisioned column. */
  readonly rawKeyHash?: string;
}

async function seedStaticKey(key: DurableStaticKey): Promise<void> {
  await db()
    .prepare(
      `INSERT INTO static_api_keys
         (key_hash, id, tenant_id, platform_operator, scopes_json, enabled, expires_at_unix,
          created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)`,
    )
    .bind(
      key.rawKeyHash ?? (await hashApiKeySecret(key.secret)),
      key.id,
      key.tenantId ?? null,
      key.platformOperator === true ? 1 : 0,
      key.scopes === undefined ? null : JSON.stringify(key.scopes),
      key.enabled === false ? 0 : 1,
      key.expiresAtUnix ?? null,
    )
    .run();
}

async function seedDirectoryKey(secret: string, id: string, tenantId: string): Promise<void> {
  await db()
    .prepare(
      `INSERT INTO api_key_directory
         (key_hash, id, tenant_id, project_id, workspace_id, key_prefix, last4, enabled,
          expires_at_unix, revoked_at_unix, created_at_unix, updated_at_unix)
       VALUES (?, ?, ?, '', '', ?, ?, 1, NULL, NULL, 0, 0)`,
    )
    .bind(await hashApiKeySecret(secret), id, tenantId, secret.slice(0, 16), secret.slice(-4))
    .run();
}

async function clearKeyTables(): Promise<void> {
  await db().batch([
    db().prepare("DELETE FROM static_api_keys"),
    db().prepare("DELETE FROM api_key_directory"),
  ]);
}

/** `GET /admin/v1/status` — an `admin.read` operation behind the auth chain. */
function status(secret: string): Promise<Response> {
  return SELF.fetch(`${BASE}/admin/v1/status`, { headers: bearer(secret) });
}

async function errorCode(response: Response): Promise<string> {
  return ((await response.json()) as { error: { code: string } }).error.code;
}

beforeAll(applySchema);

describe("durable operator keys: static_api_keys is the source of truth", () => {
  beforeEach(async () => {
    await resetD1();
    await clearKeyTables();
    // NO declarative keys at all: everything below authenticates (or fails to)
    // purely on what is in the database.
    arm({ store: "d1" });
  });

  it("authenticates a provisioned operator key with NO var declaring it", async () => {
    await seedStaticKey({ secret: "durable-operator", id: "sk_1", platformOperator: true });

    const response = await status("durable-operator");
    expect(response.status).toBe(200);
  });

  it("stores only the DIGEST — the plaintext secret is nowhere in the table", async () => {
    await seedStaticKey({ secret: "durable-operator", id: "sk_1", platformOperator: true });

    const row = await db()
      .prepare("SELECT key_hash FROM static_api_keys WHERE id = ?")
      .bind("sk_1")
      .first<{ key_hash: string }>();
    expect(row?.key_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(row?.key_hash).not.toContain("durable-operator");
  });

  it("probes the table with the DIGEST, so a mis-provisioned row cannot authenticate", async () => {
    // Two rows for the same secret: one correctly hashed under a scopeless
    // identity, one mis-provisioned with the PLAINTEXT secret in `key_hash`
    // under a platform-operator identity.
    await seedStaticKey({
      secret: "shared-secret",
      id: "sk_hashed",
      tenantId: "tenant-a",
      scopes: ["admin.read"],
    });
    await seedStaticKey({
      secret: "shared-secret",
      id: "sk_plaintext",
      platformOperator: true,
      rawKeyHash: "shared-secret",
    });

    // The credential resolves — but as the HASHED row, never the plaintext one.
    // A lookup that ever probed with the raw secret would resolve `sk_plaintext`
    // and hand a platform-operator identity to a mis-provisioned row.
    expect((await status("shared-secret")).status).toBe(200);

    // `admin.write` is out of `sk_hashed`'s scopes; `sk_plaintext` is a
    // wildcard operator. A 403 here is the proof of WHICH row answered.
    const written = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules`,
      jsonRequest("shared-secret", "POST", { id: "s_probe", name: "n" }),
    );
    expect(written.status).toBe(403);
  });

  it("REFUSES a credential whose ONLY row holds the plaintext secret in key_hash", async () => {
    await seedStaticKey({
      secret: "plain-secret",
      id: "sk_bad",
      platformOperator: true,
      rawKeyHash: "plain-secret",
    });

    const response = await status("plain-secret");
    expect(response.status).toBe(401);
    expect(await errorCode(response)).toBe("invalid_api_key");
  });

  it("a DISABLED static row is 403, not 401 — the taxonomy does not move with the source", async () => {
    await seedStaticKey({
      secret: "disabled-operator",
      id: "sk_off",
      platformOperator: true,
      enabled: false,
    });

    const response = await status("disabled-operator");
    expect(response.status).toBe(403);
  });

  it("an EXPIRED static row is 403", async () => {
    await seedStaticKey({
      secret: "expired-operator",
      id: "sk_exp",
      platformOperator: true,
      expiresAtUnix: 1,
    });

    const response = await status("expired-operator");
    expect(response.status).toBe(403);
  });

  it("`scopes_json = NULL` is the WILDCARD; `'[]'` is the empty set (403 on admin.*)", async () => {
    await seedStaticKey({ secret: "wildcard-key", id: "sk_wild", platformOperator: true });
    await seedStaticKey({ secret: "scopeless-key", id: "sk_none", scopes: [] });

    expect((await status("wildcard-key")).status).toBe(200);

    const scopeless = await status("scopeless-key");
    // Authenticated, but the empty scope set never grants an `admin.*` scope,
    // and every operation on this Worker is one.
    expect(scopeless.status).toBe(403);
  });

  it("a row's `scopes_json` decides what it reaches: admin.read yes, admin.write no", async () => {
    await seedStaticKey({
      secret: "reader-key",
      id: "sk_reader",
      tenantId: "tenant-a",
      scopes: ["admin.read"],
    });

    expect((await status("reader-key")).status).toBe(200);

    const written = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules`,
      jsonRequest("reader-key", "POST", { id: "s1", name: "n" }),
    );
    expect(written.status).toBe(403);
  });

  it("the durable row WINS over a var that still lists the same secret as enabled", async () => {
    await seedStaticKey({
      secret: "rotated-key",
      id: "sk_rot",
      platformOperator: true,
      enabled: false,
    });
    arm({
      store: "d1",
      staticKeys: [
        { secret: "rotated-key", id: "stale_var", platform_operator: true, scopes: ["*"] },
      ],
    });

    // A stale var must never re-enable a credential the database disabled.
    expect((await status("rotated-key")).status).toBe(403);
  });

  it("falls back to the var when the database has NO matching row", async () => {
    arm({
      store: "d1",
      staticKeys: [{ secret: "var-only", id: "var_1", platform_operator: true, scopes: ["*"] }],
    });

    expect((await status("var-only")).status).toBe(200);
  });
});

describe("PLATFORM LIMIT: api_key_directory cannot authorize a control-plane caller", () => {
  beforeEach(async () => {
    await resetD1();
    await clearKeyTables();
    arm({ store: "d1" });
  });

  it("a directory-only credential is 401 invalid_api_key, exactly like an unknown one", async () => {
    await seedDirectoryKey("fg_directory_secret_value", "ak_1", "tenant-a");

    const known = await status("fg_directory_secret_value");
    const unknown = await status("fg_never_provisioned_value");

    // Indistinguishable — that is the point. This Worker cannot read the
    // per-tenant `api_keys` row that carries the key's scopes (D1 bindings are
    // deploy-time), so it resolves nothing rather than inventing an authority
    // the directory does not record. See `src/store/api_keys.ts`.
    expect(known.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(await errorCode(known)).toBe(await errorCode(unknown));
  });

  it("the directory row IS present — the 401 is a decision, not a missing fixture", async () => {
    await seedDirectoryKey("fg_directory_secret_value", "ak_1", "tenant-a");

    const row = await db()
      .prepare("SELECT id, tenant_id FROM api_key_directory WHERE id = ?")
      .bind("ak_1")
      .first<{ id: string; tenant_id: string }>();
    expect(row).toMatchObject({ id: "ak_1", tenant_id: "tenant-a" });
  });
});
