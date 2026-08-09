/**
 * The DURABLE identity store, exercised against the REAL D1 and KV bindings
 * `@cloudflare/vitest-pool-workers` boots in workerd — no mocks, the same
 * SQLite and the same KV implementation `wrangler dev --local` runs.
 *
 * What these tests exist to hold:
 *
 *  1. A revoked grant STAYS revoked. `InMemoryCredentialStore` cannot promise
 *     that — its map dies with the isolate — and a grant that "comes back" is a
 *     security regression, not a cache miss.
 *  2. The anonymous OAuth callback's `state` is single-use AND time-bounded.
 *     Those two properties are the callback's ENTIRE authorization.
 *  3. `commitOauthCallback` refuses when the actor's authorization generation
 *     moved mid-flow, and refuses it in the same statement as the write.
 *  4. Malformed key material fails the Worker CLOSED rather than falling back
 *     to an ephemeral key.
 */
import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { controlNamespace } from "./support/control-namespace.js";

import { D1McpAuth } from "../src/auth.js";
import {
  DurableCredentialStore,
  IDENTITY_KEY_BYTES,
  KV_MIN_EXPIRATION_TTL_SECS,
  KvOauthFlowStore,
  OAUTH_FLOW_KEY_PREFIX,
  TenantObjectCredentialGrants,
  decodeIdentityKey,
  decodeServerRow,
  identityCipherFrom,
  loadServerCatalog,
} from "../src/durable.js";
import {
  D1R2AssetReader,
  InMemoryAssets,
  type McpEnv,
  type McpIdentityActor,
  type StoredMcpOauthCredential,
  type StoredMcpOauthFlow,
  credentialId,
  durableIdentityBound,
  portsBound,
  resolvePorts,
} from "../src/ports.js";
import { clearMcpIdentityTables, tenantDataNamespace, tenantDatabase } from "./tenant-storage.js";

const DB = env.DB as unknown as D1Database;
const KV = env.MCP_OAUTH_KV as unknown as KVNamespace;
const TENANT_DATA = tenantDataNamespace(env);
const ASSETS = env.ASSETS as unknown as R2Bucket;

const ACTOR: McpIdentityActor = { tenantId: "t1", workspaceId: "w1", userId: "u1" };
const OTHER_ACTOR: McpIdentityActor = { tenantId: "t2", workspaceId: "w1", userId: "u1" };
const SERVER = "srv";

/** A valid 32-byte key, hex-encoded. */
const KEY_HEX = "a".repeat(64);

function bytes(...values: number[]): Uint8Array {
  return new Uint8Array(values);
}

function flow(overrides: Partial<StoredMcpOauthFlow> = {}): StoredMcpOauthFlow {
  return {
    id: "state-digest-1",
    actor: ACTOR,
    serverName: SERVER,
    pkceNonce: bytes(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
    pkceCiphertext: bytes(9, 8, 7, 0, 255),
    oidcNonce: "nonce-1",
    authorizationGeneration: 0,
    createdAtUnix: 1_000,
    expiresAtUnix: 1_600,
    ...overrides,
  };
}

function credential(overrides: Partial<StoredMcpOauthCredential> = {}): StoredMcpOauthCredential {
  return {
    id: credentialId(ACTOR, SERVER),
    actor: ACTOR,
    serverName: SERVER,
    issuer: "https://idp.test",
    subject: "sub-1",
    tokenType: "Bearer",
    scopes: ["mcp.read", "mcp.write"],
    accessTokenNonce: bytes(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1),
    accessTokenCiphertext: bytes(200, 201, 202),
    refreshTokenNonce: bytes(2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2),
    refreshTokenCiphertext: bytes(50, 51),
    expiresAtUnix: 2_000,
    keyVersion: 1,
    version: 1,
    authorizationGeneration: 0,
    createdAtUnix: 1_000,
    updatedAtUnix: 1_000,
    ...overrides,
  };
}

async function truncate(): Promise<void> {
  await Promise.all(
    ["t1", "t2", "t3"].map((tenantId) => clearMcpIdentityTables(TENANT_DATA, tenantId)),
  );
  const keys = await KV.list({ prefix: OAUTH_FLOW_KEY_PREFIX });
  for (const key of keys.keys) await KV.delete(key.name);
}

beforeEach(truncate);

// ---------------------------------------------------------------------------

describe("TenantDataObject grants — durability and revocation", () => {
  it("round-trips a grant byte for byte, including the sealed token bytes", async () => {
    const grants = new TenantObjectCredentialGrants(TENANT_DATA);
    const stored = credential();
    await grants.put(stored);

    // A FRESH store object — the durability claim is about surviving the
    // object that wrote it, not about an in-process cache.
    const reloaded = await new TenantObjectCredentialGrants(TENANT_DATA).get(ACTOR, SERVER);
    expect(reloaded).toBeDefined();
    expect(reloaded?.subject).toBe("sub-1");
    expect(reloaded?.scopes).toEqual(["mcp.read", "mcp.write"]);
    expect([...(reloaded?.accessTokenCiphertext ?? [])]).toEqual([200, 201, 202]);
    expect([...(reloaded?.accessTokenNonce ?? [])]).toEqual([...stored.accessTokenNonce]);
    expect([...(reloaded?.refreshTokenCiphertext ?? [])]).toEqual([50, 51]);
    expect(reloaded?.revokedAtUnix).toBeUndefined();
  });

  it("keeps a grant revoked — a revoked credential never comes back unrevoked", async () => {
    const grants = new TenantObjectCredentialGrants(TENANT_DATA);
    await grants.put(credential());

    const revoked = await grants.revoke(ACTOR, SERVER, 1_500, "local_revoked");
    expect(revoked?.revokedAtUnix).toBe(1_500);
    expect(revoked?.lastRevocationOutcome).toBe("local_revoked");

    const reloaded = await new TenantObjectCredentialGrants(TENANT_DATA).get(ACTOR, SERVER);
    expect(reloaded?.revokedAtUnix).toBe(1_500);
  });

  it("refuses a second revoke instead of rewriting the first timestamp", async () => {
    const grants = new TenantObjectCredentialGrants(TENANT_DATA);
    await grants.put(credential());
    await grants.revoke(ACTOR, SERVER, 1_500, "local_revoked");

    expect(await grants.revoke(ACTOR, SERVER, 9_999, "second")).toBeUndefined();
    const reloaded = await grants.get(ACTOR, SERVER);
    expect(reloaded?.revokedAtUnix).toBe(1_500);
    expect(reloaded?.lastRevocationOutcome).toBe("local_revoked");
  });

  it("returns undefined when there is nothing to revoke", async () => {
    const grants = new TenantObjectCredentialGrants(TENANT_DATA);
    expect(await grants.revoke(ACTOR, SERVER, 1_500, "local_revoked")).toBeUndefined();
  });

  it("scopes a grant to its actor — another tenant's read finds nothing", async () => {
    const grants = new TenantObjectCredentialGrants(TENANT_DATA);
    await grants.put(credential());
    expect(await grants.get(OTHER_ACTOR, SERVER)).toBeUndefined();
    expect(await grants.get(ACTOR, "other-server")).toBeUndefined();
  });

  it("upserts rather than duplicating the actor row", async () => {
    const grants = new TenantObjectCredentialGrants(TENANT_DATA);
    await grants.put(credential());
    await grants.put(credential({ subject: "sub-2", version: 2, updatedAtUnix: 1_200 }));

    const rows = await tenantDatabase(TENANT_DATA, ACTOR.tenantId)
      .prepare("SELECT COUNT(*) AS n FROM mcp_oauth_credentials")
      .first<{
        n: number;
      }>();
    expect(rows?.n).toBe(1);
    expect((await grants.get(ACTOR, SERVER))?.subject).toBe("sub-2");
  });

  it("records the revocation outcome without un-revoking", async () => {
    const grants = new TenantObjectCredentialGrants(TENANT_DATA);
    await grants.put(credential());
    await grants.revoke(ACTOR, SERVER, 1_500, "local_revoked");
    await grants.updateRevocationOutcome(ACTOR, SERVER, "remote_revoked");
    const reloaded = await grants.get(ACTOR, SERVER);
    expect(reloaded?.lastRevocationOutcome).toBe("remote_revoked");
    expect(reloaded?.revokedAtUnix).toBe(1_500);
  });
});

describe("TenantDataObject grants — authorization generation guard", () => {
  it("starts at generation 0 and bumps per (actor, server)", async () => {
    const grants = new TenantObjectCredentialGrants(TENANT_DATA);
    expect(await grants.authorizationGeneration(ACTOR, SERVER)).toBe(0);
    await grants.bumpGeneration(ACTOR, SERVER);
    await grants.bumpGeneration(ACTOR, SERVER);
    expect(await grants.authorizationGeneration(ACTOR, SERVER)).toBe(2);
    // Isolated from a different actor and a different server.
    expect(await grants.authorizationGeneration(OTHER_ACTOR, SERVER)).toBe(0);
    expect(await grants.authorizationGeneration(ACTOR, "other")).toBe(0);
  });

  it("commits when the generation is unchanged", async () => {
    const grants = new TenantObjectCredentialGrants(TENANT_DATA);
    expect(await grants.commit(flow(), credential())).toBe(true);
    expect(await grants.get(ACTOR, SERVER)).toBeDefined();
  });

  it("REFUSES the commit when the generation moved mid-flow, and writes nothing", async () => {
    const grants = new TenantObjectCredentialGrants(TENANT_DATA);
    const began = flow({ authorizationGeneration: 0 });
    // Access changed while the user was at the identity provider.
    await grants.bumpGeneration(ACTOR, SERVER);

    expect(await grants.commit(began, credential())).toBe(false);
    expect(await grants.get(ACTOR, SERVER)).toBeUndefined();
  });

  it("REFUSES a stale-generation commit that would overwrite a live grant", async () => {
    const grants = new TenantObjectCredentialGrants(TENANT_DATA);
    await grants.put(credential({ subject: "existing" }));
    await grants.bumpGeneration(ACTOR, SERVER);

    expect(
      await grants.commit(
        flow({ authorizationGeneration: 0 }),
        credential({ subject: "attacker" }),
      ),
    ).toBe(false);
    expect((await grants.get(ACTOR, SERVER))?.subject).toBe("existing");
  });

  it("commits at a non-zero generation when the flow began there", async () => {
    const grants = new TenantObjectCredentialGrants(TENANT_DATA);
    await grants.bumpGeneration(ACTOR, SERVER);
    expect(await grants.commit(flow({ authorizationGeneration: 1 }), credential())).toBe(true);
  });
});

describe("KV OAuth flows", () => {
  it("round-trips the sealed PKCE bytes", async () => {
    const flows = new KvOauthFlowStore(KV);
    const began = flow();
    await flows.begin(began);

    const consumed = await new KvOauthFlowStore(KV).consume(began.id, 1_100);
    expect(consumed).toBeDefined();
    expect([...(consumed?.pkceNonce ?? [])]).toEqual([...began.pkceNonce]);
    expect([...(consumed?.pkceCiphertext ?? [])]).toEqual([...began.pkceCiphertext]);
    expect(consumed?.oidcNonce).toBe("nonce-1");
    expect(consumed?.actor).toEqual(ACTOR);
    expect(consumed?.authorizationGeneration).toBe(0);
  });

  it("is SINGLE-USE — a replayed state is unknown", async () => {
    const flows = new KvOauthFlowStore(KV);
    await flows.begin(flow());
    expect(await flows.consume("state-digest-1", 1_100)).toBeDefined();
    expect(await flows.consume("state-digest-1", 1_100)).toBeUndefined();
  });

  it("is TIME-BOUNDED in code, not only by the KV TTL", async () => {
    const flows = new KvOauthFlowStore(KV);
    await flows.begin(flow({ expiresAtUnix: 1_600 }));
    // One second past expiry, well inside the 60s KV TTL floor.
    expect(await flows.consume("state-digest-1", 1_601)).toBeUndefined();
  });

  it("refuses at exactly the expiry second (the bound is exclusive)", async () => {
    const flows = new KvOauthFlowStore(KV);
    await flows.begin(flow({ expiresAtUnix: 1_600 }));
    expect(await flows.consume("state-digest-1", 1_600)).toBeUndefined();
  });

  it("returns undefined for a state that was never begun", async () => {
    expect(await new KvOauthFlowStore(KV).consume("never-seen", 1_100)).toBeUndefined();
  });

  it("drops an undecodable record instead of leaving a poison key", async () => {
    await KV.put(`${OAUTH_FLOW_KEY_PREFIX}corrupt`, "{not json");
    const flows = new KvOauthFlowStore(KV);
    expect(await flows.consume("corrupt", 1_100)).toBeUndefined();
    expect(await KV.get(`${OAUTH_FLOW_KEY_PREFIX}corrupt`)).toBeNull();
  });

  it("accepts a flow shorter than KV's TTL floor by raising the TTL, not the expiry", async () => {
    const flows = new KvOauthFlowStore(KV);
    const short = flow({ createdAtUnix: 1_000, expiresAtUnix: 1_005 });
    // KV rejects expirationTtl < 60; begin() must not throw.
    await expect(flows.begin(short)).resolves.toBeUndefined();
    expect(KV_MIN_EXPIRATION_TTL_SECS).toBe(60);
    // The SHORT bound is still the one enforced on read.
    expect(await flows.consume(short.id, 1_006)).toBeUndefined();
  });

  it("namespaces its keys so the binding can be shared", async () => {
    await new KvOauthFlowStore(KV).begin(flow());
    const listed = await KV.list({ prefix: OAUTH_FLOW_KEY_PREFIX });
    expect(listed.keys.map((key) => key.name)).toEqual([`${OAUTH_FLOW_KEY_PREFIX}state-digest-1`]);
  });
});

describe("DurableCredentialStore (the bound composition)", () => {
  it("completes a flow begun by a DIFFERENT store object — the cross-isolate case", async () => {
    const beginner = new DurableCredentialStore(KV, TENANT_DATA);
    const began = flow();
    await beginner.beginOauthFlow(began);

    // A different isolate would construct its own store over the same bindings.
    const completer = new DurableCredentialStore(KV, TENANT_DATA);
    const consumed = await completer.consumeOauthFlow(began.id, 1_100);
    expect(consumed).toBeDefined();
    expect(await completer.commitOauthCallback(consumed as StoredMcpOauthFlow, credential())).toBe(
      true,
    );
    expect(
      await new DurableCredentialStore(KV, TENANT_DATA).getCredential(ACTOR, SERVER),
    ).toBeDefined();
  });

  it("survives a revoke across store objects", async () => {
    const store = new DurableCredentialStore(KV, TENANT_DATA);
    await store.putCredential(credential());
    await store.revokeCredential(ACTOR, SERVER, 1_500, "local_revoked");
    const fresh = await new DurableCredentialStore(KV, TENANT_DATA).getCredential(ACTOR, SERVER);
    expect(fresh?.revokedAtUnix).toBe(1_500);
  });
});

describe("server catalog", () => {
  it("reads only the requested tenant's servers", async () => {
    const t1 = tenantDatabase(TENANT_DATA, "t1");
    const t2 = tenantDatabase(TENANT_DATA, "t2");
    const sql = `INSERT INTO mcp_servers
      (tenant_id, name, transport, url, auth_type, tools_to_execute,
       tools_to_auto_execute, headers, oauth, signed_jwt_audience, timeout_ms)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    await t1
      .prepare(sql)
      .bind(
        "t1",
        "srv",
        "streamable_http",
        "https://up.test/mcp",
        "per_user_oauth",
        '["echo"]',
        '["echo"]',
        null,
        '{"issuer":"https://idp.test","clientId":"c1","scopes":["openid"]}',
        null,
        5000,
      )
      .run();
    await t2
      .prepare(sql)
      .bind(
        "t2",
        "other",
        "sse",
        "https://other.test/sse",
        "none",
        "[]",
        "[]",
        null,
        null,
        null,
        1000,
      )
      .run();

    const catalog = await loadServerCatalog(TENANT_DATA, "t1");
    expect(catalog.map((server) => server.name)).toEqual(["srv"]);
    expect(catalog[0]?.authType).toBe("per_user_oauth");
    expect(catalog[0]?.oauth?.clientId).toBe("c1");
    expect(await loadServerCatalog(TENANT_DATA, "t3")).toEqual([]);
  });

  it("REFUSES an unknown auth_type rather than downgrading it to none", () => {
    expect(
      decodeServerRow({
        name: "srv",
        transport: "streamable_http",
        url: null,
        auth_type: "totally_new_mode",
        tools_to_execute: "[]",
        tools_to_auto_execute: "[]",
        headers: null,
        oauth: null,
        signed_jwt_audience: null,
        timeout_ms: 1,
      } as never),
    ).toBeUndefined();
  });

  it("REFUSES an unknown transport rather than treating it as HTTP", () => {
    expect(
      decodeServerRow({
        name: "srv",
        transport: "quic",
        url: null,
        auth_type: "none",
        tools_to_execute: "[]",
        tools_to_auto_execute: "[]",
        headers: null,
        oauth: null,
        signed_jwt_audience: null,
        timeout_ms: 1,
      } as never),
    ).toBeUndefined();
  });

  it("keeps a stdio row decodable — it is refused at DISPATCH, not at config", () => {
    const decoded = decodeServerRow({
      name: "local",
      transport: "stdio",
      url: null,
      auth_type: "none",
      tools_to_execute: '["echo"]',
      tools_to_auto_execute: "[]",
      headers: null,
      oauth: null,
      signed_jwt_audience: null,
      timeout_ms: 1,
    } as never);
    expect(decoded?.transport).toBe("stdio");
  });
});

describe("identity key material", () => {
  it("accepts 32 bytes of hex", () => {
    const key = decodeIdentityKey(KEY_HEX);
    expect(key?.length).toBe(IDENTITY_KEY_BYTES);
  });

  it("accepts 32 bytes of base64", () => {
    const raw = new Uint8Array(IDENTITY_KEY_BYTES).fill(7);
    let binary = "";
    for (const byte of raw) binary += String.fromCharCode(byte);
    const key = decodeIdentityKey(btoa(binary));
    expect(key?.length).toBe(IDENTITY_KEY_BYTES);
    expect([...(key ?? [])]).toEqual([...raw]);
  });

  it("REFUSES a short key rather than padding or hashing it up", () => {
    expect(decodeIdentityKey("a".repeat(62))).toBeUndefined();
    expect(decodeIdentityKey("c2hvcnQ=")).toBeUndefined();
  });

  it("REFUSES absent, empty and non-encoded values", () => {
    expect(decodeIdentityKey(undefined)).toBeUndefined();
    expect(decodeIdentityKey("   ")).toBeUndefined();
    expect(decodeIdentityKey("not a key!!")).toBeUndefined();
  });

  it("builds a working AEAD cipher from valid material, and nothing from invalid", async () => {
    const cipher = identityCipherFrom(KEY_HEX);
    expect(cipher).toBeDefined();
    const aad = new TextEncoder().encode("aad");
    const sealed = await (cipher as NonNullable<typeof cipher>).encrypt(
      new TextEncoder().encode("secret"),
      aad,
    );
    const opened = await (cipher as NonNullable<typeof cipher>).decrypt(
      sealed.nonce,
      sealed.ciphertext,
      aad,
    );
    expect(new TextDecoder().decode(opened)).toBe("secret");
    expect(identityCipherFrom("short")).toBeUndefined();
  });

  it("binds the AAD — a grant sealed for one actor cannot be opened for another", async () => {
    const cipher = identityCipherFrom(KEY_HEX);
    const sealed = await (cipher as NonNullable<typeof cipher>).encrypt(
      new TextEncoder().encode("secret"),
      new TextEncoder().encode("actor-a"),
    );
    await expect(
      (cipher as NonNullable<typeof cipher>).decrypt(
        sealed.nonce,
        sealed.ciphertext,
        new TextEncoder().encode("actor-b"),
      ),
    ).rejects.toThrow();
  });

  it("two isolates given the SAME key material can open each other's grants", async () => {
    const first = identityCipherFrom(KEY_HEX);
    const second = identityCipherFrom(KEY_HEX);
    const aad = new TextEncoder().encode("aad");
    const sealed = await (first as NonNullable<typeof first>).encrypt(
      new TextEncoder().encode("grant"),
      aad,
    );
    const opened = await (second as NonNullable<typeof second>).decrypt(
      sealed.nonce,
      sealed.ciphertext,
      aad,
    );
    expect(new TextDecoder().decode(opened)).toBe("grant");
  });
});

describe("resolvePorts binding postures", () => {
  const base: McpEnv = {
    CONTROL_DATA: controlNamespace() as DurableObjectNamespace,
    DB,
    TENANT_DATA,
    MCP_OAUTH_KV: KV,
    FERROGATE_MCP_IDENTITY_KEY: KEY_HEX,
  };

  it("reports the durable identity bound only when object, KV and key are present", () => {
    expect(durableIdentityBound(base)).toBe(true);
    expect(durableIdentityBound({ ...base, TENANT_DATA: undefined })).toBe(false);
    expect(durableIdentityBound({ ...base, DB: undefined })).toBe(true);
    expect(durableIdentityBound({ ...base, MCP_OAUTH_KV: undefined })).toBe(false);
    expect(durableIdentityBound({ ...base, FERROGATE_MCP_IDENTITY_KEY: undefined })).toBe(false);
    // Malformed key material is NOT "bound" — no ephemeral fallback.
    expect(durableIdentityBound({ ...base, FERROGATE_MCP_IDENTITY_KEY: "short" })).toBe(false);
  });

  it("binds the DURABLE credential store when the bindings are present", () => {
    const ports = resolvePorts(base);
    expect(ports.credentials).toBeInstanceOf(DurableCredentialStore);
  });

  it("pins the asset reader to D1/R2 only in the production posture", () => {
    // Keep this assertion at the composition root: reader implementation tests
    // cannot catch a deployed posture silently falling back to in-memory.
    const production = resolvePorts({ ...base, ASSETS });
    expect(production.assets).toBeInstanceOf(D1R2AssetReader);
    expect(production.assets).not.toBeInstanceOf(InMemoryAssets);

    expect(resolvePorts(base).assets).toBeInstanceOf(InMemoryAssets);
    expect(resolvePorts({ ...base, ASSETS, TENANT_DATA: undefined }).assets).toBeInstanceOf(
      InMemoryAssets,
    );
    expect(resolvePorts({ ...base, ASSETS, CONTROL_DATA: undefined }).assets).toBeInstanceOf(
      InMemoryAssets,
    );

    const dev = resolvePorts({ ...base, ASSETS, FG_DEV_IN_MEMORY_PORTS: "1" });
    expect(dev.assets).toBeInstanceOf(InMemoryAssets);
    expect(dev.assets).not.toBeInstanceOf(D1R2AssetReader);
  });

  it("keys the CIPHER on the operator's material, not a per-isolate random key", async () => {
    // MCP-P6, corrected in wave 17. Every assertion in this block was about
    // `ports.credentials`; NONE was about `ports.cipher`. Measured: deleting
    // `cipher: identityCipherFrom(env.FERROGATE_MCP_IDENTITY_KEY)` from
    // `resolvePorts` left all 359 mcp tests GREEN — and left the durable
    // credential store sealing grants under `webCryptoIdentityCipher()`'s
    // EPHEMERAL fallback, a fresh 32 random bytes per isolate. Every stored
    // OAuth grant would then be undecryptable the moment the isolate recycled,
    // while the operator's configured key sat unread.
    //
    // The property asserted is interoperability with the configured key, which
    // an ephemeral one cannot fake: seal with a cipher built from KEY_HEX
    // directly, open with the one `resolvePorts` chose.
    const configured = identityCipherFrom(KEY_HEX);
    expect(configured, "the fixture key must be valid material").toBeDefined();
    const aad = new TextEncoder().encode("mcp-identity-mount-probe");
    const plaintext = new TextEncoder().encode("refresh-token-value");
    const sealed = await (configured as NonNullable<typeof configured>).encrypt(plaintext, aad);

    const mounted = resolvePorts(base).cipher;
    const opened = await mounted.decrypt(sealed.nonce, sealed.ciphertext, aad);
    expect(new TextDecoder().decode(opened)).toBe("refresh-token-value");
  });

  it("does NOT bind the durable store when the key is malformed", () => {
    const ports = resolvePorts({ ...base, FERROGATE_MCP_IDENTITY_KEY: "short" });
    expect(ports.credentials).not.toBeInstanceOf(DurableCredentialStore);
  });

  it("binds the DURABLE auth port on the durable path and reports READY", async () => {
    // This assertion used to read `portsBound(base) === false` with the comment
    // "auth is not yet bindable here" — it pinned the deferral that made a
    // production Worker answer 503 on every authenticated surface forever. That
    // deferral is closed (`src/auth.ts`), so the assertion is STRENGTHENED
    // rather than dropped: the port must now be the durable one, readiness must
    // follow it, and an unrecognized credential must get the 401 an unknown key
    // gets — never the 503 that used to be the only possible answer.
    expect(portsBound(base)).toBe(true);
    const ports = resolvePorts(base);
    expect(ports.auth).toBeInstanceOf(D1McpAuth);
    const outcome = await ports.auth.authenticate(
      new Headers({ authorization: "Bearer anything" }),
      "tools.read",
    );
    expect("code" in outcome && outcome.code).toBe("invalid_api_key");
    expect("status" in outcome && outcome.status).toBe(401);
  });

  it("STILL fails closed when no database is bound at all", async () => {
    // The fail-closed arm has not gone anywhere; it moved to the posture that
    // actually has nothing to authenticate against.
    expect(portsBound({})).toBe(false);
    const outcome = await resolvePorts({}).auth.authenticate(
      new Headers({ authorization: "Bearer anything" }),
      "tools.read",
    );
    expect("code" in outcome && outcome.code).toBe("mcp_auth_unavailable");
  });

  it("keeps the dev bundle in charge when the dev flag is set", () => {
    const ports = resolvePorts({ ...base, FG_DEV_IN_MEMORY_PORTS: "1" });
    expect(ports.credentials).not.toBeInstanceOf(DurableCredentialStore);
  });
});
