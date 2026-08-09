/**
 * Per-tenant BYOK (issue #682) — the alias indirection and its tenant fence.
 *
 * These tests exist because of ONE class of failure: a tenant resolving, reading
 * or dispatching with ANOTHER tenant's provider credential. Every assertion here
 * is either that fence or the thing that makes the fence possible (an alias that
 * is DATA rather than a deploy-time binding).
 *
 * The fence is held in two independent places on purpose, and each is pinned
 * separately below, because one of them alone is a single point of failure:
 *
 *  1. the LOOKUP is tenant-scoped — the resolver is constructed bound to one
 *     tenant and a `byok://` reference has no tenant component to spoof;
 *  2. the CIPHERTEXT is sealed to `(tenantId, alias)` through AES-GCM additional
 *     authenticated data — so a row physically copied into another tenant's
 *     partition, or renamed onto another alias, fails to open at all.
 */
import { describe, expect, it } from "vitest";
import {
  BYOK_KEY_VERSION_ENV_PREFIX,
  BYOK_MASTER_KEY_ENV,
  SecretResolverRegistry,
  TenantByokResolver,
  byokKeyringFromEnv,
  generateByokMasterKey,
  openTenantCredential,
  parseSecretRef,
  sealTenantCredential,
} from "../src/index.js";
import type { SealedTenantCredential, TenantCredentialStore } from "../src/index.js";

/** A deterministic 32-byte key, written the way an operator binds one. */
const KEY_A = generateByokMasterKey();
const KEY_B = generateByokMasterKey();

/** An in-memory store keyed exactly as the D1 table is: `(tenant_id, alias)`. */
class MapCredentialStore implements TenantCredentialStore {
  private readonly rows = new Map<string, SealedTenantCredential>();

  put(record: SealedTenantCredential): void {
    this.rows.set(`${record.tenantId}\0${record.alias}`, record);
  }

  /** Bypasses every fence — used only to simulate a compromised/copied row. */
  putRaw(tenantId: string, alias: string, record: SealedTenantCredential): void {
    this.rows.set(`${tenantId}\0${alias}`, record);
  }

  async lookup(tenantId: string, alias: string): Promise<SealedTenantCredential | null> {
    return this.rows.get(`${tenantId}\0${alias}`) ?? null;
  }
}

async function seed(
  store: MapCredentialStore,
  tenantId: string,
  alias: string,
  provider: string,
  value: string,
  keyring = byokKeyringFromEnv({ [BYOK_MASTER_KEY_ENV]: KEY_A }),
): Promise<SealedTenantCredential> {
  const sealed = await sealTenantCredential(keyring, {
    tenantId,
    alias,
    provider,
    value,
  });
  store.put(sealed);
  return sealed;
}

describe("byok:// secret references", () => {
  it("parses an alias and carries NO tenant component", () => {
    const reference = parseSecretRef("byok://openai-enterprise");
    expect(reference).toEqual({ kind: "byok", alias: "openai-enterprise" });
  });

  it("refuses an alias that could smuggle a second path segment", () => {
    // `byok://tenant_b/openai` must never parse into something a resolver could
    // read as "tenant_b's openai alias".
    expect(() => parseSecretRef("byok://tenant_b/openai")).toThrow(/alias/i);
    expect(() => parseSecretRef("byok://")).toThrow(/alias/i);
    expect(() => parseSecretRef("byok://UPPER CASE")).toThrow(/alias/i);
  });
});

describe("TenantByokResolver", () => {
  it("resolves this tenant's alias to the registered credential", async () => {
    const store = new MapCredentialStore();
    await seed(store, "tenant_a", "openai-enterprise", "openai", "sk-tenant-a");

    const resolver = new TenantByokResolver({
      tenantId: "tenant_a",
      store,
      keyring: byokKeyringFromEnv({ [BYOK_MASTER_KEY_ENV]: KEY_A }),
    });

    expect(await resolver.resolve(parseSecretRef("byok://openai-enterprise"))).toBe("sk-tenant-a");
  });

  it("THE FENCE: another tenant asking for the same alias gets nothing", async () => {
    const store = new MapCredentialStore();
    await seed(store, "tenant_a", "openai-enterprise", "openai", "sk-tenant-a");

    const attacker = new TenantByokResolver({
      tenantId: "tenant_b",
      store,
      keyring: byokKeyringFromEnv({ [BYOK_MASTER_KEY_ENV]: KEY_A }),
    });

    expect(await attacker.resolve(parseSecretRef("byok://openai-enterprise"))).toBeNull();
  });

  it("THE SECOND FENCE: a row copied into another tenant's partition will not open", async () => {
    const store = new MapCredentialStore();
    const sealed = await seed(store, "tenant_a", "openai-enterprise", "openai", "sk-tenant-a");

    // Simulate the worst case the SQL fence cannot cover: the ciphertext itself
    // is already sitting under tenant_b's key, e.g. a bad admin write or a
    // restore that crossed partitions. AES-GCM's AAD binds the plaintext to
    // (tenant, alias), so it must not decrypt.
    store.putRaw("tenant_b", "openai-enterprise", {
      ...sealed,
      tenantId: "tenant_b",
    });

    const attacker = new TenantByokResolver({
      tenantId: "tenant_b",
      store,
      keyring: byokKeyringFromEnv({ [BYOK_MASTER_KEY_ENV]: KEY_A }),
    });

    await expect(attacker.resolve(parseSecretRef("byok://openai-enterprise"))).rejects.toThrow(
      /could not be decrypted/i,
    );
  });

  it("refuses to be constructed without a tenant, rather than resolving globally", () => {
    const store = new MapCredentialStore();
    expect(
      () =>
        new TenantByokResolver({
          tenantId: "  ",
          store,
          keyring: byokKeyringFromEnv({ [BYOK_MASTER_KEY_ENV]: KEY_A }),
        }),
    ).toThrow(/tenant/i);
  });

  it("never puts the credential value in an error message", async () => {
    const store = new MapCredentialStore();
    await seed(store, "tenant_a", "openai-enterprise", "openai", "sk-super-secret");

    // Wrong master key ⇒ decryption fails. The message must name the alias and
    // the key version, never the plaintext and never the ciphertext.
    const resolver = new TenantByokResolver({
      tenantId: "tenant_a",
      store,
      keyring: byokKeyringFromEnv({ [BYOK_MASTER_KEY_ENV]: KEY_B }),
    });

    await expect(resolver.resolve(parseSecretRef("byok://openai-enterprise"))).rejects.toThrow(
      /openai-enterprise/,
    );
    const error = await resolver
      .resolve(parseSecretRef("byok://openai-enterprise"))
      .catch((caught: unknown) => caught);
    expect(String(error)).not.toContain("sk-super-secret");
  });
});

describe("rotation without a deploy", () => {
  it("re-sealing the same alias changes only DATA — the binding set is untouched", async () => {
    const keyring = byokKeyringFromEnv({ [BYOK_MASTER_KEY_ENV]: KEY_A });
    const store = new MapCredentialStore();
    await seed(store, "tenant_a", "openai-enterprise", "openai", "sk-old", keyring);

    const resolver = new TenantByokResolver({ tenantId: "tenant_a", store, keyring });
    expect(await resolver.resolve(parseSecretRef("byok://openai-enterprise"))).toBe("sk-old");

    // Rotation = one row write. No binding, no wrangler.toml edit, no deploy.
    await seed(store, "tenant_a", "openai-enterprise", "openai", "sk-new", keyring);
    expect(await resolver.resolve(parseSecretRef("byok://openai-enterprise"))).toBe("sk-new");
  });

  it("a MASTER key rotation reads old rows through the versioned keyring", async () => {
    const v1 = byokKeyringFromEnv({ [BYOK_MASTER_KEY_ENV]: KEY_A });
    const sealedUnderV1 = await sealTenantCredential(v1, {
      tenantId: "tenant_a",
      alias: "openai-enterprise",
      provider: "openai",
      value: "sk-old-era",
    });
    expect(sealedUnderV1.keyVersion).toBe(1);

    // The operator adds a v2 binding; v1 stays bound so existing rows still open
    // and can be re-sealed lazily. The BINDING SET grew by one for the whole
    // fleet — not one per tenant, which is the constraint this design exists for.
    const v2 = byokKeyringFromEnv({
      [BYOK_MASTER_KEY_ENV]: KEY_A,
      [`${BYOK_KEY_VERSION_ENV_PREFIX}2`]: KEY_B,
    });
    expect(await openTenantCredential(v2, sealedUnderV1)).toBe("sk-old-era");

    const resealed = await sealTenantCredential(v2, {
      tenantId: "tenant_a",
      alias: "openai-enterprise",
      provider: "openai",
      value: "sk-new-era",
    });
    // New writes take the HIGHEST version available.
    expect(resealed.keyVersion).toBe(2);
    expect(await openTenantCredential(v2, resealed)).toBe("sk-new-era");
  });
});

describe("SecretResolverRegistry", () => {
  it("dispatches byok:// through the tenant-bound resolver", async () => {
    const store = new MapCredentialStore();
    await seed(store, "tenant_a", "anthropic-negotiated", "anthropic", "sk-ant-a");

    const registry = SecretResolverRegistry.new({}).withByok(
      new TenantByokResolver({
        tenantId: "tenant_a",
        store,
        keyring: byokKeyringFromEnv({ [BYOK_MASTER_KEY_ENV]: KEY_A }),
      }),
    );

    expect(await registry.resolve("byok://anthropic-negotiated")).toBe("sk-ant-a");
  });

  it("refuses byok:// when no tenant-bound resolver is mounted", async () => {
    const registry = SecretResolverRegistry.new({});
    await expect(registry.resolve("byok://anthropic-negotiated")).rejects.toThrow(/tenant/i);
  });
});
