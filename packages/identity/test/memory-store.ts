/**
 * An in-memory `IdentityRepository` + the sibling ports, for the suite.
 *
 * This is a TEST DOUBLE, not a second production implementation: every
 * authorization predicate under test lives in `src/`, and this file only
 * stores and returns rows. That is deliberate — the repo has been bitten by a
 * predicate with two implementations (D1 + in-memory) where mutating one left
 * the other green. There is exactly one implementation of every SCIM/OIDC
 * decision, in `src/`, and this store cannot mask a mutation of it.
 */
import type {
  ApiKeyDecision,
  IdentityRepository,
  LifecycleSeam,
  StoredAdminUser,
  StoredAdminUserMembership,
  StoredApiKeyRecord,
  StoredSsoPendingFlow,
  StoredSsoProviderConfig,
  StoredTenantAccount,
  StoredWorkspaceRef,
  TenancyRefs,
} from "../src/ports.js";

export interface RevocationLog {
  readonly tenantRefreshTokens: { userId: string; tenantId: string }[];
  readonly allRefreshTokens: string[];
  readonly sessionKeys: { userId: string; tenantId: string }[];
}

export class MemoryIdentityRepository implements IdentityRepository {
  ssoConfigs = new Map<string, StoredSsoProviderConfig>();
  pendingFlows = new Map<string, StoredSsoPendingFlow>();
  users = new Map<string, StoredAdminUser>();
  memberships: StoredAdminUserMembership[] = [];
  tenants = new Map<string, StoredTenantAccount>();
  workspaces = new Map<string, StoredWorkspaceRef>();
  apiKeys: StoredApiKeyRecord[] = [];
  /** Tenancies whose lifecycle gate must fail, keyed by tenant id. */
  suspendedTenants = new Set<string>();
  revocations: RevocationLog = {
    tenantRefreshTokens: [],
    allRefreshTokens: [],
    sessionKeys: [],
  };

  async getSsoProviderConfig(tenantId: string): Promise<StoredSsoProviderConfig | null> {
    return this.ssoConfigs.get(tenantId) ?? null;
  }

  async insertSsoPendingFlow(flow: StoredSsoPendingFlow): Promise<void> {
    this.pendingFlows.set(flow.state, flow);
  }

  /** Single-use AND expiry-checked, exactly like `take_sso_pending_flow`. */
  async takeSsoPendingFlow(state: string, nowUnix: number): Promise<StoredSsoPendingFlow | null> {
    const flow = this.pendingFlows.get(state);
    if (!flow) return null;
    this.pendingFlows.delete(state);
    if (flow.expiresAtUnix <= nowUnix) return null;
    return flow;
  }

  async getAdminUserByEmail(email: string): Promise<StoredAdminUser | null> {
    for (const user of this.users.values()) if (user.email === email) return user;
    return null;
  }

  async getAdminUserById(userId: string): Promise<StoredAdminUser | null> {
    return this.users.get(userId) ?? null;
  }

  async upsertAdminUser(user: StoredAdminUser): Promise<void> {
    this.users.set(user.id, { ...user });
  }

  async listAdminUserMembershipsByTenant(tenantId: string): Promise<StoredAdminUserMembership[]> {
    return this.memberships.filter((m) => m.tenantId === tenantId).map((m) => ({ ...m }));
  }

  async listAdminUserMembershipsByUser(userId: string): Promise<StoredAdminUserMembership[]> {
    return this.memberships.filter((m) => m.userId === userId).map((m) => ({ ...m }));
  }

  async upsertAdminUserMembership(membership: StoredAdminUserMembership): Promise<void> {
    const index = this.memberships.findIndex(
      (m) => m.userId === membership.userId && m.tenantId === membership.tenantId,
    );
    if (index >= 0) this.memberships[index] = { ...membership };
    else this.memberships.push({ ...membership });
  }

  async deleteAdminUserMembership(userId: string, tenantId: string): Promise<boolean> {
    const before = this.memberships.length;
    this.memberships = this.memberships.filter(
      (m) => !(m.userId === userId && m.tenantId === tenantId),
    );
    return this.memberships.length !== before;
  }

  async revokeAdminUserRefreshTokensForTenant(userId: string, tenantId: string): Promise<void> {
    this.revocations.tenantRefreshTokens.push({ userId, tenantId });
  }

  async revokeAllAdminUserRefreshTokens(userId: string): Promise<void> {
    this.revocations.allRefreshTokens.push(userId);
  }

  async revokeAdminConsoleSessionKeys(tenantId: string, userId: string): Promise<void> {
    this.revocations.sessionKeys.push({ userId, tenantId });
  }

  async getTenantAccount(tenantId: string): Promise<StoredTenantAccount | null> {
    return this.tenants.get(tenantId) ?? null;
  }

  async resolveDefaultWorkspace(tenantId: string): Promise<StoredWorkspaceRef | null> {
    return this.workspaces.get(tenantId) ?? null;
  }

  async upsertApiKeyRecord(key: StoredApiKeyRecord): Promise<void> {
    this.apiKeys.push({ ...key });
  }

  async requireUsableTenancy(_seam: LifecycleSeam, refs: TenancyRefs): Promise<void> {
    if (refs.tenantId && this.suspendedTenants.has(refs.tenantId)) {
      throw new Error(`tenancy ${refs.tenantId} is suspended`);
    }
  }
}

/** A trivial api-key directory: token string → decision. */
export class MemoryApiKeyAuthenticator {
  readonly keys = new Map<string, ApiKeyDecision>();
  async authenticate(token: string): Promise<ApiKeyDecision | null> {
    return this.keys.get(token) ?? null;
  }
}

/** A deterministic clock. */
export class FakeClock {
  constructor(public seconds: number) {}
  nowUnix(): number {
    return this.seconds;
  }
  advance(by: number): void {
    this.seconds += by;
  }
}

/** Deterministic "randomness" — a counter, so authorize URLs are assertable. */
export class CountingRandom {
  private counter = 0;
  hex(byteLength: number): string {
    this.counter += 1;
    return `${this.counter}`.padStart(byteLength * 2, "0");
  }
}
