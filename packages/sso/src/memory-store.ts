import type {
  SsoPendingFlow,
  SsoPendingFlowStore,
  SsoProviderConfigStore,
  StoredSsoProviderConfig,
} from "./ports.js";

/**
 * In-memory reference implementations of the two SSO stores.
 *
 * These exist for tests and for `wrangler dev` smoke runs. They are NOT the
 * production store — `apps/control-plane` binds the D1-backed twin, and that
 * twin must be run against `samlPendingFlowStoreContract` too. See the note on
 * `SsoPendingFlowStore` about why proving only one implementation is worthless.
 */

export interface InMemorySsoConfigStore extends SsoProviderConfigStore {
  put(config: StoredSsoProviderConfig): void;
  remove(tenantId: string): void;
}

export interface InMemorySsoPendingFlowStore extends SsoPendingFlowStore {
  /** Test-only: reads WITHOUT consuming, so a test can prove `take` consumed. */
  peek(state: string): SsoPendingFlow | null;
  /** Test-only: seeds a flow verbatim (e.g. an OIDC flow, to prove it is refused). */
  insertRaw(flow: SsoPendingFlow): void;
}

export interface InMemorySsoStores {
  readonly configs: InMemorySsoConfigStore;
  readonly flows: InMemorySsoPendingFlowStore;
}

export function createInMemorySsoStores(): InMemorySsoStores {
  const configs = new Map<string, StoredSsoProviderConfig>();
  const flows = new Map<string, SsoPendingFlow>();

  return {
    configs: {
      get: async (tenantId) => configs.get(tenantId) ?? null,
      put: (config) => {
        configs.set(config.tenantId, config);
      },
      remove: (tenantId) => {
        configs.delete(tenantId);
      },
    },
    flows: {
      insert: async (flow) => {
        flows.set(flow.state, flow);
      },
      take: async (state, nowUnix) => {
        const flow = flows.get(state);
        // Delete FIRST, unconditionally: a state that was presented is burned
        // whether or not it was still valid. Returning the flow without
        // deleting — or deleting only on the success path — would leave an
        // expired-then-replayed state usable if the clock ever moved back.
        flows.delete(state);
        if (!flow) return null;
        if (flow.expiresAtUnix <= nowUnix) return null;
        return flow;
      },
      peek: (state) => flows.get(state) ?? null,
      insertRaw: (flow) => {
        flows.set(flow.state, flow);
      },
    },
  };
}
