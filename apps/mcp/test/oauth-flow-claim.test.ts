/**
 * The ATOMIC single-use claim on an in-flight MCP OAuth flow
 * (`src/oauth-flow.ts`), exercised against the REAL Durable Object
 * `@cloudflare/vitest-pool-workers` boots in workerd — the same DO
 * implementation `wrangler dev --local` runs, no mocks.
 *
 * Why this file exists as its own suite: the anonymous
 * `GET /v1/mcp/identity/callback` has NO FerroGate credential, so the flow
 * record being claimed EXACTLY ONCE is the whole of its authorization. The KV
 * store cannot promise that (no compare-and-swap), and the test that matters is
 * therefore the CONCURRENT one — a sequential replay would pass against the KV
 * store too and would prove nothing about atomicity.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { DurableCredentialStore, KvOauthFlowStore } from "../src/durable.js";
import { DurableOauthFlowStore, type McpOauthFlowClaim } from "../src/oauth-flow.js";
import type { McpIdentityActor, StoredMcpOauthFlow } from "../src/ports.js";
import { tenantDataNamespace } from "./tenant-storage.js";

const FLOWS = env.MCP_OAUTH_FLOWS as unknown as DurableObjectNamespace<McpOauthFlowClaim>;
const KV = env.MCP_OAUTH_KV as unknown as KVNamespace;
const DB = env.DB as unknown as D1Database;
const TENANT_DATA = tenantDataNamespace(env);

const ACTOR: McpIdentityActor = { tenantId: "t1", workspaceId: "w1", userId: "u1" };

let seq = 0;

function flow(overrides: Partial<StoredMcpOauthFlow> = {}): StoredMcpOauthFlow {
  seq += 1;
  return {
    // A DISTINCT digest per flow: DO storage survives between tests in this
    // pool, so reusing an id would let an earlier test's record be the one a
    // later claim consumes.
    id: `state-digest-${seq}`,
    actor: ACTOR,
    serverName: "srv",
    pkceNonce: new Uint8Array([1, 2, 3]),
    pkceCiphertext: new Uint8Array([4, 5, 6]),
    oidcNonce: "nonce",
    authorizationGeneration: 7,
    createdAtUnix: 1_000,
    expiresAtUnix: 1_600,
    ...overrides,
  };
}

describe("McpOauthFlowClaim — the atomic single-use claim", () => {
  it("round-trips the record, field for field", async () => {
    const store = new DurableOauthFlowStore(FLOWS);
    const began = flow();
    await store.begin(began);

    const consumed = await store.consume(began.id, 1_100);
    // Not just "defined": the PKCE ciphertext and the generation are what the
    // callback needs to finish the exchange, so a store that round-trips only
    // the id would be useless while still looking single-use.
    expect(consumed).toEqual(began);
  });

  it("is single-use — a sequential replay finds nothing", async () => {
    const store = new DurableOauthFlowStore(FLOWS);
    const began = flow();
    await store.begin(began);

    expect(await store.consume(began.id, 1_100)).toBeDefined();
    expect(await store.consume(began.id, 1_100)).toBeUndefined();
  });

  /** Race four claims on one state through `store` and count the winners. */
  async function raceWinners(
    store: { consume(id: string, now: number): Promise<StoredMcpOauthFlow | undefined> },
    began: StoredMcpOauthFlow,
  ): Promise<(StoredMcpOauthFlow | undefined)[]> {
    // All four promises are created BEFORE any is awaited, so the claims are
    // genuinely in flight together rather than serialized by the test itself.
    const racers = [
      store.consume(began.id, 1_100),
      store.consume(began.id, 1_100),
      store.consume(began.id, 1_100),
      store.consume(began.id, 1_100),
    ];
    return (await Promise.all(racers)).filter((result) => result !== undefined);
  }

  it("CONCURRENT claims on one state: exactly one wins — where KV serves ALL FOUR", async () => {
    // The assertion this whole module exists for, stated against a CONTROL.
    //
    // "Exactly one winner" alone would be a weak claim: it has to be shown that
    // the primitive being replaced actually FAILS this same race, or the test
    // proves nothing about why the Durable Object was introduced. So the same
    // race runs through `KvOauthFlowStore` (get + delete, no compare-and-swap)
    // and through the DO claim, and the two must disagree.
    const kvFlow = flow();
    await new KvOauthFlowStore(KV).begin(kvFlow);
    const kvWinners = await raceWinners(new KvOauthFlowStore(KV), kvFlow);

    const doStore = new DurableOauthFlowStore(FLOWS);
    const doFlow = flow();
    await doStore.begin(doFlow);
    const doWinners = await raceWinners(doStore, doFlow);

    // KV hands the SAME single-use authorization to every racer.
    expect(kvWinners.length).toBeGreaterThan(1);
    // The Durable Object hands it to exactly one, which is the Rust behavior.
    expect(doWinners).toHaveLength(1);
    expect(doWinners[0]).toEqual(doFlow);
  });

  it("an EXPIRED record is refused and is still consumed", async () => {
    const store = new DurableOauthFlowStore(FLOWS);
    const began = flow({ expiresAtUnix: 1_500 });
    await store.begin(began);

    // `expiresAtUnix` is authoritative and checked in code, not left to a TTL.
    expect(await store.consume(began.id, 1_500)).toBeUndefined();
    // And it was SPENT: an expired record must not linger as a claimable key.
    expect(await store.consume(began.id, 1_000)).toBeUndefined();
  });

  it("an unknown state digest is undefined, not an error", async () => {
    const store = new DurableOauthFlowStore(FLOWS);
    expect(await store.consume("never-began", 1_100)).toBeUndefined();
  });

  it("distinct state digests do not contend — each is its own instance", async () => {
    const store = new DurableOauthFlowStore(FLOWS);
    const first = flow();
    const second = flow();
    await store.begin(first);
    await store.begin(second);

    // Claiming one must not consume the other; `idFromName` shards by digest.
    expect(await store.consume(first.id, 1_100)).toEqual(first);
    expect(await store.consume(second.id, 1_100)).toEqual(second);
  });

  it("DurableCredentialStore routes flows through the claim it was given", async () => {
    // The composition, not just the class: a store constructed with the DO
    // claim must not quietly keep using KV underneath.
    const store = new DurableCredentialStore(KV, TENANT_DATA, new DurableOauthFlowStore(FLOWS));
    const began = flow();
    await store.beginOauthFlow(began);

    // Nothing landed in KV — the KV store cannot see this flow at all.
    expect(await new KvOauthFlowStore(KV).consume(began.id, 1_100)).toBeUndefined();
    // And the DO claim serves it exactly once.
    expect(await store.consumeOauthFlow(began.id, 1_100)).toEqual(began);
    expect(await store.consumeOauthFlow(began.id, 1_100)).toBeUndefined();
  });

  it("resolvePorts binds the ATOMIC claim whenever the namespace is bound", async () => {
    // Guards the composition root: an implementation nobody wires is dead code,
    // and this Worker's readiness posture must not silently fall back to KV.
    const { resolvePorts } = await import("../src/ports.js");
    const ports = resolvePorts({
      DB,
      TENANT_DATA,
      MCP_OAUTH_KV: KV,
      MCP_OAUTH_FLOWS: FLOWS,
      FERROGATE_MCP_IDENTITY_KEY: "a".repeat(64),
    });
    const began = flow();
    await ports.credentials.beginOauthFlow(began);

    expect(await new KvOauthFlowStore(KV).consume(began.id, 1_100)).toBeUndefined();
    expect(await ports.credentials.consumeOauthFlow(began.id, 1_100)).toEqual(began);
  });

  it("WITHOUT the tenant object it does not bind an identity store", async () => {
    // A flat control D1 is not a valid identity fallback after the cutover.
    const { resolvePorts } = await import("../src/ports.js");
    const ports = resolvePorts({
      DB,
      MCP_OAUTH_KV: KV,
      FERROGATE_MCP_IDENTITY_KEY: "a".repeat(64),
    });
    expect(ports.credentials).not.toBeInstanceOf(DurableCredentialStore);
  });
});
