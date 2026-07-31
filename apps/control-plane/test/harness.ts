/**
 * Shared test harness: declaratively arm the Worker's bindings.
 *
 * `SELF` dispatches into the same isolate the test runs in, so `env` from
 * `cloudflare:test` IS the object the Worker's `resolveDeps` reads. Arming the
 * bindings is therefore how a test states its world: which keys exist, which
 * are suspended, which tenants are suspended, what RBAC grants exist, and
 * whether an admin-console origin is configured.
 *
 * Every call mints a fresh `CONTROL_PLANE_SEED` nonce so `resolveDeps` rebuilds
 * the per-isolate in-memory store — otherwise state would leak between tests
 * and a passing assertion could be someone else's leftover row.
 *
 * `arm()` pins `CONTROL_PLANE_STORE = "memory"`. The Worker's DEFAULT is the D1
 * store whenever `DB` is bound (and `wrangler.toml` binds it, so it is bound
 * here too); these suites are about routing, auth, envelopes and status parity,
 * and they state their world through `CONTROL_PLANE_SEED`, which only the
 * in-memory store reads. The durable store is driven — through this same
 * exported Worker — by `d1-store.test.ts`, and the two stores are held to one
 * behavioural contract by `store-conformance.test.ts`.
 */
import { env } from "cloudflare:test";

export interface NativeKey {
  secret: string;
  id?: string;
  tenant_id?: string | null;
  scopes?: string[];
  enabled?: boolean;
  revoked?: boolean;
  expires_at?: number;
}

export interface StaticKey {
  secret: string;
  id?: string;
  organization_id?: string | null;
  scopes?: string[];
  enabled?: boolean;
  expires_at?: number;
  platform_operator?: boolean;
}

export interface World {
  nativeKeys?: NativeKey[];
  staticKeys?: StaticKey[];
  lifecycle?: Record<string, "active" | "disabled" | "suspended" | "deleted">;
  rbac?: Record<string, string[]>;
  seed?: Record<string, Record<string, unknown>[]>;
  corsAllowedOrigin?: string | null;
  /**
   * Which store the Worker builds for this test. Defaults to `"memory"` (see
   * the module docblock); `"d1"` leaves `CONTROL_PLANE_STORE` UNSET so the
   * Worker takes its production default — D1, because `wrangler.toml` binds
   * `DB`. `seed` is ignored under `"d1"`; seed those rows with
   * `seedD1` from `./d1.js` instead.
   */
  store?: "memory" | "d1";
}

let nonce = 0;

/** Bindings a test may write. Mirrors `ControlPlaneBindings`. */
type MutableEnv = Record<string, string | undefined>;

export function arm(world: World = {}): void {
  const bindings = env as unknown as MutableEnv;
  nonce += 1;

  // `undefined` (not `"d1"`) so the D1 suites exercise the DEFAULT branch of
  // `resolveStore`. Pinning the string would let the default rot to `memory`
  // with every test still green — the durable path would be tested only when
  // asked for, which is never in production.
  bindings.CONTROL_PLANE_STORE = world.store === "d1" ? undefined : "memory";
  bindings.CONTROL_PLANE_NATIVE_API_KEYS = JSON.stringify(world.nativeKeys ?? []);
  bindings.CONTROL_PLANE_STATIC_API_KEYS = JSON.stringify(world.staticKeys ?? []);
  bindings.TENANCY_LIFECYCLE = JSON.stringify(world.lifecycle ?? {});
  bindings.TENANT_RBAC_ACTIONS = JSON.stringify(world.rbac ?? {});
  // The nonce key is inert data in an unused collection; its only job is to
  // make the seed string differ so the store is rebuilt.
  bindings.CONTROL_PLANE_SEED = JSON.stringify({
    ...(world.seed ?? {}),
    __test_nonce: [{ id: String(nonce) }],
  });

  if (world.corsAllowedOrigin === undefined || world.corsAllowedOrigin === null) {
    // `delete` rather than `= ""`: "no console configured" must be the ABSENCE
    // of the binding, which is what a real deployment without a console has.
    bindings.ADMIN_CONSOLE_ALLOWED_ORIGIN = undefined;
  } else {
    bindings.ADMIN_CONSOLE_ALLOWED_ORIGIN = world.corsAllowedOrigin;
  }
}

/** A platform-operator static key: wildcard scopes, sees every tenant. */
export const OPERATOR_KEY = "operator-secret";
export const operatorKey: StaticKey = {
  secret: OPERATOR_KEY,
  id: "static_operator",
  platform_operator: true,
  scopes: ["*"],
};

/** A tenant-scoped native key with full admin scopes. */
export function tenantKey(
  secret: string,
  tenantId: string,
  scopes = ["admin.read", "admin.write"],
): NativeKey {
  return { secret, id: `key_${tenantId}`, tenant_id: tenantId, scopes };
}

export const BASE = "https://control-plane.test";

/** `Authorization: Bearer <secret>` header bag. */
export function bearer(secret: string): Record<string, string> {
  return { authorization: `Bearer ${secret}` };
}

/** JSON request init with a bearer credential. */
export function jsonRequest(secret: string, method: string, body: unknown): RequestInit {
  return {
    method,
    headers: { ...bearer(secret), "content-type": "application/json" },
    body: JSON.stringify(body),
  };
}
