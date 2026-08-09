/**
 * ANTI-UNMOUNT for the APP-WIDE half of the telemetry egress —
 * `requestTelemetry()` in `GATEWAY_MIDDLEWARE` (`src/index.ts`).
 *
 * ## Why this file exists alongside `mount.test.ts`
 *
 * `test/telemetry/mount.test.ts` proves the emission that
 * `src/inference/route-module.ts` makes, so it covers the SIX inference
 * operations. It stays green if the composition root never mounts the
 * middleware — and then the other 25 gateway operations (every asset push,
 * every pull, every yank) emit nothing, which is the wave's own defect shape
 * one layer out: a wired emitter with a partial mount looks identical to a
 * complete one from the inference suite.
 *
 * So this file drives a NON-inference operation — an asset push, contract
 * operation `putAsset` — through `SELF.fetch`, i.e. `src/worker.ts` →
 * `src/index.ts` → `createGatewayApp` → `GATEWAY_MIDDLEWARE`. Nothing on that
 * path emits except the middleware.
 *
 * MUTATION: delete `requestTelemetry()` from `GATEWAY_MIDDLEWARE` and the
 * `waitForCollected` below times out at zero received batches, while
 * `mount.test.ts` and the rest of the suite stay green.
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { seedApiKey } from "../keys/seed.js";

const BASE = "https://gw.test";
const TENANT = "tenant_telemetry_mw";
const PLAN = "plan_telemetry_mw";
/** `fg_` + 48 hex, the shape `virtualApiKeyPrefix` recognises. */
const SECRET = `fg_${"b7c1d2e3".repeat(6)}`;

interface CollectedOtlp {
  readonly path: string;
  readonly authorization: string | null;
  readonly tenant: string | null;
  readonly body: Record<string, unknown>;
}

const collected: CollectedOtlp[] = [];

/** The shape production gets from `[[services]] TELEMETRY_COLLECTOR`. */
const COLLECTOR = {
  async fetch(request: Request): Promise<Response> {
    collected.push({
      path: new URL(request.url).pathname,
      authorization: request.headers.get("authorization"),
      tenant: request.headers.get("x-ferrogate-tenant"),
      body: (await request.json()) as Record<string, unknown>,
    });
    return new Response(JSON.stringify({ partialSuccess: {} }), { status: 200 });
  },
};

const OVERRIDES: Record<string, unknown> = {
  TELEMETRY_COLLECTOR: COLLECTOR,
  TELEMETRY_TOKEN: "collector-secret",
};

const ORIGINAL: Record<string, unknown> = {};
const mutable = env as unknown as Record<string, unknown>;

interface Bindings {
  readonly DB?: D1Database;
  readonly CONTROL_DB?: D1Database;
}

function bindings(): { db: D1Database; control: D1Database } {
  const { DB, CONTROL_DB } = env as unknown as Bindings;
  if (DB === undefined || CONTROL_DB === undefined) {
    throw new Error(
      "expected both `DB` and `CONTROL_DB` (apps/gateway/wrangler.toml); " +
        "without them this file would 'pass' while proving nothing about the mount.",
    );
  }
  return { db: DB, control: CONTROL_DB };
}

beforeAll(() => {
  // Installed BEFORE the first `SELF.fetch`: `telemetryFromEnv` memoizes the
  // resolved emitter on the `env` object, so a request served before the
  // binding exists would cache the no-op for the whole isolate.
  for (const [name, value] of Object.entries(OVERRIDES)) {
    ORIGINAL[name] = mutable[name];
    mutable[name] = value;
  }
});

afterAll(() => {
  for (const [name, value] of Object.entries(ORIGINAL)) {
    mutable[name] = value;
  }
});

afterEach(() => {
  collected.length = 0;
});

/** Provision the durable credential + plan the asset surface requires. */
beforeEach(async () => {
  const { db, control } = bindings();
  await db.prepare("DELETE FROM stored_assets").run();
  await db.prepare("DELETE FROM asset_channels").run();
  await db.prepare("DELETE FROM api_keys WHERE tenant_id = ?1").bind(TENANT).run();
  await seedApiKey({
    id: "key_telemetry_mw",
    secret: SECRET,
    tenantId: TENANT,
    scopes: ["assets.read", "assets.write"],
  });
  await control
    .prepare(
      "INSERT OR REPLACE INTO plans (id, name, slug, asset_hosting_enabled) VALUES (?1, ?2, ?3, 1)",
    )
    .bind(PLAN, "telemetry mw", PLAN)
    .run();
  await control
    .prepare(
      "INSERT OR REPLACE INTO tenants (id, name, slug, status, plan_id) VALUES " +
        "(?1, ?2, ?3, 'active', ?4)",
    )
    .bind(TENANT, "telemetry mw", TENANT, PLAN)
    .run();
  // `tenant_telemetry_mw` is not one of `test/setup-d1.ts`'s fixture tenants,
  // and the durable_object routing default reads the `tenant_databases` roster
  // on every authenticated request — without this row the asset push is
  // answered `503 quota_resolution_unavailable` before any telemetry emission,
  // which would make the mount gate fail for a reason unrelated to the mount.
  // `migration_state` stated as `done` (the DDL default is the pre-cutover
  // `shared`), same explicit form as `test/assets/wiring.test.ts`.
  await control
    .prepare(
      "INSERT OR REPLACE INTO tenant_databases " +
        "(tenant_id, storage_backend, provisioning_status, schema_version, migration_state, migration_epoch) " +
        "VALUES (?1, 'durable_object', 'ready', 1, 'done', 0)",
    )
    .bind(TENANT)
    .run();
});

/** The emission rides `ctx.waitUntil`, so it lands after the response. */
async function waitForCollected(count: number): Promise<void> {
  for (let index = 0; index < 300; index += 1) {
    if (collected.length >= count) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  throw new Error(
    `timed out waiting for ${count} OTLP request(s); the deployed Worker emitted ${collected.length}. \`requestTelemetry()\` is not in GATEWAY_MIDDLEWARE, so the 25 non-inference operations emit nothing.`,
  );
}

describe("the deployed Worker emits telemetry for NON-inference operations", () => {
  it("an asset push emits an OTLP trace + metric batch", async () => {
    const response = await SELF.fetch(`${BASE}/v1/assets/binaries/probe/1.0.0`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${SECRET}`,
        "content-type": "application/octet-stream",
      },
      body: "telemetry-middleware-probe",
    });
    expect(response.status).toBe(200);

    // THE MOUNT GATE.
    await waitForCollected(2);
    expect(collected.map((entry) => entry.path)).toEqual(["/v1/traces", "/v1/metrics"]);
    for (const entry of collected) {
      // Exactly what `apps/telemetry/src/auth.ts::requireBearer` compares.
      expect(entry.authorization).toBe("Bearer collector-secret");
      // The AUTHENTICATED tenant of the durable api key, used as the AE index.
      expect(entry.tenant).toBe(TENANT);
    }
  });

  it("the span carries the ASSET operation id the deployed router matched", async () => {
    const response = await SELF.fetch(`${BASE}/v1/assets/binaries/probe/2.0.0`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${SECRET}`,
        "content-type": "application/octet-stream",
      },
      body: "telemetry-middleware-probe-2",
    });
    expect(response.status).toBe(200);
    const servedRequestId = response.headers.get("x-request-id");
    await waitForCollected(2);

    const traces = collected[0]?.body as {
      resourceSpans: [
        {
          scopeSpans: [
            {
              spans: {
                name: string;
                attributes: { key: string; value: { stringValue: string } }[];
              }[];
            },
          ];
        },
      ];
    };
    const span = traces.resourceSpans[0].scopeSpans[0].spans[0]!;
    const attributes = Object.fromEntries(
      span.attributes.map((attribute) => [attribute.key, attribute.value.stringValue]),
    );

    expect(span.name).toBe("ferrogate.gateway.request");
    // A CONTRACT operation id from outside the inference group — proof the
    // emission came from the app-wide mount and not from
    // `src/inference/route-module.ts`, which never sees this request.
    expect(attributes.route).toBe("putAsset");
    expect(attributes.method).toBe("PUT");
    expect(attributes.path).toBe("/v1/assets/binaries/probe/2.0.0");
    expect(attributes.status_code).toBe("200");
    expect(servedRequestId).toBeTruthy();
    expect(attributes.request_id).toBe(servedRequestId);
  });
});
