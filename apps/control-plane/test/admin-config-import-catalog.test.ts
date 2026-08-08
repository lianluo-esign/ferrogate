import { SELF, env } from "cloudflare:test";
/**
 * The platform-catalog bootstrap import (#892) over the config-ops surface.
 *
 * Drives the real `POST /admin/v1/config/import-model-catalog` operation and
 * then reads the platform tables with RAW SQL — reading back only through the
 * store would prove the store agrees with itself, this repo's dominant defect
 * mode. The three invariants the issue names are asserted directly:
 *
 *   1. an env pair becomes real provider/model/offering rows, and the default
 *      rate card becomes `platform`-kind priced offerings;
 *   2. a re-run changes NOTHING but the revision (idempotent natural keys);
 *   3. the write is fenced to platform operators.
 *
 * Plus the seam #892 must not break: `exportForSeed` (#891) excludes the
 * price-only `platform`-kind rows so a seeded tenant never inherits a channel it
 * cannot route through.
 */
import { PriceBook } from "@ferrogate/billing";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { PlatformModelCatalogStore } from "../src/store/platform-model-catalog.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

const OPERATOR = operatorKey.secret;
const DEFAULT_CONTROL_STORAGE = "d1_compat";

interface JsonBody {
  readonly [key: string]: unknown;
}
interface TestResponse {
  readonly status: number;
  readonly body: JsonBody;
}

async function request(
  secret: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<TestResponse> {
  const response = await SELF.fetch(
    `${BASE}${path}`,
    body === undefined || method === "GET"
      ? { method, headers: bearer(secret) }
      : jsonRequest(secret, method, body),
  );
  return { status: response.status, body: (await response.json()) as JsonBody };
}

function controlStorage(mode: string): void {
  (env as unknown as Record<string, string | undefined>).CONTROL_PLANE_CONTROL_STORAGE = mode;
}

const IMPORT_PATH = "/admin/v1/config/import-model-catalog";

/** A small but representative env pair: two real providers, a fallback, prices, capabilities. */
const PROVIDERS = [
  {
    name: "openai",
    kind: "openai-compatible",
    base_url: "https://api.openai.example/v1",
    api_key_var: "OPENAI_KEY",
  },
  {
    name: "anthropic",
    kind: "anthropic",
    base_url: "https://api.anthropic.example",
    api_key_var: "ANTHROPIC_KEY",
    auth_scheme: "x-api-key",
  },
];
const MODELS = [
  {
    name: "smart",
    provider: "openai",
    provider_model: "gpt-4o",
    capabilities: ["chat", "streaming"],
    routing_strategy: "priority",
    input_price_per_1m: 2.5,
    output_price_per_1m: 10,
    fallbacks: [
      {
        provider: "anthropic",
        provider_model: "claude-sonnet-4",
        capabilities: ["chat"],
        input_price_per_1m: 3,
        output_price_per_1m: 15,
      },
    ],
  },
  {
    name: "fast",
    provider: "openai",
    provider_model: "gpt-4o-mini",
    capabilities: ["chat"],
    routing_strategy: "priority",
    input_price_per_1m: 0.15,
    output_price_per_1m: 0.6,
  },
];

function importBody(includeRateCard = true): Record<string, unknown> {
  return {
    providers: PROVIDERS,
    models: MODELS,
    include_default_rate_card: includeRateCard,
  };
}

/** How many rate-card models are NOT shadowed by an env model name. */
function rateCardModelCount(): number {
  const envNames = new Set(MODELS.map((model) => model.name));
  return PriceBook.withDefaultRateCard().entries.filter(
    (entry) => entry.provider === "*" && !envNames.has(entry.model),
  ).length;
}

async function tableCount(table: string): Promise<number> {
  const row = await db().prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>();
  return Number(row?.n ?? 0);
}

async function platformRevision(): Promise<number> {
  const row = await db()
    .prepare("SELECT revision FROM platform_catalog_revisions WHERE id = 1")
    .first<{ revision: number | string }>();
  return Number(row?.revision ?? 0);
}

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  controlStorage(DEFAULT_CONTROL_STORAGE);
  await resetD1();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey("tenant-secret", "tenant_a")],
  });
});

afterEach(() => {
  controlStorage(DEFAULT_CONTROL_STORAGE);
});

describe("platform catalog bootstrap import (#892)", () => {
  it("imports the env pair as real rows and the rate card as platform-kind price rows", async () => {
    const cardModels = rateCardModelCount();
    const response = await request(OPERATOR, "POST", IMPORT_PATH, importBody());
    expect(response.status, JSON.stringify(response.body)).toBe(200);
    expect(response.body.object).toBe("platform_catalog_import");
    expect(response.body.scope).toBe("platform");

    // providers: openai, anthropic, and the synthetic platform-default channel.
    // models: 2 env + the rate card. offerings: primary + fallback + primary,
    // plus one per rate-card model.
    expect(response.body.counts).toEqual({
      providers: 3,
      models: 2 + cardModels,
      offerings: 3 + cardModels,
    });
    expect(response.body.inserted).toEqual(response.body.counts);
    expect(response.body.revision).toBe(1);

    // Real providers keep their real kind; only the rate-card channel is platform.
    const kinds = new Map(
      (
        await db().prepare("SELECT id, kind FROM platform_provider_channels").all<{
          id: string;
          kind: string;
        }>()
      ).results.map((row) => [row.id, row.kind]),
    );
    expect(kinds.get("platform:provider:openai")).toBe("openai-compatible");
    expect(kinds.get("platform:provider:anthropic")).toBe("anthropic");
    expect(kinds.get("platform:provider:platform-default")).toBe("platform");

    // The env primary price round-tripped, and the rate card's cache multiplier
    // was materialized (gpt-4o input 2.5 x 0.5 = 1.25).
    const smartPrimary = await db()
      .prepare("SELECT input_price_per_1m, role FROM platform_catalog_offerings WHERE id = ?")
      .bind("platform:offering:smart:openai:gpt-4o")
      .first<{ input_price_per_1m: number; role: string }>();
    expect(smartPrimary?.role).toBe("primary");
    expect(smartPrimary?.input_price_per_1m).toBe(2.5);

    const cardOffering = await db()
      .prepare(
        "SELECT input_price_per_1m, cached_input_price_per_1m, source FROM platform_catalog_offerings WHERE id = ?",
      )
      .bind("platform:offering:gpt-4o:platform-default:gpt-4o")
      .first<{ input_price_per_1m: number; cached_input_price_per_1m: number; source: string }>();
    expect(cardOffering?.input_price_per_1m).toBe(2.5);
    expect(cardOffering?.cached_input_price_per_1m).toBeCloseTo(1.25, 6);
    expect(cardOffering?.source).toBe("default_rate_card");

    // Exactly one audit row for the whole import (not one per row).
    const auditCount = await db()
      .prepare(
        "SELECT COUNT(*) AS n FROM audit_events WHERE audit_json LIKE '%platform_catalog_import%'",
      )
      .first<{ n: number }>();
    expect(Number(auditCount?.n ?? 0)).toBe(1);
  });

  it("is idempotent: a re-run changes nothing but the revision", async () => {
    const first = await request(OPERATOR, "POST", IMPORT_PATH, importBody());
    expect(first.status).toBe(200);
    const providersAfterFirst = await tableCount("platform_provider_channels");
    const modelsAfterFirst = await tableCount("platform_catalog_models");
    const offeringsAfterFirst = await tableCount("platform_catalog_offerings");
    expect(await platformRevision()).toBe(1);

    const second = await request(OPERATOR, "POST", IMPORT_PATH, importBody());
    expect(second.status).toBe(200);
    // Nothing new inserted; the totals are unchanged; only the revision moved.
    expect(second.body.inserted).toEqual({ providers: 0, models: 0, offerings: 0 });
    expect(second.body.revision).toBe(2);
    expect(await tableCount("platform_provider_channels")).toBe(providersAfterFirst);
    expect(await tableCount("platform_catalog_models")).toBe(modelsAfterFirst);
    expect(await tableCount("platform_catalog_offerings")).toBe(offeringsAfterFirst);
    expect(await platformRevision()).toBe(2);
  });

  it("promotes a rate-card-only model to a real route when a re-import adds it to env (#892)", async () => {
    // Import #1: real providers but NO env models, rate card on. `gpt-4o` is a
    // default-card name, so it lands as a `platform-default` PRIMARY price row —
    // priced, but with no routable upstream.
    const first = await request(OPERATOR, "POST", IMPORT_PATH, {
      providers: PROVIDERS,
      models: [],
      include_default_rate_card: true,
    });
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    const cardPrimary = await db()
      .prepare("SELECT role, provider_id FROM platform_catalog_offerings WHERE id = ?")
      .bind("platform:offering:gpt-4o:platform-default:gpt-4o")
      .first<{ role: string; provider_id: string }>();
    expect(cardPrimary?.role).toBe("primary");
    expect(cardPrimary?.provider_id).toBe("platform:provider:platform-default");

    // Import #2: the operator adds gpt-4o to GATEWAY_MODELS and re-runs — the
    // advertised "sync env changes" flow. The rate card now EXCLUDES gpt-4o, and
    // the real env primary must take the `ux_..._primary` slot the stale card row
    // held; without the purge its INSERT OR IGNORE would be dropped and gpt-4o
    // would stay unroutable (only the excluded platform-default offering).
    const second = await request(OPERATOR, "POST", IMPORT_PATH, {
      providers: PROVIDERS,
      models: [
        { name: "gpt-4o", provider: "openai", provider_model: "gpt-4o", capabilities: ["chat"] },
      ],
      include_default_rate_card: true,
    });
    expect(second.status, JSON.stringify(second.body)).toBe(200);
    // The transition inserts the real primary — not a pure no-op re-run.
    expect((second.body.inserted as { offerings: number }).offerings).toBeGreaterThanOrEqual(1);

    // The stale platform-default price offering is gone.
    const stale = await db()
      .prepare("SELECT id FROM platform_catalog_offerings WHERE id = ?")
      .bind("platform:offering:gpt-4o:platform-default:gpt-4o")
      .first<{ id: string }>();
    expect(stale).toBeNull();

    // gpt-4o now has exactly ONE primary, on the REAL openai channel — routable.
    const primaries = (
      await db()
        .prepare(
          "SELECT id, provider_id FROM platform_catalog_offerings WHERE model_id = ? AND role = 'primary'",
        )
        .bind("platform:model:gpt-4o")
        .all<{ id: string; provider_id: string }>()
    ).results;
    expect(primaries).toHaveLength(1);
    expect(primaries[0]?.id).toBe("platform:offering:gpt-4o:openai:gpt-4o");
    expect(primaries[0]?.provider_id).toBe("platform:provider:openai");
  });

  it("omits the rate card when include_default_rate_card is false", async () => {
    const response = await request(OPERATOR, "POST", IMPORT_PATH, importBody(false));
    expect(response.status).toBe(200);
    expect(response.body.counts).toEqual({ providers: 2, models: 2, offerings: 3 });
    const platformDefault = await db()
      .prepare("SELECT id FROM platform_provider_channels WHERE kind = 'platform'")
      .first<{ id: string }>();
    expect(platformDefault).toBeNull();
  });

  it("rejects a tenant-scoped caller with 403 before any write", async () => {
    const response = await request("tenant-secret", "POST", IMPORT_PATH, importBody());
    expect(response.status).toBe(403);
    expect(response.body.error).toBeDefined();
    expect(await tableCount("platform_provider_channels")).toBe(0);
  });

  it("rejects an invalid env pair with 400 and writes nothing", async () => {
    const response = await request(OPERATOR, "POST", IMPORT_PATH, {
      providers: PROVIDERS,
      // `smart` names a provider that is not in the table.
      models: [{ name: "orphan", provider: "missing", provider_model: "x" }],
    });
    expect(response.status).toBe(400);
    expect(await tableCount("platform_catalog_models")).toBe(0);
  });

  it("exportForSeed excludes the price-only platform-kind rows (#891 seam)", async () => {
    await request(OPERATOR, "POST", IMPORT_PATH, importBody());
    const store = new PlatformModelCatalogStore({ db: db() });
    const graph = await store.exportForSeed();

    // The seed carries the two REAL channels, never the platform-default one.
    expect(graph.providers.map((p) => p.name).sort()).toEqual(["anthropic", "openai"]);
    expect(graph.providers.some((p) => p.kind === "platform")).toBe(false);
    // The rate-card models (which have only a platform-default offering) are dropped.
    expect(graph.models.map((m) => m.name).sort()).toEqual(["fast", "smart"]);
    // Every seeded offering references a real channel, none the platform-default id.
    expect(
      graph.offerings.some((o) => o.provider_id === "platform:provider:platform-default"),
    ).toBe(false);
    expect(graph.offerings).toHaveLength(3);
  });
});
