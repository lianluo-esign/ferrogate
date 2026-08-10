import { AuthProvider } from "@/hooks/use-auth";
import { CatalogScopeProvider } from "@/hooks/use-catalog-scope";
import { I18nProvider } from "@/i18n";
import type { AdminSchema } from "@/lib/gateway-client";
import ModelOfferingsPage from "@/pages/model-offerings";
import { gatewayUrl, server } from "@/test/msw";
import { TEST_GATEWAY_API_KEY, createTestQueryClient, seedSession } from "@/test/test-utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";

const OPERATOR_KEY = "fg-platform-operator-key";
const MODEL_ID = "m1";

type Offering = AdminSchema<"AdminOffering">;

function offering(overrides: Partial<Offering> = {}): Offering {
  return {
    id: "off-1",
    model_id: MODEL_ID,
    provider_id: "provider-openai",
    upstream_model_id: "gpt-4o",
    role: "primary",
    priority: 10,
    enabled: true,
    scope: "tenant",
    ...overrides,
  };
}

interface CapturedPost {
  authorization: string | null;
  body: Record<string, unknown>;
  hasTenantQuery: boolean;
}

/** A superadmin session: carries the platform-operator credential (#912). */
function seedSuperadmin(): void {
  seedSession({
    user: {
      id: "user-1",
      email: "root@example.com",
      display_name: "Root",
      superadmin: true,
    },
    platformOperatorApiKey: OPERATOR_KEY,
  });
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={[`/app/models/${MODEL_ID}/offerings`]}>
      <I18nProvider initialLocale="en">
        <AuthProvider>
          <CatalogScopeProvider>
            <QueryClientProvider client={createTestQueryClient()}>
              <Routes>
                <Route path="/app/models/:modelId/offerings" element={<ModelOfferingsPage />} />
              </Routes>
            </QueryClientProvider>
          </CatalogScopeProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

/** Registers the offerings list + a POST capture; returns the capture array. */
function stubOfferings(): CapturedPost[] {
  const posts: CapturedPost[] = [];
  server.use(
    http.get(gatewayUrl(`/admin/v1/models/${MODEL_ID}/offerings`), () =>
      HttpResponse.json({ object: "list", data: [offering()] }),
    ),
    http.post(gatewayUrl(`/admin/v1/models/${MODEL_ID}/offerings`), async ({ request }) => {
      const url = new URL(request.url);
      posts.push({
        authorization: request.headers.get("authorization"),
        body: (await request.json()) as Record<string, unknown>,
        hasTenantQuery: url.searchParams.has("tenant_id"),
      });
      return HttpResponse.json(
        { object: "offering", offering: offering({ id: "off-2" }), scope: "tenant" },
        { status: 201 },
      );
    }),
  );
  return posts;
}

async function submitNewOffering(): Promise<void> {
  await userEvent.click(await screen.findByRole("button", { name: "New" }));
  await userEvent.type(await screen.findByLabelText("Provider ID *"), "provider-anthropic");
  await userEvent.type(screen.getByLabelText("Upstream model ID *"), "claude-3-5-sonnet");
  await userEvent.click(screen.getByRole("button", { name: "Create" }));
}

describe("ModelOfferingsPage", () => {
  beforeEach(() => {
    seedSession();
  });

  it("lists the offerings attached to a model", async () => {
    stubOfferings();
    renderPage();

    expect(
      await screen.findByRole("heading", { name: `Offerings for ${MODEL_ID}` }),
    ).toBeInTheDocument();
    expect(await screen.findByText("provider-openai")).toBeInTheDocument();
    expect(screen.getByText("gpt-4o")).toBeInTheDocument();
  });

  it("creates an offering via POST to the nested endpoint (tenant scope by default)", async () => {
    const posts = stubOfferings();
    renderPage();
    await screen.findByText("provider-openai");

    await submitNewOffering();

    await waitFor(() => expect(posts).toHaveLength(1));
    // Default (tenant) scope: the session gateway key, and NO tenant_id.
    expect(posts[0].authorization).toBe(`Bearer ${TEST_GATEWAY_API_KEY}`);
    expect(posts[0].body).toMatchObject({
      provider_id: "provider-anthropic",
      upstream_model_id: "claude-3-5-sonnet",
    });
    expect(posts[0].body).not.toHaveProperty("tenant_id");
    expect(posts[0].hasTenantQuery).toBe(false);
  });

  it("does not render the scope toggle for a non-superadmin session", async () => {
    stubOfferings();
    renderPage();
    await screen.findByText("provider-openai");

    expect(screen.queryByRole("switch")).not.toBeInTheDocument();
  });
});

describe("ModelOfferingsPage sync-models action (#946)", () => {
  it("posts sync-models for the row's provider and reports the result", async () => {
    seedSuperadmin();
    stubOfferings();
    const syncs: { url: string; authorization: string | null }[] = [];
    server.use(
      http.post(
        gatewayUrl("/admin/v1/providers/provider-openai/sync-models"),
        ({ request }) => {
          syncs.push({
            url: request.url,
            authorization: request.headers.get("authorization"),
          });
          return HttpResponse.json({
            object: "provider_model_sync",
            scope: "platform",
            provider_id: "provider-openai",
            added: 3,
            updated: 0,
            skipped: 5,
            upstream_count: 8,
            revision: 2,
          });
        },
      ),
    );
    renderPage();
    await screen.findByText("provider-openai");

    // Flip to platform scope so the sync rides the operator key, then trigger it
    // from the offering row's action.
    await userEvent.click(screen.getByRole("switch"));
    await userEvent.click(screen.getByRole("button", { name: "Sync models" }));

    await waitFor(() => expect(syncs).toHaveLength(1));
    expect(syncs[0].url).toContain("/admin/v1/providers/provider-openai/sync-models");
    expect(syncs[0].authorization).toBe(`Bearer ${OPERATOR_KEY}`);
  });
});

describe("ModelOfferingsPage platform scope", () => {
  it("sends the operator key and NO tenant_id after toggling platform scope", async () => {
    seedSuperadmin();
    const posts = stubOfferings();
    renderPage();
    await screen.findByText("provider-openai");

    // Flip to platform scope (the only switch on the page until the form opens),
    // then create an offering.
    await userEvent.click(screen.getByRole("switch"));
    await submitNewOffering();

    await waitFor(() => expect(posts).toHaveLength(1));
    // Scope is resolved purely from which credential asked — the operator key,
    // and STILL no tenant_id in body or query.
    expect(posts[0].authorization).toBe(`Bearer ${OPERATOR_KEY}`);
    expect(posts[0].body).not.toHaveProperty("tenant_id");
    expect(posts[0].hasTenantQuery).toBe(false);
  });
});
