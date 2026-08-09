import { ResourcePage } from "@/components/resource/resource-page";
import { modelsConfig } from "@/resources/models";
import { providersConfig } from "@/resources/providers";
import { gatewayUrl, server } from "@/test/msw";
import { TEST_GATEWAY_API_KEY, renderWithProviders, seedSession } from "@/test/test-utils";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

const OPERATOR_KEY = "fg-platform-operator-key";

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

async function submitNewProvider(): Promise<void> {
  await userEvent.click(await screen.findByRole("button", { name: "New" }));
  await userEvent.type(await screen.findByLabelText("Name *"), "Anthropic");
  await userEvent.type(screen.getByLabelText("Kind *"), "anthropic");
  await userEvent.type(screen.getByLabelText("Base URL *"), "https://api.anthropic.com");
  await userEvent.click(screen.getByRole("button", { name: "Create" }));
}

describe("provider CRUD scope", () => {
  it("sends the tenant key by default and the operator key (no tenant_id) after toggling platform", async () => {
    seedSuperadmin();
    const posts: CapturedPost[] = [];
    server.use(
      http.get(gatewayUrl("/admin/v1/providers"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            {
              id: "p1",
              name: "OpenAI",
              kind: "openai",
              compatibility: "openai-compatible",
              base_url: "https://api.openai.com/v1",
              has_api_key: true,
              enabled: true,
            },
          ],
        }),
      ),
      http.post(gatewayUrl("/admin/v1/providers"), async ({ request }) => {
        const url = new URL(request.url);
        posts.push({
          authorization: request.headers.get("authorization"),
          body: (await request.json()) as Record<string, unknown>,
          hasTenantQuery: url.searchParams.has("tenant_id"),
        });
        return HttpResponse.json({ id: "p2", name: "Anthropic" }, { status: 201 });
      }),
    );

    renderWithProviders(<ResourcePage config={providersConfig} />);
    await screen.findByText("OpenAI");

    // Tenant scope (default): the POST carries the session gateway key.
    await submitNewProvider();
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0].authorization).toBe(`Bearer ${TEST_GATEWAY_API_KEY}`);
    expect(posts[0].body).not.toHaveProperty("tenant_id");
    expect(posts[0].hasTenantQuery).toBe(false);

    // Flip to platform scope, then create again.
    await userEvent.click(screen.getByRole("switch"));
    await submitNewProvider();
    await waitFor(() => expect(posts).toHaveLength(2));

    // Platform scope: the POST now carries the operator key and STILL sends no
    // tenant_id — scope is resolved purely from which credential asked.
    expect(posts[1].authorization).toBe(`Bearer ${OPERATOR_KEY}`);
    expect(posts[1].body).not.toHaveProperty("tenant_id");
    expect(posts[1].hasTenantQuery).toBe(false);
  });
});

describe("model CRUD scope", () => {
  it("creates a model under platform scope with the operator key and no tenant_id", async () => {
    seedSuperadmin();
    const posts: CapturedPost[] = [];
    server.use(
      http.get(gatewayUrl("/admin/v1/models"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            {
              id: "m1",
              name: "gpt-4o",
              provider: "openai",
              provider_model: "openai:gpt-4o",
              routing_strategy: "priority",
              capabilities: ["chat"],
              context_window: 128000,
              enabled: true,
            },
          ],
        }),
      ),
      http.post(gatewayUrl("/admin/v1/models"), async ({ request }) => {
        const url = new URL(request.url);
        posts.push({
          authorization: request.headers.get("authorization"),
          body: (await request.json()) as Record<string, unknown>,
          hasTenantQuery: url.searchParams.has("tenant_id"),
        });
        return HttpResponse.json({ id: "m2", name: "claude-3.5" }, { status: 201 });
      }),
    );

    renderWithProviders(<ResourcePage config={modelsConfig} />);
    await screen.findByText("gpt-4o");

    await userEvent.click(screen.getByRole("switch"));
    await userEvent.click(await screen.findByRole("button", { name: "New" }));
    await userEvent.type(await screen.findByLabelText("Name *"), "claude-3.5");
    await userEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0].authorization).toBe(`Bearer ${OPERATOR_KEY}`);
    expect(posts[0].body).not.toHaveProperty("tenant_id");
    expect(posts[0].hasTenantQuery).toBe(false);
  });
});
