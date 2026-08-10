import { AuthProvider } from "@/hooks/use-auth";
import { CatalogScopeProvider } from "@/hooks/use-catalog-scope";
import { I18nProvider } from "@/i18n";
import BillingGroupsPage from "@/pages/billing-groups";
import type { AdminBillingGroup } from "@/resources/billing-groups";
import { gatewayUrl, server } from "@/test/msw";
import { TEST_GATEWAY_API_KEY, createTestQueryClient, seedSession } from "@/test/test-utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";

const OPERATOR_KEY = "fg-platform-operator-key";

/** A superadmin session whose flip-to-platform sends the operator credential. */
function seedSuperadmin(): void {
  seedSession({
    user: { id: "user-1", email: "root@example.com", display_name: "Root", superadmin: true },
    platformOperatorApiKey: OPERATOR_KEY,
  });
}

function group(overrides: Partial<AdminBillingGroup> = {}): AdminBillingGroup {
  return {
    id: "bg-1",
    scope: "platform",
    name: "Enterprise",
    multiplier: 1.5,
    description: "Marked-up tier",
    enabled: true,
    provider_ids: [],
    ...overrides,
  };
}

interface CapturedWrite {
  method: string;
  url: string;
  authorization: string | null;
  body: Record<string, unknown> | null;
}

/**
 * A mutable in-memory billing-group store wired to the seven endpoints, so the
 * page's create/patch/delete/bind/unbind flows drive real refetches like the
 * live surface. Returns the store plus a captured-writes log the tests assert on.
 */
function stubBillingGroups(initial: AdminBillingGroup[]): {
  writes: CapturedWrite[];
  groups: AdminBillingGroup[];
} {
  const groups = [...initial];
  const writes: CapturedWrite[] = [];

  async function capture(request: Request): Promise<Record<string, unknown> | null> {
    const text = await request.text();
    const body = text === "" ? null : (JSON.parse(text) as Record<string, unknown>);
    writes.push({
      method: request.method,
      url: request.url,
      authorization: request.headers.get("authorization"),
      body,
    });
    return body;
  }

  server.use(
    http.get(gatewayUrl("/admin/v1/billing-groups"), () =>
      HttpResponse.json({ object: "list", data: groups }),
    ),
    http.get(gatewayUrl("/admin/v1/providers"), () =>
      HttpResponse.json({
        object: "list",
        data: [
          {
            id: "prov-openai",
            name: "OpenAI",
            kind: "openai",
            compatibility: "openai",
            base_url: "https://api.openai.com/v1",
            has_api_key: true,
            enabled: true,
          },
          {
            id: "prov-anthropic",
            name: "Anthropic",
            kind: "anthropic",
            compatibility: "anthropic",
            base_url: "https://api.anthropic.com",
            has_api_key: true,
            enabled: true,
          },
        ],
      }),
    ),
    http.post(gatewayUrl("/admin/v1/billing-groups"), async ({ request }) => {
      const body = await capture(request);
      const created = group({
        id: "bg-new",
        provider_ids: [],
        ...(body as Partial<AdminBillingGroup>),
      });
      groups.push(created);
      return HttpResponse.json({ object: "billing_group", billing_group: created }, { status: 201 });
    }),
    http.patch(gatewayUrl("/admin/v1/billing-groups/:id"), async ({ request, params }) => {
      const body = await capture(request);
      const found = groups.find((g) => g.id === params.id);
      if (!found) return HttpResponse.json({ error: { code: "not_found" } }, { status: 404 });
      Object.assign(found, body);
      return HttpResponse.json({ object: "billing_group", billing_group: found });
    }),
    http.delete(gatewayUrl("/admin/v1/billing-groups/:id"), async ({ request, params }) => {
      await capture(request);
      const index = groups.findIndex((g) => g.id === params.id);
      if (index >= 0) groups.splice(index, 1);
      return HttpResponse.json({ object: "billing_group", id: params.id, deleted: true });
    }),
    http.put(
      gatewayUrl("/admin/v1/billing-groups/:id/providers/:providerId"),
      async ({ request, params }) => {
        await capture(request);
        const found = groups.find((g) => g.id === params.id);
        if (!found) return HttpResponse.json({ error: { code: "not_found" } }, { status: 404 });
        if (!found.provider_ids.includes(String(params.providerId))) {
          found.provider_ids = [...found.provider_ids, String(params.providerId)];
        }
        return HttpResponse.json({ object: "billing_group", billing_group: found });
      },
    ),
    http.delete(
      gatewayUrl("/admin/v1/billing-groups/:id/providers/:providerId"),
      async ({ request, params }) => {
        await capture(request);
        const found = groups.find((g) => g.id === params.id);
        if (!found) return HttpResponse.json({ error: { code: "not_found" } }, { status: 404 });
        found.provider_ids = found.provider_ids.filter((p) => p !== String(params.providerId));
        return HttpResponse.json({ object: "billing_group", billing_group: found });
      },
    ),
  );

  return { writes, groups };
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/app/billing-groups"]}>
      <I18nProvider initialLocale="en">
        <AuthProvider>
          <CatalogScopeProvider>
            <QueryClientProvider client={createTestQueryClient()}>
              <BillingGroupsPage />
            </QueryClientProvider>
          </CatalogScopeProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

/** Flip the page-level catalog-scope toggle to platform (the only switch while
 *  no sheet is open), so writes carry the operator key. */
async function flipToPlatform(): Promise<void> {
  await userEvent.click(screen.getByRole("switch"));
}

describe("billing-groups CRUD", () => {
  beforeEach(() => {
    seedSuperadmin();
  });

  it("creates a group with the operator key and no tenant_id under platform scope", async () => {
    const { writes } = stubBillingGroups([]);
    renderPage();
    await screen.findByText("No billing groups yet.");

    await flipToPlatform();
    await userEvent.click(screen.getByRole("button", { name: "New" }));
    await userEvent.type(await screen.findByLabelText("Name *"), "Startup");
    const multiplier = screen.getByLabelText("Multiplier *");
    await userEvent.clear(multiplier);
    await userEvent.type(multiplier, "2.5");
    await userEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(writes).toHaveLength(1));
    const post = writes[0];
    expect(post.method).toBe("POST");
    expect(post.authorization).toBe(`Bearer ${OPERATOR_KEY}`);
    expect(post.body).toMatchObject({
      name: "Startup",
      multiplier: 2.5,
      description: null,
      enabled: true,
    });
    expect(post.body).not.toHaveProperty("tenant_id");
    expect(new URL(post.url).searchParams.has("tenant_id")).toBe(false);
  });

  it("edits the multiplier through a PATCH", async () => {
    const { writes } = stubBillingGroups([group({ id: "bg-1", multiplier: 1 })]);
    renderPage();
    await screen.findByText("Enterprise");

    await userEvent.click(screen.getByRole("button", { name: "Edit" }));
    const multiplier = await screen.findByLabelText("Multiplier *");
    await userEvent.clear(multiplier);
    await userEvent.type(multiplier, "3");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(writes.some((w) => w.method === "PATCH")).toBe(true));
    const patch = writes.find((w) => w.method === "PATCH");
    expect(patch?.url).toContain("/admin/v1/billing-groups/bg-1");
    expect(patch?.body).toMatchObject({ name: "Enterprise", multiplier: 3 });
  });

  it("rejects a negative multiplier before any request", async () => {
    const { writes } = stubBillingGroups([group({ id: "bg-1" })]);
    renderPage();
    await screen.findByText("Enterprise");

    await userEvent.click(screen.getByRole("button", { name: "Edit" }));
    const multiplier = await screen.findByLabelText("Multiplier *");
    await userEvent.clear(multiplier);
    await userEvent.type(multiplier, "-1");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Multiplier must be a number 0 or greater.",
    );
    expect(writes.some((w) => w.method === "PATCH")).toBe(false);
  });

  it("deletes a group through the confirm dialog", async () => {
    const { writes } = stubBillingGroups([group({ id: "bg-1" })]);
    renderPage();
    await screen.findByText("Enterprise");

    await userEvent.click(screen.getByRole("button", { name: "Delete" }));
    const dialog = await screen.findByRole("alertdialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(writes.some((w) => w.method === "DELETE")).toBe(true));
    expect(writes.find((w) => w.method === "DELETE")?.url).toContain(
      "/admin/v1/billing-groups/bg-1",
    );
  });

  it("binds then unbinds a provider through the dedicated endpoints", async () => {
    const { writes } = stubBillingGroups([group({ id: "bg-1", provider_ids: [] })]);
    renderPage();
    await screen.findByText("Enterprise");

    await userEvent.click(screen.getByRole("button", { name: "Edit" }));
    const bindOpenAi = await screen.findByRole("switch", { name: "Bind provider OpenAI" });
    expect(bindOpenAi).not.toBeChecked();

    // Bind → PUT to the provider sub-resource; the refetch ticks the toggle on.
    await userEvent.click(bindOpenAi);
    await waitFor(() =>
      expect(
        writes.some(
          (w) => w.method === "PUT" && w.url.includes("/billing-groups/bg-1/providers/prov-openai"),
        ),
      ).toBe(true),
    );
    await waitFor(() =>
      expect(screen.getByRole("switch", { name: "Bind provider OpenAI" })).toBeChecked(),
    );

    // Unbind → DELETE to the same sub-resource.
    await userEvent.click(screen.getByRole("switch", { name: "Bind provider OpenAI" }));
    await waitFor(() =>
      expect(
        writes.some(
          (w) =>
            w.method === "DELETE" &&
            w.url.includes("/billing-groups/bg-1/providers/prov-openai"),
        ),
      ).toBe(true),
    );
    // The unrelated provider was never touched.
    expect(writes.some((w) => w.url.includes("/providers/prov-anthropic"))).toBe(false);
    // Every write carried the operator key path's default tenant key here (scope
    // not flipped), proving the binding calls ride the same scoped credential.
    expect(writes.every((w) => w.authorization === `Bearer ${TEST_GATEWAY_API_KEY}`)).toBe(true);
  });
});
