import { AuthProvider } from "@/hooks/use-auth";
import { CatalogScopeProvider } from "@/hooks/use-catalog-scope";
import { I18nProvider } from "@/i18n";
import AnnouncementsPage from "@/pages/announcements";
import type { AdminAnnouncement } from "@/resources/announcements";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";
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

function announcement(overrides: Partial<AdminAnnouncement> = {}): AdminAnnouncement {
  return {
    id: "an-1",
    scope: "platform",
    title: "Scheduled maintenance",
    body: "The gateway will be briefly unavailable.",
    level: "warning",
    enabled: true,
    starts_at_unix: null,
    ends_at_unix: null,
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
 * A mutable in-memory announcement store wired to the five endpoints so the
 * page's create/patch/delete flows drive real refetches like the live surface.
 */
function stubAnnouncements(initial: AdminAnnouncement[]): {
  writes: CapturedWrite[];
  announcements: AdminAnnouncement[];
} {
  const announcements = [...initial];
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
    http.get(gatewayUrl("/admin/v1/announcements"), () =>
      HttpResponse.json({ object: "list", data: announcements }),
    ),
    http.post(gatewayUrl("/admin/v1/announcements"), async ({ request }) => {
      const body = await capture(request);
      const created = announcement({
        id: "an-new",
        ...(body as Partial<AdminAnnouncement>),
      });
      announcements.push(created);
      return HttpResponse.json({ object: "announcement", announcement: created }, { status: 201 });
    }),
    http.patch(gatewayUrl("/admin/v1/announcements/:id"), async ({ request, params }) => {
      const body = await capture(request);
      const found = announcements.find((item) => item.id === params.id);
      if (!found) return HttpResponse.json({ error: { code: "not_found" } }, { status: 404 });
      Object.assign(found, body);
      return HttpResponse.json({ object: "announcement", announcement: found });
    }),
    http.delete(gatewayUrl("/admin/v1/announcements/:id"), async ({ request, params }) => {
      await capture(request);
      const index = announcements.findIndex((item) => item.id === params.id);
      if (index >= 0) announcements.splice(index, 1);
      return HttpResponse.json({ object: "announcement", id: params.id, deleted: true });
    }),
  );

  return { writes, announcements };
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/app/announcements"]}>
      <I18nProvider initialLocale="en">
        <AuthProvider>
          <CatalogScopeProvider>
            <QueryClientProvider client={createTestQueryClient()}>
              <AnnouncementsPage />
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

describe("announcements CRUD", () => {
  beforeEach(() => {
    seedSuperadmin();
  });

  it("creates a notice with the operator key and no tenant_id under platform scope", async () => {
    const { writes } = stubAnnouncements([]);
    renderPage();
    await screen.findByText("No announcements yet.");

    await flipToPlatform();
    await userEvent.click(screen.getByRole("button", { name: "New" }));
    await userEvent.type(await screen.findByLabelText("Title *"), "Heads up");
    await userEvent.type(screen.getByLabelText("Body *"), "Rolling restart tonight.");
    await userEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(writes).toHaveLength(1));
    const post = writes[0];
    expect(post.method).toBe("POST");
    expect(post.authorization).toBe(`Bearer ${OPERATOR_KEY}`);
    expect(post.body).toMatchObject({
      title: "Heads up",
      body: "Rolling restart tonight.",
      level: "info",
      enabled: true,
      starts_at_unix: null,
      ends_at_unix: null,
    });
    expect(post.body).not.toHaveProperty("tenant_id");
    expect(new URL(post.url).searchParams.has("tenant_id")).toBe(false);
  });

  it("edits the title and level through a PATCH", async () => {
    const { writes } = stubAnnouncements([
      announcement({ id: "an-1", title: "Old", level: "info" }),
    ]);
    renderPage();
    await screen.findByText("Old");

    await userEvent.click(screen.getByRole("button", { name: "Edit" }));
    const title = await screen.findByLabelText("Title *");
    await userEvent.clear(title);
    await userEvent.type(title, "New title");
    const level = screen.getByLabelText("Level");
    await userEvent.clear(level);
    await userEvent.type(level, "critical");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(writes.some((w) => w.method === "PATCH")).toBe(true));
    const patch = writes.find((w) => w.method === "PATCH");
    expect(patch?.url).toContain("/admin/v1/announcements/an-1");
    expect(patch?.body).toMatchObject({ title: "New title", level: "critical" });
  });

  it("requires a title before any request", async () => {
    const { writes } = stubAnnouncements([]);
    renderPage();
    await screen.findByText("No announcements yet.");

    await userEvent.click(screen.getByRole("button", { name: "New" }));
    // Body only, no title.
    await userEvent.type(await screen.findByLabelText("Body *"), "Body without a title.");
    await userEvent.click(screen.getByRole("button", { name: "Create" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Title is required.");
    expect(writes.some((w) => w.method === "POST")).toBe(false);
  });

  it("rejects a window whose start is after its end", async () => {
    const { writes } = stubAnnouncements([announcement({ id: "an-1" })]);
    renderPage();
    await screen.findByText("Scheduled maintenance");

    await userEvent.click(screen.getByRole("button", { name: "Edit" }));
    await userEvent.type(await screen.findByLabelText("Starts"), "2026-06-01T10:00");
    await userEvent.type(screen.getByLabelText("Ends"), "2026-05-01T10:00");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The start must be on or before the end.",
    );
    expect(writes.some((w) => w.method === "PATCH")).toBe(false);
  });

  it("deletes a notice through the confirm dialog", async () => {
    const { writes } = stubAnnouncements([announcement({ id: "an-1" })]);
    renderPage();
    await screen.findByText("Scheduled maintenance");

    await userEvent.click(screen.getByRole("button", { name: "Delete" }));
    const dialog = await screen.findByRole("alertdialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(writes.some((w) => w.method === "DELETE")).toBe(true));
    expect(writes.find((w) => w.method === "DELETE")?.url).toContain(
      "/admin/v1/announcements/an-1",
    );
  });
});
