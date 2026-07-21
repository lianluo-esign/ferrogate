// Virtual-key lifecycle page (#321): list + create + enable/disable/rotate/revoke
// action endpoints, each behind a confirmation; rotate + create reveal the secret
// once.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import VirtualKeysPage from "@/pages/virtual-keys";
import type { AdminVirtualApiKey } from "@/resources/virtual-keys";
import { gatewayUrl, mockAdminError, mockAdminList, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

function vkey(overrides: Partial<AdminVirtualApiKey> = {}): AdminVirtualApiKey {
  return {
    id: "vk-1",
    workspace_id: "ws-1",
    tenant_id: "tenant-1",
    project_id: "proj-1",
    name: "primary",
    key_prefix: "fg-live",
    last4: "abcd",
    enabled: true,
    scopes: ["admin.read"],
    allowed_models: [],
    allowed_providers: [],
    monthly_token_budget: null,
    request_limit_per_minute: null,
    created_at_unix: 1,
    updated_at_unix: 1,
    rotated_at_unix: null,
    expires_at_unix: null,
    revoked_at_unix: null,
    ...overrides,
  } as AdminVirtualApiKey;
}

beforeEach(() => {
  seedSession();
});

describe("VirtualKeysPage", () => {
  it("lists virtual keys", async () => {
    mockAdminList("/admin/v1/virtual-keys", [vkey()]);
    renderWithProviders(<VirtualKeysPage />);

    expect(await screen.findByText("primary")).toBeInTheDocument();
    expect(screen.getByText("fg-live...abcd")).toBeInTheDocument();
  });

  it("disables an enabled key after confirmation", async () => {
    const user = userEvent.setup();
    let posted = false;
    mockAdminList("/admin/v1/virtual-keys", [vkey({ enabled: true })]);
    server.use(
      http.post(gatewayUrl("/admin/v1/virtual-keys/vk-1/disable"), () => {
        posted = true;
        return HttpResponse.json({ object: "virtual_api_key" });
      }),
    );

    renderWithProviders(<VirtualKeysPage />);
    await screen.findByText("primary");

    await user.click(screen.getByRole("button", { name: "Actions for primary" }));
    await user.click(await screen.findByRole("menuitem", { name: "Disable" }));
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: "Disable",
      }),
    );

    await waitFor(() => expect(posted).toBe(true));
  });

  it("enables a disabled key after confirmation", async () => {
    const user = userEvent.setup();
    let posted = false;
    mockAdminList("/admin/v1/virtual-keys", [vkey({ enabled: false })]);
    server.use(
      http.post(gatewayUrl("/admin/v1/virtual-keys/vk-1/enable"), () => {
        posted = true;
        return HttpResponse.json({ object: "virtual_api_key" });
      }),
    );

    renderWithProviders(<VirtualKeysPage />);
    await screen.findByText("primary");

    await user.click(screen.getByRole("button", { name: "Actions for primary" }));
    await user.click(await screen.findByRole("menuitem", { name: "Enable" }));
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: "Enable",
      }),
    );

    await waitFor(() => expect(posted).toBe(true));
  });

  it("rotates a key and reveals the new secret once", async () => {
    const user = userEvent.setup();
    mockAdminList("/admin/v1/virtual-keys", [vkey()]);
    server.use(
      http.post(gatewayUrl("/admin/v1/virtual-keys/vk-1/rotate"), () =>
        HttpResponse.json({ object: "virtual_api_key", secret: "fg-live-rotated-secret" }),
      ),
    );

    renderWithProviders(<VirtualKeysPage />);
    await screen.findByText("primary");

    await user.click(screen.getByRole("button", { name: "Actions for primary" }));
    await user.click(await screen.findByRole("menuitem", { name: "Rotate" }));
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: "Rotate",
      }),
    );

    expect(await screen.findByText("Save this secret now")).toBeInTheDocument();
    expect(screen.getByText("fg-live-rotated-secret")).toBeInTheDocument();
  });

  it("creates a key and reveals its secret once", async () => {
    const user = userEvent.setup();
    mockAdminList("/admin/v1/virtual-keys", [vkey()]);
    server.use(
      http.post(gatewayUrl("/admin/v1/virtual-keys"), () =>
        HttpResponse.json(
          { object: "virtual_api_key", key: vkey({ id: "vk-2" }), secret: "fg-live-new-secret" },
          { status: 201 },
        ),
      ),
    );

    renderWithProviders(<VirtualKeysPage />);
    await screen.findByText("primary");

    await user.click(screen.getByRole("button", { name: "New" }));
    await user.type(await screen.findByLabelText("Name *"), "second");
    await user.type(screen.getByLabelText("Workspace ID *"), "ws-1");
    await user.click(screen.getByRole("button", { name: "Create" }));

    expect(await screen.findByText("Save this secret now")).toBeInTheDocument();
    expect(screen.getByText("fg-live-new-secret")).toBeInTheDocument();
  });

  it("surfaces a 403 from the list", async () => {
    mockAdminError("get", "/admin/v1/virtual-keys", 403, "forbidden", "missing admin.read");
    renderWithProviders(<VirtualKeysPage />);

    expect(
      await screen.findByText(/Failed to load virtual keys: missing admin.read/),
    ).toBeInTheDocument();
  });
});
