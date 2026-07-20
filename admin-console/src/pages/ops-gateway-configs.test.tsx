import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import OpsGatewayConfigsPage from "@/pages/ops-gateway-configs";
import { gatewayConfigProfile } from "@/test/fixtures/ops";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

beforeEach(() => {
  seedSession();
});

function mockList(profiles = [gatewayConfigProfile()]) {
  server.use(
    http.get(gatewayUrl("/admin/v1/gateway-configs"), () =>
      HttpResponse.json({ object: "list", data: profiles }),
    ),
  );
}

describe("OpsGatewayConfigsPage", () => {
  it("lists stored config profiles", async () => {
    mockList([
      gatewayConfigProfile(),
      gatewayConfigProfile({
        id: "profile-2",
        name: "Prod overlay",
        enabled: false,
        cache_enabled: null,
      }),
    ]);

    renderWithProviders(<OpsGatewayConfigsPage />);

    expect(await screen.findByText("No-cache agent")).toBeInTheDocument();
    expect(screen.getByText("Prod overlay")).toBeInTheDocument();
    expect(screen.getByText("inherit")).toBeInTheDocument();
  });

  it("creates a profile posting the contract mutation body", async () => {
    const user = userEvent.setup();
    mockList([]);
    let createdBody: unknown = null;
    server.use(
      http.post(gatewayUrl("/admin/v1/gateway-configs"), async ({ request }) => {
        createdBody = await request.json();
        return HttpResponse.json({
          object: "gateway_config",
          gateway_config: gatewayConfigProfile(),
        });
      }),
    );

    renderWithProviders(<OpsGatewayConfigsPage />);
    await screen.findByText("No config profiles.");

    await user.click(screen.getByRole("button", { name: "New profile" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Id"), "no-cache");
    await user.type(within(dialog).getByLabelText("Name"), "No cache");
    await user.type(
      within(dialog).getByLabelText("API key ids (comma-separated)"),
      "key_dev, key_prod",
    );
    await user.click(within(dialog).getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(createdBody).toEqual({
        id: "no-cache",
        name: "No cache",
        revision: 1,
        enabled: true,
        api_key_ids: ["key_dev", "key_prod"],
        cache_enabled: undefined,
      }),
    );
  });

  it("deletes a profile after confirmation", async () => {
    const user = userEvent.setup();
    mockList([gatewayConfigProfile({ id: "profile-1", name: "No-cache agent" })]);
    let deleted = false;
    server.use(
      http.delete(gatewayUrl("/admin/v1/gateway-configs/profile-1"), () => {
        deleted = true;
        return HttpResponse.json({ object: "gateway_config.deleted", id: "profile-1" });
      }),
    );

    renderWithProviders(<OpsGatewayConfigsPage />);
    await screen.findByText("No-cache agent");

    await user.click(screen.getByRole("button", { name: "Delete" }));
    expect(
      await screen.findByText("Delete config profile?"),
    ).toBeInTheDocument();
    expect(deleted).toBe(false);

    const alert = await screen.findByRole("alertdialog");
    await user.click(within(alert).getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(deleted).toBe(true));
  });
});
