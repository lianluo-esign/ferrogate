import OpsProviderHealthPage from "@/pages/ops-provider-health";
import { providerHealth } from "@/test/fixtures/ops";
import { gatewayUrl, mockAdminList, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";

beforeEach(() => {
  seedSession();
});

describe("OpsProviderHealthPage", () => {
  it("renders the provider health board", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/provider-health"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            providerHealth(),
            providerHealth({
              name: "anthropic",
              status: "error",
              reachable: false,
              circuit_open: true,
              consecutive_failures: 5,
              error: "connect timeout",
            }),
          ],
        }),
      ),
    );

    renderWithProviders(<OpsProviderHealthPage />);

    expect(await screen.findByText("openai")).toBeInTheDocument();
    expect(screen.getByText("anthropic")).toBeInTheDocument();
    expect(screen.getByText("connect timeout")).toBeInTheDocument();
    expect(screen.getByText("open")).toBeInTheDocument();
  });

  it("loads the extensions tab lazily on selection", async () => {
    const user = userEvent.setup();
    server.use(
      http.get(gatewayUrl("/admin/v1/provider-health"), () =>
        HttpResponse.json({ object: "list", data: [providerHealth()] }),
      ),
    );
    mockAdminList("/admin/v1/extensions", [
      {
        id: "ext-audit",
        kind: "event_sink",
        version: "1.0.0",
        manifest: {},
        compatibility: {},
        source: "builtin",
        capabilities: [],
        tools: [],
        enabled: true,
        active: true,
        lifecycle: "enabled",
        health: "ok",
        order: 0,
        last_error: null,
      },
    ]);

    renderWithProviders(<OpsProviderHealthPage />);
    await screen.findByText("openai");

    await user.click(screen.getByRole("tab", { name: "Extensions" }));

    expect(await screen.findByText("ext-audit")).toBeInTheDocument();
    const table = screen.getByText("ext-audit").closest("table");
    expect(within(table as HTMLElement).getByText("event_sink")).toBeInTheDocument();
  });
});
