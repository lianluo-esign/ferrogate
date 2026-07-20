import { screen } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import OpsStatusPage from "@/pages/ops-status";
import { adminStatus } from "@/test/fixtures/ops";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

beforeEach(() => {
  seedSession();
});

describe("OpsStatusPage", () => {
  it("renders health counters, ACME posture and cluster readiness", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/status"), () =>
        HttpResponse.json(adminStatus()),
      ),
    );

    renderWithProviders(<OpsStatusPage />);

    // counters (enabled / total)
    expect(await screen.findByText("3 / 4")).toBeInTheDocument(); // providers
    expect(screen.getByText("10 / 12")).toBeInTheDocument(); // models
    expect(screen.getByText("v1.2.3")).toBeInTheDocument();
    expect(screen.getByText("snapshot snap-abc")).toBeInTheDocument();

    // ACME + cluster sections present
    expect(screen.getByText("TLS / ACME")).toBeInTheDocument();
    expect(screen.getByText("gateway.example.com")).toBeInTheDocument();
    expect(screen.getByText("Cluster")).toBeInTheDocument();
    expect(screen.getByText("state_loaded")).toBeInTheDocument();
  });

  it("flags reload_required when ACME needs a listener reload (#265)", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/status"), () =>
        HttpResponse.json(
          adminStatus({
            acme: {
              ...adminStatus().acme!,
              reload_required: true,
              reload_mode: "listener",
            },
          }),
        ),
      ),
    );

    renderWithProviders(<OpsStatusPage />);

    expect(await screen.findByText("reload required")).toBeInTheDocument();
  });

  it("surfaces a load error", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/status"), () =>
        HttpResponse.json(
          { error: { code: "boom", message: "status exploded" } },
          { status: 500 },
        ),
      ),
    );

    renderWithProviders(<OpsStatusPage />);

    expect(await screen.findByText(/status exploded/)).toBeInTheDocument();
  });
});
