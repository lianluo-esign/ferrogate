import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import OpsObservabilityPage from "@/pages/ops-observability";
import { gatewayUrl, mockAdminList, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";
import type { AdminSchema } from "@/lib/gateway-client";

function exporter(
  overrides: Partial<AdminSchema<"ObservabilityStatus">> = {},
): AdminSchema<"ObservabilityStatus"> {
  return {
    provider: "otlp",
    enabled: true,
    active: true,
    endpoint: "http://collector:4318",
    endpoint_source: "observability",
    protocol: "otlp_http_json",
    signals: ["traces", "metrics"],
    prometheus_metrics_path: "/metrics",
    export_timeout_secs: 5,
    health: "ok",
    last_success_at_unix: 1_752_000_000,
    last_export_error: null,
    queue_backpressure_events: 0,
    dropped_events: 0,
    ...overrides,
  };
}

beforeEach(() => {
  seedSession();
});

describe("OpsObservabilityPage", () => {
  it("renders telemetry exporter status", async () => {
    mockAdminList("/admin/v1/observability", [exporter()]);

    renderWithProviders(<OpsObservabilityPage />);

    expect(await screen.findByText("otlp")).toBeInTheDocument();
    expect(screen.getByText("http://collector:4318")).toBeInTheDocument();
  });

  it("fetches a request-log export and previews the record count", async () => {
    const user = userEvent.setup();
    mockAdminList("/admin/v1/observability", []);
    server.use(
      http.get(gatewayUrl("/admin/v1/request-log-exports"), () =>
        HttpResponse.text(
          '{"object":"request_log_export","request_id":"a"}\n' +
            '{"object":"request_log_export","request_id":"b"}\n',
          { headers: { "Content-Type": "application/x-ndjson" } },
        ),
      ),
    );

    renderWithProviders(<OpsObservabilityPage />);
    await screen.findByText("No exporters configured.");

    await user.click(screen.getByRole("button", { name: "Fetch export" }));

    // 2 NDJSON records → count badge + download enabled.
    expect(await screen.findByText("2")).toBeInTheDocument();
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Download JSONL" }),
      ).toBeEnabled(),
    );
  });
});
