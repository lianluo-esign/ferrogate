import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { useSearchParams } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import OpsObservabilityPage from "@/pages/ops-observability";
import { gatewayUrl, mockAdminList, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";
import type { AdminSchema } from "@/lib/gateway-client";

/** Surfaces the live URL query string so URL-state assertions can read it. */
function SearchProbe() {
  const [params] = useSearchParams();
  return <span data-testid="search">{params.toString()}</span>;
}

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

  it("picks the model filter from the catalog (human label) and writes its id to the URL", async () => {
    const user = userEvent.setup();
    mockAdminList("/admin/v1/observability", []);
    mockAdminList("/admin/v1/models", [
      { name: "gpt-4o", provider: "openai", provider_model: "gpt-4o" },
    ]);

    renderWithProviders(
      <>
        <OpsObservabilityPage />
        <SearchProbe />
      </>,
    );
    await screen.findByText("No exporters configured.");

    // The model filter is an entity picker over the known models catalog: pick
    // by human name, and the canonical model name is written to the URL query.
    await user.click(screen.getByRole("combobox", { name: "Model" }));
    await user.click(await screen.findByRole("option", { name: /gpt-4o/ }));

    await waitFor(() =>
      expect(screen.getByTestId("search")).toHaveTextContent("model=gpt-4o"),
    );
    // The picker trigger displays the resolved human label, not a raw id box.
    expect(screen.getByRole("combobox", { name: "Model" })).toHaveTextContent("gpt-4o");
  });
});
