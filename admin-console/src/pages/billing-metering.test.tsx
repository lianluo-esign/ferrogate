// Component tests for the metering & usage read-only views (#319): metering
// events (paginated), export status, and usage aggregates each render from the
// typed client.
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, expect, it } from "vitest";
import BillingMeteringPage from "@/pages/billing-metering";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

function meteringEvent() {
  return {
    request_id: "req-me-1",
    trace_id: null,
    agent_run_id: null,
    cluster_id: null,
    node_id: null,
    tenant: { organization_id: "org-acme" },
    logical_model: "gpt-4o",
    provider: "openai",
    provider_model: "gpt-4o-2024",
    usage: { prompt_tokens: 100, completion_tokens: 50, total_tokens: 150 },
    usage_source: "provider_usage",
    status_code: 200,
    occurred_at_unix: 1_700_000_000,
  };
}

beforeEach(() => {
  seedSession();
});

it("renders paginated metering events", async () => {
  server.use(
    http.get(gatewayUrl("/admin/v1/metering-events"), () =>
      HttpResponse.json({
        object: "list",
        data: [meteringEvent()],
        total: 1,
        offset: 0,
        limit: 50,
      }),
    ),
  );

  renderWithProviders(<BillingMeteringPage />);

  expect(await screen.findByText("gpt-4o")).toBeInTheDocument();
  expect(screen.getByText("provider_usage")).toBeInTheDocument();
  expect(screen.getByText("150")).toBeInTheDocument();
  expect(screen.getByText("Showing 1–1 of 1")).toBeInTheDocument();
  // Only one page -> both pager buttons disabled.
  expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
});

it("renders the export status tab", async () => {
  const user = userEvent.setup();
  server.use(
    http.get(gatewayUrl("/admin/v1/metering-events"), () =>
      HttpResponse.json({ object: "list", data: [], total: 0, offset: 0, limit: 50 }),
    ),
    http.get(gatewayUrl("/admin/v1/metering-export-status"), () =>
      HttpResponse.json({
        object: "list",
        data: [
          {
            request_id: "req-ex-1",
            trace_id: null,
            provider: "openmeter",
            endpoint: "/ingest",
            success: false,
            status: "failed",
            error: "429 rate limited",
            occurred_at_unix: 1_700_000_000,
          },
        ],
      }),
    ),
  );

  renderWithProviders(<BillingMeteringPage />);
  await user.click(screen.getByRole("tab", { name: "Export status" }));

  expect(await screen.findByText("req-ex-1")).toBeInTheDocument();
  expect(screen.getByText("/ingest")).toBeInTheDocument();
  expect(screen.getByText("failed")).toBeInTheDocument();
  expect(screen.getByText("429 rate limited")).toBeInTheDocument();
});

it("renders the usage aggregates tab", async () => {
  const user = userEvent.setup();
  server.use(
    http.get(gatewayUrl("/admin/v1/metering-events"), () =>
      HttpResponse.json({ object: "list", data: [], total: 0, offset: 0, limit: 50 }),
    ),
    http.get(gatewayUrl("/admin/v1/usage-aggregates"), () =>
      HttpResponse.json({
        object: "list",
        data: [
          {
            id: "agg-1",
            organization_id: "org-acme",
            project_id: "proj-1",
            api_key_id: null,
            logical_model: "claude-3",
            provider: "anthropic",
            usage: { prompt_tokens: 1000, completion_tokens: 500, total_tokens: 1500 },
          },
        ],
      }),
    ),
  );

  renderWithProviders(<BillingMeteringPage />);
  await user.click(screen.getByRole("tab", { name: "Usage aggregates" }));

  expect(await screen.findByText("claude-3")).toBeInTheDocument();
  expect(screen.getByText("anthropic")).toBeInTheDocument();
  expect(screen.getByText("1,500")).toBeInTheDocument();
});

it("surfaces a metering events load failure", async () => {
  server.use(
    http.get(gatewayUrl("/admin/v1/metering-events"), () =>
      HttpResponse.json(
        { error: { code: "forbidden", message: "missing admin scope" } },
        { status: 403 },
      ),
    ),
  );

  renderWithProviders(<BillingMeteringPage />);

  expect(
    await screen.findByText(/Failed to load metering events: missing admin scope/),
  ).toBeInTheDocument();
});
