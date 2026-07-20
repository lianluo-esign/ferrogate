// Component tests for the billing dead-letters browser (#319).
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, expect, it } from "vitest";
import BillingDeadLettersPage from "@/pages/billing-dead-letters";
import { gatewayUrl, mockAdminError, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

const PATH = "/admin/v1/billing-outbox-dead-letters";

function entry(overrides: Record<string, unknown> = {}) {
  return {
    id: "led-dead-1",
    event: {
      request_id: "req-dead-1",
      trace_id: "trace-dead-1",
      tenant: { organization_id: "org-acme" },
      logical_model: "gpt-4o",
      provider: "openai",
      provider_model: "gpt-4o-2024",
      status_code: 200,
      cost_usd: 0.42,
      occurred_at_unix: 1_700_000_000,
    },
    attempts: 7,
    next_attempt_unix: 1_700_000_100,
    dead_lettered_at_unix: 1_700_000_500,
    ...overrides,
  };
}

function mockDeadLetters(rows: unknown[]): void {
  server.use(
    http.get(gatewayUrl(PATH), () =>
      HttpResponse.json({ object: "list", data: rows }),
    ),
  );
}

beforeEach(() => {
  seedSession();
});

it("renders dead-lettered reports with attempts and tenant", async () => {
  mockDeadLetters([entry()]);

  renderWithProviders(<BillingDeadLettersPage />);

  expect(await screen.findByText("led-dead-1")).toBeInTheDocument();
  expect(screen.getByText("org-acme")).toBeInTheDocument();
  expect(screen.getByText("7")).toBeInTheDocument();
});

it("shows the delivery/error context in the detail dialog", async () => {
  const user = userEvent.setup();
  mockDeadLetters([entry()]);

  renderWithProviders(<BillingDeadLettersPage />);
  await screen.findByText("led-dead-1");

  await user.click(screen.getByRole("button", { name: "Details" }));

  const dialog = await screen.findByRole("dialog");
  expect(within(dialog).getByText("req-dead-1")).toBeInTheDocument();
  expect(within(dialog).getByText("trace-dead-1")).toBeInTheDocument();
  expect(within(dialog).getByText("gpt-4o (openai/gpt-4o-2024)")).toBeInTheDocument();
  expect(within(dialog).getByText("$0.42")).toBeInTheDocument();
});

it("filters rows by request id", async () => {
  const user = userEvent.setup();
  mockDeadLetters([
    entry(),
    entry({ id: "led-dead-2", event: { ...entry().event, request_id: "req-other" } }),
  ]);

  renderWithProviders(<BillingDeadLettersPage />);
  await screen.findByText("led-dead-1");

  await user.type(
    screen.getByPlaceholderText("Filter by id, request id, or tenant"),
    "led-dead-2",
  );

  expect(screen.getByText("led-dead-2")).toBeInTheDocument();
  expect(screen.queryByText("led-dead-1")).not.toBeInTheDocument();
});

it("surfaces a load failure", async () => {
  mockAdminError("get", PATH, 403, "forbidden", "missing admin scope");

  renderWithProviders(<BillingDeadLettersPage />);

  expect(
    await screen.findByText(/Failed to load dead-letters: missing admin scope/),
  ).toBeInTheDocument();
});
