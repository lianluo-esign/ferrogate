import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import OpsDrainPage from "@/pages/ops-drain";
import { drainStatus } from "@/test/fixtures/ops";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

beforeEach(() => {
  seedSession();
});

describe("OpsDrainPage", () => {
  it("confirms before draining and POSTs drain=true", async () => {
    const user = userEvent.setup();
    let drainBody: unknown = null;
    let current = drainStatus();
    server.use(
      http.get(gatewayUrl("/admin/v1/drain"), () => HttpResponse.json(current)),
      http.post(gatewayUrl("/admin/v1/drain"), async ({ request }) => {
        drainBody = await request.json();
        current = drainStatus({
          draining: true,
          accepting_new_requests: false,
          drain_reason: "operator_drain",
        });
        return HttpResponse.json(current);
      }),
    );

    renderWithProviders(<OpsDrainPage />);

    // Serving initially (status badge + draining row both read "serving").
    expect((await screen.findAllByText("serving")).length).toBeGreaterThan(0);

    // Start drain opens a confirmation; nothing POSTed yet.
    await user.click(screen.getByRole("button", { name: "Start drain" }));
    expect(
      await screen.findByText("Start draining this node?"),
    ).toBeInTheDocument();
    expect(drainBody).toBeNull();

    // Confirm inside the dialog.
    const confirm = await screen.findByRole("button", { name: "Confirm drain" });
    await user.click(confirm);

    await waitFor(() => expect(drainBody).toEqual({ drain: true }));
    expect(await screen.findByText("operator_drain")).toBeInTheDocument();
  });
});
