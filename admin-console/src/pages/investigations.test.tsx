import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import InvestigationsPage from "@/pages/investigations";
import {
  correlation,
  FP_ACTION,
  FP_PARENT,
  investigation,
} from "@/test/fixtures/guardrails";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

function mockInvestigation(
  body: ReturnType<typeof investigation>,
  onRequest?: (url: URL) => void,
) {
  server.use(
    http.get(gatewayUrl("/admin/v1/investigations"), ({ request }) => {
      onRequest?.(new URL(request.url));
      return HttpResponse.json(body);
    }),
  );
}

async function submitLookup(value: string) {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Request ID"), value);
  await user.click(screen.getByRole("button", { name: "Investigate" }));
  return user;
}

beforeEach(() => {
  seedSession();
});

describe("InvestigationsPage", () => {
  it("queries by request_id and renders the joined evidence sections", async () => {
    const seenUrls: URL[] = [];
    mockInvestigation(investigation(), (url) => seenUrls.push(url));

    renderWithProviders(<InvestigationsPage />);
    await submitLookup("req-1");

    // Outcome summary ("blocked" also appears as the audit-event outcome).
    expect((await screen.findAllByText("blocked")).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("request_id=req-1")).toBeInTheDocument();
    expect(screen.getAllByText("$0.0123").length).toBeGreaterThanOrEqual(2);
    // Query param round-trip.
    expect(seenUrls[0].searchParams.get("request_id")).toBe("req-1");

    // Request evidence includes the #307 parent action fingerprint.
    expect(screen.getByText("/v1/chat/completions")).toBeInTheDocument();
    expect(screen.getByText(`${FP_PARENT.slice(0, 20)}…`)).toBeInTheDocument();
    // Guardrail evaluation, approval, timeline and billing evidence rows (the
    // ids also appear inside the correlation group, hence getAllByText).
    expect(screen.getAllByText("eval-1").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("guardrail:fail:block:enforced")).toBeInTheDocument();
    expect(screen.getAllByText("appr-1").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("files/write")).toBeInTheDocument();
    expect(screen.getByText("mcp:files/write")).toBeInTheDocument();
    expect(screen.getByText("120")).toBeInTheDocument();
    expect(screen.getByText("guardrail.enforce")).toBeInTheDocument();
  });

  it("renders action correlation groups with grouped ids and the parent->child tree", async () => {
    mockInvestigation(
      investigation({
        action_correlations: [
          correlation({
            guardrail_evaluation_ids: ["eval-1", "eval-2"],
            child_request_ids: ["req-child-1", "req-child-2"],
            child_dispatch_ids: ["disp-child-1"],
          }),
        ],
      }),
    );

    renderWithProviders(<InvestigationsPage />);
    await submitLookup("req-1");

    const group = await screen.findByTestId("correlation-group");
    expect(within(group).getByText(FP_ACTION)).toBeInTheDocument();
    expect(within(group).getByText("eval-1, eval-2")).toBeInTheDocument();
    expect(within(group).getByText("appr-1")).toBeInTheDocument();
    expect(within(group).getByText("evt-1")).toBeInTheDocument();
    expect(within(group).getByText("aud-1")).toBeInTheDocument();
    // #307 parent -> child traversal rendered as a nested tree.
    expect(within(group).getByText("child request req-child-1")).toBeInTheDocument();
    expect(within(group).getByText("child request req-child-2")).toBeInTheDocument();
    expect(within(group).getByText("child dispatch disp-child-1")).toBeInTheDocument();
  });

  it("notes when no evidence row carries an action fingerprint", async () => {
    mockInvestigation(investigation({ action_correlations: [] }));

    renderWithProviders(<InvestigationsPage />);
    await submitLookup("req-1");

    expect(
      await screen.findByText(
        "No evidence row in this investigation carries an action fingerprint.",
      ),
    ).toBeInTheDocument();
  });

  it("switches the selector kind and sends agent_run_id instead of request_id", async () => {
    const seenUrls: URL[] = [];
    mockInvestigation(investigation({ selector: "agent_run_id=run-1" }), (url) =>
      seenUrls.push(url),
    );

    renderWithProviders(<InvestigationsPage />);
    const user = userEvent.setup();
    await user.click(screen.getByRole("combobox"));
    await user.click(await screen.findByRole("option", { name: "Agent run ID" }));
    await user.type(screen.getByLabelText("Agent run ID"), "run-1");
    await user.click(screen.getByRole("button", { name: "Investigate" }));

    await waitFor(() => expect(seenUrls.length).toBeGreaterThan(0));
    expect(seenUrls[0].searchParams.get("agent_run_id")).toBe("run-1");
    expect(seenUrls[0].searchParams.has("request_id")).toBe(false);
    expect(await screen.findByText("agent_run_id=run-1")).toBeInTheDocument();
  });
});
