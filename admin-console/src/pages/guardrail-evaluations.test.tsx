import GuardrailEvaluationsPage from "@/pages/guardrail-evaluations";
import { FP_ACTION, evaluation, policyRevision } from "@/test/fixtures/guardrails";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
const nn = <T,>(v: T): NonNullable<T> => v as NonNullable<T>;

function mockEvaluations(data: ReturnType<typeof evaluation>[], onRequest?: (url: URL) => void) {
  server.use(
    http.get(gatewayUrl("/admin/v1/guardrail-evaluations"), ({ request }) => {
      onRequest?.(new URL(request.url));
      return HttpResponse.json({
        object: "list",
        data,
        total: data.length,
        offset: 0,
        limit: 100,
      });
    }),
  );
}

beforeEach(() => {
  seedSession();
});

describe("GuardrailEvaluationsPage", () => {
  it("renders evaluations with the stored decision, reason and action fingerprint (#306)", async () => {
    mockEvaluations([evaluation()]);

    renderWithProviders(<GuardrailEvaluationsPage />);

    // Scope to the data row: the filter Selects render hidden native options
    // whose text ("fail", "block", ...) would otherwise collide.
    const row = nn((await screen.findByText("req-1")).closest("tr"));
    expect(within(row).getByText("pol-pii@r3")).toBeInTheDocument();
    // Recorded triple...
    expect(within(row).getByText("fail")).toBeInTheDocument();
    expect(within(row).getByText("block")).toBeInTheDocument();
    expect(within(row).getByText("enforced")).toBeInTheDocument();
    // ...alongside the stored #306 decision columns.
    expect(within(row).getByText("deny")).toBeInTheDocument();
    expect(within(row).getByText("guardrail:fail:block:enforced")).toBeInTheDocument();
    expect(within(row).getByText(`${FP_ACTION.slice(0, 20)}…`)).toBeInTheDocument();
    expect(screen.getByText("1 evaluation matched.")).toBeInTheDocument();
  });

  it("round-trips the filter form into the list query parameters", async () => {
    const user = userEvent.setup();
    const seenUrls: URL[] = [];
    mockEvaluations([evaluation()], (url) => seenUrls.push(url));

    renderWithProviders(<GuardrailEvaluationsPage />);
    await screen.findByText("req-1");
    // The unfiltered initial load sends no filter params.
    expect([...seenUrls[0].searchParams.keys()]).toEqual([]);

    // Only the second page load should be filtered.
    mockEvaluations([evaluation({ id: "eval-2", request_id: "req-2" })], (url) =>
      seenUrls.push(url),
    );
    await user.type(screen.getByLabelText("Request ID"), "req-2");
    await user.type(screen.getByLabelText("Agent run ID"), "run-9");
    await user.click(screen.getByRole("button", { name: "Apply filters" }));

    expect(await screen.findByText("req-2")).toBeInTheDocument();
    const filtered = seenUrls[seenUrls.length - 1];
    expect(filtered.searchParams.get("request_id")).toBe("req-2");
    expect(filtered.searchParams.get("agent_run_id")).toBe("run-9");
    // Untouched filters are omitted rather than sent empty.
    expect(filtered.searchParams.has("trace_id")).toBe(false);
    expect(filtered.searchParams.has("verdict")).toBe(false);
  });

  it("filters by a policy chosen from the reference picker, applying its id to the query", async () => {
    const user = userEvent.setup();
    const seenUrls: URL[] = [];
    mockEvaluations([evaluation()], (url) => seenUrls.push(url));
    // The policy-id filter is now a searchable reference over the real policy
    // catalog rather than a raw-id text box.
    server.use(
      http.get(gatewayUrl("/admin/v1/guardrail-policies"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            policyRevision({ policy_id: "pol-pii", name: "PII guard" }),
            policyRevision({ policy_id: "pol-tox", name: "Toxicity guard", revision: 4 }),
          ],
        }),
      ),
    );

    renderWithProviders(<GuardrailEvaluationsPage />);
    await screen.findByText("req-1");

    // Open the picker and choose a policy by its human name.
    await user.click(screen.getByLabelText("Policy ID"));
    await user.click(await screen.findByRole("option", { name: /PII guard/ }));

    // The picker hydrates the chosen policy to its label, not a raw id.
    expect(screen.getByLabelText("Policy ID")).toHaveTextContent("PII guard");

    mockEvaluations([evaluation()], (url) => seenUrls.push(url));
    await user.click(screen.getByRole("button", { name: "Apply filters" }));

    await waitFor(() => {
      const last = seenUrls[seenUrls.length - 1];
      expect(last.searchParams.get("policy_id")).toBe("pol-pii");
    });
  });

  it("shows an empty state when no evaluations match", async () => {
    mockEvaluations([]);

    renderWithProviders(<GuardrailEvaluationsPage />);

    expect(
      await screen.findByText("No guardrail evaluations match the current filters."),
    ).toBeInTheDocument();
    expect(screen.getByText("0 evaluations matched.")).toBeInTheDocument();
  });
});
