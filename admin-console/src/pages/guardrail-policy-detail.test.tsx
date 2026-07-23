import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider } from "@/i18n";
import GuardrailPolicyDetailPage from "@/pages/guardrail-policy-detail";
import { dryRunResponse, policyRevision } from "@/test/fixtures/guardrails";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";

/** Renders the detail page under its real route so useParams sees policyId. */
function renderDetail(policyId = "pol-pii") {
  return render(
    <MemoryRouter initialEntries={[`/app/guardrail-policies/${policyId}`]}>
      <I18nProvider>
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            <Routes>
              <Route
                path="/app/guardrail-policies/:policyId"
                element={<GuardrailPolicyDetailPage />}
              />
            </Routes>
          </QueryClientProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

function mockHistory(revisions = [
  policyRevision({ revision: 1, status: "archived" }),
  policyRevision({ revision: 2, status: "active", name: "PII guard v2" }),
]) {
  server.use(
    http.get(gatewayUrl("/admin/v1/guardrail-policies/pol-pii/revisions"), () =>
      HttpResponse.json({ object: "list", data: revisions }),
    ),
  );
}

beforeEach(() => {
  seedSession();
});

describe("GuardrailPolicyDetailPage", () => {
  it("shows the active revision and the full revision history", async () => {
    mockHistory();

    renderDetail();

    // Active revision card + history row both show the bound revision.
    expect(await screen.findAllByText("PII guard v2")).toHaveLength(2);
    expect(screen.getAllByText("r2").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText(/block \(pii_detected\)/)).toBeInTheDocument();
    // History lists both revisions with their statuses.
    expect(screen.getByText("r1")).toBeInTheDocument();
    expect(screen.getByText("archived")).toBeInTheDocument();
    expect(screen.getByText("active")).toBeInTheDocument();
  });

  it("activates a revision only after confirmation, POSTing the selected revision", async () => {
    const user = userEvent.setup();
    mockHistory();
    let activateBody: unknown = null;
    server.use(
      http.post(
        gatewayUrl("/admin/v1/guardrail-policies/pol-pii/activate"),
        async ({ request }) => {
          activateBody = await request.json();
          return HttpResponse.json({
            object: "guardrail_policy_binding",
            policy_id: "pol-pii",
            active_revision: 1,
            rollback: false,
            reload: {},
          });
        },
      ),
    );

    renderDetail();

    // Only the non-active revision (r1) offers Activate.
    await user.click(await screen.findByRole("button", { name: "Activate" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText("Activate revision r1?")).toBeInTheDocument();
    // Nothing is POSTed until the confirmation is accepted.
    expect(activateBody).toBeNull();

    await user.click(within(dialog).getByRole("button", { name: "Activate" }));

    await waitFor(() => expect(activateBody).toEqual({ revision: 1 }));
  });

  it("rolls back after confirmation, defaulting to the highest archived revision", async () => {
    const user = userEvent.setup();
    mockHistory();
    let rollbackBody: unknown = null;
    server.use(
      http.post(
        gatewayUrl("/admin/v1/guardrail-policies/pol-pii/rollback"),
        async ({ request }) => {
          rollbackBody = await request.json();
          return HttpResponse.json({
            object: "guardrail_policy_binding",
            policy_id: "pol-pii",
            active_revision: 1,
            rollback: true,
            reload: {},
          });
        },
      ),
    );

    renderDetail();
    await screen.findAllByText("PII guard v2");

    await user.click(screen.getByRole("button", { name: "Rollback..." }));
    const dialog = await screen.findByRole("alertdialog");
    expect(rollbackBody).toBeNull();
    await user.click(within(dialog).getByRole("button", { name: "Roll back" }));

    // Blank target revision -> server picks the highest archived revision.
    await waitFor(() => expect(rollbackBody).toEqual({ revision: null }));
  });

  it("loads an exact revision definition via the revisions/{revision} endpoint", async () => {
    const user = userEvent.setup();
    mockHistory();
    server.use(
      http.get(gatewayUrl("/admin/v1/guardrail-policies/pol-pii/revisions/1"), () =>
        HttpResponse.json({
          object: "guardrail_policy_revision",
          policy: policyRevision({ revision: 1, status: "archived", name: "PII guard v1" }),
        }),
      ),
    );

    renderDetail();
    await screen.findAllByText("PII guard v2");

    // r1 row is the second history row; its View button loads the definition.
    const viewButtons = screen.getAllByRole("button", { name: "View" });
    await user.click(viewButtons[viewButtons.length - 1]);

    expect(await screen.findByText("Revision r1 definition")).toBeInTheDocument();
    expect(await screen.findByText(/"PII guard v1"/)).toBeInTheDocument();
  });

  it("dry-runs a sample payload and renders the planned checks and actions", async () => {
    const user = userEvent.setup();
    mockHistory();
    let dryRunBody: unknown = null;
    server.use(
      http.post(
        gatewayUrl("/admin/v1/guardrail-policies/pol-pii/dry-run"),
        async ({ request }) => {
          dryRunBody = await request.json();
          return HttpResponse.json(dryRunResponse());
        },
      ),
    );

    renderDetail();
    await screen.findAllByText("PII guard v2");

    await user.type(
      screen.getByLabelText("Sample payload text"),
      "my ssn is 123-45-6789",
    );
    await user.click(screen.getByRole("button", { name: "Run dry-run" }));

    await waitFor(() =>
      expect(dryRunBody).toEqual({
        revision: null,
        stage: "request",
        model: null,
        provider: null,
        text: "my ssn is 123-45-6789",
      }),
    );
    // Findings/verdict rendering: planned revision, per-check result, actions.
    expect(await screen.findByText("pol-pii@3")).toBeInTheDocument();
    expect(screen.getByText("policy selected")).toBeInTheDocument();
    expect(screen.getAllByText("pii-local").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("fail")).toBeInTheDocument();
    expect(
      screen.getAllByText(/block \(pii_detected\)/).length,
    ).toBeGreaterThanOrEqual(1);
  });
});
