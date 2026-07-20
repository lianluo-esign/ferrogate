import { screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import GuardrailPoliciesPage from "@/pages/guardrail-policies";
import { policyRevision } from "@/test/fixtures/guardrails";
import { mockAdminError, mockAdminList } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

beforeEach(() => {
  seedSession();
});

describe("GuardrailPoliciesPage", () => {
  it("groups the flat revision list into one row per policy with its active revision", async () => {
    mockAdminList("/admin/v1/guardrail-policies", [
      policyRevision({ policy_id: "pol-pii", revision: 1, status: "archived" }),
      policyRevision({ policy_id: "pol-pii", revision: 2, status: "active" }),
      policyRevision({
        policy_id: "pol-secrets",
        name: "Secrets guard",
        revision: 1,
        status: "draft",
        mode: "shadow",
      }),
    ]);

    renderWithProviders(<GuardrailPoliciesPage />);

    // pol-pii collapses to one row showing r2 as active.
    expect(await screen.findByRole("link", { name: "pol-pii" })).toHaveAttribute(
      "href",
      "/app/guardrail-policies/pol-pii",
    );
    expect(screen.getByText("r2 active")).toBeInTheDocument();
    // pol-secrets has no active revision; its latest status is surfaced.
    expect(screen.getByRole("link", { name: "pol-secrets" })).toBeInTheDocument();
    expect(screen.getByText("Secrets guard")).toBeInTheDocument();
    expect(screen.getByText("none (draft)")).toBeInTheDocument();
    expect(screen.getByText("shadow")).toBeInTheDocument();
  });

  it("shows the API error when the policy list fails to load", async () => {
    mockAdminError(
      "get",
      "/admin/v1/guardrail-policies",
      403,
      "forbidden",
      "missing guardrails.policy.read",
    );

    renderWithProviders(<GuardrailPoliciesPage />);

    expect(
      await screen.findByText(
        /Failed to load guardrail policies: missing guardrails.policy.read/,
      ),
    ).toBeInTheDocument();
  });
});
