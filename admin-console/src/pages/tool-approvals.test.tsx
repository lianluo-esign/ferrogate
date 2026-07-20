// Component tests for the tool-approvals action queue (#318).
//
// The load-bearing assertions are the fail-closed #62 fingerprint contract:
// approve/deny POSTs carry the EXACT `fingerprint` from the record, and a
// mocked 409 fingerprint-mismatch surfaces as a visible error while the
// pending row stays in the queue.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import ToolApprovalsPage from "@/pages/tool-approvals";
import type { AdminSchema } from "@/lib/gateway-client";
import { gatewayUrl, mockAdminError, mockAdminList, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

type ToolApprovalRecord = AdminSchema<"ToolApprovalRecord">;

const LIST_PATH = "/admin/v1/tool-approvals";
const NOW_UNIX = Math.floor(Date.now() / 1000);

function approval(overrides: Partial<ToolApprovalRecord> = {}): ToolApprovalRecord {
  return {
    id: "ap-1",
    request_id: "req-1",
    trace_id: "trace-1",
    agent_run_id: null,
    workflow_id: null,
    workflow_node_id: null,
    action_fingerprint: "sha256:feedbeef",
    decision: "ask",
    decision_reason: "approval_pending",
    tenant: {
      organization_id: "org-acme",
      team_id: null,
      project_id: "proj-1",
      user_id: null,
      api_key_id: "vk-actor",
    },
    actor_api_key_id: "vk-actor",
    tool_name: "delete_repo",
    server_name: "github",
    route: "agents/main",
    approval_policy: "always",
    approval_timeout_secs: 300,
    fingerprint: "blake2b:aabbccdd00112233",
    arguments_summary: '{"repo":"acme/api"}',
    risk_reason: "approval_policy_always",
    status: "pending",
    reviewer_api_key_id: null,
    reviewer_authority: null,
    terminal_reason: null,
    requested_at_unix: NOW_UNIX - 60,
    expires_at_unix: NOW_UNIX + 240,
    decided_at_unix: null,
    ...overrides,
  };
}

beforeEach(() => {
  seedSession();
});

describe("ToolApprovalsPage pending queue", () => {
  it("renders pending approvals with tool, actor, and arguments summary", async () => {
    mockAdminList(LIST_PATH, [approval()]);

    renderWithProviders(<ToolApprovalsPage />);

    expect(await screen.findByText("github/delete_repo")).toBeInTheDocument();
    expect(screen.getByText(/key vk-actor/)).toBeInTheDocument();
    expect(screen.getByText(/org org-acme/)).toBeInTheDocument();
    expect(screen.getByText('{"repo":"acme/api"}')).toBeInTheDocument();
    expect(screen.getByText("route agents/main")).toBeInTheDocument();
  });

  it("sorts the pending queue oldest-first and excludes terminal records", async () => {
    mockAdminList(LIST_PATH, [
      approval({
        id: "ap-new",
        tool_name: "newest_tool",
        requested_at_unix: NOW_UNIX - 10,
      }),
      approval({
        id: "ap-done",
        tool_name: "decided_tool",
        status: "approved",
        decided_at_unix: NOW_UNIX - 5,
      }),
      approval({
        id: "ap-old",
        tool_name: "oldest_tool",
        requested_at_unix: NOW_UNIX - 500,
      }),
    ]);

    renderWithProviders(<ToolApprovalsPage />);

    const oldest = await screen.findByText("github/oldest_tool");
    const newest = screen.getByText("github/newest_tool");
    // Terminal record only lives in the History tab, not the queue.
    expect(screen.queryByText("github/decided_tool")).not.toBeInTheDocument();
    // Oldest row precedes newest row in the DOM.
    expect(
      oldest.compareDocumentPosition(newest) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("shows run/workflow context and a TTL countdown", async () => {
    mockAdminList(LIST_PATH, [
      approval({
        agent_run_id: "run-42",
        workflow_id: "wf-7",
        workflow_node_id: "node-3",
        requested_at_unix: NOW_UNIX - 60,
        expires_at_unix: NOW_UNIX + 200,
      }),
    ]);

    renderWithProviders(<ToolApprovalsPage />);

    expect(
      await screen.findByText(/run run-42 · workflow wf-7 · node node-3/),
    ).toBeInTheDocument();
    // Age ~1m, TTL ~3m: assert the rendered "Xm Ys" countdown shapes exist.
    expect(screen.getAllByText(/^\d+m \d+s$/).length).toBeGreaterThanOrEqual(2);
  });

  it("shows an empty state when nothing is pending", async () => {
    mockAdminList(LIST_PATH, []);

    renderWithProviders(<ToolApprovalsPage />);

    expect(await screen.findByText("No pending approvals.")).toBeInTheDocument();
  });

  it("surfaces a list-load failure", async () => {
    mockAdminError("get", LIST_PATH, 403, "forbidden", "missing admin scope");

    renderWithProviders(<ToolApprovalsPage />);

    expect(
      await screen.findByText(/Failed to load tool approvals: missing admin scope/),
    ).toBeInTheDocument();
  });
});

describe("ToolApprovalsPage detail", () => {
  it("shows the invocation fingerprint, action fingerprint, and correlation ids", async () => {
    const user = userEvent.setup();
    mockAdminList(LIST_PATH, [approval()]);

    renderWithProviders(<ToolApprovalsPage />);
    await screen.findByText("github/delete_repo");

    await user.click(screen.getByRole("button", { name: "Details" }));

    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText("blake2b:aabbccdd00112233"),
    ).toBeInTheDocument();
    expect(within(dialog).getByText("sha256:feedbeef")).toBeInTheDocument();
    expect(within(dialog).getByText("req-1")).toBeInTheDocument();
    expect(within(dialog).getByText("trace-1")).toBeInTheDocument();
    expect(within(dialog).getByText("approval_policy_always")).toBeInTheDocument();
  });
});

describe("ToolApprovalsPage actions", () => {
  it("approves with the exact record fingerprint after confirmation and refreshes the queue", async () => {
    const user = userEvent.setup();
    const record = approval();
    let rows: ToolApprovalRecord[] = [record];
    let approveBody: unknown = null;
    server.use(
      http.get(gatewayUrl(LIST_PATH), () =>
        HttpResponse.json({ object: "list", data: rows }),
      ),
      http.post(
        gatewayUrl(`${LIST_PATH}/${record.id}/approve`),
        async ({ request }) => {
          approveBody = await request.json();
          rows = [{ ...record, status: "approved", decision: "allow" }];
          return HttpResponse.json(rows[0]);
        },
      ),
    );

    renderWithProviders(<ToolApprovalsPage />);
    await screen.findByText("github/delete_repo");

    await user.click(screen.getByRole("button", { name: "Approve" }));
    const dialog = await screen.findByRole("dialog");
    // Confirmation dialog restates the binding fingerprint before submit.
    expect(
      within(dialog).getByText("blake2b:aabbccdd00112233"),
    ).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Approve" }));

    await waitFor(() =>
      expect(approveBody).toEqual({
        fingerprint: "blake2b:aabbccdd00112233",
        reason: null,
      }),
    );
    // Queue invalidated -> refetch drops the now-terminal row.
    await waitFor(() =>
      expect(screen.queryByText("github/delete_repo")).not.toBeInTheDocument(),
    );
  });

  it("sends the reviewer comment as the decision reason", async () => {
    const user = userEvent.setup();
    const record = approval();
    let approveBody: unknown = null;
    mockAdminList(LIST_PATH, [record]);
    server.use(
      http.post(
        gatewayUrl(`${LIST_PATH}/${record.id}/approve`),
        async ({ request }) => {
          approveBody = await request.json();
          return HttpResponse.json({ ...record, status: "approved" });
        },
      ),
    );

    renderWithProviders(<ToolApprovalsPage />);
    await screen.findByText("github/delete_repo");

    await user.click(screen.getByRole("button", { name: "Approve" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(
      within(dialog).getByLabelText("Reviewer comment (optional)"),
      "verified with requester",
    );
    await user.click(within(dialog).getByRole("button", { name: "Approve" }));

    await waitFor(() =>
      expect(approveBody).toEqual({
        fingerprint: "blake2b:aabbccdd00112233",
        reason: "verified with requester",
      }),
    );
  });

  it("keeps the row and surfaces the error on a fingerprint-mismatch 409", async () => {
    const user = userEvent.setup();
    const record = approval();
    mockAdminList(LIST_PATH, [record]);
    server.use(
      http.post(gatewayUrl(`${LIST_PATH}/${record.id}/approve`), () =>
        HttpResponse.json(
          {
            error: {
              code: "approval_fingerprint_mismatch",
              message: "fingerprint does not match the pending invocation",
            },
          },
          { status: 409 },
        ),
      ),
    );

    renderWithProviders(<ToolApprovalsPage />);
    await screen.findByText("github/delete_repo");

    await user.click(screen.getByRole("button", { name: "Approve" }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Approve" }));

    // The rejection is rendered inside the still-open confirmation dialog...
    expect(
      await within(dialog).findByText(
        "fingerprint does not match the pending invocation",
      ),
    ).toBeInTheDocument();
    // ...and after dismissing the dialog the pending row is still queued.
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.getByText("github/delete_repo")).toBeInTheDocument();
  });

  it("denies with the bound fingerprint via the deny endpoint", async () => {
    const user = userEvent.setup();
    const record = approval();
    let rows: ToolApprovalRecord[] = [record];
    let denyBody: unknown = null;
    server.use(
      http.get(gatewayUrl(LIST_PATH), () =>
        HttpResponse.json({ object: "list", data: rows }),
      ),
      http.post(
        gatewayUrl(`${LIST_PATH}/${record.id}/deny`),
        async ({ request }) => {
          denyBody = await request.json();
          rows = [{ ...record, status: "denied", decision: "deny" }];
          return HttpResponse.json(rows[0]);
        },
      ),
    );

    renderWithProviders(<ToolApprovalsPage />);
    await screen.findByText("github/delete_repo");

    await user.click(screen.getByRole("button", { name: "Deny" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(
      within(dialog).getByLabelText("Reviewer comment (optional)"),
      "too risky",
    );
    await user.click(within(dialog).getByRole("button", { name: "Deny" }));

    await waitFor(() =>
      expect(denyBody).toEqual({
        fingerprint: "blake2b:aabbccdd00112233",
        reason: "too risky",
      }),
    );
    await waitFor(() =>
      expect(screen.queryByText("github/delete_repo")).not.toBeInTheDocument(),
    );
  });

  it("expires a pending request via the expire endpoint", async () => {
    const user = userEvent.setup();
    const record = approval();
    let rows: ToolApprovalRecord[] = [record];
    let expireBody: unknown = null;
    server.use(
      http.get(gatewayUrl(LIST_PATH), () =>
        HttpResponse.json({ object: "list", data: rows }),
      ),
      http.post(
        gatewayUrl(`${LIST_PATH}/${record.id}/expire`),
        async ({ request }) => {
          expireBody = await request.json();
          rows = [{ ...record, status: "expired", decision: "deny" }];
          return HttpResponse.json(rows[0]);
        },
      ),
    );

    renderWithProviders(<ToolApprovalsPage />);
    await screen.findByText("github/delete_repo");

    await user.click(screen.getByRole("button", { name: "Expire" }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Expire" }));

    await waitFor(() =>
      expect(expireBody).toEqual({ fingerprint: null, reason: null }),
    );
    await waitFor(() =>
      expect(screen.queryByText("github/delete_repo")).not.toBeInTheDocument(),
    );
  });
});

describe("ToolApprovalsPage history", () => {
  it("renders terminal approvals with status, decision, and decision reason", async () => {
    const user = userEvent.setup();
    mockAdminList(LIST_PATH, [
      approval({
        id: "ap-approved",
        tool_name: "approved_tool",
        status: "approved",
        decision: "allow",
        decision_reason: "approval_approved",
        reviewer_api_key_id: "vk-reviewer",
        decided_at_unix: NOW_UNIX - 30,
      }),
      approval({
        id: "ap-denied",
        tool_name: "denied_tool",
        status: "denied",
        decision: "deny",
        decision_reason: "approval_denied",
        decided_at_unix: NOW_UNIX - 20,
      }),
      approval({
        id: "ap-expired",
        tool_name: "expired_tool",
        status: "expired",
        decision: "deny",
        decision_reason: "approval_expired",
        decided_at_unix: NOW_UNIX - 10,
      }),
    ]);

    renderWithProviders(<ToolApprovalsPage />);
    await screen.findByText("No pending approvals.");

    await user.click(screen.getByRole("tab", { name: "History" }));

    expect(await screen.findByText("github/approved_tool")).toBeInTheDocument();
    expect(screen.getByText("approved")).toBeInTheDocument();
    expect(screen.getByText("allow")).toBeInTheDocument();
    expect(screen.getByText("approval_approved")).toBeInTheDocument();
    expect(screen.getByText("vk-reviewer")).toBeInTheDocument();
    expect(screen.getByText("github/denied_tool")).toBeInTheDocument();
    expect(screen.getByText("denied")).toBeInTheDocument();
    expect(screen.getByText("approval_denied")).toBeInTheDocument();
    expect(screen.getByText("github/expired_tool")).toBeInTheDocument();
    expect(screen.getByText("expired")).toBeInTheDocument();
    expect(screen.getByText("approval_expired")).toBeInTheDocument();
  });
});
