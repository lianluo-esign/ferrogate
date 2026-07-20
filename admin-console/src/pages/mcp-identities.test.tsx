import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { MemoryRouter } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
import McpIdentitiesPage from "@/pages/mcp-identities";
import type { AdminSchema } from "@/lib/gateway-client";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";

type IdentityStatus = AdminSchema<"McpIdentityStatus">;

function status(overrides: Partial<IdentityStatus> = {}): IdentityStatus {
  return {
    object: "mcp_identity",
    server_name: "github-mcp",
    auth_type: "per_user_oauth",
    connected: false,
    credential_source: "subject_bound_oauth",
    subject: null,
    expires_at_unix: null,
    revoked_at_unix: null,
    last_refresh_outcome: null,
    last_revocation_outcome: null,
    ...overrides,
  };
}

function mockServers(): void {
  server.use(
    http.get(gatewayUrl("/admin/v1/mcp-servers"), () =>
      HttpResponse.json({ object: "list", data: [] }),
    ),
  );
}

function mockIdentity(record: IdentityStatus): void {
  server.use(
    http.get(gatewayUrl("/v1/mcp/identity/github-mcp"), () => HttpResponse.json(record)),
  );
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <QueryClientProvider client={createTestQueryClient()}>
          <McpIdentitiesPage />
        </QueryClientProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  seedSession();
});

describe("McpIdentitiesPage", () => {
  it("renders identity status for a looked-up server", async () => {
    mockServers();
    mockIdentity(
      status({ connected: true, subject: "user-42", auth_type: "per_user_oauth" }),
    );
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("Server name"), "github-mcp");
    await user.click(screen.getByRole("button", { name: "Load status" }));

    expect(await screen.findByTestId("identity-connection")).toHaveTextContent("connected");
    expect(screen.getByText("user-42")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Disconnect" })).toBeInTheDocument();
  });

  it("initiates the OAuth flow and surfaces the authorization URL", async () => {
    mockServers();
    mockIdentity(status({ connected: false }));
    server.use(
      http.post(gatewayUrl("/v1/mcp/identity/github-mcp/authorize"), () =>
        HttpResponse.json({
          object: "mcp_oauth_authorization",
          server_name: "github-mcp",
          authorize_url: "https://provider.example/oauth/authorize?state=xyz",
          state: "state-xyz",
          expires_at_unix: 2000,
        }),
      ),
    );
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("Server name"), "github-mcp");
    await user.click(screen.getByRole("button", { name: "Load status" }));

    await screen.findByTestId("identity-connection");
    await user.click(screen.getByRole("button", { name: "Connect (OAuth)" }));

    const panel = await screen.findByTestId("authorization-panel");
    expect(panel).toHaveTextContent("Complete authorization out-of-band");
    expect(
      screen.getByRole("link", {
        name: "https://provider.example/oauth/authorize?state=xyz",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(/state: state-xyz/)).toBeInTheDocument();
  });

  it("disconnects a connected identity", async () => {
    mockServers();
    mockIdentity(status({ connected: true, subject: "user-42" }));
    let revoked = false;
    server.use(
      http.delete(gatewayUrl("/v1/mcp/identity/github-mcp"), () => {
        revoked = true;
        return HttpResponse.json(status({ connected: false }));
      }),
    );
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("Server name"), "github-mcp");
    await user.click(screen.getByRole("button", { name: "Load status" }));
    await screen.findByTestId("identity-connection");
    await user.click(screen.getByRole("button", { name: "Disconnect" }));

    await waitFor(() => expect(revoked).toBe(true));
  });
});
