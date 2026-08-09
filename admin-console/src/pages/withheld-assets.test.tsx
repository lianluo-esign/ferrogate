import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider, type Locale } from "@/i18n";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";
import type { AdminSchema } from "@/lib/gateway-client";
import WithheldAssetsPage from "@/pages/withheld-assets";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";

type WithheldAsset = AdminSchema<"WithheldAssetSummary">;

function withheld(overrides: Partial<WithheldAsset> = {}): WithheldAsset {
  return {
    id: "org-acme:cli_tool:ferrogate:1.0.0",
    asset_type: "cli_tool",
    name: "ferrogate",
    version: "1.0.0",
    content_type: "application/octet-stream",
    content_hash: "a".repeat(64),
    size_bytes: 2048,
    storage_backed: true,
    created_at_unix: 1000,
    updated_at_unix: 1000,
    visibility: "pending_scan",
    screening_evidence: "scanner=clamav verdict=pending signature=verified",
    ...overrides,
  };
}

function renderPage(locale: Locale = "en") {
  return render(
    <MemoryRouter>
      <I18nProvider initialLocale={locale}>
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            <WithheldAssetsPage />
          </QueryClientProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  seedSession();
});

describe("WithheldAssetsPage", () => {
  it("renders withheld rows with visibility state in English", async () => {
    server.use(
      http.get(gatewayUrl("/v1/assets/withheld"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            withheld(),
            withheld({
              id: "org-acme:mcp_manifest:widget:2.0.0",
              asset_type: "mcp_manifest",
              name: "widget",
              version: "2.0.0",
              visibility: "quarantined",
              screening_evidence: undefined,
            }),
          ],
          total: 2,
          offset: 0,
          limit: 20,
        }),
      ),
    );

    renderPage("en");

    expect(
      await screen.findByRole("heading", {
        name: en["page.withheldAssets.title"],
      }),
    ).toBeInTheDocument();
    expect(await screen.findByText("ferrogate")).toBeInTheDocument();
    expect(screen.getByText(en["page.withheldAssets.visibility.pendingScan"])).toBeInTheDocument();
    expect(screen.getByText(en["page.withheldAssets.visibility.quarantined"])).toBeInTheDocument();
    // Row without retained evidence shows the "none" affordance.
    expect(screen.getByText(en["page.withheldAssets.evidence.none"])).toBeInTheDocument();
  });

  it("renders localized copy in zh-CN", async () => {
    server.use(
      http.get(gatewayUrl("/v1/assets/withheld"), () =>
        HttpResponse.json({ object: "list", data: [withheld()], total: 1 }),
      ),
    );

    renderPage("zh-CN");

    expect(
      await screen.findByRole("heading", {
        name: zhCN["page.withheldAssets.title"],
      }),
    ).toBeInTheDocument();
    // Wait for the async list to resolve before asserting row-level copy.
    expect(
      await screen.findByText(zhCN["page.withheldAssets.visibility.pendingScan"]),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name: zhCN["page.withheldAssets.action.promote"],
      }),
    ).toBeInTheDocument();
  });

  it("shows the screening evidence in a dialog", async () => {
    server.use(
      http.get(gatewayUrl("/v1/assets/withheld"), () =>
        HttpResponse.json({ object: "list", data: [withheld()], total: 1 }),
      ),
    );
    const user = userEvent.setup();

    renderPage("en");

    await user.click(
      await screen.findByRole("button", {
        name: en["page.withheldAssets.evidence.view"],
      }),
    );

    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText("scanner=clamav verdict=pending signature=verified"),
    ).toBeInTheDocument();
  });

  it("promotes an asset with the clean verdict and refreshes the list", async () => {
    let promoteRequest: {
      url: string;
      body: AdminSchema<"AssetVisibilityPromotionRequest">;
    } | null = null;
    let promoted = false;

    server.use(
      http.get(gatewayUrl("/v1/assets/withheld"), () =>
        HttpResponse.json({
          object: "list",
          data: promoted ? [] : [withheld()],
          total: promoted ? 0 : 1,
        }),
      ),
      http.post(
        gatewayUrl("/v1/assets/cli_tool/ferrogate/1.0.0/visibility"),
        async ({ request }) => {
          promoteRequest = {
            url: request.url,
            body: (await request.json()) as AdminSchema<"AssetVisibilityPromotionRequest">,
          };
          promoted = true;
          return HttpResponse.json({
            object: "asset.visibility_promotion",
            id: "org-acme:cli_tool:ferrogate:1.0.0",
            visibility: "visible",
            scan_outcome: "visible",
            asset: {
              id: "org-acme:cli_tool:ferrogate:1.0.0",
              asset_type: "cli_tool",
              name: "ferrogate",
              version: "1.0.0",
              content_type: "application/octet-stream",
              content_hash: "a".repeat(64),
              size_bytes: 2048,
              storage_backed: true,
              created_at_unix: 1000,
              updated_at_unix: 2000,
            },
          });
        },
      ),
    );
    const user = userEvent.setup();

    renderPage("en");

    await user.click(
      await screen.findByRole("button", {
        name: en["page.withheldAssets.action.promote"],
      }),
    );

    const dialog = await screen.findByRole("dialog");
    await user.type(
      within(dialog).getByLabelText(en["page.withheldAssets.field.evidence"]),
      "clean scan, ticket OPS-42",
    );
    await user.click(
      within(dialog).getByRole("button", {
        name: en["page.withheldAssets.action.promote"],
      }),
    );

    await waitFor(() => expect(promoteRequest).not.toBeNull());
    // biome-ignore lint/style/noNonNullAssertion: promoteRequest is assigned only inside the mock fetch callback, so TS control-flow narrows the outer binding to null and no cast can name its declared type; ! reads the capture the expect() above just asserted is present
    const promoteReq = promoteRequest!;
    expect(promoteReq.body.scan_outcome).toBe("clean");
    expect(promoteReq.body.evidence).toBe("clean scan, ticket OPS-42");
    // List refreshed to the promoted (now empty) state.
    expect(await screen.findByText(en["page.withheldAssets.empty"])).toBeInTheDocument();
  });

  it("quarantines an asset with the flagged verdict", async () => {
    let scanOutcome: string | null = null;

    server.use(
      http.get(gatewayUrl("/v1/assets/withheld"), () =>
        HttpResponse.json({ object: "list", data: [withheld()], total: 1 }),
      ),
      http.post(
        gatewayUrl("/v1/assets/cli_tool/ferrogate/1.0.0/visibility"),
        async ({ request }) => {
          const body = (await request.json()) as AdminSchema<"AssetVisibilityPromotionRequest">;
          scanOutcome = body.scan_outcome;
          return HttpResponse.json({
            object: "asset.visibility_promotion",
            id: "org-acme:cli_tool:ferrogate:1.0.0",
            visibility: "quarantined",
            scan_outcome: "quarantined",
            asset: {
              id: "org-acme:cli_tool:ferrogate:1.0.0",
              asset_type: "cli_tool",
              name: "ferrogate",
              version: "1.0.0",
              content_type: "application/octet-stream",
              content_hash: "a".repeat(64),
              size_bytes: 2048,
              storage_backed: true,
              created_at_unix: 1000,
              updated_at_unix: 2000,
            },
          });
        },
      ),
    );
    const user = userEvent.setup();

    renderPage("en");

    await user.click(
      await screen.findByRole("button", {
        name: en["page.withheldAssets.action.quarantine"],
      }),
    );

    const dialog = await screen.findByRole("dialog");
    await user.type(
      within(dialog).getByLabelText(en["page.withheldAssets.field.evidence"]),
      "malware signature match",
    );
    await user.click(
      within(dialog).getByRole("button", {
        name: en["page.withheldAssets.action.quarantine"],
      }),
    );

    await waitFor(() => expect(scanOutcome).toBe("quarantined"));
  });

  it("maps a 409 conflict to a clear localized message and keeps the dialog open", async () => {
    server.use(
      http.get(gatewayUrl("/v1/assets/withheld"), () =>
        HttpResponse.json({ object: "list", data: [withheld()], total: 1 }),
      ),
      http.post(gatewayUrl("/v1/assets/cli_tool/ferrogate/1.0.0/visibility"), () =>
        HttpResponse.json(
          { error: { code: "conflict", message: "already terminal" } },
          { status: 409 },
        ),
      ),
    );
    const user = userEvent.setup();

    renderPage("en");

    await user.click(
      await screen.findByRole("button", {
        name: en["page.withheldAssets.action.promote"],
      }),
    );
    const dialog = await screen.findByRole("dialog");
    await user.type(
      within(dialog).getByLabelText(en["page.withheldAssets.field.evidence"]),
      "clean",
    );
    await user.click(
      within(dialog).getByRole("button", {
        name: en["page.withheldAssets.action.promote"],
      }),
    );

    expect(
      await within(dialog).findByText(en["page.withheldAssets.error.conflict"]),
    ).toBeInTheDocument();
  });

  it("requires evidence before submitting", async () => {
    let posted = false;
    server.use(
      http.get(gatewayUrl("/v1/assets/withheld"), () =>
        HttpResponse.json({ object: "list", data: [withheld()], total: 1 }),
      ),
      http.post(gatewayUrl("/v1/assets/cli_tool/ferrogate/1.0.0/visibility"), () => {
        posted = true;
        return HttpResponse.json({}, { status: 200 });
      }),
    );
    const user = userEvent.setup();

    renderPage("en");

    await user.click(
      await screen.findByRole("button", {
        name: en["page.withheldAssets.action.promote"],
      }),
    );
    const dialog = await screen.findByRole("dialog");
    await user.click(
      within(dialog).getByRole("button", {
        name: en["page.withheldAssets.action.promote"],
      }),
    );

    expect(
      await within(dialog).findByText(en["page.withheldAssets.error.evidenceRequired"]),
    ).toBeInTheDocument();
    expect(posted).toBe(false);
  });
});
