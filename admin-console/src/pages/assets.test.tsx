import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClientProvider } from "@tanstack/react-query";
import { HttpResponse, http } from "msw";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider } from "@/i18n";
import type { AdminSchema } from "@/lib/gateway-client";
import AssetsPage from "@/pages/assets";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";

type AssetSummary = AdminSchema<"AssetSummary">;
type AssetStorageSummary = AdminSchema<"AssetStorageSummary">;

function asset(overrides: Partial<AssetSummary> = {}): AssetSummary {
  return {
    id: "org-acme:cli_tool:ferrogate:1.0.0",
    asset_type: "cli_tool",
    name: "ferrogate",
    version: "1.0.0",
    content_type: "application/octet-stream",
    content_hash: "a".repeat(64),
    size_bytes: 100,
    storage_backed: false,
    created_at_unix: 1000,
    updated_at_unix: 1000,
    ...overrides,
  };
}

function storageSummary(
  overrides: Partial<AssetStorageSummary> = {},
): AssetStorageSummary {
  return {
    object: "asset_storage_summary",
    used_bytes: 4096,
    quota_bytes: 8192,
    remaining_bytes: 4096,
    inline_upload_max_bytes: 10 * 1024 * 1024,
    presigned_upload: {
      enabled: true,
      max_object_bytes: 1024 * 1024 * 1024,
      url_ttl_seconds: 900,
    },
    ...overrides,
  };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <I18nProvider initialLocale="en">
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            <AssetsPage />
          </QueryClientProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  seedSession();
});

describe("AssetsPage", () => {
  it("renders authoritative storage usage instead of summing list rows", async () => {
    let summaryRequests = 0;
    let resolvedDefaultsRequests = 0;
    server.use(
      http.get(gatewayUrl("/v1/assets"), () =>
        HttpResponse.json({ object: "list", data: [asset()] }),
      ),
      http.get(gatewayUrl("/v1/assets/storage/summary"), () => {
        summaryRequests += 1;
        return HttpResponse.json(storageSummary());
      }),
      http.get(
        gatewayUrl("/admin/v1/tenant-accounts/:tenantId/resolved-defaults"),
        () => {
          resolvedDefaultsRequests += 1;
          return HttpResponse.json({ default_asset_storage_quota_bytes: 9999 });
        },
      ),
    );

    renderPage();

    expect(await screen.findByText("4 KB used of 8 KB")).toBeInTheDocument();
    expect(screen.queryByText("100 B used")).not.toBeInTheDocument();
    await waitFor(() => expect(summaryRequests).toBe(1));
    expect(resolvedDefaultsRequests).toBe(0);
  });

  it("refetches authoritative storage usage after deleting an asset", async () => {
    let deleted = false;
    let summaryRequests = 0;
    server.use(
      http.get(gatewayUrl("/v1/assets"), () =>
        HttpResponse.json({ object: "list", data: deleted ? [] : [asset()] }),
      ),
      http.get(gatewayUrl("/v1/assets/storage/summary"), () => {
        summaryRequests += 1;
        return HttpResponse.json(
          storageSummary({
            used_bytes: deleted ? 0 : 100,
            remaining_bytes: deleted ? 8192 : 8092,
          }),
        );
      }),
      http.delete(gatewayUrl("/v1/assets/cli_tool/ferrogate/1.0.0"), () => {
        deleted = true;
        return HttpResponse.json({
          object: "asset",
          id: "org-acme:cli_tool:ferrogate:1.0.0",
          deleted: true,
        });
      }),
    );
    const user = userEvent.setup();

    renderPage();

    expect(await screen.findByText("100 B used of 8 KB")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Delete" }));

    expect(await screen.findByText("0 B used of 8 KB")).toBeInTheDocument();
    await waitFor(() => expect(summaryRequests).toBeGreaterThanOrEqual(2));
  });
});
