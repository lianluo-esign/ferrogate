import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";
import OpsDrainPage from "@/pages/ops-drain";
import { drainStatus } from "@/test/fixtures/ops";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";
// Bilingual smoke test for the migrated ops-* pages (#348). Proves the operator
// copy now flows through the typed `@/i18n` catalog and renders in BOTH the
// default English locale and Simplified Chinese, rather than hard-coded literals.
import { screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it } from "vitest";

beforeEach(() => {
  seedSession();
  server.use(http.get(gatewayUrl("/admin/v1/drain"), () => HttpResponse.json(drainStatus())));
});

describe("ops pages i18n", () => {
  it("renders drain copy from the English catalog by default", async () => {
    renderWithProviders(<OpsDrainPage />);

    expect(
      await screen.findByRole("heading", { name: en["page.opsDrain.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: en["page.opsDrain.action.start"] }),
    ).toBeInTheDocument();
    // The English title is genuinely the localized string, not a coincidence.
    expect(en["page.opsDrain.title"]).toBe("Graceful drain");
  });

  it("renders drain copy from the Simplified Chinese catalog", async () => {
    renderWithProviders(<OpsDrainPage />, { locale: "zh-CN" });

    expect(
      await screen.findByRole("heading", { name: zhCN["page.opsDrain.title"] }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: zhCN["page.opsDrain.action.start"] }),
    ).toBeInTheDocument();
    // Distinct catalogs: the Chinese copy differs from the English source.
    expect(zhCN["page.opsDrain.title"]).not.toBe(en["page.opsDrain.title"]);
  });
});
