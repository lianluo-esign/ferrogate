// Bilingual smoke coverage for the #348 final slice: the shared primitives and
// components de-allowlisted from `ferrogate/no-untranslated-literal` must render
// their operator copy AND sr-only/a11y labels from the typed catalog in BOTH
// `en` and `zh-CN`. This is the runtime companion to the now-empty
// I18N_UNMIGRATED_ALLOWLIST.
import type { ReactElement } from "react";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { RouteLoading } from "@/components/route-load-boundary";
import { ToolsTable } from "@/components/tools/tools-table";
import {
  CredentialRevealDialog,
  ReportedTrustBadge,
} from "@/components/worker-ops/worker-ops-primitives";
import { I18nProvider, type Locale } from "@/i18n";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";

const CATALOGS = { en, "zh-CN": zhCN } as const;

function renderLocalized(ui: ReactElement, locale: Locale) {
  return render(
    <MemoryRouter>
      <I18nProvider initialLocale={locale}>{ui}</I18nProvider>
    </MemoryRouter>,
  );
}

describe.each<Locale>(["en", "zh-CN"])("shared primitives render localized copy (%s)", (locale) => {
  const c = CATALOGS[locale];

  it("ReportedTrustBadge renders the reported-by-worker label", () => {
    renderLocalized(<ReportedTrustBadge />, locale);
    expect(screen.getByText(c["workerOps.trustBadge.reported"])).toBeInTheDocument();
  });

  it("CredentialRevealDialog renders warning, copy, and done copy", () => {
    renderLocalized(
      <CredentialRevealDialog
        open
        onClose={() => {}}
        title="Title"
        description="Description"
        credentialLabel="Fingerprint"
        credential="sha256:secret"
      />,
      locale,
    );
    expect(screen.getByText(c["workerOps.reveal.warning"])).toBeInTheDocument();
    expect(screen.getByRole("button", { name: c["common.copy"] })).toBeInTheDocument();
    expect(screen.getByText(c["common.done"])).toBeInTheDocument();
  });

  it("ToolsTable renders localized column headers and empty state", () => {
    renderLocalized(<ToolsTable tools={[]} isLoading={false} />, locale);
    const headers = screen.getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual([
      c["component.toolsTable.col.tool"],
      c["component.toolsTable.col.plugin"],
      c["component.toolsTable.col.approval"],
      c["component.toolsTable.col.tenants"],
      c["component.toolsTable.col.apiKeys"],
      c["component.toolsTable.col.routes"],
    ]);
    expect(screen.getByText(c["component.toolsTable.empty"])).toBeInTheDocument();
  });

  it("ToolsTable renders the localized loading row", () => {
    renderLocalized(<ToolsTable tools={[]} isLoading />, locale);
    expect(screen.getByText(c["common.loading"])).toBeInTheDocument();
  });

  it("RouteLoading announces a localized busy status", () => {
    renderLocalized(<RouteLoading />, locale);
    const status = screen.getByRole("status");
    expect(status).toHaveAttribute("aria-busy", "true");
    expect(within(status).getByText(c["component.routeBoundary.loading"])).toBeInTheDocument();
  });
});
