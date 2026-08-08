import { screen } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";
import OpsStatusPage from "@/pages/ops-status";
import { adminStatus } from "@/test/fixtures/ops";
import { gatewayUrl, server } from "@/test/msw";
import { renderWithProviders, seedSession } from "@/test/test-utils";

beforeEach(() => {
  seedSession();
});

describe("OpsStatusPage", () => {
  it("renders health counters, ACME posture and cluster readiness", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/status"), () =>
        HttpResponse.json(adminStatus()),
      ),
    );

    renderWithProviders(<OpsStatusPage />);

    // counters (enabled / total)
    expect(await screen.findByText("3 / 4")).toBeInTheDocument(); // providers
    expect(screen.getByText("10 / 12")).toBeInTheDocument(); // models
    expect(screen.getByText("v1.2.3")).toBeInTheDocument();
    expect(screen.getByText("snapshot snap-abc")).toBeInTheDocument();

    // ACME + cluster sections present
    expect(screen.getByText("TLS / ACME")).toBeInTheDocument();
    expect(screen.getByText("gateway.example.com")).toBeInTheDocument();
    expect(screen.getByText("Cluster")).toBeInTheDocument();
    expect(screen.getByText("state_loaded")).toBeInTheDocument();

    // #893 platform catalog counts, distinct from the tenant aggregates above.
    expect(screen.getByText("Platform catalog")).toBeInTheDocument();
    expect(screen.getByText("Platform channels")).toBeInTheDocument();
    // Platform providers=2 renders its own tile, NOT folded into providers 3/4.
    expect(screen.getByText("2")).toBeInTheDocument(); // platform channels
    expect(screen.getByText("5")).toBeInTheDocument(); // platform models
    expect(screen.getByText("8")).toBeInTheDocument(); // platform offerings
  });

  it("hides the platform catalog section when the deployment omits the counts", async () => {
    // A gateway predating #902 returns no platform_* fields; the section must
    // not render empty/undefined tiles (falsifies an unconditional render).
    const base = adminStatus();
    const legacy = { ...base } as Record<string, unknown>;
    delete legacy.platform_providers;
    delete legacy.platform_models;
    delete legacy.platform_offerings;
    server.use(
      http.get(gatewayUrl("/admin/v1/status"), () => HttpResponse.json(legacy)),
    );

    renderWithProviders(<OpsStatusPage />);

    // The tenant board still renders...
    expect(await screen.findByText("3 / 4")).toBeInTheDocument();
    // ...but the platform section is absent.
    expect(screen.queryByText("Platform catalog")).not.toBeInTheDocument();
  });

  it("flags reload_required when ACME needs a listener reload (#265)", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/status"), () =>
        HttpResponse.json(
          adminStatus({
            acme: {
              ...adminStatus().acme!,
              reload_required: true,
              reload_mode: "listener",
            },
          }),
        ),
      ),
    );

    renderWithProviders(<OpsStatusPage />);

    expect(await screen.findByText("reload required")).toBeInTheDocument();
  });

  // #348: the cluster last-sync cell used a bare `toLocaleString()`, so it was
  // formatted in the BROWSER's language regardless of the console locale (jsdom
  // and CI both default to en-US). It now resolves through `format.date` under
  // the ACTIVE locale, and carries the relative "how stale is this?" reading
  // `format.relativeTime` exists for — which had no app consumer at all before.
  //
  // The absolute assertion is deliberately shape-based, not a pinned wall-clock
  // string: the rendering is timezone-dependent, but "年" (and the absence of an
  // en-US `M/D/YYYY, h:mm AM` form) can only come from a zh-CN formatter.
  it("renders the cluster last-sync timestamp AND its relative age in the active locale", async () => {
    // Three hours before "now" — so the relative reading is exact without
    // faking the clock (faking Date stalls MSW + react-query here).
    const threeHoursAgo = Math.floor(Date.now() / 1000) - 3 * 60 * 60;
    const base = adminStatus();
    server.use(
      http.get(gatewayUrl("/admin/v1/status"), () =>
        HttpResponse.json(
          adminStatus({ cluster: { ...base.cluster, last_sync_at_unix: threeHoursAgo } }),
        ),
      ),
    );

    renderWithProviders(<OpsStatusPage />, { locale: "zh-CN" });

    expect(await screen.findByText("3小时前")).toBeInTheDocument();
    // Every timestamp on the board (cluster sync, ACME renewal/expiry/next
    // check, analytics) goes through the same helper, so they are ALL zh-CN.
    expect(screen.getAllByText(/年.*月.*日/).length).toBeGreaterThanOrEqual(4);
    // No en-US `7/9/2025, 2:40:00 AM` rendering of the same instant.
    expect(screen.queryByText(/\d+\/\d+\/\d{4}/)).not.toBeInTheDocument();
    expect(screen.queryByText(/\b(AM|PM)\b/)).not.toBeInTheDocument();
  });

  it("surfaces a load error", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/status"), () =>
        HttpResponse.json(
          { error: { code: "boom", message: "status exploded" } },
          { status: 500 },
        ),
      ),
    );

    renderWithProviders(<OpsStatusPage />);

    expect(await screen.findByText(/status exploded/)).toBeInTheDocument();
  });
});
