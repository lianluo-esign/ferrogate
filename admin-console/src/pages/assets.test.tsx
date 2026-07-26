import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClientProvider } from "@tanstack/react-query";
import { HttpResponse, http } from "msw";
import { MemoryRouter, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "@/hooks/use-auth";
import { I18nProvider, type Locale } from "@/i18n";
import { en } from "@/i18n/locales/en";
import { zhCN } from "@/i18n/locales/zh-CN";
import type { AdminSchema } from "@/lib/gateway-client";
import AssetsPage from "@/pages/assets";
import { gatewayUrl, server } from "@/test/msw";
import { createTestQueryClient, seedSession } from "@/test/test-utils";

type AssetSummary = AdminSchema<"AssetSummary">;
type AssetStorageSummary = AdminSchema<"AssetStorageSummary">;
type AssetManifest = AdminSchema<"AssetManifest">;

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

const ferrogateManifest: AssetManifest = {
  object: "asset_manifest",
  asset_type: "cli_tool",
  name: "ferrogate",
  channels: [{ channel: "stable", version: "2.0.0", updated_at_unix: 1500 }],
  versions: [
    {
      version: "2.0.0",
      yanked: false,
      variants: [
        {
          variant: "",
          content_type: "application/octet-stream",
          content_hash: "b".repeat(64),
          size_bytes: 200,
          storage_backed: true,
        },
      ],
    },
    {
      version: "1.0.0",
      yanked: false,
      variants: [
        {
          variant: "linux-x64",
          content_type: "application/octet-stream",
          content_hash: "c".repeat(64),
          size_bytes: 100,
          storage_backed: false,
        },
      ],
    },
  ],
};

// Two logical resources: ferrogate (cli_tool, 2 versions) + widget (mcp_manifest).
function seedList() {
  server.use(
    http.get(gatewayUrl("/v1/assets"), () =>
      HttpResponse.json({
        object: "list",
        data: [
          asset(),
          asset({
            id: "org-acme:cli_tool:ferrogate:2.0.0",
            version: "2.0.0",
            updated_at_unix: 2000,
            storage_backed: true,
          }),
          asset({
            id: "org-acme:mcp_manifest:widget:1.0.0",
            asset_type: "mcp_manifest",
            name: "widget",
          }),
        ],
      }),
    ),
    http.get(gatewayUrl("/v1/assets/storage/summary"), () =>
      HttpResponse.json(storageSummary()),
    ),
  );
}

/**
 * One logical-resource record in the registry list.
 *
 * The list renders through the shared responsive data surface
 * (components/resource/resource-table.tsx, #336): a <table> at >=1024px and
 * `data-compact-records` <article> cards below it. jsdom's matchMedia stub
 * reports no match, so these tests exercise the COMPACT view; the desktop table
 * is covered by the Playwright desktop-1440 project. Anchoring on the record
 * element rather than on `tr` keeps the assertions valid in either view.
 */
function registryRecord(name: string): HTMLElement {
  const record = screen.getByText(name).closest("article, tr");
  if (!record) throw new Error(`no registry record for ${name}`);
  return record as HTMLElement;
}

async function findRegistryRecord(name: string): Promise<HTMLElement> {
  await screen.findByText(name);
  return registryRecord(name);
}

// Surfaces the live location so URL-state assertions can read the query the
// registry writes as the operator filters, searches, and opens a resource.
let currentSearch = "";
function LocationProbe() {
  currentSearch = useLocation().search;
  return null;
}

function renderPage(locale: Locale = "en", initialEntry = "/app/assets") {
  currentSearch = "";
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <I18nProvider initialLocale={locale}>
        <AuthProvider>
          <QueryClientProvider client={createTestQueryClient()}>
            <AssetsPage />
            <LocationProbe />
          </QueryClientProvider>
        </AuthProvider>
      </I18nProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  seedSession();
});

describe("AssetsPage registry list", () => {
  it("renders authoritative storage usage instead of summing list rows", async () => {
    server.use(
      http.get(gatewayUrl("/v1/assets"), () =>
        HttpResponse.json({ object: "list", data: [asset()] }),
      ),
      http.get(gatewayUrl("/v1/assets/storage/summary"), () =>
        HttpResponse.json(storageSummary()),
      ),
    );

    renderPage();

    expect(await screen.findByText("4 KB used of 8 KB")).toBeInTheDocument();
    expect(screen.queryByText("100 B used")).not.toBeInTheDocument();
  });

  it("collapses per-version rows into logical resources and filters by type + search", async () => {
    seedList();
    const user = userEvent.setup();

    renderPage("en");

    // ferrogate collapses its two versions into one logical row (count = 2).
    const ferrogateRow = await findRegistryRecord("ferrogate");
    expect(within(ferrogateRow).getByText("2")).toBeInTheDocument();
    expect(within(ferrogateRow).getByText("2.0.0")).toBeInTheDocument();
    expect(screen.getByText("widget")).toBeInTheDocument();

    // Filtering to cli_tool hides the mcp_manifest resource. Two controls share
    // the "Asset type" label (push form + registry filter); the filter is second.
    const filterType = () =>
      screen.getAllByLabelText(en["page.assets.field.assetType"])[1];
    await user.click(filterType());
    await user.click(
      await screen.findByRole("option", { name: en["page.assets.type.cliTool"] }),
    );
    await waitFor(() =>
      expect(screen.queryByText("widget")).not.toBeInTheDocument(),
    );

    // Reset filter, then search narrows by name.
    await user.click(filterType());
    await user.click(
      await screen.findByRole("option", {
        name: en["page.withheldAssets.filter.allTypes"],
      }),
    );
    await user.type(
      screen.getByLabelText(en["page.withheldAssets.filter.search"]),
      "widget",
    );
    await waitFor(() =>
      expect(screen.queryByText("ferrogate")).not.toBeInTheDocument(),
    );
    expect(screen.getByText("widget")).toBeInTheDocument();
  });

  it("renders the registry list in zh-CN", async () => {
    seedList();

    renderPage("zh-CN");

    expect(
      await screen.findByRole("heading", { name: zhCN["page.assets.title"] }),
    ).toBeInTheDocument();
    expect(
      (await screen.findAllByText(zhCN["page.assets.col.versions"])).length,
    ).toBeGreaterThan(0);
  });
});

describe("AssetsPage URL browse state", () => {
  it("hydrates the type filter and search from the query on load", async () => {
    seedList();

    renderPage("en", "/app/assets?type=mcp_manifest&q=widget");

    // Only the mcp_manifest resource matching the search survives; the cli_tool
    // package is filtered out purely from the URL, with no user interaction.
    expect(await screen.findByText("widget")).toBeInTheDocument();
    expect(screen.queryByText("ferrogate")).not.toBeInTheDocument();
  });

  it("opens the detail panel from ?rtype=&rname= even when a filter hides the row", async () => {
    seedList();
    server.use(
      http.get(gatewayUrl("/v1/assets/cli_tool/ferrogate/manifest"), () =>
        HttpResponse.json(ferrogateManifest),
      ),
    );

    // The list is filtered to mcp_manifest (hiding ferrogate), yet the shared
    // link still resolves ferrogate against the full registry and opens it.
    renderPage(
      "en",
      "/app/assets?type=mcp_manifest&rtype=cli_tool&rname=ferrogate",
    );

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("cli_tool/ferrogate")).toBeInTheDocument();
    // The manifest loads async; its channel pointer confirms the panel resolved
    // the resource from the URL rather than showing an empty shell.
    expect(await within(dialog).findByText("stable")).toBeInTheDocument();
    // The mcp_manifest filter is still in force behind the panel: the list
    // shows widget, and ferrogate has no row of its own.
    expect(screen.getByText("widget")).toBeInTheDocument();
    // ferrogate has no registry record of its own behind the panel; the only
    // occurrence of its name is inside the open dialog.
    expect(
      screen
        .queryAllByText("ferrogate", { exact: true })
        .filter((node) => node.closest("[role='dialog']") === null),
    ).toEqual([]);
  });

  it("writes type, search, and the open resource back into the URL", async () => {
    seedList();
    server.use(
      http.get(gatewayUrl("/v1/assets/cli_tool/ferrogate/manifest"), () =>
        HttpResponse.json(ferrogateManifest),
      ),
    );
    const user = userEvent.setup();
    renderPage("en");

    // A pristine registry keeps a clean URL (defaults encoded as absent params).
    await screen.findByText("ferrogate");
    expect(currentSearch).toBe("");

    // Search is mirrored into ?q=.
    await user.type(
      screen.getByLabelText(en["page.withheldAssets.filter.search"]),
      "ferro",
    );
    await waitFor(() =>
      expect(new URLSearchParams(currentSearch).get("q")).toBe("ferro"),
    );

    // Type filter is mirrored into ?type=.
    const filterType = () =>
      screen.getAllByLabelText(en["page.assets.field.assetType"])[1];
    await user.click(filterType());
    await user.click(
      await screen.findByRole("option", { name: en["page.assets.type.cliTool"] }),
    );
    await waitFor(() =>
      expect(new URLSearchParams(currentSearch).get("type")).toBe("cli_tool"),
    );

    // Opening a resource records rtype+rname; closing clears them.
    const ferrogateRow = await findRegistryRecord("ferrogate");
    await user.click(
      within(ferrogateRow).getByRole("button", {
        name: en["resource.table.moreDetails"],
      }),
    );
    await waitFor(() => {
      const params = new URLSearchParams(currentSearch);
      expect(params.get("rtype")).toBe("cli_tool");
      expect(params.get("rname")).toBe("ferrogate");
    });
    // Filter + search survive selection (still shareable together).
    expect(new URLSearchParams(currentSearch).get("q")).toBe("ferro");

    await screen.findByRole("dialog");
    // Escape closes the panel (the footer + built-in dismiss both read "Close");
    // dismissing it must strip rtype/rname while leaving the filter/search.
    await user.keyboard("{Escape}");
    await waitFor(() =>
      expect(new URLSearchParams(currentSearch).has("rtype")).toBe(false),
    );
    expect(new URLSearchParams(currentSearch).has("rname")).toBe(false);
  });
});

describe("AssetsPage detail + lifecycle", () => {
  async function openDetail(user: ReturnType<typeof userEvent.setup>) {
    const ferrogateRow = await findRegistryRecord("ferrogate");
    await user.click(
      within(ferrogateRow).getByRole("button", {
        name: en["resource.table.moreDetails"],
      }),
    );
    return screen.findByRole("dialog");
  }

  it("renders the manifest versions, variants, hashes, and channels", async () => {
    seedList();
    server.use(
      http.get(gatewayUrl("/v1/assets/cli_tool/ferrogate/manifest"), () =>
        HttpResponse.json(ferrogateManifest),
      ),
    );
    const user = userEvent.setup();
    renderPage("en");

    const dialog = await openDetail(user);

    // Channel pointer.
    expect(within(dialog).getByText("stable")).toBeInTheDocument();
    // Both versions, their variant + short hashes render.
    expect(within(dialog).getByText("linux-x64")).toBeInTheDocument();
    expect(within(dialog).getByText(`${"b".repeat(12)}…`)).toBeInTheDocument();
    expect(within(dialog).getByText(`${"c".repeat(12)}…`)).toBeInTheDocument();
    expect(
      within(dialog).getAllByText(en["page.assets.state.active"]).length,
    ).toBe(2);
  });

  it("yanks a version behind a destructive confirm and refreshes the manifest", async () => {
    seedList();
    let yankUrl: string | null = null;
    let manifestRequests = 0;
    server.use(
      http.get(gatewayUrl("/v1/assets/cli_tool/ferrogate/manifest"), () => {
        manifestRequests += 1;
        return HttpResponse.json(ferrogateManifest);
      }),
      http.post(
        gatewayUrl("/v1/assets/cli_tool/ferrogate/1.0.0/yank"),
        ({ request }) => {
          yankUrl = request.url;
          return HttpResponse.json({ object: "list", data: [] });
        },
      ),
    );
    const user = userEvent.setup();
    renderPage("en");

    const dialog = await openDetail(user);

    // The 1.0.0 row carries the Yank button (2.0.0 too); yank the first.
    const yankButtons = within(dialog).getAllByRole("button", {
      name: en["page.assets.action.yank"],
    });
    await user.click(yankButtons[yankButtons.length - 1]);

    // Consequence-aware confirm names the exact resource@version.
    const confirm = await screen.findByText(
      en["page.assets.yank.title"].replace(
        "{asset}",
        "cli_tool/ferrogate@1.0.0",
      ),
    );
    const confirmDialog = confirm.closest("[role='dialog']") as HTMLElement;
    await user.click(
      within(confirmDialog).getByRole("button", {
        name: en["page.assets.action.yank"],
      }),
    );

    await waitFor(() => expect(yankUrl).not.toBeNull());
    expect(yankUrl).toContain("/v1/assets/cli_tool/ferrogate/1.0.0/yank");
    // Manifest refetched after the mutation (initial + invalidation).
    await waitFor(() => expect(manifestRequests).toBeGreaterThanOrEqual(2));
  });

  it("creates/moves a channel pointer with the version query parameter", async () => {
    seedList();
    let channelUrl: string | null = null;
    server.use(
      http.get(gatewayUrl("/v1/assets/cli_tool/ferrogate/manifest"), () =>
        HttpResponse.json(ferrogateManifest),
      ),
      http.put(
        gatewayUrl("/v1/assets/cli_tool/ferrogate/channels/canary"),
        ({ request }) => {
          channelUrl = request.url;
          return HttpResponse.json({
            object: "asset_channel",
            asset_type: "cli_tool",
            name: "ferrogate",
            channel: { channel: "canary", version: "2.0.0", updated_at_unix: 3000 },
          });
        },
      ),
    );
    const user = userEvent.setup();
    renderPage("en");

    const dialog = await openDetail(user);

    await user.click(
      within(dialog).getByRole("button", {
        name: en["page.assets.action.setChannel"],
      }),
    );

    const formDialog = (
      await screen.findByText(en["page.assets.channel.title"])
    ).closest("[role='dialog']") as HTMLElement;
    await user.type(
      within(formDialog).getByLabelText(en["page.assets.col.channel"]),
      "canary",
    );
    // Pick a non-yanked target version.
    await user.click(within(formDialog).getByRole("combobox"));
    await user.click(await screen.findByRole("option", { name: "2.0.0" }));
    await user.click(
      within(formDialog).getByRole("button", {
        name: en["page.assets.action.setChannel"],
      }),
    );

    await waitFor(() => expect(channelUrl).not.toBeNull());
    expect(channelUrl).toContain("/channels/canary");
    expect(channelUrl).toContain("version=2.0.0");
  });
});

describe("AssetsPage presigned large-object upload", () => {
  const UPLOAD_ID = `upl_${"0".repeat(32)}`;
  const UPLOAD_URL = "https://bucket.example.test/staging/object-1";

  async function fillPresignDialog(user: ReturnType<typeof userEvent.setup>) {
    await user.click(
      await screen.findByRole("button", {
        name: en["page.assets.presign.submit"],
      }),
    );
    const dialog = await screen.findByRole("dialog");
    await user.type(
      within(dialog).getByLabelText(en["page.assets.field.name"]),
      "big-tool",
    );
    await user.type(
      within(dialog).getByLabelText(en["page.assets.field.version"]),
      "9.0.0",
    );
    const file = new File(["a very large bundle payload"], "big.tar.gz", {
      type: "application/gzip",
    });
    await user.upload(
      within(dialog).getByLabelText(en["page.assets.field.file"]),
      file,
    );
    await user.click(
      within(dialog).getByRole("button", {
        name: en["page.assets.presign.submit"],
      }),
    );
    return { dialog, file };
  }

  it("runs register-intent -> direct PUT -> commit in order with verified metadata", async () => {
    seedList();
    const calls: string[] = [];
    let commitBody: AdminSchema<"AssetPresignCommitRequest"> | null = null;
    let putSha256Header: string | null = null;
    let declaredSha256: string | null = null;
    server.use(
      http.post(
        gatewayUrl("/v1/assets/presign/upload/cli_tool/big-tool/9.0.0"),
        async ({ request }) => {
          calls.push("intent");
          const body = (await request.json()) as {
            size_bytes: number;
            sha256: string;
          };
          declaredSha256 = body.sha256;
          return HttpResponse.json({
            object: "asset_upload_intent",
            key: "tenant-1/cli_tool/big-tool/9.0.0",
            upload_id: UPLOAD_ID,
            upload_url: UPLOAD_URL,
            method: "PUT",
            expires_in_seconds: 900,
            size_bytes: body.size_bytes,
            sha256: body.sha256,
            // #368: SigV4 SignedHeaders of upload_url. A real bucket 403s a PUT
            // that omits x-amz-content-sha256, so the console must forward it.
            required_headers: {
              "content-length": String(body.size_bytes),
              "x-amz-content-sha256": body.sha256,
            },
            max_object_bytes: 5 * 1024 * 1024 * 1024,
            upload_protocol: "single_put",
          });
        },
      ),
      http.put(UPLOAD_URL, ({ request }) => {
        // The bytes must go DIRECTLY to storage, only after the intent.
        calls.push("put");
        putSha256Header = request.headers.get("x-amz-content-sha256");
        return new HttpResponse(null, { status: 200 });
      }),
      http.post(
        gatewayUrl("/v1/assets/presign/commit/cli_tool/big-tool/9.0.0"),
        async ({ request }) => {
          calls.push("commit");
          commitBody = (await request.json()) as AdminSchema<"AssetPresignCommitRequest">;
          return HttpResponse.json({
            object: "asset",
            asset: asset({ name: "big-tool", version: "9.0.0", storage_backed: true }),
          });
        },
      ),
    );
    const user = userEvent.setup();
    renderPage("en");

    const { file } = await fillPresignDialog(user);

    await waitFor(() =>
      expect(calls).toEqual(["intent", "put", "commit"]),
    );
    expect(commitBody).not.toBeNull();
    // The commit re-declares the same identity the intent registered so the
    // gateway can verify size + SHA-256 over the staged bytes.
    expect(commitBody!.upload_id).toMatch(/^upl_[0-9a-f]{32}$/);
    expect(commitBody!.size_bytes).toBe(file.size);
    expect(commitBody!.sha256).toMatch(/^[a-f0-9]{64}$/);
    // #368: the direct PUT carries the intent's signed payload-hash header
    // verbatim. Drop it and a real bucket returns 403 -- before this assertion
    // the console sent only Content-Type and nothing in the repo noticed.
    expect(putSha256Header).toBe(declaredSha256);
  });

  it("refuses to PUT bytes whose length differs from the signed content-length", async () => {
    seedList();
    let putCalls = 0;
    server.use(
      http.post(
        gatewayUrl("/v1/assets/presign/upload/cli_tool/big-tool/9.0.0"),
        async ({ request }) => {
          const body = (await request.json()) as {
            size_bytes: number;
            sha256: string;
          };
          return HttpResponse.json({
            object: "asset_upload_intent",
            key: "k",
            upload_id: UPLOAD_ID,
            upload_url: UPLOAD_URL,
            method: "PUT",
            expires_in_seconds: 900,
            size_bytes: body.size_bytes,
            sha256: body.sha256,
            // A gateway that signed a DIFFERENT length than the bytes on hand.
            // The browser cannot override content-length, so the PUT would be
            // signed for one length and sent with another: a guaranteed 403.
            // Fail locally with a legible message instead of burning the
            // round-trip and leaving an unusable intent behind.
            required_headers: {
              "content-length": String(body.size_bytes + 1),
              "x-amz-content-sha256": body.sha256,
            },
            max_object_bytes: 5 * 1024 * 1024 * 1024,
            upload_protocol: "single_put",
          });
        },
      ),
      http.put(UPLOAD_URL, () => {
        putCalls += 1;
        return new HttpResponse(null, { status: 200 });
      }),
    );
    const user = userEvent.setup();
    renderPage("en");

    await fillPresignDialog(user);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/signed for \d+ bytes/);
    expect(putCalls).toBe(0);
  });

  it("aborts an intent it will not commit instead of leaking staging capacity", async () => {
    // #368: the migration doc tells integrators to release an intent they will
    // not commit; the first-party console has to follow the contract it
    // publishes, or every failed upload holds bucket bytes until the lifecycle
    // GC's next sweep. Driven through the length-mismatch failure because it
    // reaches the error path without a direct PUT.
    seedList();
    let declaredSha256: string | null = null;
    let intentSize: number | null = null;
    let abortBody: AdminSchema<"AssetPresignAbortRequest"> | null = null;
    server.use(
      http.post(
        gatewayUrl("/v1/assets/presign/upload/cli_tool/big-tool/9.0.0"),
        async ({ request }) => {
          const body = (await request.json()) as {
            size_bytes: number;
            sha256: string;
          };
          declaredSha256 = body.sha256;
          intentSize = body.size_bytes;
          return HttpResponse.json({
            object: "asset_upload_intent",
            key: "k",
            upload_id: UPLOAD_ID,
            upload_url: UPLOAD_URL,
            method: "PUT",
            expires_in_seconds: 900,
            size_bytes: body.size_bytes,
            sha256: body.sha256,
            required_headers: {
              "content-length": String(body.size_bytes + 1),
              "x-amz-content-sha256": body.sha256,
            },
            max_object_bytes: 5 * 1024 * 1024 * 1024,
            upload_protocol: "single_put",
          });
        },
      ),
      http.post(
        gatewayUrl("/v1/assets/presign/abort/cli_tool/big-tool/9.0.0"),
        async ({ request }) => {
          abortBody = (await request.json()) as AdminSchema<"AssetPresignAbortRequest">;
          return HttpResponse.json({
            object: "asset_upload_abort",
            upload_id: UPLOAD_ID,
            staging_object_removed: false,
            staging_reclamation: "not_staged",
            outcome: "aborted",
          });
        },
      ),
    );
    const user = userEvent.setup();
    renderPage("en");

    await fillPresignDialog(user);

    // The operator still reads the real failure verbatim; the abort is
    // cleanup, not a verdict.
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/signed for \d+ bytes/);

    await waitFor(() => expect(abortBody).not.toBeNull());
    // The staging key is server-derived from all three declarations, so an
    // abort that names them wrongly would release nothing.
    expect(abortBody!.upload_id).toBe(UPLOAD_ID);
    expect(abortBody!.size_bytes).toBe(intentSize);
    expect(abortBody!.sha256).toBe(declaredSha256);
    // The PUT never left the browser, so claiming the bucket refused it would
    // fabricate a "corroborated" bucket rejection in the gateway's audit trail
    // and counter — a class any caller can otherwise mint at will.
    expect(abortBody!.reason).toBe("abandoned");
  });

  it("surfaces a gateway commit error verbatim in an alert", async () => {
    seedList();
    const verbatim =
      "sha256 mismatch: declared aaa… but staged bytes hash to bbb…";
    server.use(
      http.post(
        gatewayUrl("/v1/assets/presign/upload/cli_tool/big-tool/9.0.0"),
        async ({ request }) => {
          const body = (await request.json()) as {
            size_bytes: number;
            sha256: string;
          };
          return HttpResponse.json({
            object: "asset_upload_intent",
            key: "k",
            upload_id: UPLOAD_ID,
            upload_url: UPLOAD_URL,
            method: "PUT",
            expires_in_seconds: 900,
            size_bytes: body.size_bytes,
            sha256: body.sha256,
          });
        },
      ),
      http.put(UPLOAD_URL, () => new HttpResponse(null, { status: 200 })),
      http.post(
        gatewayUrl("/v1/assets/presign/commit/cli_tool/big-tool/9.0.0"),
        () =>
          HttpResponse.json(
            { error: { code: "asset_size_mismatch", message: verbatim } },
            { status: 422 },
          ),
      ),
    );
    const user = userEvent.setup();
    renderPage("en");

    await fillPresignDialog(user);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(verbatim);
  });
});

describe("AssetsPage permanent version deletion", () => {
  async function openDetail(
    user: ReturnType<typeof userEvent.setup>,
    moreDetailsLabel: string = en["resource.table.moreDetails"],
  ) {
    const ferrogateRow = await findRegistryRecord("ferrogate");
    await user.click(
      within(ferrogateRow).getByRole("button", { name: moreDetailsLabel }),
    );
    return screen.findByRole("dialog");
  }

  it("requires the exact typed name@version before enabling delete, then calls DELETE", async () => {
    seedList();
    let deleteUrl: string | null = null;
    server.use(
      http.get(gatewayUrl("/v1/assets/cli_tool/ferrogate/manifest"), () =>
        HttpResponse.json(ferrogateManifest),
      ),
      http.delete(
        gatewayUrl("/v1/assets/cli_tool/ferrogate/1.0.0"),
        ({ request }) => {
          deleteUrl = request.url;
          return HttpResponse.json({
            object: "asset",
            id: "org-acme:cli_tool:ferrogate:1.0.0",
            deleted: true,
          });
        },
      ),
    );
    const user = userEvent.setup();
    renderPage("en");

    const dialog = await openDetail(user);
    // Two versions render a permanent-delete button; the last is 1.0.0.
    const deleteButtons = within(dialog).getAllByRole("button", {
      name: en["page.assets.delete.action"],
    });
    await user.click(deleteButtons[deleteButtons.length - 1]);

    const confirmDialog = (
      await screen.findByText(
        en["page.assets.delete.title"].replace("{asset}", "ferrogate@1.0.0"),
      )
    ).closest("[role='dialog']") as HTMLElement;
    const confirmButton = within(confirmDialog).getByRole("button", {
      name: en["page.assets.delete.action"],
    });
    // Disarmed until the exact identifier is retyped.
    expect(confirmButton).toBeDisabled();

    const input = within(confirmDialog).getByLabelText(
      en["page.assets.delete.confirmLabel"].replace("{asset}", "ferrogate@1.0.0"),
    );
    await user.type(input, "ferrogate@9.9.9");
    expect(confirmButton).toBeDisabled();

    await user.clear(input);
    await user.type(input, "ferrogate@1.0.0");
    expect(confirmButton).toBeEnabled();

    await user.click(confirmButton);
    await waitFor(() => expect(deleteUrl).not.toBeNull());
    expect(deleteUrl).toContain("/v1/assets/cli_tool/ferrogate/1.0.0");
    // The gateway's DELETE removes ONE variant row and defaults to the "" one
    // (`deleteAsset`'s `platform` query). ferrogate@1.0.0 has a single
    // linux-x64 variant, so an unqualified DELETE addresses a row that does not
    // exist and 404s: the purge must name the variant it is removing.
    expect(new URL(deleteUrl!).searchParams.get("platform")).toBe("linux-x64");
  });

  it("renders the large-object upload and permanent-delete affordances in zh-CN", async () => {
    seedList();
    server.use(
      http.get(gatewayUrl("/v1/assets/cli_tool/ferrogate/manifest"), () =>
        HttpResponse.json(ferrogateManifest),
      ),
    );
    const user = userEvent.setup();
    renderPage("zh-CN");

    expect(
      await screen.findByText(zhCN["page.assets.presign.title"]),
    ).toBeInTheDocument();

    const dialog = await openDetail(user, zhCN["resource.table.moreDetails"]);
    expect(
      within(dialog).getAllByRole("button", {
        name: zhCN["page.assets.delete.action"],
      }).length,
    ).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// #344 code-review bounce (2026-07-25): the boxes below were UNMET or unproven.
// Each test names the behaviour it locks and the failure it would let through.
// ---------------------------------------------------------------------------

/** A version carrying two variant rows, for the per-variant purge/download paths. */
const multiVariantManifest: AssetManifest = {
  object: "asset_manifest",
  asset_type: "cli_tool",
  name: "ferrogate",
  // No channel points at 3.0.0, so the purge is not blocked for the wrong reason.
  channels: [{ channel: "stable", version: "2.0.0", updated_at_unix: 1500 }],
  versions: [
    {
      version: "3.0.0",
      yanked: false,
      variants: [
        {
          variant: "",
          content_type: "application/gzip",
          content_hash: "d".repeat(64),
          size_bytes: 300,
          storage_backed: true,
        },
        {
          variant: "linux-arm64",
          content_type: "application/gzip",
          content_hash: "e".repeat(64),
          size_bytes: 310,
          storage_backed: true,
        },
      ],
    },
    ...ferrogateManifest.versions,
  ],
};

const yankedManifest: AssetManifest = {
  ...ferrogateManifest,
  channels: [],
  versions: [
    { ...ferrogateManifest.versions[0], yanked: true },
    ferrogateManifest.versions[1],
  ],
};

function seedManifest(manifest: AssetManifest) {
  server.use(
    http.get(gatewayUrl("/v1/assets/cli_tool/ferrogate/manifest"), () =>
      HttpResponse.json(manifest),
    ),
  );
}

async function openFerrogateDetail(user: ReturnType<typeof userEvent.setup>) {
  const record = await findRegistryRecord("ferrogate");
  await user.click(
    within(record).getByRole("button", {
      name: en["resource.table.moreDetails"],
    }),
  );
  return screen.findByRole("dialog");
}

/** The dialog containing `text`, for assertions that must not stray into another. */
function dialogWith(text: string): HTMLElement {
  return screen.getByText(text).closest("[role='dialog']") as HTMLElement;
}

function renderKey(key: keyof typeof en, values: Record<string, string>): string {
  let out: string = en[key];
  for (const [name, value] of Object.entries(values)) {
    out = out.replace(`{${name}}`, value);
  }
  return out;
}

/** jsdom-safe object-URL + anchor-click doubles for a download assertion. */
function stubDownloadPlumbing() {
  const urlWithBlob = URL as unknown as {
    createObjectURL?: (obj: Blob) => string;
    revokeObjectURL?: (url: string) => void;
  };
  const originalCreate = urlWithBlob.createObjectURL;
  const originalRevoke = urlWithBlob.revokeObjectURL;
  urlWithBlob.createObjectURL = vi.fn(() => "blob:mock-url");
  urlWithBlob.revokeObjectURL = vi.fn();
  const saved: string[] = [];
  const clickSpy = vi
    .spyOn(HTMLAnchorElement.prototype, "click")
    .mockImplementation(function mockClick(this: HTMLAnchorElement) {
      saved.push(this.download);
    });
  return {
    saved,
    restore() {
      clickSpy.mockRestore();
      urlWithBlob.createObjectURL = originalCreate;
      urlWithBlob.revokeObjectURL = originalRevoke;
    },
  };
}

describe("AssetsPage lifecycle mutations without prior coverage", () => {
  // Box 4 of the acceptance list: `unyank` and `channel delete` shipped with
  // ZERO coverage in either suite. Both are one-line-deletable without any
  // other test noticing.
  it("unyanks a yanked version with DELETE .../yank behind the consequence confirm", async () => {
    seedList();
    seedManifest(yankedManifest);
    let unyankMethod: string | null = null;
    let unyankUrl: string | null = null;
    server.use(
      http.delete(
        gatewayUrl("/v1/assets/cli_tool/ferrogate/2.0.0/yank"),
        ({ request }) => {
          unyankMethod = request.method;
          unyankUrl = request.url;
          return HttpResponse.json({ object: "list", data: [] });
        },
      ),
    );
    const user = userEvent.setup();
    renderPage("en");

    const dialog = await openFerrogateDetail(user);
    await user.click(
      within(dialog).getByRole("button", { name: en["page.assets.action.unyank"] }),
    );

    // Unyank is confirmed too, and its confirm names the exact resource.
    const confirm = dialogWith(
      renderKey("page.assets.unyank.title", { asset: "cli_tool/ferrogate@2.0.0" }),
    );
    await user.click(
      within(confirm).getByRole("button", { name: en["page.assets.action.unyank"] }),
    );

    await waitFor(() => expect(unyankUrl).not.toBeNull());
    // The verb is the whole contract here: POST yanks, DELETE unyanks, on the
    // SAME path. A copy-paste that kept POST would still "succeed".
    expect(unyankMethod).toBe("DELETE");
    expect(unyankUrl).toContain("/v1/assets/cli_tool/ferrogate/2.0.0/yank");
  });

  it("deletes a channel pointer with DELETE .../channels/{channel} behind a confirm", async () => {
    seedList();
    seedManifest(ferrogateManifest);
    let channelMethod: string | null = null;
    let channelUrl: string | null = null;
    server.use(
      http.delete(
        gatewayUrl("/v1/assets/cli_tool/ferrogate/channels/stable"),
        ({ request }) => {
          channelMethod = request.method;
          channelUrl = request.url;
          return HttpResponse.json({ object: "asset_channel", id: "stable", deleted: true });
        },
      ),
    );
    const user = userEvent.setup();
    renderPage("en");

    const dialog = await openFerrogateDetail(user);
    const channelRow = within(dialog).getByText("stable").closest("tr") as HTMLElement;
    await user.click(
      within(channelRow).getByRole("button", { name: en["resource.action.delete"] }),
    );

    const confirm = dialogWith(
      renderKey("page.assets.channel.deleteTitle", { channel: "stable" }),
    );
    await user.click(
      within(confirm).getByRole("button", { name: en["resource.action.delete"] }),
    );

    await waitFor(() => expect(channelUrl).not.toBeNull());
    expect(channelMethod).toBe("DELETE");
    expect(channelUrl).toContain("/v1/assets/cli_tool/ferrogate/channels/stable");
    // Only the pointer goes; nothing addresses the version itself.
    expect(channelUrl).not.toContain("/2.0.0");
  });
});

describe("AssetsPage permanent delete reports blockers and failures", () => {
  // Box 5: "Permanent delete is ... confirmed, and reports blockers/failure."
  it("names the channels that will block the purge BEFORE it fires", async () => {
    seedList();
    seedManifest(ferrogateManifest); // stable -> 2.0.0
    const user = userEvent.setup();
    renderPage("en");

    const dialog = await openFerrogateDetail(user);
    // 2.0.0 is the first version row; `stable` still points at it.
    const deleteButtons = within(dialog).getAllByRole("button", {
      name: en["page.assets.delete.action"],
    });
    await user.click(deleteButtons[0]);

    const confirm = dialogWith(
      renderKey("page.assets.delete.title", { asset: "ferrogate@2.0.0" }),
    );
    const blocker = await within(confirm).findByRole("alert");
    // The blocker is stated, with the channel named and the gateway's own error
    // code, so the operator knows the remedy before burning a destructive call.
    expect(blocker).toHaveTextContent("stable");
    expect(blocker).toHaveTextContent("asset_version_referenced");
  });

  it("does not warn about a blocker no channel actually creates", async () => {
    seedList();
    seedManifest(ferrogateManifest); // stable -> 2.0.0, nothing -> 1.0.0
    const user = userEvent.setup();
    renderPage("en");

    const dialog = await openFerrogateDetail(user);
    const deleteButtons = within(dialog).getAllByRole("button", {
      name: en["page.assets.delete.action"],
    });
    await user.click(deleteButtons[deleteButtons.length - 1]); // 1.0.0

    const confirm = dialogWith(
      renderKey("page.assets.delete.title", { asset: "ferrogate@1.0.0" }),
    );
    // An unconditional warning would be noise that teaches operators to ignore
    // the real one, so the absence is part of the contract.
    expect(within(confirm).queryByRole("alert")).not.toBeInTheDocument();
  });

  it("keeps a 409 asset_version_referenced verdict in the dialog instead of a vanishing toast", async () => {
    seedList();
    seedManifest(ferrogateManifest);
    server.use(
      http.delete(gatewayUrl("/v1/assets/cli_tool/ferrogate/2.0.0"), () =>
        HttpResponse.json(
          {
            error: {
              code: "asset_version_referenced",
              message:
                "cli_tool/ferrogate/2.0.0 is the last resolvable variant of a channel-referenced version; move or delete the channel first",
            },
          },
          { status: 409 },
        ),
      ),
    );
    const user = userEvent.setup();
    renderPage("en");

    const dialog = await openFerrogateDetail(user);
    await user.click(
      within(dialog).getAllByRole("button", {
        name: en["page.assets.delete.action"],
      })[0],
    );
    const confirm = dialogWith(
      renderKey("page.assets.delete.title", { asset: "ferrogate@2.0.0" }),
    );
    await user.type(
      within(confirm).getByLabelText(
        renderKey("page.assets.delete.confirmLabel", { asset: "ferrogate@2.0.0" }),
      ),
      "ferrogate@2.0.0",
    );
    await user.click(
      within(confirm).getByRole("button", { name: en["page.assets.delete.action"] }),
    );

    // The verdict is on screen, VERBATIM, with its machine-readable code, and
    // the dialog is still open holding it.
    await waitFor(() =>
      expect(
        within(confirm)
          .getAllByRole("alert")
          .some((alert) =>
            alert.textContent?.includes("move or delete the channel first"),
          ),
      ).toBe(true),
    );
    expect(within(confirm).getByRole("button", { name: en["common.cancel"] })).toBeVisible();
  });

  it("purges every variant row, non-default first, and reports a partial purge as partial", async () => {
    seedList();
    seedManifest(multiVariantManifest);
    const platforms: (string | null)[] = [];
    server.use(
      http.delete(gatewayUrl("/v1/assets/cli_tool/ferrogate/3.0.0"), ({ request }) => {
        const platform = new URL(request.url).searchParams.get("platform");
        platforms.push(platform);
        // The gateway blocks the LAST resolvable variant of a referenced
        // version (#367); model that on the default-variant call.
        if (platform === null) {
          return HttpResponse.json(
            {
              error: {
                code: "asset_version_referenced",
                message: "still referenced by a channel",
              },
            },
            { status: 409 },
          );
        }
        return HttpResponse.json({ object: "asset", id: "x", deleted: true });
      }),
    );
    const user = userEvent.setup();
    renderPage("en");

    const dialog = await openFerrogateDetail(user);
    await user.click(
      within(dialog).getAllByRole("button", {
        name: en["page.assets.delete.action"],
      })[0],
    );
    const confirm = dialogWith(
      renderKey("page.assets.delete.title", { asset: "ferrogate@3.0.0" }),
    );
    await user.type(
      within(confirm).getByLabelText(
        renderKey("page.assets.delete.confirmLabel", { asset: "ferrogate@3.0.0" }),
      ),
      "ferrogate@3.0.0",
    );
    await user.click(
      within(confirm).getByRole("button", { name: en["page.assets.delete.action"] }),
    );

    // One DELETE per variant row, platform-specific ones first.
    await waitFor(() => expect(platforms).toEqual(["linux-arm64", null]));
    // A half-applied purge is reported AS half-applied: claiming plain failure
    // after a row is already gone would misstate the registry's state.
    await waitFor(() =>
      expect(
        within(confirm)
          .getAllByRole("alert")
          .some((alert) => /1 of 2 variant rows/.test(alert.textContent ?? "")),
      ).toBe(true),
    );
  });
});

describe("AssetsPage presigned upload cancellation", () => {
  const UPLOAD_ID = `upl_${"1".repeat(32)}`;

  it("cancels an in-flight upload and reports it as cancelled, never as published", async () => {
    seedList();
    let intentAborted = false;
    let commitCalls = 0;
    server.use(
      // Hold the intent open so Cancel lands mid-flight. `request.signal`
      // firing is the proof the console threaded an AbortSignal at all: before
      // this, Cancel was a disabled button and the request ran to completion.
      http.post(
        gatewayUrl("/v1/assets/presign/upload/cli_tool/big-tool/9.0.0"),
        ({ request }) =>
          new Promise<Response>((_resolve, reject) => {
            request.signal.addEventListener("abort", () => {
              intentAborted = true;
              reject(new Error("aborted"));
            });
          }),
      ),
      http.post(
        gatewayUrl("/v1/assets/presign/commit/cli_tool/big-tool/9.0.0"),
        () => {
          commitCalls += 1;
          return HttpResponse.json({ object: "asset", asset: asset() });
        },
      ),
    );
    const user = userEvent.setup();
    renderPage("en");

    await user.click(
      await screen.findByRole("button", { name: en["page.assets.presign.submit"] }),
    );
    const dialog = await screen.findByRole("dialog");
    await user.type(
      within(dialog).getByLabelText(en["page.assets.field.name"]),
      "big-tool",
    );
    await user.type(
      within(dialog).getByLabelText(en["page.assets.field.version"]),
      "9.0.0",
    );
    await user.upload(
      within(dialog).getByLabelText(en["page.assets.field.file"]),
      new File(["a very large bundle payload"], "big.tar.gz", {
        type: "application/gzip",
      }),
    );
    await user.click(
      within(dialog).getByRole("button", { name: en["page.assets.presign.submit"] }),
    );

    // Mid-flight the footer offers a REAL cancel, not a disabled placeholder.
    const cancel = await within(dialog).findByRole("button", {
      name: en["page.assets.presign.cancelUpload"],
    });
    expect(cancel).toBeEnabled();
    await user.click(cancel);

    await waitFor(() => expect(intentAborted).toBe(true));
    // The outcome reads as a cancellation and explicitly denies a publish...
    const alert = await within(dialog).findByRole("alert");
    expect(alert).toHaveTextContent(en["page.assets.presign.cancelledNoIntent"]);
    // ...the success copy never appears, and nothing was committed.
    expect(
      screen.queryByText(en["page.assets.presign.success"]),
    ).not.toBeInTheDocument();
    expect(commitCalls).toBe(0);
    void UPLOAD_ID;
  });
});

describe("AssetsPage inline vs presigned upload selection", () => {
  it("refuses an inline push over inline_upload_max_bytes and points at the large-object path", async () => {
    // The authoritative ceiling comes from the storage summary (#338); before
    // this, `inline_upload_max_bytes` was read NOWHERE in src/ and the operator
    // had to guess which of the two unlinked forms to use.
    seedList();
    server.use(
      http.get(gatewayUrl("/v1/assets/storage/summary"), () =>
        HttpResponse.json(storageSummary({ inline_upload_max_bytes: 8 })),
      ),
    );
    let pushCalls = 0;
    server.use(
      http.put(gatewayUrl("/v1/assets/cli_tool/big/1.0.0"), () => {
        pushCalls += 1;
        return HttpResponse.json({ object: "asset" });
      }),
    );
    const user = userEvent.setup();
    renderPage("en");

    // The limit is stated up front, from the summary.
    expect(
      await screen.findByText(
        renderKey("page.assets.push.inlineLimit", { max: "8 B" }),
      ),
    ).toBeInTheDocument();

    await user.type(screen.getByLabelText(en["page.assets.field.name"]), "big");
    await user.type(screen.getByLabelText(en["page.assets.field.version"]), "1.0.0");
    await user.upload(
      screen.getByLabelText(en["page.assets.field.file"]),
      new File(["0123456789abcdef"], "big.bin", { type: "application/octet-stream" }),
    );

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/over the 8 B inline push limit/);
    expect(
      screen.getByRole("button", { name: en["page.assets.push.submit"] }),
    ).toBeDisabled();
    expect(pushCalls).toBe(0);
  });
});

describe("AssetsPage typed download, references, and version URL state", () => {
  it("downloads a named variant with its platform selector and a typed filename", async () => {
    seedList();
    seedManifest(multiVariantManifest);
    let downloadUrl: string | null = null;
    server.use(
      http.get(gatewayUrl("/v1/assets/cli_tool/ferrogate/3.0.0"), ({ request }) => {
        downloadUrl = request.url;
        return new HttpResponse("bytes", {
          headers: { "Content-Type": "application/gzip" },
        });
      }),
    );
    const plumbing = stubDownloadPlumbing();
    try {
      const user = userEvent.setup();
      renderPage("en");

      const dialog = await openFerrogateDetail(user);
      const arm64Row = within(dialog)
        .getByText("linux-arm64")
        .closest("tr") as HTMLElement;
      // A per-variant Download button: with one button per VERSION, the
      // linux-arm64 artifact was unreachable from this page entirely.
      await user.click(
        within(arm64Row).getByRole("button", {
          name: en["page.assets.action.download"],
        }),
      );

      await waitFor(() => expect(downloadUrl).not.toBeNull());
      expect(new URL(downloadUrl!).searchParams.get("platform")).toBe("linux-arm64");
      // "Typed download": the saved name carries the variant and an extension
      // derived from the manifest's own content type, not a bare `name-version`.
      await waitFor(() =>
        expect(plumbing.saved).toEqual(["ferrogate-3.0.0-linux-arm64.tar.gz"]),
      );
    } finally {
      plumbing.restore();
    }
  });

  it("offers a copyable ferrogate assets pull reference for a variant and a channel", async () => {
    seedList();
    seedManifest(multiVariantManifest);
    const copied: string[] = [];
    const user = userEvent.setup();
    // AFTER userEvent.setup(), which installs its own clipboard double.
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: async (text: string) => void copied.push(text) },
    });
    renderPage("en");

    const dialog = await openFerrogateDetail(user);
    const arm64Row = within(dialog)
      .getByText("linux-arm64")
      .closest("tr") as HTMLElement;
    await user.click(
      within(arm64Row).getByRole("button", {
        name: renderKey("common.copyLabel", {
          label: renderKey("page.assets.reference.pullLabel", {
            asset: "cli_tool/ferrogate@3.0.0",
          }),
        }),
      }),
    );

    // Mirrors the real CLI surface (AssetsIdentityArgs): --type/--name/--version
    // plus the --platform variant selector.
    await waitFor(() =>
      expect(copied).toEqual([
        "ferrogate assets pull --type cli_tool --name ferrogate --version 3.0.0 --platform linux-arm64",
      ]),
    );

    // The channel row's reference resolves through the channel, which the CLI's
    // --version accepts verbatim (exact version | channel | semver range).
    const stableRow = within(dialog).getByText("stable").closest("tr") as HTMLElement;
    await user.click(
      within(stableRow).getByRole("button", {
        name: renderKey("common.copyLabel", {
          label: renderKey("page.assets.reference.pullLabel", {
            asset: "cli_tool/ferrogate@stable",
          }),
        }),
      }),
    );
    await waitFor(() =>
      expect(copied[1]).toBe(
        "ferrogate assets pull --type cli_tool --name ferrogate --version stable",
      ),
    );
  });

  it("preserves the focused version in the URL and hydrates it from a shared link", async () => {
    seedList();
    seedManifest(ferrogateManifest);
    const user = userEvent.setup();

    // Hydrate: a link naming a version opens the panel with that row focused.
    renderPage("en", "/app/assets?rtype=cli_tool&rname=ferrogate&rver=1.0.0");
    const dialog = await screen.findByRole("dialog");
    await within(dialog).findByText("linux-x64");
    const focused = within(dialog)
      .getAllByRole("row")
      .filter((row) => row.getAttribute("aria-current") === "true");
    expect(focused).toHaveLength(1);
    expect(focused[0]).toHaveTextContent("1.0.0");

    // Write-back: focusing another version moves ?rver=.
    await user.click(
      within(dialog).getByRole("button", {
        name: renderKey("page.assets.action.focusVersion", { version: "2.0.0" }),
      }),
    );
    await waitFor(() =>
      expect(new URLSearchParams(currentSearch).get("rver")).toBe("2.0.0"),
    );
    // Clearing it prunes the param rather than leaving an empty one behind.
    await user.click(
      within(dialog).getByRole("button", {
        name: en["page.assets.action.clearVersion"],
      }),
    );
    await waitFor(() =>
      expect(new URLSearchParams(currentSearch).has("rver")).toBe(false),
    );
  });
});

describe("AssetsPage localized types and quota pressure", () => {
  it("localizes the asset type column and falls back to the raw identifier", async () => {
    server.use(
      http.get(gatewayUrl("/v1/assets"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            asset(),
            asset({
              id: "org-acme:custom_family:oddball:1.0.0",
              asset_type: "custom_family",
              name: "oddball",
            }),
          ],
        }),
      ),
      http.get(gatewayUrl("/v1/assets/storage/summary"), () =>
        HttpResponse.json(storageSummary()),
      ),
    );

    renderPage("zh-CN");

    // A known type renders its catalog label, not the raw `cli_tool` the filter
    // directly above it already localizes.
    const known = await findRegistryRecord("ferrogate");
    expect(within(known).getByText(zhCN["page.assets.type.cliTool"])).toBeInTheDocument();
    expect(within(known).queryByText("cli_tool")).not.toBeInTheDocument();
    // An asset_type the console has no catalog entry for renders VERBATIM;
    // inventing a label would name a family the API never used.
    const unknown = registryRecord("oddball");
    expect(within(unknown).getByText("custom_family")).toBeInTheDocument();
  });

  it("renders authoritative remaining bytes and raises quota pressure near the ceiling", async () => {
    server.use(
      http.get(gatewayUrl("/v1/assets"), () =>
        HttpResponse.json({ object: "list", data: [asset()] }),
      ),
      http.get(gatewayUrl("/v1/assets/storage/summary"), () =>
        HttpResponse.json(
          storageSummary({
            used_bytes: 9_500,
            quota_bytes: 10_000,
            remaining_bytes: 500,
          }),
        ),
      ),
    );

    renderPage("en");

    // remaining_bytes is the gateway's own saturating headroom, not a
    // subtraction this page performs.
    expect(
      await screen.findByText(/500 B remaining/),
    ).toBeInTheDocument();
    const meter = screen.getByRole("progressbar", {
      name: en["page.assets.storage.title"],
    });
    expect(meter).toHaveAttribute("aria-valuenow", "95");
    expect(await screen.findByRole("alert")).toHaveTextContent(/Quota pressure/);
  });

  it("renders no meter and no fabricated headroom when storage is unlimited", async () => {
    server.use(
      http.get(gatewayUrl("/v1/assets"), () =>
        HttpResponse.json({ object: "list", data: [asset()] }),
      ),
      http.get(gatewayUrl("/v1/assets/storage/summary"), () =>
        HttpResponse.json(
          storageSummary({ quota_bytes: null, remaining_bytes: null }),
        ),
      ),
    );

    renderPage("en");

    await screen.findByText(/no quota configured/);
    // No denominator means no percentage: a 0%-used meter would be a
    // fabricated fact about an unlimited tenant.
    expect(
      screen.queryByRole("progressbar", { name: en["page.assets.storage.title"] }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/remaining/)).not.toBeInTheDocument();
  });
});
