import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClientProvider } from "@tanstack/react-query";
import { HttpResponse, http } from "msw";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
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

function renderPage(locale: Locale = "en") {
  return render(
    <MemoryRouter>
      <I18nProvider initialLocale={locale}>
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
    const ferrogateRow = (await screen.findByText("ferrogate")).closest("tr")!;
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
      screen.getAllByText(zhCN["page.assets.col.versions"]).length,
    ).toBeGreaterThan(0);
  });
});

describe("AssetsPage detail + lifecycle", () => {
  async function openDetail(user: ReturnType<typeof userEvent.setup>) {
    const ferrogateRow = (await screen.findByText("ferrogate")).closest("tr")!;
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
    server.use(
      http.post(
        gatewayUrl("/v1/assets/presign/upload/cli_tool/big-tool/9.0.0"),
        async ({ request }) => {
          calls.push("intent");
          const body = (await request.json()) as {
            size_bytes: number;
            sha256: string;
          };
          return HttpResponse.json({
            object: "asset_upload_intent",
            key: "tenant-1/cli_tool/big-tool/9.0.0",
            upload_id: UPLOAD_ID,
            upload_url: UPLOAD_URL,
            method: "PUT",
            expires_in_seconds: 900,
            size_bytes: body.size_bytes,
            sha256: body.sha256,
          });
        },
      ),
      http.put(UPLOAD_URL, () => {
        // The bytes must go DIRECTLY to storage, only after the intent.
        calls.push("put");
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
    const ferrogateRow = (await screen.findByText("ferrogate")).closest("tr")!;
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
