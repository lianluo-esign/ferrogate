import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuth } from "@/hooks/use-auth";
import { useI18n, type TranslationKey } from "@/i18n";
import {
  adminDelete,
  adminGet,
  type AdminSchema,
  gatewayGetBinary,
  gatewayPutBinary,
} from "@/lib/gateway-client";

type AssetSummary = AdminSchema<"AssetSummary">;

// Asset-type option values map to their catalog label key; the labels are
// resolved through `t()` at render so the picker localizes with the console.
const ASSET_TYPES: { value: string; labelKey: TranslationKey }[] = [
  { value: "cli_tool", labelKey: "page.assets.type.cliTool" },
  { value: "mcp_manifest", labelKey: "page.assets.type.mcpManifest" },
  { value: "skill_bundle", labelKey: "page.assets.type.skillBundle" },
  { value: "static_site", labelKey: "page.assets.type.staticSite" },
  { value: "config_file", labelKey: "page.assets.type.configFile" },
];
const ASSETS_QUERY_KEY = ["assets"] as const;
const ASSET_STORAGE_SUMMARY_QUERY_KEY = ["asset-storage-summary"] as const;

function assetPath(assetType: string, name: string, version: string): string {
  return `/v1/assets/${encodeURIComponent(assetType)}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
}

export default function AssetsPage() {
  const { session } = useAuth();
  const { t, format } = useI18n();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();

  const [assetType, setAssetType] = useState("cli_tool");
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const { data, isLoading, error: listError } = useQuery({
    queryKey: ASSETS_QUERY_KEY,
    queryFn: () => adminGet(apiKey, "/v1/assets"),
  });

  const {
    data: storageSummary,
    isLoading: isStorageSummaryLoading,
    error: storageSummaryError,
  } = useQuery({
    queryKey: ASSET_STORAGE_SUMMARY_QUERY_KEY,
    queryFn: () => adminGet(apiKey, "/v1/assets/storage/summary"),
  });

  const uploadMutation = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error(t("page.assets.error.chooseFile"));
      if (!name.trim() || !version.trim())
        throw new Error(t("page.assets.error.nameVersionRequired"));
      return gatewayPutBinary(
        apiKey,
        assetPath(assetType, name.trim(), version.trim()),
        file,
        file.type,
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ASSETS_QUERY_KEY });
      queryClient.invalidateQueries({ queryKey: ASSET_STORAGE_SUMMARY_QUERY_KEY });
      toast.success(t("page.assets.toast.pushed"));
      setName("");
      setVersion("");
      setFile(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
    },
    onError: (uploadError: Error) => toast.error(uploadError.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (asset: AssetSummary) =>
      adminDelete(apiKey, "/v1/assets/{asset_type}/{name}/{version}", {
        params: {
          asset_type: asset.asset_type,
          name: asset.name,
          version: asset.version,
        },
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ASSETS_QUERY_KEY });
      queryClient.invalidateQueries({ queryKey: ASSET_STORAGE_SUMMARY_QUERY_KEY });
      toast.success(t("page.assets.toast.deleted"));
    },
    onError: (deleteError: Error) => toast.error(deleteError.message),
  });

  async function handleDownload(asset: AssetSummary) {
    try {
      const blob = await gatewayGetBinary(
        apiKey,
        assetPath(asset.asset_type, asset.name, asset.version),
      );
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = asset.name;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (downloadError) {
      toast.error(
        downloadError instanceof Error
          ? downloadError.message
          : t("page.assets.error.downloadFailed"),
      );
    }
  }

  const rows = data?.data ?? [];

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">{t("page.assets.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("page.assets.description")}
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("page.assets.storage.title")}</CardTitle>
        </CardHeader>
        <CardContent>
          {storageSummaryError ? (
            <p role="alert" className="text-sm text-destructive">
              {t("page.assets.storage.error", { message: storageSummaryError.message })}
            </p>
          ) : isStorageSummaryLoading || !storageSummary ? (
            <p className="text-sm text-muted-foreground">{t("resource.table.loading")}</p>
          ) : (
            <p className="text-sm">
              {storageSummary.quota_bytes !== null
                ? t("page.assets.storage.usageWithQuota", {
                    used: format.bytes(storageSummary.used_bytes),
                    quota: format.bytes(storageSummary.quota_bytes),
                  })
                : t("page.assets.storage.usageNoQuota", {
                    used: format.bytes(storageSummary.used_bytes),
                  })}
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("page.assets.push.title")}</CardTitle>
          <CardDescription>
            {t("page.assets.push.description")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="grid gap-4 sm:grid-cols-2"
            onSubmit={(event) => {
              event.preventDefault();
              uploadMutation.mutate();
            }}
          >
            <div className="grid gap-2">
              <Label htmlFor="asset-type">{t("page.assets.field.assetType")}</Label>
              <Select value={assetType} onValueChange={setAssetType}>
                <SelectTrigger id="asset-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ASSET_TYPES.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {t(option.labelKey)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="asset-name">{t("page.assets.field.name")}</Label>
              <Input
                id="asset-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                // eslint-disable-next-line ferrogate/no-untranslated-literal -- example asset name, not translatable copy
                placeholder="my-tool"
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="asset-version">{t("page.assets.field.version")}</Label>
              <Input
                id="asset-version"
                value={version}
                onChange={(event) => setVersion(event.target.value)}
                placeholder="1.0.0"
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="asset-file">{t("page.assets.field.file")}</Label>
              <Input
                id="asset-file"
                type="file"
                ref={fileInputRef}
                onChange={(event) => setFile(event.target.files?.[0] ?? null)}
                required
              />
            </div>
            <div className="sm:col-span-2">
              <Button type="submit" disabled={uploadMutation.isPending}>
                {uploadMutation.isPending
                  ? t("page.assets.push.submitting")
                  : t("page.assets.push.submit")}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {listError && (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t("page.assets.list.error", { message: listError.message })}
        </p>
      )}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("page.assets.col.type")}</TableHead>
              <TableHead>{t("page.assets.col.name")}</TableHead>
              <TableHead>{t("page.assets.col.version")}</TableHead>
              <TableHead>{t("page.assets.col.contentType")}</TableHead>
              <TableHead>{t("page.assets.col.contentHash")}</TableHead>
              <TableHead>{t("page.assets.col.size")}</TableHead>
              <TableHead>{t("page.assets.col.storage")}</TableHead>
              <TableHead className="w-32" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  {t("page.assets.empty")}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((asset) => (
                <TableRow key={asset.id}>
                  <TableCell>{asset.asset_type}</TableCell>
                  <TableCell>{asset.name}</TableCell>
                  <TableCell>{asset.version}</TableCell>
                  <TableCell>{asset.content_type}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {asset.content_hash.slice(0, 12)}...
                  </TableCell>
                  <TableCell>{format.bytes(asset.size_bytes)}</TableCell>
                  <TableCell>
                    {asset.storage_backed
                      ? t("page.assets.storage.bucket")
                      : t("page.assets.storage.inline")}
                  </TableCell>
                  <TableCell className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => handleDownload(asset)}>
                      {t("page.assets.action.download")}
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => deleteMutation.mutate(asset)}
                    >
                      {t("resource.action.delete")}
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
